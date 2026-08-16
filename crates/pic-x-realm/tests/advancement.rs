//! Profile 0.2 centralized advancement, end to end through the realm token endpoint.
//!
//! OAuth access token → PIC Token JWT 0 → a workload-signed candidate carrying an issuer-signed
//! SD-JWT Proof of Relationship → PIC Token JWT 1, with the read authority attenuated away.
//!
//! Nothing here is stubbed at the trust boundary: a real attester signs a real SD-JWT presentation,
//! served from a real key-set endpoint the realm fetches over HTTP, and the workload signs the three
//! candidate artifacts with the key that credential binds.

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::digest::{SHA256, digest};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use tower::ServiceExt;

use pic::continuity::artifacts::token::{decode_token, sign_token};
use pic::continuity::artifacts::{
    PicContinuityCose, PicContinuityPayload, PicPcaCose, PicPcaPayload, ProofOfRelationship,
};
use pic::continuity::authority::attenuation::Attenuations;
use pic::continuity::authority::bitmap::RemoveBitmap;
use pic::continuity::prover::{CandidateRequest, build_candidate};
use pic::continuity::trust::Ed25519Signer;
use pic_x_core::audit::{AuditEvent, Result as AuditResult};
use pic_x_core::{
    BoxFuture, ClaimMapping, Config, EXCHANGE_ON_UNMATCHED_SCOPE_REJECT,
    EXCHANGE_SOURCE_FORMAT_JWT, EXCHANGE_SOURCE_OAUTH_ACCESS_TOKEN, ExchangeProfileClaims,
    ExchangeProfileConfig, ExchangeProfilePrivileges, ExchangeProfileSource,
    ExchangeTokenValidation, Jwk, KeyId, KeyManager, Maintenance, PrivilegeEmit, PrivilegeRule,
    ProductIdentity, Pseudonymizer, Realm, Realms, Signature, TrustedAttesterConfig,
};
use pic_x_realm::WellKnownService;

const ATTESTER_ISSUER: &str = "https://attestation.example.com";

/// A sink that can be made to fail, so the "no record, no token" rule can be observed.
#[derive(Debug, Default)]
struct SilentSink {
    broken: std::sync::atomic::AtomicBool,
    events: Mutex<Vec<RecordedEvent>>,
}

#[derive(Debug, Clone)]
struct RecordedEvent {
    action: String,
    subject: String,
    subject_kind: String,
    target: Option<String>,
    continuity_id: Option<String>,
    continuity_position: Option<u64>,
}

impl SilentSink {
    fn breaks() -> Self {
        Self {
            broken: std::sync::atomic::AtomicBool::new(true),
            events: Mutex::new(Vec::new()),
        }
    }

    fn events(&self) -> Vec<RecordedEvent> {
        self.events.lock().expect("events lock").clone()
    }
}

impl pic_x_core::AuditSink for SilentSink {
    fn name(&self) -> &'static str {
        "silent"
    }

    fn record<'a>(
        &'a self,
        event: &'a AuditEvent<'a>,
        policy: Option<&'a dyn Pseudonymizer>,
    ) -> BoxFuture<'a, AuditResult<()>> {
        Box::pin(async move {
            if self.broken.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(pic_x_core::AuditError::backend("the trail is full"));
            }
            self.events
                .lock()
                .expect("events lock")
                .push(RecordedEvent {
                    action: event.action().to_owned(),
                    subject: event.subject().render(policy),
                    subject_kind: event.subject().kind().to_owned(),
                    target: event.target().map(ToOwned::to_owned),
                    continuity_id: event.continuity_id().map(ToOwned::to_owned),
                    continuity_position: event.continuity_position(),
                });
            Ok(())
        })
    }
}

/// The realm token ring: a real Ed25519 key that signs and publishes itself.
///
/// It has to be real now — a checkpoint is accepted because *this realm's signature verifies over
/// it*, so a stand-in that returns fixed bytes would fail the very check under test.
#[derive(Debug)]
struct RealmRing {
    key: ed25519_dalek::SigningKey,
}

impl RealmRing {
    fn new() -> Self {
        Self {
            key: ed25519_dalek::SigningKey::from_bytes(&[0x77; 32]),
        }
    }
}

impl KeyManager for RealmRing {
    fn name(&self) -> &'static str {
        "test-realm-ring"
    }

    fn public_keys(&self) -> pic_x_core::keys::Result<Vec<Jwk>> {
        Ok(vec![Jwk {
            kid: "realm-key-1".to_owned(),
            kty: "OKP".to_owned(),
            crv: Some("Ed25519".to_owned()),
            x: b64(self.key.verifying_key().as_bytes()),
            y: None,
            alg: "EdDSA".to_owned(),
            usage: "sig".to_owned(),
        }])
    }

    fn active_key_id(&self) -> pic_x_core::keys::Result<KeyId> {
        Ok(KeyId::new("realm-key-1"))
    }

    fn sign(&self, payload: &[u8]) -> pic_x_core::keys::Result<Signature> {
        use ed25519_dalek::Signer;
        Ok(Signature::new(
            KeyId::new("realm-key-1"),
            "EdDSA",
            self.key.sign(payload).to_bytes().to_vec(),
        ))
    }

    fn maintain(&self) -> pic_x_core::keys::Result<Maintenance> {
        Ok(Maintenance::default())
    }
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The lab attester: an Ed25519 issuing key, the key set it publishes, and the credentials it signs.
struct Attester {
    pair: Ed25519KeyPair,
}

impl Attester {
    fn new() -> Self {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("key generates");
        Self {
            pair: Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("key parses"),
        }
    }

    fn key_set(&self) -> String {
        serde_json::json!({
            "keys": [{
                "kid": "attester-1",
                "kty": "OKP",
                "crv": "Ed25519",
                "use": "sig",
                "x": b64(self.pair.public_key().as_ref()),
            }]
        })
        .to_string()
    }

    /// An SD-JWT presentation binding `workload_public_key`, disclosing corporation and department.
    fn presentation(&self, workload_public_key: &[u8]) -> String {
        self.presentation_for(workload_public_key, "ACME", "sensitive-documents")
    }

    /// A presentation that discloses only a claim the execution contract says nothing about.
    fn presentation_silent(&self, workload_public_key: &[u8]) -> String {
        let disclosure =
            b64(
                serde_json::json!(["Xn7kw6wekrrpvjPLcrMOQQ", "workload_role", "document-reader"])
                    .to_string()
                    .as_bytes(),
            );
        let digests = vec![b64(digest(&SHA256, disclosure.as_bytes()).as_ref())];
        let jwt = self.sign_credential(workload_public_key, &digests);

        format!("{jwt}~{disclosure}~")
    }

    /// A presentation that satisfies only part of the execution contract.
    fn presentation_corporation_only(&self, workload_public_key: &[u8]) -> String {
        let disclosure = b64(
            serde_json::json!(["f0UUCvMSycSUXaVfuiDWAA", "corporation", "ACME"])
                .to_string()
                .as_bytes(),
        );
        let digests = vec![b64(digest(&SHA256, disclosure.as_bytes()).as_ref())];
        let jwt = self.sign_credential(workload_public_key, &digests);

        format!("{jwt}~{disclosure}~")
    }

    /// The same as [`presentation`](Self::presentation), with the disclosed values chosen here.
    fn presentation_for(
        &self,
        workload_public_key: &[u8],
        corporation: &str,
        department: &str,
    ) -> String {
        let disclosures = [
            b64(
                serde_json::json!(["f0UUCvMSycSUXaVfuiDWAA", "corporation", corporation])
                    .to_string()
                    .as_bytes(),
            ),
            b64(
                serde_json::json!(["E54m03bpDTSeWfZOQ-1wVw", "department", department])
                    .to_string()
                    .as_bytes(),
            ),
        ];
        let digests: Vec<String> = disclosures
            .iter()
            .map(|d| b64(digest(&SHA256, d.as_bytes()).as_ref()))
            .collect();

        let mut presentation = self.sign_credential(workload_public_key, &digests);
        for disclosure in &disclosures {
            presentation.push('~');
            presentation.push_str(disclosure);
        }
        presentation.push('~');

        presentation
    }

    /// The issuer-signed half of a credential: digest commitments and the bound workload key.
    fn sign_credential(&self, workload_public_key: &[u8], digests: &[String]) -> String {
        let header = serde_json::json!({"alg": "EdDSA", "kid": "attester-1", "typ": "vc+sd-jwt"});
        let payload = serde_json::json!({
            "iss": ATTESTER_ISSUER,
            "iat": 1_700_000_000_i64,
            "exp": 4_000_000_000_i64,
            "_sd_alg": "sha-256",
            "_sd": digests,
            "cnf": { "jwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": "worker-1-key",
                "x": b64(workload_public_key),
            }},
        });
        let signing_input = format!(
            "{}.{}",
            b64(&serde_json::to_vec(&header).expect("header")),
            b64(&serde_json::to_vec(&payload).expect("payload"))
        );
        let signature = self.pair.sign(signing_input.as_bytes());

        format!("{signing_input}.{}", b64(signature.as_ref()))
    }
}

/// A test identity provider: it signs access tokens and publishes the key that verifies them.
///
/// The realm now verifies that signature, so the demo token can no longer be hand-assembled.
struct IdentityProvider {
    key: ed25519_dalek::SigningKey,
    issuer: String,
}

impl IdentityProvider {
    fn key_set(&self) -> String {
        serde_json::json!({
            "keys": [{
                "kid": "idp-key-1",
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "use": "sig",
                "x": b64(self.key.verifying_key().as_bytes()),
            }]
        })
        .to_string()
    }

    /// A signed access token carrying the scopes the Exchange Profile maps.
    fn access_token(&self) -> String {
        use ed25519_dalek::Signer;

        let header = serde_json::json!({"alg": "EdDSA", "typ": "JWT", "kid": "idp-key-1"});
        let payload = serde_json::json!({
            "iss": self.issuer,
            "sub": "user-123",
            "aud": "pic-x",
            "iat": 1_786_700_400_i64,
            "exp": 4_000_000_000_i64,
            "scope": "documents:read:document-42 storage:save",
        });
        let signing_input = format!(
            "{}.{}",
            b64(&serde_json::to_vec(&header).expect("header")),
            b64(&serde_json::to_vec(&payload).expect("payload"))
        );

        format!(
            "{signing_input}.{}",
            b64(&self.key.sign(signing_input.as_bytes()).to_bytes())
        )
    }
}

/// Serves an identity provider's discovery document and key set.
async fn serve_identity_provider() -> IdentityProvider {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("the identity-provider listener binds");
    let address = listener.local_addr().expect("the listener has an address");
    let issuer = format!("http://{address}");

    let provider = IdentityProvider {
        key: ed25519_dalek::SigningKey::from_bytes(&[0x99; 32]),
        issuer: issuer.clone(),
    };
    let key_set = provider.key_set();
    let discovery = serde_json::json!({
        "issuer": issuer,
        "jwks_uri": format!("{issuer}/keys"),
    })
    .to_string();

    let router = axum::Router::new()
        .route(
            "/.well-known/openid-configuration",
            axum::routing::get(move || {
                let discovery = discovery.clone();
                async move { discovery }
            }),
        )
        .route(
            "/keys",
            axum::routing::get(move || {
                let key_set = key_set.clone();
                async move { key_set }
            }),
        );
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });

    provider
}

/// Serves the attester key set, so the realm fetches it the way it would in a deployment.
async fn serve_key_set(key_set: String) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("the key-set listener binds");
    let address = listener.local_addr().expect("the listener has an address");

    let router = axum::Router::new().route(
        "/jwks.json",
        axum::routing::get(move || {
            let key_set = key_set.clone();
            async move { key_set }
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });

    format!("http://{address}/jwks.json")
}

fn exchange_profile(issuer: &str) -> ExchangeProfileConfig {
    ExchangeProfileConfig {
        id: "test-oauth-to-pic".to_owned(),
        source: ExchangeProfileSource {
            token_type: EXCHANGE_SOURCE_OAUTH_ACCESS_TOKEN.to_owned(),
            format: EXCHANGE_SOURCE_FORMAT_JWT.to_owned(),
            issuer: issuer.to_owned(),
            discovery_url: None,
            audience: "pic-x".to_owned(),
            validation: ExchangeTokenValidation {
                allowed_algorithms: vec!["EdDSA".to_owned()],
                require_expiration: true,
                require_token_type: Some("JWT".to_owned()),
            },
        },
        claims: ExchangeProfileClaims {
            identity_context: Default::default(),
            scopes: ClaimMapping {
                from: Some("scope".to_owned()),
                value: None,
                value_type: Some("set".to_owned()),
                encoding: Some("space-delimited".to_owned()),
            },
        },
        privileges: ExchangeProfilePrivileges {
            source: "scopes".to_owned(),
            rules: vec![
                PrivilegeRule {
                    name: "resource-instance".to_owned(),
                    priority: 10,
                    pattern: r"^(?<resourceType>[a-z][a-z0-9_-]*):(?<operation>[a-z][a-z0-9_-]*):(?<resourceId>[a-zA-Z0-9_-]+)$".to_owned(),
                    emit: PrivilegeEmit {
                        scope: "${raw}".to_owned(),
                        operation: "${operation}".to_owned(),
                        resource_type: "${resourceType}".to_owned(),
                        resource_id: "${resourceId}".to_owned(),
                    },
                },
                PrivilegeRule {
                    name: "resource-collection".to_owned(),
                    priority: 1,
                    pattern: r"^(?<resourceType>[a-z][a-z0-9_-]*):(?<operation>[a-z][a-z0-9_-]*)$".to_owned(),
                    emit: PrivilegeEmit {
                        scope: "${raw}".to_owned(),
                        operation: "${operation}".to_owned(),
                        resource_type: "${resourceType}".to_owned(),
                        resource_id: "*".to_owned(),
                    },
                },
            ],
        },
        on_unmatched_scope: EXCHANGE_ON_UNMATCHED_SCOPE_REJECT.to_owned(),
    }
}

fn realm_with_broken_trail(jwks_uri: &str, idp_issuer: &str) -> Realm {
    Realm::new(
        "acme",
        "/realms/acme".to_owned(),
        Some("https://pic-x.example.com/realms/acme".to_owned()),
        true,
        None,
        Some(Arc::new(RealmRing::new())),
        Arc::new(SilentSink::breaks()),
        None,
    )
    .with_exchange_profiles([exchange_profile(idp_issuer)])
    .with_trusted_attesters([TrustedAttesterConfig {
        id: "test-por-attester".to_owned(),
        issuer: ATTESTER_ISSUER.to_owned(),
        jwks_uri: jwks_uri.to_owned(),
        proof_types: vec!["sd-jwt".to_owned()],
        formats: vec!["sd-jwt".to_owned()],
    }])
}

fn realm_trusting_with_audit(
    jwks_uri: &str,
    idp_issuer: &str,
    audit: Arc<dyn pic_x_core::AuditSink>,
) -> Realm {
    Realm::new(
        "acme",
        "/realms/acme".to_owned(),
        Some("https://pic-x.example.com/realms/acme".to_owned()),
        true,
        None,
        Some(Arc::new(RealmRing::new())),
        audit,
        None,
    )
    .with_exchange_profiles([exchange_profile(idp_issuer)])
    .with_trusted_attesters([TrustedAttesterConfig {
        id: "test-por-attester".to_owned(),
        issuer: ATTESTER_ISSUER.to_owned(),
        jwks_uri: jwks_uri.to_owned(),
        proof_types: vec!["sd-jwt".to_owned()],
        formats: vec!["sd-jwt".to_owned()],
    }])
}

fn development_config() -> Config {
    Config::from_layers(
        pic_x_core::BuildSettings::new("9.9.9", "2026", "Test Holder"),
        Vec::<String>::new(),
        pic_x_core::Layers::new().with_file(vec![(
            pic_x_core::config::SETTING_DEVELOPMENT_MODE.to_owned(),
            "true".to_owned(),
        )]),
    )
    .expect("the configuration resolves")
}

async fn post_token(router: &axum::Router, body: String) -> (StatusCode, serde_json::Value) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/realms/acme/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .expect("the request builds"),
        )
        .await
        .expect("the route answers");

    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the body reads");

    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

fn jwt_payload(token: &str) -> serde_json::Value {
    let payload = token.split('.').nth(1).expect("the token has a payload");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("base64url"))
        .expect("the payload is JSON")
}

fn initialization_body(access_token: &str) -> String {
    let proposal = pic::continuity::proposal::InitialContinuityProposal::new(
        [
            (
                "corporation".to_owned(),
                pic::continuity::authority::AuthorityValue::One("ACME".to_owned()),
            ),
            (
                "department".to_owned(),
                pic::continuity::authority::AuthorityValue::One("sensitive-documents".to_owned()),
            ),
        ]
        .into_iter()
        .collect(),
    )
    .to_continuity_proposal()
    .expect("the proposal encodes");

    format!(
        "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
         &subject_token={access_token}\
         &subject_token_type=urn:ietf:params:oauth:token-type:access_token\
         &requested_token_type=https://pic-protocol.org/definitions/token-types/pic\
         &continuity_proposal={proposal}"
    )
}

fn advancement_body(candidate: &str) -> String {
    format!(
        "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
         &subject_token={candidate}\
         &subject_token_type=https://pic-protocol.org/definitions/token-types/pic\
         &requested_token_type=https://pic-protocol.org/definitions/token-types/pic"
    )
}

fn rewrite_token_algorithm(token: &str, algorithm: &str) -> String {
    let segments: Vec<&str> = token.split('.').collect();
    assert_eq!(segments.len(), 3, "the token is compact JWS");
    let mut header: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segments[0]).expect("header"))
            .expect("header JSON");
    header["alg"] = serde_json::Value::String(algorithm.to_owned());

    format!(
        "{}.{}.{}",
        b64(&serde_json::to_vec(&header).expect("header encodes")),
        segments[1],
        segments[2]
    )
}

fn rewrite_token_jti_and_resign(token: &str, jti: Option<&str>, signer: &Ed25519Signer) -> String {
    let mut decoded = decode_token(token).expect("the token decodes");
    decoded.claims.jti = jti.map(ToOwned::to_owned);
    sign_token(&decoded.claims, signer).expect("the token resigns")
}

/// The exact signed PIC PCA COSE bytes a settled token carries, and the checkpoint they decode to.
fn checkpoint_of(token: &str) -> (Vec<u8>, PicPcaPayload) {
    let claims = jwt_payload(token);
    let continuity_bytes = URL_SAFE_NO_PAD
        .decode(claims["pic"]["root"].as_str().expect("pic.root"))
        .expect("pic.root is base64url");

    let continuity: PicContinuityPayload = PicContinuityCose::from_bytes(&continuity_bytes)
        .expect("the continuity parses")
        .payload_unverified()
        .expect("the continuity payload decodes");
    let pca_bytes = continuity.root.pca.clone();
    let checkpoint: PicPcaPayload = PicPcaCose::from_bytes(&pca_bytes)
        .expect("the checkpoint parses")
        .payload_unverified()
        .expect("the checkpoint payload decodes");

    (pca_bytes, checkpoint)
}

struct Lab {
    router: axum::Router,
    attester: Attester,
    provider: IdentityProvider,
    audit: Arc<SilentSink>,
}

async fn lab() -> Lab {
    let attester = Attester::new();
    let provider = serve_identity_provider().await;
    let jwks_uri = serve_key_set(attester.key_set()).await;
    let audit = Arc::new(SilentSink::default());
    let realms = Realms::new([realm_trusting_with_audit(
        &jwks_uri,
        &provider.issuer,
        audit.clone(),
    )]);
    let config = development_config();

    let service = WellKnownService::new();
    let router = service.router(
        &ProductIdentity::new("demo-x", "Demo X", "A tagline", "Demo X CLI", "<art>"),
        &config,
        &realms,
    );
    // The realm fetches both key sets the way the background task would.
    service.refresh_attester_keys().await;

    Lab {
        router,
        attester,
        provider,
        audit,
    }
}

#[tokio::test]
async fn a_workload_advances_the_lineage_and_the_removed_authority_is_gone() {
    let lab = lab().await;

    // OAuth authority becomes checkpoint 0, carrying both invariants.
    let (status, body) = post_token(
        &lab.router,
        initialization_body(&lab.provider.access_token()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "initialization failed: {body}");
    let token0 = body["access_token"].as_str().expect("token 0").to_owned();
    let (pca0_bytes, pca0) = checkpoint_of(&token0);
    let token0_jti = jwt_payload(&token0)["jti"]
        .as_str()
        .expect("token 0 has jti")
        .to_owned();
    assert_eq!(pca0.position, 0);
    assert_eq!(pca0.lineage_id.as_deref(), Some(token0_jti.as_str()));
    assert_eq!(pca0.context_of_authority.invariants.len(), 2);
    assert_eq!(
        pca0.context_of_authority.invariants[&0].0,
        "documents:read:document-42"
    );

    // The workload holds a key, and the attester binds it in a Proof of Relationship.
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("key generates");
    let workload_pair =
        ed25519_dalek::SigningKey::from_bytes(&pkcs8.as_ref()[16..48].try_into().expect("seed"));
    let workload = Ed25519Signer::new(workload_pair.clone(), "spiffe://acme/workload-1");
    let presentation = lab
        .attester
        .presentation(workload_pair.verifying_key().as_bytes());

    // It reads document-42, then proposes dropping that invariant.
    let candidate = build_candidate(
        &pca0_bytes,
        CandidateRequest {
            attenuations: Attenuations {
                invariants: RemoveBitmap::from_indices(&[0]),
                ..Default::default()
            },
            next_challenge: vec![0x5a; 32],
            proof_of_relationship: Some(ProofOfRelationship::sd_jwt(&presentation)),
            aud: Some("pic-x".to_owned()),
            ..Default::default()
        },
        &workload,
        None,
    )
    .expect("the candidate builds");

    let (status, body) = post_token(&lab.router, advancement_body(&candidate.token)).await;
    assert_eq!(status, StatusCode::OK, "advancement rejected: {body}");

    let token1 = body["access_token"].as_str().expect("token 1");
    let (_, pca1) = checkpoint_of(token1);
    let token1_jti = jwt_payload(token1)["jti"]
        .as_str()
        .expect("token 1 has jti")
        .to_owned();
    assert_eq!(pca1.position, 1);
    assert_eq!(token1_jti, token0_jti);
    assert_eq!(pca1.lineage_id.as_deref(), Some(token0_jti.as_str()));
    // The read authority is gone, storage:save survives and is re-indexed to 0.
    assert_eq!(pca1.context_of_authority.invariants.len(), 1);
    assert_eq!(pca1.context_of_authority.invariants[&0].0, "storage:save");
    // The accepted transition's challenge became the new checkpoint's.
    assert_eq!(pca1.challenge.next_challenge, vec![0x5a; 32]);
    // The execution contract carried forward untouched.
    assert_eq!(pca1.context_of_authority.execution_contract.len(), 2);

    let events = lab.audit.events();
    let initialized = events
        .iter()
        .find(|event| event.action == "pic.exchange.initialized")
        .expect("initialization was audited");
    assert_eq!(
        initialized.continuity_id.as_deref(),
        Some(token0_jti.as_str())
    );
    assert_eq!(initialized.continuity_position, Some(0));
    assert_eq!(initialized.target.as_deref(), Some("test-oauth-to-pic"));

    let advanced = events
        .iter()
        .find(|event| event.action == "pic.exchange.advanced")
        .expect("advancement was audited");
    assert_eq!(advanced.subject_kind, "continuity");
    assert_eq!(advanced.subject, token0_jti);
    assert_eq!(
        advanced.continuity_id.as_deref(),
        Some(advanced.subject.as_str())
    );
    assert_eq!(advanced.continuity_position, Some(1));
}

#[tokio::test]
async fn a_candidate_jti_must_match_the_predecessor_lineage() {
    let lab = lab().await;
    let (_, body) = post_token(
        &lab.router,
        initialization_body(&lab.provider.access_token()),
    )
    .await;
    let token0 = body["access_token"].as_str().expect("token 0").to_owned();
    let (pca0_bytes, _) = checkpoint_of(&token0);

    let workload_pair = ed25519_dalek::SigningKey::from_bytes(&[0x68; 32]);
    let presentation = lab
        .attester
        .presentation(workload_pair.verifying_key().as_bytes());
    let workload = Ed25519Signer::new(workload_pair, "spiffe://acme/wrong-jti");
    let candidate = build_candidate(
        &pca0_bytes,
        CandidateRequest {
            attenuations: Attenuations {
                invariants: RemoveBitmap::from_indices(&[0]),
                ..Default::default()
            },
            next_challenge: vec![0x5a; 32],
            proof_of_relationship: Some(ProofOfRelationship::sd_jwt(&presentation)),
            aud: Some("pic-x".to_owned()),
            ..Default::default()
        },
        &workload,
        None,
    )
    .expect("the candidate builds");
    let rewritten =
        rewrite_token_jti_and_resign(&candidate.token, Some("not-the-predecessor"), &workload);

    let (status, body) = post_token(&lab.router, advancement_body(&rewritten)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error_description"]
            .as_str()
            .expect("a description")
            .contains("jti"),
        "unexpected rejection: {body}"
    );
    assert!(
        lab.audit
            .events()
            .iter()
            .any(|event| event.action == "pic.exchange.rejected"),
        "rejected advancement was not audited"
    );
}

#[tokio::test]
async fn a_candidate_whose_por_names_an_unconfigured_issuer_is_rejected() {
    let lab = lab().await;
    let (_, body) = post_token(
        &lab.router,
        initialization_body(&lab.provider.access_token()),
    )
    .await;
    let token0 = body["access_token"].as_str().expect("token 0").to_owned();
    let (pca0_bytes, _) = checkpoint_of(&token0);

    // A different attester, correctly signing its own credential, but not one this realm trusts.
    let stranger = Attester::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("key generates");
    let workload_pair =
        ed25519_dalek::SigningKey::from_bytes(&pkcs8.as_ref()[16..48].try_into().expect("seed"));
    let workload = Ed25519Signer::new(workload_pair.clone(), "spiffe://acme/workload-1");
    let presentation = stranger.presentation(workload_pair.verifying_key().as_bytes());

    let candidate = build_candidate(
        &pca0_bytes,
        CandidateRequest {
            next_challenge: vec![0x5a; 32],
            proof_of_relationship: Some(ProofOfRelationship::sd_jwt(&presentation)),
            ..Default::default()
        },
        &workload,
        None,
    )
    .expect("the candidate builds");

    let (status, body) = post_token(&lab.router, advancement_body(&candidate.token)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // The signature is valid; the issuer is simply not one this realm accepts.
    assert!(
        body["error_description"]
            .as_str()
            .expect("a description")
            .contains("issuer"),
        "unexpected rejection: {body}"
    );
}

#[tokio::test]
async fn a_candidate_signed_by_a_key_the_por_does_not_bind_is_rejected() {
    let lab = lab().await;
    let (_, body) = post_token(
        &lab.router,
        initialization_body(&lab.provider.access_token()),
    )
    .await;
    let token0 = body["access_token"].as_str().expect("token 0").to_owned();
    let (pca0_bytes, _) = checkpoint_of(&token0);

    // The credential binds one key; the candidate is signed with another.
    let bound = ed25519_dalek::SigningKey::from_bytes(&[0x11; 32]);
    let impostor = ed25519_dalek::SigningKey::from_bytes(&[0x22; 32]);
    let presentation = lab.attester.presentation(bound.verifying_key().as_bytes());
    let candidate = build_candidate(
        &pca0_bytes,
        CandidateRequest {
            next_challenge: vec![0x5a; 32],
            proof_of_relationship: Some(ProofOfRelationship::sd_jwt(&presentation)),
            ..Default::default()
        },
        &Ed25519Signer::new(impostor, "spiffe://acme/impostor"),
        None,
    )
    .expect("the candidate builds");

    let (status, body) = post_token(&lab.router, advancement_body(&candidate.token)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error_description"]
            .as_str()
            .expect("a description")
            .contains("signature"),
        "unexpected rejection: {body}"
    );
}

#[tokio::test]
async fn a_candidate_whose_token_algorithm_disagrees_with_the_por_key_is_rejected() {
    let lab = lab().await;
    let (_, body) = post_token(
        &lab.router,
        initialization_body(&lab.provider.access_token()),
    )
    .await;
    let token0 = body["access_token"].as_str().expect("token 0").to_owned();
    let (pca0_bytes, _) = checkpoint_of(&token0);

    let workload_pair = ed25519_dalek::SigningKey::from_bytes(&[0x23; 32]);
    let presentation = lab
        .attester
        .presentation(workload_pair.verifying_key().as_bytes());
    let candidate = build_candidate(
        &pca0_bytes,
        CandidateRequest {
            next_challenge: vec![0x5a; 32],
            proof_of_relationship: Some(ProofOfRelationship::sd_jwt(&presentation)),
            ..Default::default()
        },
        &Ed25519Signer::new(workload_pair, "spiffe://acme/workload-1"),
        None,
    )
    .expect("the candidate builds");
    let wrong_algorithm = rewrite_token_algorithm(&candidate.token, "ES256");

    let (status, body) = post_token(&lab.router, advancement_body(&wrong_algorithm)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error_description"]
            .as_str()
            .expect("a description")
            .contains("algorithm"),
        "unexpected rejection: {body}"
    );
}

#[tokio::test]
async fn a_candidate_rooted_at_a_checkpoint_this_realm_never_issued_is_rejected() {
    let lab = lab().await;

    // A checkpoint that was never settled here: its bytes are in no store.
    let foreign_realm = Ed25519Signer::new(ed25519_dalek::SigningKey::from_bytes(&[0x33; 32]), "k");
    let map = pic::continuity::authority::IndexedAuthorityMap::from_logical(
        &pic::continuity::authority::LogicalAuthority::new(
            None,
            vec![pic::continuity::authority::Invariant::new(
                "payments:approve",
                "approve",
                "payments",
                "*",
            )],
            [(
                "corporation".to_owned(),
                pic::continuity::authority::AuthorityValue::One("ACME".to_owned()),
            )]
            .into_iter()
            .collect(),
        ),
    )
    .expect("the authority canonicalizes");
    let foreign = pic::continuity::verifier::issue_settled(
        PicPcaPayload::new(0, map, vec![0x7b; 32]),
        &foreign_realm,
        &pic::continuity::verifier::SettlementContext {
            iss: "https://elsewhere.example.com".to_owned(),
            ..Default::default()
        },
    )
    .expect("the foreign checkpoint issues");

    let workload_pair = ed25519_dalek::SigningKey::from_bytes(&[0x44; 32]);
    let presentation = lab
        .attester
        .presentation(workload_pair.verifying_key().as_bytes());
    let candidate = build_candidate(
        &foreign.pca_bytes,
        CandidateRequest {
            next_challenge: vec![0x5a; 32],
            proof_of_relationship: Some(ProofOfRelationship::sd_jwt(&presentation)),
            ..Default::default()
        },
        &Ed25519Signer::new(workload_pair, "spiffe://acme/workload-1"),
        None,
    )
    .expect("the candidate builds");

    let (status, body) = post_token(&lab.router, advancement_body(&candidate.token)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error_description"]
            .as_str()
            .expect("a description")
            .contains("checkpoint"),
        "unexpected rejection: {body}"
    );
}

#[tokio::test]
async fn advancement_still_refuses_a_continuity_proposal() {
    let lab = lab().await;
    let (_, body) = post_token(
        &lab.router,
        initialization_body(&lab.provider.access_token()),
    )
    .await;
    let token0 = body["access_token"].as_str().expect("token 0").to_owned();

    // Profile 0.2 PIC-to-PIC advancement omits it; sending one is a request error.
    let (status, _) = post_token(
        &lab.router,
        format!("{}&continuity_proposal=abc", advancement_body(&token0)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_workload_that_contradicts_the_execution_contract_is_rejected() {
    let lab = lab().await;
    let (_, body) = post_token(
        &lab.router,
        initialization_body(&lab.provider.access_token()),
    )
    .await;
    let token0 = body["access_token"].as_str().expect("token 0").to_owned();
    let (pca0_bytes, _) = checkpoint_of(&token0);

    // Properly attested by an issuer this realm trusts, with a key it controls — and belonging to
    // a corporation the lineage's execution contract does not allow.
    let workload_pair = ed25519_dalek::SigningKey::from_bytes(&[0x55; 32]);
    let presentation = lab.attester.presentation_for(
        workload_pair.verifying_key().as_bytes(),
        "OTHER-CORP",
        "sensitive-documents",
    );
    let candidate = build_candidate(
        &pca0_bytes,
        CandidateRequest {
            next_challenge: vec![0x5a; 32],
            proof_of_relationship: Some(ProofOfRelationship::sd_jwt(&presentation)),
            ..Default::default()
        },
        &Ed25519Signer::new(workload_pair, "spiffe://acme/outsider"),
        None,
    )
    .expect("the candidate builds");

    let (status, body) = post_token(&lab.router, advancement_body(&candidate.token)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error_description"]
            .as_str()
            .expect("a description")
            .contains("conformance"),
        "unexpected rejection: {body}"
    );
    assert!(
        lab.audit
            .events()
            .iter()
            .any(|event| event.action == "pic.exchange.rejected"
                && event.subject_kind == "continuity"
                && event.continuity_position == Some(1)),
        "rejected advancement was not audited"
    );
}

#[tokio::test]
async fn a_presentation_that_discloses_nothing_the_contract_constrains_is_rejected() {
    let lab = lab().await;
    let (_, body) = post_token(
        &lab.router,
        initialization_body(&lab.provider.access_token()),
    )
    .await;
    let token0 = body["access_token"].as_str().expect("token 0").to_owned();
    let (pca0_bytes, _) = checkpoint_of(&token0);

    // Attested, but silent about `corporation`: the credential proves a relationship and nothing
    // about whether this workload may run in this lineage.
    let workload_pair = ed25519_dalek::SigningKey::from_bytes(&[0x66; 32]);
    let presentation = lab
        .attester
        .presentation_silent(workload_pair.verifying_key().as_bytes());
    let candidate = build_candidate(
        &pca0_bytes,
        CandidateRequest {
            next_challenge: vec![0x5a; 32],
            proof_of_relationship: Some(ProofOfRelationship::sd_jwt(&presentation)),
            ..Default::default()
        },
        &Ed25519Signer::new(workload_pair, "spiffe://acme/quiet"),
        None,
    )
    .expect("the candidate builds");

    let (status, body) = post_token(&lab.router, advancement_body(&candidate.token)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error_description"]
            .as_str()
            .expect("a description")
            .contains("conformance"),
        "unexpected rejection: {body}"
    );
}

#[tokio::test]
async fn a_presentation_that_discloses_only_part_of_the_contract_is_rejected() {
    let lab = lab().await;
    let (_, body) = post_token(
        &lab.router,
        initialization_body(&lab.provider.access_token()),
    )
    .await;
    let token0 = body["access_token"].as_str().expect("token 0").to_owned();
    let (pca0_bytes, _) = checkpoint_of(&token0);

    // `corporation` agrees, but `department` is also in the execution contract and must be proven.
    let workload_pair = ed25519_dalek::SigningKey::from_bytes(&[0x67; 32]);
    let presentation = lab
        .attester
        .presentation_corporation_only(workload_pair.verifying_key().as_bytes());
    let candidate = build_candidate(
        &pca0_bytes,
        CandidateRequest {
            next_challenge: vec![0x5a; 32],
            proof_of_relationship: Some(ProofOfRelationship::sd_jwt(&presentation)),
            ..Default::default()
        },
        &Ed25519Signer::new(workload_pair, "spiffe://acme/partial"),
        None,
    )
    .expect("the candidate builds");

    let (status, body) = post_token(&lab.router, advancement_body(&candidate.token)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error_description"]
            .as_str()
            .expect("a description")
            .contains("conformance"),
        "unexpected rejection: {body}"
    );
}

#[tokio::test]
async fn no_token_is_issued_when_the_audit_trail_cannot_be_written() {
    // The whole point of a synchronous record: authority does not reach a caller unless the trail
    // that says who obtained it was written first.
    let attester = Attester::new();
    let provider = serve_identity_provider().await;
    let jwks_uri = serve_key_set(attester.key_set()).await;
    let realms = Realms::new([realm_with_broken_trail(&jwks_uri, &provider.issuer)]);

    let service = WellKnownService::new();
    let router = service.router(
        &ProductIdentity::new("demo-x", "Demo X", "A tagline", "Demo X CLI", "<art>"),
        &development_config(),
        &realms,
    );
    service.refresh_attester_keys().await;

    let (status, body) = post_token(&router, initialization_body(&provider.access_token())).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        body["error_description"]
            .as_str()
            .expect("a description")
            .contains("not recorded"),
        "{body}"
    );
    assert!(body["access_token"].is_null(), "a token escaped: {body}");
}

#[tokio::test]
async fn a_transition_that_repeats_the_challenge_it_answers_is_rejected() {
    // Answering a challenge with the same value advances the lineage without moving its challenge
    // state, so the successor would accept the very transition that produced it.
    let lab = lab().await;
    let (_, body) = post_token(
        &lab.router,
        initialization_body(&lab.provider.access_token()),
    )
    .await;
    let token0 = body["access_token"].as_str().expect("token 0").to_owned();
    let (pca0_bytes, pca0) = checkpoint_of(&token0);

    let workload_pair = ed25519_dalek::SigningKey::from_bytes(&[0x5c; 32]);
    let presentation = lab
        .attester
        .presentation(workload_pair.verifying_key().as_bytes());
    let candidate = build_candidate(
        &pca0_bytes,
        CandidateRequest {
            // The same bytes the checkpoint is waiting to be answered with.
            next_challenge: pca0.challenge.next_challenge.clone(),
            proof_of_relationship: Some(ProofOfRelationship::sd_jwt(&presentation)),
            ..Default::default()
        },
        &Ed25519Signer::new(workload_pair, "spiffe://acme/replayer"),
        None,
    )
    .expect("the candidate builds");

    let (status, body) = post_token(&lab.router, advancement_body(&candidate.token)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error_description"]
            .as_str()
            .expect("a description")
            .contains("repeats the challenge"),
        "unexpected rejection: {body}"
    );
}
