//! Profile 0.2 centralized advancement, end to end through the realm token endpoint.
//!
//! OAuth access token → PIC Token JWT 0 → a workload-signed candidate carrying an issuer-signed
//! SD-JWT Proof of Relationship → PIC Token JWT 1, with the read authority attenuated away.
//!
//! Nothing here is stubbed at the trust boundary: a real attester signs a real SD-JWT presentation,
//! served from a real key-set endpoint the realm fetches over HTTP, and the workload signs the three
//! candidate artifacts with the key that credential binds.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::digest::{SHA256, digest};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use tower::ServiceExt;

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

#[derive(Debug)]
struct SilentSink;

impl pic_x_core::AuditSink for SilentSink {
    fn name(&self) -> &'static str {
        "silent"
    }

    fn record<'a>(
        &'a self,
        _event: &'a AuditEvent<'a>,
        _policy: Option<&'a dyn Pseudonymizer>,
    ) -> BoxFuture<'a, AuditResult<()>> {
        Box::pin(async { Ok(()) })
    }
}

/// The realm signing key. Settlement never verifies its own past signatures — a checkpoint is
/// trusted by exact bytes — so a deterministic stand-in keeps the test about the flow.
#[derive(Debug)]
struct FakeKeys;

impl KeyManager for FakeKeys {
    fn name(&self) -> &'static str {
        "fake"
    }

    fn public_keys(&self) -> pic_x_core::keys::Result<Vec<Jwk>> {
        Ok(Vec::new())
    }

    fn active_key_id(&self) -> pic_x_core::keys::Result<KeyId> {
        Ok(KeyId::new("realm-key-1"))
    }

    fn sign(&self, _payload: &[u8]) -> pic_x_core::keys::Result<Signature> {
        Ok(Signature::new(
            KeyId::new("realm-key-1"),
            "EdDSA",
            vec![0x42; 64],
        ))
    }

    fn maintain(&self) -> pic_x_core::keys::Result<Maintenance> {
        Ok(Maintenance::default())
    }
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn compact_jwt(header: serde_json::Value, payload: serde_json::Value) -> String {
    format!(
        "{}.{}.{}",
        b64(&serde_json::to_vec(&header).expect("header")),
        b64(&serde_json::to_vec(&payload).expect("payload")),
        b64(b"signature")
    )
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
        let disclosures = [
            b64(
                serde_json::json!(["f0UUCvMSycSUXaVfuiDWAA", "corporation", "ACME"])
                    .to_string()
                    .as_bytes(),
            ),
            b64(serde_json::json!([
                "E54m03bpDTSeWfZOQ-1wVw",
                "department",
                "sensitive-documents"
            ])
            .to_string()
            .as_bytes()),
        ];
        let digests: Vec<String> = disclosures
            .iter()
            .map(|d| b64(digest(&SHA256, d.as_bytes()).as_ref()))
            .collect();

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

        let mut presentation = format!("{signing_input}.{}", b64(signature.as_ref()));
        for disclosure in &disclosures {
            presentation.push('~');
            presentation.push_str(disclosure);
        }
        presentation.push('~');

        presentation
    }
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

fn exchange_profile() -> ExchangeProfileConfig {
    ExchangeProfileConfig {
        id: "test-oauth-to-pic".to_owned(),
        source: ExchangeProfileSource {
            token_type: EXCHANGE_SOURCE_OAUTH_ACCESS_TOKEN.to_owned(),
            format: EXCHANGE_SOURCE_FORMAT_JWT.to_owned(),
            issuer: "https://idp.example.com".to_owned(),
            audience: "pic-x".to_owned(),
            validation: ExchangeTokenValidation {
                allowed_algorithms: vec!["RS256".to_owned()],
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

fn realm_trusting(jwks_uri: &str) -> Realm {
    Realm::new(
        "acme",
        "/realms/acme".to_owned(),
        Some("https://pic-x.example.com/realms/acme".to_owned()),
        true,
        None,
        Some(Arc::new(FakeKeys)),
        Arc::new(SilentSink),
        None,
    )
    .with_exchange_profiles([exchange_profile()])
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

fn initialization_body() -> String {
    let access_token = compact_jwt(
        serde_json::json!({"alg": "RS256", "typ": "JWT", "kid": "idp-key-1"}),
        serde_json::json!({
            "iss": "https://idp.example.com",
            "sub": "user-123",
            "aud": "pic-x",
            "iat": 1_786_700_400_i64,
            "exp": 4_000_000_000_i64,
            "scope": "documents:read:document-42 storage:save"
        }),
    );
    let proposal = pic::continuity::proposal::InitialContinuityProposal::new(
        [(
            "corporation".to_owned(),
            pic::continuity::authority::AuthorityValue::One("ACME".to_owned()),
        )]
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

/// The exact signed PIC PCA COSE bytes a settled token carries, and the checkpoint they decode to.
fn checkpoint_of(token: &str) -> (Vec<u8>, PicPcaPayload) {
    let payload = token.split('.').nth(1).expect("the token has a payload");
    let claims: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("base64url"))
            .expect("the payload is JSON");
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
}

async fn lab() -> Lab {
    let attester = Attester::new();
    let jwks_uri = serve_key_set(attester.key_set()).await;
    let realms = Realms::new([realm_trusting(&jwks_uri)]);
    let config = development_config();

    let service = WellKnownService::new();
    let router = service.router(
        &ProductIdentity::new("demo-x", "Demo X", "A tagline", "Demo X CLI", "<art>"),
        &config,
        &realms,
    );
    // The realm fetches the attester key set the way the background task would.
    service.refresh_attester_keys().await;

    Lab { router, attester }
}

#[tokio::test]
async fn a_workload_advances_the_lineage_and_the_removed_authority_is_gone() {
    let lab = lab().await;

    // OAuth authority becomes checkpoint 0, carrying both invariants.
    let (status, body) = post_token(&lab.router, initialization_body()).await;
    assert_eq!(status, StatusCode::OK, "initialization failed: {body}");
    let token0 = body["access_token"].as_str().expect("token 0").to_owned();
    let (pca0_bytes, pca0) = checkpoint_of(&token0);
    assert_eq!(pca0.position, 0);
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
    assert_eq!(pca1.position, 1);
    // The read authority is gone, storage:save survives and is re-indexed to 0.
    assert_eq!(pca1.context_of_authority.invariants.len(), 1);
    assert_eq!(pca1.context_of_authority.invariants[&0].0, "storage:save");
    // The accepted transition's challenge became the new checkpoint's.
    assert_eq!(pca1.challenge.next_challenge, vec![0x5a; 32]);
    // The execution contract carried forward untouched.
    assert_eq!(pca1.context_of_authority.execution_contract.len(), 1);
}

#[tokio::test]
async fn a_candidate_whose_por_names_an_unconfigured_issuer_is_rejected() {
    let lab = lab().await;
    let (_, body) = post_token(&lab.router, initialization_body()).await;
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
    let (_, body) = post_token(&lab.router, initialization_body()).await;
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
    let (_, body) = post_token(&lab.router, initialization_body()).await;
    let token0 = body["access_token"].as_str().expect("token 0").to_owned();

    // Profile 0.2 PIC-to-PIC advancement omits it; sending one is a request error.
    let (status, _) = post_token(
        &lab.router,
        format!("{}&continuity_proposal=abc", advancement_body(&token0)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
