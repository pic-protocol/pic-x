use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};

const SERVICE: &str = "trust-lab";
const DEFAULT_PUBLIC_URL: &str = "http://localhost:17080";
const DEFAULT_ARTIFACT_DIR: &str = ".volume/trust-lab/artifacts";
const DEFAULT_CONFIG_PATH: &str = "trust-lab/config.lab.json";
const DEFAULT_ATTESTER_ID: &str = "acme-por-attester";
const DEFAULT_KEY_ID: &str = "lab-attester-ed25519-1";
const PROOF_TYPE_SD_JWT: &str = "sd-jwt";
const FORMAT_SD_JWT: &str = "sd-jwt";
const PROFILE: &str = "https://pic-protocol.org/profiles/0.2";
/// Salt entropy per disclosure. RFC 9901 asks for at least 128 bits.
const SALT_BYTES: usize = 16;
/// Bounds on an issuance request, so a lab service cannot be pushed into arbitrary work.
const MAX_CLAIMS: usize = 64;
const MAX_CLAIM_LENGTH: usize = 512;
const DEFAULT_VALIDITY_SECONDS: u64 = 3_600;
const MAX_VALIDITY_SECONDS: u64 = 86_400;
/// This service issues credentials to anyone who asks, for any key, without authenticating the
/// caller or checking that it holds the matching private key. That is the point of a lab fixture
/// and the reason it must never stand in for a real attestation issuer.
const FIXTURE_WARNING: &str = "local fixture for the PIC-X lab; not a production attestation issuer";

#[derive(Debug, Serialize)]
struct BaseResponse {
    service: &'static str,
    status: &'static str,
    message: &'static str,
    attesters_endpoint: &'static str,
    artifact_dir: String,
}

#[derive(Debug, Clone)]
struct LabState {
    artifact_dir: PathBuf,
    attesters: Arc<BTreeMap<String, AttesterRuntime>>,
}

#[derive(Debug, Clone)]
struct AttesterRuntime {
    id: String,
    issuer: String,
    jwks_uri: String,
    presentation_endpoint: String,
    credentials_endpoint: String,
    configuration_endpoint: String,
    key: Jwk,
    key_id: String,
    signing_key: Arc<Ed25519KeyPair>,
    workers: BTreeMap<String, WorkerArtifact>,
}

#[derive(Debug, Clone)]
struct WorkerArtifact {
    manifest: WorkerManifest,
    presentation: String,
    processed_payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LabConfig {
    #[serde(default)]
    public_url: Option<String>,
    #[serde(default)]
    artifact_dir: Option<String>,
    #[serde(default)]
    attesters: Vec<AttesterConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AttesterConfig {
    id: String,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    key_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct AttestersResponse {
    service: &'static str,
    attesters: Vec<AttesterSummary>,
}

#[derive(Debug, Serialize)]
struct AttesterSummary {
    id: String,
    issuer: String,
    configuration_endpoint: String,
    jwks_uri: String,
    presentation_endpoint: String,
    credentials_endpoint: String,
}

/// A request to issue a credential for a caller-supplied key and claim set.
///
/// This is what makes the lab attester usable beyond the two walkthrough fixtures: a workload
/// generates its own key pair, asks for a credential bound to its public half, and receives every
/// Disclosure so it — as the RFC 9901 Holder — decides which ones to present per hop.
#[derive(Debug, Deserialize)]
struct CredentialRequest {
    /// The workload public key to bind, as an RFC 7517 JWK. It lands in `cnf.jwk`, which is the
    /// claim PIC-X reads to obtain the key that must verify the three candidate signatures.
    cnf_jwk: serde_json::Value,
    /// Attributes to issue as selectively disclosable claims.
    claims: BTreeMap<String, String>,
    #[serde(default)]
    validity_seconds: Option<u64>,
}

#[derive(Debug, Serialize)]
struct CredentialResponse {
    issuer: String,
    proof_of_relationship_type: &'static str,
    format: &'static str,
    issuer_signed_jwt: String,
    /// Every issued Disclosure, so the Holder can choose. Only the ones it joins into a
    /// presentation ever reach a verifier.
    disclosures: Vec<IssuedDisclosure>,
    /// Convenience: the presentation carrying *all* Disclosures. A workload that wants selective
    /// disclosure builds its own from the list above instead of sending this one.
    presentation_all_disclosed: String,
    expires_at: u64,
    fixture: bool,
    fixture_warning: &'static str,
}

#[derive(Debug, Serialize)]
struct IssuedDisclosure {
    claim: String,
    value: String,
    /// The Base64url Disclosure string: this exact text is what a presentation carries.
    disclosure: String,
    /// Its SHA-256 digest, as committed in the credential's `_sd` array.
    digest: String,
}

#[derive(Debug, Serialize)]
struct AttesterConfiguration {
    issuer: String,
    jwks_uri: String,
    presentation_endpoint: String,
    credentials_endpoint: String,
    proof_types_supported: [&'static str; 1],
    formats_supported: [&'static str; 1],
    profile: &'static str,
    fixture: bool,
    fixture_warning: &'static str,
    artifacts: Vec<WorkerManifest>,
}

#[derive(Debug, Clone, Serialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Serialize)]
struct Jwk {
    kid: String,
    kty: &'static str,
    crv: &'static str,
    alg: &'static str,
    #[serde(rename = "use")]
    usage: &'static str,
    x: String,
}

#[derive(Debug, Default, Deserialize)]
struct PresentationRequest {
    #[serde(default)]
    subject: Option<String>,
}

#[derive(Debug, Serialize)]
struct PresentationResponse {
    issuer: String,
    subject: String,
    proof_of_relationship_type: &'static str,
    format: &'static str,
    presentation: String,
    processed_payload: serde_json::Value,
    artifact: WorkerManifest,
    note: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct WorkerManifest {
    worker_id: &'static str,
    role: &'static str,
    issuer: String,
    proof_of_relationship_type: &'static str,
    format: &'static str,
    issued_selectively_disclosable_attributes: usize,
    presented_disclosures: Vec<&'static str>,
    undisclosed_disclosures: Vec<&'static str>,
    files: ArtifactFiles,
    note: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct ArtifactFiles {
    issuer_signed_jwt: String,
    presentation: String,
    processed_payload: String,
    manifest: String,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: &'static str,
    error_description: String,
}

#[derive(Clone, Copy)]
struct WorkerDefinition {
    id: &'static str,
    role: &'static str,
    iat: u64,
    exp: u64,
    key: WorkloadKey,
    sd_digests: &'static [&'static str],
    selected_disclosures: &'static [Disclosure],
    undisclosed_disclosures: &'static [&'static str],
}

#[derive(Clone, Copy)]
struct WorkloadKey {
    kid: &'static str,
    x: &'static str,
    y: &'static str,
}

#[derive(Clone, Copy)]
struct Disclosure {
    claim: &'static str,
    value: &'static str,
    encoded: &'static str,
}

type ApiResult<T> = Result<Json<T>, (StatusCode, Json<ErrorResponse>)>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let bind = env::var("TRUST_LAB_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:7080".to_string());
    let config = load_config()?;
    let router = app(config)?;

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    eprintln!("{SERVICE} listening on {bind}");

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

fn app(config: LabConfig) -> Result<Router, Box<dyn Error>> {
    let state = prepare_state(config)?;

    Ok(Router::new()
        .route("/", get(index))
        .route("/attesters", get(attesters))
        .route(
            "/attesters/{attester_id}/.well-known/attester-configuration",
            get(attester_configuration),
        )
        .route("/attesters/{attester_id}/jwks.json", get(attester_jwks))
        .route(
            "/attesters/{attester_id}/presentations/{worker_id}",
            get(worker_presentation),
        )
        .route(
            "/attesters/{attester_id}/presentations",
            post(create_presentation),
        )
        .route(
            "/attesters/{attester_id}/credentials",
            post(create_credential),
        )
        .with_state(state))
}

fn load_config() -> Result<LabConfig, Box<dyn Error>> {
    let path = env::var("TRUST_LAB_CONFIG").unwrap_or_else(|_| DEFAULT_CONFIG_PATH.to_owned());
    let mut config = match fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str::<LabConfig>(&text)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => LabConfig::default(),
        Err(error) => return Err(Box::new(error)),
    };

    if let Ok(public_url) = env::var("TRUST_LAB_PUBLIC_URL") {
        config.public_url = Some(public_url);
    }
    if let Ok(artifact_dir) = env::var("TRUST_LAB_ARTIFACT_DIR") {
        config.artifact_dir = Some(artifact_dir);
    }
    if config.attesters.is_empty() {
        config.attesters.push(AttesterConfig {
            id: DEFAULT_ATTESTER_ID.to_owned(),
            path: None,
            key_id: Some(DEFAULT_KEY_ID.to_owned()),
        });
    }

    Ok(config)
}

fn prepare_state(config: LabConfig) -> Result<LabState, Box<dyn Error>> {
    let public_url = config
        .public_url
        .unwrap_or_else(|| DEFAULT_PUBLIC_URL.to_owned())
        .trim_end_matches('/')
        .to_owned();
    let artifact_dir = PathBuf::from(
        config
            .artifact_dir
            .unwrap_or_else(|| DEFAULT_ARTIFACT_DIR.to_owned()),
    );
    let mut attesters = BTreeMap::new();

    for configured in config.attesters {
        let runtime = prepare_attester(&public_url, &artifact_dir, configured)?;
        attesters.insert(runtime.id.clone(), runtime);
    }

    Ok(LabState {
        artifact_dir,
        attesters: Arc::new(attesters),
    })
}

fn prepare_attester(
    public_url: &str,
    artifact_dir: &Path,
    configured: AttesterConfig,
) -> Result<AttesterRuntime, Box<dyn Error>> {
    let id = configured.id;
    let key_id = configured
        .key_id
        .unwrap_or_else(|| DEFAULT_KEY_ID.to_owned());
    let path = configured
        .path
        .unwrap_or_else(|| format!("/attesters/{id}"));
    let issuer = format!("{public_url}{}", path.trim_end_matches('/'));
    let configuration_endpoint = format!("{issuer}/.well-known/attester-configuration");
    let jwks_uri = format!("{issuer}/jwks.json");
    let presentation_endpoint = format!("{issuer}/presentations");
    let credentials_endpoint = format!("{issuer}/credentials");
    let attester_dir = artifact_dir.join("attesters").join(&id);
    fs::create_dir_all(&attester_dir)?;

    let key_path = attester_dir.join("issuer-ed25519.pkcs8");
    let pair = load_or_create_key(&key_path)?;
    let key = Jwk {
        kid: key_id.clone(),
        kty: "OKP",
        crv: "Ed25519",
        alg: "EdDSA",
        usage: "sig",
        x: b64url(pair.public_key().as_ref()),
    };

    write_json(
        &attester_dir.join("jwks.json"),
        &JwkSet {
            keys: vec![key.clone()],
        },
    )?;

    let mut worker_artifacts = BTreeMap::new();
    for worker in workers() {
        let artifact =
            prepare_worker_artifact(artifact_dir, &attester_dir, &issuer, &key_id, &pair, worker)?;
        worker_artifacts.insert(worker.id.to_owned(), artifact);
    }

    Ok(AttesterRuntime {
        id,
        issuer,
        jwks_uri,
        presentation_endpoint,
        credentials_endpoint,
        configuration_endpoint,
        key,
        key_id,
        signing_key: Arc::new(pair),
        workers: worker_artifacts,
    })
}

fn prepare_worker_artifact(
    artifact_dir: &Path,
    attester_dir: &Path,
    issuer: &str,
    key_id: &str,
    pair: &Ed25519KeyPair,
    worker: WorkerDefinition,
) -> Result<WorkerArtifact, Box<dyn Error>> {
    let worker_dir = attester_dir.join("workers").join(worker.id);
    fs::create_dir_all(&worker_dir)?;

    let issuer_signed_jwt = sign_sd_jwt_credential(issuer, key_id, pair, worker)?;
    let presentation = format!(
        "{}~{}~{}~",
        issuer_signed_jwt,
        worker.selected_disclosures[0].encoded,
        worker.selected_disclosures[1].encoded
    );
    let processed_payload = processed_payload(issuer, worker);
    let files = ArtifactFiles {
        issuer_signed_jwt: relative_artifact_path(
            artifact_dir,
            &worker_dir.join("issuer-signed.jwt"),
        ),
        presentation: relative_artifact_path(artifact_dir, &worker_dir.join("presentation.sd-jwt")),
        processed_payload: relative_artifact_path(
            artifact_dir,
            &worker_dir.join("processed-payload.json"),
        ),
        manifest: relative_artifact_path(artifact_dir, &worker_dir.join("manifest.json")),
    };
    let manifest = WorkerManifest {
        worker_id: worker.id,
        role: worker.role,
        issuer: issuer.to_owned(),
        proof_of_relationship_type: PROOF_TYPE_SD_JWT,
        format: FORMAT_SD_JWT,
        issued_selectively_disclosable_attributes: worker.sd_digests.len(),
        presented_disclosures: worker
            .selected_disclosures
            .iter()
            .map(|disclosure| disclosure.claim)
            .collect(),
        undisclosed_disclosures: worker.undisclosed_disclosures.to_vec(),
        files,
        note: "Only the selected disclosure strings are present in presentation.sd-jwt; omitted disclosures are not written into the presentation.",
    };

    fs::write(worker_dir.join("issuer-signed.jwt"), &issuer_signed_jwt)?;
    fs::write(worker_dir.join("presentation.sd-jwt"), &presentation)?;
    write_json(
        &worker_dir.join("processed-payload.json"),
        &processed_payload,
    )?;
    write_json(&worker_dir.join("manifest.json"), &manifest)?;

    let issued = serde_json::json!({
        "issued_selectively_disclosable_attributes": worker.sd_digests.len(),
        "presented": worker.selected_disclosures.iter().map(|disclosure| disclosure.claim).collect::<Vec<_>>(),
        "not_presented": worker.undisclosed_disclosures,
        "selected_disclosure_strings": worker.selected_disclosures.iter().map(|disclosure| {
            serde_json::json!({
                "claim": disclosure.claim,
                "value": disclosure.value,
                "disclosure": disclosure.encoded,
            })
        }).collect::<Vec<_>>(),
    });
    write_json(&worker_dir.join("issued-disclosures-summary.json"), &issued)?;

    Ok(WorkerArtifact {
        manifest,
        presentation,
        processed_payload,
    })
}

async fn index(State(state): State<LabState>) -> Json<BaseResponse> {
    Json(BaseResponse {
        service: SERVICE,
        status: "ok",
        message: "public trust lab API",
        attesters_endpoint: "/attesters",
        artifact_dir: state.artifact_dir.display().to_string(),
    })
}

async fn attesters(State(state): State<LabState>) -> Json<AttestersResponse> {
    Json(AttestersResponse {
        service: SERVICE,
        attesters: state.attesters.values().map(attester_summary).collect(),
    })
}

async fn attester_configuration(
    AxumPath(attester_id): AxumPath<String>,
    State(state): State<LabState>,
) -> ApiResult<AttesterConfiguration> {
    let attester = require_attester(&state, &attester_id)?;

    Ok(Json(AttesterConfiguration {
        issuer: attester.issuer.clone(),
        jwks_uri: attester.jwks_uri.clone(),
        presentation_endpoint: attester.presentation_endpoint.clone(),
        credentials_endpoint: attester.credentials_endpoint.clone(),
        proof_types_supported: [PROOF_TYPE_SD_JWT],
        formats_supported: [FORMAT_SD_JWT],
        profile: PROFILE,
        fixture: true,
        fixture_warning: FIXTURE_WARNING,
        artifacts: attester
            .workers
            .values()
            .map(|artifact| artifact.manifest.clone())
            .collect(),
    }))
}

async fn attester_jwks(
    AxumPath(attester_id): AxumPath<String>,
    State(state): State<LabState>,
) -> ApiResult<JwkSet> {
    let attester = require_attester(&state, &attester_id)?;

    Ok(Json(JwkSet {
        keys: vec![attester.key.clone()],
    }))
}

async fn worker_presentation(
    AxumPath((attester_id, worker_id)): AxumPath<(String, String)>,
    State(state): State<LabState>,
) -> ApiResult<PresentationResponse> {
    presentation_for(&state, &attester_id, &worker_id)
}

async fn create_presentation(
    AxumPath(attester_id): AxumPath<String>,
    State(state): State<LabState>,
    Json(request): Json<PresentationRequest>,
) -> ApiResult<PresentationResponse> {
    presentation_for(
        &state,
        &attester_id,
        request.subject.as_deref().unwrap_or("worker-1"),
    )
}

fn presentation_for(
    state: &LabState,
    attester_id: &str,
    worker_id: &str,
) -> ApiResult<PresentationResponse> {
    let attester = require_attester(state, attester_id)?;
    let Some(artifact) = attester.workers.get(worker_id) else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "unknown_worker",
                error_description: format!("attester `{attester_id}` has no worker `{worker_id}`"),
            }),
        ));
    };

    Ok(Json(PresentationResponse {
        issuer: attester.issuer.clone(),
        subject: artifact.manifest.worker_id.to_owned(),
        proof_of_relationship_type: PROOF_TYPE_SD_JWT,
        format: FORMAT_SD_JWT,
        presentation: artifact.presentation.clone(),
        processed_payload: artifact.processed_payload.clone(),
        artifact: artifact.manifest.clone(),
        note: "The presentation string is the exact UTF-8 value a future PIC transition would carry as proof_of_relationship.evidence.",
    }))
}

fn attester_summary(attester: &AttesterRuntime) -> AttesterSummary {
    AttesterSummary {
        id: attester.id.clone(),
        issuer: attester.issuer.clone(),
        configuration_endpoint: attester.configuration_endpoint.clone(),
        jwks_uri: attester.jwks_uri.clone(),
        presentation_endpoint: attester.presentation_endpoint.clone(),
        credentials_endpoint: attester.credentials_endpoint.clone(),
    }
}

fn require_attester<'a>(
    state: &'a LabState,
    attester_id: &str,
) -> Result<&'a AttesterRuntime, (StatusCode, Json<ErrorResponse>)> {
    state.attesters.get(attester_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "unknown_attester",
                error_description: format!("trust-lab has no attester `{attester_id}`"),
            }),
        )
    })
}

/// Issues a credential bound to a caller-supplied key, with caller-supplied claims.
///
/// Every claim becomes a selectively disclosable Disclosure with its own fresh CSPRNG salt, and the
/// credential commits only to the digests. The Disclosures go back to the caller, never into the
/// issuer-signed JWT.
async fn create_credential(
    AxumPath(attester_id): AxumPath<String>,
    State(state): State<LabState>,
    Json(request): Json<CredentialRequest>,
) -> ApiResult<CredentialResponse> {
    let attester = require_attester(&state, &attester_id)?;
    validate_credential_request(&request)?;

    let issued = issue_disclosures(&request.claims).map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "issuance_failed",
                error_description: error.to_string(),
            }),
        )
    })?;

    let issued_at = unix_now().map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "issuance_failed",
                error_description: error.to_string(),
            }),
        )
    })?;
    let expires_at = issued_at
        + request
            .validity_seconds
            .unwrap_or(DEFAULT_VALIDITY_SECONDS)
            .min(MAX_VALIDITY_SECONDS);

    // Sorted so that the order of the commitments says nothing about the order of the claims.
    let mut digests: Vec<&str> = issued
        .iter()
        .map(|disclosure| disclosure.digest.as_str())
        .collect();
    digests.sort_unstable();

    let payload = serde_json::json!({
        "iss": attester.issuer,
        "iat": issued_at,
        "exp": expires_at,
        "_sd_alg": "sha-256",
        "_sd": digests,
        "cnf": { "jwk": request.cnf_jwk },
    });
    let issuer_signed_jwt = sign_compact_jws(
        &attester.key_id,
        &attester.signing_key,
        &payload,
    )
    .map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "issuance_failed",
                error_description: error.to_string(),
            }),
        )
    })?;

    let mut presentation = issuer_signed_jwt.clone();
    for disclosure in &issued {
        presentation.push('~');
        presentation.push_str(&disclosure.disclosure);
    }
    presentation.push('~');

    Ok(Json(CredentialResponse {
        issuer: attester.issuer.clone(),
        proof_of_relationship_type: PROOF_TYPE_SD_JWT,
        format: FORMAT_SD_JWT,
        issuer_signed_jwt,
        disclosures: issued,
        presentation_all_disclosed: presentation,
        expires_at,
        fixture: true,
        fixture_warning: FIXTURE_WARNING,
    }))
}

/// Rejects a request the lab will not issue for: no claims, empty names or values, oversized input.
fn validate_credential_request(
    request: &CredentialRequest,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let reject = |description: String| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_request",
                error_description: description,
            }),
        )
    };

    let jwk = request
        .cnf_jwk
        .as_object()
        .ok_or_else(|| reject("`cnf_jwk` must be a JWK object".to_owned()))?;
    match jwk.get("kty").and_then(serde_json::Value::as_str) {
        Some("EC") | Some("OKP") => {}
        Some(other) => return Err(reject(format!("unsupported `cnf_jwk.kty` `{other}`"))),
        None => return Err(reject("`cnf_jwk` has no `kty`".to_owned())),
    }
    for required in ["crv", "x"] {
        if !jwk.contains_key(required) {
            return Err(reject(format!("`cnf_jwk` has no `{required}`")));
        }
    }
    if jwk.get("kty").and_then(serde_json::Value::as_str) == Some("EC")
        && !jwk.contains_key("y")
    {
        return Err(reject("an EC `cnf_jwk` has no `y`".to_owned()));
    }
    if jwk.contains_key("d") {
        return Err(reject(
            "`cnf_jwk` carries a private key component `d`; send the public key only".to_owned(),
        ));
    }

    if request.claims.is_empty() {
        return Err(reject("`claims` must carry at least one attribute".to_owned()));
    }
    if request.claims.len() > MAX_CLAIMS {
        return Err(reject(format!("`claims` carries more than {MAX_CLAIMS} attributes")));
    }
    for (name, value) in &request.claims {
        if name.is_empty() || value.is_empty() {
            return Err(reject(
                "claim names and values must be non-empty strings".to_owned(),
            ));
        }
        if name.len() > MAX_CLAIM_LENGTH || value.len() > MAX_CLAIM_LENGTH {
            return Err(reject(format!(
                "claim `{name}` exceeds {MAX_CLAIM_LENGTH} characters"
            )));
        }
    }

    Ok(())
}

/// Builds one Disclosure per claim: a fresh salt, the RFC 9901 `[salt, name, value]` array, its
/// Base64url encoding, and the SHA-256 digest committed in `_sd`.
fn issue_disclosures(
    claims: &BTreeMap<String, String>,
) -> Result<Vec<IssuedDisclosure>, Box<dyn Error>> {
    let random = SystemRandom::new();
    let mut issued = Vec::with_capacity(claims.len());

    for (name, value) in claims {
        let mut salt = [0_u8; SALT_BYTES];
        random
            .fill(&mut salt)
            .map_err(|_| "generating a disclosure salt")?;
        let contents = serde_json::to_string(&serde_json::json!([b64url(&salt), name, value]))?;
        let disclosure = b64url(contents.as_bytes());
        let digest_value = b64url(digest(&SHA256, disclosure.as_bytes()).as_ref());

        issued.push(IssuedDisclosure {
            claim: name.clone(),
            value: value.clone(),
            disclosure,
            digest: digest_value,
        });
    }

    Ok(issued)
}

fn sign_compact_jws(
    key_id: &str,
    pair: &Ed25519KeyPair,
    payload: &serde_json::Value,
) -> Result<String, Box<dyn Error>> {
    let header = serde_json::json!({
        "alg": "EdDSA",
        "kid": key_id,
        "typ": "vc+sd-jwt"
    });
    let signing_input = format!(
        "{}.{}",
        b64url(compact_json(&header)?.as_bytes()),
        b64url(compact_json(payload)?.as_bytes())
    );
    let signature = pair.sign(signing_input.as_bytes());

    Ok(format!("{}.{}", signing_input, b64url(signature.as_ref())))
}

fn unix_now() -> Result<u64, Box<dyn Error>> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn sign_sd_jwt_credential(
    issuer: &str,
    key_id: &str,
    pair: &Ed25519KeyPair,
    worker: WorkerDefinition,
) -> Result<String, Box<dyn Error>> {
    let header = serde_json::json!({
        "alg": "EdDSA",
        "kid": key_id,
        "typ": "vc+sd-jwt"
    });
    let payload = serde_json::json!({
        "iss": issuer,
        "iat": worker.iat,
        "exp": worker.exp,
        "_sd_alg": "sha-256",
        "_sd": worker.sd_digests,
        "cnf": {
            "jwk": workload_key(worker.key)
        }
    });
    let signing_input = format!(
        "{}.{}",
        b64url(compact_json(&header)?.as_bytes()),
        b64url(compact_json(&payload)?.as_bytes())
    );
    let signature = pair.sign(signing_input.as_bytes());

    Ok(format!("{}.{}", signing_input, b64url(signature.as_ref())))
}

fn processed_payload(issuer: &str, worker: WorkerDefinition) -> serde_json::Value {
    let mut payload = serde_json::json!({
        "iss": issuer,
        "iat": worker.iat,
        "exp": worker.exp,
        "cnf": {
            "jwk": workload_key(worker.key)
        }
    });
    if let Some(object) = payload.as_object_mut() {
        for disclosure in worker.selected_disclosures {
            object.insert(
                disclosure.claim.to_owned(),
                serde_json::Value::String(disclosure.value.to_owned()),
            );
        }
    }
    payload
}

fn workload_key(key: WorkloadKey) -> serde_json::Value {
    serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "kid": key.kid,
        "x": key.x,
        "y": key.y
    })
}

fn load_or_create_key(path: &Path) -> Result<Ed25519KeyPair, Box<dyn Error>> {
    if !path.exists() {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|_| "generating the lab attester signing key")?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, pkcs8.as_ref())?;
        restrict_owner_only(path)?;
    }

    let bytes = fs::read(path)?;
    Ed25519KeyPair::from_pkcs8(&bytes).map_err(|_| "reading the lab attester signing key".into())
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

fn relative_artifact_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn compact_json(value: &serde_json::Value) -> Result<String, serde_json::Error> {
    serde_json::to_string(value)
}

fn b64url(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let first = chunk[0];
        let second = *chunk.get(1).unwrap_or(&0);
        let third = *chunk.get(2).unwrap_or(&0);
        let combined = ((first as u32) << 16) | ((second as u32) << 8) | third as u32;

        out.push(TABLE[((combined >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((combined >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((combined >> 6) & 0x3f) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(TABLE[(combined & 0x3f) as usize] as char);
        }
    }

    out
}

#[cfg(test)]
fn b64url_decode(input: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    let mut accumulator: u32 = 0;
    let mut bits = 0_u32;
    let mut out = Vec::with_capacity(input.len() * 3 / 4);

    for byte in input.bytes() {
        let index = TABLE
            .iter()
            .position(|candidate| *candidate == byte)
            .ok_or("value is not unpadded base64url")? as u32;
        accumulator = (accumulator << 6) | index;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((accumulator >> bits) as u8);
        }
    }

    Ok(out)
}

#[cfg(unix)]
fn restrict_owner_only(path: &Path) -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_owner_only(_path: &Path) -> Result<(), Box<dyn Error>> {
    Ok(())
}

fn workers() -> [WorkerDefinition; 2] {
    [worker_1(), worker_2()]
}

fn worker_1() -> WorkerDefinition {
    WorkerDefinition {
        id: "worker-1",
        role: "document-reader",
        iat: 1_786_700_500,
        exp: 1_786_704_100,
        key: WorkloadKey {
            kid: "worker-1-key",
            x: "AbZzIerBJYtaxamji_Z4jT3oAuhAw_p-IPnIHFQ_YsM",
            y: "LxUSbSzHe7-a3WbnZqMTfpRo_2VdTY_ugsn5xW9OWtU",
        },
        sd_digests: &[
            "3CNTPr87PwmN0oW4tNoyswYdsgSUCc6R2B1JSC7I6pI",
            "62rjCYviAli2R9bOU8etQ2DWjOGJETL4L2_Vewqzl8I",
            "6g3ffib_cNuBmTs4R3AyvyGK8dcZIteeRtw8yPAmDCU",
            "POtp4eFO4TReywR0yahpwryzSO_dLgiK6Y8lbmdb7SA",
            "P_9_ewlbKJ-ddpy7LivbSPPCYO219Si_0pAj-iElZJQ",
            "Xn7kw6_wekrrpvjPLcrMOQWwVzvVgSsMla6892-qlx8",
            "cmQs8BFsB9ejZrCaaXNbiq0iZW19oG0bTx-N5wLGm24",
            "mzeyOGQIao4tTM8WvLC-qG2hQa1oxmCYl-wjz7GS0yo",
            "vh7enFAhHilhjEs409goqcE44UWGuIgzcMNhDih_Cgc",
            "yjForVdxBM3AP4GqLrN715bZbnrJ9XqzanJ4WeW5Ru4",
        ],
        selected_disclosures: &[
            Disclosure {
                claim: "corporation",
                value: "ACME",
                encoded: "WyJmMFVVQ3ZNU3ljU1VYYVZmdWlEV0FBIiwiY29ycG9yYXRpb24iLCJBQ01FIl0",
            },
            Disclosure {
                claim: "department",
                value: "sensitive-documents",
                encoded: "WyJFNTRtMDNicERUU2VXZlpPUS0xd1Z3IiwiZGVwYXJ0bWVudCIsInNlbnNpdGl2ZS1kb2N1bWVudHMiXQ",
            },
        ],
        undisclosed_disclosures: &[
            "workload_role",
            "service",
            "clearance",
            "reader_region",
            "deployment_environment",
            "build_id",
            "host_class",
            "internal_cluster",
        ],
    }
}

fn worker_2() -> WorkerDefinition {
    WorkerDefinition {
        id: "worker-2",
        role: "storage-writer",
        iat: 1_786_700_600,
        exp: 1_786_704_200,
        key: WorkloadKey {
            kid: "worker-2-key",
            x: "qVrnRMgFK2zqdeguigyDOcX9p3PzUXTzey5VRIdSKgw",
            y: "BHCfKNUuGjvLYow1uxoz43CpyKKeM1_fXxrnNC3GMqE",
        },
        sd_digests: &[
            "3n0NhmZG6-aCGQ4rmfAzwDSHjdVXK93gl23p0DrE2NE",
            "5jS4X8__1_bsn9BIGOHMFaaSAcrFC4QapluetUD3q9Y",
            "7LZcdUaO9sx9SPw6HOLKucCgsLzgU1lXRUH-cyPMgZA",
            "HLCCyUiFz4hWQc9UEs3CxJ0jJs3aWQsEKCDyu1WDSHk",
            "Q0uqe1mYb0FWc8HHwxrXTAhvDF9r8yHiU68uB5ZhfvI",
            "Qe7z-9SG7SSc4V4XQFsYtAVbBKKma-DkGf2VpVrXf9w",
            "WZL2Zh1LPIk4_CKq8XS8cifzcn9Acflj2kbA-j56R8E",
            "YdzFXlL-LbeoTudnQMtMmjI8jHe6GNQbLDqkXI1SoxA",
            "xjMzpQA6cwywHrkPgKYcSEZ0wiP0WgvPRmElTrAXQfE",
            "yOK0mbTnJYzeTizNrQU683ZcK6C5GtjsHnw_3hwop5E",
        ],
        selected_disclosures: &[
            Disclosure {
                claim: "corporation",
                value: "ACME",
                encoded: "WyJMZllXSWN6VG9MSXNqV3JHZjNCU1d3IiwiY29ycG9yYXRpb24iLCJBQ01FIl0",
            },
            Disclosure {
                claim: "department",
                value: "sensitive-documents",
                encoded: "WyJQakN5bHRGalhidDViN3NyX09IbEhBIiwiZGVwYXJ0bWVudCIsInNlbnNpdGl2ZS1kb2N1bWVudHMiXQ",
            },
        ],
        undisclosed_disclosures: &[
            "workload_role",
            "service",
            "storage_class",
            "storage_region",
            "storage_namespace",
            "retention_profile",
            "replication_mode",
            "internal_cluster",
        ],
    }
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

impl Default for LabConfig {
    fn default() -> Self {
        Self {
            public_url: Some(DEFAULT_PUBLIC_URL.to_owned()),
            artifact_dir: Some(DEFAULT_ARTIFACT_DIR.to_owned()),
            attesters: vec![AttesterConfig {
                id: DEFAULT_ATTESTER_ID.to_owned(),
                path: None,
                key_id: Some(DEFAULT_KEY_ID.to_owned()),
            }],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("trust-lab-{name}"));
        let _ = fs::remove_dir_all(&path);
        path
    }

    #[test]
    fn app_builds_with_the_configured_attester_routes() {
        let config = LabConfig {
            artifact_dir: Some(temp_dir("app").display().to_string()),
            ..LabConfig::default()
        };

        let _ = app(config).expect("app builds");
    }

    #[test]
    fn preparing_state_writes_two_worker_presentations_to_disk() {
        let artifact_dir = temp_dir("artifacts");
        let config = LabConfig {
            artifact_dir: Some(artifact_dir.display().to_string()),
            ..LabConfig::default()
        };
        let state = prepare_state(config).expect("state prepares");
        let attester = state
            .attesters
            .get(DEFAULT_ATTESTER_ID)
            .expect("attester exists");

        assert_eq!(attester.workers.len(), 2);
        for worker in ["worker-1", "worker-2"] {
            let presentation = artifact_dir
                .join("attesters")
                .join(DEFAULT_ATTESTER_ID)
                .join("workers")
                .join(worker)
                .join("presentation.sd-jwt");
            assert!(presentation.exists(), "{presentation:?} was not written");
            let text = fs::read_to_string(presentation).expect("presentation reads");
            assert!(text.ends_with('~'));
            assert_eq!(text.split('~').count(), 4);
        }
    }

    fn sample_request() -> CredentialRequest {
        let mut claims = BTreeMap::new();
        claims.insert("corporation".to_owned(), "ACME".to_owned());
        claims.insert("department".to_owned(), "sensitive-documents".to_owned());

        CredentialRequest {
            cnf_jwk: serde_json::json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": "worker-key",
                "x": "AbZzIerBJYtaxamji_Z4jT3oAuhAw_p-IPnIHFQ_YsM"
            }),
            claims,
            validity_seconds: None,
        }
    }

    #[test]
    fn each_issued_disclosure_commits_to_its_own_digest() {
        let request = sample_request();
        let issued = issue_disclosures(&request.claims).expect("disclosures are issued");

        assert_eq!(issued.len(), 2);
        for disclosure in &issued {
            // The digest committed in `_sd` must be SHA-256 over the Disclosure string itself.
            let expected = b64url(digest(&SHA256, disclosure.disclosure.as_bytes()).as_ref());
            assert_eq!(disclosure.digest, expected);

            // The Disclosure decodes to the RFC 9901 [salt, name, value] array.
            let decoded = b64url_decode(&disclosure.disclosure).expect("disclosure decodes");
            let parts: Vec<String> =
                serde_json::from_slice(&decoded).expect("disclosure is a JSON array");
            assert_eq!(parts.len(), 3);
            assert_eq!(parts[1], disclosure.claim);
            assert_eq!(parts[2], disclosure.value);
            // At least 128 bits of salt, per RFC 9901.
            assert!(b64url_decode(&parts[0]).expect("salt decodes").len() >= 16);
        }
    }

    #[test]
    fn salts_are_fresh_for_every_issuance() {
        let request = sample_request();
        let first = issue_disclosures(&request.claims).expect("first issuance");
        let second = issue_disclosures(&request.claims).expect("second issuance");

        // Same claims, different salts: reusing a salt would let a verifier correlate two
        // credentials, and would make the digests collide across issuances.
        for (left, right) in first.iter().zip(second.iter()) {
            assert_eq!(left.claim, right.claim);
            assert_ne!(left.disclosure, right.disclosure);
            assert_ne!(left.digest, right.digest);
        }
    }

    #[test]
    fn a_credential_request_is_validated_before_anything_is_signed() {
        let mut no_claims = sample_request();
        no_claims.claims.clear();
        assert!(validate_credential_request(&no_claims).is_err());

        let mut empty_value = sample_request();
        empty_value.claims.insert("clearance".to_owned(), String::new());
        assert!(validate_credential_request(&empty_value).is_err());

        let mut private_key = sample_request();
        private_key.cnf_jwk["d"] = serde_json::json!("a-private-scalar");
        assert!(validate_credential_request(&private_key).is_err());

        let mut wrong_kty = sample_request();
        wrong_kty.cnf_jwk = serde_json::json!({"kty": "RSA", "crv": "x", "x": "y"});
        assert!(validate_credential_request(&wrong_kty).is_err());

        let mut ec_without_y = sample_request();
        ec_without_y.cnf_jwk = serde_json::json!({"kty": "EC", "crv": "P-256", "x": "abc"});
        assert!(validate_credential_request(&ec_without_y).is_err());

        assert!(validate_credential_request(&sample_request()).is_ok());
    }

    #[test]
    fn an_issued_credential_verifies_and_hides_its_claim_values() {
        let request = sample_request();
        let issued = issue_disclosures(&request.claims).expect("disclosures are issued");
        let mut digests: Vec<&str> = issued.iter().map(|d| d.digest.as_str()).collect();
        digests.sort_unstable();

        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("key generates");
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("key parses");
        let payload = serde_json::json!({
            "iss": "http://localhost/attesters/lab",
            "_sd_alg": "sha-256",
            "_sd": digests,
            "cnf": { "jwk": request.cnf_jwk },
        });
        let jwt = sign_compact_jws("lab-key", &pair, &payload).expect("credential signs");

        let segments: Vec<&str> = jwt.split('.').collect();
        assert_eq!(segments.len(), 3);

        // The signature verifies against the issuer public key.
        let signing_input = format!("{}.{}", segments[0], segments[1]);
        let signature = b64url_decode(segments[2]).expect("signature decodes");
        ring::signature::UnparsedPublicKey::new(
            &ring::signature::ED25519,
            pair.public_key().as_ref(),
        )
        .verify(signing_input.as_bytes(), &signature)
        .expect("the issuer signature verifies");

        // The credential commits to digests only: no claim name or value is in the signed payload.
        let signed = String::from_utf8(b64url_decode(segments[1]).expect("payload decodes"))
            .expect("payload is UTF-8");
        for disclosure in &issued {
            assert!(!signed.contains(&disclosure.claim));
            assert!(!signed.contains(&disclosure.value));
            assert!(signed.contains(&disclosure.digest));
        }
    }

    #[test]
    fn worker_one_presentation_contains_only_the_selected_disclosures() {
        let artifact_dir = temp_dir("selective");
        let config = LabConfig {
            artifact_dir: Some(artifact_dir.display().to_string()),
            ..LabConfig::default()
        };
        prepare_state(config).expect("state prepares");
        let manifest_path = artifact_dir
            .join("attesters")
            .join(DEFAULT_ATTESTER_ID)
            .join("workers")
            .join("worker-1")
            .join("manifest.json");
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(manifest_path).expect("manifest reads"))
                .expect("manifest parses");

        assert_eq!(
            manifest["issued_selectively_disclosable_attributes"],
            serde_json::json!(10)
        );
        assert_eq!(
            manifest["presented_disclosures"],
            serde_json::json!(["corporation", "department"])
        );
        assert_eq!(
            manifest["undisclosed_disclosures"]
                .as_array()
                .expect("undisclosed disclosures array")
                .len(),
            8
        );
    }
}
