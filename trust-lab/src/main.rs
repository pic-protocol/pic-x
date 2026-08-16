use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use ring::rand::SystemRandom;
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
    configuration_endpoint: String,
    key: Jwk,
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
}

#[derive(Debug, Serialize)]
struct AttesterConfiguration {
    issuer: String,
    jwks_uri: String,
    presentation_endpoint: String,
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
        configuration_endpoint,
        key,
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
        proof_types_supported: [PROOF_TYPE_SD_JWT],
        formats_supported: [FORMAT_SD_JWT],
        profile: PROFILE,
        fixture: true,
        fixture_warning: "local fixture for the PIC-X lab; not a production attestation issuer",
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
