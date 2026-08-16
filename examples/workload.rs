//! The workload side of a Profile 0.2 advancement, for the local lab walkthrough.
//!
//! A workload does three things PIC-X cannot do for it: it holds a key, it obtains a Proof of
//! Relationship bound to that key, and it signs the three candidate artifacts. The first and third
//! need Ed25519 and CBOR/COSE, which is why this exists as a small Rust helper the lab demo drives
//! rather than living in the Python script.
//!
//! Two subcommands, both speaking JSON on stdout so a script can consume them:
//!
//! ```text
//! workload keygen
//!   -> { "seed": "<base64url>", "jwk": { ... } }
//!
//! workload candidate --pca <base64url> --presentation <sd-jwt> --seed <base64url>
//!                    [--remove-invariant <index>]
//!   -> { "token": "<candidate pic+jwt>", "next_challenge": "<base64url>" }
//! ```
//!
//! The seed round-trips through the caller because the credential must be issued *for* this key
//! before the candidate can be signed *with* it: keygen, then ask the attester, then sign.

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::SigningKey;
use pic::continuity::artifacts::{PicPcaCose, PicPcaPayload, ProofOfRelationship};
use pic::continuity::authority::attenuation::Attenuations;
use pic::continuity::authority::bitmap::RemoveBitmap;
use pic::continuity::prover::{CandidateRequest, build_candidate};
use pic::continuity::trust::Ed25519Signer;

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn unb64(value: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|error| format!("`{value}` is not unpadded base64url: {error}"))
}

fn main() -> Result<(), String> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match arguments.first().map(String::as_str) {
        Some("keygen") => keygen(),
        Some("candidate") => candidate(&flags(&arguments[1..])),
        _ => Err("usage: workload <keygen|candidate> [--flag value ...]".to_owned()),
    }
}

fn flags(arguments: &[String]) -> BTreeMap<String, String> {
    let mut flags = BTreeMap::new();
    let mut index = 0;
    while index + 1 < arguments.len() {
        if let Some(name) = arguments[index].strip_prefix("--") {
            flags.insert(name.to_owned(), arguments[index + 1].clone());
            index += 2;
        } else {
            index += 1;
        }
    }

    flags
}

fn required<'a>(flags: &'a BTreeMap<String, String>, name: &str) -> Result<&'a String, String> {
    flags.get(name).ok_or_else(|| format!("missing --{name}"))
}

/// A fresh workload key, and the JWK the attester binds in `cnf.jwk`.
fn keygen() -> Result<(), String> {
    let mut seed = [0_u8; 32];
    getrandom(&mut seed)?;
    let key = SigningKey::from_bytes(&seed);

    println!(
        "{}",
        serde_json::json!({
            "seed": b64(&seed),
            "jwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": "lab-workload-1",
                "x": b64(key.verifying_key().as_bytes()),
            }
        })
    );

    Ok(())
}

/// Builds the candidate: one Transition COSE, the candidate Continuity COSE that carries it, and
/// the candidate PIC Token JWT — all signed with the PoR-bound key.
fn candidate(flags: &BTreeMap<String, String>) -> Result<(), String> {
    let pca_bytes = unb64(required(flags, "pca")?)?;
    let presentation = required(flags, "presentation")?;
    let seed = unb64(required(flags, "seed")?)?;
    let seed: [u8; 32] = seed
        .try_into()
        .map_err(|_| "the seed is not 32 bytes".to_owned())?;
    let workload = Ed25519Signer::new(SigningKey::from_bytes(&seed), "lab-workload-1");

    // The invariant this hop consumes. Omitted means "carry the authority forward unchanged".
    let attenuations = match flags.get("remove-invariant") {
        Some(index) => {
            let index: u32 = index
                .parse()
                .map_err(|_| format!("`{index}` is not an invariant index"))?;
            Attenuations {
                invariants: RemoveBitmap::from_indices(&[index]),
                ..Default::default()
            }
        }
        None => Attenuations::default(),
    };

    let mut next_challenge = [0_u8; 32];
    getrandom(&mut next_challenge)?;

    let candidate = build_candidate(
        &pca_bytes,
        CandidateRequest {
            attenuations,
            next_challenge: next_challenge.to_vec(),
            proof_of_relationship: Some(ProofOfRelationship::sd_jwt(presentation)),
            aud: Some("pic-x".to_owned()),
            ..Default::default()
        },
        &workload,
        // The realm key is not published to this lab client, so the predecessor is parsed and
        // semantically validated rather than signature-checked. PIC-X re-validates everything.
        None,
    )
    .map_err(|error| format!("the candidate could not be built: {error}"))?;

    // What the workload proposes, so the demo can show it before PIC-X answers.
    let checkpoint: PicPcaPayload = PicPcaCose::from_bytes(&pca_bytes)
        .and_then(|cose| cose.payload_unverified())
        .map_err(|error| format!("the predecessor checkpoint could not be read: {error}"))?;

    println!(
        "{}",
        serde_json::json!({
            "token": candidate.token,
            "next_challenge": b64(&next_challenge),
            "predecessor_position": checkpoint.position,
            "proposed_position": candidate.transition.position,
            "transition_bytes": candidate.transition_bytes.len(),
            "continuity_bytes": candidate.continuity_bytes.len(),
        })
    );

    Ok(())
}

/// Random bytes from the OS. `ring` is already in the dependency graph, so nothing new is pulled in
/// for the two places this needs entropy.
fn getrandom(destination: &mut [u8]) -> Result<(), String> {
    use ring::rand::SecureRandom;

    ring::rand::SystemRandom::new()
        .fill(destination)
        .map_err(|_| "the system random source failed".to_owned())
}
