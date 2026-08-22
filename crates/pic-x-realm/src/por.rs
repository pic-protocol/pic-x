// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Profile 0.2 Proof-of-Relationship validation: issuer-signed SD-JWT presentations.
//!
//! The protocol crate leaves this deployment-specific and takes it through the [`PorValidator`]
//! boundary. This is the PIC-X realization for `proof_of_relationship.type = "sd-jwt"`, following
//! the validation order the Profile 0.2 articles state:
//!
//! ```text
//! validate proof_of_relationship.type = "sd-jwt"
//! parse evidence as issuer-signed SD-JWT + selected Disclosures
//! verify issuer JWS signature and issuer trust
//! validate _sd_alg
//! Base64url decode each selected Disclosure
//! validate Disclosure structure and digest matches
//! reject unreferenced Disclosures and duplicate digest use
//! reconstruct the Processed SD-JWT Payload
//! validate required validity claims
//! obtain the workload public key from cnf.jwk
//! ```
//!
//! Trust is decided *before* cryptography is spent: the presentation's `iss` must name an attester
//! this realm was configured to accept, and the signature is then verified against that attester's
//! published key set. An issuer nobody configured is rejected without a signature check.
//!
//! The workload key this yields is what the settlement procedure uses to verify the three
//! workload-signed candidate artifacts. PoR establishes the relationship and the key binding; it is
//! not, by itself, Proof of Continuity.

use std::collections::BTreeSet;
use std::sync::Mutex;

use pic::continuity::artifacts::ProofOfRelationship;
use pic::continuity::error::RejectReason;
use pic::continuity::jwk::{expected_algorithms_for_jwk, public_key_from_jwk};
use pic::continuity::por::PorValidator;
use pic::continuity::trust::ArtifactVerifier;
use ring::digest::{SHA256, digest};
use ring::signature::{RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
use serde_json::Value;

use pic_x_core::TrustedAttesterConfig;

use crate::attester_keys::AttesterKeySource;

/// The algorithms this build accepts on workload-signed COSE artifacts.
///
/// The same set the PoR key agreement enforces: a workload signs with the key its credential bound,
/// and these are the key kinds that can produce a COSE signature here — the curve features this
/// build enables on the protocol crate, no more and no less. Announcing fewer than are accepted
/// would turn a working workload away for a reason the document does not give; announcing more
/// would invite one that is then refused.
///
/// RSA is verifiable for a JWS but has no COSE algorithm, so it is not offered for the artifacts.
pub(crate) const WORKLOAD_COSE_ALGORITHMS: [&str; 3] = ["EdDSA", "ES256", "ES384"];

/// The SD-JWT digest algorithm Profile 0.2 accepts.
const SD_ALG_SHA_256: &str = "sha-256";
/// Bounds on presentation size, so an unauthenticated caller cannot make the verifier do unbounded
/// work before any trust decision has been made.
const MAX_EVIDENCE_BYTES: usize = 64 * 1024;
const MAX_DISCLOSURES: usize = 128;
/// Tolerance for clock skew between the attester and this realm, in seconds.
const CLOCK_SKEW_SECONDS: i64 = 60;

/// Validates Profile 0.2 SD-JWT Proof-of-Relationship evidence for one realm.
pub(crate) struct SdJwtPorValidator<'a> {
    /// The attesters this realm accepts. An `iss` outside this list is never trusted.
    pub(crate) attesters: &'a [TrustedAttesterConfig],
    /// Where the attesters' published verification keys come from.
    pub(crate) keys: &'a dyn AttesterKeySource,
    /// Now, in seconds since the Unix epoch, for the validity claims.
    pub(crate) now: i64,
    /// What the accepted presentation disclosed, and the evidence it came from.
    ///
    /// This carries two jobs. The `PorValidator` boundary hands back only a verifier, but an
    /// accepted advancement has to be attributable — *which* attester vouched for the workload, on
    /// the strength of which disclosed claims — and this is how the caller reads that back.
    ///
    /// It also makes a second validation of the same presentation free. A settlement validates the
    /// evidence twice: once to bind the candidate's algorithms to the PoR key before anything else
    /// is trusted, and once inside the settlement procedure. Recomputing an issuer signature and
    /// every disclosure digest for a second identical answer is work an unauthenticated caller
    /// should not be able to ask for twice.
    pub(crate) accepted: Mutex<Option<Accepted>>,
}

/// A presentation this validator already accepted.
#[derive(Debug, Clone)]
pub(crate) struct Accepted {
    /// The exact evidence bytes, compared before the cached answer is reused.
    evidence: Vec<u8>,
    /// The key the credential bound, kept as a JWK so the verifier can be rebuilt cheaply.
    jwk: Value,
    /// What the presentation disclosed.
    pub(crate) processed: ProcessedPor,
}

/// What a validated presentation disclosed, kept for policy and audit.
#[derive(Debug, Clone, Default)]
pub(crate) struct ProcessedPor {
    /// The attester id from the realm configuration that accepted this evidence.
    pub(crate) attester_id: String,
    /// The credential issuer.
    pub(crate) issuer: String,
    /// The claims the Holder chose to disclose, plus the always-disclosed ones.
    pub(crate) claims: serde_json::Map<String, Value>,
}

impl PorValidator for SdJwtPorValidator<'_> {
    fn validate(
        &self,
        por: &ProofOfRelationship,
    ) -> Result<Box<dyn ArtifactVerifier>, RejectReason> {
        // Reusing an answer is safe only for byte-identical evidence: anything else is a different
        // presentation and gets the full procedure.
        if let Some(cached) = self.cached_for(&por.evidence) {
            // The cached JWK already passed every check when it was first accepted; rebuilding the
            // verifier from it repeats the algorithm agreement rather than assuming it.
            return rebuild_workload_key(&cached.jwk);
        }

        let (verifier, processed, jwk) = self.validate_evidence_with_key(por)?;
        if let Ok(mut accepted) = self.accepted.lock() {
            *accepted = Some(Accepted {
                evidence: por.evidence.clone(),
                jwk,
                processed,
            });
        }

        Ok(verifier)
    }
}

impl SdJwtPorValidator<'_> {
    /// What this validator last accepted, if anything.
    pub(crate) fn accepted(&self) -> Option<ProcessedPor> {
        self.accepted
            .lock()
            .ok()
            .and_then(|accepted| accepted.as_ref().map(|entry| entry.processed.clone()))
    }

    /// The cached answer for exactly these evidence bytes.
    fn cached_for(&self, evidence: &[u8]) -> Option<Accepted> {
        self.accepted
            .lock()
            .ok()
            .and_then(|accepted| accepted.clone())
            .filter(|entry| entry.evidence == evidence)
    }

    /// Validates and records the presentation, so a later identical validation is free.
    pub(crate) fn validate_and_remember(
        &self,
        por: &ProofOfRelationship,
    ) -> Result<ProcessedPor, RejectReason> {
        if let Some(cached) = self.cached_for(&por.evidence) {
            return Ok(cached.processed);
        }

        let (_, processed, jwk) = self.validate_evidence_with_key(por)?;
        if let Ok(mut accepted) = self.accepted.lock() {
            *accepted = Some(Accepted {
                evidence: por.evidence.clone(),
                jwk,
                processed: processed.clone(),
            });
        }

        Ok(processed)
    }

    /// The full validation, also returning what the presentation disclosed.
    ///
    /// Production paths go through [`Self::validate_and_remember`] or the `PorValidator` boundary,
    /// which reuse an accepted answer; this is the uncached form the tests exercise.
    #[cfg(test)]
    pub(crate) fn validate_evidence(
        &self,
        por: &ProofOfRelationship,
    ) -> Result<(Box<dyn ArtifactVerifier>, ProcessedPor), RejectReason> {
        let (verifier, processed, _) = self.validate_evidence_with_key(por)?;

        Ok((verifier, processed))
    }

    /// The full validation, also handing back the bound key as a JWK.
    fn validate_evidence_with_key(
        &self,
        por: &ProofOfRelationship,
    ) -> Result<(Box<dyn ArtifactVerifier>, ProcessedPor, Value), RejectReason> {
        if por.evidence.len() > MAX_EVIDENCE_BYTES {
            return Err(reject("proof_of_relationship.evidence is too large"));
        }
        let presentation = std::str::from_utf8(&por.evidence)
            .map_err(|_| reject("proof_of_relationship.evidence is not UTF-8"))?;

        let (issuer_signed, disclosures) = split_presentation(presentation)?;
        let (header, payload) = decode_jws_segments(issuer_signed)?;

        // Trust first: an issuer this realm never configured is rejected before any signature is
        // verified, so an unknown caller cannot even choose which cryptography we run.
        let issuer = payload
            .get("iss")
            .and_then(Value::as_str)
            .ok_or_else(|| reject("the SD-JWT has no `iss` claim"))?;
        let attester = self
            .attesters
            .iter()
            .find(|candidate| candidate.issuer == issuer)
            .ok_or_else(|| {
                RejectReason::PorRejected(format!(
                    "issuer `{issuer}` is not a trusted attester of this realm"
                ))
            })?;
        if !attester.proof_types.iter().any(|value| value == "sd-jwt") {
            return Err(RejectReason::PorRejected(format!(
                "attester `{}` is not configured for proof type `sd-jwt`",
                attester.id
            )));
        }

        verify_issuer_signature(issuer_signed, &header, attester, self.keys)?;

        // Only now is the payload authentic enough to interpret.
        match payload.get("_sd_alg").and_then(Value::as_str) {
            Some(SD_ALG_SHA_256) => {}
            Some(other) => {
                return Err(RejectReason::PorRejected(format!(
                    "unsupported `_sd_alg` `{other}`"
                )));
            }
            // RFC 9901 defaults to sha-256 when absent.
            None => {}
        }
        validate_validity_claims(&payload, self.now)?;

        let claims = process_disclosures(&payload, &disclosures)?;
        let jwk = payload
            .get("cnf")
            .and_then(|cnf| cnf.get("jwk"))
            .cloned()
            .ok_or_else(|| reject("the SD-JWT does not bind a workload key through `cnf.jwk`"))?;
        let workload_key = workload_key_from_cnf(&payload)?;

        Ok((
            workload_key,
            ProcessedPor {
                attester_id: attester.id.clone(),
                issuer: issuer.to_owned(),
                claims,
            },
            jwk,
        ))
    }
}

/// Splits `<issuer-signed JWT>~<disclosure>~...~` into its parts.
///
/// A Profile 0.2 presentation ends with `~` and carries no Key Binding JWT: the workload proves key
/// control by signing the candidate PIC artifacts instead.
fn split_presentation(presentation: &str) -> Result<(&str, Vec<&str>), RejectReason> {
    if !presentation.ends_with('~') {
        return Err(reject(
            "the SD-JWT presentation does not end with `~`; a Key Binding JWT is not used in Profile 0.2",
        ));
    }

    let mut segments = presentation.split('~');
    let issuer_signed = segments
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| reject("the SD-JWT presentation has no issuer-signed JWT"))?;

    // The trailing `~` produces a final empty segment, which is the terminator, not a Disclosure.
    let disclosures: Vec<&str> = segments.filter(|value| !value.is_empty()).collect();
    if disclosures.len() > MAX_DISCLOSURES {
        return Err(reject(
            "the SD-JWT presentation carries too many disclosures",
        ));
    }

    Ok((issuer_signed, disclosures))
}

fn decode_jws_segments(jws: &str) -> Result<(Value, Value), RejectReason> {
    let mut parts = jws.split('.');
    let (Some(header), Some(payload), Some(_signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(reject("the issuer-signed SD-JWT is not a compact JWS"));
    };

    Ok((
        decode_json(header, "header")?,
        decode_json(payload, "payload")?,
    ))
}

fn verify_issuer_signature(
    issuer_signed: &str,
    header: &Value,
    attester: &TrustedAttesterConfig,
    keys: &dyn AttesterKeySource,
) -> Result<(), RejectReason> {
    let algorithm = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| reject("the SD-JWT header has no `alg`"))?;
    if algorithm == "none" {
        return Err(reject("the SD-JWT declares `alg: none`"));
    }
    let key_id = header.get("kid").and_then(Value::as_str);

    let (signing_input, signature) = jws_signature_parts(issuer_signed)?;
    let candidates = keys.keys_for(&attester.id).map_err(|error| {
        RejectReason::PorRejected(format!(
            "the key set of attester `{}` is unavailable: {error}",
            attester.id
        ))
    })?;
    if candidates.is_empty() {
        return Err(RejectReason::PorRejected(format!(
            "attester `{}` published no verification keys",
            attester.id
        )));
    }

    // A `kid` narrows the candidates; without one, every published key of that attester is tried,
    // which is what makes issuer key rotation transparent here.
    let selected: Vec<&Value> = candidates
        .iter()
        .filter(|jwk| match key_id {
            Some(wanted) => jwk.get("kid").and_then(Value::as_str) == Some(wanted),
            None => true,
        })
        .collect();
    if selected.is_empty() {
        return Err(RejectReason::PorRejected(format!(
            "attester `{}` published no key matching `kid`",
            attester.id
        )));
    }

    for jwk in selected {
        if !algorithm_matches(algorithm, jwk) {
            continue;
        }
        let Ok(key) = verification_key_from_jwk(jwk) else {
            continue;
        };
        if key.verify(&signing_input, &signature) {
            return Ok(());
        }
    }

    Err(RejectReason::PorRejected(format!(
        "the SD-JWT issuer signature does not verify against the key set of attester `{}`",
        attester.id
    )))
}

/// `true` when the JOSE `alg` is the one this key can produce, so a token cannot ask for a weaker
/// algorithm than the key was published for.
fn algorithm_matches(algorithm: &str, jwk: &Value) -> bool {
    expected_jose_algorithm(jwk).is_some_and(|expected| expected == algorithm)
}

fn jws_signature_parts(jws: &str) -> Result<(Vec<u8>, Vec<u8>), RejectReason> {
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err(reject("the issuer-signed SD-JWT is not a compact JWS"));
    }
    let signing_input = format!("{}.{}", parts[0], parts[1]).into_bytes();
    let signature = b64url_decode(parts[2])
        .ok_or_else(|| reject("the SD-JWT signature is not unpadded base64url"))?;

    Ok((signing_input, signature))
}

/// Reconstructs the Processed SD-JWT Payload from the presented Disclosures.
///
/// Every Disclosure must be committed in `_sd`; an unreferenced Disclosure, a malformed one, or the
/// same digest used twice makes the whole presentation invalid.
fn process_disclosures(
    payload: &Value,
    disclosures: &[&str],
) -> Result<serde_json::Map<String, Value>, RejectReason> {
    let committed: BTreeSet<&str> = payload
        .get("_sd")
        .and_then(Value::as_array)
        .map(|values| values.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();

    let mut claims = serde_json::Map::new();
    // Everything except the SD-JWT machinery is always disclosed.
    if let Some(object) = payload.as_object() {
        for (key, value) in object {
            if key != "_sd" && key != "_sd_alg" {
                claims.insert(key.clone(), value.clone());
            }
        }
    }

    let mut used: BTreeSet<String> = BTreeSet::new();
    for disclosure in disclosures {
        let computed = base64url(digest(&SHA256, disclosure.as_bytes()).as_ref());
        if !committed.contains(computed.as_str()) {
            return Err(reject(
                "a presented disclosure is not committed in the credential `_sd`",
            ));
        }
        if !used.insert(computed) {
            return Err(reject("a disclosure digest was presented twice"));
        }

        let decoded = b64url_decode(disclosure)
            .ok_or_else(|| reject("a disclosure is not unpadded base64url"))?;
        let parts: Vec<Value> = serde_json::from_slice(&decoded)
            .map_err(|_| reject("a disclosure is not a JSON array"))?;
        // Profile 0.2 uses object-property disclosures: [salt, name, value].
        let [_salt, name, value] = parts.as_slice() else {
            return Err(reject(
                "a disclosure is not a [salt, name, value] object-property disclosure",
            ));
        };
        let name = name
            .as_str()
            .ok_or_else(|| reject("a disclosure claim name is not a string"))?;
        if name.starts_with("_sd") || name == "..." {
            return Err(reject("a disclosure uses a reserved claim name"));
        }
        if claims.insert(name.to_owned(), value.clone()).is_some() {
            return Err(reject("a disclosure would overwrite an existing claim"));
        }
    }

    Ok(claims)
}

fn validate_validity_claims(payload: &Value, now: i64) -> Result<(), RejectReason> {
    if let Some(expiry) = payload.get("exp").and_then(Value::as_i64) {
        if now - CLOCK_SKEW_SECONDS >= expiry {
            return Err(reject("the SD-JWT Proof of Relationship is expired"));
        }
    } else {
        return Err(reject("the SD-JWT has no numeric `exp` claim"));
    }

    if let Some(not_before) = payload.get("nbf").and_then(Value::as_i64)
        && now + CLOCK_SKEW_SECONDS < not_before
    {
        return Err(reject("the SD-JWT Proof of Relationship is not yet valid"));
    }
    if let Some(issued_at) = payload.get("iat").and_then(Value::as_i64)
        && now + CLOCK_SKEW_SECONDS < issued_at
    {
        return Err(reject(
            "the SD-JWT Proof of Relationship is issued in the future",
        ));
    }

    Ok(())
}

/// The workload verification key the credential binds through `cnf.jwk`.
///
/// Profile 0.2 requires the selected PoR schema to bind or identify this key; the walkthrough uses
/// RFC 9901's `cnf.jwk` form, and that is the form this deployment accepts.
fn workload_key_from_cnf(payload: &Value) -> Result<Box<dyn ArtifactVerifier>, RejectReason> {
    let jwk = payload
        .get("cnf")
        .and_then(|cnf| cnf.get("jwk"))
        .ok_or_else(|| reject("the SD-JWT does not bind a workload key through `cnf.jwk`"))?;

    public_key_from_jwk(jwk)
        .map(|key| Box::new(key) as Box<dyn ArtifactVerifier>)
        .map_err(|error| RejectReason::PorRejected(format!("`cnf.jwk` is unusable: {error}")))
}

/// Rebuilds a workload verifier from a JWK that was already accepted.
fn rebuild_workload_key(jwk: &Value) -> Result<Box<dyn ArtifactVerifier>, RejectReason> {
    public_key_from_jwk(jwk)
        .map(|key| Box::new(key) as Box<dyn ArtifactVerifier>)
        .map_err(|error| RejectReason::PorRejected(format!("`cnf.jwk` is unusable: {error}")))
}

/// A verification key for a JWS this deployment reads but the PIC profile does not define: an
/// OAuth access token, or the SD-JWT an attestation issuer signed.
///
/// The curves come from the protocol crate, which is what every PIC verifier uses; RSA is added
/// here, because identity providers publish RSA keys and PIC artifacts never carry one.
pub(crate) fn verification_key_from_jwk(jwk: &Value) -> Result<Box<dyn ArtifactVerifier>, String> {
    if jwk.get("d").is_some() {
        return Err("the JWK carries a private key component".to_owned());
    }
    if jwk.get("kty").and_then(Value::as_str) == Some("RSA") {
        return rsa_key_from_jwk(jwk).map(|key| Box::new(key) as Box<dyn ArtifactVerifier>);
    }

    public_key_from_jwk(jwk)
        .map(|key| Box::new(key) as Box<dyn ArtifactVerifier>)
        .map_err(|error| error.to_string())
}

/// The JOSE algorithm a key of this shape produces, RSA included.
fn expected_jose_algorithm(jwk: &Value) -> Option<&'static str> {
    if jwk.get("kty").and_then(Value::as_str) == Some("RSA") {
        return Some("RS256");
    }

    expected_algorithms_for_jwk(jwk)
        .ok()
        .map(|expected| expected.jose)
}

/// A verifier over one RSA key.
pub(crate) struct RsaVerifier {
    key: Vec<u8>,
}

impl ArtifactVerifier for RsaVerifier {
    fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &self.key)
            .verify(data, signature)
            .is_ok()
    }
}

/// An RSA verification key from its JWK modulus and exponent.
///
/// `ring` verifies RSA against a DER `RSAPublicKey`, so the two integers are re-encoded into one.
/// Keys below 2048 bits are refused: an identity provider signing with less is a finding, not
/// something to accommodate quietly.
fn rsa_key_from_jwk(jwk: &Value) -> Result<RsaVerifier, String> {
    let modulus = jwk
        .get("n")
        .and_then(Value::as_str)
        .ok_or_else(|| "the RSA JWK has no `n`".to_owned())?;
    let exponent = jwk
        .get("e")
        .and_then(Value::as_str)
        .ok_or_else(|| "the RSA JWK has no `e`".to_owned())?;
    let modulus = b64url_decode(modulus).ok_or_else(|| "`n` is not base64url".to_owned())?;
    let exponent = b64url_decode(exponent).ok_or_else(|| "`e` is not base64url".to_owned())?;

    if modulus.len() < 256 {
        return Err(format!(
            "the RSA key is {} bits; 2048 is the minimum",
            modulus.len() * 8
        ));
    }

    Ok(RsaVerifier {
        key: der_rsa_public_key(&modulus, &exponent),
    })
}

/// `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`, DER-encoded.
fn der_rsa_public_key(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
    let mut body = der_integer(modulus);
    body.extend(der_integer(exponent));

    let mut out = vec![0x30];
    out.extend(der_length(body.len()));
    out.extend(body);

    out
}

fn der_integer(value: &[u8]) -> Vec<u8> {
    // Strip the leading zeroes a JWK may carry, then add one back when the high bit is set, so the
    // value stays positive in DER's two's-complement reading.
    let trimmed = value
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(value.len());
    let value = &value[trimmed..];

    let mut content = Vec::with_capacity(value.len() + 1);
    if value.first().is_some_and(|byte| byte & 0x80 != 0) {
        content.push(0x00);
    }
    content.extend_from_slice(value);

    let mut out = vec![0x02];
    out.extend(der_length(content.len()));
    out.extend(content);

    out
}

fn der_length(length: usize) -> Vec<u8> {
    if length < 0x80 {
        return vec![length as u8];
    }

    let bytes = length.to_be_bytes();
    let significant = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    let significant = &bytes[significant..];

    let mut out = vec![0x80 | significant.len() as u8];
    out.extend_from_slice(significant);

    out
}

fn decode_json(segment: &str, label: &str) -> Result<Value, RejectReason> {
    let bytes = b64url_decode(segment)
        .ok_or_else(|| RejectReason::PorRejected(format!("the SD-JWT {label} is not base64url")))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| RejectReason::PorRejected(format!("the SD-JWT {label} is not JSON")))
}

fn reject(description: &str) -> RejectReason {
    RejectReason::PorRejected(description.to_owned())
}

fn base64url(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn b64url_decode(value: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .ok()
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "a failing assertion is the point"
)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use serde_json::json;

    const NOW: i64 = 1_786_700_800;

    // Captured from the lab Keycloak: a real RS256 access token and the key that signed it.
    const KEYCLOAK_HEADER: &str = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI4QUtvT09DYldoQV9QbGhKTi14dzBZWnhuWk44UW92cHJURXZLdlVPaDY4In0";
    const KEYCLOAK_PAYLOAD: &str = "eyJleHAiOjE3ODY4ODg1OTIsImlhdCI6MTc4Njg4ODI5MiwianRpIjoib25ydHJvOjFkY2I5NjE0LWQzODgtZjk1OS1kMDcxLTMyMzBjZGJiY2VmYiIsImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6MTgwODAvcmVhbG1zL2FjbWUtaWRwIiwiYXVkIjoicGljLXgiLCJzdWIiOiJhZGNlZTBhNi1hZWVkLTQ2ZjItYTIxYi1mMTQwNDI5Mjc2ZmYiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJhY21lLWlkcC1jbGllbnQiLCJzaWQiOiJjVTBtZEtqNFpNMFFuVklFa3ZtSEM2M2oiLCJhY3IiOiIxIiwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbInN0b3JhZ2U6c2F2ZSIsImRvY3VtZW50czpyZWFkOmRvY3VtZW50LTQyIiwiZXhhbXBsZS11c2VyIl19LCJzY29wZSI6ImVtYWlsIHByb2ZpbGUiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IkFsaWNlIEV4YW1wbGUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhbGljZSIsImdpdmVuX25hbWUiOiJBbGljZSIsImZhbWlseV9uYW1lIjoiRXhhbXBsZSIsImVtYWlsIjoiYWxpY2VAZXhhbXBsZS5sb2NhbCIsInBpY19zY29wZXMiOlsiZG9jdW1lbnRzOnJlYWQ6ZG9jdW1lbnQtNDIiLCJzdG9yYWdlOnNhdmUiXX0";
    const KEYCLOAK_SIGNATURE: &str = "QSm_ENG0wrHjt32QH7iI731Ut2uB-hHJqtc0wCnTDOeeRWWX-2BeZI0UNpoDp-f0IB3Ie57Hr9H3GzFTedCtMnm62nkkrKL3LEn0m35vLABHtqsHwgx6MrJQ-lusdfHV7p4VILL5JovnDziWSJzbgRpXER1QDzYeS5_Y7Tqr6iJIzr9rzo7XYaiESGQ4dkm_7cuEzu_xJdllUzypW8IqnIHU_JjuwbGhMfQ1HW4sLOLGJabz4Yi9sYEoczdTvCIOw7mS2I9iPoslgvpQHdJtRVvMM6lDQXZYm04KiQr_9lEYggVXCYmC5vTeXYQh7Y_PhhQ_CQg78UuJuFJv8GoV2g";
    const KEYCLOAK_MODULUS: &str = "p_IK08O9i822gXL1EpnwOdyBInMJvbjPebtXBGpSat0TKwXCjDVi-mWNupuoW0FC5Ama_Z-fjEjWCKCydISeXDYnVWJEgWVaJ8Rma1kEmIIdN8UHu_CUAW1NvJeyISjf4XMQsBnkx2fqVHu32HFvKLlBZ6rhL2cPjD7N8xiS_tKcQ-wDdRz6r4czW43gEPzXfSQDMphie70Bu99la5vjnm1pHnUPw7anrPoI36K2dJYY0vrYD7HCqJFcG9in5Wi2Fl1RlhpUguHyjMPnWxdGu7D6IsN5hd9SOCyaaA0C37tzNQ9U_ekTRGWAv5iXB06kEJMqSi_3iKC5JIb1zpAWow";

    /// A lab attester: an Ed25519 issuing key and the key set it publishes.
    struct Attester {
        pair: Ed25519KeyPair,
        config: TrustedAttesterConfig,
    }

    impl Attester {
        fn new() -> Self {
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
                .expect("the attester key generates");
            let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("the attester key parses");

            Self {
                pair,
                config: TrustedAttesterConfig {
                    id: "acme-por-attester".to_owned(),
                    issuer: "https://attestation.example.com".to_owned(),
                    jwks_uri: "https://attestation.example.com/jwks.json".to_owned(),
                    proof_types: vec!["sd-jwt".to_owned()],
                    formats: vec!["sd-jwt".to_owned()],
                },
            }
        }

        fn key_set(&self) -> Vec<Value> {
            vec![json!({
                "kid": "attester-1",
                "kty": "OKP",
                "crv": "Ed25519",
                "use": "sig",
                "x": base64url(self.pair.public_key().as_ref()),
            })]
        }

        fn sign(&self, payload: &Value) -> String {
            let header = json!({"alg": "EdDSA", "kid": "attester-1", "typ": "vc+sd-jwt"});
            let signing_input = format!(
                "{}.{}",
                base64url(serde_json::to_string(&header).unwrap().as_bytes()),
                base64url(serde_json::to_string(payload).unwrap().as_bytes())
            );
            let signature = self.pair.sign(signing_input.as_bytes());

            format!("{signing_input}.{}", base64url(signature.as_ref()))
        }
    }

    struct Keys(Vec<Value>);

    impl AttesterKeySource for Keys {
        fn keys_for(&self, _attester_id: &str) -> anyhow::Result<Vec<Value>> {
            Ok(self.0.clone())
        }
    }

    /// The workload key the credential binds, and the disclosures of one credential.
    struct Credential {
        payload: Value,
        disclosures: Vec<String>,
        workload: Ed25519KeyPair,
    }

    fn disclosure(salt: &str, name: &str, value: &str) -> String {
        base64url(json!([salt, name, value]).to_string().as_bytes())
    }

    fn digest_of(disclosure: &str) -> String {
        base64url(digest(&SHA256, disclosure.as_bytes()).as_ref())
    }

    fn credential(issuer: &str) -> Credential {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let workload = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

        let disclosures = vec![
            disclosure("f0UUCvMSycSUXaVfuiDWAA", "corporation", "ACME"),
            disclosure(
                "E54m03bpDTSeWfZOQ-1wVw",
                "department",
                "sensitive-documents",
            ),
            // Issued but not presented below, the way the walkthrough keeps eight back.
            disclosure("Xn7kw6wekrrpvjPLcrMOQQ", "clearance", "sensitive"),
        ];
        let payload = json!({
            "iss": issuer,
            "iat": NOW - 100,
            "exp": NOW + 3_500,
            "_sd_alg": "sha-256",
            "_sd": disclosures.iter().map(|d| digest_of(d)).collect::<Vec<_>>(),
            "cnf": { "jwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": "worker-1-key",
                "x": base64url(workload.public_key().as_ref()),
            }},
        });

        Credential {
            payload,
            disclosures,
            workload,
        }
    }

    fn presentation(attester: &Attester, credential: &Credential, present: &[usize]) -> Vec<u8> {
        let mut text = attester.sign(&credential.payload);
        for index in present {
            text.push('~');
            text.push_str(&credential.disclosures[*index]);
        }
        text.push('~');

        text.into_bytes()
    }

    fn por(evidence: Vec<u8>) -> ProofOfRelationship {
        ProofOfRelationship {
            por_type: "sd-jwt".to_owned(),
            evidence,
        }
    }

    /// `Box<dyn ArtifactVerifier>` is not `Debug`, so `expect_err` cannot be used: this states
    /// the same expectation and yields the message to assert on.
    fn expect_rejection(
        result: Result<(Box<dyn ArtifactVerifier>, ProcessedPor), RejectReason>,
    ) -> String {
        match result {
            Err(reason) => reason.to_string(),
            Ok((_, processed)) => panic!("expected a rejection, got {processed:?}"),
        }
    }

    fn validator<'a>(attester: &'a Attester, keys: &'a Keys) -> SdJwtPorValidator<'a> {
        SdJwtPorValidator {
            attesters: std::slice::from_ref(&attester.config),
            keys,
            now: NOW,
            accepted: Default::default(),
        }
    }

    #[test]
    fn a_valid_presentation_yields_the_bound_workload_key() {
        let attester = Attester::new();
        let keys = Keys(attester.key_set());
        let credential = credential(&attester.config.issuer);
        let evidence = presentation(&attester, &credential, &[0, 1]);

        let (verifier, processed) = validator(&attester, &keys)
            .validate_evidence(&por(evidence))
            .expect("the presentation validates");

        // The returned verifier is the key the credential bound: it accepts that workload's
        // signature and nothing else.
        let signature = credential.workload.sign(b"candidate artifact bytes");
        assert!(verifier.verify(b"candidate artifact bytes", signature.as_ref()));
        assert!(!verifier.verify(b"different bytes", signature.as_ref()));

        // Only the presented claims are reconstructed; the withheld one is absent.
        assert_eq!(processed.claims["corporation"], "ACME");
        assert_eq!(processed.claims["department"], "sensitive-documents");
        assert!(!processed.claims.contains_key("clearance"));
        assert_eq!(processed.attester_id, "acme-por-attester");
    }

    #[test]
    fn an_issuer_outside_the_realm_list_is_rejected() {
        let attester = Attester::new();
        let keys = Keys(attester.key_set());
        // Correctly signed by this attester, but claiming an issuer the realm never configured.
        let credential = credential("https://attacker.example.com");
        let evidence = presentation(&attester, &credential, &[0, 1]);

        let error = expect_rejection(validator(&attester, &keys).validate_evidence(&por(evidence)));
        assert!(error.contains("not a trusted attester"));
    }

    #[test]
    fn a_presentation_signed_by_another_key_is_rejected() {
        let attester = Attester::new();
        // The realm holds a different attester's key set than the one that signed.
        let keys = Keys(Attester::new().key_set());
        let credential = credential(&attester.config.issuer);
        let evidence = presentation(&attester, &credential, &[0, 1]);

        let error = expect_rejection(validator(&attester, &keys).validate_evidence(&por(evidence)));
        assert!(error.contains("does not verify"));
    }

    #[test]
    fn a_tampered_payload_is_rejected() {
        let attester = Attester::new();
        let keys = Keys(attester.key_set());
        let credential = credential(&attester.config.issuer);
        let signed = String::from_utf8(presentation(&attester, &credential, &[0, 1])).unwrap();

        // Swap in a payload that binds an attacker-controlled key, keeping the issuer signature.
        let mut forged = credential.payload.clone();
        forged["cnf"]["jwk"]["x"] = json!(base64url(&[0x11; 32]));
        let parts: Vec<&str> = signed.splitn(3, '.').collect();
        let tampered = format!(
            "{}.{}.{}",
            parts[0],
            base64url(serde_json::to_string(&forged).unwrap().as_bytes()),
            parts[2].split('~').next().unwrap()
        );

        let error = expect_rejection(
            validator(&attester, &keys)
                .validate_evidence(&por(format!("{tampered}~").into_bytes())),
        );
        assert!(error.contains("does not verify"));
    }

    #[test]
    fn a_disclosure_the_credential_never_committed_is_rejected() {
        let attester = Attester::new();
        let keys = Keys(attester.key_set());
        let credential = credential(&attester.config.issuer);

        let mut evidence = String::from_utf8(presentation(&attester, &credential, &[0])).unwrap();
        // Append a disclosure whose digest is in no `_sd` entry.
        evidence.push_str(&disclosure(
            "aaaaaaaaaaaaaaaaaaaaaa",
            "clearance",
            "top-secret",
        ));
        evidence.push('~');

        let error = expect_rejection(
            validator(&attester, &keys).validate_evidence(&por(evidence.into_bytes())),
        );
        assert!(error.contains("not committed"));
    }

    #[test]
    fn the_same_disclosure_presented_twice_is_rejected() {
        let attester = Attester::new();
        let keys = Keys(attester.key_set());
        let credential = credential(&attester.config.issuer);
        let evidence = presentation(&attester, &credential, &[0, 0]);

        let error = expect_rejection(validator(&attester, &keys).validate_evidence(&por(evidence)));
        assert!(error.contains("presented twice"));
    }

    #[test]
    fn an_expired_credential_is_rejected() {
        let attester = Attester::new();
        let keys = Keys(attester.key_set());
        let mut credential = credential(&attester.config.issuer);
        credential.payload["exp"] = json!(NOW - 3_600);
        let evidence = presentation(&attester, &credential, &[0, 1]);

        let error = expect_rejection(validator(&attester, &keys).validate_evidence(&por(evidence)));
        assert!(error.contains("expired"));
    }

    #[test]
    fn a_credential_without_expiry_or_bound_key_is_rejected() {
        let attester = Attester::new();
        let keys = Keys(attester.key_set());

        let mut no_expiry = credential(&attester.config.issuer);
        no_expiry.payload.as_object_mut().unwrap().remove("exp");
        assert!(
            validator(&attester, &keys)
                .validate_evidence(&por(presentation(&attester, &no_expiry, &[0])))
                .is_err()
        );

        let mut no_key = credential(&attester.config.issuer);
        no_key.payload.as_object_mut().unwrap().remove("cnf");
        let error = expect_rejection(
            validator(&attester, &keys).validate_evidence(&por(presentation(
                &attester,
                &no_key,
                &[0],
            ))),
        );
        assert!(error.contains("cnf.jwk"));
    }

    #[test]
    fn a_credential_whose_bound_key_declares_the_wrong_algorithm_is_rejected() {
        let attester = Attester::new();
        let keys = Keys(attester.key_set());
        let mut credential = credential(&attester.config.issuer);
        credential.payload["cnf"]["jwk"]["alg"] = json!("ES256");

        let error = expect_rejection(
            validator(&attester, &keys).validate_evidence(&por(presentation(
                &attester,
                &credential,
                &[0, 1],
            ))),
        );
        assert!(error.contains("cnf.jwk"));
        assert!(error.contains("alg"));
    }

    #[test]
    fn the_same_presentation_is_validated_once_and_reused() {
        let attester = Attester::new();
        let keys = Keys(attester.key_set());
        let credential = credential(&attester.config.issuer);
        let evidence = por(presentation(&attester, &credential, &[0, 1]));
        let validator = validator(&attester, &keys);

        // First pass: the full procedure runs and the answer is remembered.
        let first = validator
            .validate_and_remember(&evidence)
            .expect("the presentation validates");
        assert_eq!(first.attester_id, "acme-por-attester");

        // Second pass through the `PorValidator` boundary: same key, no re-verification.
        let verifier = PorValidator::validate(&validator, &evidence).expect("cached answer");
        let signature = credential.workload.sign(b"candidate artifact bytes");
        assert!(verifier.verify(b"candidate artifact bytes", signature.as_ref()));
    }

    #[test]
    fn a_different_presentation_never_reuses_a_cached_answer() {
        let attester = Attester::new();
        let keys = Keys(attester.key_set());
        let validator = validator(&attester, &keys);

        let good = credential(&attester.config.issuer);
        validator
            .validate_and_remember(&por(presentation(&attester, &good, &[0, 1])))
            .expect("the first presentation validates");

        // A presentation from an issuer this realm does not trust must not inherit the previous
        // acceptance: the cache is keyed on the exact evidence bytes.
        let stranger = credential("https://attacker.example.com");
        let error = expect_rejection(validator.validate_evidence(&por(presentation(
            &attester,
            &stranger,
            &[0, 1],
        ))));
        assert!(error.contains("not a trusted attester"), "{error}");
    }

    #[test]
    fn an_unsigned_or_unsupported_credential_is_rejected() {
        let attester = Attester::new();
        let keys = Keys(attester.key_set());
        let issued = credential(&attester.config.issuer);

        // `alg: none` must never be accepted, whatever else the token says.
        let header = json!({"alg": "none", "kid": "attester-1"});
        let unsigned = format!(
            "{}.{}.~",
            base64url(serde_json::to_string(&header).unwrap().as_bytes()),
            base64url(serde_json::to_string(&issued.payload).unwrap().as_bytes())
        );
        let error = expect_rejection(
            validator(&attester, &keys).validate_evidence(&por(unsigned.into_bytes())),
        );
        assert!(error.contains("alg: none"));

        // An unsupported digest algorithm is rejected rather than assumed.
        let mut wrong_alg = credential(&attester.config.issuer);
        wrong_alg.payload["_sd_alg"] = json!("sha-1");
        let error = expect_rejection(
            validator(&attester, &keys).validate_evidence(&por(presentation(
                &attester,
                &wrong_alg,
                &[0],
            ))),
        );
        assert!(error.contains("_sd_alg"));
    }

    #[test]
    fn a_presentation_with_a_key_binding_jwt_is_rejected() {
        let attester = Attester::new();
        let keys = Keys(attester.key_set());
        let credential = credential(&attester.config.issuer);

        // Profile 0.2 uses no KB-JWT: a presentation that does not end with `~` carries one, and
        // this deployment does not accept it in place of the workload signatures.
        let mut evidence = String::from_utf8(presentation(&attester, &credential, &[0])).unwrap();
        evidence.push_str("eyJhbGciOiJFZERTQSJ9.e30.c2ln");

        let error = expect_rejection(
            validator(&attester, &keys).validate_evidence(&por(evidence.into_bytes())),
        );
        assert!(error.contains("Key Binding JWT"));
    }

    /// A real RS256 token from the lab IdP, with the JWK Keycloak publishes for it. Identity
    /// providers sign with RSA, so this path has to work against a genuine key, not a synthetic one.
    #[test]
    fn an_rsa_key_verifies_a_real_identity_provider_signature() {
        let jwk = serde_json::json!({
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "n": KEYCLOAK_MODULUS,
            "e": "AQAB",
        });
        let key = verification_key_from_jwk(&jwk).expect("the RSA JWK is read");

        let signing_input = format!("{KEYCLOAK_HEADER}.{KEYCLOAK_PAYLOAD}");
        let signature = b64url_decode(KEYCLOAK_SIGNATURE).expect("signature decodes");
        assert!(key.verify(signing_input.as_bytes(), &signature));

        // A different payload under the same signature must not verify.
        assert!(!key.verify(b"not what was signed", &signature));
    }

    #[test]
    fn an_undersized_or_malformed_rsa_key_is_refused() {
        // 1024-bit keys are not accommodated quietly.
        let small = serde_json::json!({
            "kty": "RSA",
            "n": base64url(&[0xC5; 128]),
            "e": "AQAB",
        });
        assert!(verification_key_from_jwk(&small).is_err());

        let no_exponent = serde_json::json!({ "kty": "RSA", "n": base64url(&[0xC5; 256]) });
        assert!(verification_key_from_jwk(&no_exponent).is_err());
    }

    #[test]
    fn a_p256_bound_key_is_accepted_as_the_walkthrough_uses_one() {
        // The centralized walkthrough binds P-256 workload keys through `cnf.jwk`, so the JWK
        // reader must produce a usable verifier for that curve too.
        let jwk = json!({
            "kty": "EC",
            "crv": "P-256",
            "kid": "worker-1-key",
            "x": "AbZzIerBJYtaxamji_Z4jT3oAuhAw_p-IPnIHFQ_YsM",
            "y": "LxUSbSzHe7-a3WbnZqMTfpRo_2VdTY_ugsn5xW9OWtU",
        });
        assert!(public_key_from_jwk(&jwk).is_ok());

        // A JWK carrying private material, or a truncated coordinate, is not a verification key.
        let mut private = jwk.clone();
        private["d"] = json!("a-private-scalar");
        assert!(public_key_from_jwk(&private).is_err());

        let mut short = jwk.clone();
        short["x"] = json!(base64url(&[0x01; 16]));
        assert!(public_key_from_jwk(&short).is_err());
    }
}
