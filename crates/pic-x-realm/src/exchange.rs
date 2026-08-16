//! Realm token exchange for PIC Profile 0.2.
//!
//! This module is intentionally the boundary between HTTP/OAuth integration and the pure PIC
//! protocol crate. It validates and maps the incoming access token according to the selected realm's
//! Exchange Profile, then hands an already-canonicalized authority checkpoint to `pic-rust` for the
//! PIC PCA COSE, settled Continuity COSE, and PIC Token JWT serialization/signing.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use pic::continuity::artifacts::token::decode_token;
use pic::continuity::artifacts::{PicContinuityCose, PicPcaCose, PicPcaPayload, PicTransitionCose};
use pic::continuity::authority::attenuation::ReferenceProfile;
use pic::continuity::authority::{
    AuthorityValue, IndexedAuthorityMap, Invariant, LogicalAuthority,
};
use pic::continuity::cose::{CoseError, SigningAlgorithm};
use pic::continuity::por::PorValidator;
use pic::continuity::proposal::InitialContinuityProposal;
use pic::continuity::trust::ArtifactSigner;
use pic::continuity::verifier::{SettlementAuthority, SettlementContext, issue_settled};
use regex::{Captures, Regex};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Serialize;
use serde_json::Value;
use tracing::{info, warn};

use pic_x_core::audit::{AuditEvent, Subject};
use pic_x_core::{
    ClaimMapping, EXCHANGE_ON_UNMATCHED_SCOPE_REJECT, EXCHANGE_SOURCE_OAUTH_ACCESS_TOKEN,
    ExchangeProfileConfig, InitialTokenExpiryPolicy, KeyManager, OAUTH_ACCESS_TOKEN_TYPE, Realm,
};

use crate::COMPONENT;
use crate::attester_keys::AttesterKeyCache;
use crate::checkpoints::{NoRevocationConfigured, RealmSignedCheckpoints};
use crate::conformance::ContractConformance;
use crate::idp_keys::IdpKeyCache;
use crate::por::{SdJwtPorValidator, verification_key_from_jwk};
use pic::continuity::jwk::expected_algorithms_for_jwk;

const GRANT_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const TOKEN_TYPE_N_A: &str = "N_A";
/// The longest lifetime an Initial Continuity Proposal may ask for, in seconds. The realm's
/// configured value still caps it; this only keeps an absurd request from being arithmetic.
const MAX_REQUESTED_LIFETIME: i64 = 365 * 24 * 3_600;

/// Runtime state for one realm token endpoint.
#[derive(Clone)]
pub(crate) struct TokenEndpoint {
    pub(crate) realm: Realm,
    /// The attester key sets backing Proof-of-Relationship validation.
    pub(crate) attester_keys: Arc<AttesterKeyCache>,
    /// The identity-provider key sets backing access-token verification.
    pub(crate) idp_keys: Arc<IdpKeyCache>,
}

/// RFC 8693 token-exchange response carrying a PIC Token JWT.
#[derive(Serialize)]
struct TokenExchangeResponse {
    access_token: String,
    issued_token_type: &'static str,
    token_type: &'static str,
}

/// OAuth-style error body.
#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
    error_description: String,
}

#[derive(Debug)]
struct ExchangeError {
    status: StatusCode,
    code: &'static str,
    description: String,
}

impl ExchangeError {
    fn invalid_request(description: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "invalid_request",
            description: description.into(),
        }
    }

    fn invalid_grant(description: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "invalid_grant",
            description: description.into(),
        }
    }

    fn invalid_target(description: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "invalid_target",
            description: description.into(),
        }
    }

    fn unsupported_token_type(description: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "unsupported_token_type",
            description: description.into(),
        }
    }

    fn temporarily_unavailable(description: impl Into<String>) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "temporarily_unavailable",
            description: description.into(),
        }
    }

    fn server_error(description: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "server_error",
            description: description.into(),
        }
    }

    fn response(self) -> Response {
        (
            self.status,
            Json(ErrorBody {
                error: self.code,
                error_description: self.description,
            }),
        )
            .into_response()
    }
}

/// The realm's token endpoint.
pub(crate) async fn token(State(endpoint): State<TokenEndpoint>, body: Bytes) -> Response {
    match endpoint.exchange(body).await {
        Ok(response) => response,
        Err(error) => error.response(),
    }
}

impl TokenEndpoint {
    async fn exchange(&self, body: Bytes) -> Result<Response, ExchangeError> {
        let form = parse_form(&body)?;

        require(&form, "grant_type").and_then(|grant| {
            if grant == GRANT_TOKEN_EXCHANGE {
                Ok(())
            } else {
                Err(ExchangeError::invalid_request(format!(
                    "unsupported grant_type `{grant}`"
                )))
            }
        })?;

        let requested = form.get("requested_token_type");
        if requested.is_some_and(|value| value != pic::continuity::TOKEN_TYPE_PIC) {
            return Err(ExchangeError::invalid_target(format!(
                "requested_token_type must be `{}`",
                pic::continuity::TOKEN_TYPE_PIC
            )));
        }

        let subject_token_type = require(&form, "subject_token_type")?;
        let subject_token = require(&form, "subject_token")?;

        match subject_token_type {
            OAUTH_ACCESS_TOKEN_TYPE => self.exchange_initial(subject_token, &form).await,
            value if value == pic::continuity::TOKEN_TYPE_PIC => {
                if form.contains_key("continuity_proposal")
                    || form.contains_key("continuity_proposal_type")
                {
                    return Err(ExchangeError::invalid_request(
                        "Profile 0.2 PIC-to-PIC advancement omits continuity_proposal",
                    ));
                }
                self.advance(subject_token).await
            }
            value => Err(ExchangeError::unsupported_token_type(format!(
                "unsupported subject_token_type `{value}`"
            ))),
        }
    }

    async fn exchange_initial(
        &self,
        access_token: &str,
        form: &BTreeMap<String, String>,
    ) -> Result<Response, ExchangeError> {
        let proposal_value = require(form, "continuity_proposal")?;
        if form
            .get("continuity_proposal_type")
            .is_some_and(|value| value != pic::continuity::PROPOSAL_TYPE_CONTINUITY_INITIAL)
        {
            return Err(ExchangeError::invalid_request(format!(
                "continuity_proposal_type must be `{}`",
                pic::continuity::PROPOSAL_TYPE_CONTINUITY_INITIAL
            )));
        }

        let jwt = DecodedJwt::decode(access_token)?;
        let profile = self.select_initial_profile(&jwt)?;
        self.validate_source_jwt(&jwt, profile)?;

        let mapped = map_authority(profile, &jwt.payload)?;
        let proposal = InitialContinuityProposal::from_continuity_proposal(proposal_value)
            .map_err(|error| {
                ExchangeError::invalid_request(format!("invalid continuity_proposal: {error}"))
            })?;

        let logical = LogicalAuthority::new(
            mapped.identity_context,
            mapped.invariants,
            proposal.execution_contract,
        );
        let authority = IndexedAuthorityMap::from_logical(&logical).map_err(|error| {
            ExchangeError::invalid_grant(format!("invalid derived authority: {error}"))
        })?;

        let mut challenge = vec![0_u8; 32];
        SystemRandom::new()
            .fill(&mut challenge)
            .map_err(|_| ExchangeError::server_error("could not generate the next challenge"))?;
        let lineage_id = new_lineage_id()?;
        let now = unix_now()?;
        let expiry = initial_expiry(
            proposal_value,
            jwt.claim_i64("exp"),
            now,
            self.realm.token_lifetime(),
            self.realm.initial_token_expiry_policy(),
        )?;
        let checkpoint = PicPcaPayload::new(0, authority, challenge)
            .with_lineage_id(lineage_id.clone())
            .with_expires_at(expiry);

        let keys = self.realm.token_keys().map(Arc::clone).ok_or_else(|| {
            ExchangeError::temporarily_unavailable(
                "the selected realm has no token-signing key ring",
            )
        })?;
        let signer = RealmTokenSigner::new(keys, self.realm.token_signing_algorithm())?;
        let context = SettlementContext {
            iss: self
                .realm
                .issuer()
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| self.realm.mount_path().to_owned()),
            sub: jwt.claim_string("sub"),
            aud: None,
            iat: Some(now),
            exp: Some(expiry),
            jti: Some(lineage_id.clone()),
        };
        let issued = issue_settled(checkpoint, &signer, &context).map_err(|error| {
            ExchangeError::server_error(format!("could not issue PIC Token JWT: {error}"))
        })?;

        // Recorded before the token leaves: authority that reached a caller with no durable trace
        // of who obtained it is exactly what a continuity system must not produce.
        self.record(
            AuditEvent::new(
                "pic.exchange.initialized",
                jwt.claim_string("sub")
                    .as_deref()
                    .map_or(Subject::Anonymous, Subject::Principal),
            )
            .on(&profile.id)
            .with_continuity_id(&lineage_id)
            .at_continuity_position(issued.checkpoint.position),
        )
        .await?;

        Ok(Json(TokenExchangeResponse {
            access_token: issued.token,
            issued_token_type: pic::continuity::TOKEN_TYPE_PIC,
            token_type: TOKEN_TYPE_N_A,
        })
        .into_response())
    }

    /// Profile 0.2 centralized advancement: validate a workload-signed candidate and, on success,
    /// checkpoint it into the next realm-signed PIC Token JWT.
    ///
    /// Every check belongs to the protocol crate's settlement procedure; what this realm supplies is
    /// the deployment boundary — which attesters it trusts, which checkpoints it accepts, its
    /// revocation and policy, and its signing key.
    async fn advance(&self, candidate_token: &str) -> Result<Response, ExchangeError> {
        let now = unix_now()?;
        let keys = self.realm.token_keys().map(Arc::clone).ok_or_else(|| {
            ExchangeError::temporarily_unavailable(
                "the selected realm has no token-signing key ring",
            )
        })?;
        let signer =
            RealmTokenSigner::new(Arc::clone(&keys), self.realm.token_signing_algorithm())?;

        let por = SdJwtPorValidator {
            attesters: self.realm.trusted_attesters(),
            keys: self.attester_keys.as_ref(),
            now,
            accepted: Default::default(),
        };
        let candidate_metadata = match preflight_candidate_key_metadata(candidate_token, &por) {
            Ok(metadata) => metadata,
            Err(error) => {
                self.record_advancement_rejected(None, None).await?;
                return Err(error);
            }
        };
        let Some(lineage_id) = candidate_metadata.lineage_id.clone() else {
            self.record_advancement_rejected(None, Some(candidate_metadata.proposed_position))
                .await?;
            return Err(ExchangeError::invalid_grant(
                "the candidate predecessor checkpoint has no lineage identifier",
            ));
        };
        if candidate_metadata.expires_at <= now {
            self.record_advancement_rejected(
                Some(&lineage_id),
                Some(candidate_metadata.proposed_position),
            )
            .await?;
            return Err(ExchangeError::invalid_grant(
                "the candidate predecessor checkpoint is expired",
            ));
        }
        // The settled token inherits the absolute expiry of the checkpoint it advances, so a
        // lineage cannot outlive the authority it started from by advancing repeatedly.
        let context = SettlementContext {
            iss: self
                .realm
                .issuer()
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| self.realm.mount_path().to_owned()),
            sub: None,
            aud: None,
            iat: Some(now),
            exp: Some(candidate_metadata.expires_at),
            jti: Some(lineage_id.clone()),
        };

        let settled = {
            // A checkpoint is this realm's when this realm's signature verifies over it — no store,
            // so a restart or a second replica changes nothing.
            let trusted = RealmSignedCheckpoints {
                keys: Arc::clone(&keys),
            };
            // The conformance check needs the claims the presentation disclosed, which exist only
            // after the PoR has been validated. The policy therefore reads them back from the
            // validator, which records what it accepted during the same settlement pass.
            let policy = ContractConformance { por: &por };
            let authority = SettlementAuthority {
                trusted: &trusted,
                por: &por,
                revocation: &NoRevocationConfigured,
                policy: &policy,
                order: &ReferenceProfile,
                realm: &signer,
            };
            authority.settle(candidate_token, &context)
        };

        let issued = match settled {
            Ok(issued) => issued,
            Err(error) => {
                warn!(
                    event.name = "token_exchange.advancement_rejected",
                    component = COMPONENT,
                    realm = self.realm.name(),
                    error = %error,
                    "a candidate PIC Token JWT was rejected"
                );
                self.record_advancement_rejected(
                    Some(&lineage_id),
                    Some(candidate_metadata.proposed_position),
                )
                .await?;
                // The reason is deliberately specific: every variant names a check the caller can fix,
                // and none of them reveals realm state the caller did not already hold.
                return Err(ExchangeError::invalid_grant(format!(
                    "the candidate was rejected: {error}"
                )));
            }
        };

        // An accepted advancement has to be attributable: which attester vouched for the workload,
        // and how many claims it disclosed to do so. The values themselves stay out of the record —
        // a disclosure is minimized on purpose, and re-emitting it here would undo that.
        if let Some(accepted) = por.accepted() {
            info!(
                event.name = "token_exchange.advancement_settled",
                component = COMPONENT,
                realm = self.realm.name(),
                attester = accepted.attester_id,
                por_issuer = accepted.issuer,
                disclosed_claims = accepted.claims.len(),
                position = issued.checkpoint.position,
                "a candidate PIC Token JWT was settled into the next checkpoint"
            );
        }

        let lineage_id = issued.checkpoint.lineage_id.clone().ok_or_else(|| {
            ExchangeError::server_error("the settled checkpoint has no lineage identifier to audit")
        })?;
        self.record(
            AuditEvent::continuity("pic.exchange.advanced", &lineage_id)
                .on(self.realm.name())
                .with_continuity_id(&lineage_id)
                .at_continuity_position(issued.checkpoint.position),
        )
        .await?;

        Ok(Json(TokenExchangeResponse {
            access_token: issued.token,
            issued_token_type: pic::continuity::TOKEN_TYPE_PIC,
            token_type: TOKEN_TYPE_N_A,
        })
        .into_response())
    }

    fn select_initial_profile<'a>(
        &'a self,
        jwt: &DecodedJwt,
    ) -> Result<&'a ExchangeProfileConfig, ExchangeError> {
        self.realm
            .exchange_profiles()
            .iter()
            .find(|profile| {
                profile.source.token_type == EXCHANGE_SOURCE_OAUTH_ACCESS_TOKEN
                    && jwt.claim_string("iss").as_deref() == Some(profile.source.issuer.as_str())
                    && jwt.audience_contains(&profile.source.audience)
            })
            .ok_or_else(|| {
                ExchangeError::invalid_grant(
                    "no exchange profile accepts this token issuer and audience in the selected realm",
                )
            })
    }

    fn validate_source_jwt(
        &self,
        jwt: &DecodedJwt,
        profile: &ExchangeProfileConfig,
    ) -> Result<(), ExchangeError> {
        let alg = jwt.header_string("alg").ok_or_else(|| {
            ExchangeError::invalid_grant("source access token header has no `alg`")
        })?;
        if !profile
            .source
            .validation
            .allowed_algorithms
            .iter()
            .any(|allowed| allowed == &alg)
        {
            return Err(ExchangeError::invalid_grant(format!(
                "source access token algorithm `{alg}` is not allowed by exchange profile `{}`",
                profile.id
            )));
        }

        if let Some(required) = &profile.source.validation.require_token_type {
            let typ = jwt.header_string("typ").ok_or_else(|| {
                ExchangeError::invalid_grant("source access token header has no `typ`")
            })?;
            if typ != *required {
                return Err(ExchangeError::invalid_grant(format!(
                    "source access token typ `{typ}` does not match required `{required}`"
                )));
            }
        }

        if jwt.claim_string("iss").as_deref() != Some(profile.source.issuer.as_str()) {
            return Err(ExchangeError::invalid_grant(
                "source access token issuer does not match the exchange profile",
            ));
        }
        if !jwt.audience_contains(&profile.source.audience) {
            return Err(ExchangeError::invalid_grant(
                "source access token audience does not match the exchange profile",
            ));
        }

        if profile.source.validation.require_expiration {
            let exp = jwt.claim_i64("exp").ok_or_else(|| {
                ExchangeError::invalid_grant("source access token has no numeric `exp`")
            })?;
            let now = unix_now()?;
            if exp <= now {
                return Err(ExchangeError::invalid_grant(
                    "source access token is expired",
                ));
            }
        }

        // Everything above read the token; this is where it becomes trustworthy. There is no
        // development shortcut: a token whose signature was never checked is indistinguishable from
        // one an attacker wrote, and deriving PIC authority from it would make every check that
        // follows meaningless.
        self.verify_source_signature(jwt, profile)
    }

    /// Verifies the access token against the key set its identity provider publishes.
    fn verify_source_signature(
        &self,
        jwt: &DecodedJwt,
        profile: &ExchangeProfileConfig,
    ) -> Result<(), ExchangeError> {
        let published = self.idp_keys.keys_for(&profile.id).map_err(|error| {
            // Not "invalid token": this realm cannot decide, and says so with a status a client
            // can retry against.
            ExchangeError::temporarily_unavailable(format!(
                "the key set of the identity provider for exchange profile `{}` is unavailable: {error}",
                profile.id
            ))
        })?;

        let algorithm = jwt.header_string("alg").ok_or_else(|| {
            ExchangeError::invalid_grant("source access token header has no `alg`")
        })?;
        let key_id = jwt.header_string("kid");

        // A `kid` narrows the candidates; without one, every published key is tried, which is what
        // keeps provider key rotation transparent.
        let candidates: Vec<&Value> = published
            .iter()
            .filter(|jwk| match &key_id {
                Some(wanted) => jwk.get("kid").and_then(Value::as_str) == Some(wanted.as_str()),
                None => true,
            })
            .collect();
        if candidates.is_empty() {
            return Err(ExchangeError::invalid_grant(
                "no published identity-provider key matches the token `kid`",
            ));
        }

        for jwk in candidates {
            // The key must be published for the algorithm the token claims, so a token cannot ask
            // for a weaker one than the provider stands behind.
            if jwk
                .get("alg")
                .and_then(Value::as_str)
                .is_some_and(|published| published != algorithm)
            {
                continue;
            }
            let Ok(key) = verification_key_from_jwk(jwk) else {
                continue;
            };
            if key.verify(jwt.signing_input.as_bytes(), &jwt.signature) {
                return Ok(());
            }
        }

        Err(ExchangeError::invalid_grant(
            "the source access token signature does not verify against the identity provider key set",
        ))
    }

    /// Writes one record, and refuses the exchange if it cannot be written.
    ///
    /// Synchronous on purpose. Handing the record to a background task and answering immediately
    /// would lose precisely the record of a crash, which is the one worth having; and authority
    /// that reached a caller with no durable trace of who obtained it is what a continuity system
    /// must not produce. The cost is one local append on the issuing path.
    async fn record(&self, event: AuditEvent<'_>) -> Result<(), ExchangeError> {
        let pseudonymizer = self.realm.pseudonymizer().map(Arc::as_ref);

        self.realm
            .audit()
            .record(&event, pseudonymizer)
            .await
            .map_err(|error| {
                ExchangeError::server_error(format!(
                    "the exchange was not recorded, so no token was issued: {error}"
                ))
            })
    }

    async fn record_advancement_rejected(
        &self,
        lineage_id: Option<&str>,
        position: Option<u64>,
    ) -> Result<(), ExchangeError> {
        let mut event = match lineage_id {
            Some(id) => AuditEvent::continuity("pic.exchange.rejected", id).with_continuity_id(id),
            None => AuditEvent::anonymous("pic.exchange.rejected"),
        }
        .on(self.realm.name());
        if let Some(position) = position {
            event = event.at_continuity_position(position);
        }

        self.record(event).await
    }
}

struct CandidateMetadata {
    lineage_id: Option<String>,
    expires_at: i64,
    proposed_position: u64,
}

fn preflight_candidate_key_metadata(
    candidate_token: &str,
    por: &SdJwtPorValidator<'_>,
) -> Result<CandidateMetadata, ExchangeError> {
    let decoded = decode_token(candidate_token).map_err(|error| {
        ExchangeError::invalid_grant(format!(
            "the candidate PIC Token JWT cannot be decoded: {error}"
        ))
    })?;
    let continuity_bytes = decoded.claims.root_bytes().map_err(|error| {
        ExchangeError::invalid_grant(format!(
            "the candidate PIC Token JWT root cannot be decoded: {error}"
        ))
    })?;
    let continuity_cose = PicContinuityCose::from_bytes(&continuity_bytes).map_err(|error| {
        ExchangeError::invalid_grant(format!(
            "the candidate Continuity COSE cannot be decoded: {error}"
        ))
    })?;
    let continuity = continuity_cose.payload_unverified().map_err(|error| {
        ExchangeError::invalid_grant(format!(
            "the candidate Continuity COSE payload cannot be decoded: {error}"
        ))
    })?;
    let transition_bytes = continuity.candidate_transition().map_err(|error| {
        ExchangeError::invalid_grant(format!(
            "the candidate Continuity does not carry exactly one transition: {error}"
        ))
    })?;
    let transition_cose = PicTransitionCose::from_bytes(transition_bytes).map_err(|error| {
        ExchangeError::invalid_grant(format!(
            "the candidate Transition COSE cannot be decoded: {error}"
        ))
    })?;
    let transition = transition_cose.payload_unverified().map_err(|error| {
        ExchangeError::invalid_grant(format!(
            "the candidate Transition COSE payload cannot be decoded: {error}"
        ))
    })?;
    let predecessor = PicPcaCose::from_bytes(&continuity.root.pca).map_err(|error| {
        ExchangeError::invalid_grant(format!(
            "the candidate predecessor PCA COSE cannot be decoded: {error}"
        ))
    })?;
    let predecessor = predecessor.payload_unverified().map_err(|error| {
        ExchangeError::invalid_grant(format!(
            "the candidate predecessor PCA payload cannot be decoded: {error}"
        ))
    })?;

    if transition.proof_of_relationship.por_type != por.accepted_type() {
        return Err(ExchangeError::invalid_grant(format!(
            "proof_of_relationship.type must be `{}`",
            por.accepted_type()
        )));
    }

    let processed = por
        .validate_and_remember(&transition.proof_of_relationship)
        .map_err(|error| {
            ExchangeError::invalid_grant(format!("the Proof of Relationship was rejected: {error}"))
        })?;
    let jwk = processed
        .claims
        .get("cnf")
        .and_then(|cnf| cnf.get("jwk"))
        .ok_or_else(|| {
            ExchangeError::invalid_grant(
                "the accepted Proof of Relationship did not expose `cnf.jwk`",
            )
        })?;
    let expected = expected_algorithms_for_jwk(jwk).map_err(|error| {
        ExchangeError::invalid_grant(format!(
            "the Proof of Relationship `cnf.jwk` is unusable: {error}"
        ))
    })?;

    if decoded.alg != expected.jose {
        return Err(ExchangeError::invalid_grant(format!(
            "candidate PIC Token JWT algorithm `{}` does not match Proof of Relationship key \
             algorithm `{}`",
            decoded.alg, expected.jose
        )));
    }
    let Some(cose_algorithm) = expected.cose else {
        return Err(ExchangeError::invalid_grant(
            "the Proof of Relationship workload key cannot verify PIC COSE signatures",
        ));
    };

    require_cose_algorithm(
        "candidate Continuity",
        continuity_cose.algorithm(),
        cose_algorithm,
    )?;
    require_cose_algorithm(
        "candidate Transition",
        transition_cose.algorithm(),
        cose_algorithm,
    )?;
    require_matching_cose_kid(continuity_cose.kid(), transition_cose.kid())?;

    // A transition that answers a challenge with the same value it was given advances the lineage
    // without moving its challenge state: the successor checkpoint would then accept the transition
    // that produced it. The profile keeps challenges per-lineage rather than globally single-use —
    // sibling branches from one checkpoint are intentional — so this is the freshness that can be
    // required without breaking fan-out.
    if transition.challenge.next_challenge == transition.challenge.previous_challenge {
        return Err(ExchangeError::invalid_grant(
            "the transition next_challenge repeats the challenge it answers",
        ));
    }

    if let Some(expected) = predecessor.lineage_id.as_deref() {
        match decoded.claims.jti.as_deref() {
            Some(actual) if actual == expected => {}
            Some(_) => {
                return Err(ExchangeError::invalid_grant(
                    "candidate PIC Token JWT jti does not match predecessor PCA lineage_id",
                ));
            }
            None => {
                return Err(ExchangeError::invalid_grant(
                    "candidate PIC Token JWT has no jti matching predecessor PCA lineage_id",
                ));
            }
        }
    }
    let Some(expires_at) = predecessor.expires_at else {
        return Err(ExchangeError::invalid_grant(
            "the candidate predecessor checkpoint has no absolute expiration",
        ));
    };
    match decoded.claims.exp {
        Some(exp) if exp == expires_at => {}
        Some(_) => {
            return Err(ExchangeError::invalid_grant(
                "candidate PIC Token JWT exp does not match predecessor PCA expiration",
            ));
        }
        None => {
            return Err(ExchangeError::invalid_grant(
                "candidate PIC Token JWT has no exp matching predecessor PCA expiration",
            ));
        }
    }

    Ok(CandidateMetadata {
        lineage_id: predecessor.lineage_id,
        expires_at,
        proposed_position: transition.position,
    })
}

fn require_cose_algorithm(
    label: &str,
    actual: Option<SigningAlgorithm>,
    expected: SigningAlgorithm,
) -> Result<(), ExchangeError> {
    match actual {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(ExchangeError::invalid_grant(format!(
            "{label} COSE algorithm `{actual}` does not match Proof of Relationship key algorithm \
             `{expected}`"
        ))),
        None => Err(ExchangeError::invalid_grant(format!(
            "{label} COSE has no supported signing algorithm"
        ))),
    }
}

fn require_matching_cose_kid(
    continuity_kid: Option<String>,
    transition_kid: Option<String>,
) -> Result<(), ExchangeError> {
    match (continuity_kid, transition_kid) {
        (Some(continuity), Some(transition)) if continuity == transition => Ok(()),
        (Some(continuity), Some(transition)) => Err(ExchangeError::invalid_grant(format!(
            "candidate Continuity COSE kid `{continuity}` does not match Transition COSE kid \
             `{transition}`"
        ))),
        (None, _) => Err(ExchangeError::invalid_grant(
            "candidate Continuity COSE has no `kid`",
        )),
        (_, None) => Err(ExchangeError::invalid_grant(
            "candidate Transition COSE has no `kid`",
        )),
    }
}

struct DecodedJwt {
    header: Value,
    payload: Value,
    /// `b64(header) . b64(payload)`, the bytes the provider signed.
    signing_input: String,
    signature: Vec<u8>,
}

impl DecodedJwt {
    fn decode(token: &str) -> Result<Self, ExchangeError> {
        let mut parts = token.split('.');
        let (Some(header), Some(payload), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(ExchangeError::invalid_grant(
                "source access token is not a compact JWS",
            ));
        };

        Ok(Self {
            header: decode_json_segment(header, "source access token header")?,
            payload: decode_json_segment(payload, "source access token payload")?,
            signing_input: format!("{header}.{payload}"),
            signature: URL_SAFE_NO_PAD.decode(signature).map_err(|error| {
                ExchangeError::invalid_grant(format!(
                    "source access token signature is not base64url: {error}"
                ))
            })?,
        })
    }

    fn header_string(&self, name: &str) -> Option<String> {
        self.header.get(name)?.as_str().map(ToOwned::to_owned)
    }

    fn claim_string(&self, name: &str) -> Option<String> {
        claim_at_path(&self.payload, name)?
            .as_str()
            .map(ToOwned::to_owned)
    }

    fn claim_i64(&self, name: &str) -> Option<i64> {
        claim_at_path(&self.payload, name)?.as_i64()
    }

    fn audience_contains(&self, expected: &str) -> bool {
        match claim_at_path(&self.payload, "aud") {
            Some(Value::String(value)) => value == expected,
            Some(Value::Array(values)) => values
                .iter()
                .any(|value| value.as_str().is_some_and(|aud| aud == expected)),
            _ => false,
        }
    }
}

struct MappedAuthority {
    identity_context: Option<BTreeMap<String, AuthorityValue>>,
    invariants: Vec<Invariant>,
}

fn map_authority(
    profile: &ExchangeProfileConfig,
    payload: &Value,
) -> Result<MappedAuthority, ExchangeError> {
    let identity_context = map_identity_context(profile, payload)?;
    let scopes = map_scopes(&profile.claims.scopes, payload)?;
    let invariants = map_invariants(profile, &scopes)?;

    Ok(MappedAuthority {
        identity_context,
        invariants,
    })
}

fn map_identity_context(
    profile: &ExchangeProfileConfig,
    payload: &Value,
) -> Result<Option<BTreeMap<String, AuthorityValue>>, ExchangeError> {
    let mut identity = BTreeMap::new();
    for (key, mapping) in &profile.claims.identity_context {
        let value = map_authority_value(mapping, payload).map_err(|error| {
            ExchangeError::invalid_grant(format!(
                "identity-context claim `{key}` could not be mapped: {error}"
            ))
        })?;
        identity.insert(key.clone(), value);
    }

    Ok((!identity.is_empty()).then_some(identity))
}

fn map_scopes(mapping: &ClaimMapping, payload: &Value) -> Result<Vec<String>, ExchangeError> {
    if mapping.value_type.as_deref() != Some("set") {
        return Err(ExchangeError::invalid_grant(
            "claims.scopes must be mapped as `type: set`",
        ));
    }

    let Some(path) = &mapping.from else {
        return Err(ExchangeError::invalid_grant(
            "claims.scopes must map from an upstream claim",
        ));
    };
    let source = claim_at_path(payload, path).ok_or_else(|| {
        ExchangeError::invalid_grant(format!("source access token has no `{path}` claim"))
    })?;

    let scopes = match source {
        Value::String(text) if mapping.encoding.as_deref() == Some("space-delimited") => text
            .split_whitespace()
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>(),
        Value::String(text) => vec![text.clone()],
        Value::Array(values) => values
            .iter()
            .map(|value| {
                value.as_str().map(ToOwned::to_owned).ok_or_else(|| {
                    ExchangeError::invalid_grant(format!(
                        "`{path}` must contain only string scope values"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => {
            return Err(ExchangeError::invalid_grant(format!(
                "`{path}` must be a string or array of strings"
            )));
        }
    };

    let scopes = scopes
        .into_iter()
        .filter(|scope| !scope.is_empty())
        .collect::<Vec<_>>();
    if scopes.is_empty() {
        return Err(ExchangeError::invalid_grant(
            "source access token produced no scopes",
        ));
    }

    Ok(scopes)
}

fn map_invariants(
    profile: &ExchangeProfileConfig,
    scopes: &[String],
) -> Result<Vec<Invariant>, ExchangeError> {
    let mut rules = Vec::new();
    for rule in &profile.privileges.rules {
        let pattern = Regex::new(&rule.pattern).map_err(|error| {
            ExchangeError::invalid_request(format!(
                "exchange profile `{}` has an invalid rule pattern `{}`: {error}",
                profile.id, rule.name
            ))
        })?;
        rules.push((rule.priority, rule, pattern));
    }
    // Highest priority first, so a specific rule consumes a scope before a generic one can.
    rules.sort_by_key(|(priority, _, _)| std::cmp::Reverse(*priority));

    let mut invariants = BTreeSet::new();
    for scope in scopes {
        let mut matched = false;
        for (_, rule, pattern) in &rules {
            let Some(captures) = pattern.captures(scope) else {
                continue;
            };
            let invariant = Invariant::new(
                render_template(&rule.emit.scope, scope, &captures)?,
                render_template(&rule.emit.operation, scope, &captures)?,
                render_template(&rule.emit.resource_type, scope, &captures)?,
                render_template(&rule.emit.resource_id, scope, &captures)?,
            );
            invariants.insert(invariant);
            matched = true;
            break;
        }

        if !matched && profile.on_unmatched_scope == EXCHANGE_ON_UNMATCHED_SCOPE_REJECT {
            return Err(ExchangeError::invalid_grant(format!(
                "scope `{scope}` is not accepted by exchange profile `{}`",
                profile.id
            )));
        }
    }

    if invariants.is_empty() {
        return Err(ExchangeError::invalid_grant(
            "the exchange produced no executable authority invariants",
        ));
    }

    Ok(invariants.into_iter().collect())
}

fn map_authority_value(mapping: &ClaimMapping, payload: &Value) -> Result<AuthorityValue, String> {
    if let Some(value) = &mapping.value {
        return Ok(AuthorityValue::One(value.clone()));
    }

    let path = mapping
        .from
        .as_ref()
        .ok_or_else(|| "mapping has no `from` or `value`".to_owned())?;
    let value = claim_at_path(payload, path).ok_or_else(|| format!("missing `{path}`"))?;

    match mapping.value_type.as_deref() {
        Some("set") => match value {
            Value::Array(values) => values
                .iter()
                .map(|item| {
                    item.as_str()
                        .map(ToOwned::to_owned)
                        .ok_or_else(|| format!("`{path}` contains a non-string value"))
                })
                .collect::<Result<Vec<_>, _>>()
                .map(AuthorityValue::Many),
            Value::String(text) if mapping.encoding.as_deref() == Some("space-delimited") => Ok(
                AuthorityValue::Many(text.split_whitespace().map(ToOwned::to_owned).collect()),
            ),
            Value::String(text) => Ok(AuthorityValue::Many(vec![text.clone()])),
            _ => Err(format!("`{path}` is not a string or array of strings")),
        },
        _ => value
            .as_str()
            .map(|text| AuthorityValue::One(text.to_owned()))
            .ok_or_else(|| format!("`{path}` is not a string")),
    }
}

fn render_template(
    template: &str,
    raw: &str,
    captures: &Captures<'_>,
) -> Result<String, ExchangeError> {
    let mut rendered = String::new();
    let mut rest = template;

    while let Some(start) = rest.find("${") {
        rendered.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            return Err(ExchangeError::invalid_request(format!(
                "template `{template}` has an unterminated placeholder"
            )));
        };
        let name = &after[..end];
        if name == "raw" {
            rendered.push_str(raw);
        } else {
            let Some(value) = captures.name(name) else {
                return Err(ExchangeError::invalid_request(format!(
                    "template `{template}` references missing capture `{name}`"
                )));
            };
            rendered.push_str(value.as_str());
        }
        rest = &after[end + 1..];
    }

    rendered.push_str(rest);
    Ok(rendered)
}

fn claim_at_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}

fn decode_json_segment(segment: &str, label: &str) -> Result<Value, ExchangeError> {
    let bytes = URL_SAFE_NO_PAD.decode(segment).map_err(|error| {
        ExchangeError::invalid_grant(format!("{label} is not base64url: {error}"))
    })?;
    serde_json::from_slice(&bytes)
        .map_err(|error| ExchangeError::invalid_grant(format!("{label} is not JSON: {error}")))
}

fn parse_form(body: &Bytes) -> Result<BTreeMap<String, String>, ExchangeError> {
    let text = std::str::from_utf8(body).map_err(|error| {
        ExchangeError::invalid_request(format!("request body is not UTF-8: {error}"))
    })?;
    let mut form = BTreeMap::new();

    for pair in text.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_decode(key)?;
        if form.insert(key.clone(), percent_decode(value)?).is_some() {
            return Err(ExchangeError::invalid_request(format!(
                "duplicate `{key}` parameter"
            )));
        }
    }

    Ok(form)
}

fn percent_decode(value: &str) -> Result<String, ExchangeError> {
    let mut decoded = Vec::new();
    let bytes = value.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' => {
                if index + 2 >= bytes.len() {
                    return Err(ExchangeError::invalid_request(
                        "form value contains an incomplete percent escape",
                    ));
                }
                let high = from_hex(bytes[index + 1])?;
                let low = from_hex(bytes[index + 2])?;
                decoded.push((high << 4) | low);
                index += 3;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }

    String::from_utf8(decoded).map_err(|error| {
        ExchangeError::invalid_request(format!("form value is not UTF-8: {error}"))
    })
}

fn from_hex(byte: u8) -> Result<u8, ExchangeError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(ExchangeError::invalid_request(
            "form value contains a non-hex percent escape",
        )),
    }
}

fn require<'a>(form: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str, ExchangeError> {
    form.get(name)
        .filter(|value| !value.is_empty())
        .map(String::as_str)
        .ok_or_else(|| ExchangeError::invalid_request(format!("missing `{name}` parameter")))
}

fn unix_now() -> Result<i64, ExchangeError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .map_err(|error| {
            ExchangeError::server_error(format!("system clock is before Unix epoch: {error}"))
        })
}

/// The absolute expiry an Initial Continuity Proposal asks for, when it asks for one.
///
/// The articles allow a proposal to carry "additional initialization material defined by its
/// proposal type", which is what this reads. The protocol crate tolerates the extra member, so the
/// proposal is parsed twice: once by the crate for the parts it defines, once here for this.
fn initial_expiry(
    encoded: &str,
    source_expiry: Option<i64>,
    now: i64,
    default_lifetime: Duration,
    policy: InitialTokenExpiryPolicy,
) -> Result<i64, ExchangeError> {
    if let Some(proposal_expiry) = proposal_expiry(encoded, now)? {
        return Ok(proposal_expiry);
    }

    let default_expiry = now
        .checked_add(default_lifetime.as_secs() as i64)
        .ok_or_else(|| ExchangeError::invalid_request("realm token_lifetime overflows time"))?;
    let expiry = match source_expiry {
        Some(source_expiry) => match policy {
            InitialTokenExpiryPolicy::Later => source_expiry.max(default_expiry),
            InitialTokenExpiryPolicy::Pic => default_expiry,
            InitialTokenExpiryPolicy::OAuth => source_expiry,
        },
        None => default_expiry,
    };
    if expiry <= now {
        return Err(ExchangeError::invalid_grant(
            "initial PIC Token expiration is not in the future",
        ));
    }

    Ok(expiry)
}

fn proposal_expiry(encoded: &str, now: i64) -> Result<Option<i64>, ExchangeError> {
    let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|error| {
        ExchangeError::invalid_request(format!("continuity_proposal is not base64url: {error}"))
    })?;
    let document: Value = serde_json::from_slice(&bytes).map_err(|error| {
        ExchangeError::invalid_request(format!("continuity_proposal is not JSON: {error}"))
    })?;

    if let Some(value) = document.get("tokenExpiresAt") {
        let expires_at = value
            .as_i64()
            .filter(|expires_at| *expires_at > now)
            .ok_or_else(|| {
                ExchangeError::invalid_request(
                    "`tokenExpiresAt` must be a future NumericDate in whole seconds",
                )
            })?;
        if expires_at - now > MAX_REQUESTED_LIFETIME {
            return Err(ExchangeError::invalid_request(
                "`tokenExpiresAt` is more than a year in the future",
            ));
        }
        return Ok(Some(expires_at));
    }

    let Some(value) = document.get("tokenLifetimeSeconds") else {
        return Ok(None);
    };
    let seconds = value
        .as_i64()
        .filter(|seconds| *seconds > 0)
        .ok_or_else(|| {
            ExchangeError::invalid_request(
                "`tokenLifetimeSeconds` must be a positive whole number of seconds",
            )
        })?;
    if seconds > MAX_REQUESTED_LIFETIME {
        return Err(ExchangeError::invalid_request(
            "`tokenLifetimeSeconds` is longer than a year",
        ));
    }

    now.checked_add(seconds)
        .ok_or_else(|| ExchangeError::invalid_request("`tokenLifetimeSeconds` overflows time"))
        .map(Some)
}

fn new_lineage_id() -> Result<String, ExchangeError> {
    let mut bytes = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| ExchangeError::server_error("could not generate a lineage identifier"))?;

    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

struct RealmTokenSigner {
    keys: Arc<dyn KeyManager>,
    kid: String,
    /// What the realm is configured to sign with; the ring must agree.
    algorithm: SigningAlgorithm,
    jose: String,
}

impl RealmTokenSigner {
    fn new(keys: Arc<dyn KeyManager>, jose: &str) -> Result<Self, ExchangeError> {
        let algorithm = match jose {
            "EdDSA" => SigningAlgorithm::EdDSA,
            "ES256" => SigningAlgorithm::ES256,
            other => {
                return Err(ExchangeError::server_error(format!(
                    "the realm is configured to sign with `{other}`, which this build cannot produce"
                )));
            }
        };
        let kid = keys
            .active_key_id()
            .map_err(|error| {
                ExchangeError::temporarily_unavailable(format!(
                    "the realm token-signing key ring is not ready: {error}"
                ))
            })?
            .to_string();

        Ok(Self {
            keys,
            kid,
            algorithm,
            jose: jose.to_owned(),
        })
    }
}

impl ArtifactSigner for RealmTokenSigner {
    fn kid(&self) -> &str {
        &self.kid
    }

    fn cose_algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    fn jws_algorithm(&self) -> &str {
        &self.jose
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CoseError> {
        let signature = self
            .keys
            .sign(data)
            .map_err(|error| CoseError::InvalidKey(error.to_string()))?;
        if signature.algorithm() != self.jws_algorithm() {
            return Err(CoseError::AlgorithmMismatch {
                expected: self.jws_algorithm().to_owned(),
                got: signature.algorithm().to_owned(),
            });
        }
        if signature.key_id().as_str() != self.kid {
            return Err(CoseError::InvalidKey(
                "active signing key changed while signing".to_owned(),
            ));
        }

        Ok(signature.bytes().to_vec())
    }
}
