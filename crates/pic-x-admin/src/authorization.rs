//! Deciding whether the client that got through the handshake may administer this deployment.
//!
//! # Why the handshake is not the decision
//!
//! Mutual TLS establishes that a client holds a certificate signed by an authority this deployment
//! trusts. That authority also signs every other client it was built to serve — service identities,
//! test fixtures, whatever else the organisation issues from it. A surface that stops there has
//! granted administration to all of them, and has done so invisibly, because nothing in the
//! configuration says that is what it did.
//!
//! So the handshake answers *who*, and the list answers *may they*.
//!
//! # What a refusal looks like
//!
//! A gRPC status, not an HTTP error. A client that receives `403 Forbidden` from what it believes is
//! a gRPC channel reports a transport failure, which sends whoever is debugging it to the network.
//! `PERMISSION_DENIED` sends them to the allowlist, which is where the answer is.
//!
//! # What is recorded
//!
//! Both outcomes, always, with the identity the certificate asserted. An administrative surface that
//! records what it allowed and not what it refused keeps no evidence of the thing most worth having
//! evidence of.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use tracing::{debug, warn};

use pic_x_core::{AllowedPeer, AuditRecorder, PeerIdentity, Subject};

/// The `component` every record of this surface carries.
const COMPONENT: &str = "admin";

/// The gRPC status code for a client that is who it says and may not do this.
const PERMISSION_DENIED: &str = "7";

/// Who may administer this deployment, and what to do about everyone else.
pub struct Authorization {
    allowed: Vec<AllowedPeer>,
    development: bool,
    recorder: Option<AuditRecorder>,
}

impl Authorization {
    /// Builds the policy from the peers a deployment listed.
    pub fn new(allowed: Vec<AllowedPeer>, development: bool) -> Self {
        Self {
            allowed,
            development,
            recorder: None,
        }
    }

    /// Records every decision to `recorder`.
    pub fn recording(mut self, recorder: AuditRecorder) -> Self {
        self.recorder = Some(recorder);

        self
    }

    /// Returns how many peers are named.
    pub fn len(&self) -> usize {
        self.allowed.len()
    }

    /// Reports whether nobody is named.
    pub fn is_empty(&self) -> bool {
        self.allowed.is_empty()
    }

    /// Decides whether `peer` may call this surface.
    ///
    /// An empty list admits everyone the authority signed, and only in development. That is the
    /// behaviour a deployment gets when it has said it is somebody's laptop, and
    /// `Config::validate` refuses the same configuration anywhere else — so this arm is reachable
    /// only after somebody wrote down that they meant it.
    pub fn permits(&self, peer: Option<&PeerIdentity>) -> bool {
        let Some(peer) = peer else {
            // No certificate reached the application, which means the verifier did not demand one.
            // Nothing here can tell who this is, so nothing here may let them through.
            return false;
        };

        if self.allowed.is_empty() {
            return self.development;
        }

        peer.is_allowed_by(&self.allowed)
    }
}

/// Refuses every request that the policy does not permit, and records both outcomes.
pub async fn authorize(
    State(policy): State<Arc<Authorization>>,
    request: Request,
    next: Next,
) -> Response {
    let peer = request
        .extensions()
        .get::<Arc<PeerIdentity>>()
        .map(Arc::clone);
    // The gRPC method is the path, and it is what the audit trail means by "what was done".
    let target = request.uri().path().to_owned();

    if policy.permits(peer.as_deref()) {
        let label = peer.as_ref().map_or("-", |peer| peer.label());

        debug!(
            event.name = "admin.permitted",
            component = COMPONENT,
            rpc = %target,
            "admitted"
        );
        record(&policy, "admin.request", label, &target).await;

        return next.run(request).await;
    }

    match peer.as_ref() {
        Some(peer) => {
            warn!(
                event.name = "admin.refused",
                component = COMPONENT,
                rpc = %target,
                // Named in full here, and pseudonymised in the audit record below. The two streams
                // are for different readers: this one is for the operator who has to work out why a
                // colleague cannot administer anything, and answering that with a pseudonym would
                // make it unanswerable. A client certificate is also public by construction — it is
                // presented in the clear on every connection — and it identifies an operator rather
                // than an end user.
                peer = %peer,
                peer.fingerprint = peer.fingerprint(),
                "the client is not on the list of peers that may administer this deployment"
            );
            record(&policy, "admin.refused", peer.label(), &target).await;
        }
        None => {
            warn!(
                event.name = "admin.refused",
                component = COMPONENT,
                rpc = %target,
                "the client presented no certificate this surface could read"
            );
            record(&policy, "admin.refused", "-", &target).await;
        }
    }

    refuse()
}

/// Records one decision, and says so if it could not.
///
/// A decision that was made but not recorded is worth a warning: it is the difference between an
/// audit trail with a gap and an audit trail nobody knows has one.
async fn record(policy: &Authorization, action: &str, principal: &str, target: &str) {
    let Some(recorder) = &policy.recorder else {
        return;
    };

    if let Err(error) = recorder
        .record_on(action, Subject::Principal(principal), target)
        .await
    {
        warn!(
            event.name = "admin.unrecorded",
            component = COMPONENT,
            audit.action = action,
            error = %error,
            "the decision was made but not recorded"
        );
    }
}

/// Builds the trailers-only response a gRPC client reads as `PERMISSION_DENIED`.
fn refuse() -> Response {
    let mut response = (StatusCode::OK, Body::empty()).into_response();
    let headers = response.headers_mut();

    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/grpc"),
    );
    headers.insert("grpc-status", HeaderValue::from_static(PERMISSION_DENIED));
    headers.insert(
        "grpc-message",
        HeaderValue::from_static("this client may not administer this deployment"),
    );

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(common_name: &str) -> PeerIdentity {
        PeerIdentity::new(
            format!("CN={common_name}"),
            Some(common_name.to_owned()),
            "ab".repeat(32),
            "01",
        )
    }

    fn listing(entries: &[&str]) -> Vec<AllowedPeer> {
        entries
            .iter()
            .filter_map(|entry| entry.parse().ok())
            .collect()
    }

    #[test]
    fn test_a_named_peer_is_admitted_and_an_unnamed_one_is_not() {
        let policy = Authorization::new(listing(&["cn:operator"]), false);

        assert!(policy.permits(Some(&peer("operator"))));
        assert!(!policy.permits(Some(&peer("someone-else"))));
    }

    #[test]
    fn test_a_client_with_no_certificate_is_never_admitted() {
        // Not even in development: there is nothing to record and nothing to check.
        for development in [false, true] {
            let policy = Authorization::new(Vec::new(), development);

            assert!(!policy.permits(None), "development = {development}");
        }
    }

    #[test]
    fn test_an_empty_list_admits_the_authoritys_clients_only_in_development() {
        assert!(Authorization::new(Vec::new(), true).permits(Some(&peer("anyone"))));
        assert!(!Authorization::new(Vec::new(), false).permits(Some(&peer("anyone"))));
    }

    #[test]
    fn test_development_does_not_widen_a_list_that_was_written() {
        // Having said "this is a laptop" must not quietly turn an allowlist into a suggestion.
        let policy = Authorization::new(listing(&["cn:operator"]), true);

        assert!(!policy.permits(Some(&peer("someone-else"))));
    }

    #[test]
    fn test_a_refusal_is_a_grpc_status_rather_than_an_http_error() {
        let response = refuse();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("grpc-status")
                .and_then(|value| value.to_str().ok()),
            Some(PERMISSION_DENIED)
        );
    }
}
