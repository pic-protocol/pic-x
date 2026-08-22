// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

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
//!
//! # What happens when the trail cannot be written
//!
//! The call is refused, and it is refused *before* it runs. A full disk, a permission that changed, a
//! volume that went read-only: whatever the reason, an administrative operation that happened and was
//! not recorded is worse than one that did not happen. The first leaves a deployment in a state
//! nobody can account for; the second leaves it exactly as it was, and says so.
//!
//! There is no setting to turn that off. A knob here would be a knob for trading away the property
//! the surface exists to provide, and it would be found turned off during the investigation that
//! needed the record.
//!
//! A **refusal** that cannot be recorded is a warning and nothing more. The call is already being
//! refused, so there is no operation to prevent and nothing that failing harder would protect.

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

/// The gRPC status code for a deployment that cannot serve this right now.
///
/// Not `INTERNAL`: nothing here is broken and nothing about the request is wrong. The deployment
/// cannot write the record that has to exist before the work does, which is a condition that clears
/// when somebody frees the disk — and `UNAVAILABLE` is the one status a client is expected to retry.
const UNAVAILABLE: &str = "14";

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
        // Recorded before the work, and the work only happens if the record did.
        if !record(&policy, "admin.request", label, &target).await {
            return unrecordable();
        }

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
            // Not checked: the call is already refused, so there is no operation to prevent.
            let _recorded = record(&policy, "admin.refused", peer.label(), &target).await;
        }
        None => {
            warn!(
                event.name = "admin.refused",
                component = COMPONENT,
                rpc = %target,
                "the client presented no certificate this surface could read"
            );
            let _recorded = record(&policy, "admin.refused", "-", &target).await;
        }
    }

    refuse()
}

/// Records one decision. Returns whether the trail now says so.
///
/// A build that composed no recorder returns `true`: it has no trail to leave a gap in, and it was
/// warned about that when the surface started. Refusing every call because a deployment chose not to
/// audit would be enforcing a decision it already made.
async fn record(policy: &Authorization, action: &str, principal: &str, target: &str) -> bool {
    let Some(recorder) = &policy.recorder else {
        return true;
    };

    match recorder
        .record_on(action, Subject::Principal(principal), target)
        .await
    {
        Ok(()) => true,
        Err(error) => {
            warn!(
                event.name = "admin.unrecorded",
                component = COMPONENT,
                audit.action = action,
                error = %error,
                "the audit trail could not be written"
            );

            false
        }
    }
}

/// Builds the trailers-only response a gRPC client reads as `PERMISSION_DENIED`.
fn refuse() -> Response {
    status(
        PERMISSION_DENIED,
        "this client may not administer this deployment",
    )
}

/// Builds the answer for work that was not done because it could not be recorded.
///
/// It says which of the two happened, because "denied" and "not attempted" send whoever is reading it
/// to completely different places: one to the allowlist, the other to the disk.
fn unrecordable() -> Response {
    warn!(
        event.name = "admin.refused_unrecordable",
        component = COMPONENT,
        "refusing administrative work this deployment cannot record"
    );

    status(
        UNAVAILABLE,
        "this deployment cannot record what you asked it to do, so it did not do it",
    )
}

/// Builds the trailers-only response a gRPC client reads as `code`.
fn status(code: &'static str, message: &'static str) -> Response {
    let mut response = (StatusCode::OK, Body::empty()).into_response();
    let headers = response.headers_mut();

    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/grpc"),
    );
    headers.insert("grpc-status", HeaderValue::from_static(code));
    headers.insert("grpc-message", HeaderValue::from_static(message));

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
