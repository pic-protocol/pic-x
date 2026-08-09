//! What the administrative surface does when it cannot write the trail.
//!
//! Here rather than beside the code because it needs the middleware assembled the way the surface
//! assembles it — a router, a policy as state, a peer identity on the request — and a sink that
//! fails. That is a fixture, and the property it establishes is worth the fixture:
//!
//! **an operation that cannot be recorded does not happen.**
//!
//! The failure mode this exists to prevent is quiet and specific. A volume fills, or goes read-only,
//! or a permission changes; the calls keep succeeding; and the record of what was done to the
//! deployment during those hours does not exist. Nobody finds out until the day somebody asks what
//! happened, which is the one day the answer matters.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::routing::post;
use tower::ServiceExt;

use pic_x_core::{
    AuditError, AuditEvent, AuditRecorder, AuditSink, BoxFuture, PeerIdentity, Pseudonymizer,
};

use pic_x_admin::authorization::{Authorization, authorize};

/// A sink that behaves the way a full disk does.
#[derive(Debug)]
struct FullDisk;

impl AuditSink for FullDisk {
    fn name(&self) -> &'static str {
        "full-disk"
    }

    fn record<'a>(
        &'a self,
        _event: &'a AuditEvent<'a>,
        _pseudonymizer: Option<&'a dyn Pseudonymizer>,
    ) -> BoxFuture<'a, Result<(), AuditError>> {
        Box::pin(async { Err(AuditError::backend("No space left on device")) })
    }
}

/// A sink that takes everything, for the run that has to succeed.
#[derive(Debug)]
struct Accepting;

impl AuditSink for Accepting {
    fn name(&self) -> &'static str {
        "accepting"
    }

    fn record<'a>(
        &'a self,
        _event: &'a AuditEvent<'a>,
        _pseudonymizer: Option<&'a dyn Pseudonymizer>,
    ) -> BoxFuture<'a, Result<(), AuditError>> {
        Box::pin(async { Ok(()) })
    }
}

/// The operator the allowlist names.
fn operator() -> PeerIdentity {
    PeerIdentity::new(
        "CN=operator".to_owned(),
        Some("operator".to_owned()),
        "ab".repeat(32),
        "01",
    )
}

/// Builds the surface the way `AdminService` builds it, over a handler that records being reached.
///
/// The handler writing to a flag is the whole point: "the call was refused" and "the work did not
/// happen" are different claims, and only the second one matters.
fn surface(sink: Arc<dyn AuditSink>, reached: Arc<std::sync::atomic::AtomicBool>) -> Router {
    let policy = Authorization::new(vec!["cn:operator".parse().expect("a valid entry")], false)
        .recording(AuditRecorder::new(sink));

    Router::new()
        .route(
            "/picx.admin.v1.Admin/DoSomething",
            post(move || {
                let reached = Arc::clone(&reached);

                async move {
                    reached.store(true, std::sync::atomic::Ordering::SeqCst);

                    "done"
                }
            }),
        )
        .layer(axum::middleware::from_fn_with_state(
            Arc::new(policy),
            authorize,
        ))
}

/// Sends one administrative call as `peer`, and says what came back and whether the work ran.
async fn call(sink: Arc<dyn AuditSink>) -> (Option<String>, bool) {
    let reached = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut request = Request::builder()
        .method("POST")
        .uri("/picx.admin.v1.Admin/DoSomething")
        .body(Body::empty())
        .expect("the request builds");
    request.extensions_mut().insert(Arc::new(operator()));

    let response = surface(sink, Arc::clone(&reached))
        .oneshot(request)
        .await
        .expect("the surface answers");

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "a gRPC status travels in a header, never in the HTTP status"
    );

    let grpc = response
        .headers()
        .get("grpc-status")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);

    (grpc, reached.load(std::sync::atomic::Ordering::SeqCst))
}

#[tokio::test]
async fn test_work_that_cannot_be_recorded_is_not_done() {
    let (grpc, reached) = call(Arc::new(FullDisk)).await;

    assert!(
        !reached,
        "the operation ran even though the deployment could not record it"
    );
    assert_eq!(
        grpc.as_deref(),
        Some("14"),
        "the client was not told this is a condition that clears, so it will not retry"
    );
}

#[tokio::test]
async fn test_the_same_call_is_done_when_the_trail_takes_it() {
    // The other half. A surface that refuses everything is not strict, it is broken.
    let (grpc, reached) = call(Arc::new(Accepting)).await;

    assert!(reached, "the operation did not run: {grpc:?}");
    assert_eq!(grpc, None, "an admitted call carries no gRPC status header");
}

#[tokio::test]
async fn test_an_unrecordable_refusal_is_still_a_refusal_and_not_something_else() {
    // A client that is not on the list, and a trail that cannot be written. Two things are wrong and
    // the answer has to name the one the client can act on: it is not on the list. Reporting
    // `UNAVAILABLE` here would send an operator to look at the disk of a deployment that would have
    // refused them anyway.
    let reached = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut request = Request::builder()
        .method("POST")
        .uri("/picx.admin.v1.Admin/DoSomething")
        .body(Body::empty())
        .expect("the request builds");
    request.extensions_mut().insert(Arc::new(PeerIdentity::new(
        "CN=somebody-else".to_owned(),
        Some("somebody-else".to_owned()),
        "cd".repeat(32),
        "02",
    )));

    let response = surface(Arc::new(FullDisk), Arc::clone(&reached))
        .oneshot(request)
        .await
        .expect("the surface answers");

    assert_eq!(
        response
            .headers()
            .get("grpc-status")
            .and_then(|value| value.to_str().ok()),
        Some("7"),
    );
    assert!(!reached.load(std::sync::atomic::Ordering::SeqCst));
}
