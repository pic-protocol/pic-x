//! What the surface answers: liveness, readiness, and the exposition a scraper reads.
//!
//! Free functions rather than methods, because a build that assembles its own HTTP surface should be
//! able to mount these somewhere else instead of reimplementing what "ready" means.

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;

use pic_x_core::Health;

/// Builds the routes this surface answers on.
pub fn routes(health: Health) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .with_state(health)
}

/// Answers whether the process is wedged. A failure here means *restart me*.
async fn healthz(State(health): State<Health>) -> (StatusCode, &'static str) {
    if health.is_live() {
        (StatusCode::OK, "live\n")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not live\n")
    }
}

/// Answers whether the process should be sent work. False from the first instant of shutdown.
async fn readyz(State(health): State<Health>) -> (StatusCode, &'static str) {
    if health.is_ready() {
        (StatusCode::OK, "ready\n")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready\n")
    }
}

/// The Prometheus exposition.
///
/// Deliberately thin for now: readiness and liveness as gauges, which is what an operator needs
/// before there is anything else to count. A metrics registry is a decision of its own and does not
/// have to be made to have a `/metrics` that already means something.
async fn metrics(State(health): State<Health>) -> (StatusCode, String) {
    let body = format!(
        "# HELP picx_up Whether the process reports itself live.\n\
         # TYPE picx_up gauge\n\
         picx_up {}\n\
         # HELP picx_ready Whether the process is willing to be sent work.\n\
         # TYPE picx_ready gauge\n\
         picx_ready {}\n",
        u8::from(health.is_live()),
        u8::from(health.is_ready())
    );

    (StatusCode::OK, body)
}
