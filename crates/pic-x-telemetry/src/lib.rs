//! The telemetry surface: liveness, readiness and metrics.
//!
//! It is HTTP and it is on a port of its own, and both of those are deliberate.
//!
//! **HTTP**, because this is the one surface whose clients are not ours: Prometheus scrapes over
//! HTTP and a kubelet probes over HTTP. Serving it over gRPC would mean every operator needs a custom
//! client to read a number.
//!
//! **A port of its own**, because it must never leave the cluster. Metrics describe the inside of the
//! process and health tells an attacker when the process is struggling; neither belongs on the port
//! that faces the world.
//!
//! # Liveness is not readiness
//!
//! `/healthz` answers "is this process wedged", and a `false` means *restart me*. `/readyz` answers
//! "should I be sent work", and it goes false at the very start of shutdown — before anything is
//! closed — so a load balancer stops routing while the process is still able to finish what it
//! already has. Reporting one number for both loses requests at every deploy.

#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::unwrap_used, clippy::expect_used)]

use std::sync::Mutex;

use anyhow::{Context, Result, anyhow};
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use tracing::info;

use pic_x_core::{BoxFuture, Health, ServerContext, Service, ready};
use pic_x_transport::Surface;

/// The `component` every record of this surface carries.
const COMPONENT: &str = "telemetry";

/// The telemetry surface.
///
/// It is a [`Service`] like any other, so it starts and stops with everything else and needs no
/// special case in the host. What makes it unusual is only that it reads the health the host writes.
#[derive(Default)]
pub struct TelemetryService {
    running: Mutex<Option<Surface>>,
}

impl TelemetryService {
    /// Builds a telemetry surface that has not started yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds the routes this surface answers on.
    ///
    /// Public so a build that assembles its own HTTP surface can mount the same handlers somewhere
    /// else rather than reimplement them.
    pub fn routes(health: Health) -> Router {
        Router::new()
            .route("/healthz", get(healthz))
            .route("/readyz", get(readyz))
            .route("/metrics", get(metrics))
            .with_state(health)
    }
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

impl Service for TelemetryService {
    fn name(&self) -> &'static str {
        COMPONENT
    }

    fn start<'a>(&'a self, context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            // No address means the deployment did not ask for this surface. That is a choice, not a
            // misconfiguration, so it is reported and the run continues.
            let Some(configured) = context.config().telemetry_addr() else {
                info!(
                    event.name = "telemetry.disabled",
                    component = COMPONENT,
                    "no telemetry address is configured"
                );

                return Ok(());
            };

            let secured = context.config().telemetry_tls();
            let surface = Surface::start(
                configured,
                Self::routes(context.health().clone()),
                secured.as_ref(),
            )
            .await
            .context("starting the telemetry surface")?;

            let bound = surface.address();
            *self
                .running
                .lock()
                .map_err(|_| anyhow!("the telemetry surface lock is poisoned"))? = Some(surface);

            info!(
                event.name = "telemetry.listening",
                component = COMPONENT,
                address = %bound,
                tls = secured.is_some(),
                "listening"
            );

            Ok(())
        })
    }

    fn stop<'a>(&'a self, context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        let surface = match self.running.lock() {
            Ok(mut running) => running.take(),
            Err(_) => return ready(Err(anyhow!("the telemetry surface lock is poisoned"))),
        };

        Box::pin(async move {
            let Some(surface) = surface else {
                return Ok(());
            };

            let address = surface
                .stop(context.config().shutdown_timeout())
                .await
                .context("waiting for the telemetry surface to finish")?;

            info!(
                event.name = "telemetry.stopped_listening",
                component = COMPONENT,
                address = %address,
                "stopped listening"
            );

            Ok(())
        })
    }
}
