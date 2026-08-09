//! The surface itself: one [`Service`] that binds, serves the probes, and stops with everything else.

use std::sync::Mutex;

use anyhow::{Context, Result, anyhow};
use axum::Router;
use tracing::info;

use pic_x_core::{BoxFuture, ServerContext, Service, ready};
use pic_x_transport::Surface;

use crate::probes;

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
    pub fn routes(reported: probes::Reported) -> Router {
        probes::routes(reported)
    }
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
            let surface = Surface::listener(
                COMPONENT,
                configured,
                Self::routes(probes::Reported::new(
                    context.health().clone(),
                    context.metrics().clone(),
                )),
            )
            .tls(secured.as_ref())
            .limits(context.config().limits())
            .metrics(context.metrics().clone())
            .start()
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
