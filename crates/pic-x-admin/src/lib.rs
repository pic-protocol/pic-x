//! The PIC-X administrative surface.
//!
//! It is gRPC, it is on a port of its own, and it is the one that must never be reachable from
//! outside without authentication. Everything that changes the state of a deployment belongs here,
//! which is exactly why the transport is separate from the public one: a mistake in a reverse proxy
//! should not be able to expose administration by accident.
//!
//! # Extending it
//!
//! A build adds RPCs by **registering services**, not by wrapping this crate — the same rule as the
//! public surface, for the same reason. A [`ServiceProvider`] contributes whatever `tonic` services
//! it defines from its own `.proto`, in its own package, compiled by its own build script. Nothing
//! about the protocol has to be centralised for that to work.
//!
//! # Who may call it
//!
//! Two questions, answered in two places. The handshake answers *who is this* — mutual TLS, so a
//! client with no certificate never reaches the application. The allowlist answers *may they* — see
//! [`authorization`], and the reason the second question exists at all.
//!
//! An administrative surface bound to an address outside this host, with no client certificate
//! demanded, is refused by `Config::validate` before anything binds. That has always been what the
//! documentation here promised; it is now also what the code does.

#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::unwrap_used, clippy::expect_used)]

pub mod authorization;

use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow};
use axum::Router;
use tonic::service::RoutesBuilder;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use pic_x_core::{BoxFuture, Health, ServerContext, Service, TlsSettings, ready};
use pic_x_transport::Surface;

use crate::authorization::Authorization;

/// The protocol this surface speaks, compiled from `proto/picx/admin/v1/admin.proto`.
pub mod v1 {
    #![allow(clippy::all, clippy::pedantic, missing_docs)]

    tonic::include_proto!("picx.admin.v1");
}

use v1::admin_server::{Admin, AdminServer};
use v1::{GetHealthRequest, GetHealthResponse, GetVersionRequest, GetVersionResponse};

/// The `component` every record of this surface carries.
const COMPONENT: &str = "admin";

/// Contributes gRPC services to the administrative surface.
///
/// A build outside this workspace implements this over its own generated code and registers it.
pub trait ServiceProvider: Send + Sync {
    /// Returns the name of this provider, for diagnostics.
    fn name(&self) -> &'static str;

    /// Adds whatever services it defines to the surface being assembled.
    fn add_to(&self, routes: &mut RoutesBuilder);
}

/// The implementation of the administrative RPCs PIC-X itself defines.
struct AdminApi {
    product: String,
    version: String,
    health: Health,
}

#[tonic::async_trait]
impl Admin for AdminApi {
    async fn get_version(
        &self,
        _request: Request<GetVersionRequest>,
    ) -> Result<Response<GetVersionResponse>, Status> {
        Ok(Response::new(GetVersionResponse {
            product: self.product.clone(),
            version: self.version.clone(),
        }))
    }

    async fn get_health(
        &self,
        _request: Request<GetHealthRequest>,
    ) -> Result<Response<GetHealthResponse>, Status> {
        Ok(Response::new(GetHealthResponse {
            live: self.health.is_live(),
            ready: self.health.is_ready(),
        }))
    }
}

/// The administrative surface.
pub struct AdminService {
    providers: Vec<Box<dyn ServiceProvider>>,
    running: Mutex<Option<Surface>>,
}

impl Default for AdminService {
    fn default() -> Self {
        Self::new()
    }
}

impl AdminService {
    /// Builds an administrative surface with nothing but the RPCs PIC-X defines.
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
            running: Mutex::new(None),
        }
    }

    /// Registers services a build adds, beside the ones PIC-X defines.
    pub fn with_services(mut self, provider: Box<dyn ServiceProvider>) -> Self {
        self.providers.push(provider);

        self
    }

    /// Returns the names of the providers whose services this surface is serving.
    pub fn providers(&self) -> impl Iterator<Item = &'static str> {
        self.providers.iter().map(|provider| provider.name())
    }

    /// Assembles every service this surface answers: the ones PIC-X defines, plus registered ones.
    pub fn routes(&self, context: &ServerContext<'_>) -> tonic::service::Routes {
        let mut routes = RoutesBuilder::default();

        routes.add_service(AdminServer::new(AdminApi {
            product: context.identity().product_name().to_owned(),
            version: context.config().version().to_owned(),
            health: context.health().clone(),
        }));

        for provider in &self.providers {
            provider.add_to(&mut routes);
        }

        routes.routes()
    }

    /// Assembles what the surface actually serves: the routes, behind the policy when there is one.
    ///
    /// Returns nothing to authorise against when the surface demands no client certificate. That
    /// configuration is either a loopback address or a deployment that said it is somebody's laptop
    /// — `Config::validate` has already refused everything else — and in both cases there is no
    /// identity to check, so pretending to check one would be theatre.
    fn serving(&self, context: &ServerContext<'_>, secured: Option<&TlsSettings>) -> Router {
        let router = self.routes(context).into_axum_router();

        if !secured.is_some_and(TlsSettings::is_mutual) {
            warn!(
                event.name = "admin.unauthenticated",
                component = COMPONENT,
                "this surface demands no client certificate, so it authorises nobody and admits \
                 anything that can reach the address"
            );

            return router;
        }

        let mut policy = Authorization::new(
            context.config().grpc_allow().to_vec(),
            context.config().development_mode(),
        );

        match context.recorder() {
            Some(recorder) => policy = policy.recording(recorder.clone()),
            None => warn!(
                event.name = "admin.unrecorded",
                component = COMPONENT,
                "this build composes no audit recorder, so administrative calls reach the log and \
                 not the audit trail"
            ),
        }

        if policy.is_empty() {
            warn!(
                event.name = "admin.open_to_the_authority",
                component = COMPONENT,
                "no peers are listed, so every client this authority signed may administer this \
                 deployment: acceptable only because this deployment says it is a development one"
            );
        } else {
            info!(
                event.name = "admin.authorising",
                component = COMPONENT,
                peers = policy.len(),
                "only the listed peers may administer this deployment"
            );
        }

        router.layer(axum::middleware::from_fn_with_state(
            Arc::new(policy),
            authorization::authorize,
        ))
    }
}

impl Service for AdminService {
    fn name(&self) -> &'static str {
        COMPONENT
    }

    fn start<'a>(&'a self, context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let Some(configured) = context.config().grpc_addr() else {
                info!(
                    event.name = "admin.disabled",
                    component = COMPONENT,
                    "no gRPC address is configured"
                );

                return Ok(());
            };

            let secured = context.config().grpc_tls();
            let surface = Surface::start(
                configured,
                self.serving(context, secured.as_ref()),
                secured.as_ref(),
            )
            .await
            .context("starting the administrative surface")?;

            let bound = surface.address();
            *self
                .running
                .lock()
                .map_err(|_| anyhow!("the administrative surface lock is poisoned"))? =
                Some(surface);

            info!(
                event.name = "admin.listening",
                component = COMPONENT,
                address = %bound,
                providers = self.providers.len(),
                tls = secured.is_some(),
                mutual_tls = secured.as_ref().is_some_and(pic_x_core::TlsSettings::is_mutual),
                "listening"
            );

            Ok(())
        })
    }

    fn stop<'a>(&'a self, context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        let surface = match self.running.lock() {
            Ok(mut running) => running.take(),
            Err(_) => return ready(Err(anyhow!("the administrative surface lock is poisoned"))),
        };

        Box::pin(async move {
            let Some(surface) = surface else {
                return Ok(());
            };

            let address = surface
                .stop(context.config().shutdown_timeout())
                .await
                .context("waiting for the administrative surface to finish")?;

            info!(
                event.name = "admin.stopped_listening",
                component = COMPONENT,
                address = %address,
                "stopped listening"
            );

            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    use pic_x_audit::RecordingAuditSink;
    use pic_x_core::{Config, ProductIdentity};
    use pic_x_storage::MemoryStorage;

    fn identity() -> ProductIdentity {
        ProductIdentity::new("demo-x", "Demo X", "A tagline", "Demo X CLI", "<art>")
    }

    #[tokio::test]
    async fn test_the_rpcs_answer_what_the_context_says() {
        let config = Config::default();
        let storage = MemoryStorage::new();
        let audit = RecordingAuditSink::new();
        let context = ServerContext::new(identity(), &config, &storage, &audit);
        context.health().set_ready(true);

        let api = AdminApi {
            product: context.identity().product_name().to_owned(),
            version: context.config().version().to_owned(),
            health: context.health().clone(),
        };

        let version = api
            .get_version(Request::new(GetVersionRequest {}))
            .await
            .expect("the version answers")
            .into_inner();
        assert_eq!(version.product, "Demo X");
        assert_eq!(version.version, config.version());

        let health = api
            .get_health(Request::new(GetHealthRequest {}))
            .await
            .expect("the health answers")
            .into_inner();
        assert!(health.live);
        assert!(health.ready);
    }

    #[tokio::test]
    async fn test_health_follows_the_state_the_host_flips() {
        let config = Config::default();
        let storage = MemoryStorage::new();
        let audit = RecordingAuditSink::new();
        let context = ServerContext::new(identity(), &config, &storage, &audit);

        let api = AdminApi {
            product: "Demo X".to_owned(),
            version: "9.9.9".to_owned(),
            health: context.health().clone(),
        };

        // Not ready before the host says so, which is what a probe during startup must see.
        let before = api
            .get_health(Request::new(GetHealthRequest {}))
            .await
            .expect("the health answers")
            .into_inner();
        assert!(!before.ready);

        context.health().set_ready(true);

        let after = api
            .get_health(Request::new(GetHealthRequest {}))
            .await
            .expect("the health answers")
            .into_inner();
        assert!(after.ready);
    }
}
