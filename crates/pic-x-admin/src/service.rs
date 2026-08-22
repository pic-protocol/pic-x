// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The surface itself: what it serves, who may reach it, and how it starts and stops.

use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow};
use axum::Router;
use tonic::service::RoutesBuilder;
use tracing::{info, warn};

use pic_x_core::{BoxFuture, ServerContext, Service, TlsSettings, ready};
use pic_x_transport::Surface;

use crate::COMPONENT;
use crate::api::AdminApi;
use crate::authorization::{self, Authorization};
use crate::v1::admin_server::AdminServer;

/// Contributes gRPC services to the administrative surface.
///
/// A build outside this workspace implements this over its own generated code and registers it.
pub trait ServiceProvider: Send + Sync {
    /// Returns the name of this provider, for diagnostics.
    fn name(&self) -> &'static str;

    /// Adds whatever services it defines to the surface being assembled.
    fn add_to(&self, routes: &mut RoutesBuilder);
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
            commit: context.config().commit().to_owned(),
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
            context.config().admin_allow().to_vec(),
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
            let Some(configured) = context.config().admin_addr() else {
                info!(
                    event.name = "admin.disabled",
                    component = COMPONENT,
                    "no admin address is configured"
                );

                return Ok(());
            };

            let secured = context.config().admin_tls();
            let surface = Surface::listener(
                COMPONENT,
                configured,
                self.serving(context, secured.as_ref()),
            )
            .tls(secured.as_ref())
            .limits(context.config().limits())
            .metrics(context.metrics().clone())
            .start()
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
