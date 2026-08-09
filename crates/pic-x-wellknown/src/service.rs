//! The surface itself: what it mounts, what may wrap it, and how it starts and stops.

use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow};
use axum::Router;
use axum::routing::get;
use tracing::info;

use pic_x_core::{BoxFuture, Config, KeyManager, ProductIdentity, ServerContext, Service, ready};
use pic_x_transport::Surface;

use crate::COMPONENT;
use crate::routes::{Discovery, Public, discovery, jwks, root};

/// Contributes routes to the public surface.
///
/// A build outside this workspace implements this and registers it; nothing here has to know the
/// implementation exists.
pub trait RouteProvider: Send + Sync {
    /// Returns the name of this provider, for diagnostics.
    fn name(&self) -> &'static str;

    /// Returns the routes it contributes.
    fn routes(&self) -> Router;
}

/// The public surface.
pub struct WellKnownService {
    providers: Vec<Box<dyn RouteProvider>>,
    layers: Vec<Box<dyn Fn(Router) -> Router + Send + Sync>>,
    running: Mutex<Option<Surface>>,
}

impl Default for WellKnownService {
    fn default() -> Self {
        Self::new()
    }
}

impl WellKnownService {
    /// Builds a public surface with nothing but the routes PIC-X defines.
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
            layers: Vec::new(),
            running: Mutex::new(None),
        }
    }

    /// Registers routes a build adds, beside the ones PIC-X defines.
    pub fn with_routes(mut self, provider: Box<dyn RouteProvider>) -> Self {
        self.providers.push(provider);

        self
    }

    /// Registers something that wraps every route, including the ones PIC-X defines.
    ///
    /// This is the extension point that matters: authentication, rate limiting and per-request
    /// logging are not routes to add, they are behaviour to impose on routes that already exist.
    pub fn with_layer<F>(mut self, layer: F) -> Self
    where
        F: Fn(Router) -> Router + Send + Sync + 'static,
    {
        self.layers.push(Box::new(layer));

        self
    }

    /// Assembles the router: the routes PIC-X defines, plus registered ones, under every layer.
    /// Assembles the router: the routes PIC-X defines, plus registered ones, under every layer.
    ///
    /// What the discovery document *advertises* comes from the issuer, and where the routes are
    /// *mounted* comes from the path prefix. They are separate on purpose: a proxy that serves this
    /// deployment under a path normally strips that path before forwarding, so the advertised URL has
    /// a prefix the process never sees. Deriving one from the other — as some do — is what makes a
    /// working proxy configuration hard to arrive at.
    pub fn router(
        &self,
        identity: &ProductIdentity,
        config: &Config,
        keys: Option<Arc<dyn KeyManager>>,
    ) -> Router {
        let mut router = Router::new()
            .route("/", get(root))
            .route("/.well-known/pic-x-configuration", get(discovery))
            .route("/.well-known/jwks.json", get(jwks))
            .with_state(Public {
                discovery: Discovery {
                    product: identity.product_name().to_owned(),
                    version: config.version().to_owned(),
                    issuer: config.issuer().map(ToOwned::to_owned),
                    jwks_uri: config.public_url("/.well-known/jwks.json"),
                },
                keys,
            });

        for provider in &self.providers {
            router = router.merge(provider.routes());
        }

        for layer in &self.layers {
            router = layer(router);
        }

        // Mounting under a prefix is for the proxies that forward the path unstripped. The advertised
        // URLs are unaffected: they come from the issuer, which already contains the public path.
        match config.web_path_prefix() {
            "" => router,
            prefix => Router::new().nest(prefix, router),
        }
    }

    /// Returns the names of the providers whose routes this surface is serving.
    pub fn providers(&self) -> impl Iterator<Item = &'static str> {
        self.providers.iter().map(|provider| provider.name())
    }
}

impl Service for WellKnownService {
    fn name(&self) -> &'static str {
        COMPONENT
    }

    fn start<'a>(&'a self, context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let Some(configured) = context.config().web_http_addr() else {
                info!(
                    event.name = "wellknown.disabled",
                    component = COMPONENT,
                    "no web address is configured"
                );

                return Ok(());
            };

            let secured = context.config().web_tls();
            let surface = Surface::start(
                configured,
                self.router(
                    context.identity(),
                    context.config(),
                    context.keys().map(Arc::clone),
                ),
                secured.as_ref(),
            )
            .await
            .context("starting the public surface")?;

            let bound = surface.address();
            *self
                .running
                .lock()
                .map_err(|_| anyhow!("the public surface lock is poisoned"))? = Some(surface);

            info!(
                event.name = "wellknown.listening",
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
            Err(_) => return ready(Err(anyhow!("the public surface lock is poisoned"))),
        };

        Box::pin(async move {
            let Some(surface) = surface else {
                return Ok(());
            };

            let address = surface
                .stop(context.config().shutdown_timeout())
                .await
                .context("waiting for the public surface to finish")?;

            info!(
                event.name = "wellknown.stopped_listening",
                component = COMPONENT,
                address = %address,
                "stopped listening"
            );

            Ok(())
        })
    }
}
