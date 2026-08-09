//! The public PIC-X surface: what a client is meant to find on its own.
//!
//! This is the only surface that faces the world, which is what makes it the one with the least on
//! it. Discovery documents belong here; anything that changes state belongs on the admin surface,
//! behind mTLS, on another port.
//!
//! # Extending it
//!
//! A build adds endpoints by **registering routes**, not by wrapping this crate. Wrapping would not
//! work anyway: the router is assembled here, so a wrapper would have nothing to add to. Registration
//! goes both ways —
//!
//! * a [`RouteProvider`] contributes an `axum::Router`, and its routes sit beside the ones PIC-X
//!   defines;
//! * a `tower` layer registered with [`WellKnownService::with_layer`] wraps **every** route,
//!   including the ones PIC-X defines — which is how an enterprise build puts its own authentication,
//!   rate limiting or request logging in front of endpoints it did not write.
//!
//! Adding is the easy half. Modifying what is already there is the half that wrapping never gives
//! you, and it is the reason the extension point is a layer rather than a merge.

#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow};
use axum::Router;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::routing::get;
use axum::{Json, response::IntoResponse, response::Response};
use serde::Serialize;
use tracing::{info, warn};

use pic_x_core::{
    BoxFuture, Config, JwkSet, KeyManager, ProductIdentity, ServerContext, Service, ready,
};
use pic_x_transport::Surface;

/// The `component` every record of this surface carries.
const COMPONENT: &str = "wellknown";

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

/// What the discovery document says about this deployment.
#[derive(Debug, Clone, Serialize)]
struct Discovery {
    /// The product this is, so a client that reached the wrong service can tell immediately.
    product: String,
    /// The version, which a client may key compatibility on.
    version: String,
    /// The public URL this deployment is reached at, when it was told one.
    issuer: Option<String>,
    /// Where the keys used to verify what this deployment signs are published.
    jwks_uri: String,
}

/// Everything the public routes are allowed to reach.
#[derive(Clone)]
struct Public {
    discovery: Discovery,
    keys: Option<Arc<dyn KeyManager>>,
}

/// How long a client may cache the key set.
///
/// This is the number `keys.publish_ahead` has to be longer than: a verifier that cached the set
/// five minutes ago will not see a key published since, so a key that started signing sooner than
/// that would be verified against a set that does not contain it.
const KEY_SET_MAX_AGE: &str = "public, max-age=300";

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

/// Answers the request an operator makes first: opening the address in a browser.
///
/// A 404 here is indistinguishable from a server that is not running, which is the worst possible
/// answer to "is it up?". It discloses nothing new either: the product and version are already public
/// at the discovery document below, and that document sits at a path every scanner already tries. So
/// the choice is not between disclosing and not disclosing — it is between an operator who can tell
/// what they reached and one who cannot.
async fn root(State(public): State<Public>) -> impl IntoResponse {
    format!(
        "{} {}\n\nDiscovery: /.well-known/pic-x-configuration\nKeys:      {}\n",
        public.discovery.product, public.discovery.version, public.discovery.jwks_uri
    )
}

/// Says what this deployment is and where to find what it publishes.
async fn discovery(State(public): State<Public>) -> impl IntoResponse {
    Json(serde_json::json!({
        "product": public.discovery.product,
        "version": public.discovery.version,
        "issuer": public.discovery.issuer,
        "jwks_uri": public.discovery.jwks_uri,
    }))
}

/// The keys a client verifies signatures with.
///
/// A deployment with no key ring publishes an empty set, and that is the truthful answer: it signs
/// nothing, so there is nothing to verify against.
///
/// A deployment whose key ring cannot be read publishes **nothing at all**, with a 503. The
/// difference matters more than it looks: an empty set is a statement that no signature is valid,
/// and answering it during a transient failure would turn a filesystem hiccup into every verifier in
/// the estate deciding that this deployment's signatures are forgeries.
async fn jwks(State(public): State<Public>) -> Response {
    let Some(keys) = public.keys else {
        return published(JwkSet::default());
    };

    match keys.public_keys() {
        Ok(published_keys) => published(JwkSet::new(published_keys)),
        Err(error) => {
            warn!(
                event.name = "wellknown.key_set_unavailable",
                component = COMPONENT,
                error = %error,
                retryable = error.is_retryable(),
                "the key set could not be read, so none was published"
            );

            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "the key set is not available" })),
            )
                .into_response()
        }
    }
}

/// Serves a key set with the cache directive its lifecycle assumes.
fn published(keys: JwkSet) -> Response {
    (
        StatusCode::OK,
        [(header::CACHE_CONTROL, KEY_SET_MAX_AGE)],
        Json(keys),
    )
        .into_response()
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
