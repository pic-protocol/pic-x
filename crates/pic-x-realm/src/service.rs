// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The surface itself: what it mounts, what may wrap it, and how it starts and stops.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow};
use axum::Router;
use axum::routing::{get, post};
use tracing::info;

use pic_x_core::{
    BoxFuture, Config, PIC_PROFILE, ProductIdentity, Realm, Realms, ServerContext, Service, ready,
};
use pic_x_transport::Surface;

use crate::COMPONENT;
use crate::attester_keys::{AttesterKeyCache, REFRESH_EVERY, RETRY_UNTIL_READY};
use crate::exchange::{TokenEndpoint, token};
use crate::idp_keys::IdpKeyCache;
use crate::key_fetch::HttpKeySetFetcher;
use crate::routes::{
    AttestationIssuer, Attestations, CatalogRealm, KeyRing, ProfileEntry, RealmLanding, RealmMeta,
    Server, attestations, jwks, realm_configuration, realm_root, root, server_configuration,
};

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
    /// One attester key cache per realm, shared between the token endpoint that reads it and the
    /// background task that refreshes it.
    attester_keys: Mutex<BTreeMap<String, Arc<AttesterKeyCache>>>,
    /// One identity-provider key cache per realm, shared the same way.
    idp_keys: Mutex<BTreeMap<String, Arc<IdpKeyCache>>>,
    /// The refresh task, stopped with the surface.
    refreshing: Mutex<Option<tokio::task::JoinHandle<()>>>,
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
            attester_keys: Mutex::new(BTreeMap::new()),
            idp_keys: Mutex::new(BTreeMap::new()),
            refreshing: Mutex::new(None),
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
    pub fn router(&self, identity: &ProductIdentity, config: &Config, realms: &Realms) -> Router {
        // The build details follow `public.disclose_build`: a deployment that turned it off answers
        // with the product name — enough to identify what answered — and nothing a fingerprinting
        // pass can match an exploit against.
        let version = if config.disclose_build() {
            config.version().to_owned()
        } else {
            String::new()
        };

        // The server surface: what this deployment is and which realms it lists. It issues nothing
        // and publishes no key set — the key that seals its system trail is internal, reached through
        // the administrative surface and never here. So there is no key route and no issuer discovery.
        let server = Server {
            product: identity.product_name().to_owned(),
            version: version.clone(),
            logo: identity.logo().to_owned(),
            tagline: identity.tagline().to_owned(),
            profiles: vec![ProfileEntry {
                profile: PIC_PROFILE,
                realms: realms
                    .listed()
                    .map(|realm| CatalogRealm {
                        name: realm.name().to_owned(),
                        issuer: realm.issuer().map(ToOwned::to_owned),
                        configuration_url: realm.url("/.well-known/pic-x-configuration"),
                        jwks_uri: realm.url("/keys"),
                        mount_path: realm.mount_path().to_owned(),
                    })
                    .collect(),
            }],
        };

        let mut router = Router::new()
            .route("/", get(root))
            .route(
                "/.well-known/server-configuration",
                get(server_configuration),
            )
            .with_state(server);

        // One issuer surface per realm, mounted at its own path. Every realm is mounted, listed or
        // not: `listed` decides whether the server *advertises* it, not whether a client that knows
        // its name can reach the discovery and keys it needs to verify a token.
        //
        // The key set is the realm's *token* ring — what a relying party verifies an issued token
        // against — served at `/keys` so that the `{issuer}/keys` the discovery advertises resolves
        // here. It is empty until token issuance exists; the ring that seals the realm's trail is a
        // different, internal ring and is never on this surface.
        for realm in realms.all() {
            let landing = RealmLanding {
                product: identity.product_name().to_owned(),
                version: version.clone(),
                tagline: identity.tagline().to_owned(),
                logo: identity.logo().to_owned(),
                name: realm.name().to_owned(),
                mount_path: realm.mount_path().to_owned(),
            };

            let issuer = Router::new()
                .route("/", get(realm_root))
                .with_state(landing.clone())
                .merge(
                    Router::new()
                        .route("/.well-known/pic-x-configuration", get(realm_configuration))
                        .with_state(RealmMeta {
                            issuer: realm.issuer().map(ToOwned::to_owned),
                            token_endpoint: realm.url("/token"),
                            jwks_uri: realm.url("/keys"),
                            signing_algorithm: realm.token_signing_algorithm().to_owned(),
                            workload_algorithms: crate::por::WORKLOAD_COSE_ALGORITHMS
                                .iter()
                                .map(|algorithm| (*algorithm).to_owned())
                                .collect(),
                        }),
                )
                .merge(
                    Router::new()
                        .route("/attestations", get(attestations))
                        .with_state(Attestations {
                            issuers: realm
                                .trusted_attesters()
                                .iter()
                                .map(|attester| AttestationIssuer {
                                    id: attester.id.clone(),
                                    issuer: attester.issuer.clone(),
                                    jwks_uri: attester.jwks_uri.clone(),
                                    proof_types_supported: attester.proof_types.clone(),
                                    formats_supported: attester.formats.clone(),
                                })
                                .collect(),
                        }),
                )
                .merge(Router::new().route("/keys", get(jwks)).with_state(KeyRing {
                    keys: realm.token_keys().map(Arc::clone),
                }))
                .merge(
                    Router::new()
                        .route("/token", post(token))
                        .with_state(TokenEndpoint {
                            realm: realm.clone(),
                            attester_keys: self.attester_keys(realm),
                            idp_keys: self.idp_keys(realm),
                        }),
                );

            // The nest answers the realm's path and everything under it, but a nested `/` route matches
            // only the path *without* a trailing slash. A browser often adds one, so `/realms/<name>/`
            // gets the same landing, registered explicitly beside the nest.
            let trailing = Router::new()
                .route(&format!("{}/", realm.mount_path()), get(realm_root))
                .with_state(landing);

            router = router.nest(realm.mount_path(), issuer).merge(trailing);
        }

        for provider in &self.providers {
            router = router.merge(provider.routes());
        }

        for layer in &self.layers {
            router = layer(router);
        }

        // Mounting under a prefix is for the proxies that forward the path unstripped. The advertised
        // URLs are unaffected: they come from the issuer, which already contains the public path.
        match config.public_path_prefix() {
            "" => router,
            prefix => Router::new().nest(prefix, router),
        }
    }

    /// The attester key cache for one realm, created on first use.
    ///
    /// Shared deliberately: the token endpoint reads it on the request path and the background task
    /// refreshes it, so both must see the same cache. A poisoned lock yields an unshared cache
    /// rather than a panic — it will simply be refreshed by nobody, and the realm rejects Proof of
    /// Relationship with "no key set has been fetched" instead of taking the process down.
    fn attester_keys(&self, realm: &Realm) -> Arc<AttesterKeyCache> {
        let fresh = || {
            Arc::new(AttesterKeyCache::with_stale_for(
                realm.trusted_attesters().to_vec(),
                realm.key_cache_stale_for(),
            ))
        };

        match self.attester_keys.lock() {
            Ok(mut caches) => caches
                .entry(realm.name().to_owned())
                .or_insert_with(fresh)
                .clone(),
            Err(_) => fresh(),
        }
    }

    /// The identity-provider key cache for one realm, created on first use.
    fn idp_keys(&self, realm: &Realm) -> Arc<IdpKeyCache> {
        let fresh = || {
            Arc::new(IdpKeyCache::with_stale_for(
                realm.exchange_profiles().to_vec(),
                realm.key_cache_stale_for(),
            ))
        };

        match self.idp_keys.lock() {
            Ok(mut caches) => caches
                .entry(realm.name().to_owned())
                .or_insert_with(fresh)
                .clone(),
            Err(_) => fresh(),
        }
    }

    /// Fetches every realm's attester key sets once, now.
    ///
    /// The background task does this on a timer; this is the same sweep on demand, for a caller
    /// that needs the keys present before the first request — a test, or an operator who just
    /// changed which attesters a realm trusts.
    pub async fn refresh_attester_keys(&self) {
        let attesters: Vec<Arc<AttesterKeyCache>> = match self.attester_keys.lock() {
            Ok(caches) => caches.values().cloned().collect(),
            Err(_) => Vec::new(),
        };
        let providers: Vec<Arc<IdpKeyCache>> = match self.idp_keys.lock() {
            Ok(caches) => caches.values().cloned().collect(),
            Err(_) => Vec::new(),
        };

        let fetcher = HttpKeySetFetcher::new();
        for cache in attesters {
            cache.refresh(&fetcher).await;
        }
        for cache in providers {
            cache.refresh(&fetcher).await;
        }
    }

    /// Keeps every realm's attester key sets fresh, so an attester can rotate its signing key
    /// without a restart. The first sweep runs immediately, because a realm that has fetched
    /// nothing yet cannot validate any Proof of Relationship.
    fn start_key_refresh(&self) {
        let attesters: Vec<Arc<AttesterKeyCache>> = match self.attester_keys.lock() {
            Ok(caches) => caches.values().cloned().collect(),
            Err(_) => Vec::new(),
        };
        let providers: Vec<Arc<IdpKeyCache>> = match self.idp_keys.lock() {
            Ok(caches) => caches.values().cloned().collect(),
            Err(_) => Vec::new(),
        };
        let nothing_to_fetch = attesters.iter().all(|cache| cache.attesters().is_empty())
            && providers.iter().all(|cache| cache.is_empty());
        if nothing_to_fetch {
            return;
        }

        let handle = tokio::spawn(async move {
            let fetcher = HttpKeySetFetcher::new();
            loop {
                for cache in &attesters {
                    cache.refresh(&fetcher).await;
                }
                for cache in &providers {
                    cache.refresh(&fetcher).await;
                }

                // Until every configured source has answered once, retry soon rather than waiting
                // out the interval: a provider that starts after this one would otherwise leave the
                // realm refusing exchanges for minutes with the fix already available.
                let ready = attesters.iter().all(|cache| cache.is_ready())
                    && providers.iter().all(|cache| cache.is_ready());
                tokio::time::sleep(if ready {
                    REFRESH_EVERY
                } else {
                    RETRY_UNTIL_READY
                })
                .await;
            }
        });

        if let Ok(mut refreshing) = self.refreshing.lock() {
            *refreshing = Some(handle);
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
            let Some(configured) = context.config().public_http_addr() else {
                info!(
                    event.name = "wellknown.disabled",
                    component = COMPONENT,
                    "no public address is configured"
                );

                return Ok(());
            };

            let secured = context.config().public_tls();
            let router = self.router(context.identity(), context.config(), context.realms());
            // After the router: the caches exist only once the realms have been walked.
            self.start_key_refresh();

            let surface = Surface::listener(COMPONENT, configured, router)
                .tls(secured.as_ref())
                .limits(context.config().limits())
                .metrics(context.metrics().clone())
                .start()
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
        if let Ok(mut refreshing) = self.refreshing.lock()
            && let Some(handle) = refreshing.take()
        {
            handle.abort();
        }

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
