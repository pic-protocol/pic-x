//! The documents this deployment publishes, and what serving them costs it.
//!
//! Two surfaces, one file, because they answer the same shape of question at two scopes:
//!
//! * the **server** — the control plane — says what this deployment is and which issuers it hosts,
//!   and publishes the key that signs its system trail. It issues no tokens, so it has no issuer
//!   discovery of its own;
//! * a **realm** — an issuer — says what a client integrating against it needs (its issuer URL, where
//!   its keys are), and publishes those keys.
//!
//! # Why the server lists realms rather than being one
//!
//! A token comes from a realm, signed by that realm's key. The server is the registry above them: it
//! names the realms that opted to be listed and points at each one's configuration. A future profile
//! is a new entry in the same generic envelope, not a new shape — see [`profiles`].

use std::sync::Arc;

use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::{Json, response::IntoResponse, response::Response};
use serde::Serialize;
use tracing::warn;

use pic_x_core::{JwkSet, KeyManager, PIC_PROFILE};

use crate::COMPONENT;

/// How long a client may cache a key set.
///
/// This is the number `keys.publish_ahead` has to be longer than: a verifier that cached a set five
/// minutes ago will not see a key published since, so a key that started signing sooner than that
/// would be verified against a set that does not contain it.
const KEY_SET_MAX_AGE: &str = "public, max-age=300";

/// A key set to publish, shared by the server surface and every realm surface.
///
/// The same endpoint, the same handler, the same failure behaviour at both scopes — the only
/// difference is whose ring is behind it.
#[derive(Clone)]
pub(crate) struct KeyRing {
    pub(crate) keys: Option<Arc<dyn KeyManager>>,
}

/// What the server document says about this deployment.
#[derive(Clone)]
pub(crate) struct Server {
    pub(crate) product: String,
    pub(crate) version: String,
    pub(crate) jwks_uri: String,
    pub(crate) profiles: Vec<ProfileEntry>,
}

/// One profile this server speaks, and what it hosts under it.
///
/// Generic on purpose: today the only entry is PIC, carrying its realms. A future profile is another
/// entry with its own resources, not a change to this document's shape.
#[derive(Clone, Serialize)]
pub(crate) struct ProfileEntry {
    pub(crate) profile: &'static str,
    pub(crate) realms: Vec<CatalogRealm>,
}

/// One realm as the server catalogue lists it.
#[derive(Clone, Serialize)]
pub(crate) struct CatalogRealm {
    pub(crate) name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) issuer: Option<String>,
    pub(crate) configuration_url: String,
    pub(crate) jwks_uri: String,
}

/// What a realm's own configuration document says.
#[derive(Clone)]
pub(crate) struct RealmMeta {
    pub(crate) issuer: Option<String>,
    pub(crate) jwks_uri: String,
}

/// Answers the request an operator makes first: opening the address in a browser.
///
/// A 404 here is indistinguishable from a server that is not running, which is the worst possible
/// answer to "is it up?". It points at the machine-readable documents rather than repeating them.
pub(crate) async fn root(State(server): State<Server>) -> impl IntoResponse {
    let realms: usize = server
        .profiles
        .iter()
        .map(|profile| profile.realms.len())
        .sum();

    format!(
        "{} {}\n\nServer:  /.well-known/server-configuration\nKeys:    {}\nRealms:  {realms} listed\n",
        server.product, server.version, server.jwks_uri
    )
}

/// Says what this deployment is and which issuers it hosts.
///
/// The generic envelope: product, version, the server's own key set, and a profile array. A client
/// that speaks a profile finds it here and follows the links to the realms under it.
pub(crate) async fn server_configuration(State(server): State<Server>) -> impl IntoResponse {
    Json(serde_json::json!({
        "product": server.product,
        "version": server.version,
        "jwks_uri": server.jwks_uri,
        "profiles": server.profiles,
    }))
}

/// The issuer discovery a client integrates a realm against.
pub(crate) async fn realm_configuration(State(realm): State<RealmMeta>) -> impl IntoResponse {
    Json(serde_json::json!({
        "profile": PIC_PROFILE,
        "issuer": realm.issuer,
        "jwks_uri": realm.jwks_uri,
    }))
}

/// The keys a client verifies signatures with, for whichever ring is behind this route.
///
/// A ring with no manager publishes an empty set — the truthful answer for something that signs
/// nothing. A ring whose manager cannot be read publishes **nothing**, with a 503: an empty set is a
/// statement that no signature is valid, and answering it during a transient failure would turn a
/// filesystem hiccup into every verifier deciding these signatures are forgeries.
pub(crate) async fn jwks(State(ring): State<KeyRing>) -> Response {
    let Some(keys) = ring.keys else {
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
