//! The documents this deployment publishes, and what serving them costs it.
//!
//! Kept apart from the surface that mounts them because they answer a different question: the surface
//! decides where to listen and who may reach it, and this decides what a client is told once it has.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::{Json, response::IntoResponse, response::Response};
use serde::Serialize;
use tracing::warn;

use pic_x_core::{JwkSet, KeyManager};

use crate::COMPONENT;

/// What the discovery document says about this deployment.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Discovery {
    /// The product this is, so a client that reached the wrong service can tell immediately.
    pub(crate) product: String,
    /// The version, which a client may key compatibility on.
    pub(crate) version: String,
    /// The public URL this deployment is reached at, when it was told one.
    pub(crate) issuer: Option<String>,
    /// Where the keys used to verify what this deployment signs are published.
    pub(crate) jwks_uri: String,
}

/// Everything the public routes are allowed to reach.
#[derive(Clone)]
pub(crate) struct Public {
    pub(crate) discovery: Discovery,
    pub(crate) keys: Option<Arc<dyn KeyManager>>,
}

/// How long a client may cache the key set.
///
/// This is the number `keys.publish_ahead` has to be longer than: a verifier that cached the set
/// five minutes ago will not see a key published since, so a key that started signing sooner than
/// that would be verified against a set that does not contain it.
const KEY_SET_MAX_AGE: &str = "public, max-age=300";

/// Answers the request an operator makes first: opening the address in a browser.
///
/// A 404 here is indistinguishable from a server that is not running, which is the worst possible
/// answer to "is it up?". It discloses nothing new either: the product and version are already public
/// at the discovery document below, and that document sits at a path every scanner already tries. So
/// the choice is not between disclosing and not disclosing — it is between an operator who can tell
/// what they reached and one who cannot.
pub(crate) async fn root(State(public): State<Public>) -> impl IntoResponse {
    format!(
        "{} {}\n\nDiscovery: /.well-known/pic-x-configuration\nKeys:      {}\n",
        public.discovery.product, public.discovery.version, public.discovery.jwks_uri
    )
}

/// Says what this deployment is and where to find what it publishes.
pub(crate) async fn discovery(State(public): State<Public>) -> impl IntoResponse {
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
pub(crate) async fn jwks(State(public): State<Public>) -> Response {
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
