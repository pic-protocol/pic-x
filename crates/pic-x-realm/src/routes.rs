//! The documents this deployment publishes, and what serving them costs it.
//!
//! Two surfaces, one file, because they answer the same shape of question at two scopes:
//!
//! * the **server** — the control plane — says what this deployment is and which issuers it hosts. It
//!   signs its system trail with an operations key, but that key's public half is an internal matter
//!   reached through the administrative surface, never served here; and it issues no tokens, so it
//!   publishes no key set and has no issuer discovery of its own;
//! * a **realm** — an issuer — says what a client integrating against it needs (its issuer URL, its
//!   endpoints, where its token keys are), and publishes those token keys at its `jwks_uri`.
//!
//! # Why the server lists realms rather than being one
//!
//! A token comes from a realm, signed by that realm's key. The server is the registry above them: it
//! names the realms that opted to be listed and points at each one's configuration. A future profile
//! is a new entry in the same generic envelope, not a new shape — see [`profiles`].

use std::sync::Arc;

use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::{Json, response::Html, response::IntoResponse, response::Response};
use serde::Serialize;
use tracing::warn;

use pic_x_core::{JwkSet, KeyManager, PIC_PROFILE};

use crate::COMPONENT;

/// The generic landing shell — structure and style, no product in it.
///
/// The branding it renders (logo, name, tagline) is supplied per request from the product identity,
/// so this crate stays reusable: a different product drops in its own logo and this page is its page.
const LANDING_TEMPLATE: &str = include_str!("../assets/landing.html");

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
///
/// No key set: the server's operations key is internal, and it issues nothing, so the document is the
/// deployment's identity and the realms it lists — nothing to verify a signature against.
#[derive(Clone, Serialize)]
pub(crate) struct Server {
    pub(crate) product: String,
    pub(crate) version: String,
    pub(crate) profiles: Vec<ProfileEntry>,
    // Branding for the human landing only — never part of the machine document, hence skipped.
    #[serde(skip)]
    pub(crate) logo: String,
    #[serde(skip)]
    pub(crate) tagline: String,
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
///
/// The endpoints are absolute URLs, each rooted at the realm's issuer (or its mount path when it was
/// told no public name). The service assembles them once, where the issuer is known; the handler only
/// renders. Everything below the endpoints in the document is the profile's fixed capability set —
/// hardcoded for now, and read from configuration once dynamic loading exists.
#[derive(Clone)]
pub(crate) struct RealmMeta {
    pub(crate) issuer: Option<String>,
    pub(crate) token_endpoint: String,
    pub(crate) jwks_uri: String,
    pub(crate) attestations_endpoint: String,
    pub(crate) trust_anchors_endpoint: String,
}

/// What a realm's landing page shows.
///
/// Enough to tell an operator which realm this is and where its machine-readable documents are, so
/// opening the realm's own path in a browser lands on something rather than a bare 404.
#[derive(Clone)]
pub(crate) struct RealmLanding {
    pub(crate) product: String,
    pub(crate) version: String,
    pub(crate) tagline: String,
    pub(crate) logo: String,
    pub(crate) name: String,
    pub(crate) configuration_url: String,
    pub(crate) jwks_uri: String,
}

/// The issuer discovery document, as a type so its fields serialise in the order they are declared.
///
/// The `issuer` and endpoint URLs are the realm's own; the capability fields are the PIC profile 0.2
/// set this build implements, fixed for now (`&'static` because they are constants, not per-realm).
#[derive(Serialize)]
struct Discovery {
    issuer: Option<String>,
    profile: &'static str,
    token_endpoint: String,
    jwks_uri: String,
    attestations_endpoint: String,
    trust_anchors_endpoint: String,
    grant_types_supported: &'static [&'static str],
    subject_token_types_supported: &'static [&'static str],
    issued_token_types_supported: &'static [&'static str],
    token_endpoint_auth_methods_supported: &'static [&'static str],
    token_exchange_parameters_supported: &'static [&'static str],
    pca: Pca,
    continuity_proposals: ContinuityProposals,
    continuity: Continuity,
}

/// The PCA capabilities block of the discovery document.
#[derive(Serialize)]
struct Pca {
    format: &'static str,
    execution_contract_binding_methods_supported: &'static [&'static str],
}

/// The continuity-proposal parameters block of the discovery document.
#[derive(Serialize)]
struct ContinuityProposals {
    parameter: &'static str,
    type_parameter: &'static str,
    types_supported: &'static [&'static str],
}

/// The continuity-token capabilities block of the discovery document.
#[derive(Serialize)]
struct Continuity {
    token_type: &'static str,
    transition_signing_alg_values_supported: &'static [&'static str],
    formats_supported: &'static [&'static str],
    continuity_modes_supported: &'static [&'static str],
}

/// One link a landing page offers: a label and the path it points at.
struct Link {
    label: String,
    href: String,
}

/// Escapes the few characters that would otherwise let a configured value break out of the HTML.
///
/// Realm names are already restricted to `[a-z0-9-]`, but a product name, tagline or issuer is
/// whatever a deployment wrote, so nothing interpolated into the page is trusted to be inert.
fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Fills the landing shell with one page's branding and links.
///
/// The logo is a `data:` URI from the product identity and is *not* escaped — it is trusted material
/// the binary compiled in, not a configured value. Everything else is escaped.
fn landing(
    title: &str,
    logo: &str,
    name: &str,
    subtitle: &str,
    foot: &str,
    links: &[Link],
) -> Html<String> {
    let hero = if logo.is_empty() {
        format!("<h1 class=\"wordmark\">{}</h1>", escape(name))
    } else {
        format!(
            "<img class=\"logo\" src=\"{}\" alt=\"{}\" />",
            logo,
            escape(name)
        )
    };

    let rows = links
        .iter()
        .map(|link| {
            format!(
                "<a class=\"row\" href=\"{href}\"><span class=\"label\">{label}</span><span class=\"path\">{href}</span></a>",
                href = escape(&link.href),
                label = escape(&link.label),
            )
        })
        .collect::<String>();

    let page = LANDING_TEMPLATE
        .replace("{{TITLE}}", &escape(title))
        .replace("{{HERO}}", &hero)
        .replace("{{SUBTITLE}}", &escape(subtitle))
        .replace("{{ROWS}}", &rows)
        .replace("{{FOOT}}", &escape(foot));

    Html(page)
}

/// Answers the request an operator makes first: opening the address in a browser.
///
/// A 404 here is indistinguishable from a server that is not running, which is the worst possible
/// answer to "is it up?". A branded landing points at the machine-readable documents rather than
/// repeating them, and reaches off the host for nothing — the logo is inlined.
pub(crate) async fn root(State(server): State<Server>) -> impl IntoResponse {
    let mut links = vec![Link {
        label: "Server configuration".to_owned(),
        href: "/.well-known/server-configuration".to_owned(),
    }];
    for profile in &server.profiles {
        for realm in &profile.realms {
            links.push(Link {
                label: format!("Realm — {}", realm.name),
                href: realm.configuration_url.clone(),
            });
        }
    }

    landing(
        &server.product,
        &server.logo,
        &server.product,
        &format!("v{}", server.version),
        &server.tagline,
        &links,
    )
}

/// Answers a browser opening a realm's own path, the way [`root`] answers the server's.
///
/// A realm is reachable at its path whether it is listed or not — a token verifier must reach its
/// discovery and keys — so a bare 404 here is the same unhelpful "is it even up?" the server root
/// exists to avoid. It names the realm and points at its documents rather than repeating them.
pub(crate) async fn realm_root(State(realm): State<RealmLanding>) -> impl IntoResponse {
    let links = vec![
        Link {
            label: "Discovery".to_owned(),
            href: realm.configuration_url.clone(),
        },
        Link {
            label: "Keys".to_owned(),
            href: realm.jwks_uri.clone(),
        },
    ];

    landing(
        &format!("{} \u{2014} {}", realm.product, realm.name),
        &realm.logo,
        &realm.product,
        &format!(
            "realm \u{201c}{}\u{201d} \u{00b7} v{}",
            realm.name, realm.version
        ),
        &realm.tagline,
        &links,
    )
}

/// Says what this deployment is and which issuers it hosts.
///
/// The generic envelope: product, version, and a profile array. A client that speaks a profile finds
/// it here and follows the links to the realms under it. There is no key set — the server issues
/// nothing, and the key that seals its trail is not published here.
///
/// Serialised through the typed [`Server`], not a `json!` value, so the fields keep the order they are
/// declared in rather than being sorted alphabetically.
pub(crate) async fn server_configuration(State(server): State<Server>) -> impl IntoResponse {
    Json(server)
}

/// The issuer discovery a client integrates a realm against.
///
/// The `issuer` and the endpoint URLs are the realm's own; everything else is the PIC profile 0.2
/// capability set this build implements, fixed for now. The endpoints below `jwks_uri` are advertised
/// ahead of the issuance they describe: a client learns the contract here, and the handlers that
/// answer `/token`, `/attestations` and `/trust-anchors` arrive with token issuance.
pub(crate) async fn realm_configuration(State(realm): State<RealmMeta>) -> impl IntoResponse {
    // A typed document rather than a `json!` value: `json!` builds an ordered map and serialises its
    // members alphabetically, which scrambles a document whose order is meaningful. A struct
    // serialises its fields in the order they are declared, so this is the shape a reader sees.
    Json(Discovery {
        issuer: realm.issuer,
        profile: PIC_PROFILE,

        token_endpoint: realm.token_endpoint,
        jwks_uri: realm.jwks_uri,

        attestations_endpoint: realm.attestations_endpoint,
        trust_anchors_endpoint: realm.trust_anchors_endpoint,

        grant_types_supported: &["urn:ietf:params:oauth:grant-type:token-exchange"],

        subject_token_types_supported: &[
            "urn:ietf:params:oauth:token-type:access_token",
            "https://pic-protocol.org/definitions/token-types/continuity",
        ],

        issued_token_types_supported: &[
            "https://pic-protocol.org/definitions/token-types/continuity",
        ],

        token_endpoint_auth_methods_supported: &["none"],

        token_exchange_parameters_supported: &["continuity_proposal", "continuity_proposal_type"],

        pca: Pca {
            format: "json",
            execution_contract_binding_methods_supported: &["embedded"],
        },

        continuity_proposals: ContinuityProposals {
            parameter: "continuity_proposal",
            type_parameter: "continuity_proposal_type",
            types_supported: &[
                "https://pic-protocol.org/definitions/proposal-types/continuity-initial",
                "https://pic-protocol.org/definitions/proposal-types/continuity",
            ],
        },

        continuity: Continuity {
            token_type: "https://pic-protocol.org/definitions/token-types/continuity",
            transition_signing_alg_values_supported: &["ES256"],
            formats_supported: &["jwt"],
            continuity_modes_supported: &["centralized-continuity", "decentralized-continuity"],
        },
    })
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
