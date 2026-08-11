//! What the public surface answers, and what a build that extends it can change.
//!
//! Two scopes are exercised here because the surface has two: the **server** (the control plane —
//! what this deployment is and which realms it lists; it publishes no key set) and each **realm** (an
//! issuer, at its own path, publishing the token keys a relying party verifies against). And the cases
//! that matter are about composition — a route a build registers, a layer that wraps routes it did not
//! write, a realm that opted out of the catalogue — so each needs a router assembled a different way.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use tower::ServiceExt;

use pic_x_core::audit::{AuditEvent, Result};
use pic_x_core::{BoxFuture, Config, Layers, ProductIdentity, Pseudonymizer, Realm, Realms};
use pic_x_realm::{RouteProvider, WellKnownService};

fn identity() -> ProductIdentity {
    ProductIdentity::new("demo-x", "Demo X", "A tagline", "Demo X CLI", "<art>")
}

/// A sink a realm can be built around when a test does not care what it records.
#[derive(Debug)]
struct SilentSink;

impl pic_x_core::AuditSink for SilentSink {
    fn name(&self) -> &'static str {
        "silent"
    }

    fn record<'a>(
        &'a self,
        _event: &'a AuditEvent<'a>,
        _policy: Option<&'a dyn Pseudonymizer>,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

/// A realm mounted at `/realms/{name}`, with neither operations nor token keys of its own.
fn realm(name: &str, issuer: Option<&str>, listed: bool) -> Realm {
    Realm::new(
        name,
        format!("/realms/{name}"),
        issuer.map(ToOwned::to_owned),
        listed,
        None,
        None,
        Arc::new(SilentSink),
        None,
    )
}

/// A provider of the kind a build outside this workspace would register.
struct OwnRoutes;

impl RouteProvider for OwnRoutes {
    fn name(&self) -> &'static str {
        "own-routes"
    }

    fn routes(&self) -> Router {
        Router::new().route("/own", get(|| async { "mine\n" }))
    }
}

fn config_with(pairs: &[(&str, &str)]) -> Config {
    Config::from_layers(
        pic_x_core::BuildSettings::new("9.9.9", "2026", "Test Holder"),
        Vec::<String>::new(),
        Layers::new().with_file(
            pairs
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect::<Vec<_>>(),
        ),
    )
    .expect("the config builds")
}

async fn ask(service: &WellKnownService, path: &str) -> (StatusCode, String) {
    ask_full(service, &config_with(&[]), &Realms::default(), path).await
}

async fn ask_with(service: &WellKnownService, config: &Config, path: &str) -> (StatusCode, String) {
    ask_full(service, config, &Realms::default(), path).await
}

async fn ask_full(
    service: &WellKnownService,
    config: &Config,
    realms: &Realms,
    path: &str,
) -> (StatusCode, String) {
    let response = service
        .router(&identity(), config, realms)
        .oneshot(
            Request::builder()
                .uri(path)
                .body(Body::empty())
                .expect("the request builds"),
        )
        .await
        .expect("the routes answer");

    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the body is readable");

    (status, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn test_the_server_document_says_what_this_deployment_is() {
    let (status, body) = ask(
        &WellKnownService::new(),
        "/.well-known/server-configuration",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Demo X"));
    assert!(body.contains("9.9.9"));
    // It is an envelope over profiles, not an issuer document — no issuer, and no key set of its own.
    assert!(body.contains("profiles"));
    assert!(body.contains("https://pic-protocol.org/profiles/0.2"));
    assert!(
        !body.contains("jwks"),
        "the server publishes no key set: {body}"
    );
}

#[tokio::test]
async fn test_the_server_does_not_serve_issuer_discovery() {
    // The deliberate behaviour change: the root is the control plane, not an issuer. Its old
    // discovery moved under the realms.
    assert_eq!(
        ask(&WellKnownService::new(), "/.well-known/pic-x-configuration")
            .await
            .0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn test_the_server_publishes_no_key_set() {
    // The server's operations key seals its trail and is reached through the administrative surface,
    // never here. So the key-set route that used to sit at the root is gone.
    assert_eq!(
        ask(&WellKnownService::new(), "/.well-known/jwks.json")
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        ask(&WellKnownService::new(), "/keys").await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn test_a_registered_provider_serves_beside_the_routes_pic_x_defines() {
    let service = WellKnownService::new().with_routes(Box::new(OwnRoutes));

    assert_eq!(ask(&service, "/own").await.1, "mine\n");
    assert_eq!(
        ask(&service, "/.well-known/server-configuration").await.0,
        StatusCode::OK
    );
    assert_eq!(service.providers().collect::<Vec<_>>(), vec!["own-routes"]);
}

#[tokio::test]
async fn test_a_registered_layer_wraps_the_routes_pic_x_defines_too() {
    // The layer refuses everything, which is the bluntest possible proof that it runs in front of
    // routes this crate wrote and the registering build did not.
    let service = WellKnownService::new()
        .with_routes(Box::new(OwnRoutes))
        .with_layer(|router: Router| {
            router.layer(axum::middleware::from_fn(
                |_request: axum::extract::Request, _next: axum::middleware::Next| async move {
                    StatusCode::FORBIDDEN
                },
            ))
        });

    assert_eq!(
        ask(&service, "/.well-known/server-configuration").await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(ask(&service, "/own").await.0, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_the_root_says_what_this_is_and_where_to_look_next() {
    let (status, body) = ask(&WellKnownService::new(), "/").await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Demo X"));
    assert!(body.contains("9.9.9"));
    assert!(body.contains("/.well-known/server-configuration"));
}

#[tokio::test]
async fn test_a_listed_realms_advertised_urls_are_absolute() {
    // A realm's catalogue entry points at the realm's own issuer, and its key set is `{issuer}/keys`.
    let realms = Realms::new([realm("acme", Some("https://acme.example.com"), true)]);

    let (_, catalogue) = ask_full(
        &WellKnownService::new(),
        &config_with(&[]),
        &realms,
        "/.well-known/server-configuration",
    )
    .await;

    assert!(
        catalogue.contains(r#""jwks_uri":"https://acme.example.com/keys""#),
        "{catalogue}"
    );
}

#[tokio::test]
async fn test_a_realm_serves_its_own_discovery_and_keys_at_its_path() {
    let realms = Realms::new([realm("acme", Some("https://acme.example.com"), true)]);

    let (status, document) = ask_full(
        &WellKnownService::new(),
        &config_with(&[]),
        &realms,
        "/realms/acme/.well-known/pic-x-configuration",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        document.contains(r#""issuer":"https://acme.example.com""#),
        "{document}"
    );
    // Every endpoint is rooted at the realm's issuer, and the key set is `{issuer}/keys`.
    assert!(
        document.contains(r#""jwks_uri":"https://acme.example.com/keys""#),
        "{document}"
    );
    assert!(
        document.contains(r#""token_endpoint":"https://acme.example.com/token""#),
        "{document}"
    );
    // Only the token surface is advertised: this deployment hosts no revocation, attestation or
    // trust-anchor endpoints.
    for absent in [
        "revocation_endpoint",
        "attestations_endpoint",
        "trust_anchors_endpoint",
    ] {
        assert!(
            !document.contains(absent),
            "{absent} should not be advertised: {document}"
        );
    }
    assert!(
        document.contains("https://pic-protocol.org/profiles/0.2"),
        "{document}"
    );
    // The capability set this build implements is advertised.
    assert!(
        document.contains("urn:ietf:params:oauth:grant-type:token-exchange"),
        "{document}"
    );

    // Its key set is reachable at `{issuer}/keys`. This test realm has no token ring, so it is empty;
    // a realm with token keys enabled publishes them here.
    let (status, keys) = ask_full(
        &WellKnownService::new(),
        &config_with(&[]),
        &realms,
        "/realms/acme/keys",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        keys, r#"{"keys":[]}"#,
        "this test realm was built with no token ring"
    );
}

#[tokio::test]
async fn test_the_token_endpoint_is_a_post_that_reports_it_is_not_implemented() {
    let realms = Realms::new([realm("acme", Some("https://acme.example.com"), true)]);
    let service = WellKnownService::new();

    // A POST is answered — with 501, because issuance is not built — not a 404.
    let response = service
        .router(&identity(), &config_with(&[]), &realms)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/realms/acme/token")
                .body(Body::empty())
                .expect("the request builds"),
        )
        .await
        .expect("the route answers");
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the body is readable");
    assert!(
        String::from_utf8_lossy(&body).contains("not_implemented"),
        "the 501 should say why"
    );

    // The method is part of the contract: a GET is refused with 405, not served.
    assert_eq!(
        ask_full(&service, &config_with(&[]), &realms, "/realms/acme/token")
            .await
            .0,
        StatusCode::METHOD_NOT_ALLOWED
    );
}

#[tokio::test]
async fn test_the_catalogue_lists_opted_in_realms_and_hides_the_rest() {
    // Fail-closed enumeration: `beta` did not opt in, so the world does not learn it exists from the
    // catalogue — but a client that knows its name still reaches its discovery.
    let realms = Realms::new([
        realm("acme", Some("https://acme.example.com"), true),
        realm("beta", Some("https://beta.example.com"), false),
    ]);

    let (_, catalogue) = ask_full(
        &WellKnownService::new(),
        &config_with(&[]),
        &realms,
        "/.well-known/server-configuration",
    )
    .await;
    assert!(catalogue.contains("acme"), "{catalogue}");
    assert!(!catalogue.contains("beta"), "{catalogue}");

    // The hidden realm's own discovery is still served.
    assert_eq!(
        ask_full(
            &WellKnownService::new(),
            &config_with(&[]),
            &realms,
            "/realms/beta/.well-known/pic-x-configuration"
        )
        .await
        .0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn test_a_path_prefix_moves_where_everything_is_mounted() {
    let config = config_with(&[(pic_x_core::config::SETTING_PUBLIC_PATH_PREFIX, "/pic-x")]);
    let service = WellKnownService::new();

    // Mounted under the prefix...
    let (status, body) =
        ask_with(&service, &config, "/pic-x/.well-known/server-configuration").await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // ...and no longer at the root.
    assert_eq!(
        ask_with(&service, &config, "/.well-known/server-configuration")
            .await
            .0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn test_a_realm_lands_on_a_page_at_its_own_path() {
    // Opening the realm's path in a browser lands on something, not a bare 404 — with or without the
    // trailing slash a browser might add — and points at the machine-readable documents.
    let realms = Realms::new([realm("acme", Some("https://acme.example.com"), true)]);

    for path in ["/realms/acme", "/realms/acme/"] {
        let (status, body) =
            ask_full(&WellKnownService::new(), &config_with(&[]), &realms, path).await;

        assert_eq!(status, StatusCode::OK, "{path} did not land");
        assert!(
            body.contains("acme"),
            "{path} does not name the realm: {body}"
        );
        assert!(
            body.contains(".well-known/pic-x-configuration"),
            "{path} does not point at the discovery document: {body}"
        );
    }
}

#[tokio::test]
async fn test_a_realm_that_is_not_hosted_is_not_found() {
    // A realm nobody configured has no surface, whatever path is asked for — landing included.
    for path in [
        "/realms/ghost",
        "/realms/ghost/",
        "/realms/ghost/keys",
        "/realms/ghost/.well-known/pic-x-configuration",
    ] {
        assert_eq!(
            ask(&WellKnownService::new(), path).await.0,
            StatusCode::NOT_FOUND,
            "{path} should not be found"
        );
    }
}

#[tokio::test]
async fn test_an_unknown_path_is_not_found() {
    assert_eq!(
        ask(&WellKnownService::new(), "/nope").await.0,
        StatusCode::NOT_FOUND
    );
}
