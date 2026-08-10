//! What the public surface answers, and what a build that extends it can change.
//!
//! Two scopes are exercised here because the surface has two: the **server** (the control plane —
//! what this deployment is, which realms it lists, the key that signs its system trail) and each
//! **realm** (an issuer, at its own path). And the cases that matter are about composition — a route a
//! build registers, a layer that wraps routes it did not write, a realm that opted out of the
//! catalogue — so each needs a router assembled a different way.

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

/// A realm mounted at `/realms/{name}`, with no keys of its own.
fn realm(name: &str, issuer: Option<&str>, listed: bool) -> Realm {
    Realm::new(
        name,
        format!("/realms/{name}"),
        issuer.map(ToOwned::to_owned),
        listed,
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
        .router(&identity(), config, None, realms)
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
    assert!(body.contains("jwks.json"));
    // It is an envelope over profiles, not an issuer document — no issuer of its own.
    assert!(body.contains("profiles"));
    assert!(body.contains("https://pic-protocol.org/profiles/0.2"));
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
async fn test_the_key_set_is_empty_until_there_are_keys_to_publish() {
    let (status, body) = ask(&WellKnownService::new(), "/.well-known/jwks.json").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, r#"{"keys":[]}"#);
}

#[tokio::test]
async fn test_a_registered_provider_serves_beside_the_routes_pic_x_defines() {
    let service = WellKnownService::new().with_routes(Box::new(OwnRoutes));

    assert_eq!(ask(&service, "/own").await.1, "mine\n");
    assert_eq!(
        ask(&service, "/.well-known/jwks.json").await.0,
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
        ask(&service, "/.well-known/jwks.json").await.0,
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
async fn test_an_issuer_makes_the_servers_advertised_url_absolute() {
    let config = config_with(&[(
        pic_x_core::config::SETTING_ISSUER,
        "https://login.example.com/pic-x",
    )]);

    let (_, body) = ask_with(
        &WellKnownService::new(),
        &config,
        "/.well-known/server-configuration",
    )
    .await;

    assert!(
        body.contains(r#""jwks_uri":"https://login.example.com/pic-x/.well-known/jwks.json""#),
        "{body}"
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
    assert!(
        document.contains(r#""jwks_uri":"https://acme.example.com/.well-known/jwks.json""#),
        "{document}"
    );
    assert!(
        document.contains("https://pic-protocol.org/profiles/0.2"),
        "{document}"
    );

    // And its key set is reachable at its path.
    assert_eq!(
        ask_full(
            &WellKnownService::new(),
            &config_with(&[]),
            &realms,
            "/realms/acme/.well-known/jwks.json"
        )
        .await
        .0,
        StatusCode::OK
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
    let config = config_with(&[
        (pic_x_core::config::SETTING_WEB_PATH_PREFIX, "/pic-x"),
        (
            pic_x_core::config::SETTING_ISSUER,
            "https://login.example.com/pic-x",
        ),
    ]);
    let service = WellKnownService::new();

    // Mounted under the prefix...
    let (status, body) = ask_with(&service, &config, "/pic-x/.well-known/jwks.json").await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // ...and no longer at the root.
    assert_eq!(
        ask_with(&service, &config, "/.well-known/jwks.json")
            .await
            .0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn test_a_realm_that_is_not_hosted_is_not_found() {
    // A realm nobody configured has no surface, whatever path is asked for.
    assert_eq!(
        ask(
            &WellKnownService::new(),
            "/realms/ghost/.well-known/jwks.json"
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn test_an_unknown_path_is_not_found() {
    assert_eq!(
        ask(&WellKnownService::new(), "/nope").await.0,
        StatusCode::NOT_FOUND
    );
}
