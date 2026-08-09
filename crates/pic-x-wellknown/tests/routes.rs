//! What the public surface answers, and what a build that extends it can change.
//!
//! Here rather than beside the code because the cases that matter are about *composition*: routes a
//! build registers, a layer that wraps routes it did not write, and what a proxy-facing deployment
//! advertises. Each needs a router assembled a different way.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use tower::ServiceExt;

use pic_x_core::{Config, Layers, ProductIdentity};
use pic_x_wellknown::{RouteProvider, WellKnownService};

fn identity() -> ProductIdentity {
    ProductIdentity::new("demo-x", "Demo X", "A tagline", "Demo X CLI", "<art>")
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
    ask_with(service, &config_with(&[]), path).await
}

async fn ask_with(service: &WellKnownService, config: &Config, path: &str) -> (StatusCode, String) {
    let response = service
        .router(&identity(), config, None)
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
async fn test_the_discovery_document_says_what_this_deployment_is() {
    let (status, body) = ask(&WellKnownService::new(), "/.well-known/pic-x-configuration").await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Demo X"));
    assert!(body.contains("9.9.9"));
    assert!(body.contains("jwks.json"));
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
    assert!(body.contains("/.well-known/pic-x-configuration"));
}

#[tokio::test]
async fn test_without_an_issuer_the_document_advertises_paths() {
    let (_, body) = ask(&WellKnownService::new(), "/.well-known/pic-x-configuration").await;

    assert!(
        body.contains(r#""jwks_uri":"/.well-known/jwks.json""#),
        "{body}"
    );
    assert!(body.contains(r#""issuer":null"#), "{body}");
}

#[tokio::test]
async fn test_an_issuer_makes_the_advertised_urls_absolute() {
    let config = config_with(&[(
        pic_x_core::config::SETTING_ISSUER,
        "https://login.example.com/pic-x",
    )]);

    let (_, body) = ask_with(
        &WellKnownService::new(),
        &config,
        "/.well-known/pic-x-configuration",
    )
    .await;

    assert!(
        body.contains(r#""jwks_uri":"https://login.example.com/pic-x/.well-known/jwks.json""#),
        "{body}"
    );
    assert!(
        body.contains(r#""issuer":"https://login.example.com/pic-x""#),
        "{body}"
    );
}

#[tokio::test]
async fn test_a_path_prefix_moves_where_the_routes_are_mounted_and_nothing_else() {
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

    // The advertised URL is the issuer's, which already carries the public path once.
    let (_, document) = ask_with(&service, &config, "/pic-x/.well-known/pic-x-configuration").await;
    assert!(
        document.contains(r#""jwks_uri":"https://login.example.com/pic-x/.well-known/jwks.json""#),
        "{document}"
    );
}

#[tokio::test]
async fn test_an_unknown_path_is_not_found() {
    assert_eq!(
        ask(&WellKnownService::new(), "/nope").await.0,
        StatusCode::NOT_FOUND
    );
}
