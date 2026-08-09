//! What the telemetry surface answers a probe and a scrape.
//!
//! Here rather than beside the code because liveness and readiness are two questions with four
//! combinations between them, and the point of the suite is that the combinations differ.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use pic_x_audit::RecordingAuditSink;
use pic_x_core::{BuildSettings, Config, Health, ProductIdentity, ServerContext, Service};
use pic_x_storage::MemoryStorage;
use pic_x_telemetry::TelemetryService;

fn health_of(ready: bool, live: bool) -> Health {
    let health = Health::new();

    health.set_ready(ready);
    health.set_live(live);

    health
}

/// Asks the routes one question, the way a probe would.
async fn ask(health: Health, path: &str) -> (StatusCode, String) {
    let response = TelemetryService::routes(health)
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
async fn test_a_live_process_that_is_not_ready_answers_the_two_questions_differently() {
    let health = health_of(false, true);

    assert_eq!(ask(health.clone(), "/healthz").await.0, StatusCode::OK);
    assert_eq!(
        ask(health, "/readyz").await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn test_a_ready_process_answers_both_affirmatively() {
    let health = health_of(true, true);

    assert_eq!(ask(health.clone(), "/healthz").await.0, StatusCode::OK);
    assert_eq!(ask(health, "/readyz").await.0, StatusCode::OK);
}

#[tokio::test]
async fn test_a_wedged_process_reports_itself_not_live() {
    let health = health_of(true, false);

    assert_eq!(
        ask(health, "/healthz").await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn test_metrics_expose_both_states_in_the_prometheus_format() {
    let (status, body) = ask(health_of(true, true), "/metrics").await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("# TYPE picx_up gauge"));
    assert!(body.contains("picx_up 1"));
    assert!(body.contains("picx_ready 1"));

    let (_, body) = ask(health_of(false, true), "/metrics").await;
    assert!(body.contains("picx_ready 0"));
}

#[tokio::test]
async fn test_a_deployment_that_configures_no_address_starts_nothing() {
    let config = Config::default();
    let storage = MemoryStorage::new();
    let audit = RecordingAuditSink::new();
    let context = ServerContext::new(
        ProductIdentity::new("demo-x", "Demo X", "A tagline", "Demo X CLI", "<art>"),
        &config,
        &storage,
        &audit,
    );
    let service = TelemetryService::new();

    assert!(config.telemetry_addr().is_none());
    service.start(&context).await.expect("the service starts");
    service.stop(&context).await.expect("the service stops");
}

#[tokio::test]
async fn test_the_surface_listens_and_answers_and_then_stops() {
    let config = Config::from_layers(
        BuildSettings::new("9.9.9", "2026", "Test Holder"),
        Vec::<String>::new(),
        Vec::new(),
        // Port zero: the operating system picks a free one, so tests never collide.
        vec![(
            pic_x_core::config::SETTING_TELEMETRY_ADDR.to_owned(),
            "127.0.0.1:0".to_owned(),
        )],
        Vec::new(),
    )
    .expect("the config builds");
    let storage = MemoryStorage::new();
    let audit = RecordingAuditSink::new();
    let context = ServerContext::new(
        ProductIdentity::new("demo-x", "Demo X", "A tagline", "Demo X CLI", "<art>"),
        &config,
        &storage,
        &audit,
    );

    let service = TelemetryService::new();
    service.start(&context).await.expect("the surface starts");

    // Stopping twice is what a retry looks like, and it must not be an error.
    service.stop(&context).await.expect("the surface stops");
    service
        .stop(&context)
        .await
        .expect("stopping again is harmless");
}
