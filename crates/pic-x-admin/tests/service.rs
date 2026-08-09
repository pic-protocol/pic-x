//! What the administrative surface does when it is told to start and stop.
//!
//! Here rather than beside the code because these bind a real socket and take it down again. The two
//! tests that stayed inline are about the RPC implementation, which is private to the crate: an
//! integration test cannot reach it, and making it public to be testable would be the tail wagging
//! the dog.

use tonic::service::RoutesBuilder;

use pic_x_admin::{AdminService, ServiceProvider};
use pic_x_audit::RecordingAuditSink;
use pic_x_core::{BuildSettings, Config, ProductIdentity, ServerContext, Service};
use pic_x_storage::MemoryStorage;

fn identity() -> ProductIdentity {
    ProductIdentity::new("demo-x", "Demo X", "A tagline", "Demo X CLI", "<art>")
}

fn config_at(addr: Option<&str>) -> Config {
    let file = match addr {
        Some(addr) => vec![(
            pic_x_core::config::SETTING_GRPC_ADDR.to_owned(),
            addr.to_owned(),
        )],
        None => Vec::new(),
    };

    Config::from_layers(
        BuildSettings::new("9.9.9", "2026", "Test Holder"),
        Vec::<String>::new(),
        Vec::new(),
        file,
        Vec::new(),
    )
    .expect("the config builds")
}

/// A provider of the kind a build outside this workspace would register.
struct OwnServices;

impl ServiceProvider for OwnServices {
    fn name(&self) -> &'static str {
        "own-services"
    }

    fn add_to(&self, _routes: &mut RoutesBuilder) {
        // A real one adds its own generated server here; this one only has to be registerable.
    }
}

#[tokio::test]
async fn test_a_deployment_that_configures_no_address_starts_nothing() {
    let config = config_at(None);
    let storage = MemoryStorage::new();
    let audit = RecordingAuditSink::new();
    let context = ServerContext::new(identity(), &config, &storage, &audit);
    let service = AdminService::new();

    service.start(&context).await.expect("the service starts");
    service.stop(&context).await.expect("the service stops");
}

#[tokio::test]
async fn test_the_surface_binds_serves_and_stops() {
    let config = config_at(Some("127.0.0.1:0"));
    let storage = MemoryStorage::new();
    let audit = RecordingAuditSink::new();
    let context = ServerContext::new(identity(), &config, &storage, &audit);

    let service = AdminService::new().with_services(Box::new(OwnServices));
    assert_eq!(
        service.providers().collect::<Vec<_>>(),
        vec!["own-services"]
    );

    service.start(&context).await.expect("the surface starts");
    service.stop(&context).await.expect("the surface stops");
    service
        .stop(&context)
        .await
        .expect("stopping again is harmless");
}

#[tokio::test]
async fn test_an_address_that_cannot_be_read_is_reported_as_a_failure_to_start() {
    let config = config_at(Some("not-an-address"));
    let storage = MemoryStorage::new();
    let audit = RecordingAuditSink::new();
    let context = ServerContext::new(identity(), &config, &storage, &audit);

    let error = AdminService::new()
        .start(&context)
        .await
        .expect_err("the address is unreadable");

    assert!(format!("{error:#}").contains("not-an-address"));
}
