//! The PIC-X binary: the composition root of this build.
//!
//! This file is the only place in the workspace that names a concrete implementation. Every crate it
//! composes takes its collaborators instead of resolving them, so another binary can reuse the same
//! crates, keep the implementations that suit it, and replace the rest — without forking anything.
//!
//! `scripts/check-composition-root.sh` enforces that this stays the only such place.

#![forbid(unsafe_code)]

use std::process::ExitCode;
use std::sync::Arc;

use pic_x_admin::AdminService;
use pic_x_audit::{FileAuditSink, TracingAuditSink};
use pic_x_core::{AuditDestination, AuditSink, KeyManager};
use pic_x_core::{BuildSettings, ProductIdentity};
use pic_x_core::{Config, SecretProvider, SecretStore};
use pic_x_keys::{DirectoryKeyManager, KeyPolicy, KeyService};
use pic_x_pseudonym::HmacPseudonymizer;
use pic_x_secrets::{DirectorySecretStore, EnvironmentSecretStore};
use pic_x_server::{App, DefaultServerHost};
use pic_x_storage::MemoryStorage;
use pic_x_telemetry::TelemetryService;
use pic_x_wellknown::WellKnownService;

/// The executable name shown in usage text and diagnostics.
const BINARY_NAME: &str = "pic-x";

/// The product identity rendered by both banner modes.
const PRODUCT_NAME: &str = "PIC-X (Provenance Identity Continuity Exchange)";

/// The product tagline rendered by both banner modes.
const PRODUCT_TAGLINE: &str = "Verifiable Authority Continuity";

/// The one-line description shown by `--help`.
const PRODUCT_ABOUT: &str = "PIC-X command line interface";

/// The ASCII art the full banner renders above the startup metadata.
const BANNER_ART: &str = r#" ____ ___ ____    __  __
|  _ \_ _/ ___|   \ \/ /
| |_) | | |   _____\  /
|  __/| | |__|_____/  \
|_|  |___\____|   /_/\_\"#;

#[tokio::main]
async fn main() -> ExitCode {
    let identity = ProductIdentity::new(
        BINARY_NAME,
        PRODUCT_NAME,
        PRODUCT_TAGLINE,
        PRODUCT_ABOUT,
        BANNER_ART,
    );

    let build_settings = BuildSettings::new(
        env!("CARGO_PKG_VERSION"),
        env!("PIC_X_COPYRIGHT_YEAR"),
        env!("PIC_X_COPYRIGHT_HOLDER"),
    );

    App::new(
        identity,
        build_settings,
        Box::new(DefaultServerHost::new()),
        Box::new(MemoryStorage::new()),
        Box::new(TracingAuditSink::new(
            BINARY_NAME,
            env!("CARGO_PKG_VERSION"),
        )),
    )
    .with_provisioner(pic_x_provision::prepare)
    .with_secrets_factory(secret_store_for)
    .with_audit_factory(audit_sink_for)
    .with_audit_verifier(verify_audit_trail)
    .with_keys_factory(key_manager_for)
    .with_pseudonymizer_factory(|key, key_version| {
        Box::new(HmacPseudonymizer::new(key, key_version))
    })
    // SIGHUP means re-read what can be re-read. What that is, in this build, is every listener's
    // transport material — so a renewed certificate is picked up without a restart.
    .with_reload_handler(|| {
        pic_x_transport::reload_all();
    })
    // Registration order is start order, and shutdown reverses it. Telemetry goes first so it is
    // answering probes before anything it reports on exists, and last to stop so it can still be
    // asked about the shutdown while the shutdown is happening. The key ring comes next, because a
    // surface that publishes keys should not come up before there are any. The public surface goes
    // last, so it is the first to stop taking requests.
    .with_service(Box::new(TelemetryService::new()))
    .with_service(Box::new(KeyService::new()))
    .with_service(Box::new(AdminService::new()))
    .with_service(Box::new(WellKnownService::new()))
    .run()
    .await
}

/// Builds the audit destination the effective configuration names.
///
/// Returning nothing leaves the sink this binary was composed with, which is the log stream.
fn audit_sink_for(config: &Config) -> anyhow::Result<Option<Arc<dyn AuditSink>>> {
    match config.audit_destination() {
        AuditDestination::Tracing => Ok(None),
        AuditDestination::File => {
            let sink = FileAuditSink::new(
                config.audit_directory(),
                BINARY_NAME,
                config.version(),
                config.audit_retention(),
            );

            // Prepared here rather than at the first record: a trail that cannot be written is a
            // reason not to start, not something to discover later from whoever needed the record.
            sink.prepare()?;

            Ok(Some(Arc::new(sink)))
        }
    }
}

/// Checks a trail written by the file sink, and says what checking it found.
///
/// The head is the value that matters and is printed for that reason: one digest stands for every
/// record before it, so writing it down somewhere this process cannot reach is what turns tamper
/// evidence into something an attacker with write access cannot undo.
fn verify_audit_trail(directory: &std::path::Path) -> anyhow::Result<String> {
    let verified = pic_x_audit::verify(directory)?;

    Ok(format!(
        "{} record(s) over {} day(s) verify. Head: {}",
        verified.records, verified.days, verified.head
    ))
}

/// Builds the key ring the effective configuration names.
fn key_manager_for(config: &Config) -> anyhow::Result<Option<Arc<dyn KeyManager>>> {
    Ok(Some(Arc::new(DirectoryKeyManager::new(
        config.keys_directory(),
        KeyPolicy {
            publish_ahead: config.keys_publish_ahead(),
            rotate_every: config.keys_rotate_every(),
            retain: config.keys_retain(),
        },
    ))))
}

/// Builds the secret store the effective configuration names.
///
/// This is the only place in the build that names a secret store implementation. A deployment that
/// needs Vault or a KMS adds the crate and one arm here — nothing else in the workspace changes,
/// because everything else only ever sees the contract.
fn secret_store_for(config: &Config) -> anyhow::Result<Option<Box<dyn SecretStore>>> {
    Ok(match config.secrets_provider() {
        SecretProvider::None => None,
        // The directory is always known: it is `secrets` inside the volume unless a deployment
        // named somewhere else.
        SecretProvider::Directory => Some(Box::new(DirectorySecretStore::new(
            config.secrets_directory(),
        ))),
        SecretProvider::Environment => Some(Box::new(EnvironmentSecretStore::new(
            config.secrets_env_prefix(),
        ))),
    })
}
