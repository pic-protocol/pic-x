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

use anyhow::Context;
use pic_x_admin::AdminService;
use pic_x_core::{AuditDestination, AuditSink, JwkSet, KeyManager, Metrics};
use pic_x_core::{BuildSettings, ProductIdentity};
use pic_x_core::{Config, SecretProvider, SecretStore};
use pic_x_core::{Pseudonymizer, Realm, RealmConfig};
use pic_x_realm::WellKnownService;
use pic_x_server::{App, DefaultServerHost};
use pic_x_std::audit::{FileAuditSink, TracingAuditSink};
use pic_x_std::keys::{DirectoryKeyManager, KeyPolicy, KeyService};
use pic_x_std::metrics::Registry;
use pic_x_std::pseudonym::HmacPseudonymizer;
use pic_x_std::secrets::{DirectorySecretStore, EnvironmentSecretStore};
use pic_x_std::storage::MemoryStorage;
use pic_x_telemetry::TelemetryService;

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
    )
    // The web logo the public landing renders, inline and self-contained: the transparent mini logo
    // as a `data:` URI, so the page reaches off the host for nothing. Branding lives here, in the
    // binary. `build.rs` encodes it from `assets/pic-x-logo-mini.png` on every build, so changing the
    // image is all it takes — there is no derived file to keep in sync.
    .with_logo(include_str!(concat!(
        env!("OUT_DIR"),
        "/pic-x-logo.datauri"
    )));

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
    // The numbers this process records about itself, kept in memory and published at /metrics. One
    // registry for the whole process: which one it is, is a decision only this file makes, and a
    // build that wants its measurements somewhere else changes this line and nothing more.
    .with_metrics(Metrics::new(Arc::new(Registry::new())))
    .with_provisioner(pic_x_std::provision::prepare)
    .with_secrets_factory(secret_store_for)
    .with_audit_factory(audit_sink_for)
    .with_audit_verifier(verify_audit_trail)
    .with_keys_exporter(export_keys)
    .with_keys_factory(key_manager_for)
    .with_pseudonymizer_factory(|key, key_version| {
        Box::new(HmacPseudonymizer::new(key, key_version))
    })
    // How this build assembles one realm: its own key ring, its own trail, its own pseudonymisation,
    // each rooted in the realm's own directory. Same implementations as the server's, pointed
    // elsewhere — which is the whole reason multi-tenancy costs a loop and not a rewrite.
    .with_realm_factory(build_realm)
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
fn audit_sink_for(
    config: &Config,
    keys: Option<&Arc<dyn KeyManager>>,
) -> anyhow::Result<Option<Arc<dyn AuditSink>>> {
    match config.audit_destination() {
        AuditDestination::Tracing => Ok(None),
        AuditDestination::File => {
            let mut sink = FileAuditSink::new(
                config.audit_directory(),
                BINARY_NAME,
                config.version(),
                config.audit_retention(),
            );

            // With a key ring, every day the trail closes is sealed with a signature — a statement
            // about where the chain stood that can leave this machine and still be checked. Without
            // one the seal is still written, and simply proves less.
            if let Some(keys) = keys {
                sink = sink.sealed_by(Arc::clone(keys));
            }

            // Prepared here rather than at the first record: a trail that cannot be written is a
            // reason not to start, not something to discover later from whoever needed the record.
            sink.prepare()?;

            Ok(Some(Arc::new(sink)))
        }
    }
}

/// Prints an operations ring's public keys as the JWKS a verifier checks seals against.
///
/// The counterpart to `audit verify --keys`. An operations ring is never served over HTTP, so this
/// is how its public half is obtained: read straight from the ring on disk, which is what a restore
/// needs — the server is stopped, and the set has to be exported from the volume being backed up so a
/// later signature is checked against a key an attacker on the restored host could not have replaced.
fn export_keys(directory: &std::path::Path) -> anyhow::Result<String> {
    pic_x_std::keys::export(directory)
        .with_context(|| format!("reading the key ring in {}", directory.display()))
}

/// Checks a trail written by the file sink, and says what checking it found.
///
/// The head is the value that matters and is printed for that reason: one digest stands for every
/// record before it, so writing it down somewhere this process cannot reach is what turns tamper
/// evidence into something an attacker with write access cannot undo.
///
/// When a key set is named, every seal's signature is checked against it. The set has to be named
/// rather than found: verifying against keys taken from the machine under suspicion checks a
/// signature against a key the same attacker could have replaced.
fn verify_audit_trail(
    directory: &std::path::Path,
    keys: Option<&std::path::Path>,
) -> anyhow::Result<String> {
    let verified = pic_x_std::audit::verify(directory)?;

    let mut summary = format!(
        "{} record(s) over {} day(s) verify. Head: {}",
        verified.records, verified.days, verified.head
    );

    if verified.seals.is_empty() {
        return Ok(summary);
    }

    let Some(path) = keys else {
        summary.push_str(&format!(
            "\n{} seal(s) present, signatures unchecked. Pass --keys <JWKS> to check them.",
            verified.seals.len()
        ));

        return Ok(summary);
    };

    let published: JwkSet = serde_json::from_str(&std::fs::read_to_string(path)?)
        .with_context(|| format!("reading the key set from {}", path.display()))?;

    let mut signed = 0_usize;
    for seal in &verified.seals {
        let (Some(kid), Some(signature)) = (seal.kid.as_deref(), seal.signature.as_deref()) else {
            anyhow::bail!("the seal for {} carries no signature", seal.body.day);
        };

        let key = published
            .keys
            .iter()
            .find(|key| key.kid == kid)
            .with_context(|| format!("the key set does not publish `{kid}`"))?;

        let signature = from_hex(signature).with_context(|| {
            format!("the seal for {} has an unreadable signature", seal.body.day)
        })?;

        if !pic_x_std::keys::verify_signature(key, &seal.signed_bytes()?, &signature) {
            anyhow::bail!(
                "the seal for {} does not verify against `{kid}`: it was not signed by the key it \
                 names, or it has been altered since",
                seal.body.day
            );
        }

        signed += 1;
    }

    summary.push_str(&format!("\n{signed} seal(s) verify against the key set."));

    Ok(summary)
}

/// Reads lowercase hexadecimal back into the bytes it renders.
fn from_hex(text: &str) -> anyhow::Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        anyhow::bail!("a hexadecimal string has an even number of characters");
    }

    (0..text.len() / 2)
        .map(|index| {
            u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
                .map_err(|error| anyhow::anyhow!("{error}"))
        })
        .collect()
}

/// Builds the key ring the effective configuration names.
///
/// This is the server's operations ring: it seals the system trail. Its public half must stay
/// verifiable for as long as that trail is kept, so `verify_retain` is the audit retention — the
/// private half still goes at `retain`, but a seal keeps verifying until the records it covers age
/// out. The `KeyPolicy` treats `verify_retain` as at least `retain`, so the common default (a long
/// `retain`, a shorter audit retention) simply keeps the key its full `retain` and is unaffected.
fn key_manager_for(config: &Config) -> anyhow::Result<Option<Arc<dyn KeyManager>>> {
    Ok(Some(Arc::new(DirectoryKeyManager::new(
        config.keys_directory(),
        KeyPolicy {
            publish_ahead: config.keys_publish_ahead(),
            rotate_every: config.keys_rotate_every(),
            retain: config.keys_retain(),
            verify_retain: config.audit_retention(),
        },
    ))))
}

/// Assembles one realm: its own key ring, its own trail, its own pseudonymisation.
///
/// The same implementations the server uses, pointed at the realm's own directories under
/// `realms/<name>/`, on the server's lifecycle policy. That is the whole shape of multi-tenancy here
/// — a realm is these collaborators rooted somewhere else, not a second copy of the code that builds
/// them — and it is why this is the only function that grew.
fn build_realm(config: &Config, realm: &RealmConfig) -> anyhow::Result<Realm> {
    let name = realm.name();

    // The realm's operations ring — when it keeps a signed trail — on its own lifecycle, so this
    // realm's seals verify against this realm's keys and no other. Internal: it seals the trail and
    // its public half is never served over HTTP. Its settings come from the realm's resolved
    // `operations` block (inherited from the server's, or overridden).
    let operations_keys: Option<Arc<dyn KeyManager>> = if realm.operations_keys_enabled() {
        Some(Arc::new(DirectoryKeyManager::new(
            config.realm_keys_directory(name),
            KeyPolicy {
                publish_ahead: realm.operations_keys_publish_ahead(),
                rotate_every: realm.operations_keys_rotate_every(),
                retain: realm.operations_keys_retain(),
                // Its public half outlives its private one by the realm's own audit retention, so
                // this realm's seals verify for as long as this realm keeps its trail.
                verify_retain: realm.audit_retention(),
            },
        )))
    } else {
        None
    };
    // The realm's token-signing ring, at `realms/<name>/keys`, published at its `jwks_uri`. Unlike
    // the operations ring, a token key's public half dies with its private one (`verify_retain` =
    // `retain`): a token older than `retain` has expired, so nothing needs to verify it afterwards.
    // It reuses the same Ed25519 ring as everything else here; the wire algorithm the discovery
    // advertises is `EdDSA` to match. (When real issuance lands, a profile that mandates ES256 gets
    // ES256 added to the ring then.)
    let token_keys: Option<Arc<dyn KeyManager>> = if realm.token_keys_enabled() {
        Some(Arc::new(DirectoryKeyManager::new(
            config.realm_token_keys_directory(name),
            KeyPolicy {
                publish_ahead: realm.token_keys_publish_ahead(),
                rotate_every: realm.token_keys_rotate_every(),
                retain: realm.token_keys_retain(),
                verify_retain: realm.token_keys_retain(),
            },
        )))
    } else {
        None
    };

    // Its own trail, to its own destination and retention. A file trail is sealed by the realm's own
    // key, so its attestations are checkable against the realm's published key set alone.
    let audit: Arc<dyn AuditSink> = match realm.audit_destination() {
        AuditDestination::Tracing => Arc::new(TracingAuditSink::new(
            BINARY_NAME,
            env!("CARGO_PKG_VERSION"),
        )),
        AuditDestination::File => {
            let mut sink = FileAuditSink::new(
                config.realm_audit_directory(name),
                BINARY_NAME,
                config.version(),
                realm.audit_retention(),
            );
            if let Some(keys) = &operations_keys {
                sink = sink.sealed_by(Arc::clone(keys));
            }

            sink.prepare()
                .with_context(|| format!("preparing the audit trail for the realm `{name}`"))?;

            Arc::new(sink)
        }
    };

    // Its own pseudonymisation key, resolved from wherever this realm's secrets live — its own
    // directory, or the environment under its own prefix. A different key per realm is the point: a
    // subject pseudonymised in one realm cannot be correlated with the same subject in another.
    let pseudonymizer: Option<Arc<dyn Pseudonymizer>> = if realm.audit_pseudonym_enabled() {
        let reference = realm
            .audit_pseudonym_key_ref()
            .context("audit pseudonymisation is enabled but names no secret")?;
        let store: Box<dyn SecretStore> = match realm.secrets_provider() {
            SecretProvider::Directory => Box::new(DirectorySecretStore::new(
                config.realm_secrets_directory(name),
            )),
            SecretProvider::Environment => {
                Box::new(EnvironmentSecretStore::new(realm.secrets_env_prefix()))
            }
            // Validation refuses pseudonymisation with no provider before this runs.
            SecretProvider::None => {
                anyhow::bail!("the realm `{name}` pseudonymises but resolves secrets from nowhere")
            }
        };
        let key = store.resolve(reference).with_context(|| {
            format!(
                "resolving the pseudonymisation key `{}` for the realm `{name}`",
                reference.name()
            )
        })?;

        Some(Arc::new(HmacPseudonymizer::new(
            key.expose(),
            realm.audit_pseudonym_key_version(),
        )))
    } else {
        None
    };

    Ok(Realm::new(
        name,
        realm.mount_path(),
        realm.issuer().map(ToOwned::to_owned),
        realm.listed(),
        operations_keys,
        token_keys,
        audit,
        pseudonymizer,
    ))
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
