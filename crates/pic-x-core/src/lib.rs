//! Every contract the PIC-X crates agree on, and nothing else.
//!
//! This crate holds traits and the types they exchange: layered configuration, the configuration-file
//! format, the product identity a binary supplies, and the interfaces a build implements — storage,
//! secrets, audit, services, and the server host itself.
//!
//! It contains no implementation, opens no socket, starts no runtime, and constructs no collaborator.
//! That is the point: a crate that implements one of these contracts depends only on this one, so
//! implementing something never means linking the implementation you meant to replace.
//!
//! The dependency list is part of the contract too — `scripts/check-core-dependencies.sh` keeps it to
//! the three crates needed to describe configuration.

#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::unwrap_used, clippy::expect_used)]

pub mod audit;
pub mod config;
pub mod config_file;
pub mod config_section;
pub mod error;
pub mod future;
pub mod identity;
pub mod keys;
pub mod limits;
pub mod logging;
pub mod metrics;
pub mod peer;
pub mod pseudonym;
pub mod realm;
pub mod redact;
pub mod secrets;
pub mod server;
pub mod storage;
pub mod tls;

pub use audit::{AuditDestination, AuditEvent, AuditSink, Sensitivity, Subject};
pub use config::{BuildSettings, Config, Layers};
pub use config_file::ConfigFile;
pub use config_section::{AnyConfigSection, ConfigSection};
pub use error::{AuditError, KeyError, SecretError, ServiceError, StorageError};
pub use future::{BoxFuture, ready};
pub use identity::ProductIdentity;
pub use keys::{Jwk, JwkSet, KEY_SET_MAX_AGE, KeyId, KeyManager, KeyState, Maintenance, Signature};
pub use limits::Limits;
pub use logging::{LogFormat, LogLevel};
pub use metrics::{Kind, Label, Metric, Metrics, Reading, Recorder, Sample};
pub use peer::{AllowedPeer, PeerIdentity};
pub use pseudonym::Pseudonymizer;
pub use realm::{
    ClaimMapping, EXCHANGE_ON_UNMATCHED_SCOPE_REJECT, EXCHANGE_SOURCE_FORMAT_JWT,
    EXCHANGE_SOURCE_OAUTH_ACCESS_TOKEN, ExchangeProfileClaims, ExchangeProfileConfig,
    ExchangeProfilePrivileges, ExchangeProfileSource, ExchangeTokenValidation,
    OAUTH_ACCESS_TOKEN_TYPE, PIC_PROFILE, PrivilegeEmit, PrivilegeRule, Realm, RealmConfig,
    RealmInput, Realms, TokenInitialExpiryPolicy, TrustedAttesterConfig,
};
pub use redact::Masked;
pub use secrets::{Secret, SecretProvider, SecretRef, SecretStore};
pub use server::{AuditRecorder, Health, ServerContext, ServerHost, Service};
pub use storage::Storage;
pub use tls::{TlsSettings, TlsVersion};

/// The parsed form of a configuration-file section this crate does not itself understand.
///
/// Re-exported so a crate that reads an extra section does not have to depend on the YAML
/// implementation this one happens to use.
pub use serde_norway::Value;
