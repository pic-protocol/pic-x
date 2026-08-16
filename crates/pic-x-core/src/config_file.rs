//! ConfigFile class: reads and parses the YAML configuration file named on the command line.
//!
//! The binary never looks for a configuration file on its own. The path always arrives as the
//! positional argument of the invocation, so a container or orchestrator supplies its own default
//! through the command it runs.
//!
//! Sections this crate does not know about are kept, not rejected: a build that adds capabilities
//! claims its own sections by name and reads them back with [`ConfigFile::section`]. Whatever nobody
//! claims is reported by [`ConfigFile::reject_unknown_sections`], so a typo is still an error.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_norway::Value;

use crate::config::{
    SETTING_ADMIN_ADDR, SETTING_ADMIN_ALLOW, SETTING_ADMIN_TLS_CERT, SETTING_ADMIN_TLS_CLIENT_CA,
    SETTING_ADMIN_TLS_CRL, SETTING_ADMIN_TLS_KEY, SETTING_ADMIN_TLS_MIN_VERSION,
    SETTING_AUDIT_DIRECTORY, SETTING_AUDIT_PSEUDONYM_ENABLED, SETTING_AUDIT_PSEUDONYM_KEY_REF,
    SETTING_AUDIT_PSEUDONYM_KEY_VERSION, SETTING_AUDIT_RETENTION, SETTING_AUDIT_SINK,
    SETTING_AUTOGENERATE, SETTING_DEVELOPMENT_MODE, SETTING_ISSUER, SETTING_KEYS_DIRECTORY,
    SETTING_KEYS_ENABLED, SETTING_KEYS_MAINTENANCE_INTERVAL, SETTING_KEYS_PUBLISH_AHEAD,
    SETTING_KEYS_RETAIN, SETTING_KEYS_ROTATE_EVERY, SETTING_LIMITS_BODY_BYTES,
    SETTING_LIMITS_CONCURRENT_REQUESTS, SETTING_LIMITS_CONNECTIONS,
    SETTING_LIMITS_HANDSHAKE_TIMEOUT, SETTING_LIMITS_HEADER_TIMEOUT,
    SETTING_LIMITS_REQUEST_TIMEOUT, SETTING_LOG_FORMAT, SETTING_LOG_LEVEL,
    SETTING_PUBLIC_HTTP_ADDR, SETTING_PUBLIC_PATH_PREFIX, SETTING_PUBLIC_TLS_CERT,
    SETTING_PUBLIC_TLS_CLIENT_CA, SETTING_PUBLIC_TLS_CRL, SETTING_PUBLIC_TLS_KEY,
    SETTING_PUBLIC_TLS_MIN_VERSION, SETTING_SECRETS_DIRECTORY, SETTING_SECRETS_ENV_PREFIX,
    SETTING_SECRETS_PROVIDER, SETTING_SHUTDOWN_TIMEOUT, SETTING_TELEMETRY_ADDR,
    SETTING_TELEMETRY_TLS_CERT, SETTING_TELEMETRY_TLS_KEY, SETTING_TELEMETRY_TLS_MIN_VERSION,
    SETTING_TLS_RELOAD, SETTING_TLS_RELOAD_INTERVAL, SETTING_WORKING_DIR,
};
use crate::realm::{
    ClaimMapping, ExchangeProfileClaims, ExchangeProfileConfig, ExchangeProfilePrivileges,
    ExchangeProfileSource, ExchangeTokenValidation, PrivilegeEmit, PrivilegeRule, RealmInput,
    TrustedAttesterConfig,
};

/// The section names this crate parses into typed settings.
const KNOWN_SECTIONS: [&str; 8] = [
    "public",
    "telemetry",
    "admin",
    "tls",
    "limits",
    "log",
    "shutdown",
    "operations",
];

/// The parsed contents of a PIC-X configuration file.
#[derive(Debug, Default, Clone, PartialEq, Deserialize)]
pub struct ConfigFile {
    /// The directory relative paths resolve against. Defaults to the process's working directory.
    #[serde(default)]
    working_dir: Option<String>,
    /// Whether the server may create material it was not given. False unless said otherwise.
    #[serde(default)]
    autogenerate: Option<String>,
    /// Whether this deployment is somebody's laptop. False unless said otherwise.
    #[serde(default)]
    development_mode: Option<String>,
    #[serde(default)]
    public: PublicSection,
    #[serde(default)]
    telemetry: TelemetrySection,
    #[serde(default)]
    admin: AdminSection,
    #[serde(default)]
    tls: TransportSection,
    #[serde(default)]
    limits: LimitsSection,
    #[serde(default)]
    log: LogSection,
    #[serde(default)]
    shutdown: ShutdownSection,
    /// The record-keeping subsystem — the keys that seal a trail, the trail itself, and the secret
    /// that pseudonymises it. These are the server's own, and the defaults every realm inherits.
    #[serde(default)]
    operations: OperationsSection,
    /// The issuers this deployment hosts. A list, not a flat setting, so it is carried as structured
    /// configuration rather than through the layered key/value pipeline — realms come from the file
    /// (and, later, a database), never from a single environment variable.
    #[serde(default)]
    realms: Vec<RealmSection>,
    /// Sections outside the typed ones, kept verbatim for whoever claims them.
    #[serde(flatten)]
    sections: BTreeMap<String, Value>,
}

/// One realm as the file declares it, before resolution.
///
/// `name` has no default: a realm without a name is a realm nothing can be routed to, and serde
/// refuses the file rather than inventing one. Every other field — and every nested block — is
/// optional: what a realm does not state, it inherits from the server. The blocks mirror the
/// server's own sections, so a realm overriding its rotation reads exactly like the server setting it.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RealmSection {
    name: String,
    /// How long the PIC Tokens this realm issues stay valid, e.g. `1h`, `30m`.
    #[serde(default, alias = "tokenLifetime")]
    token_lifetime: Option<String>,
    /// Which algorithm this realm signs with: `EdDSA` (default) or `ES256`.
    #[serde(default, alias = "tokenSigningAlgorithm")]
    token_signing_algorithm: Option<String>,
    #[serde(default)]
    issuer: Option<String>,
    /// Whether this realm appears in the server's public catalogue. Absent means no.
    #[serde(default)]
    listed: Option<String>,
    /// The realm's token-signing keys — what it signs the tokens it issues with. Its own ring.
    #[serde(default)]
    keys: RealmKeysSection,
    /// The realm's override of the shared `operations` block: the keys that seal its trail, the trail
    /// itself, and its pseudonymisation. Any field absent inherits the server's `operations`.
    #[serde(default)]
    operations: RealmOperationsSection,
    /// Realm-scoped OAuth/PIC Exchange Profiles. Each realm owns its own mappings.
    #[serde(default)]
    exchange_profiles: Vec<ExchangeProfileSection>,
    /// Realm-scoped trusted Proof-of-Relationship attestation issuers.
    #[serde(default)]
    attesters: Vec<TrustedAttesterSection>,
}

/// One Exchange Profile exactly as the file declares it.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExchangeProfileSection {
    id: String,
    source: ExchangeProfileSourceSection,
    claims: ExchangeProfileClaimsSection,
    privileges: ExchangeProfilePrivilegesSection,
    #[serde(default, alias = "onUnmatchedScope")]
    on_unmatched_scope: Option<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExchangeProfileSourceSection {
    #[serde(alias = "tokenType")]
    token_type: String,
    format: String,
    issuer: String,
    /// Optional: where to reach the provider's discovery document when that address differs from
    /// the issuer identity.
    #[serde(default, alias = "discoveryUrl")]
    discovery_url: Option<String>,
    audience: String,
    #[serde(default)]
    validation: ExchangeTokenValidationSection,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExchangeTokenValidationSection {
    #[serde(default, alias = "allowedAlgorithms")]
    allowed_algorithms: Vec<String>,
    #[serde(default, alias = "requireExpiration")]
    require_expiration: Option<bool>,
    #[serde(default, alias = "requireTokenType")]
    require_token_type: Option<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExchangeProfileClaimsSection {
    #[serde(default)]
    identity_context: BTreeMap<String, ClaimMappingSection>,
    scopes: ClaimMappingSection,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimMappingSection {
    #[serde(default)]
    from: Option<String>,
    #[serde(default)]
    value: Option<String>,
    #[serde(default, rename = "type")]
    value_type: Option<String>,
    #[serde(default)]
    encoding: Option<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExchangeProfilePrivilegesSection {
    source: String,
    #[serde(default)]
    rules: Vec<PrivilegeRuleSection>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivilegeRuleSection {
    name: String,
    priority: i32,
    pattern: String,
    emit: PrivilegeEmitSection,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivilegeEmitSection {
    scope: String,
    operation: String,
    #[serde(alias = "resourceType")]
    resource_type: String,
    #[serde(alias = "resourceId")]
    resource_id: String,
}

/// One trusted attestation issuer exactly as the file declares it.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedAttesterSection {
    id: String,
    issuer: String,
    jwks_uri: String,
    #[serde(default)]
    proof_types: Vec<String>,
    #[serde(default)]
    formats: Vec<String>,
}

impl TrustedAttesterSection {
    fn to_input(&self) -> TrustedAttesterConfig {
        TrustedAttesterConfig {
            id: self.id.clone(),
            issuer: self.issuer.clone(),
            jwks_uri: self.jwks_uri.clone(),
            proof_types: self.proof_types.clone(),
            formats: self.formats.clone(),
        }
    }
}

impl ExchangeProfileSection {
    fn to_input(&self) -> ExchangeProfileConfig {
        ExchangeProfileConfig {
            id: self.id.clone(),
            source: ExchangeProfileSource {
                token_type: self.source.token_type.clone(),
                format: self.source.format.clone(),
                issuer: self.source.issuer.clone(),
                discovery_url: self.source.discovery_url.clone(),
                audience: self.source.audience.clone(),
                validation: ExchangeTokenValidation {
                    allowed_algorithms: self.source.validation.allowed_algorithms.clone(),
                    require_expiration: self.source.validation.require_expiration.unwrap_or(false),
                    require_token_type: self.source.validation.require_token_type.clone(),
                },
            },
            claims: ExchangeProfileClaims {
                identity_context: self
                    .claims
                    .identity_context
                    .iter()
                    .map(|(key, mapping)| (key.clone(), mapping.to_input()))
                    .collect(),
                scopes: self.claims.scopes.to_input(),
            },
            privileges: ExchangeProfilePrivileges {
                source: self.privileges.source.clone(),
                rules: self
                    .privileges
                    .rules
                    .iter()
                    .map(PrivilegeRuleSection::to_input)
                    .collect(),
            },
            on_unmatched_scope: self
                .on_unmatched_scope
                .clone()
                .unwrap_or_else(|| "reject".to_owned()),
        }
    }
}

impl ClaimMappingSection {
    fn to_input(&self) -> ClaimMapping {
        ClaimMapping {
            from: self.from.clone(),
            value: self.value.clone(),
            value_type: self.value_type.clone(),
            encoding: self.encoding.clone(),
        }
    }
}

impl PrivilegeRuleSection {
    fn to_input(&self) -> PrivilegeRule {
        PrivilegeRule {
            name: self.name.clone(),
            priority: self.priority,
            pattern: self.pattern.clone(),
            emit: PrivilegeEmit {
                scope: self.emit.scope.clone(),
                operation: self.emit.operation.clone(),
                resource_type: self.emit.resource_type.clone(),
                resource_id: self.emit.resource_id.clone(),
            },
        }
    }
}

/// A realm's override of the shared `operations` block. Each sub-block mirrors the server's, so a
/// realm overriding its audit retention reads exactly like the server setting it.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RealmOperationsSection {
    #[serde(default)]
    keys: RealmKeysSection,
    #[serde(default)]
    audit: RealmAuditSection,
    #[serde(default)]
    secrets: RealmSecretsSection,
}

/// A realm's override of the signing-key lifecycle. Any field absent inherits the server's.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RealmKeysSection {
    #[serde(default)]
    enabled: Option<String>,
    #[serde(default)]
    publish_ahead: Option<String>,
    #[serde(default)]
    rotate_every: Option<String>,
    #[serde(default)]
    retain: Option<String>,
}

/// A realm's override of its audit trail. Any field absent inherits the server's.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RealmAuditSection {
    #[serde(default)]
    sink: Option<String>,
    #[serde(default)]
    retention: Option<String>,
    #[serde(default)]
    pseudonym: RealmPseudonymSection,
}

/// A realm's override of how audit subjects are pseudonymised.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RealmPseudonymSection {
    #[serde(default)]
    enabled: Option<String>,
    #[serde(default)]
    key_ref: Option<String>,
    #[serde(default)]
    key_version: Option<String>,
}

/// A realm's override of where its secrets come from. Any field absent inherits the server's.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RealmSecretsSection {
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    env_prefix: Option<String>,
}

/// Listener addresses for the user-facing public surface.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicSection {
    #[serde(default)]
    http: Option<String>,
    /// The public URL this deployment is reached at. Stated, never inferred from a proxy header. It
    /// is the base a realm's `issuer` defaults to (`{url}/realms/<name>`) and, when it carries
    /// a path, what the surface's mount prefix is derived from. The server issues nothing, so this is
    /// a public *address*, not a token issuer.
    #[serde(default)]
    url: Option<String>,
    /// Where the surface is mounted. Empty — the root — unless a proxy forwards a path unstripped.
    #[serde(default)]
    path_prefix: Option<String>,
    #[serde(default)]
    tls: TlsSection,
}

/// The certificate a surface presents, and whether it demands one back.
///
/// `client_ca` is the line that turns TLS into mTLS. It is offered on the surfaces where a client has
/// an identity to present, and left out of the telemetry section entirely: a scrape and a kubelet
/// probe have none.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct TlsSection {
    #[serde(default)]
    cert: Option<String>,
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    client_ca: Option<String>,
    /// The list the authority publishes of certificates it has taken back.
    #[serde(default)]
    crl: Option<String>,
    #[serde(default)]
    min_version: Option<String>,
}

/// How transport material is treated while the server runs, across every surface at once.
///
/// Not per surface, because the cadence at which files are re-read is a property of the deployment
/// rather than of any one listener, and three copies of it would only ever be three chances to set
/// two of them.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransportSection {
    #[serde(default)]
    reload: Option<String>,
    #[serde(default)]
    reload_interval: Option<String>,
}

/// What a surface refuses to spend on any one client.
///
/// Values are kept as text and read as types by `Config`, so an unreadable one is reported the same
/// way whether it came from here, the environment or the command line.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitsSection {
    #[serde(default)]
    connections: Option<String>,
    #[serde(default)]
    concurrent_requests: Option<String>,
    #[serde(default)]
    request_timeout: Option<String>,
    #[serde(default)]
    handshake_timeout: Option<String>,
    #[serde(default)]
    header_timeout: Option<String>,
    #[serde(default)]
    body_bytes: Option<String>,
}

/// The record-keeping subsystem: the ring that seals a trail, the trail, and the pseudonym secret.
///
/// One block at the top level is the server's own and the default every realm inherits; a realm's
/// `operations` override has the same shape.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationsSection {
    #[serde(default)]
    keys: KeysSection,
    #[serde(default)]
    audit: AuditSection,
    #[serde(default)]
    secrets: SecretsSection,
}

/// The keys this deployment signs with and publishes.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeysSection {
    #[serde(default)]
    enabled: Option<String>,
    #[serde(default)]
    directory: Option<String>,
    #[serde(default)]
    publish_ahead: Option<String>,
    #[serde(default)]
    rotate_every: Option<String>,
    #[serde(default)]
    retain: Option<String>,
    #[serde(default)]
    maintenance_interval: Option<String>,
}

/// The certificate the telemetry surface presents. No client authority, on purpose.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct TelemetryTlsSection {
    #[serde(default)]
    cert: Option<String>,
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    min_version: Option<String>,
}

/// Listener address for the telemetry surface.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct TelemetrySection {
    #[serde(default)]
    addr: Option<String>,
    #[serde(default)]
    tls: TelemetryTlsSection,
}

/// Listener address for the administrative surface.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminSection {
    #[serde(default)]
    addr: Option<String>,
    #[serde(default)]
    tls: TlsSection,
    /// Who may administer this deployment. A list, because it is one.
    ///
    /// Kept as written and joined for the settings layer, so the same list can arrive from a file as
    /// YAML and from the environment as lines without either form being the special case.
    #[serde(default)]
    allow: Vec<String>,
}

/// How much the build says, and in what shape.
///
/// The values are kept as text here and read as types by `Config`, so an unreadable one is reported
/// with the same wording whether it came from this file, the environment, or the command line.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct LogSection {
    #[serde(default)]
    level: Option<String>,
    #[serde(default)]
    format: Option<String>,
}

/// Where secret material is resolved from.
///
/// Nothing in this section is itself a secret: it says where to look, and the store says what is
/// there.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretsSection {
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    directory: Option<String>,
    #[serde(default)]
    env_prefix: Option<String>,
}

/// How long the server is given to put itself away.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ShutdownSection {
    #[serde(default)]
    timeout: Option<String>,
}

/// How the audit trail treats the people it records.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditSection {
    /// Where the trail is written: into the log stream, or into files of its own.
    #[serde(default)]
    sink: Option<String>,
    #[serde(default)]
    directory: Option<String>,
    #[serde(default)]
    retention: Option<String>,
    #[serde(default)]
    pseudonym: PseudonymSection,
}

/// Which secret the pseudonymisation key is, and the version every token names.
///
/// The key itself is not here and never will be: this names it, and the secret store resolves it.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct PseudonymSection {
    #[serde(default)]
    enabled: Option<String>,
    /// The *name* of the key in the secret store. Never the key.
    #[serde(default)]
    key_ref: Option<String>,
    #[serde(default)]
    key_version: Option<String>,
}

impl ConfigFile {
    /// Reads the file at `path` and parses it as YAML.
    ///
    /// Both a missing file and malformed YAML are reported to the caller; neither is recovered from
    /// by falling back to another location.
    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("reading the configuration file {}", path.display()))?;

        Self::parse(&text)
            .with_context(|| format!("parsing the configuration file {}", path.display()))
    }

    /// Parses configuration-file text.
    pub fn parse(text: &str) -> Result<Self> {
        Ok(serde_norway::from_str(text)?)
    }

    /// The settings this file actually defines, as the configuration-file layer.
    ///
    /// Absent keys are omitted so that they never overwrite a value an earlier layer supplied.
    pub fn settings(&self) -> Vec<(String, String)> {
        // A list is one setting whose value happens to have lines in it, so it travels through the
        // same precedence layers as everything else instead of needing a mechanism of its own.
        let allow = (!self.admin.allow.is_empty()).then(|| self.admin.allow.join("\n"));

        let candidates = [
            (SETTING_WORKING_DIR, self.working_dir.as_ref()),
            (SETTING_AUTOGENERATE, self.autogenerate.as_ref()),
            (SETTING_DEVELOPMENT_MODE, self.development_mode.as_ref()),
            (SETTING_ISSUER, self.public.url.as_ref()),
            (SETTING_ADMIN_ALLOW, allow.as_ref()),
            (SETTING_TLS_RELOAD, self.tls.reload.as_ref()),
            (
                SETTING_TLS_RELOAD_INTERVAL,
                self.tls.reload_interval.as_ref(),
            ),
            (SETTING_LIMITS_CONNECTIONS, self.limits.connections.as_ref()),
            (
                SETTING_LIMITS_CONCURRENT_REQUESTS,
                self.limits.concurrent_requests.as_ref(),
            ),
            (
                SETTING_LIMITS_REQUEST_TIMEOUT,
                self.limits.request_timeout.as_ref(),
            ),
            (
                SETTING_LIMITS_HANDSHAKE_TIMEOUT,
                self.limits.handshake_timeout.as_ref(),
            ),
            (
                SETTING_LIMITS_HEADER_TIMEOUT,
                self.limits.header_timeout.as_ref(),
            ),
            (SETTING_LIMITS_BODY_BYTES, self.limits.body_bytes.as_ref()),
            (SETTING_PUBLIC_TLS_CRL, self.public.tls.crl.as_ref()),
            (SETTING_ADMIN_TLS_CRL, self.admin.tls.crl.as_ref()),
            (SETTING_AUDIT_SINK, self.operations.audit.sink.as_ref()),
            (
                SETTING_AUDIT_DIRECTORY,
                self.operations.audit.directory.as_ref(),
            ),
            (
                SETTING_AUDIT_RETENTION,
                self.operations.audit.retention.as_ref(),
            ),
            (SETTING_KEYS_ENABLED, self.operations.keys.enabled.as_ref()),
            (
                SETTING_KEYS_DIRECTORY,
                self.operations.keys.directory.as_ref(),
            ),
            (
                SETTING_KEYS_PUBLISH_AHEAD,
                self.operations.keys.publish_ahead.as_ref(),
            ),
            (
                SETTING_KEYS_ROTATE_EVERY,
                self.operations.keys.rotate_every.as_ref(),
            ),
            (SETTING_KEYS_RETAIN, self.operations.keys.retain.as_ref()),
            (
                SETTING_KEYS_MAINTENANCE_INTERVAL,
                self.operations.keys.maintenance_interval.as_ref(),
            ),
            (SETTING_PUBLIC_PATH_PREFIX, self.public.path_prefix.as_ref()),
            (SETTING_PUBLIC_HTTP_ADDR, self.public.http.as_ref()),
            (SETTING_TELEMETRY_ADDR, self.telemetry.addr.as_ref()),
            (SETTING_ADMIN_ADDR, self.admin.addr.as_ref()),
            (SETTING_LOG_LEVEL, self.log.level.as_ref()),
            (SETTING_PUBLIC_TLS_CERT, self.public.tls.cert.as_ref()),
            (SETTING_PUBLIC_TLS_KEY, self.public.tls.key.as_ref()),
            (
                SETTING_PUBLIC_TLS_CLIENT_CA,
                self.public.tls.client_ca.as_ref(),
            ),
            (
                SETTING_PUBLIC_TLS_MIN_VERSION,
                self.public.tls.min_version.as_ref(),
            ),
            (SETTING_ADMIN_TLS_CERT, self.admin.tls.cert.as_ref()),
            (SETTING_ADMIN_TLS_KEY, self.admin.tls.key.as_ref()),
            (
                SETTING_ADMIN_TLS_CLIENT_CA,
                self.admin.tls.client_ca.as_ref(),
            ),
            (
                SETTING_ADMIN_TLS_MIN_VERSION,
                self.admin.tls.min_version.as_ref(),
            ),
            (SETTING_TELEMETRY_TLS_CERT, self.telemetry.tls.cert.as_ref()),
            (SETTING_TELEMETRY_TLS_KEY, self.telemetry.tls.key.as_ref()),
            (
                SETTING_TELEMETRY_TLS_MIN_VERSION,
                self.telemetry.tls.min_version.as_ref(),
            ),
            (SETTING_LOG_FORMAT, self.log.format.as_ref()),
            (SETTING_SHUTDOWN_TIMEOUT, self.shutdown.timeout.as_ref()),
            (
                SETTING_SECRETS_PROVIDER,
                self.operations.secrets.provider.as_ref(),
            ),
            (
                SETTING_SECRETS_DIRECTORY,
                self.operations.secrets.directory.as_ref(),
            ),
            (
                SETTING_SECRETS_ENV_PREFIX,
                self.operations.secrets.env_prefix.as_ref(),
            ),
            (
                SETTING_AUDIT_PSEUDONYM_ENABLED,
                self.operations.audit.pseudonym.enabled.as_ref(),
            ),
            (
                SETTING_AUDIT_PSEUDONYM_KEY_REF,
                self.operations.audit.pseudonym.key_ref.as_ref(),
            ),
            (
                SETTING_AUDIT_PSEUDONYM_KEY_VERSION,
                self.operations.audit.pseudonym.key_version.as_ref(),
            ),
        ];

        candidates
            .into_iter()
            .filter_map(|(key, value)| value.map(|value| (key.to_owned(), value.clone())))
            .collect()
    }

    /// Returns a section this crate does not parse, for whoever declared it.
    pub fn section(&self, name: &str) -> Option<&Value> {
        self.sections.get(name)
    }

    /// Returns the realms this file declares, as raw overrides to be resolved against the server.
    ///
    /// No value is parsed here — a duration or a boolean is read by the same rules the server uses,
    /// which live where the server configuration is resolved. This only carries what the file said,
    /// in the file's order, so the catalogue and the log list realms the way an operator wrote them.
    pub fn realms(&self) -> Vec<RealmInput> {
        self.realms
            .iter()
            .map(|realm| RealmInput {
                token_lifetime: realm.token_lifetime.clone(),
                token_signing_algorithm: realm.token_signing_algorithm.clone(),
                name: realm.name.clone(),
                issuer: realm.issuer.clone(),
                listed: realm.listed.clone(),
                token_keys_enabled: realm.keys.enabled.clone(),
                token_keys_publish_ahead: realm.keys.publish_ahead.clone(),
                token_keys_rotate_every: realm.keys.rotate_every.clone(),
                token_keys_retain: realm.keys.retain.clone(),
                operations_keys_enabled: realm.operations.keys.enabled.clone(),
                operations_keys_publish_ahead: realm.operations.keys.publish_ahead.clone(),
                operations_keys_rotate_every: realm.operations.keys.rotate_every.clone(),
                operations_keys_retain: realm.operations.keys.retain.clone(),
                audit_sink: realm.operations.audit.sink.clone(),
                audit_retention: realm.operations.audit.retention.clone(),
                audit_pseudonym_enabled: realm.operations.audit.pseudonym.enabled.clone(),
                audit_pseudonym_key_ref: realm.operations.audit.pseudonym.key_ref.clone(),
                audit_pseudonym_key_version: realm.operations.audit.pseudonym.key_version.clone(),
                secrets_provider: realm.operations.secrets.provider.clone(),
                secrets_env_prefix: realm.operations.secrets.env_prefix.clone(),
                exchange_profiles: realm
                    .exchange_profiles
                    .iter()
                    .map(ExchangeProfileSection::to_input)
                    .collect(),
                trusted_attesters: realm
                    .attesters
                    .iter()
                    .map(TrustedAttesterSection::to_input)
                    .collect(),
            })
            .collect()
    }

    /// Returns every section outside the typed ones, in file-independent order.
    pub fn extra_sections(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.sections
            .iter()
            .map(|(name, value)| (name.as_str(), value))
    }

    /// Fails when the file declares a section neither this crate nor `claimed` accounts for.
    ///
    /// This is what keeps a misspelled top-level section an error instead of a silently ignored one.
    pub fn reject_unknown_sections<'a, I>(&self, claimed: I) -> Result<()>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let claimed: Vec<&str> = claimed.into_iter().collect();

        let unknown: Vec<&str> = self
            .sections
            .keys()
            .map(String::as_str)
            .filter(|name| !claimed.contains(name))
            .collect();

        if unknown.is_empty() {
            return Ok(());
        }

        let known = KNOWN_SECTIONS
            .iter()
            .copied()
            .chain(claimed)
            .collect::<Vec<_>>()
            .join(", ");

        bail!(
            "the configuration file declares unknown section(s): {}. Known sections: {known}",
            unknown.join(", ")
        );
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    const FULL: &str = "public:\n  http: 0.0.0.0:5556\ntelemetry:\n  addr: 0.0.0.0:5558\nadmin:\n  addr: 127.0.0.1:5557\n";

    fn settings_of(text: &str) -> Vec<(String, String)> {
        ConfigFile::parse(text).expect("the file parses").settings()
    }

    #[test]
    fn test_parse_reads_every_documented_section() {
        let file = ConfigFile::parse(FULL).expect("the file parses");

        assert_eq!(file.public.http.as_deref(), Some("0.0.0.0:5556"));
        assert_eq!(file.telemetry.addr.as_deref(), Some("0.0.0.0:5558"));
        assert_eq!(file.admin.addr.as_deref(), Some("127.0.0.1:5557"));
    }

    #[test]
    fn test_settings_yield_one_pair_per_declared_value() {
        assert_eq!(
            settings_of(FULL),
            vec![
                (
                    SETTING_PUBLIC_HTTP_ADDR.to_owned(),
                    "0.0.0.0:5556".to_owned()
                ),
                (SETTING_TELEMETRY_ADDR.to_owned(), "0.0.0.0:5558".to_owned()),
                (SETTING_ADMIN_ADDR.to_owned(), "127.0.0.1:5557".to_owned()),
            ]
        );
    }

    #[test]
    fn test_absent_sections_yield_no_settings() {
        assert!(
            settings_of("public:\n  http: 0.0.0.0:5556\n")
                .iter()
                .all(|(key, _)| key == SETTING_PUBLIC_HTTP_ADDR)
        );
        assert!(settings_of("{}").is_empty());
    }

    #[test]
    fn test_unknown_key_is_rejected() {
        let unknown_section = ConfigFile::parse("public:\n  http: 0.0.0.0:5556\nnope: 1\n")
            .expect("an unclaimed section still parses");
        assert!(unknown_section.reject_unknown_sections([]).is_err());

        assert!(ConfigFile::parse("public:\n  htpp: 0.0.0.0:5556\n").is_err());
    }

    #[test]
    fn test_tls_material_is_read_from_the_section_of_the_surface_it_belongs_to() {
        let settings = settings_of(
            "public:\n  http: 0.0.0.0:5556\n  tls:\n    cert: /tls/public.pem\n    key: /tls/public.key\n\
             admin:\n  addr: 127.0.0.1:5557\n  tls:\n    cert: /tls/admin.pem\n    key: /tls/admin.key\n    client_ca: /tls/clients.pem\n",
        );

        assert!(settings.contains(&(
            SETTING_PUBLIC_TLS_CERT.to_owned(),
            "/tls/public.pem".to_owned()
        )));
        assert!(settings.contains(&(
            SETTING_ADMIN_TLS_CLIENT_CA.to_owned(),
            "/tls/clients.pem".to_owned()
        )));
    }

    #[test]
    fn test_the_telemetry_section_offers_no_client_authority() {
        // `client_ca` under telemetry is a typo or a misunderstanding; either way the file is refused
        // rather than quietly serving without the mutual authentication somebody thought they asked
        // for.
        assert!(
            ConfigFile::parse(
                "telemetry:\n  addr: 0.0.0.0:5558\n  tls:\n    client_ca: /tls/clients.pem\n"
            )
            .is_err()
        );
    }

    #[test]
    fn test_malformed_yaml_is_rejected() {
        assert!(ConfigFile::parse("public: [unclosed\n").is_err());
    }

    #[test]
    fn test_a_claimed_section_is_kept_and_readable() {
        let file =
            ConfigFile::parse("public:\n  http: 0.0.0.0:5556\nsso:\n  issuer: https://idp\n")
                .expect("the file parses");

        assert!(file.reject_unknown_sections(["sso"]).is_ok());
        assert!(file.section("sso").is_some());
        assert_eq!(
            file.extra_sections()
                .map(|(name, _)| name)
                .collect::<Vec<_>>(),
            vec!["sso"]
        );
        // Claiming a section does not change the typed settings the file contributes.
        assert_eq!(
            file.settings(),
            vec![(
                SETTING_PUBLIC_HTTP_ADDR.to_owned(),
                "0.0.0.0:5556".to_owned()
            )]
        );
    }

    #[test]
    fn test_an_unclaimed_section_is_named_in_the_error() {
        let file = ConfigFile::parse("sso:\n  issuer: https://idp\n").expect("the file parses");

        let error = file
            .reject_unknown_sections([])
            .expect_err("nobody claimed the section");
        assert!(format!("{error}").contains("sso"));
    }

    #[test]
    fn test_load_reports_a_missing_file_instead_of_falling_back() {
        let error = ConfigFile::load(Path::new("/nonexistent/pic-x/config.yaml"))
            .expect_err("a missing file is an error");

        assert!(format!("{error:#}").contains("/nonexistent/pic-x/config.yaml"));
    }
}
