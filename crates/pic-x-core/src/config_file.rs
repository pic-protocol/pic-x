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
    SETTING_AUDIT_DIRECTORY, SETTING_AUDIT_PSEUDONYM_ENABLED, SETTING_AUDIT_PSEUDONYM_KEY_REF,
    SETTING_AUDIT_PSEUDONYM_KEY_VERSION, SETTING_AUDIT_RETENTION, SETTING_AUDIT_SINK,
    SETTING_AUTOGENERATE, SETTING_DEVELOPMENT_MODE, SETTING_GRPC_ADDR, SETTING_GRPC_ALLOW,
    SETTING_GRPC_TLS_CERT, SETTING_GRPC_TLS_CLIENT_CA, SETTING_GRPC_TLS_CRL, SETTING_GRPC_TLS_KEY,
    SETTING_GRPC_TLS_MIN_VERSION, SETTING_ISSUER, SETTING_KEYS_DIRECTORY, SETTING_KEYS_ENABLED,
    SETTING_KEYS_PUBLISH_AHEAD, SETTING_KEYS_RETAIN, SETTING_KEYS_ROTATE_EVERY,
    SETTING_LIMITS_BODY_BYTES, SETTING_LIMITS_CONCURRENT_REQUESTS, SETTING_LIMITS_CONNECTIONS,
    SETTING_LIMITS_HANDSHAKE_TIMEOUT, SETTING_LIMITS_HEADER_TIMEOUT,
    SETTING_LIMITS_REQUEST_TIMEOUT, SETTING_LOG_FORMAT, SETTING_LOG_LEVEL,
    SETTING_SECRETS_DIRECTORY, SETTING_SECRETS_ENV_PREFIX, SETTING_SECRETS_PROVIDER,
    SETTING_SHUTDOWN_TIMEOUT, SETTING_TELEMETRY_ADDR, SETTING_TELEMETRY_TLS_CERT,
    SETTING_TELEMETRY_TLS_KEY, SETTING_TELEMETRY_TLS_MIN_VERSION, SETTING_TLS_RELOAD,
    SETTING_TLS_RELOAD_INTERVAL, SETTING_WEB_HTTP_ADDR, SETTING_WEB_PATH_PREFIX,
    SETTING_WEB_TLS_CERT, SETTING_WEB_TLS_CLIENT_CA, SETTING_WEB_TLS_CRL, SETTING_WEB_TLS_KEY,
    SETTING_WEB_TLS_MIN_VERSION, SETTING_WORKING_DIR,
};

/// The section names this crate parses into typed settings.
const KNOWN_SECTIONS: [&str; 10] = [
    "web",
    "telemetry",
    "grpc",
    "tls",
    "limits",
    "log",
    "audit",
    "shutdown",
    "secrets",
    "keys",
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
    /// The public URL this deployment is reached at. Stated, never inferred from a proxy header.
    #[serde(default)]
    issuer: Option<String>,
    #[serde(default)]
    web: WebSection,
    #[serde(default)]
    telemetry: TelemetrySection,
    #[serde(default)]
    grpc: GrpcSection,
    #[serde(default)]
    tls: TransportSection,
    #[serde(default)]
    limits: LimitsSection,
    #[serde(default)]
    log: LogSection,
    #[serde(default)]
    audit: AuditSection,
    #[serde(default)]
    shutdown: ShutdownSection,
    #[serde(default)]
    secrets: SecretsSection,
    #[serde(default)]
    keys: KeysSection,
    /// Sections outside the typed ones, kept verbatim for whoever claims them.
    #[serde(flatten)]
    sections: BTreeMap<String, Value>,
}

/// Listener addresses for the user-facing web surface.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct WebSection {
    #[serde(default)]
    http: Option<String>,
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

/// Listener address for the gRPC surface.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrpcSection {
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
        let allow = (!self.grpc.allow.is_empty()).then(|| self.grpc.allow.join("\n"));

        let candidates = [
            (SETTING_WORKING_DIR, self.working_dir.as_ref()),
            (SETTING_AUTOGENERATE, self.autogenerate.as_ref()),
            (SETTING_DEVELOPMENT_MODE, self.development_mode.as_ref()),
            (SETTING_ISSUER, self.issuer.as_ref()),
            (SETTING_GRPC_ALLOW, allow.as_ref()),
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
            (SETTING_WEB_TLS_CRL, self.web.tls.crl.as_ref()),
            (SETTING_GRPC_TLS_CRL, self.grpc.tls.crl.as_ref()),
            (SETTING_AUDIT_SINK, self.audit.sink.as_ref()),
            (SETTING_AUDIT_DIRECTORY, self.audit.directory.as_ref()),
            (SETTING_AUDIT_RETENTION, self.audit.retention.as_ref()),
            (SETTING_KEYS_ENABLED, self.keys.enabled.as_ref()),
            (SETTING_KEYS_DIRECTORY, self.keys.directory.as_ref()),
            (SETTING_KEYS_PUBLISH_AHEAD, self.keys.publish_ahead.as_ref()),
            (SETTING_KEYS_ROTATE_EVERY, self.keys.rotate_every.as_ref()),
            (SETTING_KEYS_RETAIN, self.keys.retain.as_ref()),
            (SETTING_WEB_PATH_PREFIX, self.web.path_prefix.as_ref()),
            (SETTING_WEB_HTTP_ADDR, self.web.http.as_ref()),
            (SETTING_TELEMETRY_ADDR, self.telemetry.addr.as_ref()),
            (SETTING_GRPC_ADDR, self.grpc.addr.as_ref()),
            (SETTING_LOG_LEVEL, self.log.level.as_ref()),
            (SETTING_WEB_TLS_CERT, self.web.tls.cert.as_ref()),
            (SETTING_WEB_TLS_KEY, self.web.tls.key.as_ref()),
            (SETTING_WEB_TLS_CLIENT_CA, self.web.tls.client_ca.as_ref()),
            (
                SETTING_WEB_TLS_MIN_VERSION,
                self.web.tls.min_version.as_ref(),
            ),
            (SETTING_GRPC_TLS_CERT, self.grpc.tls.cert.as_ref()),
            (SETTING_GRPC_TLS_KEY, self.grpc.tls.key.as_ref()),
            (SETTING_GRPC_TLS_CLIENT_CA, self.grpc.tls.client_ca.as_ref()),
            (
                SETTING_GRPC_TLS_MIN_VERSION,
                self.grpc.tls.min_version.as_ref(),
            ),
            (SETTING_TELEMETRY_TLS_CERT, self.telemetry.tls.cert.as_ref()),
            (SETTING_TELEMETRY_TLS_KEY, self.telemetry.tls.key.as_ref()),
            (
                SETTING_TELEMETRY_TLS_MIN_VERSION,
                self.telemetry.tls.min_version.as_ref(),
            ),
            (SETTING_LOG_FORMAT, self.log.format.as_ref()),
            (SETTING_SHUTDOWN_TIMEOUT, self.shutdown.timeout.as_ref()),
            (SETTING_SECRETS_PROVIDER, self.secrets.provider.as_ref()),
            (SETTING_SECRETS_DIRECTORY, self.secrets.directory.as_ref()),
            (SETTING_SECRETS_ENV_PREFIX, self.secrets.env_prefix.as_ref()),
            (
                SETTING_AUDIT_PSEUDONYM_ENABLED,
                self.audit.pseudonym.enabled.as_ref(),
            ),
            (
                SETTING_AUDIT_PSEUDONYM_KEY_REF,
                self.audit.pseudonym.key_ref.as_ref(),
            ),
            (
                SETTING_AUDIT_PSEUDONYM_KEY_VERSION,
                self.audit.pseudonym.key_version.as_ref(),
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

    const FULL: &str = "web:\n  http: 0.0.0.0:5556\ntelemetry:\n  addr: 0.0.0.0:5558\ngrpc:\n  addr: 127.0.0.1:5557\n";

    fn settings_of(text: &str) -> Vec<(String, String)> {
        ConfigFile::parse(text).expect("the file parses").settings()
    }

    #[test]
    fn test_parse_reads_every_documented_section() {
        let file = ConfigFile::parse(FULL).expect("the file parses");

        assert_eq!(file.web.http.as_deref(), Some("0.0.0.0:5556"));
        assert_eq!(file.telemetry.addr.as_deref(), Some("0.0.0.0:5558"));
        assert_eq!(file.grpc.addr.as_deref(), Some("127.0.0.1:5557"));
    }

    #[test]
    fn test_settings_yield_one_pair_per_declared_value() {
        assert_eq!(
            settings_of(FULL),
            vec![
                (SETTING_WEB_HTTP_ADDR.to_owned(), "0.0.0.0:5556".to_owned()),
                (SETTING_TELEMETRY_ADDR.to_owned(), "0.0.0.0:5558".to_owned()),
                (SETTING_GRPC_ADDR.to_owned(), "127.0.0.1:5557".to_owned()),
            ]
        );
    }

    #[test]
    fn test_absent_sections_yield_no_settings() {
        assert!(
            settings_of("web:\n  http: 0.0.0.0:5556\n")
                .iter()
                .all(|(key, _)| key == SETTING_WEB_HTTP_ADDR)
        );
        assert!(settings_of("{}").is_empty());
    }

    #[test]
    fn test_unknown_key_is_rejected() {
        let unknown_section = ConfigFile::parse("web:\n  http: 0.0.0.0:5556\nnope: 1\n")
            .expect("an unclaimed section still parses");
        assert!(unknown_section.reject_unknown_sections([]).is_err());

        assert!(ConfigFile::parse("web:\n  htpp: 0.0.0.0:5556\n").is_err());
    }

    #[test]
    fn test_tls_material_is_read_from_the_section_of_the_surface_it_belongs_to() {
        let settings = settings_of(
            "web:\n  http: 0.0.0.0:5556\n  tls:\n    cert: /tls/web.pem\n    key: /tls/web.key\n\
             grpc:\n  addr: 127.0.0.1:5557\n  tls:\n    cert: /tls/grpc.pem\n    key: /tls/grpc.key\n    client_ca: /tls/clients.pem\n",
        );

        assert!(settings.contains(&(SETTING_WEB_TLS_CERT.to_owned(), "/tls/web.pem".to_owned())));
        assert!(settings.contains(&(
            SETTING_GRPC_TLS_CLIENT_CA.to_owned(),
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
        assert!(ConfigFile::parse("web: [unclosed\n").is_err());
    }

    #[test]
    fn test_a_claimed_section_is_kept_and_readable() {
        let file = ConfigFile::parse("web:\n  http: 0.0.0.0:5556\nsso:\n  issuer: https://idp\n")
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
            vec![(SETTING_WEB_HTTP_ADDR.to_owned(), "0.0.0.0:5556".to_owned())]
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
