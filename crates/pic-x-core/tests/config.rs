//! How the configuration layers resolve, driven from outside the crate.
//!
//! Here rather than beside the code because precedence is the kind of thing that needs a table of
//! cases to be convincing: five layers, each overwriting only what it actually declares. Every case
//! is three lines, and there are thirty of them.

use std::time::Duration;

use pic_x_core::config::*;
use pic_x_core::{BuildSettings, Config, LogFormat, LogLevel, TlsVersion};

/// The extra-settings layer of a build that declares none.
const NO_DECLARED: [&str; 0] = [];

fn pairs(entries: &[(&str, &str)]) -> Vec<(String, String)> {
    entries
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
}

fn build_settings() -> BuildSettings {
    BuildSettings::new("1.2.3", "2026", "Build Holder")
}

/// Builds a config from the three input layers, failing the test on an unreadable value.
///
/// The parameters are in precedence order — file, then environment, then command line — so a call
/// reads the same way the layers apply.
fn config(file: &[(&str, &str)], env: &[(&str, &str)], cli: &[(&str, &str)]) -> Config {
    Config::from_layers(
        build_settings(),
        NO_DECLARED,
        Layers::new()
            .with_file(pairs(file))
            .with_environment(pairs(env))
            .with_command_line(pairs(cli)),
    )
    .expect("the layers build a config")
}

/// Builds a config for a build that declares extra setting keys.
fn declaring(
    declared: &[&str],
    file: &[(&str, &str)],
    env: &[(&str, &str)],
    cli: &[(&str, &str)],
) -> Config {
    Config::from_layers(
        build_settings(),
        declared.to_vec(),
        Layers::new()
            .with_file(pairs(file))
            .with_environment(pairs(env))
            .with_command_line(pairs(cli)),
    )
    .expect("the layers build a config")
}

fn servable() -> Config {
    config(&[(SETTING_WEB_HTTP_ADDR, "0.0.0.0:5556")], &[], &[])
}

#[test]
fn test_from_layers_uses_build_metadata_after_defaults() {
    let config = config(&[], &[], &[]);

    assert_eq!(config.version(), "1.2.3");
    assert_eq!(config.copyright_year(), "2026");
    assert_eq!(config.copyright_holder(), "Build Holder");
}

#[test]
fn test_absent_values_do_not_overwrite_existing_values() {
    let config = config(&[], &[(SETTING_COPYRIGHT_HOLDER, "Env Holder")], &[]);

    assert_eq!(config.version(), "1.2.3");
    assert_eq!(config.copyright_year(), "2026");
    assert_eq!(config.copyright_holder(), "Env Holder");
}

#[test]
fn test_layers_are_applied_in_default_build_file_environment_cli_order() {
    // One setting declared by every layer at once, so the winner names the order outright. The build
    // metadata supplies the version, and each layer after it overwrites what the one before said.
    let every_layer = config(
        &[(SETTING_VERSION, "from-the-file")],
        &[(SETTING_VERSION, "from-the-environment")],
        &[(SETTING_VERSION, "from-the-command-line")],
    );
    assert_eq!(every_layer.version(), "from-the-command-line");

    // Take the last layer away, and the one before it wins — down to the build metadata.
    let without_cli = config(
        &[(SETTING_VERSION, "from-the-file")],
        &[(SETTING_VERSION, "from-the-environment")],
        &[],
    );
    assert_eq!(without_cli.version(), "from-the-environment");

    let file_only = config(&[(SETTING_VERSION, "from-the-file")], &[], &[]);
    assert_eq!(file_only.version(), "from-the-file");

    let nothing = config(&[], &[], &[]);
    assert_eq!(
        nothing.version(),
        "1.2.3",
        "the build metadata is the floor"
    );
}

#[test]
fn test_the_environment_overwrites_the_file_and_is_overwritten_by_the_command_line() {
    // The rule that matters in practice: a file travels with the build — baked into an image, copied
    // between environments — and the environment is set by whoever is running this instance. When
    // they disagree, the one that knows something the other could not is the environment.
    let config = config(
        &[
            (SETTING_VERSION, "file-version"),
            (SETTING_COPYRIGHT_HOLDER, "File Holder"),
        ],
        &[(SETTING_VERSION, "env-version")],
        &[(SETTING_COPYRIGHT_HOLDER, "CLI Holder")],
    );

    assert_eq!(config.version(), "env-version");
    assert_eq!(config.copyright_year(), "2026");
    assert_eq!(config.copyright_holder(), "CLI Holder");
}

#[test]
fn test_unknown_inputs_do_not_change_typed_config() {
    let with_noise = config(
        &[("unknown", "file")],
        &[("PATH", "/usr/bin")],
        &[("other", "cli")],
    );
    let without = config(&[], &[], &[]);

    assert_eq!(with_noise.version(), without.version());
    assert_eq!(with_noise.copyright_holder(), without.copyright_holder());
    assert_eq!(with_noise.web_http_addr(), without.web_http_addr());
    assert_eq!(with_noise.grpc_addr(), without.grpc_addr());
    assert_eq!(with_noise.log_level(), without.log_level());
    assert_eq!(with_noise.log_format(), without.log_format());
}

#[test]
fn test_a_registered_section_reads_back_as_its_own_type() {
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct Feature {
        enabled: bool,
    }

    impl pic_x_core::ConfigSection for Feature {
        const NAME: &'static str = "feature";
    }

    let plain = config(&[], &[], &[]);
    assert!(plain.section::<Feature>().is_none());

    let with_section = plain.with_section(Feature { enabled: true });
    assert!(
        with_section
            .section::<Feature>()
            .expect("the section is kept")
            .enabled
    );
    assert_eq!(
        with_section.section_names().collect::<Vec<_>>(),
        vec!["feature"]
    );
}

#[test]
fn test_listen_addresses_have_no_built_in_default() {
    let config = config(&[], &[], &[]);

    assert_eq!(config.web_http_addr(), None);
    assert_eq!(config.telemetry_addr(), None);
    assert_eq!(config.grpc_addr(), None);
}

#[test]
fn test_command_line_addresses_override_the_configuration_file() {
    let config = config(
        &[
            (SETTING_WEB_HTTP_ADDR, "0.0.0.0:5556"),
            (SETTING_GRPC_ADDR, "127.0.0.1:5557"),
        ],
        &[],
        &[(SETTING_WEB_HTTP_ADDR, "127.0.0.1:9999")],
    );

    assert_eq!(config.web_http_addr(), Some("127.0.0.1:9999"));
    assert_eq!(config.grpc_addr(), Some("127.0.0.1:5557"));
}

#[test]
fn test_validate_accepts_a_config_with_a_web_address() {
    assert!(servable().validate().is_ok());
}

#[test]
fn test_validate_rejects_a_config_with_no_web_address() {
    let config = config(&[(SETTING_GRPC_ADDR, "127.0.0.1:5557")], &[], &[]);

    let error = config.validate().expect_err("no web address is invalid");
    assert!(format!("{error}").contains("web listen address"));
}

#[test]
fn test_the_public_surface_has_one_address_and_tls_is_a_property_of_it() {
    // There is no second address for "the same surface, but encrypted": whether it is HTTP or HTTPS
    // is decided by `web.tls`. A surface that accepted an https address and never bound it would be
    // a configuration that looks served and is not.
    let plain = config(&[(SETTING_WEB_HTTP_ADDR, "0.0.0.0:5556")], &[], &[]);
    assert!(plain.validate().is_ok());
    assert!(plain.web_tls().is_none());

    let secured = config(
        &[
            (SETTING_WEB_HTTP_ADDR, "0.0.0.0:5556"),
            (SETTING_WEB_TLS_CERT, "/nonexistent/server.pem"),
            (SETTING_WEB_TLS_KEY, "/nonexistent/server.key"),
        ],
        &[],
        &[],
    );
    assert_eq!(secured.web_http_addr(), Some("0.0.0.0:5556"));
    assert!(secured.web_tls().is_some());
}

#[test]
fn test_validate_rejects_a_blank_declared_address() {
    let config = config(
        &[
            (SETTING_WEB_HTTP_ADDR, "0.0.0.0:5556"),
            (SETTING_GRPC_ADDR, "   "),
        ],
        &[],
        &[],
    );

    let error = config.validate().expect_err("a blank address is invalid");
    assert!(format!("{error}").contains("gRPC"));
}

#[test]
fn test_the_shutdown_budget_defaults_to_what_kubernetes_gives_a_pod() {
    assert_eq!(
        config(&[], &[], &[]).shutdown_timeout(),
        Duration::from_secs(30)
    );
}

#[test]
fn test_a_shutdown_budget_is_read_in_seconds_minutes_or_hours() {
    let cases = [("45", 45), ("45s", 45), ("2m", 120), ("1h", 3600)];

    for (written, seconds) in cases {
        assert_eq!(
            config(&[(SETTING_SHUTDOWN_TIMEOUT, written)], &[], &[]).shutdown_timeout(),
            Duration::from_secs(seconds),
            "reading {written}"
        );
    }
}

#[test]
fn test_an_unreadable_shutdown_budget_is_an_error() {
    // The empty string is absent, not unreadable: that case is covered above.
    for written in ["soon", "0", "-5", "   "] {
        assert!(
            Config::from_layers(
                build_settings(),
                NO_DECLARED,
                Layers::new()
                    .with_file(pairs(&[(SETTING_SHUTDOWN_TIMEOUT, written)]))
                    .with_environment(pairs(&[]))
                    .with_command_line(pairs(&[])),
            )
            .is_err(),
            "`{written}` should not be a budget"
        );
    }
}

#[test]
fn test_without_an_issuer_a_public_url_is_the_path_itself() {
    let config = config(&[], &[], &[]);

    assert!(config.issuer().is_none());
    assert_eq!(
        config.public_url("/.well-known/jwks.json"),
        "/.well-known/jwks.json"
    );
    assert_eq!(config.web_path_prefix(), "");
}

#[test]
fn test_an_issuer_makes_public_urls_absolute() {
    let config = config(
        &[(SETTING_ISSUER, "https://login.example.com/pic-x")],
        &[],
        &[],
    );

    assert_eq!(
        config.public_url("/.well-known/jwks.json"),
        "https://login.example.com/pic-x/.well-known/jwks.json"
    );
}

#[test]
fn test_a_trailing_slash_on_the_issuer_never_doubles_up() {
    let config = config(&[(SETTING_ISSUER, "https://login.example.com/")], &[], &[]);

    assert_eq!(
        config.public_url("/.well-known/jwks.json"),
        "https://login.example.com/.well-known/jwks.json"
    );
}

#[test]
fn test_an_issuer_that_offers_no_protection_is_refused() {
    let public = config(
        &[
            (SETTING_WEB_HTTP_ADDR, "0.0.0.0:5556"),
            (SETTING_ISSUER, "http://login.example.com"),
        ],
        &[],
        &[],
    );
    let error = public.validate().expect_err("http is not a public issuer");
    assert!(format!("{error}").contains("not https"));

    // Loopback is the exception: there is nothing in between to protect the client from.
    let local = config(
        &[
            (SETTING_WEB_HTTP_ADDR, "0.0.0.0:5556"),
            (SETTING_ISSUER, "http://localhost:7556"),
        ],
        &[],
        &[],
    );
    assert!(local.validate().is_ok());
}

#[test]
fn test_a_path_prefix_has_to_look_like_a_path() {
    let config = config(
        &[
            (SETTING_WEB_HTTP_ADDR, "0.0.0.0:5556"),
            (SETTING_WEB_PATH_PREFIX, "pic-x"),
        ],
        &[],
        &[],
    );

    let error = config.validate().expect_err("a prefix without a slash");
    assert!(format!("{error}").contains("does not start with a slash"));
}

#[test]
fn test_an_empty_value_means_the_setting_was_never_supplied() {
    // How a Taskfile or a container manifest expresses "not this time" for an optional setting.
    let config = config(
        &[],
        &[
            (SETTING_WEB_TLS_CERT, ""),
            (SETTING_WEB_TLS_KEY, ""),
            (SETTING_LOG_LEVEL, ""),
        ],
        &[],
    );

    assert!(config.web_tls().is_none());
    assert_eq!(config.log_level(), LogLevel::Info, "the default survives");
}

#[test]
fn test_whitespace_is_not_empty_because_it_is_a_typo() {
    let config = config(
        &[
            (SETTING_WEB_HTTP_ADDR, "0.0.0.0:5556"),
            (SETTING_GRPC_ADDR, "   "),
        ],
        &[],
        &[],
    );

    assert!(
        config.validate().is_err(),
        "a blank address should be reported, not quietly dropped"
    );
}

#[test]
fn test_a_surface_without_tls_settings_serves_in_the_clear() {
    let config = config(&[], &[], &[]);

    assert!(config.web_tls().is_none());
    assert!(config.grpc_tls().is_none());
    assert!(config.telemetry_tls().is_none());
}

#[test]
fn test_tls_material_is_read_per_surface_and_defaults_to_the_modern_floor() {
    let config = config(
        &[
            (SETTING_WEB_TLS_CERT, "/tls/web.pem"),
            (SETTING_WEB_TLS_KEY, "/tls/web.key"),
            (SETTING_GRPC_TLS_CERT, "/tls/grpc.pem"),
            (SETTING_GRPC_TLS_KEY, "/tls/grpc.key"),
            (SETTING_GRPC_TLS_CLIENT_CA, "/tls/clients.pem"),
        ],
        &[],
        &[],
    );

    let web = config.web_tls().expect("the web surface has material");
    assert_eq!(web.certificate(), std::path::Path::new("/tls/web.pem"));
    assert_eq!(web.min_version(), TlsVersion::V1_3);
    assert!(!web.is_mutual());

    let grpc = config.grpc_tls().expect("the admin surface has material");
    assert!(grpc.is_mutual(), "a client CA is what makes it mutual");
}

#[test]
fn test_a_certificate_without_its_key_is_refused_rather_than_ignored() {
    let only_cert = Config::from_layers(
        build_settings(),
        NO_DECLARED,
        Layers::new()
            .with_file(pairs(&[(SETTING_WEB_TLS_CERT, "/tls/web.pem")]))
            .with_environment(pairs(&[]))
            .with_command_line(pairs(&[])),
    );
    assert!(
        only_cert.is_err(),
        "serving in the clear here would be silent"
    );

    let only_key = Config::from_layers(
        build_settings(),
        NO_DECLARED,
        Layers::new()
            .with_file(pairs(&[(SETTING_GRPC_TLS_KEY, "/tls/grpc.key")]))
            .with_environment(pairs(&[]))
            .with_command_line(pairs(&[])),
    );
    assert!(only_key.is_err());
}

#[test]
fn test_the_protocol_floor_can_be_lowered_by_naming_it() {
    let config = config(
        &[
            (SETTING_WEB_TLS_CERT, "/tls/web.pem"),
            (SETTING_WEB_TLS_KEY, "/tls/web.key"),
            (SETTING_WEB_TLS_MIN_VERSION, "1.2"),
        ],
        &[],
        &[],
    );

    assert_eq!(
        config
            .web_tls()
            .expect("the web surface has material")
            .min_version(),
        TlsVersion::V1_2
    );
}

#[test]
fn test_telemetry_is_offered_tls_but_never_a_client_authority() {
    let config = config(
        &[
            (SETTING_TELEMETRY_TLS_CERT, "/tls/telemetry.pem"),
            (SETTING_TELEMETRY_TLS_KEY, "/tls/telemetry.key"),
        ],
        &[],
        &[],
    );

    let telemetry = config
        .telemetry_tls()
        .expect("the telemetry surface has material");
    assert!(
        !telemetry.is_mutual(),
        "a scrape and a kubelet probe have no client identity to present"
    );
}

#[test]
fn test_material_that_names_missing_files_stops_validation() {
    let config = config(
        &[
            (SETTING_WEB_HTTP_ADDR, "0.0.0.0:5556"),
            (SETTING_WEB_TLS_CERT, "/nonexistent/web.pem"),
            (SETTING_WEB_TLS_KEY, "/nonexistent/web.key"),
        ],
        &[],
        &[],
    );

    let error = config.validate().expect_err("the files are not there");
    assert!(format!("{error:#}").contains("/nonexistent/web.pem"));
}

#[test]
fn test_logging_defaults_to_the_production_settings() {
    let config = config(&[], &[], &[]);

    assert_eq!(config.log_level(), LogLevel::Info);
    assert_eq!(config.log_format(), LogFormat::Json);
}

#[test]
fn test_logging_settings_travel_through_the_same_layers() {
    let config = config(
        &[(SETTING_LOG_LEVEL, "warn")],
        &[
            (SETTING_LOG_LEVEL, "error"),
            (SETTING_LOG_FORMAT, "terminal"),
        ],
        &[(SETTING_LOG_LEVEL, "debug")],
    );

    assert_eq!(config.log_level(), LogLevel::Debug);
    assert_eq!(config.log_format(), LogFormat::Terminal);
}

#[test]
fn test_an_unreadable_log_level_is_an_error_not_a_silent_default() {
    let error = Config::from_layers(
        build_settings(),
        NO_DECLARED,
        Layers::new()
            .with_file(pairs(&[]))
            .with_environment(pairs(&[(SETTING_LOG_LEVEL, "verbose")]))
            .with_command_line(pairs(&[])),
    )
    .expect_err("`verbose` is not a level");

    let message = format!("{error:#}");
    assert!(message.contains(SETTING_LOG_LEVEL));
    assert!(message.contains("verbose"));
}

#[test]
fn test_an_unreadable_log_format_is_an_error_not_a_silent_default() {
    let error = Config::from_layers(
        build_settings(),
        NO_DECLARED,
        Layers::new()
            .with_file(pairs(&[(SETTING_LOG_FORMAT, "xml")]))
            .with_environment(pairs(&[]))
            .with_command_line(pairs(&[])),
    )
    .expect_err("`xml` is not a format");

    let message = format!("{error:#}");
    assert!(message.contains(SETTING_LOG_FORMAT));
    assert!(message.contains("xml"));
}

#[test]
fn test_a_declared_setting_travels_through_every_layer() {
    // A setting a build added obeys the same precedence as a typed one: no capability gets its own
    // rules about which layer wins.
    let config = declaring(
        &["PERMGUARD_SSO_ISSUER"],
        &[("PERMGUARD_SSO_ISSUER", "file")],
        &[("PERMGUARD_SSO_ISSUER", "env")],
        &[],
    );

    assert_eq!(config.setting("PERMGUARD_SSO_ISSUER"), Some("env"));
    assert_eq!(
        config.declared_settings().collect::<Vec<_>>(),
        vec!["PERMGUARD_SSO_ISSUER"]
    );
}

#[test]
fn test_an_undeclared_setting_never_reaches_the_config() {
    let config = config(&[], &[("PERMGUARD_SSO_ISSUER", "env")], &[]);

    assert_eq!(config.setting("PERMGUARD_SSO_ISSUER"), None);
}

#[test]
fn test_a_declared_setting_no_layer_supplies_stays_absent() {
    let config = declaring(&["PERMGUARD_SSO_ISSUER"], &[], &[], &[]);

    assert_eq!(config.setting("PERMGUARD_SSO_ISSUER"), None);
}
