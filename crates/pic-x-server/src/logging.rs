// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Installs the process-wide subscriber the lifecycle records go to.
//!
//! Records go to standard output, which is where a container runtime collects them, and their shape
//! is whatever the effective configuration asked for: one JSON object per record by default, or
//! human-readable lines for a terminal someone is looking at.
//!
//! Installing a subscriber is a process-global effect, so it happens once, from the entry point that
//! owns the process — not from a library path a test or a downstream command might take twice.

use anyhow::{Context, Result};
use tracing::{Level, info};
use tracing_subscriber::FmtSubscriber;

use pic_x_core::{Config, LogFormat, LogLevel, ProductIdentity};

/// Installs the subscriber the effective config asks for.
///
/// Fails when a subscriber is already installed, because that means two things in one process both
/// believe they decide where records go, and silently letting the first one win hides it.
pub fn install(config: &Config) -> Result<()> {
    let level = level_of(config.log_level());

    match config.log_format() {
        LogFormat::Json => FmtSubscriber::builder()
            .with_max_level(level)
            .json()
            .flatten_event(true)
            .with_current_span(false)
            .try_init(),
        LogFormat::Terminal => FmtSubscriber::builder().with_max_level(level).try_init(),
    }
    .map_err(|error| anyhow::anyhow!(error))
    .context("installing the log subscriber")
}

/// Records which build is running, as the first record of the stream.
///
/// In `json` there is no banner, so this record is the only thing that says which build produced
/// everything after it — and a stream nobody can attribute to a build is a stream nobody can act on.
/// In `terminal` the banner says the same thing to a human; the record is emitted either way so the
/// two formats carry the same information.
pub fn record_build(identity: &ProductIdentity, config: &Config, host: &str) {
    info!(
        event.name = "server.build",
        service.name = identity.binary_name(),
        service.version = config.version(),
        server.host = host,
        log.level = config.log_level().as_str(),
        log.format = config.log_format().as_str(),
        process.pid = std::process::id(),
        "build"
    );
}

/// Maps the configured level onto the one `tracing` filters with.
fn level_of(level: LogLevel) -> Level {
    match level {
        LogLevel::Error => Level::ERROR,
        LogLevel::Warn => Level::WARN,
        LogLevel::Info => Level::INFO,
        LogLevel::Debug => Level::DEBUG,
        LogLevel::Trace => Level::TRACE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_every_configured_level_maps_to_the_tracing_level_of_the_same_name() {
        assert_eq!(level_of(LogLevel::Error), Level::ERROR);
        assert_eq!(level_of(LogLevel::Warn), Level::WARN);
        assert_eq!(level_of(LogLevel::Info), Level::INFO);
        assert_eq!(level_of(LogLevel::Debug), Level::DEBUG);
        assert_eq!(level_of(LogLevel::Trace), Level::TRACE);
    }

    #[test]
    fn test_the_default_config_asks_for_info_and_json() {
        let config = Config::default();

        assert_eq!(level_of(config.log_level()), Level::INFO);
        assert_eq!(config.log_format(), LogFormat::Json);
    }
}
