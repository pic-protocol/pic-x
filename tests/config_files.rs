//! The four configuration files that ship with this repository, checked against the binary.
//!
//! A configuration file is documentation that is also executable, which means it can be wrong in two
//! directions: it can stop matching the code, and the code can stop matching it. Both are silent.
//!
//! So each file is exercised here by the thing it configures:
//!
//! * `config.template.yaml` is **uncommented** and started, which proves every setting it documents
//!   still exists, still parses, and still makes a configuration a server will accept;
//! * `config.local.yaml` and `config.local-tls.yaml` are started from an empty volume, which is the
//!   claim they make on their first line;
//! * `config.prod.yaml` is started too, because a shipped default that does not start is worse than
//!   no default at all — and separately checked for the postures it must *not* have.

use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// How long a silence has to last before the server counts as up and waiting.
const LULL: Duration = Duration::from_millis(1_500);

/// Returns the repository root, which is where the configuration files live.
fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Reads one of the shipped files.
fn shipped(name: &str) -> String {
    fs::read_to_string(root().join(name)).unwrap_or_else(|error| panic!("reading {name}: {error}"))
}

/// A volume nothing else is using.
fn volume(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("pic-x-configs-{name}"));
    let _ = fs::remove_dir_all(&path);

    path
}

/// Turns the template into the configuration it documents.
///
/// The convention the template keeps: `##` is prose and disappears, `# ` is a setting and loses its
/// marker. Anything else is left alone. It is mechanical on purpose — a rule a human has to apply by
/// judgement is a rule that stops being applied.
fn uncomment(template: &str) -> String {
    template
        .lines()
        .filter(|line| !line.starts_with("##"))
        .map(|line| match line {
            "#" => "",
            line => line.strip_prefix("# ").unwrap_or(line),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Writes `contents` to a file of its own, verbatim.
///
/// The volume is pointed elsewhere with `PIC_X_WORKING_DIR` at the call site rather than by editing
/// the file, which is only possible because the environment overwrites the file. That is worth doing
/// here rather than the other way round: it means these tests exercise the shipped files exactly as
/// they are, with not one line rewritten.
fn at(volume: &Path, name: &str, contents: &str) -> PathBuf {
    let path = volume.with_file_name(format!(
        "{}-{name}.yaml",
        volume.file_name().unwrap_or_default().to_string_lossy()
    ));
    fs::write(&path, contents).expect("writing the configuration under test");

    path
}

/// What starting the binary against a configuration produced.
struct Outcome {
    started: bool,
    stdout: String,
    stderr: String,
}

/// Starts the binary against `config`, waits for it to settle, and asks it to stop.
///
/// Every address is overridden to port zero, because these files name real ports and the suite runs
/// in parallel. The overrides arrive on the command line, which is the last layer of all, so they
/// beat both the file and the `PIC_X_WORKING_DIR` set beside them.
fn start(config: &Path, volume: &Path) -> Outcome {
    let mut child = Command::new(env!("CARGO_BIN_EXE_pic-x"))
        .arg(config)
        .env("PIC_X_WORKING_DIR", volume)
        .args(["--web-http-addr", "127.0.0.1:0"])
        .args(["--telemetry-addr", "127.0.0.1:0"])
        .args(["--grpc-addr", "127.0.0.1:0"])
        // JSON regardless of what the file asks for: the terminal format styles field names with
        // escape codes, and a test that greps for `mutual_tls=true` would be asserting about a
        // colour scheme.
        .args(["--log-format", "json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("starting the pic-x binary");

    let out = child.stdout.take().expect("standard output is piped");
    let (lines, incoming) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut reader = BufReader::new(out);

        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if lines.send(line).is_err() {
                        break;
                    }
                }
            }
        }
    });

    let mut stdout = String::new();
    let mut ended = false;

    loop {
        match incoming.recv_timeout(LULL) {
            Ok(line) => {
                let started = line.contains("server.started");
                stdout.push_str(&line);

                if started {
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => break,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                ended = true;
                break;
            }
        }
    }

    if !ended {
        let _ = Command::new("kill")
            .arg("-TERM")
            .arg(child.id().to_string())
            .status();
    }

    while let Ok(line) = incoming.recv() {
        stdout.push_str(&line);
    }
    let _ = reader.join();

    let status = child.wait().expect("waiting for the pic-x binary");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("standard error is piped")
        .read_to_string(&mut stderr)
        .expect("reading standard error");

    Outcome {
        started: status.success(),
        stdout,
        stderr,
    }
}

#[test]
fn test_the_template_documents_a_configuration_that_actually_starts() {
    // The whole point of the file. Uncommented, it must be a configuration the binary accepts — so
    // it cannot document a setting that was renamed, removed, or never existed.
    //
    // The template describes a *production* deployment, so it generates nothing and expects its
    // material to be there. The development file is used to put it there first, which incidentally
    // checks the two agree about what the material is called.
    let volume = volume("template");
    let generator = at(&volume, "generator", &shipped("config.local-tls.yaml"));
    let generated = start(&generator, &volume);
    assert!(
        generated.started,
        "the development file could not prepare the volume: {}",
        generated.stderr
    );

    let config = at(
        &volume,
        "template",
        &uncomment(&shipped("config.template.yaml")),
    );
    let outcome = start(&config, &volume);

    assert!(
        outcome.started,
        "the template does not describe a configuration this build accepts: {}",
        outcome.stderr
    );
}

#[test]
fn test_the_template_leaves_nothing_it_documents_commented_out() {
    // A setting mentioned only in prose is a setting nobody can copy. Every one of them has to appear
    // as a line that uncommenting turns into YAML.
    let uncommented = uncomment(&shipped("config.template.yaml"));

    for section in [
        "web:",
        "telemetry:",
        "grpc:",
        "tls:",
        "log:",
        "shutdown:",
        "secrets:",
        "audit:",
        "keys:",
    ] {
        assert!(
            uncommented.lines().any(|line| line.trim() == section),
            "the template documents no `{section}` section"
        );
    }

    for setting in [
        "working_dir:",
        "development_mode:",
        "autogenerate:",
        "issuer:",
        "path_prefix:",
        "client_ca:",
        "crl:",
        "min_version:",
        "reload:",
        "reload_interval:",
        "allow:",
        "provider:",
        "env_prefix:",
        "sink:",
        "retention:",
        "key_ref:",
        "key_version:",
        "publish_ahead:",
        "rotate_every:",
        "retain:",
    ] {
        assert!(
            uncommented
                .lines()
                .any(|line| line.trim().starts_with(setting)),
            "the template does not offer `{setting}` as a line you can uncomment"
        );
    }
}

#[test]
fn test_the_local_file_starts_from_an_empty_volume() {
    // Its first claim: nothing has to be set up first.
    let volume = volume("local");
    let config = at(&volume, "local", &shipped("config.local.yaml"));

    let outcome = start(&config, &volume);

    assert!(outcome.started, "{}", outcome.stderr);
    assert!(
        volume.join("secrets/audit-pseudonym").exists(),
        "the pseudonymisation secret was not generated"
    );
    assert!(
        volume.join("keys/ring.json").exists(),
        "the key ring was not created"
    );
    assert!(
        volume.join("audit").exists(),
        "the audit trail was not written"
    );
}

#[test]
fn test_the_local_tls_file_generates_its_own_certificates_and_serves_with_them() {
    let volume = volume("local-tls");
    let config = at(&volume, "local-tls", &shipped("config.local-tls.yaml"));

    let outcome = start(&config, &volume);

    assert!(outcome.started, "{}", outcome.stderr);
    for material in ["tls/ca.pem", "tls/server.pem", "tls/client.pem"] {
        assert!(
            volume.join(material).exists(),
            "{material} was not generated"
        );
    }
    // Both halves: TLS on the public surface, and a client certificate demanded on the
    // administrative one. A file called `local-tls` that only did the first would be a lie.
    assert!(
        outcome.stdout.contains(r#""mutual_tls":true"#),
        "the administrative surface is not demanding a client certificate:\n{}",
        outcome.stdout
    );
}

#[test]
fn test_the_production_file_starts_and_is_not_a_development_one() {
    let volume = volume("prod");
    let shipped_text = shipped("config.prod.yaml");
    let config = at(&volume, "prod", &shipped_text);

    let outcome = start(&config, &volume);

    // A shipped default that does not start is worse than no default: the first thing anybody does
    // with an image is run it.
    assert!(outcome.started, "{}", outcome.stderr);

    // And it must not have quietly become a development configuration, which is how this file went
    // wrong once already.
    let settings: Vec<&str> = shipped_text
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .collect();

    for forbidden in ["development_mode:", "autogenerate:"] {
        assert!(
            !settings.iter().any(|line| line.starts_with(forbidden)),
            "config.prod.yaml sets `{forbidden}`, which is a development switch"
        );
    }

    // Nothing outside the host reaches administration by default.
    assert!(
        settings.iter().any(|line| line == &"addr: 127.0.0.1:7557"),
        "the administrative surface is not on loopback in the shipped configuration"
    );
}

#[test]
fn test_the_file_the_image_ships_is_the_production_one() {
    // The Dockerfile and the file it copies drift apart silently, and the symptom is a container
    // that runs somebody's old defaults.
    let dockerfile = shipped("Dockerfile");

    assert!(
        dockerfile.contains("COPY config.prod.yaml /etc/pic-x/config.yaml"),
        "the image does not ship config.prod.yaml"
    );
    assert!(
        dockerfile.contains(r#"CMD ["/etc/pic-x/config.yaml"]"#),
        "the image does not run the file it ships"
    );
}
