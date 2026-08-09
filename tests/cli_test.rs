//! Use-case tests driving the built `pic-x` binary.
//!
//! Serving is the default action, so an invocation that names a configuration file and nothing else
//! starts the server. A named command asks for something other than serving.
//!
//! The server lifecycle reaches standard output as log records, not as printed lines, so these tests
//! read it the way an operator would: as JSON by default, as readable lines when asked.

use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// A configuration file written under the test's own directory and removed when it goes out of
/// scope, plus a volume of its own for the server to keep things in.
///
/// The volume matters as much as the file. The server remembers things about its own configuration
/// between runs — which pseudonymisation key versions it has already written records under, for one
/// — and a suite that shared one volume would have every test inherit whatever the last one decided.
struct ConfigFixture {
    path: PathBuf,
    volume: PathBuf,
}

impl ConfigFixture {
    /// Writes `contents` to a uniquely named file for `name`, beside a volume of its own.
    fn new(name: &str, contents: &str) -> Self {
        let dir = std::env::temp_dir().join("pic-x-cli-test");
        fs::create_dir_all(&dir).expect("creating the fixture directory");

        let path = dir.join(format!("{name}.yaml"));
        fs::write(&path, contents).expect("writing the fixture configuration file");

        let volume = dir.join(format!("{name}.volume"));
        let _ = fs::remove_dir_all(&volume);

        Self { path, volume }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn as_arg(&self) -> &str {
        self.path.to_str().expect("the fixture path is valid UTF-8")
    }

    /// The environment pair that points the server at this fixture's own volume.
    fn volume(&self) -> (&str, &str) {
        (
            "PIC_X_WORKING_DIR",
            self.volume
                .to_str()
                .expect("the volume path is valid UTF-8"),
        )
    }
}

impl Drop for ConfigFixture {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        let _ = fs::remove_dir_all(&self.volume);
    }
}

/// A configuration that satisfies validation and binds nothing anyone has to guess.
///
/// Port zero on every surface: the operating system picks a free one, so the whole suite can run in
/// parallel without the tests fighting each other for a port — which is exactly what happened the
/// first time the surfaces started binding for real.
const SERVABLE_CONFIG: &str =
    "web:\n  http: 127.0.0.1:0\ntelemetry:\n  addr: 127.0.0.1:0\ngrpc:\n  addr: 127.0.0.1:0\n";

/// Runs the built binary with the given arguments.
fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pic-x"))
        .args(args)
        .output()
        .expect("running the pic-x binary")
}

/// Runs the built binary with explicit environment overrides.
fn run_with_env(args: &[&str], envs: &[(&str, &str)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_pic-x"));

    command.args(args);
    for (key, value) in envs {
        command.env(key, value);
    }

    command.output().expect("running the pic-x binary")
}

/// Returns the standard output of a run as text.
fn stdout_of(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("standard output is valid UTF-8")
}

/// Returns the standard error of a run as text.
fn stderr_of(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("standard error is valid UTF-8")
}

/// What a served run produced, once it had been asked to stop.
struct Served {
    succeeded: bool,
    stdout: String,
    stderr: String,
}

/// Starts the server, waits until it is up, asks it to stop, and collects everything it said.
///
/// The binary now waits: a server that returned on its own would be a server nobody could use. So a
/// use-case test drives it the way an orchestrator does — start, wait, SIGTERM — which also means
/// every one of these tests exercises the shutdown path for free.
///
/// "Up" cannot be defined as "printed `server.started`", because a run configured quietly enough
/// prints nothing at all and the wait would never end. It is defined as *stopped saying things*:
/// output is read until a lull, and the signal follows. A run that fails before it starts ends the
/// stream instead, and its real exit status is what comes back.
fn serve(args: &[&str], envs: &[(&str, &str)]) -> Served {
    /// How long a silence has to last before the server counts as up and waiting.
    const LULL: Duration = Duration::from_millis(1_500);

    let mut command = Command::new(env!("CARGO_BIN_EXE_pic-x"));

    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in envs {
        command.env(key, value);
    }

    let mut child = command.spawn().expect("starting the pic-x binary");
    let out = child.stdout.take().expect("standard output is piped");

    // Reading on another thread is what makes the lull observable: a blocking read cannot be given
    // up on, and a pipe that is never drained eventually blocks the writer.
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

    Served {
        succeeded: status.success(),
        stdout,
        stderr,
    }
}

#[test]
fn test_the_default_run_is_a_json_stream_and_nothing_else() {
    let config = ConfigFixture::new("servable", SERVABLE_CONFIG);
    let served = serve(&[config.as_arg()], &[]);
    assert!(served.succeeded, "{}", served.stderr);

    let stdout = served.stdout;

    // No banner: in json the stream belongs to a log pipeline, so every line has to be a record.
    assert!(!stdout.contains("PIC-X (Provenance Identity Continuity Exchange)"));
    assert!(!stdout.contains("____"));
    for line in stdout.lines() {
        assert!(line.starts_with('{'), "not a record: {line}");
        assert!(line.ends_with('}'), "not one JSON object per line: {line}");
    }

    // The greeting is gone: what a run says about itself is the lifecycle.
    assert!(!stdout.contains("Hello, world!"));
    assert!(stdout.contains(r#""event.name":"server.started""#));
    assert!(stdout.contains(r#""event.name":"server.stopped""#));
    assert!(stdout.contains(r#""component":"server""#));
}

#[test]
fn test_the_first_record_says_which_build_is_running() {
    let config = ConfigFixture::new("build-record", SERVABLE_CONFIG);
    let stdout = serve(&[config.as_arg()], &[]).stdout;

    let first = stdout.lines().next().expect("the run wrote a record");

    assert!(first.contains(r#""event.name":"server.build""#));
    assert!(first.contains(r#""service.name":"pic-x""#));
    assert!(first.contains(&format!(
        r#""service.version":"{}""#,
        env!("CARGO_PKG_VERSION")
    )));
    assert!(first.contains(r#""log.level":"info""#));
    assert!(first.contains(r#""log.format":"json""#));
    assert!(first.contains(r#""process.pid""#));
}

#[test]
fn test_every_record_carries_the_keys_a_monitoring_tool_keys_on() {
    let config = ConfigFixture::new("record-shape", SERVABLE_CONFIG);
    let stdout = serve(&[config.as_arg()], &[]).stdout;

    for line in stdout.lines() {
        for key in [
            r#""timestamp""#,
            r#""level""#,
            r#""message""#,
            r#""event.name""#,
        ] {
            assert!(line.contains(key), "a record without {key}: {line}");
        }
    }

    // `info` reports what happened, not the transitions in between.
    assert!(!stdout.contains(r#""event.name":"server.starting""#));
    assert!(!stdout.contains(r#""event.name":"server.stopping""#));
}

#[test]
fn test_the_terminal_format_prints_the_banner_the_json_format_leaves_out() {
    let config = ConfigFixture::new("terminal-banner", SERVABLE_CONFIG);
    let stdout = serve(&[config.as_arg(), "--log-format", "terminal"], &[]).stdout;

    assert!(stdout.starts_with(" ____"));
    assert!(stdout.contains("PIC-X (Provenance Identity Continuity Exchange)"));
    assert!(stdout.contains("Verifiable Authority Continuity"));
    assert!(stdout.contains("All rights reserved."));

    // The build record is emitted either way, so both formats say which build produced the stream.
    assert!(stdout.contains("server.build"));
    assert!(stdout.contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn test_debug_adds_the_transitions_info_leaves_out() {
    let config = ConfigFixture::new("debug-logging", SERVABLE_CONFIG);
    let stdout = serve(&[config.as_arg(), "--log-level", "debug"], &[]).stdout;

    for event in [
        "server.starting",
        "server.started",
        "server.stopping",
        "server.stopped",
    ] {
        assert!(
            stdout.contains(&format!(r#""event.name":"{event}""#)),
            "debug omits {event}"
        );
    }
}

#[test]
fn test_the_terminal_format_writes_readable_lines_instead_of_json() {
    let config = ConfigFixture::new("terminal-logging", SERVABLE_CONFIG);
    let stdout = serve(&[config.as_arg(), "--log-format", "terminal"], &[]).stdout;

    assert!(!stdout.contains(r#""event.name":"server.started""#));
    assert!(stdout.contains("server.started"));
    assert!(stdout.contains("component"));
}

#[test]
fn test_logging_can_be_set_from_the_configuration_file_and_the_environment() {
    let from_file = ConfigFixture::new(
        "log-section",
        "web:\n  http: 127.0.0.1:0\nlog:\n  level: debug\n  format: terminal\n",
    );
    let stdout = serve(&[from_file.as_arg()], &[]).stdout;
    assert!(stdout.contains("server.starting"));
    assert!(!stdout.contains(r#""event.name":"server.starting""#));

    let plain = ConfigFixture::new("log-env", SERVABLE_CONFIG);
    let from_env = serve(
        &[plain.as_arg()],
        &[
            ("PIC_X_LOG_LEVEL", "debug"),
            ("PIC_X_LOG_FORMAT", "terminal"),
        ],
    );
    assert!(from_env.stdout.contains("server.starting"));

    // The command line still wins over both: at `error` the lifecycle says nothing at all.
    let quiet = serve(
        &[plain.as_arg(), "--log-level", "error"],
        &[
            ("PIC_X_LOG_LEVEL", "debug"),
            ("PIC_X_LOG_FORMAT", "terminal"),
        ],
    );
    assert!(quiet.succeeded, "{}", quiet.stderr);
    assert!(!quiet.stdout.contains("server.started"));
}

#[test]
fn test_an_unreadable_log_setting_is_refused_with_what_was_expected() {
    let config = ConfigFixture::new("bad-level", SERVABLE_CONFIG);

    let flag = run(&[config.as_arg(), "--log-level", "verbose"]);
    assert!(!flag.status.success());
    assert!(stderr_of(&flag).contains("error, warn, info, debug, trace"));

    let env = run_with_env(&[config.as_arg()], &[("PIC_X_LOG_FORMAT", "xml")]);
    assert!(!env.status.success());
    assert!(stderr_of(&env).contains("json, terminal"));
}

#[test]
fn test_pseudonymisation_without_a_key_refuses_to_start() {
    let config = ConfigFixture::new(
        "pseudonym-nokey",
        "web:\n  http: 127.0.0.1:0\nsecrets:\n  provider: environment\naudit:\n  pseudonym:\n    enabled: true\n",
    );
    let output = run(&[config.as_arg()]);

    assert!(!output.status.success());
    assert!(stderr_of(&output).contains("audit.pseudonym.key"));
}

#[test]
fn test_pseudonymisation_without_anywhere_to_resolve_the_key_refuses_to_start() {
    let config = ConfigFixture::new(
        "pseudonym-no-store",
        "web:\n  http: 127.0.0.1:0\naudit:\n  pseudonym:\n    enabled: true\n    key_ref: audit-pseudonym\n",
    );
    let output = run(&[config.as_arg()]);

    assert!(!output.status.success());
    assert!(stderr_of(&output).contains("no secret provider"));
}

#[test]
fn test_a_secret_the_store_does_not_have_refuses_to_start_naming_the_reference() {
    let config = ConfigFixture::new(
        "pseudonym-absent",
        "web:\n  http: 127.0.0.1:0\nsecrets:\n  provider: environment\n  env_prefix: PIC_X_NOTHING\naudit:\n  pseudonym:\n    enabled: true\n    key_ref: audit-pseudonym\n",
    );
    let output = run(&[config.as_arg()]);

    assert!(!output.status.success());
    let stderr = stderr_of(&output);
    // The reference is safe to name; it is not the secret.
    assert!(stderr.contains("audit-pseudonym"), "{stderr}");
    assert!(stderr.contains("no secret named"), "{stderr}");
}

#[test]
fn test_a_key_resolved_from_the_environment_starts_and_pseudonymises() {
    let config = ConfigFixture::new(
        "pseudonym-resolved",
        "web:\n  http: 127.0.0.1:0\nsecrets:\n  provider: environment\n  env_prefix: PIC_X_TEST_SECRET\naudit:\n  pseudonym:\n    enabled: true\n    key_ref: audit-pseudonym\n",
    );

    let served = serve(
        &[config.as_arg()],
        &[
            config.volume(),
            (
                "PIC_X_TEST_SECRET_AUDIT_PSEUDONYM",
                "0123456789abcdef0123456789abcdef",
            ),
        ],
    );

    assert!(served.succeeded, "{}", served.stderr);
    // The key reached the pseudonymiser and never reached the stream.
    assert!(
        !served.stdout.contains("0123456789abcdef"),
        "{}",
        served.stdout
    );
    assert!(served.stdout.contains(r#""event.name":"server.started""#));
}

#[test]
fn test_pseudonymisation_stays_off_unless_the_configuration_asks() {
    let config = ConfigFixture::new("pseudonym-default-off", SERVABLE_CONFIG);
    let served = serve(&[config.as_arg()], &[]);

    assert!(served.succeeded, "{}", served.stderr);
    assert!(served.stdout.contains(r#""audit.subject.kind":"system""#));
}

#[test]
fn test_a_signalled_server_says_why_it_stopped_and_stops_in_order() {
    let config = ConfigFixture::new("graceful", SERVABLE_CONFIG);
    let served = serve(&[config.as_arg(), "--log-level", "debug"], &[]);

    assert!(served.succeeded, "{}", served.stderr);

    let order: Vec<&str> = [
        "server.starting",
        "server.started",
        "server.signal",
        "server.stopping",
        "server.stopped",
    ]
    .into_iter()
    .filter(|event| {
        served
            .stdout
            .contains(&format!(r#""event.name":"{event}""#))
    })
    .collect();

    assert_eq!(
        order,
        vec![
            "server.starting",
            "server.started",
            "server.signal",
            "server.stopping",
            "server.stopped"
        ],
        "the lifecycle is incomplete: {}",
        served.stdout
    );
    // The signal that arrived is named, because "why did it go away" is the first question asked.
    assert!(served.stdout.contains(r#""signal":"SIGTERM""#));
}

#[test]
fn test_serve_is_not_a_command_name() {
    let config = ConfigFixture::new("not-a-command", SERVABLE_CONFIG);
    let output = run(&["serve", config.as_arg()]);

    assert!(!output.status.success());
    assert!(stdout_of(&output).is_empty());
    assert!(!stderr_of(&output).is_empty());
}

#[test]
fn test_flags_without_a_configuration_file_fail_with_usage() {
    let output = run(&["--grpc-addr", "127.0.0.1:5557"]);

    assert!(!output.status.success());
    assert!(stdout_of(&output).is_empty());
    assert!(stderr_of(&output).contains("Usage"));
}

#[test]
fn test_the_named_file_is_the_one_that_is_read() {
    let named = ConfigFixture::new("named", SERVABLE_CONFIG);
    let decoy = ConfigFixture::new("decoy", "web:\n  http: 127.0.0.1:0\n");

    // The decoy exists but is never named, so its contents cannot reach the run.
    let served = serve(&[named.as_arg()], &[]);
    assert!(served.succeeded, "{}", served.stderr);
    assert!(decoy.path().exists());

    let missing = run(&["/nonexistent/pic-x/config.yaml"]);
    assert!(!missing.status.success());
    assert!(stderr_of(&missing).contains("/nonexistent/pic-x/config.yaml"));
}

#[test]
fn test_no_config_flag_exists() {
    let config = ConfigFixture::new("no-config-flag", SERVABLE_CONFIG);
    let output = run(&["--config", config.as_arg()]);

    assert!(!output.status.success());
    assert!(stderr_of(&output).contains("--config"));
}

#[test]
fn test_command_line_flags_override_the_parsed_configuration_file() {
    let config = ConfigFixture::new("override-rejected", "grpc:\n  addr: 127.0.0.1:0\n");

    // The file alone declares no web address, so validation fails.
    let without = run(&[config.as_arg()]);
    assert!(!without.status.success());
    assert!(stderr_of(&without).contains("web listen address"));

    // The flag is applied after the file is parsed, which satisfies the same validation.
    let with = serve(&[config.as_arg(), "--web-http-addr", "127.0.0.1:0"], &[]);
    assert!(with.succeeded, "{}", with.stderr);
    assert!(with.stdout.contains(r#""event.name":"server.started""#));
}

#[test]
fn test_invalid_configuration_file_is_reported() {
    let unknown_key = ConfigFixture::new("unknown-key", "web:\n  http: 127.0.0.1:0\nnope: 1\n");
    let output = run(&[unknown_key.as_arg()]);

    assert!(!output.status.success());
    assert!(stderr_of(&output).contains(unknown_key.as_arg()));
}

#[test]
fn test_bare_invocation_shows_usage_and_starts_nothing() {
    let output = run(&[]);

    assert!(!output.status.success());
    assert!(!stderr_of(&output).is_empty());
    assert!(!stdout_of(&output).contains("server.started"));
}

#[test]
fn test_version_command_uses_the_short_banner_and_needs_no_configuration_file() {
    let output = run(&["version"]);
    assert!(output.status.success(), "{}", stderr_of(&output));

    let stdout = stdout_of(&output);
    assert!(stdout.starts_with("PIC-X (Provenance Identity Continuity Exchange)"));
    assert!(stdout.contains("Verifiable Authority Continuity"));
    assert!(!stdout.contains("____"));
    assert!(!stdout.contains(r#""event.name":"server.started""#));
    assert!(stdout.trim_end().ends_with(env!("CARGO_PKG_VERSION")));
}

#[test]
fn test_a_named_command_refuses_the_arguments_of_the_default_action() {
    let config = ConfigFixture::new("version-with-file", SERVABLE_CONFIG);
    let output = run(&["version", config.as_arg()]);

    assert!(!output.status.success());
    assert!(!stderr_of(&output).is_empty());
}

#[test]
fn test_every_banner_mode_resolves_its_metadata_placeholders() {
    let config = ConfigFixture::new("placeholders", SERVABLE_CONFIG);
    let served = serve(&[config.as_arg(), "--log-format", "terminal"], &[]).stdout;
    let reported = stdout_of(&run(&["version"]));

    for stdout in [served, reported] {
        for placeholder in ["<version>", "<copyright_year>", "<copyright_holder>"] {
            assert!(
                !stdout.contains(placeholder),
                "{placeholder} was left unresolved"
            );
        }
    }
}

#[test]
fn test_runtime_environment_overrides_build_banner_metadata() {
    let output = run_with_env(
        &["version"],
        &[
            ("PIC_X_VERSION", "9.8.7"),
            ("PIC_X_COPYRIGHT_YEAR", "2031"),
            ("PIC_X_COPYRIGHT_HOLDER", "Runtime Holder"),
        ],
    );
    assert!(output.status.success(), "{}", stderr_of(&output));

    let stdout = stdout_of(&output);
    assert!(stdout.contains("Version 9.8.7"));
    assert!(stdout.contains("© 2031 Runtime Holder."));
    assert!(stdout.trim_end().ends_with("9.8.7"));
}

#[test]
fn test_help_documents_the_default_action_its_flags_and_the_named_commands() {
    let output = run(&["--help"]);
    assert!(output.status.success());

    let stdout = stdout_of(&output);
    assert!(stdout.contains("CONFIG_FILE"));
    assert!(stdout.contains("version"));
    for flag in [
        "--web-http-addr",
        "--telemetry-addr",
        "--grpc-addr",
        "--log-level",
        "--log-format",
    ] {
        assert!(stdout.contains(flag), "help omits {flag}");
    }
    assert!(!stdout.contains("--config "));
    // One address for the public surface. Whether it is HTTP or HTTPS is `web.tls`, not a second
    // flag that used to be accepted and never bound anything.
    assert!(!stdout.contains("--web-https-addr"));
}

#[test]
fn test_unknown_command_fails_with_a_diagnostic_on_standard_error() {
    let output = run(&["unknown-command", "extra-argument"]);

    assert!(!output.status.success());
    assert!(!output.stderr.is_empty());
    assert!(stdout_of(&output).is_empty());
}

#[test]
fn test_generating_material_needs_the_deployment_to_say_it_is_a_development_one() {
    // Two switches rather than one, so a production configuration cannot become a self-signing one
    // by a single variable being set somewhere nobody is looking.
    let config = ConfigFixture::new("autogenerate-alone", "web:\n  http: 127.0.0.1:0\n");
    let output = run_with_env(
        &[config.as_arg()],
        &[config.volume(), ("PIC_X_AUTOGENERATE", "true")],
    );

    assert!(!output.status.success());
    let stderr = stderr_of(&output);
    assert!(stderr.contains("only offered in development"), "{stderr}");
    assert!(stderr.contains("development_mode"), "{stderr}");
}

#[test]
fn test_an_administrative_surface_the_world_can_reach_needs_a_client_certificate() {
    // The configuration that reads as fine and hands administration to anything that can route to
    // the port. It has to be a failure to start, because there is no later moment at which anybody
    // would notice.
    let config = ConfigFixture::new(
        "admin-exposed",
        "web:\n  http: 127.0.0.1:0\ngrpc:\n  addr: 0.0.0.0:7557\n",
    );
    let output = run_with_env(&[config.as_arg()], &[config.volume()]);

    assert!(!output.status.success());
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("reachable from outside this host"),
        "{stderr}"
    );
    assert!(stderr.contains("grpc.tls.client_ca"), "{stderr}");
}

#[test]
fn test_the_same_surface_on_loopback_starts() {
    let config = ConfigFixture::new(
        "admin-loopback",
        "web:\n  http: 127.0.0.1:0\ngrpc:\n  addr: 127.0.0.1:0\n",
    );

    let served = serve(&[config.as_arg()], &[config.volume()]);

    assert!(served.succeeded, "{}", served.stderr);
}

#[test]
fn test_a_trail_this_build_wrote_is_a_trail_this_build_can_check() {
    let config = ConfigFixture::new(
        "audit-verify",
        "web:\n  http: 127.0.0.1:0\ntelemetry:\n  addr: 127.0.0.1:0\naudit:\n  sink: file\n",
    );

    let served = serve(&[config.as_arg()], &[config.volume()]);
    assert!(served.succeeded, "{}", served.stderr);

    let (_, volume) = config.volume();
    let directory = format!("{volume}/audit");
    let output = run(&["audit", "verify", "--directory", &directory]);

    assert!(output.status.success(), "{}", stderr_of(&output));

    let said = String::from_utf8_lossy(&output.stdout);
    // The lifecycle alone produces records, so a run that served nothing still has a trail.
    assert!(said.contains("verify"), "{said}");
    assert!(said.contains("Head:"), "{said}");
}

#[test]
fn test_a_trail_somebody_edited_does_not_verify() {
    let config = ConfigFixture::new(
        "audit-tampered",
        "web:\n  http: 127.0.0.1:0\naudit:\n  sink: file\n",
    );

    let served = serve(&[config.as_arg()], &[config.volume()]);
    assert!(served.succeeded, "{}", served.stderr);

    let (_, volume) = config.volume();
    let directory = format!("{volume}/audit");
    let day = fs::read_dir(&directory)
        .expect("the trail is there")
        .flatten()
        .map(|entry| entry.path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "jsonl")
        })
        .expect("a day of records");

    let text = fs::read_to_string(&day).expect("the file reads");
    fs::write(&day, text.replace("server.start", "server.stort")).expect("the file is edited");

    let output = run(&["audit", "verify", "--directory", &directory]);

    assert!(!output.status.success(), "an edited trail verified");
    assert!(
        stderr_of(&output).contains("altered"),
        "{}",
        stderr_of(&output)
    );
}
