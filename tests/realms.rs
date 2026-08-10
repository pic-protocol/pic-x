//! Two realms, one server, against the real binary.
//!
//! The whole multi-tenant claim in one run: a deployment hosts two issuers; each publishes its own
//! discovery and its own key set at its own path; the server lists the one that opted in and hides
//! the one that did not; and a single process — one maintenance loop, no task per realm — gives each
//! realm a *different* signing key. If any of that regresses, this fails.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// How long to wait for the server to say it is up.
const READY: Duration = Duration::from_secs(20);

fn scratch(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("pic-x-realms-{name}"));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("the scratch directory is created");

    path
}

/// A running server, and the web address it bound.
struct Running {
    child: Child,
    web: String,
    lines: mpsc::Receiver<String>,
}

impl Running {
    fn stop(mut self) {
        let _ = Command::new("kill")
            .arg("-TERM")
            .arg(self.child.id().to_string())
            .status();
        while self.lines.recv().is_ok() {}
        let _ = self.child.wait();
    }
}

/// Starts the binary against `config`, and waits until it reports itself started.
fn serve(config: &std::path::Path) -> Running {
    let mut child = Command::new(env!("CARGO_BIN_EXE_pic-x"))
        .arg(config)
        .args(["--web-http-addr", "127.0.0.1:0"])
        .args(["--telemetry-addr", "127.0.0.1:0"])
        .args(["--grpc-addr", "127.0.0.1:0"])
        .args(["--log-format", "json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("starting the pic-x binary");

    let out = child.stdout.take().expect("standard output is piped");
    let (sender, lines) = mpsc::channel();
    thread::spawn(move || {
        let mut reader = BufReader::new(out);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if sender.send(line).is_err() {
                        break;
                    }
                }
            }
        }
    });

    let mut web = String::new();
    loop {
        match lines.recv_timeout(READY) {
            Ok(line) => {
                if line.contains("wellknown.listening") {
                    web = address_in(&line);
                }
                if line.contains("server.started") {
                    break;
                }
            }
            Err(_) => panic!("the server never reported itself started"),
        }
    }
    assert!(!web.is_empty(), "the public surface reported no address");

    Running { child, web, lines }
}

/// Reads the `address` field out of a JSON log line.
fn address_in(line: &str) -> String {
    let marker = r#""address":""#;
    let Some(start) = line.find(marker) else {
        return String::new();
    };
    let rest = &line[start + marker.len()..];

    rest.find('"')
        .map(|end| rest[..end].to_owned())
        .unwrap_or_default()
}

/// Fetches one path over plain HTTP and returns `(status_line, body)`.
fn get(address: &str, path: &str) -> (String, String) {
    let mut stream = TcpStream::connect(address).expect("the surface accepts a connection");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("the read timeout is set");
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .expect("the request is sent");

    let mut answer = String::new();
    stream
        .read_to_string(&mut answer)
        .expect("the answer is readable");

    let (head, body) = answer.split_once("\r\n\r\n").unwrap_or((&answer, ""));
    let status = head.lines().next().unwrap_or_default().to_owned();

    (status, body.to_owned())
}

/// Writes a two-realm development configuration into `volume`.
fn config_in(volume: &std::path::Path) -> PathBuf {
    let path = volume.join("config.yaml");
    fs::write(
        &path,
        format!(
            "development_mode: true\n\
             autogenerate: true\n\
             working_dir: {}/vol\n\
             log:\n  level: info\n  format: json\n\
             web:\n  http: 127.0.0.1:0\n\
             secrets:\n  provider: directory\n\
             audit:\n  sink: file\n  retention: 7d\n  \
             pseudonym:\n    enabled: true\n    key_ref: audit-pseudonym\n    key_version: \"v1\"\n\
             keys:\n  enabled: true\n  publish_ahead: 1m\n  rotate_every: 10m\n  retain: 1h\n\
             realms:\n  \
             - name: acme\n    issuer: https://acme.example.com\n    listed: true\n  \
             - name: beta\n    listed: false\n",
            volume.display()
        ),
    )
    .expect("the configuration is written");

    path
}

/// Returns the `kid`s a JWKS document publishes.
fn kids(body: &str) -> Vec<String> {
    // A hand parse rather than a JSON dependency: the field is unambiguous and the test is about
    // whether two documents differ, not about the shape of a key.
    body.match_indices(r#""kid":""#)
        .map(|(at, marker)| {
            let rest = &body[at + marker.len()..];
            rest.find('"')
                .map(|end| rest[..end].to_owned())
                .unwrap_or_default()
        })
        .collect()
}

#[test]
fn test_two_realms_each_get_their_own_issuer_surface_and_key() {
    let volume = scratch("two");
    let config = config_in(&volume);
    let server = serve(&config);

    // The server catalogue lists the realm that opted in, and not the one that did not.
    let (status, catalogue) = get(&server.web, "/.well-known/server-configuration");
    assert!(status.contains("200"), "{status}");
    assert!(
        catalogue.contains("acme"),
        "the catalogue omits the listed realm: {catalogue}"
    );
    assert!(
        !catalogue.contains("beta"),
        "the catalogue enumerates a realm that opted out: {catalogue}"
    );
    assert!(
        catalogue.contains("https://pic-protocol.org/profiles/0.2"),
        "the catalogue names no profile: {catalogue}"
    );

    // Each realm serves its own issuer discovery at its own path — including the unlisted one, which
    // a client that knows its name must still be able to verify tokens against.
    let (acme_status, acme) = get(&server.web, "/realms/acme/.well-known/pic-x-configuration");
    assert!(acme_status.contains("200"), "{acme_status}");
    assert!(acme.contains("https://acme.example.com"), "{acme}");

    let (beta_status, _) = get(&server.web, "/realms/beta/.well-known/pic-x-configuration");
    assert!(
        beta_status.contains("200"),
        "the unlisted realm is unreachable: {beta_status}"
    );

    // The heart of it: one process, one maintenance loop, and yet the server and each realm sign with
    // a *different* key. If the rings were shared, or the loop only maintained one, these would match.
    let (_, server_keys) = get(&server.web, "/.well-known/jwks.json");
    let (_, acme_keys) = get(&server.web, "/realms/acme/.well-known/jwks.json");
    let (_, beta_keys) = get(&server.web, "/realms/beta/.well-known/jwks.json");

    let server_kids = kids(&server_keys);
    let acme_kids = kids(&acme_keys);
    let beta_kids = kids(&beta_keys);

    assert_eq!(
        server_kids.len(),
        1,
        "the server published no key: {server_keys}"
    );
    assert_eq!(acme_kids.len(), 1, "acme published no key: {acme_keys}");
    assert_eq!(beta_kids.len(), 1, "beta published no key: {beta_keys}");

    assert_ne!(
        server_kids, acme_kids,
        "the server and acme share a signing key"
    );
    assert_ne!(acme_kids, beta_kids, "two realms share a signing key");

    server.stop();

    // The realms left their material behind, each in its own directory — isolation on disk.
    let vol = volume.join("vol");
    for realm in ["acme", "beta"] {
        assert!(
            vol.join(format!("realms/{realm}/keys/ring.json")).exists(),
            "{realm} has no key ring of its own"
        );
        assert!(
            vol.join(format!("realms/{realm}/secrets/audit-pseudonym"))
                .exists(),
            "{realm} has no pseudonymisation key of its own"
        );
    }

    let _ = fs::remove_dir_all(&volume);
}
