//! Two realms, one server, against the real binary.
//!
//! The whole multi-tenant claim in one run: a deployment hosts two issuers; each serves its own
//! discovery at its own path; the server lists the one that opted in and hides the one that did not;
//! and a single process — one maintenance loop, no task per realm — seals each realm's trail with a
//! *different* key. Those sealing keys are the realms' operations keys, which are internal and never
//! served over HTTP, so the "different key" claim is checked on disk; the HTTP key set is the realm's
//! token ring, now enabled and populated, and the token endpoint answers a POST. If any of that
//! regresses, this fails.

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

/// Sends an empty POST to one path and returns `(status_line, body)`.
fn post(address: &str, path: &str) -> (String, String) {
    let mut stream = TcpStream::connect(address).expect("the surface accepts a connection");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("the read timeout is set");
    write!(
        stream,
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
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
             operations:\n  \
             secrets:\n    provider: directory\n  \
             audit:\n    sink: file\n    retention: 7d\n    \
             pseudonym:\n      enabled: true\n      key_ref: audit-pseudonym\n      key_version: \"v1\"\n  \
             keys:\n    enabled: true\n    publish_ahead: 1m\n    rotate_every: 10m\n    retain: 1h\n\
             realms:\n  \
             - name: acme\n    issuer: https://acme.example.com\n    listed: true\n  \
             - name: beta\n    listed: false\n",
            volume.display()
        ),
    )
    .expect("the configuration is written");

    path
}

/// Returns the `kid`s a JWKS document — or a `ring.json` — names.
fn kids(body: &str) -> Vec<String> {
    // A hand parse rather than a JSON dependency: the field is unambiguous and the test is about
    // whether two documents differ, not about the shape of a key. It reads a served key set and an
    // on-disk ring the same way — the served set is compact (`"kid":"…"`) and the ring is
    // pretty-printed (`"kid": "…"`), so it skips to the value's opening quote rather than assuming one.
    body.match_indices(r#""kid""#)
        .filter_map(|(at, marker)| {
            let rest = &body[at + marker.len()..];
            let open = rest.find('"')?;
            let value = &rest[open + 1..];
            value.find('"').map(|end| value[..end].to_owned())
        })
        .collect()
}

/// Reads a file to a string, or empty when it is not there.
fn read(path: &std::path::Path) -> String {
    fs::read_to_string(path).unwrap_or_default()
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

    // Over HTTP, a realm's key set is its *token* ring, published at `/keys` now that token keys are
    // enabled — so it is populated. The server publishes none of its own. The sealing keys are checked
    // on disk below.
    let (server_keys_status, _) = get(&server.web, "/.well-known/jwks.json");
    assert!(
        server_keys_status.contains("404"),
        "the server should publish no key set of its own: {server_keys_status}"
    );
    let (acme_keys_status, acme_token_keys) = get(&server.web, "/realms/acme/keys");
    assert!(acme_keys_status.contains("200"), "{acme_keys_status}");
    assert!(
        !kids(&acme_token_keys).is_empty(),
        "the realm publishes no token keys: {acme_token_keys}"
    );
    // The token endpoint answers a POST — with 501, since issuance is not built — rather than 404.
    let (token_status, token_body) = post(&server.web, "/realms/acme/token");
    assert!(
        token_status.contains("501"),
        "the token endpoint should answer a POST: {token_status}"
    );
    assert!(
        token_body.contains("not_implemented"),
        "the 501 should say why: {token_body}"
    );
    // The old realm key path is gone; the key set moved to `{issuer}/keys`.
    let (old_path_status, _) = get(&server.web, "/realms/acme/.well-known/jwks.json");
    assert!(
        old_path_status.contains("404"),
        "the realm key set should have moved off the well-known path: {old_path_status}"
    );

    server.stop();

    // The heart of it, checked on disk since operations keys never leave it: one process, one
    // maintenance loop, and yet the server and each realm seal with a *different* key. If the rings
    // were shared, or the loop only maintained one, these would match.
    let vol = volume.join("vol");
    let server_kids = kids(&read(&vol.join("operations/keys/ring.json")));
    let acme_kids = kids(&read(&vol.join("realms/acme/operations/keys/ring.json")));
    let beta_kids = kids(&read(&vol.join("realms/beta/operations/keys/ring.json")));

    assert!(!server_kids.is_empty(), "the server sealed with no key");
    assert!(!acme_kids.is_empty(), "acme sealed with no key");
    assert!(!beta_kids.is_empty(), "beta sealed with no key");
    assert_ne!(
        server_kids, acme_kids,
        "the server and acme share a signing key"
    );
    assert_ne!(acme_kids, beta_kids, "two realms share a signing key");

    // A realm's token ring is a *second*, distinct ring beside its operations ring — its own keys at
    // `realms/<name>/keys`, different from the ones that seal its trail.
    let acme_token_kids = kids(&read(&vol.join("realms/acme/keys/ring.json")));
    assert!(
        !acme_token_kids.is_empty(),
        "acme has no token ring of its own"
    );
    assert_ne!(
        acme_token_kids, acme_kids,
        "acme's token ring and operations ring share a key"
    );

    // Each realm left its material behind, in its own directory — isolation on disk.
    for realm in ["acme", "beta"] {
        assert!(
            vol.join(format!("realms/{realm}/operations/secrets/audit-pseudonym"))
                .exists(),
            "{realm} has no pseudonymisation key of its own"
        );
    }

    let _ = fs::remove_dir_all(&volume);
}
