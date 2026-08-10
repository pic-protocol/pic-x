//! Restoring the volume from a copy of it, against the real binary.
//!
//! A backup nobody has restored is not a backup, and a seal nobody has checked after a restore is
//! decoration. This performs the whole cycle every time the suite runs: a server writes and seals a
//! trail, the volume is copied, the original is destroyed, the copy is put back, and what came back
//! is verified — against a key set exported *before* the loss, which is the only kind worth checking
//! a signature against.
//!
//! The procedure it exercises is written down in `docs/backup-and-restore.md`. That is the point of
//! it being a test: a documented procedure nobody runs stops being true quietly.

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// How long a silence has to last before a server counts as up and waiting.
const LULL: Duration = Duration::from_secs(5);

/// Returns the repository root, which is where the configuration files live.
fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// A directory nothing else is using.
fn scratch(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("pic-x-restore-{name}"));
    let _ = fs::remove_dir_all(&path);

    path
}

/// A server that is up, and what is needed to talk to it and stop it.
struct Running {
    child: Child,
    lines: mpsc::Receiver<String>,
}

impl Running {
    /// Asks it to stop and waits, which is when the trail is sealed.
    ///
    /// Waiting matters: the seal is written during shutdown, so a test that killed the process and
    /// carried on would be backing up a volume the server had not finished writing.
    fn stop(mut self) -> bool {
        let _ = Command::new("kill")
            .arg("-TERM")
            .arg(self.child.id().to_string())
            .status();

        while self.lines.recv().is_ok() {}

        self.child
            .wait()
            .map(|status| status.success())
            .unwrap_or_default()
    }
}

/// Starts the binary against `config` with `volume` as its working directory, and waits for it.
fn serve(config: &str, volume: &Path) -> Running {
    let mut child = Command::new(env!("CARGO_BIN_EXE_pic-x"))
        .arg(root().join(config))
        .env("PIC_X_WORKING_DIR", volume)
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

    let mut listening = false;
    loop {
        match lines.recv_timeout(LULL) {
            Ok(line) => {
                if line.contains("wellknown.listening") {
                    listening = true;
                }

                if line.contains("server.started") {
                    break;
                }
            }
            Err(_) => panic!("the server never reported itself started"),
        }
    }

    assert!(listening, "the public surface never came up");

    Running { child, lines }
}

/// Exports an operations ring's public keys as a JWKS document, via the binary.
///
/// The operations ring is never served over HTTP, so the key set is read from the ring on disk — the
/// server stopped — exactly as the backup runbook has an operator do it.
fn export_keys(ring: &Path) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_pic-x"))
        .args(["keys", "export", "--directory"])
        .arg(ring)
        .output()
        .expect("running the key exporter");

    assert!(
        output.status.success(),
        "exporting the key ring failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Copies a directory tree, the way `cp -a` does.
fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("the destination is created");

    for entry in fs::read_dir(from).expect("the source is readable") {
        let entry = entry.expect("the entry is readable");
        let target = to.join(entry.file_name());

        if entry.file_type().expect("the kind is readable").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).expect("the file is copied");
        }
    }
}

/// Runs `pic-x audit verify` and returns what it said, and whether it was happy.
fn verify(audit: &Path, keys: Option<&Path>) -> (bool, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_pic-x"));
    command.args(["audit", "verify", "--directory"]).arg(audit);

    if let Some(keys) = keys {
        command.arg("--keys").arg(keys);
    }

    let output = command.output().expect("running the verifier");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    (output.status.success(), said)
}

#[test]
fn test_a_volume_can_be_lost_entirely_and_put_back() {
    let volume = scratch("volume");
    let backup = scratch("backup");

    // 1. A deployment that ran: it generated its key ring, wrote an audit trail, and sealed it when
    //    it stopped.
    let server = serve("config.local.yaml", &volume);
    assert!(server.stop(), "the server did not shut down cleanly");

    // The key set, exported before the loss — read from the operations ring on disk, because that
    // ring is never served over HTTP. This is the part a restore cannot recreate: taking it from the
    // restored machine afterwards would mean checking a signature against a key whoever tampered with
    // the machine could have replaced.
    let published = export_keys(&volume.join("operations/keys"));
    assert!(
        published.contains("\"kid\""),
        "the deployment sealed with no key to check its seals against: {published}"
    );
    let exported = backup.with_extension("jwks.json");
    fs::create_dir_all(backup.parent().unwrap_or(&backup))
        .expect("the backup directory is created");
    fs::write(&exported, &published).expect("the key set is exported");

    assert!(
        volume.join("operations/audit").read_dir().is_ok(),
        "no trail was written to back up"
    );

    // 2. The backup.
    copy_tree(&volume, &backup);

    // 3. The loss. Not a corruption, not a partial delete — the volume is gone.
    fs::remove_dir_all(&volume).expect("the volume is destroyed");
    assert!(!volume.exists());

    // 4. The restore.
    copy_tree(&backup, &volume);

    // 5. What came back verifies, and its seals check against the key set exported beforehand. This
    //    is the assertion the whole procedure exists for: an intact chain proves nothing was edited
    //    within the trail, and a seal that still checks proves the trail is the one that deployment
    //    actually wrote.
    let (verified, said) = verify(&volume.join("operations/audit"), Some(&exported));
    assert!(verified, "the restored trail does not verify: {said}");
    assert!(
        said.contains("verify"),
        "the verifier said something unexpected: {said}"
    );
    assert!(
        !said.contains("unchecked"),
        "the seals were not actually checked against the exported key set: {said}"
    );

    // 6. And it is a working deployment, not just readable files: the server starts again on it and
    //    continues the same trail rather than beginning a new one.
    let again = serve("config.local.yaml", &volume);
    assert!(
        again.stop(),
        "the server did not start on the restored volume"
    );

    let (still, said) = verify(&volume.join("operations/audit"), Some(&exported));
    assert!(
        still,
        "appending to a restored trail broke it, which makes the restore single-use: {said}"
    );

    let _ = fs::remove_dir_all(&volume);
    let _ = fs::remove_dir_all(&backup);
    let _ = fs::remove_file(&exported);
}

#[test]
fn test_a_trail_restored_without_its_key_set_is_reported_as_unchecked() {
    // The failure this distinguishes: a restore that looks fine because nobody passed the keys. The
    // chain verifying says the trail was not edited *within itself*; only the seal says it is the
    // trail that deployment wrote. The verifier must not let the two be confused.
    let volume = scratch("unchecked");

    let server = serve("config.local.yaml", &volume);
    assert!(server.stop(), "the server did not shut down cleanly");

    let (verified, said) = verify(&volume.join("operations/audit"), None);

    assert!(verified, "the trail does not verify: {said}");
    assert!(
        said.contains("unchecked"),
        "a verification with no key set did not say the signatures went unchecked: {said}"
    );

    let _ = fs::remove_dir_all(&volume);
}
