//! A key ring on the local filesystem.
//!
//! Ed25519 signing keys, one PEM file each, described by a `ring.json` beside them. It is the
//! deployment the user asked for — everything on disk, nothing external — and it is a real one: a
//! mounted volume with `0600` files is what a Kubernetes secret looks like from inside a container.
//!
//! # The lifecycle, and why it is not a swap
//!
//! See [`pic_x_core::keys`] for the shape. What this crate adds is the part that has to be right:
//!
//! * a key is created **published**, and signs nothing until `publish_ahead` has passed — long
//!   enough for every verifier holding a cached key set to have refetched it;
//! * the successor is created `publish_ahead` *before* the incumbent is due to stop, so the handover
//!   happens exactly at `rotate_every` rather than `publish_ahead` late;
//! * a key that stops signing stays **retired** and published for `retain`, because a signature made
//!   yesterday has to keep verifying tomorrow;
//! * the very first key of a fresh deployment signs immediately. Publishing ahead protects verifiers
//!   that already cached something, and a deployment starting for the first time has none — waiting
//!   an hour to serve its first request would be downtime bought for nobody.
//!
//! # What serving the key set touches
//!
//! Nothing private. The public half of every key is kept in `ring.json` when the key is created, so
//! answering the key-set endpoint reads one small file and never opens a private key at all.
//!
//! # One writer
//!
//! `ring.json` is written by replacing it, so a reader sees either the old file or the new one and
//! never half of either. Two *processes* maintaining the same directory is a different question, and
//! this does not answer it: they would both be right about what they did and could disagree about
//! what happened. A deployment that shares a volume between replicas should let one of them maintain
//! the ring, or use a key manager backed by something that arbitrates.

mod encoding;
mod service;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use pic_x_core::keys::Result;
use pic_x_core::{Jwk, KeyError, KeyId, KeyManager, KeyState, Maintenance, Signature};

pub use service::KeyService;

/// The curve every key on this ring is on.
const CURVE: &str = "Ed25519";

/// The algorithm a signature made by this ring names.
const ALGORITHM: &str = "EdDSA";

/// The PEM label PKCS#8 private keys are written under.
const PEM_LABEL: &str = "PRIVATE KEY";

/// The file that says which keys exist and where each of them is in its life.
const RING_FILE: &str = "ring.json";

/// How long each key spends in each state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyPolicy {
    /// How long a key is published before it signs.
    pub publish_ahead: Duration,
    /// How long a key signs before it is replaced.
    pub rotate_every: Duration,
    /// How long a key stays published after it stops signing.
    pub retain: Duration,
}

/// What time it is, so that a rotation can be tested without waiting for one.
///
/// A trait rather than a parameter because the manager consults the clock from several places, and
/// threading an instant through all of them would let a caller pass two different ones.
pub trait Clock: Send + Sync {
    /// Returns the number of seconds since the Unix epoch.
    fn now(&self) -> u64;
}

/// The clock a deployment uses.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs())
    }
}

/// One key, and where it is in its life.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Entry {
    kid: String,
    state: KeyState,
    /// The public half, kept here so that publishing the key set never opens a private key.
    public_key: String,
    created_at: u64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    activated_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    retired_at: Option<u64>,
}

impl Entry {
    /// Returns this key in the form a client fetches it.
    fn to_jwk(&self) -> Jwk {
        Jwk::okp(&self.kid, CURVE, ALGORITHM, &self.public_key)
    }
}

/// The state of the whole ring, as it is written to disk.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Ring {
    /// The format this file is in, so a later version can recognise an earlier one.
    #[serde(default = "one")]
    version: u32,
    #[serde(default)]
    keys: Vec<Entry>,
}

fn one() -> u32 {
    1
}

/// A key ring kept in a directory.
pub struct DirectoryKeyManager {
    directory: PathBuf,
    policy: KeyPolicy,
    clock: Box<dyn Clock>,
    /// Serialises maintenance, so two passes never both decide to publish a successor.
    maintaining: Mutex<()>,
    /// Parsed private keys, kept so signing does not re-read and re-parse a file per signature.
    signers: Mutex<BTreeMap<String, Arc<Ed25519KeyPair>>>,
}

impl DirectoryKeyManager {
    /// Builds a manager over the keys in `directory`.
    pub fn new(directory: impl Into<PathBuf>, policy: KeyPolicy) -> Self {
        Self::with_clock(directory, policy, Box::new(SystemClock))
    }

    /// Builds a manager that reads the time from somewhere other than the system.
    pub fn with_clock(
        directory: impl Into<PathBuf>,
        policy: KeyPolicy,
        clock: Box<dyn Clock>,
    ) -> Self {
        Self {
            directory: directory.into(),
            policy,
            clock,
            maintaining: Mutex::new(()),
            signers: Mutex::new(BTreeMap::new()),
        }
    }

    /// Returns the directory the ring lives in.
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Returns where the ring file is.
    fn ring_path(&self) -> PathBuf {
        self.directory.join(RING_FILE)
    }

    /// Returns where the private half of `kid` is.
    fn key_path(&self, kid: &str) -> PathBuf {
        self.directory.join(format!("{kid}.pem"))
    }

    /// Reads the ring, treating a directory with nothing in it as an empty one.
    fn read_ring(&self) -> Result<Ring> {
        match fs::read_to_string(self.ring_path()) {
            Ok(text) => serde_json::from_str(&text).map_err(|error| {
                KeyError::backend(format!(
                    "reading the key ring at {}: {error}",
                    self.ring_path().display()
                ))
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Ring::default()),
            Err(error) => Err(KeyError::unavailable(error)),
        }
    }

    /// Replaces the ring file, so a reader sees one whole version or the other.
    fn write_ring(&self, ring: &Ring) -> Result<()> {
        let text = serde_json::to_string_pretty(ring)
            .map_err(|error| KeyError::backend(format!("describing the key ring: {error}")))?;

        let path = self.ring_path();
        let staged = path.with_extension("json.tmp");

        fs::write(&staged, text.as_bytes())
            .map_err(|error| KeyError::backend(format!("writing {}: {error}", staged.display())))?;
        fs::rename(&staged, &path)
            .map_err(|error| KeyError::backend(format!("replacing {}: {error}", path.display())))?;

        Ok(())
    }

    /// Creates a key and writes its private half, returning the entry that describes it.
    fn create(&self, now: u64, signing: bool) -> Result<Entry> {
        fs::create_dir_all(&self.directory).map_err(|error| {
            KeyError::backend(format!("creating {}: {error}", self.directory.display()))
        })?;
        restrict(&self.directory, 0o700)?;

        let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|error| KeyError::backend(format!("generating a key: {error}")))?;
        let pkcs8 = Zeroizing::new(document.as_ref().to_vec());

        let pair = Ed25519KeyPair::from_pkcs8(&pkcs8)
            .map_err(|error| KeyError::backend(format!("reading back a generated key: {error}")))?;
        let public_key = encoding::base64url(pair.public_key().as_ref());
        let kid = thumbprint(&public_key);

        let path = self.key_path(&kid);
        fs::write(&path, encoding::pem(PEM_LABEL, &pkcs8).as_bytes())
            .map_err(|error| KeyError::backend(format!("writing {}: {error}", path.display())))?;
        restrict(&path, 0o600)?;

        Ok(Entry {
            kid,
            state: if signing {
                KeyState::Active
            } else {
                KeyState::Published
            },
            public_key,
            created_at: now,
            activated_at: signing.then_some(now),
            retired_at: None,
        })
    }

    /// Returns the parsed private key for `kid`, reading it the first time it is asked for.
    fn signer(&self, kid: &str) -> Result<Arc<Ed25519KeyPair>> {
        let mut signers = self
            .signers
            .lock()
            .map_err(|_| KeyError::backend("the key cache lock is poisoned"))?;

        if let Some(pair) = signers.get(kid) {
            return Ok(Arc::clone(pair));
        }

        let path = self.key_path(kid);
        let text = fs::read_to_string(&path).map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => KeyError::not_ready(format!(
                "the ring names the key `{kid}` but {} is not there",
                path.display()
            )),
            _ => KeyError::unavailable(error),
        })?;

        let pkcs8 = Zeroizing::new(encoding::from_pem(&text).ok_or_else(|| {
            KeyError::backend(format!("{} is not a PEM private key", path.display()))
        })?);

        let pair =
            Arc::new(Ed25519KeyPair::from_pkcs8(&pkcs8).map_err(|error| {
                KeyError::backend(format!("reading {}: {error}", path.display()))
            })?);

        signers.insert(kid.to_owned(), Arc::clone(&pair));

        Ok(pair)
    }

    /// Forgets a key entirely: the entry, the cached signer, and the file.
    fn forget(&self, kid: &str) -> Result<()> {
        if let Ok(mut signers) = self.signers.lock() {
            signers.remove(kid);
        }

        match fs::remove_file(self.key_path(kid)) {
            Ok(()) => Ok(()),
            // Already gone is the state that was wanted.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(KeyError::backend(format!(
                "removing the key `{kid}`: {error}"
            ))),
        }
    }
}

impl KeyManager for DirectoryKeyManager {
    fn name(&self) -> &'static str {
        "directory"
    }

    fn public_keys(&self) -> Result<Vec<Jwk>> {
        Ok(self.read_ring()?.keys.iter().map(Entry::to_jwk).collect())
    }

    fn active_key_id(&self) -> Result<KeyId> {
        self.read_ring()?
            .keys
            .into_iter()
            .find(|entry| entry.state == KeyState::Active)
            .map(|entry| KeyId::new(entry.kid))
            .ok_or_else(|| {
                KeyError::not_ready(format!(
                    "no key in {} is active yet",
                    self.directory.display()
                ))
            })
    }

    fn sign(&self, payload: &[u8]) -> Result<Signature> {
        let key_id = self.active_key_id()?;
        let signer = self.signer(key_id.as_str())?;

        Ok(Signature::new(
            key_id,
            ALGORITHM,
            signer.sign(payload).as_ref().to_vec(),
        ))
    }

    fn maintain(&self) -> Result<Maintenance> {
        let _serialised = self
            .maintaining
            .lock()
            .map_err(|_| KeyError::backend("the key maintenance lock is poisoned"))?;

        let now = self.clock.now();
        let mut ring = self.read_ring()?;
        let mut report = Maintenance::default();

        // A ring with nothing in it: the first key signs at once. See the crate documentation.
        if ring.keys.is_empty() {
            ring.keys.push(self.create(now, true)?);
            report.published += 1;
            report.activated += 1;
        }

        // Every published key whose window has passed takes over, oldest first. A loop rather than
        // one step because a process that was stopped for a week comes back with several due, and
        // waking up to a ring that needs three more passes to become correct is not a state worth
        // being able to reach.
        loop {
            let due = ring
                .keys
                .iter()
                .filter(|entry| entry.state == KeyState::Published)
                .filter(|entry| entry.created_at.saturating_add(self.seconds_ahead()) <= now)
                .min_by_key(|entry| entry.created_at)
                .map(|entry| entry.kid.clone());

            let Some(kid) = due else {
                break;
            };

            for entry in &mut ring.keys {
                if entry.state == KeyState::Active {
                    entry.state = KeyState::Retired;
                    entry.retired_at = Some(now);
                    report.retired += 1;
                }
            }

            if let Some(entry) = ring.keys.iter_mut().find(|entry| entry.kid == kid) {
                entry.state = KeyState::Active;
                entry.activated_at = Some(now);
                report.activated += 1;
            }
        }

        // The successor is created before the incumbent is due to stop, so the handover lands on
        // `rotate_every` rather than `publish_ahead` after it.
        let successor_due = ring
            .keys
            .iter()
            .find(|entry| entry.state == KeyState::Active)
            .and_then(|entry| entry.activated_at)
            .is_some_and(|activated| {
                activated
                    .saturating_add(self.seconds_rotating())
                    .saturating_sub(self.seconds_ahead())
                    <= now
            });
        let waiting = ring
            .keys
            .iter()
            .any(|entry| entry.state == KeyState::Published);

        if successor_due && !waiting {
            ring.keys.push(self.create(now, false)?);
            report.published += 1;
        }

        // A retired key stops being published once nothing it signed is still expected to verify.
        let expired: Vec<String> = ring
            .keys
            .iter()
            .filter(|entry| entry.state == KeyState::Retired)
            .filter(|entry| {
                entry
                    .retired_at
                    .is_some_and(|retired| retired.saturating_add(self.seconds_retained()) <= now)
            })
            .map(|entry| entry.kid.clone())
            .collect();

        for kid in &expired {
            self.forget(kid)?;
            report.forgotten += 1;
        }

        ring.keys.retain(|entry| !expired.contains(&entry.kid));

        if !report.is_empty() {
            self.write_ring(&ring)?;
        }

        Ok(report)
    }
}

impl DirectoryKeyManager {
    fn seconds_ahead(&self) -> u64 {
        self.policy.publish_ahead.as_secs()
    }

    fn seconds_rotating(&self) -> u64 {
        self.policy.rotate_every.as_secs()
    }

    fn seconds_retained(&self) -> u64 {
        self.policy.retain.as_secs()
    }
}

/// Returns the RFC 7638 thumbprint of an Ed25519 public key, which is what names it.
///
/// The name is derived from the key rather than assigned to it, so two deployments never disagree
/// about what a key is called and a client can check that the `kid` it was given belongs to the key
/// it was given.
fn thumbprint(public_key: &str) -> String {
    // RFC 7638 §3: the required members, no whitespace, lexicographic order. For an OKP key that is
    // exactly crv, kty, x.
    let canonical = format!(r#"{{"crv":"{CURVE}","kty":"OKP","x":"{public_key}"}}"#);
    let digest = ring::digest::digest(&ring::digest::SHA256, canonical.as_bytes());

    encoding::base64url(digest.as_ref())
}

/// Narrows permissions where the platform has them.
#[cfg(unix)]
fn restrict(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| KeyError::backend(format!("restricting {}: {error}", path.display())))
}

#[cfg(not(unix))]
fn restrict(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn test_the_name_of_a_key_is_derived_from_the_key() {
        // RFC 7638 leaves nothing to choose, so the same public key must always get the same name.
        let first = thumbprint("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");
        let second = thumbprint("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");

        assert_eq!(first, second);
        assert_ne!(first, thumbprint("AAAA"));
        // base64url of a SHA-256, unpadded.
        assert_eq!(first.len(), 43);
    }

    #[test]
    fn test_a_ring_reads_back_as_what_was_written() {
        let ring = Ring {
            version: 1,
            keys: vec![Entry {
                kid: "k1".to_owned(),
                state: KeyState::Active,
                public_key: "AAAA".to_owned(),
                created_at: 10,
                activated_at: Some(20),
                retired_at: None,
            }],
        };

        let text = serde_json::to_string(&ring).expect("it serialises");
        let read: Ring = serde_json::from_str(&text).expect("it reads back");

        assert_eq!(read, ring);
        // A key that has not retired must not carry a null saying so: the file is read by later
        // versions of this code, and an absent field is the one thing every version agrees on.
        assert!(!text.contains("retired_at"));
    }
}
