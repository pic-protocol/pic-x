//! An audit trail that survives the process, and notices when somebody edits it.
//!
//! One JSON object per line, one file per UTC day, appended and flushed to the disk before the write
//! is reported as done.
//!
//! # The chain
//!
//! Every record carries the digest of the record before it. That makes the file a hash chain: change
//! a field, remove a line, reorder two entries, and every digest from that point on stops matching.
//!
//! This is tamper **evidence**, not tamper prevention, and the difference is worth being precise
//! about. Anyone who can write the file can also rewrite the whole chain from the point they changed
//! — the records are hashed, not signed, so nothing here stops an attacker with write access and
//! patience. What it stops is the much more common thing: a line quietly deleted, a value edited in
//! place, a file truncated. And because the chain is continuous across days, a whole day's file
//! going missing is detectable too.
//!
//! Making it survive an attacker with write access needs the head of the chain to leave the machine
//! — signed with a key they do not have, or written somewhere append-only. The chain is what makes
//! that possible later: a single digest is enough to attest to everything before it.
//!
//! # Why it flushes every record
//!
//! An audit trail that loses its last few records to a crash loses exactly the records that were
//! being written when whatever went wrong went wrong. Buffering would make this faster at the cost
//! of the entries most likely to matter.
//!
//! # Blocking
//!
//! The writes are synchronous, inside an async method. They are small, they are rare — a service
//! starting, a service stopping, an administrative call — and ordering them is the whole point, so
//! they are not worth moving off the runtime thread for. A deployment that audits per data-plane
//! request should implement the contract over something that batches.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use pic_x_core::{AuditError, AuditEvent, AuditSink, BoxFuture, Pseudonymizer};

use crate::civil::{self, Date};

/// What this sink answers with.
type Result<T> = std::result::Result<T, AuditError>;

/// What a file of records is called, either side of the date.
const PREFIX: &str = "audit-";
const SUFFIX: &str = ".jsonl";

/// The digest the first record of a trail names as its predecessor.
///
/// Sixty-four zeroes rather than an absent field, so every record has the same shape and the
/// verifier has one case instead of two.
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Everything a record says, and the only thing the digest covers.
///
/// Nested inside the line rather than flattened beside the digest, because verification re-serialises
/// exactly this and compares — and a scheme where the hashed bytes have to be reconstructed by
/// removing a field from the middle of an object is a scheme that eventually disagrees with itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Body {
    /// Where this record sits in the trail, from 1 and never reused.
    pub seq: u64,
    /// When it happened, RFC 3339 in UTC.
    pub at: String,
    /// The digest of the record before this one, across day boundaries.
    pub prev: String,
    /// What happened.
    pub action: String,
    /// Who it was about, already rendered under the privacy policy in force.
    pub subject: String,
    /// What kind of thing the subject is, which survives even when the subject is masked.
    pub subject_kind: String,
    /// How sensitive that made it.
    pub subject_sensitivity: String,
    /// What it was done to, when the event named something.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub target: Option<String>,
    /// Which build recorded it.
    pub service: String,
    /// Which version of it.
    pub version: String,
}

/// One line of the trail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// The record itself.
    pub body: Body,
    /// The digest of `body`, which the next record names as its `prev`.
    pub digest: String,
}

impl Record {
    /// Returns the digest `body` should have.
    fn expected_digest(body: &Body) -> Result<String> {
        let canonical = serde_json::to_vec(body)
            .map_err(|error| AuditError::backend(format!("describing a record: {error}")))?;

        Ok(hex(Sha256::digest(&canonical).as_slice()))
    }
}

/// The file currently being appended to.
struct Open {
    day: i64,
    file: File,
    seq: u64,
    previous: String,
}

/// An audit trail on the local filesystem.
pub struct FileAuditSink {
    directory: PathBuf,
    service_name: String,
    service_version: String,
    retention: Duration,
    open: Mutex<Option<Open>>,
}

impl FileAuditSink {
    /// Builds a sink that writes to `directory`, keeping each day for `retention`.
    pub fn new(
        directory: impl Into<PathBuf>,
        service_name: impl Into<String>,
        service_version: impl Into<String>,
        retention: Duration,
    ) -> Self {
        Self {
            directory: directory.into(),
            service_name: service_name.into(),
            service_version: service_version.into(),
            retention,
            open: Mutex::new(None),
        }
    }

    /// Returns the directory the trail lives in.
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Prepares the directory and drops whatever is past its retention.
    ///
    /// Called once before the server starts, so a trail that cannot be written is a failure to start
    /// rather than a failure to record, discovered later by whoever needed the record.
    pub fn prepare(&self) -> Result<()> {
        fs::create_dir_all(&self.directory).map_err(|error| {
            AuditError::backend(format!("creating {}: {error}", self.directory.display()))
        })?;

        restrict(&self.directory, 0o700)?;
        self.expire(civil::day_of(now()))?;

        Ok(())
    }

    /// Removes every day of records older than the retention allows.
    fn expire(&self, today: i64) -> Result<usize> {
        let days = (self.retention.as_secs() / 86_400) as i64;
        let oldest_kept = today - days;
        let mut removed = 0;

        let entries = match fs::read_dir(&self.directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(AuditError::unavailable(error)),
        };

        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(day) = day_of_file(&name.to_string_lossy()) else {
                continue;
            };

            if day >= oldest_kept {
                continue;
            }

            fs::remove_file(entry.path()).map_err(|error| {
                AuditError::backend(format!("removing {}: {error}", entry.path().display()))
            })?;
            removed += 1;

            tracing::info!(
                event.name = "audit.expired",
                component = "audit",
                path = %entry.path().display(),
                "removed a day of records that is past its retention"
            );
        }

        Ok(removed)
    }

    /// Returns the file for `day`, opening or rolling over as needed.
    fn open_for(&self, open: &mut Option<Open>, day: i64) -> Result<()> {
        if open.as_ref().is_some_and(|current| current.day == day) {
            return Ok(());
        }

        // Where the chain continues from: the last record of whatever was being written, or — on a
        // cold start — the last record of the most recent day on disk.
        let tail = match open.as_ref() {
            Some(current) => Some((current.seq, current.previous.clone())),
            None => self.tail()?,
        };

        let path = self.path_for(day);
        fs::create_dir_all(&self.directory).map_err(|error| {
            AuditError::backend(format!("creating {}: {error}", self.directory.display()))
        })?;

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|error| AuditError::backend(format!("opening {}: {error}", path.display())))?;
        restrict(&path, 0o600)?;

        let (seq, previous) = tail.unwrap_or((0, GENESIS.to_owned()));

        *open = Some(Open {
            day,
            file,
            seq,
            previous,
        });

        Ok(())
    }

    /// Returns where the chain left off: the sequence and digest of the last record written.
    fn tail(&self) -> Result<Option<(u64, String)>> {
        let Some(latest) = self.days()?.pop() else {
            return Ok(None);
        };

        let file = File::open(self.path_for(latest)).map_err(AuditError::unavailable)?;

        // A whole day is read to find its last line. The file is small — an audit trail records
        // decisions, not traffic — and this happens once, when the process starts.
        let last = BufReader::new(file)
            .lines()
            .map_while(std::result::Result::ok)
            .filter(|line| !line.trim().is_empty())
            .last();

        let Some(last) = last else {
            return Ok(None);
        };

        let record: Record = serde_json::from_str(&last).map_err(|error| {
            AuditError::backend(format!("reading the last record of the trail: {error}"))
        })?;

        Ok(Some((record.body.seq, record.digest)))
    }

    /// Returns every day the directory holds records for, oldest first.
    fn days(&self) -> Result<Vec<i64>> {
        let entries = match fs::read_dir(&self.directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(AuditError::unavailable(error)),
        };

        let mut days: Vec<i64> = entries
            .flatten()
            .filter_map(|entry| day_of_file(&entry.file_name().to_string_lossy()))
            .collect();

        days.sort_unstable();

        Ok(days)
    }

    fn path_for(&self, day: i64) -> PathBuf {
        self.directory
            .join(format!("{PREFIX}{}{SUFFIX}", civil::date_of(day).to_iso()))
    }
}

impl AuditSink for FileAuditSink {
    fn name(&self) -> &'static str {
        "file"
    }

    fn record<'a>(
        &'a self,
        event: &'a AuditEvent<'a>,
        policy: Option<&'a dyn Pseudonymizer>,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let seconds = now();
            let day = civil::day_of(seconds);

            let mut open = self
                .open
                .lock()
                .map_err(|_| AuditError::backend("the audit file lock is poisoned"))?;

            let rolled = !open.as_ref().is_some_and(|current| current.day == day);
            self.open_for(&mut open, day)?;

            // A new day is the natural moment to drop the oldest one: it happens once, it happens
            // while something is already being written, and it needs no timer of its own.
            if rolled {
                self.expire(day)?;
            }

            let current = open
                .as_mut()
                .ok_or_else(|| AuditError::backend("the audit file was not opened"))?;

            let body = Body {
                seq: current.seq + 1,
                at: civil::to_rfc3339(seconds),
                prev: current.previous.clone(),
                action: event.action().to_owned(),
                subject: event.subject().render(policy),
                subject_kind: event.subject().kind().to_owned(),
                subject_sensitivity: event.subject().sensitivity().as_str().to_owned(),
                target: event.target().map(ToOwned::to_owned),
                service: self.service_name.clone(),
                version: self.service_version.clone(),
            };

            let digest = Record::expected_digest(&body)?;
            let line = serde_json::to_string(&Record {
                body,
                digest: digest.clone(),
            })
            .map_err(|error| AuditError::backend(format!("describing a record: {error}")))?;

            writeln!(current.file, "{line}")
                .map_err(|error| AuditError::backend(format!("appending a record: {error}")))?;
            current
                .file
                .sync_data()
                .map_err(|error| AuditError::backend(format!("flushing a record: {error}")))?;

            current.seq += 1;
            current.previous = digest;

            Ok(())
        })
    }

    fn shutdown(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            let mut open = self
                .open
                .lock()
                .map_err(|_| AuditError::backend("the audit file lock is poisoned"))?;

            if let Some(current) = open.as_mut() {
                current
                    .file
                    .sync_all()
                    .map_err(|error| AuditError::backend(format!("closing the trail: {error}")))?;
            }

            *open = None;

            Ok(())
        })
    }
}

/// What checking a trail found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    /// How many records were read.
    pub records: u64,
    /// How many days of records were read.
    pub days: usize,
    /// The digest of the last record, which is what attests to everything before it.
    pub head: String,
}

/// Reads a whole trail and checks that nothing in it has been altered.
///
/// Checks three things, and they catch different edits: every digest matches the record it covers
/// (a field was changed), every record names the previous digest (a record was replaced), and the
/// sequence increases by exactly one across the whole trail including day boundaries (a record, or a
/// whole day, was removed).
pub fn verify(directory: &Path) -> anyhow::Result<Verification> {
    use anyhow::{Context, bail};

    let mut days: Vec<i64> = fs::read_dir(directory)
        .with_context(|| format!("reading {}", directory.display()))?
        .flatten()
        .filter_map(|entry| day_of_file(&entry.file_name().to_string_lossy()))
        .collect();
    days.sort_unstable();

    let mut expected_previous = GENESIS.to_owned();
    let mut expected_seq = 1_u64;
    let mut records = 0_u64;

    for day in &days {
        let path = directory.join(format!("{PREFIX}{}{SUFFIX}", civil::date_of(*day).to_iso()));
        let file = File::open(&path).with_context(|| format!("opening {}", path.display()))?;

        for (index, line) in BufReader::new(file).lines().enumerate() {
            let line = line.with_context(|| format!("reading {}", path.display()))?;

            if line.trim().is_empty() {
                continue;
            }

            let where_ = format!("{}:{}", path.display(), index + 1);
            let record: Record =
                serde_json::from_str(&line).with_context(|| format!("parsing {where_}"))?;

            let digest = Record::expected_digest(&record.body)
                .map_err(|error| anyhow::anyhow!("{error}"))?;

            if digest != record.digest {
                bail!("{where_} has been altered: it does not match its own digest");
            }

            if record.body.prev != expected_previous {
                bail!(
                    "{where_} does not follow the record before it: the chain is broken, which \
                     means something between them was changed or removed"
                );
            }

            if record.body.seq != expected_seq {
                bail!(
                    "{where_} is numbered {} where {expected_seq} was expected: {} record(s) are \
                     missing",
                    record.body.seq,
                    record.body.seq.saturating_sub(expected_seq)
                );
            }

            expected_previous = record.digest;
            expected_seq += 1;
            records += 1;
        }
    }

    Ok(Verification {
        records,
        days: days.len(),
        head: expected_previous,
    })
}

/// Returns which day a file holds records for, or nothing when it is not one of ours.
fn day_of_file(name: &str) -> Option<i64> {
    let date = name.strip_prefix(PREFIX)?.strip_suffix(SUFFIX)?;

    Date::from_iso(date).map(civil::days_of)
}

/// Returns the current time in seconds since the Unix epoch.
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs() as i64)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;

    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");

        out
    })
}

/// Narrows permissions where the platform has them.
#[cfg(unix)]
fn restrict(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| AuditError::backend(format!("restricting {}: {error}", path.display())))
}

#[cfg(not(unix))]
fn restrict(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn body(seq: u64, prev: &str) -> Body {
        Body {
            seq,
            at: "2026-08-09T00:00:00Z".to_owned(),
            prev: prev.to_owned(),
            action: "server.start".to_owned(),
            subject: "default".to_owned(),
            subject_kind: "system".to_owned(),
            subject_sensitivity: "public".to_owned(),
            target: None,
            service: "pic-x".to_owned(),
            version: "0.1.0".to_owned(),
        }
    }

    #[test]
    fn test_a_records_digest_covers_every_field_of_it() {
        let original = body(1, GENESIS);
        let digest = Record::expected_digest(&original).expect("it digests");

        let mut altered = original.clone();
        altered.action = "server.stop".to_owned();

        assert_ne!(
            Record::expected_digest(&altered).expect("it digests"),
            digest,
            "changing the action left the digest alone"
        );

        let mut retargeted = original;
        retargeted.target = Some("/picx.admin.v1.Admin/GetVersion".to_owned());

        assert_ne!(
            Record::expected_digest(&retargeted).expect("it digests"),
            digest,
            "adding a target left the digest alone"
        );
    }

    #[test]
    fn test_the_same_record_always_digests_to_the_same_value() {
        // The chain is only worth anything if two readers agree on what a record hashes to.
        assert_eq!(
            Record::expected_digest(&body(1, GENESIS)).expect("it digests"),
            Record::expected_digest(&body(1, GENESIS)).expect("it digests")
        );
    }

    #[test]
    fn test_only_our_own_files_are_treated_as_days_of_records() {
        assert_eq!(
            day_of_file("audit-1970-01-02.jsonl"),
            Some(1),
            "a file of ours"
        );

        for other in [
            "audit-1970-01-02.jsonl.gz",
            "audit-not-a-date.jsonl",
            "README.md",
            "audit-.jsonl",
            ".",
        ] {
            assert!(day_of_file(other).is_none(), "{other} was claimed");
        }
    }
}
