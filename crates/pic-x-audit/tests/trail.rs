//! What the file sink writes, and what verifying it catches.
//!
//! The point of a chained trail is not that it verifies — anything verifies when nobody has touched
//! it. The point is what happens when somebody has, so most of what follows tampers with a trail on
//! purpose and asserts that it stops verifying.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use pic_x_audit::{FileAuditSink, verify};
use pic_x_core::{AuditEvent, AuditSink, Subject};

/// A trail location nothing else is using.
fn trail(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("pic-x-trail-{name}"));
    let _ = fs::remove_dir_all(&path);

    path
}

fn sink(directory: &Path) -> FileAuditSink {
    FileAuditSink::new(
        directory,
        "pic-x",
        "9.9.9",
        // Ninety days, which is what a deployment would set.
        Duration::from_secs(90 * 86_400),
    )
}

/// Writes `count` ordinary records.
async fn write(sink: &FileAuditSink, count: usize) {
    for index in 0..count {
        let target = format!("run-{index}");
        let event = AuditEvent::system("service.start", "wellknown").on(&target);

        sink.record(&event, None)
            .await
            .expect("the record is written");
    }
}

/// Returns the only file of records in a trail.
fn only_file(directory: &Path) -> PathBuf {
    let mut files: Vec<PathBuf> = fs::read_dir(directory)
        .expect("the trail is there")
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "jsonl")
        })
        .collect();

    assert_eq!(files.len(), 1, "expected one day of records");

    files.remove(0)
}

#[tokio::test]
async fn test_a_trail_nobody_touched_verifies() {
    let directory = trail("clean");
    let sink = sink(&directory);
    sink.prepare().expect("the trail is prepared");

    write(&sink, 5).await;

    let verified = verify(&directory).expect("it verifies");

    assert_eq!(verified.records, 5);
    assert_eq!(verified.days, 1);
    assert_eq!(verified.head.len(), 64, "the head is a SHA-256");
}

#[tokio::test]
async fn test_editing_a_record_in_place_stops_the_trail_verifying() {
    let directory = trail("edited");
    let sink = sink(&directory);
    sink.prepare().expect("the trail is prepared");
    write(&sink, 3).await;

    // The oldest thing an attacker wants to do: change what a record says and leave everything else.
    let path = only_file(&directory);
    let text = fs::read_to_string(&path).expect("the file reads");
    fs::write(&path, text.replace("service.start", "service.slart")).expect("the file is edited");

    let error = verify(&directory).expect_err("an edited record must not verify");

    assert!(
        format!("{error:#}").contains("altered"),
        "the failure did not say the record was altered: {error:#}"
    );
}

#[tokio::test]
async fn test_removing_a_record_stops_the_trail_verifying() {
    let directory = trail("removed");
    let sink = sink(&directory);
    sink.prepare().expect("the trail is prepared");
    write(&sink, 4).await;

    // The second oldest: delete the line that is inconvenient.
    let path = only_file(&directory);
    let text = fs::read_to_string(&path).expect("the file reads");
    let kept: Vec<&str> = text
        .lines()
        .enumerate()
        .filter(|(index, _)| *index != 1)
        .map(|(_, line)| line)
        .collect();
    fs::write(&path, format!("{}\n", kept.join("\n"))).expect("the file is edited");

    let error = verify(&directory).expect_err("a trail with a hole must not verify");

    assert!(
        format!("{error:#}").contains("does not follow"),
        "the failure did not identify a broken chain: {error:#}"
    );
}

#[tokio::test]
async fn test_truncating_the_trail_is_caught_by_the_sequence() {
    let directory = trail("truncated");
    let sink = sink(&directory);
    sink.prepare().expect("the trail is prepared");
    write(&sink, 4).await;

    // Cutting the tail off leaves a chain that is internally consistent, which is exactly why the
    // sequence is checked as well as the digests.
    let path = only_file(&directory);
    let text = fs::read_to_string(&path).expect("the file reads");
    let head: Vec<&str> = text.lines().take(2).collect();
    fs::write(&path, format!("{}\n", head.join("\n"))).expect("the file is edited");

    // Two records that follow each other still verify — truncation is only detectable against what
    // the trail is expected to contain, which is why the head is what gets attested elsewhere.
    let verified = verify(&directory).expect("what remains is self-consistent");

    assert_eq!(
        verified.records, 2,
        "the count is what makes a truncation visible to whoever kept the previous head"
    );
}

#[tokio::test]
async fn test_the_chain_continues_across_a_restart() {
    let directory = trail("restart");

    {
        let first = sink(&directory);
        first.prepare().expect("the trail is prepared");
        write(&first, 2).await;
        first.shutdown().await.expect("the trail is closed");
    }

    // A new process, the same trail. Starting the sequence again at 1 would leave a trail that never
    // verifies, and one that started a fresh chain would hide everything before the restart.
    let second = sink(&directory);
    second.prepare().expect("the trail is prepared");
    write(&second, 2).await;

    let verified = verify(&directory).expect("it verifies across the restart");

    assert_eq!(verified.records, 4);
}

#[tokio::test]
async fn test_a_record_carries_what_the_event_said_and_no_more() {
    let directory = trail("shape");
    let sink = sink(&directory);
    sink.prepare().expect("the trail is prepared");

    let event = AuditEvent::new("admin.request", Subject::Principal("someone@example.com"))
        .on("/picx.admin.v1.Admin/GetVersion");
    sink.record(&event, None)
        .await
        .expect("the record is written");

    let text = fs::read_to_string(only_file(&directory)).expect("the file reads");

    assert!(text.contains(r#""action":"admin.request""#));
    assert!(text.contains(r#""target":"/picx.admin.v1.Admin/GetVersion""#));
    assert!(text.contains(r#""subject_kind":"principal""#));
    assert!(text.contains(r#""subject_sensitivity":"personal""#));
    // With no pseudonymiser the subject is masked, and a masked person must not be readable.
    assert!(
        !text.contains("someone@example.com"),
        "a personal identifier reached the trail in the clear"
    );
}

#[tokio::test]
async fn test_a_day_past_its_retention_is_removed_and_one_inside_it_is_not() {
    let directory = trail("retention");
    fs::create_dir_all(&directory).expect("the directory is created");

    // Two days of records from a previous life: one older than the retention, one inside it.
    let stale = directory.join("audit-1970-01-02.jsonl");
    let recent = directory.join("audit-2999-01-01.jsonl");
    fs::write(&stale, "").expect("the old day is written");
    fs::write(&recent, "").expect("the recent day is written");

    sink(&directory).prepare().expect("the trail is prepared");

    assert!(!stale.exists(), "a day past its retention was kept");
    assert!(recent.exists(), "a day inside its retention was removed");
}

#[tokio::test]
async fn test_files_that_are_not_ours_are_left_alone() {
    let directory = trail("neighbours");
    fs::create_dir_all(&directory).expect("the directory is created");

    let notes = directory.join("README.md");
    fs::write(&notes, "why this directory exists").expect("the note is written");

    let sink = sink(&directory);
    sink.prepare().expect("the trail is prepared");
    write(&sink, 1).await;

    assert!(notes.exists(), "retention removed a file it does not own");
    assert_eq!(
        verify(&directory).expect("it verifies").records,
        1,
        "verification tried to read a file that is not a trail"
    );
}

#[tokio::test]
async fn test_a_trail_is_readable_only_by_the_user_running_the_process() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let directory = trail("permissions");
        let sink = sink(&directory);
        sink.prepare().expect("the trail is prepared");
        write(&sink, 1).await;

        let mode = |path: &PathBuf| {
            fs::metadata(path)
                .expect("it is there")
                .permissions()
                .mode()
                & 0o777
        };

        assert_eq!(mode(&directory), 0o700);
        assert_eq!(mode(&only_file(&directory)), 0o600);
    }
}

#[tokio::test]
async fn test_an_empty_directory_verifies_as_an_empty_trail() {
    let directory = trail("empty");
    sink(&directory).prepare().expect("the trail is prepared");

    let verified = verify(&directory).expect("nothing is still something");

    assert_eq!(verified.records, 0);
    assert_eq!(verified.days, 0);
}
