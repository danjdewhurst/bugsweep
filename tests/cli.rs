//! End-to-end tests of the command line. None of them need Bluetooth or a network.

use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn bugsweep() -> Command {
    Command::cargo_bin("bugsweep").expect("binary is built")
}

const CUSTOM_SIGNATURES: &str = r#"
[[signature]]
id = "test-tag"
name = "Test tag"
category = "tracker"
severity = "high"
confidence = "low"
evidence = "guess"
source = "integration test"
[[signature.match]]
name_regex = "^TestTag"
"#;

#[test]
fn version_matches_the_package() {
    bugsweep()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn help_lists_each_subcommand() {
    let assert = bugsweep().arg("--help").assert().success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    // Subcommand lines start with the name; option lines start with "-".
    for command in ["scan", "lan", "followers", "signatures"] {
        let listed = out.lines().any(|line| line.split_whitespace().next() == Some(command));
        assert!(listed, "--help does not list {command}:\n{out}");
    }
}

#[test]
fn unknown_subcommand_fails() {
    bugsweep().arg("no-such-command").assert().failure().stderr(predicate::str::contains("no-such-command"));
}

#[test]
fn signatures_lists_the_built_in_database() {
    bugsweep()
        .arg("signatures")
        .assert()
        .success()
        .stdout(predicate::str::starts_with("ID"))
        .stdout(predicate::str::contains("apple-airtag-separated"))
        .stdout(predicate::str::contains("samsung-smarttag"));
}

#[test]
fn custom_signature_file_replaces_the_built_in_database() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("custom.toml");
    fs::write(&path, CUSTOM_SIGNATURES).unwrap();

    bugsweep()
        .arg("--signatures")
        .arg(&path)
        .arg("signatures")
        .assert()
        .success()
        .stdout(predicate::str::contains("test-tag"))
        .stdout(predicate::str::contains("apple-airtag-separated").not());
}

#[test]
fn bad_signature_file_is_an_error() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("bad.toml");
    fs::write(&path, CUSTOM_SIGNATURES.replace("tracker", "toaster")).unwrap();

    bugsweep()
        .arg("--signatures")
        .arg(&path)
        .arg("signatures")
        .assert()
        .failure()
        .stderr(predicate::str::contains("bad.toml"));
}

#[test]
fn missing_signature_file_is_an_error() {
    bugsweep()
        .args(["--signatures", "does-not-exist.toml", "signatures"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot read"));
}

#[test]
fn followers_needs_the_log() {
    bugsweep()
        .args(["--no-log", "followers"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("the log is off"));
}

#[test]
fn followers_on_a_new_log_is_empty() {
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("nested").join("bugsweep.db");

    bugsweep()
        .arg("--db")
        .arg(&db)
        .arg("followers")
        .assert()
        .success()
        .stdout(predicate::str::contains("No device was seen at two or more places."));
    assert!(db.exists(), "the log file was not created");
}

/// Without --db, the log goes to the data directory of the user. Windows
/// finds that directory without the environment, so the test is for Unix.
#[cfg(unix)]
#[test]
fn followers_uses_the_default_log() {
    let home = TempDir::new().unwrap();
    bugsweep()
        .arg("followers")
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", home.path().join("data"))
        .assert()
        .success()
        .stdout(predicate::str::contains("No device was seen"));
    let in_data = home.path().join("data/bugsweep/bugsweep.db");
    let in_library = home.path().join("Library/Application Support/bugsweep/bugsweep.db");
    assert!(in_data.exists() || in_library.exists(), "the log is not in the data directory");
}
