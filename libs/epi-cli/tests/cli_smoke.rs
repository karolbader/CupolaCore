use serde_json::Value;
use std::process::Command;
use tempfile::TempDir;

fn bin_path() -> &'static str {
    env!("CARGO_BIN_EXE_epi-cli")
}

#[test]
fn help_runs() {
    let output = Command::new(bin_path())
        .arg("--help")
        .output()
        .expect("failed to run epi-cli --help");

    assert!(output.status.success(), "help command should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Usage:"),
        "unexpected help output: {stdout}"
    );
}

#[test]
fn verify_fails_on_missing_file() {
    let temp = TempDir::new().expect("tempdir");
    let missing = temp.path().join("missing.epi.json");
    let missing_s = missing.to_string_lossy().to_string();

    let output = Command::new(bin_path())
        .args(["verify", &missing_s])
        .output()
        .expect("failed to run verify for missing path");

    assert!(
        !output.status.success(),
        "verify should fail for a missing path"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("path does not exist"),
        "expected clear missing-path error, stderr: {stderr}"
    );
}

#[test]
fn verify_json_succeeds_for_existing_file() {
    let temp = TempDir::new().expect("tempdir");
    let existing = temp.path().join("existing.epi.json");
    std::fs::write(&existing, "{}").expect("write temp file");
    let existing_s = existing.to_string_lossy().to_string();

    let output = Command::new(bin_path())
        .args(["verify", &existing_s, "--json"])
        .output()
        .expect("failed to run verify --json");

    assert!(output.status.success(), "verify --json should succeed");
    let parsed: Value =
        serde_json::from_slice(&output.stdout).expect("stdout should be valid JSON");
    assert_eq!(parsed["status"]["success"], true);
    assert_eq!(parsed["command"], "verify");
    assert_eq!(parsed["path"], existing_s);
}
