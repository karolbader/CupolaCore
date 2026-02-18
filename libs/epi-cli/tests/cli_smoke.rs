use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::TempDir;
use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};

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
fn verify_fails_on_missing_required_file() {
    let temp = TempDir::new().expect("tempdir");
    let pack = build_pack_zip(&temp, Some("epi.claims.v1.json"), None, vec![], None);
    let (output, parsed) = run_verify_json(&pack);

    assert!(!output.status.success(), "verify should fail");
    assert_eq!(parsed["ok"], false);
    assert!(
        json_string_array(&parsed["missing"]).contains(&"epi.claims.v1.json".to_string()),
        "missing list should include required file, got: {}",
        parsed
    );
}

#[test]
fn verify_fails_on_schema_version_mismatch() {
    let temp = TempDir::new().expect("tempdir");
    let pack = build_pack_zip(
        &temp,
        None,
        Some(("epi.runlog.v1.json", "epi.runlog.v999")),
        vec![],
        None,
    );
    let (output, parsed) = run_verify_json(&pack);

    assert!(!output.status.success(), "verify should fail");
    assert_eq!(parsed["ok"], false);
    let schema_errors = json_string_array(&parsed["schema_errors"]);
    assert!(
        schema_errors
            .iter()
            .any(|item| item.contains("epi.runlog.v1.json: schema_version expected")),
        "expected schema mismatch error, got: {:?}",
        schema_errors
    );
}

#[test]
fn verify_detects_extra_file_without_failing() {
    let temp = TempDir::new().expect("tempdir");
    let pack = build_pack_zip(
        &temp,
        None,
        None,
        vec![("notes/extra.txt".to_string(), b"extra".to_vec())],
        None,
    );
    let (output, parsed) = run_verify_json(&pack);

    assert!(
        output.status.success(),
        "verify should pass when only extras exist"
    );
    assert_eq!(parsed["ok"], true);
    assert!(
        json_string_array(&parsed["extras"]).contains(&"notes/extra.txt".to_string()),
        "extras should include unsealed file, got: {}",
        parsed
    );
}

#[test]
fn verify_detects_hash_mismatch() {
    let temp = TempDir::new().expect("tempdir");
    let pack = build_pack_zip(&temp, None, None, vec![], Some("epi.claims.v1.json"));
    let (output, parsed) = run_verify_json(&pack);

    assert!(
        !output.status.success(),
        "verify should fail on tampered bytes"
    );
    assert_eq!(parsed["ok"], false);
    let mismatches = json_string_array(&parsed["hash_mismatches"]);
    assert!(
        mismatches
            .iter()
            .any(|line| line.contains("epi.claims.v1.json")),
        "expected claims hash mismatch, got: {:?}",
        mismatches
    );
}

fn run_verify_json(pack: &Path) -> (std::process::Output, Value) {
    let pack_s = pack.to_string_lossy().to_string();
    let output = Command::new(bin_path())
        .args(["verify", &pack_s, "--json"])
        .output()
        .expect("failed to run verify --json");
    let parsed: Value = serde_json::from_slice(&output.stdout).expect("stdout should be JSON");
    (output, parsed)
}

fn json_string_array(value: &Value) -> Vec<String> {
    value
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|item| item.as_str().map(ToOwned::to_owned))
        .collect()
}

fn build_pack_zip(
    temp: &TempDir,
    missing_required: Option<&str>,
    schema_override: Option<(&str, &str)>,
    unsealed_extra_files: Vec<(String, Vec<u8>)>,
    tamper_after_seal: Option<&str>,
) -> PathBuf {
    let mut sealed_files = required_files();

    if let Some(required_name) = missing_required {
        sealed_files.remove(required_name);
    }

    if let Some((file_name, schema_version)) = schema_override {
        if let Some(value) = sealed_files.get_mut(file_name) {
            if let Some(object) = value.as_object_mut() {
                object.insert(
                    "schema_version".to_string(),
                    Value::String(schema_version.to_string()),
                );
            }
        }
    }

    let seal_entries = build_seal_entries(&sealed_files);
    let seal_json = json!({
        "schema_version": "epi.seal.v1",
        "schema": "epi.seal.v1",
        "created_at": "2026-01-01T00:00:00Z",
        "pack_sha256": "placeholder",
        "pack_files": seal_entries,
        "replay": { "commands": [] }
    });

    let mut final_files = sealed_files
        .iter()
        .map(|(name, value)| (name.clone(), to_json_bytes(value)))
        .collect::<BTreeMap<String, Vec<u8>>>();

    if let Some(file_name) = tamper_after_seal {
        if let Some(bytes) = final_files.get_mut(file_name) {
            let tampered = json!({
                "schema_version": "epi.claims.v1",
                "generated_at": "2026-01-01T00:00:00Z",
                "claims": [{ "claim_id": "TAMPERED" }]
            });
            *bytes = to_json_bytes(&tampered);
        }
    }

    if missing_required != Some("epi.seal.v1.json") {
        final_files.insert("epi.seal.v1.json".to_string(), to_json_bytes(&seal_json));
    }

    for (path, bytes) in unsealed_extra_files {
        final_files.insert(path, bytes);
    }

    let mut ordered_paths = final_files.keys().cloned().collect::<Vec<String>>();
    ordered_paths.sort_by(|left, right| {
        left.to_ascii_lowercase()
            .cmp(&right.to_ascii_lowercase())
            .then_with(|| left.cmp(right))
    });

    let pack_path = temp.path().join("pack.zip");
    let file = File::create(&pack_path).expect("create zip");
    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    for path in ordered_paths {
        zip.start_file(path.clone(), options)
            .expect("start zip file");
        zip.write_all(final_files.get(&path).expect("entry bytes"))
            .expect("write zip entry");
    }
    zip.finish().expect("finish zip");

    pack_path
}

fn required_files() -> BTreeMap<String, Value> {
    BTreeMap::from([
        (
            "epi.evidence_pack.v1.json".to_string(),
            json!({
                "schema_version": "epi.evidence_pack.v1",
                "vault_id": "vault-1",
                "vault_snapshot_id": "snap-1",
                "source_manifest": {},
                "query_log": {},
                "hits": [],
                "source_extracts": []
            }),
        ),
        (
            "epi.decision_pack.v1.json".to_string(),
            json!({
                "schema_version": "epi.decision_pack.v1",
                "generated_at": "2026-01-01T00:00:00Z",
                "toolchain": {},
                "artifacts": []
            }),
        ),
        (
            "epi.runlog.v1.json".to_string(),
            json!({
                "schema_version": "epi.runlog.v1",
                "schema": "epi.runlog.v1",
                "run_id": "run-1",
                "created_at": "2026-01-01T00:00:00Z",
                "inputs": {},
                "steps": [],
                "stop_reason": "success"
            }),
        ),
        (
            "epi.claims.v1.json".to_string(),
            json!({
                "schema_version": "epi.claims.v1",
                "generated_at": "2026-01-01T00:00:00Z",
                "claims": []
            }),
        ),
        (
            "epi.drift_report.v1.json".to_string(),
            json!({
                "schema_version": "epi.drift_report.v1",
                "generated_at": "2026-01-01T00:00:00Z",
                "a_sha256": "a",
                "b_sha256": "b",
                "changes": [],
                "drift_summary": {}
            }),
        ),
    ])
}

fn build_seal_entries(files: &BTreeMap<String, Value>) -> Value {
    let mut entries = files
        .iter()
        .map(|(path, value)| {
            json!({
                "rel_path": path,
                "sha256": sha256_hex(&to_json_bytes(value))
            })
        })
        .collect::<Vec<Value>>();
    entries.sort_by(|left, right| {
        let left_path = left["rel_path"].as_str().unwrap_or_default();
        let right_path = right["rel_path"].as_str().unwrap_or_default();
        left_path
            .to_ascii_lowercase()
            .cmp(&right_path.to_ascii_lowercase())
            .then_with(|| left_path.cmp(right_path))
    });
    Value::Array(entries)
}

fn to_json_bytes(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(value).expect("serialize json");
    bytes.push(b'\n');
    bytes
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    hex::encode(digest)
}
