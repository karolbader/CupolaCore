use cupola_core::VerifyReport;
use cupola_protocol::SearchResponseDTO;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

fn bin_path() -> &'static str {
    env!("CARGO_BIN_EXE_cupola-cli")
}

fn run_cli(appdata: &Path, args: &[&str]) -> Output {
    Command::new(bin_path())
        .args(args)
        .env("APPDATA", appdata)
        .output()
        .expect("failed to run cupola-cli")
}

fn setup_vault_with_file(name: &str, contents: &str) -> (TempDir, PathBuf, PathBuf) {
    let td = TempDir::new().expect("tempdir");
    let vault = td.path().join("vault");
    std::fs::create_dir_all(&vault).expect("vault dir");
    std::fs::write(vault.join(name), contents).expect("write file");
    let appdata = td.path().join("appdata");
    std::fs::create_dir_all(&appdata).expect("appdata dir");
    (td, vault, appdata)
}

fn parse_chunk_ids_from_human_search(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .filter_map(|l| l.split(" | ").next().map(|s| s.to_string()))
        .filter(|s| !s.is_empty())
        .collect()
}

#[test]
fn verify_human_output_pass_then_modified_fail() {
    let (_td, vault, appdata) = setup_vault_with_file("a.txt", "hello cupola\n");
    let manifest = vault.with_extension("freeze.json");
    let vault_s = vault.to_string_lossy().to_string();
    let manifest_s = manifest.to_string_lossy().to_string();

    let hash = run_cli(&appdata, &["hash", "--vault", &vault_s]);
    assert!(hash.status.success(), "hash failed: {:?}", hash);

    let freeze = run_cli(
        &appdata,
        &["freeze", "--vault", &vault_s, "--out", &manifest_s],
    );
    assert!(freeze.status.success(), "freeze failed: {:?}", freeze);

    let verify_ok = run_cli(
        &appdata,
        &["verify", "--vault", &vault_s, "--manifest", &manifest_s],
    );
    assert!(
        verify_ok.status.success(),
        "verify pass failed: {:?}",
        verify_ok
    );
    assert_eq!(
        String::from_utf8_lossy(&verify_ok.stdout).trim(),
        "OK: verify passed (1 artifacts)"
    );

    std::fs::write(vault.join("a.txt"), "changed content\n").expect("modify file");

    let verify_fail = run_cli(
        &appdata,
        &["verify", "--vault", &vault_s, "--manifest", &manifest_s],
    );
    assert!(
        !verify_fail.status.success(),
        "verify should fail after modification"
    );
    let out = String::from_utf8_lossy(&verify_fail.stdout);
    assert!(
        out.contains("ERR: MODIFIED a.txt expected="),
        "stdout was: {out}"
    );
    assert!(out.contains(" actual="), "stdout was: {out}");
}

#[test]
fn verify_json_output_pass_and_fail_shapes() {
    let (_td, vault, appdata) = setup_vault_with_file("a.txt", "hello cupola\n");
    let manifest = vault.with_extension("freeze.json");
    let vault_s = vault.to_string_lossy().to_string();
    let manifest_s = manifest.to_string_lossy().to_string();

    assert!(run_cli(&appdata, &["hash", "--vault", &vault_s])
        .status
        .success());
    assert!(run_cli(
        &appdata,
        &["freeze", "--vault", &vault_s, "--out", &manifest_s]
    )
    .status
    .success());

    let verify_ok = run_cli(
        &appdata,
        &[
            "verify",
            "--vault",
            &vault_s,
            "--manifest",
            &manifest_s,
            "--json",
        ],
    );
    assert!(verify_ok.status.success(), "verify --json pass failed");
    let out_ok = String::from_utf8_lossy(&verify_ok.stdout);
    assert!(
        !out_ok.contains("OK: verify passed"),
        "stdout mixed human output when --json set: {out_ok}"
    );
    assert!(
        !out_ok.contains("ERR: "),
        "stdout mixed human output when --json set: {out_ok}"
    );
    let report_ok: VerifyReport =
        serde_json::from_slice(&verify_ok.stdout).expect("parse verify pass json");
    assert!(report_ok.ok);
    assert_eq!(report_ok.artifact_count, 1);
    assert_eq!(report_ok.mismatches.len(), 0);

    std::fs::write(vault.join("a.txt"), "changed content\n").expect("modify file");

    let verify_fail = run_cli(
        &appdata,
        &[
            "verify",
            "--vault",
            &vault_s,
            "--manifest",
            &manifest_s,
            "--json",
        ],
    );
    assert!(
        !verify_fail.status.success(),
        "verify --json should fail after modification"
    );
    let out_fail = String::from_utf8_lossy(&verify_fail.stdout);
    assert!(
        !out_fail.contains("OK: verify passed"),
        "stdout mixed human output when --json set: {out_fail}"
    );
    assert!(
        !out_fail.contains("ERR: "),
        "stdout mixed human output when --json set: {out_fail}"
    );
    let report_fail: VerifyReport =
        serde_json::from_slice(&verify_fail.stdout).expect("parse verify fail json");
    assert!(!report_fail.ok);
    assert_eq!(report_fail.artifact_count, 1);
    assert!(
        !report_fail.mismatches.is_empty(),
        "expected at least one mismatch"
    );
    let modified = report_fail
        .mismatches
        .iter()
        .find(|m| matches!(m.kind, cupola_core::VerifyDiffKind::Modified))
        .expect("expected Modified mismatch");
    assert_eq!(modified.rel_path, "a.txt");
    assert!(
        modified
            .expected_raw_blob_id
            .as_deref()
            .is_some_and(|s| !s.is_empty()),
        "expected hash missing/empty"
    );
    assert!(
        modified
            .actual_raw_blob_id
            .as_deref()
            .is_some_and(|s| !s.is_empty()),
        "actual hash missing/empty"
    );
}

#[test]
fn verify_mismatch_order_is_stable() {
    let td = TempDir::new().expect("tempdir");
    let vault = td.path().join("vault");
    std::fs::create_dir_all(&vault).expect("vault dir");
    std::fs::write(vault.join("a.txt"), "alpha\n").expect("write a");
    std::fs::write(vault.join("b.txt"), "beta\n").expect("write b");
    let appdata = td.path().join("appdata");
    std::fs::create_dir_all(&appdata).expect("appdata dir");
    let manifest = vault.with_extension("freeze.json");
    let vault_s = vault.to_string_lossy().to_string();
    let manifest_s = manifest.to_string_lossy().to_string();

    assert!(run_cli(&appdata, &["hash", "--vault", &vault_s])
        .status
        .success());
    assert!(run_cli(
        &appdata,
        &["freeze", "--vault", &vault_s, "--out", &manifest_s]
    )
    .status
    .success());

    std::fs::write(vault.join("a.txt"), "alpha changed\n").expect("modify a");
    std::fs::write(vault.join("b.txt"), "beta changed\n").expect("modify b");

    let verify_fail = run_cli(
        &appdata,
        &["verify", "--vault", &vault_s, "--manifest", &manifest_s],
    );
    assert!(!verify_fail.status.success());
    let out = String::from_utf8_lossy(&verify_fail.stdout);
    let err_lines: Vec<&str> = out
        .lines()
        .filter(|l| l.starts_with("ERR: MODIFIED "))
        .collect();
    assert_eq!(err_lines.len(), 2, "stdout was: {out}");
    assert!(err_lines[0].contains(" a.txt "), "stdout was: {out}");
    assert!(err_lines[1].contains(" b.txt "), "stdout was: {out}");
}

#[test]
fn search_json_matches_human_order_and_is_stable() {
    let (_td, vault, appdata) = setup_vault_with_file("a.txt", "hello cupola\nhello cupola\n");
    std::fs::write(vault.join("b.txt"), "hello cupola in b\n").expect("write b");
    let vault_s = vault.to_string_lossy().to_string();

    let hash = run_cli(&appdata, &["hash", "--vault", &vault_s]);
    assert!(hash.status.success(), "hash failed: {:?}", hash);

    let human = run_cli(
        &appdata,
        &[
            "search", "--vault", &vault_s, "--q", "hello", "--limit", "20",
        ],
    );
    assert!(human.status.success(), "human search failed: {:?}", human);
    let human_chunk_ids =
        parse_chunk_ids_from_human_search(&String::from_utf8_lossy(&human.stdout));

    let json1 = run_cli(
        &appdata,
        &[
            "search", "--vault", &vault_s, "--q", "hello", "--limit", "20", "--json",
        ],
    );
    assert!(json1.status.success(), "json search failed: {:?}", json1);
    let r1: SearchResponseDTO = serde_json::from_slice(&json1.stdout).expect("parse json search");
    assert_eq!(r1.query, "hello");
    assert_eq!(r1.limit, 20);
    assert!(r1
        .hits
        .iter()
        .any(|h| h.rel_path == "a.txt" && h.excerpt.contains("hello cupola")));
    let json_chunk_ids_1: Vec<String> = r1.hits.iter().map(|h| h.chunk_id.clone()).collect();
    assert_eq!(json_chunk_ids_1, human_chunk_ids);

    let json2 = run_cli(
        &appdata,
        &[
            "search", "--vault", &vault_s, "--q", "hello", "--limit", "20", "--json",
        ],
    );
    assert!(json2.status.success(), "json search second run failed");
    let r2: SearchResponseDTO =
        serde_json::from_slice(&json2.stdout).expect("parse second json search");
    let json_chunk_ids_2: Vec<String> = r2.hits.iter().map(|h| h.chunk_id.clone()).collect();
    assert_eq!(json_chunk_ids_2, json_chunk_ids_1);
}

#[test]
fn search_json_contract_is_valid_and_deterministic_for_alpha_query() {
    let td = TempDir::new().expect("tempdir");
    let vault = td.path().join("vault");
    std::fs::create_dir_all(&vault).expect("vault dir");
    std::fs::write(vault.join("a.txt"), "alpha beta gamma\n").expect("write a");
    std::fs::write(vault.join("b.txt"), "alpha delta\n").expect("write b");
    let appdata = td.path().join("appdata");
    std::fs::create_dir_all(&appdata).expect("appdata dir");
    let vault_s = vault.to_string_lossy().to_string();

    let hash = run_cli(&appdata, &["hash", "--vault", &vault_s]);
    assert!(hash.status.success(), "hash failed: {:?}", hash);

    let run1 = run_cli(
        &appdata,
        &[
            "search", "--vault", &vault_s, "--q", "alpha", "--limit", "20", "--json",
        ],
    );
    assert!(
        run1.status.success(),
        "search --json run1 failed: {:?}",
        run1
    );
    let out1 = String::from_utf8_lossy(&run1.stdout);
    assert!(
        !out1.contains(" | "),
        "stdout mixed human lines when --json set: {out1}"
    );
    let v1: serde_json::Value = serde_json::from_slice(&run1.stdout).expect("valid json run1");

    let run2 = run_cli(
        &appdata,
        &[
            "search", "--vault", &vault_s, "--q", "alpha", "--limit", "20", "--json",
        ],
    );
    assert!(
        run2.status.success(),
        "search --json run2 failed: {:?}",
        run2
    );
    let out2 = String::from_utf8_lossy(&run2.stdout);
    assert!(
        !out2.contains(" | "),
        "stdout mixed human lines when --json set: {out2}"
    );
    let v2: serde_json::Value = serde_json::from_slice(&run2.stdout).expect("valid json run2");

    assert_eq!(v1.get("query").and_then(|v| v.as_str()), Some("alpha"));
    assert_eq!(v1.get("limit").and_then(|v| v.as_u64()), Some(20));
    let hits1 = v1
        .get("hits")
        .and_then(|h| h.as_array())
        .expect("hits array in run1");
    let hits2 = v2
        .get("hits")
        .and_then(|h| h.as_array())
        .expect("hits array in run2");
    assert!(!hits1.is_empty(), "expected at least one hit");

    for hit in hits1 {
        assert!(
            hit.get("chunk_id").and_then(|v| v.as_str()).is_some(),
            "missing chunk_id in hit: {hit}"
        );
        assert!(
            hit.get("rel_path").and_then(|v| v.as_str()).is_some(),
            "missing rel_path in hit: {hit}"
        );
    }

    let ids1: Vec<String> = hits1
        .iter()
        .map(|h| {
            h.get("chunk_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string()
        })
        .collect();
    let ids2: Vec<String> = hits2
        .iter()
        .map(|h| {
            h.get("chunk_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string()
        })
        .collect();
    assert_eq!(ids1, ids2, "chunk_id ordering changed between runs");
}
