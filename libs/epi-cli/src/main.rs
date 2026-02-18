use clap::{Parser, Subcommand};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use zip::ZipArchive;

const VERIFY_NOTE: &str = "v0 placeholder: pack structure not enforced yet";
const SCHEMA_VALIDATE_NOTE: &str = "v0 placeholder: schema rules not enforced yet";
const DIFF_NOTE: &str = "v0 placeholder: diff engine not implemented yet";
const REPLAY_NOTE: &str = "v0 placeholder: replay engine not implemented yet";
const VERIFY_FAILURE_EXIT: u8 = 2;

const REQUIRED_PACK_FILES: [(&str, &str); 6] = [
    ("epi.evidence_pack.v1.json", "epi.evidence_pack.v1"),
    ("epi.claims.v1.json", "epi.claims.v1"),
    ("epi.decision_pack.v1.json", "epi.decision_pack.v1"),
    ("epi.runlog.v1.json", "epi.runlog.v1"),
    ("epi.seal.v1.json", "epi.seal.v1"),
    ("epi.drift_report.v1.json", "epi.drift_report.v1"),
];

const OPTIONAL_PACK_FILES: [&str; 2] = ["epi.signoff.v1.json", "epi.attestation.v1.json"];

#[derive(Parser, Debug)]
#[command(name = "epi-cli", version, about = "EPI verifier CLI (v0)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Verify a pack file path (v0 placeholder).
    Verify {
        path: PathBuf,
        /// Emit stable JSON output.
        #[arg(long)]
        json: bool,
    },
    /// Validate JSON syntax for a schema file path.
    SchemaValidate {
        path: PathBuf,
        /// Emit stable JSON output.
        #[arg(long)]
        json: bool,
    },
    /// Compare two files (v0 placeholder).
    Diff {
        a: PathBuf,
        b: PathBuf,
        /// Emit stable JSON output.
        #[arg(long)]
        json: bool,
    },
    /// Replay placeholder command.
    Replay {
        arg: String,
        /// Emit stable JSON output.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Serialize)]
struct Status {
    success: bool,
}

#[derive(Serialize)]
struct VerifyOutput {
    status: Status,
    command: &'static str,
    path: String,
    notes: Vec<&'static str>,
}

#[derive(Serialize)]
struct VerifyZipOutput {
    status: Status,
    command: &'static str,
    path: String,
    missing_files: Vec<String>,
    invalid_json: Vec<String>,
    schema_version_mismatches: Vec<SchemaVersionMismatch>,
    file_hashes: BTreeMap<String, String>,
    notes: Vec<String>,
}

#[derive(Serialize)]
struct SchemaVersionMismatch {
    file: String,
    expected: String,
    found: String,
}

#[derive(Serialize)]
struct SchemaValidateOutput {
    status: Status,
    command: &'static str,
    path: String,
    notes: Vec<&'static str>,
}

#[derive(Serialize)]
struct DiffOutput {
    status: Status,
    command: &'static str,
    a: String,
    b: String,
    notes: Vec<&'static str>,
}

#[derive(Serialize)]
struct ReplayOutput {
    status: Status,
    command: &'static str,
    arg: String,
    notes: Vec<&'static str>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("ERR: {err}");
            ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode, String> {
    match cli.command {
        Command::Verify { path, json } => handle_verify(path, json),
        Command::SchemaValidate { path, json } => {
            handle_schema_validate(path, json)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Diff { a, b, json } => {
            handle_diff(a, b, json)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Replay { arg, json } => {
            handle_replay(arg, json)?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn handle_verify(path: PathBuf, json: bool) -> Result<ExitCode, String> {
    if !path.exists() {
        let message = format!("path does not exist: {}", path.display());
        eprintln!("ERR: {message}");
        let output = verify_zip_failure_output(&path, message);
        print_verify_zip_output(&path, json, &output)?;
        return Ok(ExitCode::from(VERIFY_FAILURE_EXIT));
    }

    if !is_zip_path(&path) {
        if json {
            print_json(&VerifyOutput {
                status: Status { success: true },
                command: "verify",
                path: path_string(&path),
                notes: vec![VERIFY_NOTE],
            })?;
        } else {
            println!("OK: verify placeholder passed for {}", path.display());
            println!("NOTE: {VERIFY_NOTE}");
        }
        return Ok(ExitCode::SUCCESS);
    }

    let output = match verify_zip_pack(&path) {
        Ok(output) => output,
        Err(err) => verify_zip_failure_output(&path, err),
    };

    print_verify_zip_output(&path, json, &output)?;
    if output.status.success {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(VERIFY_FAILURE_EXIT))
    }
}

fn handle_schema_validate(path: PathBuf, json: bool) -> Result<(), String> {
    ensure_exists(&path)?;
    let bytes =
        std::fs::read(&path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    serde_json::from_slice::<serde_json::Value>(&bytes)
        .map_err(|e| format!("invalid JSON in {}: {e}", path.display()))?;

    if json {
        print_json(&SchemaValidateOutput {
            status: Status { success: true },
            command: "schema-validate",
            path: path_string(&path),
            notes: vec![SCHEMA_VALIDATE_NOTE],
        })?;
    } else {
        println!("OK: schema-validate passed for {}", path.display());
        println!("NOTE: {SCHEMA_VALIDATE_NOTE}");
    }
    Ok(())
}

fn handle_diff(a: PathBuf, b: PathBuf, json: bool) -> Result<(), String> {
    ensure_exists(&a)?;
    ensure_exists(&b)?;
    if json {
        print_json(&DiffOutput {
            status: Status { success: true },
            command: "diff",
            a: path_string(&a),
            b: path_string(&b),
            notes: vec![DIFF_NOTE],
        })?;
    } else {
        println!(
            "OK: diff placeholder for {} vs {}",
            a.display(),
            b.display()
        );
        println!("NOTE: {DIFF_NOTE}");
    }
    Ok(())
}

fn handle_replay(arg: String, json: bool) -> Result<(), String> {
    if json {
        print_json(&ReplayOutput {
            status: Status { success: true },
            command: "replay",
            arg,
            notes: vec![REPLAY_NOTE],
        })?;
    } else {
        println!("OK: replay placeholder for {}", arg);
        println!("NOTE: {REPLAY_NOTE}");
    }
    Ok(())
}

fn ensure_exists(path: &Path) -> Result<(), String> {
    if path.exists() {
        return Ok(());
    }
    Err(format!("path does not exist: {}", path.display()))
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

fn is_zip_path(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("zip"))
        .unwrap_or(false)
}

fn verify_zip_failure_output(path: &Path, note: String) -> VerifyZipOutput {
    VerifyZipOutput {
        status: Status { success: false },
        command: "verify",
        path: path_string(path),
        missing_files: Vec::new(),
        invalid_json: Vec::new(),
        schema_version_mismatches: Vec::new(),
        file_hashes: BTreeMap::new(),
        notes: vec![note],
    }
}

fn verify_zip_pack(path: &Path) -> Result<VerifyZipOutput, String> {
    let file = File::open(path).map_err(|e| format!("failed to open {}: {e}", path.display()))?;
    let mut archive = ZipArchive::new(file)
        .map_err(|e| format!("failed to read ZIP archive {}: {e}", path.display()))?;

    let mut contained_files = BTreeSet::new();
    let mut normalized_to_actual = BTreeMap::new();
    for idx in 0..archive.len() {
        let entry = archive
            .by_index(idx)
            .map_err(|e| format!("failed to inspect ZIP entry #{idx}: {e}"))?;
        let actual_name = entry.name().to_string();
        let normalized_name = normalize_zip_name(&actual_name);
        contained_files.insert(normalized_name.clone());
        normalized_to_actual
            .entry(normalized_name)
            .or_insert(actual_name);
    }

    let _optional_present: Vec<&str> = OPTIONAL_PACK_FILES
        .iter()
        .copied()
        .filter(|name| contained_files.contains(*name))
        .collect();

    let mut missing_files = Vec::new();
    let mut invalid_json = Vec::new();
    let mut schema_version_mismatches = Vec::new();
    let mut file_hashes = BTreeMap::new();

    for (required_file, expected_schema_version) in REQUIRED_PACK_FILES {
        if !contained_files.contains(required_file) {
            missing_files.push(required_file.to_string());
            continue;
        }

        let Some(actual_name) = normalized_to_actual.get(required_file) else {
            missing_files.push(required_file.to_string());
            continue;
        };

        let mut entry = archive
            .by_name(actual_name)
            .map_err(|e| format!("failed to open ZIP entry {required_file}: {e}"))?;
        let mut raw_bytes = Vec::new();
        entry
            .read_to_end(&mut raw_bytes)
            .map_err(|e| format!("failed to read ZIP entry {required_file}: {e}"))?;

        file_hashes.insert(required_file.to_string(), sha256_hex(&raw_bytes));

        match serde_json::from_slice::<serde_json::Value>(&raw_bytes) {
            Ok(value) => {
                let schema_value = value.get("schema_version");
                let found_schema = schema_value.and_then(|s| s.as_str());

                if found_schema != Some(expected_schema_version) {
                    let found = match schema_value {
                        Some(serde_json::Value::String(s)) => s.clone(),
                        Some(_) => "<non-string>".to_string(),
                        None => "<missing>".to_string(),
                    };
                    schema_version_mismatches.push(SchemaVersionMismatch {
                        file: required_file.to_string(),
                        expected: expected_schema_version.to_string(),
                        found,
                    });
                }
            }
            Err(_) => invalid_json.push(required_file.to_string()),
        }
    }

    missing_files.sort();
    invalid_json.sort();
    schema_version_mismatches.sort_by(|a, b| a.file.cmp(&b.file));

    let success =
        missing_files.is_empty() && invalid_json.is_empty() && schema_version_mismatches.is_empty();

    Ok(VerifyZipOutput {
        status: Status { success },
        command: "verify",
        path: path_string(path),
        missing_files,
        invalid_json,
        schema_version_mismatches,
        file_hashes,
        notes: Vec::new(),
    })
}

fn normalize_zip_name(name: &str) -> String {
    name.replace('\\', "/")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    hex::encode(digest)
}

fn print_verify_zip_output(
    path: &Path,
    json: bool,
    output: &VerifyZipOutput,
) -> Result<(), String> {
    if json {
        print_json(output)?;
        return Ok(());
    }

    if output.status.success {
        println!("PASS: verify {}", path.display());
        return Ok(());
    }

    println!("FAIL: verify {}", path.display());
    if !output.missing_files.is_empty() {
        println!("missing: {}", output.missing_files.join(", "));
    }
    if !output.invalid_json.is_empty() {
        println!("invalid_json: {}", output.invalid_json.join(", "));
    }
    for mismatch in &output.schema_version_mismatches {
        println!(
            "schema_version mismatch: {} expected {} found {}",
            mismatch.file, mismatch.expected, mismatch.found
        );
    }
    for note in &output.notes {
        println!("note: {note}");
    }

    Ok(())
}

fn print_json<T: Serialize>(output: &T) -> Result<(), String> {
    let json = serde_json::to_string_pretty(output)
        .map_err(|e| format!("failed to serialize JSON output: {e}"))?;
    println!("{json}");
    Ok(())
}
