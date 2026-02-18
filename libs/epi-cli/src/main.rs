use chrono::{SecondsFormat, Utc};
use clap::{Args, Parser, Subcommand};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    process::ExitCode,
};
use zip::ZipArchive;

const VERIFY_FAILURE_EXIT: u8 = 2;
const REPLAY_NOTE: &str = "v0 placeholder: replay engine not implemented yet";

#[derive(Clone, Copy)]
struct RequiredPackFile {
    file_name: &'static str,
    schema_name: &'static str,
    schema_file: &'static str,
}

const REQUIRED_PACK_FILES: [RequiredPackFile; 6] = [
    RequiredPackFile {
        file_name: "epi.evidence_pack.v1.json",
        schema_name: "epi.evidence_pack.v1",
        schema_file: "epi.evidence_pack.v1.schema.json",
    },
    RequiredPackFile {
        file_name: "epi.decision_pack.v1.json",
        schema_name: "epi.decision_pack.v1",
        schema_file: "epi.decision_pack.v1.schema.json",
    },
    RequiredPackFile {
        file_name: "epi.runlog.v1.json",
        schema_name: "epi.runlog.v1",
        schema_file: "epi.runlog.v1.schema.json",
    },
    RequiredPackFile {
        file_name: "epi.seal.v1.json",
        schema_name: "epi.seal.v1",
        schema_file: "epi.seal.v1.schema.json",
    },
    RequiredPackFile {
        file_name: "epi.claims.v1.json",
        schema_name: "epi.claims.v1",
        schema_file: "epi.claims.v1.schema.json",
    },
    RequiredPackFile {
        file_name: "epi.drift_report.v1.json",
        schema_name: "epi.drift_report.v1",
        schema_file: "epi.drift_report.v1.schema.json",
    },
];

const KNOWN_SCHEMAS: [(&str, &str); 9] = [
    ("epi.attestation.v1", "epi.attestation.v1.schema.json"),
    ("epi.claims.v1", "epi.claims.v1.schema.json"),
    ("epi.decision_pack.v1", "epi.decision_pack.v1.schema.json"),
    ("epi.drift_report.v1", "epi.drift_report.v1.schema.json"),
    ("epi.evidence_pack.v1", "epi.evidence_pack.v1.schema.json"),
    ("epi.runlog.v1", "epi.runlog.v1.schema.json"),
    ("epi.seal.v1", "epi.seal.v1.schema.json"),
    ("epi.signoff.v1", "epi.signoff.v1.schema.json"),
    ("epi.source_extract.v1", "epi.source_extract.v1.schema.json"),
];

#[derive(Parser, Debug)]
#[command(name = "epi-cli", version, about = "EPI verifier CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Verify an EPI pack zip.
    Verify(VerifyArgs),
    /// Validate a JSON file against a schema.
    SchemaValidate(SchemaValidateArgs),
    /// Compare two pack zip files using their seal hash maps.
    Diff(DiffArgs),
    /// Replay placeholder command.
    Replay(ReplayArgs),
}

#[derive(Args, Debug)]
struct VerifyArgs {
    /// Path to pack.zip
    path: PathBuf,
    /// Emit stable JSON output.
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
struct SchemaValidateArgs {
    /// JSON file path to validate.
    json_path: PathBuf,
    /// Known schema name, e.g. epi.runlog.v1.
    #[arg(long, conflicts_with = "schema_path")]
    schema: Option<String>,
    /// Schema file path.
    #[arg(long, conflicts_with = "schema")]
    schema_path: Option<PathBuf>,
    /// Emit stable JSON output.
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
struct DiffArgs {
    /// Baseline pack zip path.
    a: PathBuf,
    /// Candidate pack zip path.
    b: PathBuf,
    /// Emit stable JSON output.
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
struct ReplayArgs {
    arg: String,
    /// Emit stable JSON output.
    #[arg(long)]
    json: bool,
}

#[derive(Serialize)]
struct VerifyJsonOutput {
    ok: bool,
    pack_path: String,
    missing: Vec<String>,
    schema_errors: Vec<String>,
    hash_mismatches: Vec<String>,
    extras: Vec<String>,
    checked_entries_count: usize,
    timestamp_utc: String,
}

#[derive(Serialize)]
struct SchemaValidateJsonOutput {
    ok: bool,
    json_path: String,
    schema: String,
    schema_path: String,
    errors: Vec<String>,
    timestamp_utc: String,
}

#[derive(Serialize)]
struct DiffJsonOutput {
    ok: bool,
    a_path: String,
    b_path: String,
    added: Vec<String>,
    removed: Vec<String>,
    modified: Vec<String>,
    checked_entries_count: usize,
    timestamp_utc: String,
}

#[derive(Serialize)]
struct ReplayOutput {
    ok: bool,
    arg: String,
    notes: Vec<&'static str>,
    timestamp_utc: String,
}

#[derive(Clone)]
struct ZipEntryRecord {
    path: String,
    bytes: Vec<u8>,
    sha256: String,
}

#[derive(Clone)]
struct SealFileHash {
    rel_path: String,
    sha256: String,
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
        Command::Verify(args) => handle_verify(args),
        Command::SchemaValidate(args) => handle_schema_validate(args),
        Command::Diff(args) => handle_diff(args),
        Command::Replay(args) => {
            handle_replay(args)?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn handle_verify(args: VerifyArgs) -> Result<ExitCode, String> {
    let output = verify_pack_zip(&args.path);
    print_verify_output(args.json, &output)?;
    if output.ok {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(VERIFY_FAILURE_EXIT))
    }
}

fn verify_pack_zip(path: &Path) -> VerifyJsonOutput {
    let mut missing = BTreeSet::new();
    let mut schema_errors = BTreeSet::new();
    let mut hash_mismatches = BTreeSet::new();
    let mut extras = BTreeSet::new();
    let mut checked_entries_count = 0_usize;

    if !path.exists() {
        schema_errors.insert(format!("path does not exist: {}", path.display()));
        return verify_output(
            path,
            missing,
            schema_errors,
            hash_mismatches,
            extras,
            checked_entries_count,
        );
    }
    if !is_zip_path(path) {
        schema_errors.insert(format!("path is not a .zip file: {}", path.display()));
        return verify_output(
            path,
            missing,
            schema_errors,
            hash_mismatches,
            extras,
            checked_entries_count,
        );
    }

    let entries = match read_zip_entries(path) {
        Ok(entries) => entries,
        Err(err) => {
            schema_errors.insert(err);
            return verify_output(
                path,
                missing,
                schema_errors,
                hash_mismatches,
                extras,
                checked_entries_count,
            );
        }
    };

    let contracts_dir = match resolve_contracts_v1_dir() {
        Ok(dir) => Some(dir),
        Err(err) => {
            schema_errors.insert(err);
            None
        }
    };

    let root_entries = build_root_entry_map(&entries);

    for required in REQUIRED_PACK_FILES {
        let Some(entry) = root_entries.get(required.file_name) else {
            missing.insert(required.file_name.to_string());
            continue;
        };

        let value = match serde_json::from_slice::<Value>(&entry.bytes) {
            Ok(value) => value,
            Err(err) => {
                schema_errors.insert(format!("{}: invalid JSON: {err}", required.file_name));
                continue;
            }
        };

        let found_schema = value
            .get("schema_version")
            .and_then(Value::as_str)
            .unwrap_or("<missing>");
        if found_schema != required.schema_name {
            schema_errors.insert(format!(
                "{}: schema_version expected `{}` found `{}`",
                required.file_name, required.schema_name, found_schema
            ));
        }

        if let Some(dir) = &contracts_dir {
            let schema_path = dir.join(required.schema_file);
            match validate_json_against_schema_file(&schema_path, &value) {
                Ok(errors) => {
                    for error in errors {
                        schema_errors.insert(format!("{}: {error}", required.file_name));
                    }
                }
                Err(err) => {
                    schema_errors.insert(format!("{}: {err}", required.file_name));
                }
            }
        }
    }

    if let Some(seal_entry) = root_entries.get("epi.seal.v1.json") {
        match serde_json::from_slice::<Value>(&seal_entry.bytes) {
            Ok(seal_value) => {
                let seal_entries = parse_seal_entries(&seal_value, &mut schema_errors);
                if !seal_entries.is_empty() {
                    let actual_by_path = build_entry_hash_map(&entries);
                    let seal_by_path = build_seal_hash_map(&seal_entries);

                    for listed in &seal_entries {
                        match actual_by_path.get(&listed.rel_path) {
                            Some(actual_sha) => {
                                checked_entries_count += 1;
                                if actual_sha != &listed.sha256 {
                                    hash_mismatches.insert(format!(
                                        "{}: expected {} found {}",
                                        listed.rel_path, listed.sha256, actual_sha
                                    ));
                                }
                            }
                            None => {
                                missing.insert(format!("seal-listed-missing:{}", listed.rel_path));
                            }
                        }
                    }

                    for path in actual_by_path.keys() {
                        if !seal_by_path.contains_key(path) {
                            extras.insert(path.clone());
                        }
                    }
                }
            }
            Err(err) => {
                schema_errors.insert(format!("epi.seal.v1.json: invalid JSON: {err}"));
            }
        }
    }

    verify_output(
        path,
        missing,
        schema_errors,
        hash_mismatches,
        extras,
        checked_entries_count,
    )
}

fn verify_output(
    path: &Path,
    missing: BTreeSet<String>,
    schema_errors: BTreeSet<String>,
    hash_mismatches: BTreeSet<String>,
    extras: BTreeSet<String>,
    checked_entries_count: usize,
) -> VerifyJsonOutput {
    let missing_vec = missing.into_iter().collect::<Vec<String>>();
    let schema_errors_vec = schema_errors.into_iter().collect::<Vec<String>>();
    let hash_mismatches_vec = hash_mismatches.into_iter().collect::<Vec<String>>();
    let extras_vec = extras.into_iter().collect::<Vec<String>>();

    let ok =
        missing_vec.is_empty() && schema_errors_vec.is_empty() && hash_mismatches_vec.is_empty();
    VerifyJsonOutput {
        ok,
        pack_path: path_to_string(path),
        missing: missing_vec,
        schema_errors: schema_errors_vec,
        hash_mismatches: hash_mismatches_vec,
        extras: extras_vec,
        checked_entries_count,
        timestamp_utc: now_rfc3339_utc(),
    }
}

fn handle_schema_validate(args: SchemaValidateArgs) -> Result<ExitCode, String> {
    let mut errors = BTreeSet::new();

    let (schema_name, schema_path) =
        match resolve_schema_target(args.schema.as_deref(), args.schema_path.as_deref()) {
            Ok(value) => value,
            Err(err) => {
                errors.insert(err);
                (
                    "<unknown>".to_string(),
                    PathBuf::from("<unknown-schema-path>"),
                )
            }
        };

    let json_value = if args.json_path.exists() {
        match std::fs::read(&args.json_path) {
            Ok(bytes) => match serde_json::from_slice::<Value>(&bytes) {
                Ok(value) => Some(value),
                Err(err) => {
                    errors.insert(format!(
                        "invalid JSON in {}: {err}",
                        args.json_path.display()
                    ));
                    None
                }
            },
            Err(err) => {
                errors.insert(format!(
                    "failed to read {}: {err}",
                    args.json_path.display()
                ));
                None
            }
        }
    } else {
        errors.insert(format!("path does not exist: {}", args.json_path.display()));
        None
    };

    if let Some(value) = json_value {
        match validate_json_against_schema_file(&schema_path, &value) {
            Ok(schema_errors) => {
                for error in schema_errors {
                    errors.insert(error);
                }
            }
            Err(err) => {
                errors.insert(err);
            }
        }
    }

    let output = SchemaValidateJsonOutput {
        ok: errors.is_empty(),
        json_path: path_to_string(&args.json_path),
        schema: schema_name,
        schema_path: path_to_string(&schema_path),
        errors: errors.into_iter().collect(),
        timestamp_utc: now_rfc3339_utc(),
    };

    print_schema_validate_output(args.json, &output)?;
    if output.ok {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(VERIFY_FAILURE_EXIT))
    }
}

fn resolve_schema_target(
    schema_name: Option<&str>,
    schema_path: Option<&Path>,
) -> Result<(String, PathBuf), String> {
    match (schema_name, schema_path) {
        (Some(name), None) => {
            let schema_file =
                schema_file_for_name(name).ok_or_else(|| format!("unknown schema name: {name}"))?;
            let contracts_dir = resolve_contracts_v1_dir()?;
            let full_path = contracts_dir.join(schema_file);
            if !full_path.exists() {
                return Err(format!(
                    "schema file does not exist: {}",
                    full_path.display()
                ));
            }
            Ok((name.to_string(), full_path))
        }
        (None, Some(path)) => {
            if !path.exists() {
                return Err(format!("schema file does not exist: {}", path.display()));
            }
            let schema_name = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or("<custom-schema>")
                .replace(".schema", "");
            Ok((schema_name, normalize_lexical(path)))
        }
        (None, None) => Err("provide --schema <name> or --schema-path <file>".to_string()),
        (Some(_), Some(_)) => Err("use either --schema or --schema-path, not both".to_string()),
    }
}

fn handle_diff(args: DiffArgs) -> Result<ExitCode, String> {
    if !args.a.exists() {
        return Err(format!("path does not exist: {}", args.a.display()));
    }
    if !args.b.exists() {
        return Err(format!("path does not exist: {}", args.b.display()));
    }
    if !is_zip_path(&args.a) {
        return Err(format!("path is not a .zip file: {}", args.a.display()));
    }
    if !is_zip_path(&args.b) {
        return Err(format!("path is not a .zip file: {}", args.b.display()));
    }

    let a_map = read_seal_hash_map_from_pack(&args.a)?;
    let b_map = read_seal_hash_map_from_pack(&args.b)?;

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut modified = Vec::new();

    let mut all_paths: BTreeSet<String> = BTreeSet::new();
    all_paths.extend(a_map.keys().cloned());
    all_paths.extend(b_map.keys().cloned());

    for path in all_paths {
        match (a_map.get(&path), b_map.get(&path)) {
            (None, Some(_)) => added.push(path),
            (Some(_), None) => removed.push(path),
            (Some(a_hash), Some(b_hash)) if a_hash != b_hash => modified.push(path),
            _ => {}
        }
    }

    sort_strings_deterministically(&mut added);
    sort_strings_deterministically(&mut removed);
    sort_strings_deterministically(&mut modified);

    let output = DiffJsonOutput {
        ok: true,
        a_path: path_to_string(&args.a),
        b_path: path_to_string(&args.b),
        added,
        removed,
        modified,
        checked_entries_count: a_map.len() + b_map.len(),
        timestamp_utc: now_rfc3339_utc(),
    };

    print_diff_output(args.json, &output)?;
    Ok(ExitCode::SUCCESS)
}

fn read_seal_hash_map_from_pack(pack_path: &Path) -> Result<BTreeMap<String, String>, String> {
    let entries = read_zip_entries(pack_path)?;
    let root_entries = build_root_entry_map(&entries);
    let seal = root_entries
        .get("epi.seal.v1.json")
        .ok_or_else(|| "missing required file at zip root: epi.seal.v1.json".to_string())?;
    let seal_value = serde_json::from_slice::<Value>(&seal.bytes)
        .map_err(|err| format!("invalid JSON in epi.seal.v1.json: {err}"))?;

    let mut schema_errors = BTreeSet::new();
    let seal_entries = parse_seal_entries(&seal_value, &mut schema_errors);
    if !schema_errors.is_empty() {
        return Err(schema_errors
            .into_iter()
            .collect::<Vec<String>>()
            .join("; "));
    }
    Ok(build_seal_hash_map(&seal_entries))
}

fn handle_replay(args: ReplayArgs) -> Result<(), String> {
    let output = ReplayOutput {
        ok: true,
        arg: args.arg,
        notes: vec![REPLAY_NOTE],
        timestamp_utc: now_rfc3339_utc(),
    };

    if args.json {
        print_json(&output)?;
    } else {
        println!("OK: replay placeholder for {}", output.arg);
        println!("NOTE: {REPLAY_NOTE}");
    }
    Ok(())
}

fn build_root_entry_map(entries: &[ZipEntryRecord]) -> BTreeMap<String, &ZipEntryRecord> {
    let mut map = BTreeMap::new();
    for entry in entries {
        if !entry.path.contains('/') {
            map.insert(entry.path.clone(), entry);
        }
    }
    map
}

fn build_entry_hash_map(entries: &[ZipEntryRecord]) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for entry in entries {
        map.insert(entry.path.clone(), entry.sha256.clone());
    }
    map
}

fn build_seal_hash_map(entries: &[SealFileHash]) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for entry in entries {
        map.insert(entry.rel_path.clone(), entry.sha256.clone());
    }
    map
}

fn parse_seal_entries(seal: &Value, errors: &mut BTreeSet<String>) -> Vec<SealFileHash> {
    let mut output = Vec::new();
    let Some(seal_obj) = seal.as_object() else {
        errors.insert("epi.seal.v1.json: top-level value must be an object".to_string());
        return output;
    };

    let Some(pack_files) = seal_obj.get("pack_files") else {
        errors.insert("epi.seal.v1.json: missing `pack_files`".to_string());
        return output;
    };

    let Some(pack_file_list) = pack_files.as_array() else {
        errors.insert("epi.seal.v1.json: `pack_files` must be an array".to_string());
        return output;
    };

    for (index, item) in pack_file_list.iter().enumerate() {
        let Some(item_obj) = item.as_object() else {
            errors.insert(format!(
                "epi.seal.v1.json: pack_files[{index}] must be an object"
            ));
            continue;
        };

        let rel_path = match item_obj.get("rel_path").and_then(Value::as_str) {
            Some(path) if !path.trim().is_empty() => normalize_zip_path(path),
            _ => {
                errors.insert(format!(
                    "epi.seal.v1.json: pack_files[{index}].rel_path must be a non-empty string"
                ));
                continue;
            }
        };

        let sha256 = match item_obj.get("sha256").and_then(Value::as_str) {
            Some(value) if is_hex_sha256(value) => value.to_ascii_lowercase(),
            _ => {
                errors.insert(format!(
                    "epi.seal.v1.json: pack_files[{index}].sha256 must be a 64-char hex string"
                ));
                continue;
            }
        };

        output.push(SealFileHash { rel_path, sha256 });
    }

    let mut seen = BTreeSet::new();
    for item in &output {
        if !seen.insert(item.rel_path.clone()) {
            errors.insert(format!(
                "epi.seal.v1.json: duplicate pack_files.rel_path `{}`",
                item.rel_path
            ));
        }
    }

    let mut sorted = output
        .iter()
        .map(|item| item.rel_path.clone())
        .collect::<Vec<String>>();
    sort_strings_deterministically(&mut sorted);
    let listed = output
        .iter()
        .map(|item| item.rel_path.clone())
        .collect::<Vec<String>>();
    if listed != sorted {
        errors
            .insert("epi.seal.v1.json: `pack_files` must be sorted by canonical path".to_string());
    }

    output
}

fn validate_json_against_schema_file(
    schema_path: &Path,
    value: &Value,
) -> Result<Vec<String>, String> {
    let schema_bytes = std::fs::read(schema_path)
        .map_err(|err| format!("failed to read schema {}: {err}", schema_path.display()))?;
    let schema = serde_json::from_slice::<Value>(&schema_bytes)
        .map_err(|err| format!("invalid schema JSON {}: {err}", schema_path.display()))?;
    Ok(validate_document_top_level_against_schema(value, &schema))
}

// Gate E intentionally applies deterministic top-level checks only.
// Full nested JSON Schema evaluation is out of scope for this verifier.
fn validate_document_top_level_against_schema(document: &Value, schema: &Value) -> Vec<String> {
    let mut errors = BTreeSet::new();

    let Some(schema_obj) = schema.as_object() else {
        errors.insert("schema root must be a JSON object".to_string());
        return errors.into_iter().collect();
    };

    if let Some(type_spec) = schema_obj.get("type") {
        if !value_matches_type_spec(document, type_spec) {
            errors.insert(format!(
                "document type mismatch: expected {}, found {}",
                render_type_spec(type_spec),
                json_type_name(document)
            ));
        }
    }

    let Some(document_obj) = document.as_object() else {
        errors.insert("document root must be a JSON object".to_string());
        return errors.into_iter().collect();
    };

    let required_keys = schema_obj
        .get("required")
        .and_then(Value::as_array)
        .map(|keys| {
            let mut items = keys
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect::<Vec<String>>();
            sort_strings_deterministically(&mut items);
            items
        })
        .unwrap_or_default();

    for key in required_keys {
        if !document_obj.contains_key(&key) {
            errors.insert(format!("missing required key `{key}`"));
        }
    }

    let properties = schema_obj.get("properties").and_then(Value::as_object);
    let additional_allowed = schema_obj
        .get("additionalProperties")
        .and_then(Value::as_bool)
        .unwrap_or(true);

    let mut document_keys = document_obj.keys().cloned().collect::<Vec<String>>();
    sort_strings_deterministically(&mut document_keys);

    for key in document_keys {
        let value = match document_obj.get(&key) {
            Some(value) => value,
            None => continue,
        };

        match properties.and_then(|props| props.get(&key)) {
            Some(property_schema) => {
                validate_property_value(&key, value, property_schema, &mut errors);
            }
            None => {
                if !additional_allowed {
                    errors.insert(format!("unexpected key `{key}`"));
                }
            }
        }
    }

    errors.into_iter().collect()
}

fn validate_property_value(
    key: &str,
    value: &Value,
    property_schema: &Value,
    errors: &mut BTreeSet<String>,
) {
    if let Some(type_spec) = property_schema.get("type") {
        if !value_matches_type_spec(value, type_spec) {
            errors.insert(format!(
                "key `{key}` type mismatch: expected {}, found {}",
                render_type_spec(type_spec),
                json_type_name(value)
            ));
        }
    }

    if let Some(constraint) = property_schema.get("const") {
        if value != constraint {
            errors.insert(format!(
                "key `{key}` const mismatch: expected {}, found {}",
                render_json_short(constraint),
                render_json_short(value)
            ));
        }
    }

    if let Some(enum_values) = property_schema.get("enum").and_then(Value::as_array) {
        if !enum_values.iter().any(|candidate| candidate == value) {
            let expected = enum_values
                .iter()
                .map(render_json_short)
                .collect::<Vec<String>>()
                .join(", ");
            errors.insert(format!(
                "key `{key}` enum mismatch: expected one of [{expected}], found {}",
                render_json_short(value)
            ));
        }
    }
}

fn value_matches_type_spec(value: &Value, type_spec: &Value) -> bool {
    match type_spec {
        Value::String(name) => value_matches_type(value, name),
        Value::Array(items) => items
            .iter()
            .filter_map(Value::as_str)
            .any(|name| value_matches_type(value, name)),
        _ => true,
    }
}

fn value_matches_type(value: &Value, name: &str) -> bool {
    match name {
        "string" => value.is_string(),
        "number" => value.is_number(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "boolean" => value.is_boolean(),
        "object" => value.is_object(),
        "array" => value.is_array(),
        "null" => value.is_null(),
        _ => true,
    }
}

fn render_type_spec(type_spec: &Value) -> String {
    match type_spec {
        Value::String(name) => name.clone(),
        Value::Array(items) => items
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<&str>>()
            .join("|"),
        _ => "<unspecified>".to_string(),
    }
}

fn json_type_name(value: &Value) -> &'static str {
    if value.is_null() {
        "null"
    } else if value.is_boolean() {
        "boolean"
    } else if value.as_i64().is_some() || value.as_u64().is_some() {
        "integer"
    } else if value.is_number() {
        "number"
    } else if value.is_string() {
        "string"
    } else if value.is_array() {
        "array"
    } else {
        "object"
    }
}

fn render_json_short(value: &Value) -> String {
    match value {
        Value::String(text) => format!("\"{text}\""),
        _ => value.to_string(),
    }
}

fn read_zip_entries(path: &Path) -> Result<Vec<ZipEntryRecord>, String> {
    let file =
        File::open(path).map_err(|err| format!("failed to open {}: {err}", path.display()))?;
    let mut archive = ZipArchive::new(file)
        .map_err(|err| format!("failed to read ZIP archive {}: {err}", path.display()))?;

    let mut seen = BTreeSet::new();
    let mut entries = Vec::new();

    for idx in 0..archive.len() {
        let mut entry = archive
            .by_index(idx)
            .map_err(|err| format!("failed to inspect ZIP entry #{idx}: {err}"))?;

        let normalized = normalize_zip_path(entry.name());
        if normalized.is_empty() || entry.is_dir() || normalized.ends_with('/') {
            continue;
        }
        if !seen.insert(normalized.clone()) {
            return Err(format!("ZIP contains duplicate entry path: {normalized}"));
        }

        let mut bytes = Vec::new();
        entry
            .read_to_end(&mut bytes)
            .map_err(|err| format!("failed to read ZIP entry `{normalized}`: {err}"))?;

        entries.push(ZipEntryRecord {
            path: normalized,
            sha256: sha256_hex(&bytes),
            bytes,
        });
    }

    entries.sort_by(|left, right| compare_paths(&left.path, &right.path));
    Ok(entries)
}

fn resolve_contracts_v1_dir() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("EPI_CONTRACTS_V1_DIR") {
        let env_path = PathBuf::from(path);
        if env_path.is_dir() {
            return Ok(normalize_lexical(&env_path));
        }
        return Err(format!(
            "EPI_CONTRACTS_V1_DIR is not a directory: {}",
            env_path.display()
        ));
    }

    let mut candidate_roots = Vec::new();

    if let Ok(cwd) = std::env::current_dir() {
        for ancestor in cwd.ancestors() {
            candidate_roots.push(ancestor.to_path_buf());
        }
    }

    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(parent) = exe_path.parent() {
            for ancestor in parent.ancestors() {
                candidate_roots.push(ancestor.to_path_buf());
            }
        }
    }

    let mut seen = BTreeSet::new();
    for root in candidate_roots {
        let normalized_root = normalize_lexical(&root);
        let compare_key = path_compare_key(&normalized_root);
        if !seen.insert(compare_key) {
            continue;
        }

        let contracts_dir = normalized_root.join("contracts").join("v1");
        if contracts_dir.is_dir() {
            return Ok(contracts_dir);
        }
    }

    Err(
        "failed to locate contracts/v1 (set EPI_CONTRACTS_V1_DIR or run from workspace)"
            .to_string(),
    )
}

fn schema_file_for_name(schema_name: &str) -> Option<&'static str> {
    KNOWN_SCHEMAS
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(schema_name))
        .map(|(_, file)| *file)
}

fn print_verify_output(json: bool, output: &VerifyJsonOutput) -> Result<(), String> {
    if json {
        return print_json(output);
    }

    if output.ok {
        println!("PASS: verify {}", output.pack_path);
        println!("checked_entries_count={}", output.checked_entries_count);
        if !output.extras.is_empty() {
            println!("extras (allowed): {}", output.extras.join(", "));
        }
        return Ok(());
    }

    println!("FAIL: verify {}", output.pack_path);
    if !output.missing.is_empty() {
        println!("missing: {}", output.missing.join(", "));
    }
    if !output.schema_errors.is_empty() {
        println!("schema_errors: {}", output.schema_errors.join(" | "));
    }
    if !output.hash_mismatches.is_empty() {
        println!("hash_mismatches: {}", output.hash_mismatches.join(" | "));
    }
    if !output.extras.is_empty() {
        println!("extras (allowed): {}", output.extras.join(", "));
    }
    println!("checked_entries_count={}", output.checked_entries_count);
    Ok(())
}

fn print_schema_validate_output(
    json: bool,
    output: &SchemaValidateJsonOutput,
) -> Result<(), String> {
    if json {
        return print_json(output);
    }

    if output.ok {
        println!(
            "PASS: schema-validate {} against {}",
            output.json_path, output.schema
        );
    } else {
        println!(
            "FAIL: schema-validate {} against {}",
            output.json_path, output.schema
        );
        if !output.errors.is_empty() {
            println!("errors: {}", output.errors.join(" | "));
        }
    }
    Ok(())
}

fn print_diff_output(json: bool, output: &DiffJsonOutput) -> Result<(), String> {
    if json {
        return print_json(output);
    }

    if output.added.is_empty() && output.removed.is_empty() && output.modified.is_empty() {
        println!(
            "PASS: diff {} vs {} (no changes)",
            output.a_path, output.b_path
        );
    } else {
        println!(
            "OK: diff {} vs {} (added={}, removed={}, modified={})",
            output.a_path,
            output.b_path,
            output.added.len(),
            output.removed.len(),
            output.modified.len()
        );
        if !output.added.is_empty() {
            println!("added: {}", output.added.join(", "));
        }
        if !output.removed.is_empty() {
            println!("removed: {}", output.removed.join(", "));
        }
        if !output.modified.is_empty() {
            println!("modified: {}", output.modified.join(", "));
        }
    }
    Ok(())
}

fn print_json<T: Serialize>(output: &T) -> Result<(), String> {
    let json = serde_json::to_string_pretty(output)
        .map_err(|err| format!("failed to serialize JSON output: {err}"))?;
    println!("{json}");
    Ok(())
}

fn now_rfc3339_utc() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn normalize_zip_path(path: &str) -> String {
    path.replace('\\', "/")
        .trim_start_matches("./")
        .trim_start_matches('/')
        .to_string()
}

fn compare_paths(left: &str, right: &str) -> Ordering {
    left.to_ascii_lowercase()
        .cmp(&right.to_ascii_lowercase())
        .then_with(|| left.cmp(right))
}

fn sort_strings_deterministically(values: &mut [String]) {
    values.sort_by(|left, right| compare_paths(left, right));
}

fn is_zip_path(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("zip"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    hex::encode(digest)
}

fn is_hex_sha256(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

fn normalize_lexical(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            std::path::Component::RootDir => normalized.push(component.as_os_str()),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                let _ = normalized.pop();
            }
            std::path::Component::Normal(segment) => normalized.push(segment),
        }
    }
    normalized
}

fn path_compare_key(path: &Path) -> String {
    normalize_lexical(path)
        .to_string_lossy()
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_ascii_lowercase()
}
