use clap::{Parser, Subcommand};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const VERIFY_NOTE: &str = "v0 placeholder: pack structure not enforced yet";
const SCHEMA_VALIDATE_NOTE: &str = "v0 placeholder: schema rules not enforced yet";
const DIFF_NOTE: &str = "v0 placeholder: diff engine not implemented yet";
const REPLAY_NOTE: &str = "v0 placeholder: replay engine not implemented yet";

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
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("ERR: {err}");
            ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::Verify { path, json } => handle_verify(path, json),
        Command::SchemaValidate { path, json } => handle_schema_validate(path, json),
        Command::Diff { a, b, json } => handle_diff(a, b, json),
        Command::Replay { arg, json } => handle_replay(arg, json),
    }
}

fn handle_verify(path: PathBuf, json: bool) -> Result<(), String> {
    ensure_exists(&path)?;
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
    Ok(())
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

fn print_json<T: Serialize>(output: &T) -> Result<(), String> {
    let json = serde_json::to_string_pretty(output)
        .map_err(|e| format!("failed to serialize JSON output: {e}"))?;
    println!("{json}");
    Ok(())
}
