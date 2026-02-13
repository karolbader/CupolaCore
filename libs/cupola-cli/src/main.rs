use anyhow::Result;
use clap::{Parser, Subcommand};
use cupola_cas::CasStore;
use cupola_core::{
    app_data_root, deterministic_vault_id_from_root_path, now_ns, vault_indexes_root,
    ManifestArtifactV0, ManifestV0, VaultId, VerifyDiffKind,
};
use cupola_db::DbPool;
use cupola_protocol::{
    EnvelopeDTO, ReplayCheckDTO, ReplayReportDTO, SearchHitDTO, SearchResponseDTO, ToolInfoDTO,
    VaultInfoDTO,
};
use serde::Serialize;
use sqlx::Row;
use std::io::Write;
use std::path::PathBuf;
#[derive(Parser, Debug)]
#[command(name = "cupola", version, about = "Cupola CLI (v0)")]
struct Cli {
    /// Override application data root (portable mode). Default: %APPDATA%\Cupola
    #[arg(long, global = true, value_name = "DIR")]
    app_root: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Hash + index all files under a vault root (writes to db + cas under app data).
    Hash {
        /// Absolute or relative path to the vault root folder.
        #[arg(long)]
        vault: PathBuf,
    },

    /// Show vault status (counts + last journal stage).
    Status {
        /// Absolute or relative path to the vault root folder.
        #[arg(long)]
        vault: PathBuf,

        /// Emit JSON (machine-readable).
        #[arg(long)]
        json: bool,
    },

    /// Search chunks using Tantivy BM25 when index is present; fallback to SQLite LIKE.
    Search {
        /// Absolute or relative path to the vault root folder.
        #[arg(long)]
        vault: PathBuf,

        /// Query text (substring match).
        #[arg(long)]
        q: String,

        /// Max results.
        #[arg(long, default_value_t = 20)]
        limit: u32,

        /// Emit JSON (machine-readable).
        #[arg(long)]
        json: bool,
    },

    /// Freeze current vault content into a manifest JSON.
    Freeze {
        /// Absolute or relative path to the vault root folder.
        #[arg(long)]
        vault: PathBuf,
        /// Output path for manifest JSON.
        #[arg(long)]
        out: PathBuf,
    },

    /// Verify vault content against a manifest JSON.
    Verify {
        /// Absolute or relative path to the vault root folder.
        #[arg(long)]
        vault: PathBuf,
        /// Input manifest JSON path.
        #[arg(long)]
        manifest: PathBuf,

        /// Emit JSON (machine-readable).
        #[arg(long)]
        json: bool,
    },

    /// Replay (validation-only): check required artifacts exist for a manifest/vault pair.
    Replay {
        /// Absolute or relative path to the vault root folder.
        #[arg(long)]
        vault: PathBuf,
        /// Input manifest JSON path.
        #[arg(long)]
        manifest: PathBuf,
        /// Emit JSON (machine-readable).
        #[arg(long)]
        json: bool,
    },

    /// One-command local proof loop (hash/search/freeze/verify/replay).
    Demo {
        /// Absolute or relative path to the vault root folder.
        #[arg(long)]
        vault: PathBuf,
        /// Emit JSON (machine-readable).
        #[arg(long)]
        json: bool,
    },

    /// Compute BLAKE3 of a single file (v0 utility).
    Blake3 {
        /// Path to a file to hash.
        #[arg(long)]
        file: PathBuf,
    },
}

fn resolve_app_root(app_root: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = app_root {
        let abs = if path.is_absolute() {
            path
        } else {
            std::env::current_dir()?.join(path)
        };
        std::fs::create_dir_all(&abs)?;
        return Ok(abs.canonicalize().unwrap_or(abs));
    }
    app_data_root()
}

fn resolve_demo_app_root(
    cli_app_root: Option<PathBuf>,
    vault: &std::path::Path,
) -> Result<PathBuf> {
    if let Some(p) = cli_app_root {
        return resolve_app_root(Some(p));
    }
    resolve_app_root(Some(vault.join(".cupola_app")))
}

fn is_lock_or_perm_error(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    m.contains("failed to acquire lockfile")
        || m.contains("tantivy error")
        || m.contains("database is locked")
        || m.contains("sqlite_busy")
        || m.contains("access is denied")
        || m.contains("os error 5")
        || m.contains("permissiondenied")
        || m.contains("permission denied")
}

fn print_app_root_hint_if_relevant(err: &anyhow::Error, app_root: &std::path::Path) {
    let msg = format!("{:#}", err);
    if is_lock_or_perm_error(&msg) {
        eprintln!(
            "App root locked or not writable: {}. Close other Cupola processes or rerun with --app-root E:\\CupolaSession",
            app_root.display()
        );
    }
}

async fn ensure_vault(db: &DbPool, vault_root: &std::path::Path) -> anyhow::Result<VaultId> {
    let root_path = vault_root.to_string_lossy().to_string();

    // 1) Try existing by unique root_path
    let existing = sqlx::query("SELECT id FROM vaults WHERE root_path = ?1")
        .bind(&root_path)
        .fetch_optional(db.pool())
        .await?;

    if let Some(row) = existing {
        let id_str: String = row.try_get("id")?;
        let id = uuid::Uuid::parse_str(&id_str)?;
        return Ok(VaultId(id));
    }

    // 2) Insert new vault row
    let id = {
        let mut h = blake3::Hasher::new();
        h.update(b"cupola:vault:v1\0");
        h.update(root_path.as_bytes());
        let out = h.finalize();
        let mut b = [0u8; 16];
        b.copy_from_slice(&out.as_bytes()[0..16]);
        b[6] = (b[6] & 0x0f) | 0x40; // version
        b[8] = (b[8] & 0x3f) | 0x80; // variant
        uuid::Uuid::from_bytes(b)
    };
    let name = vault_root
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("vault")
        .to_string();

    sqlx::query(
        "INSERT INTO vaults (id, root_path, name, created_at, config_json) VALUES (?1, ?2, ?3, ?4, '{}')"
    )
    .bind(id.to_string())
    .bind(&root_path)
    .bind(&name)
    .bind(now_ns())
    .execute(db.pool())
    .await?;

    Ok(VaultId(id))
}

fn row_to_search_hit(r: &sqlx::sqlite::SqliteRow) -> anyhow::Result<SearchHitDTO> {
    let rel_path: String = r.try_get("rel_path")?;
    let excerpt: String = r.try_get("excerpt")?;
    let chunk_id: String = r.try_get("chunk_id")?;
    let raw_blob_id: String = r.try_get("raw_blob_id")?;
    let chunk_blob_id: String = r.try_get("chunk_blob_id")?;
    let mtime_ns: i64 = r.try_get("mtime_ns")?;
    let file_type: Option<String> = r.try_get("file_type")?;
    let start_line: Option<i64> = r.try_get("start_line")?;
    let end_line: Option<i64> = r.try_get("end_line")?;
    Ok(SearchHitDTO {
        chunk_id,
        rel_path,
        file_type: file_type.unwrap_or_else(|| "unknown".to_string()),
        mtime_ns,
        raw_blob_id,
        chunk_blob_id,
        start_line,
        end_line,
        excerpt: excerpt.replace('\n', " "),
    })
}

fn print_search_hit(hit: &SearchHitDTO) {
    let mut line_info = String::new();
    if let (Some(start), Some(end)) = (hit.start_line, hit.end_line) {
        line_info = format!("{}-{}", start, end);
    }
    println!(
        "{} | {} | [{}] | {} | {} | {} | {} | {}",
        hit.chunk_id,
        hit.rel_path,
        hit.file_type,
        hit.mtime_ns,
        hit.raw_blob_id,
        hit.chunk_blob_id,
        line_info,
        hit.excerpt,
    );
}

async fn freeze_vault_with_app_root(vault: PathBuf, out: PathBuf, app_root: PathBuf) -> Result<()> {
    let vault_root = vault.canonicalize()?;
    let db_path = app_root.join("db.sqlite");
    let db = DbPool::new(&db_path).await?;

    let vault_id = ensure_vault(&db, &vault_root).await?;
    let vdir = app_root.join("vaults").join(vault_id.0.to_string());
    let cas_root = vdir.join("cas");
    tokio::fs::create_dir_all(&cas_root).await?;
    let cas = CasStore::new(cas_root);

    let items = cupola_indexer::crawl_sorted(&vault_root)?;
    let mut artifacts = Vec::with_capacity(items.len());

    for it in items {
        let out = cupola_indexer::stages::hash::HashStage::run(
            &db,
            &cas,
            &vault_id,
            &vault_root,
            &it.abs_path,
        )
        .await?;
        artifacts.push(ManifestArtifactV0 {
            rel_path: it.rel_path,
            raw_blob_id: out.raw_blob_id.as_str().to_string(),
            mtime_ns: out.mtime_ns,
            file_size: out.file_size as i64,
            file_type: out.file_type,
            artifact_version_id: out.artifact_version_id,
        });
    }

    artifacts.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));

    let manifest = ManifestV0 {
        vault_id: vault_id.0.to_string(),
        root: vault_root.to_string_lossy().to_string(),
        created_at: now_ns(),
        artifacts,
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    if let Some(parent) = out.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(&out, &manifest_bytes).await?;

    let manifest_blob_id = cas.put(&manifest_bytes).await?;
    sqlx::query("INSERT OR IGNORE INTO blobs (hash, size, cas_key) VALUES (?1, ?2, ?3)")
        .bind(manifest_blob_id.as_str())
        .bind(manifest_bytes.len() as i64)
        .bind(manifest_blob_id.as_str())
        .execute(db.pool())
        .await?;

    sqlx::query(
        "INSERT INTO freezes (id, vault_id, created_at, manifest_blob_id) VALUES (?1, ?2, ?3, ?4)",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(vault_id.0.to_string())
    .bind(manifest.created_at)
    .bind(manifest_blob_id.as_str())
    .execute(db.pool())
    .await?;

    println!(
        "OK: froze {} artifacts -> {}",
        manifest.artifacts.len(),
        out.display()
    );
    Ok(())
}

async fn rebuild_search_index_for_vault(
    db: &DbPool,
    cas: &CasStore,
    vault_id: &str,
    index_dir: &std::path::Path,
) -> Result<usize> {
    if index_dir.exists() {
        let _ = std::fs::remove_dir_all(index_dir);
    }
    let si = cupola_search::SearchIndex::new(index_dir)?;

    let rows = sqlx::query(
        r#"
        SELECT
            c.id as chunk_id,
            c.chunk_blob_id as chunk_blob_id,
            c.excerpt as excerpt
        FROM chunks c
        JOIN artifact_versions av ON av.id = c.artifact_version_id
        JOIN artifacts a ON a.id = av.artifact_id
        WHERE a.vault_id = ?1
        ORDER BY c.id ASC
        "#,
    )
    .bind(vault_id)
    .fetch_all(db.pool())
    .await?;

    for r in &rows {
        let chunk_id: String = r.try_get("chunk_id")?;
        let chunk_blob_id: String = r.try_get("chunk_blob_id")?;
        let excerpt: String = r.try_get("excerpt")?;
        let content = match cas
            .get(&cupola_cas::BlobId::from_hash(chunk_blob_id.clone()))
            .await
        {
            Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
            Err(_) => excerpt,
        };
        let _ = si.ingest_document(&chunk_id, &content)?;
    }
    Ok(rows.len())
}

async fn verify_vault_with_app_root(
    vault: PathBuf,
    manifest_path: PathBuf,
    _app_root: PathBuf,
    json: bool,
) -> Result<()> {
    let vault_root = vault.canonicalize()?;
    let report = cupola_core::verify_manifest(&vault_root, &manifest_path).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        if report.ok {
            return Ok(());
        }
        anyhow::bail!("verify failed: {} mismatch(es)", report.mismatches.len());
    }

    if report.ok {
        println!("OK: verify passed ({} artifacts)", report.artifact_count);
        return Ok(());
    }

    for m in &report.mismatches {
        match m.kind {
            VerifyDiffKind::Modified => {
                let expected = m.expected_raw_blob_id.as_deref().unwrap_or("");
                let actual = m.actual_raw_blob_id.as_deref().unwrap_or("");
                println!(
                    "ERR: MODIFIED {} expected={} actual={}",
                    m.rel_path, expected, actual
                );
            }
            VerifyDiffKind::Missing => {
                println!("ERR: MISSING {}", m.rel_path);
            }
            VerifyDiffKind::Extra => {
                println!("ERR: EXTRA {}", m.rel_path);
            }
        }
    }
    anyhow::bail!("verify failed: {} mismatch(es)", report.mismatches.len());
}

fn replay_validation_report(
    vault: PathBuf,
    manifest_path: PathBuf,
    app_root: PathBuf,
) -> ReplayReportDTO {
    let vault_path_s = vault.to_string_lossy().to_string();
    let manifest_path_s = manifest_path.to_string_lossy().to_string();

    let mut checks: Vec<ReplayCheckDTO> = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    let vault_exists = vault.is_dir();
    checks.push(ReplayCheckDTO {
        name: "vault_exists".to_string(),
        ok: vault_exists,
        detail: if vault_exists {
            None
        } else {
            Some("vault path does not exist or is not a directory".to_string())
        },
    });
    if !vault_exists {
        errors.push("vault path missing".to_string());
    }

    let manifest_exists = manifest_path.is_file();
    checks.push(ReplayCheckDTO {
        name: "manifest_exists".to_string(),
        ok: manifest_exists,
        detail: if manifest_exists {
            None
        } else {
            Some("manifest file does not exist".to_string())
        },
    });
    if !manifest_exists {
        errors.push("manifest path missing".to_string());
    }

    let parsed_manifest = if manifest_exists {
        std::fs::read(&manifest_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<ManifestV0>(&bytes).ok())
    } else {
        None
    };
    let manifest_valid_json = parsed_manifest.is_some();
    checks.push(ReplayCheckDTO {
        name: "manifest_valid_json".to_string(),
        ok: manifest_valid_json,
        detail: if manifest_valid_json {
            None
        } else {
            Some("manifest is not valid ManifestV0 JSON".to_string())
        },
    });
    if !manifest_valid_json {
        errors.push("manifest json invalid".to_string());
    }

    let db_exists = app_root.join("db.sqlite").is_file();
    checks.push(ReplayCheckDTO {
        name: "db_exists".to_string(),
        ok: db_exists,
        detail: if db_exists {
            None
        } else {
            Some("app db file missing".to_string())
        },
    });
    if !db_exists {
        errors.push("db file missing".to_string());
    }

    let vault_root_for_id = if vault_exists {
        vault
            .canonicalize()
            .unwrap_or_else(|_| vault.clone())
            .to_string_lossy()
            .to_string()
    } else {
        vault_path_s.clone()
    };
    let vault_id = deterministic_vault_id_from_root_path(&vault_root_for_id);
    let index_dir = vault_indexes_root(&app_root, &vault_id).join("tantivy");
    let index_exists = index_dir.is_dir();
    checks.push(ReplayCheckDTO {
        name: "index_dir_exists".to_string(),
        ok: index_exists,
        detail: if index_exists {
            None
        } else {
            Some(format!("index dir missing at {}", index_dir.display()))
        },
    });
    if !index_exists {
        errors.push("index dir missing".to_string());
    }

    let mut missing_blob_ids: Vec<String> = Vec::new();
    if let Some(manifest) = &parsed_manifest {
        let cas_root = app_root.join("vaults").join(&manifest.vault_id).join("cas");
        let cas = CasStore::new(cas_root);
        for a in &manifest.artifacts {
            let blob_path = cas.shard_path(&a.raw_blob_id);
            if !blob_path.is_file() {
                missing_blob_ids.push(a.raw_blob_id.clone());
            }
        }
    }
    let cas_ok = manifest_valid_json && missing_blob_ids.is_empty();
    checks.push(ReplayCheckDTO {
        name: "cas_blobs_exist".to_string(),
        ok: cas_ok,
        detail: if !manifest_valid_json {
            Some("manifest invalid; CAS check skipped".to_string())
        } else if missing_blob_ids.is_empty() {
            None
        } else {
            Some(format!(
                "missing={} total={}",
                missing_blob_ids.len(),
                parsed_manifest
                    .as_ref()
                    .map(|m| m.artifacts.len())
                    .unwrap_or_default()
            ))
        },
    });
    if !cas_ok {
        if !manifest_valid_json {
            errors.push("cas check skipped due to invalid manifest".to_string());
        } else {
            for id in missing_blob_ids.iter().take(20) {
                errors.push(format!("missing blob: {id}"));
            }
            if missing_blob_ids.len() > 20 {
                errors.push(format!(
                    "... {} more missing blobs",
                    missing_blob_ids.len() - 20
                ));
            }
        }
    }

    ReplayReportDTO {
        ok: errors.is_empty(),
        vault_path: vault_path_s,
        manifest_path: manifest_path_s,
        checks,
        errors,
    }
}

#[derive(Serialize)]
struct DemoStep {
    name: String,
    ok: bool,
    detail: Option<String>,
}

#[derive(Serialize)]
struct DemoSummary {
    #[serde(flatten)]
    env: EnvelopeDTO,
    ok: bool,
    steps: Vec<DemoStep>,
    manifest_path: String,
    search_sample: Option<SearchHitDTO>,
}

async fn run_demo(vault: PathBuf, json: bool, app_root: PathBuf) -> Result<()> {
    let vault_path = vault.to_string_lossy().to_string();
    let vault_root = vault.canonicalize()?;
    let mut steps: Vec<DemoStep> = Vec::new();

    let demo_file = vault_root.join("_tmp").join("demo.txt");
    if !demo_file.exists() {
        if let Some(parent) = demo_file.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&demo_file, "alpha beta gamma")?;
        steps.push(DemoStep {
            name: "ensure_demo_file".to_string(),
            ok: true,
            detail: Some("created _tmp/demo.txt".to_string()),
        });
    } else {
        steps.push(DemoStep {
            name: "ensure_demo_file".to_string(),
            ok: true,
            detail: Some("reused _tmp/demo.txt".to_string()),
        });
    }

    let db_path = app_root.join("db.sqlite");
    let db = DbPool::new(&db_path).await?;
    let vault_id = ensure_vault(&db, &vault_root).await?;
    let vdir = app_root.join("vaults").join(vault_id.0.to_string());
    let cas_root = vdir.join("cas");
    tokio::fs::create_dir_all(&cas_root).await?;
    let cas = CasStore::new(cas_root);

    let pipe = cupola_indexer::pipeline::Pipeline::new(
        DbPool::new(&db_path).await?,
        cas.clone(),
        vault_id.clone(),
        vault_root.clone(),
    );
    let _ = pipe.run_hash_all().await?;
    let vid = vault_id.0.to_string();
    let index_dir = vault_indexes_root(&app_root, &vault_id).join("tantivy");
    let _ = rebuild_search_index_for_vault(&db, &cas, &vid, &index_dir).await?;
    steps.push(DemoStep {
        name: "hash".to_string(),
        ok: true,
        detail: None,
    });

    let search_hits = cupola_search::SearchIndex::new(&index_dir)?.search("alpha", 5)?;
    let search_sample = if let Some(first_chunk_id) = search_hits.first() {
        let row = sqlx::query(
            r#"
            SELECT
                a.rel_path as rel_path,
                c.excerpt as excerpt,
                c.id as chunk_id,
                av.raw_blob_id as raw_blob_id,
                c.chunk_blob_id as chunk_blob_id,
                av.mtime_ns as mtime_ns,
                av.file_type as file_type,
                c.start_line as start_line,
                c.end_line as end_line
            FROM chunks c
            JOIN artifact_versions av ON av.id = c.artifact_version_id
            JOIN artifacts a ON a.id = av.artifact_id
            WHERE a.vault_id = ?1 AND c.id = ?2
            LIMIT 1
            "#,
        )
        .bind(&vid)
        .bind(first_chunk_id)
        .fetch_optional(db.pool())
        .await?;
        if let Some(r) = row {
            Some(row_to_search_hit(&r)?)
        } else {
            None
        }
    } else {
        None
    };
    steps.push(DemoStep {
        name: "search".to_string(),
        ok: !search_hits.is_empty(),
        detail: if search_hits.is_empty() {
            Some("no hits for alpha".to_string())
        } else {
            None
        },
    });

    let manifest_path = app_root.join("demo.manifest.json");
    let freeze_db = DbPool::new(&db_path).await?;
    let freeze_vault_id = ensure_vault(&freeze_db, &vault_root).await?;
    let freeze_vdir = app_root.join("vaults").join(freeze_vault_id.0.to_string());
    let freeze_cas_root = freeze_vdir.join("cas");
    tokio::fs::create_dir_all(&freeze_cas_root).await?;
    let freeze_cas = CasStore::new(freeze_cas_root);
    let items = cupola_indexer::crawl_sorted(&vault_root)?;
    let mut artifacts = Vec::with_capacity(items.len());
    for it in items {
        let out = cupola_indexer::stages::hash::HashStage::run(
            &freeze_db,
            &freeze_cas,
            &freeze_vault_id,
            &vault_root,
            &it.abs_path,
        )
        .await?;
        artifacts.push(ManifestArtifactV0 {
            rel_path: it.rel_path,
            raw_blob_id: out.raw_blob_id.as_str().to_string(),
            mtime_ns: out.mtime_ns,
            file_size: out.file_size as i64,
            file_type: out.file_type,
            artifact_version_id: out.artifact_version_id,
        });
    }
    artifacts.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    let manifest = ManifestV0 {
        vault_id: freeze_vault_id.0.to_string(),
        root: vault_root.to_string_lossy().to_string(),
        created_at: now_ns(),
        artifacts,
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    if let Some(parent) = manifest_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(&manifest_path, &manifest_bytes).await?;
    let manifest_blob_id = freeze_cas.put(&manifest_bytes).await?;
    sqlx::query("INSERT OR IGNORE INTO blobs (hash, size, cas_key) VALUES (?1, ?2, ?3)")
        .bind(manifest_blob_id.as_str())
        .bind(manifest_bytes.len() as i64)
        .bind(manifest_blob_id.as_str())
        .execute(freeze_db.pool())
        .await?;
    sqlx::query(
        "INSERT INTO freezes (id, vault_id, created_at, manifest_blob_id) VALUES (?1, ?2, ?3, ?4)",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(freeze_vault_id.0.to_string())
    .bind(manifest.created_at)
    .bind(manifest_blob_id.as_str())
    .execute(freeze_db.pool())
    .await?;
    steps.push(DemoStep {
        name: "freeze".to_string(),
        ok: true,
        detail: None,
    });

    let verify_pass = cupola_core::verify_manifest(&vault_root, &manifest_path).await?;
    steps.push(DemoStep {
        name: "verify_pass".to_string(),
        ok: verify_pass.ok,
        detail: if verify_pass.ok {
            None
        } else {
            Some("expected pass but got mismatches".to_string())
        },
    });

    {
        let mut f = std::fs::OpenOptions::new().append(true).open(&demo_file)?;
        f.write_all(b" delta")?;
    }
    let verify_fail = cupola_core::verify_manifest(&vault_root, &manifest_path).await?;
    let modified_expected = verify_fail
        .mismatches
        .iter()
        .any(|m| matches!(m.kind, VerifyDiffKind::Modified) && m.rel_path == "_tmp/demo.txt");
    steps.push(DemoStep {
        name: "verify_fail_expected".to_string(),
        ok: !verify_fail.ok && modified_expected,
        detail: if !verify_fail.ok && modified_expected {
            None
        } else {
            Some("expected modified mismatch for _tmp/demo.txt".to_string())
        },
    });

    let replay = replay_validation_report(vault_root.clone(), manifest_path.clone(), app_root);
    steps.push(DemoStep {
        name: "replay".to_string(),
        ok: replay.ok,
        detail: if replay.ok {
            None
        } else {
            Some(format!("replay errors={}", replay.errors.len()))
        },
    });

    let summary = DemoSummary {
        env: EnvelopeDTO {
            schema_version: "1.0.0".to_string(),
            tool: ToolInfoDTO {
                name: "cupola-cli".to_string(),
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
                build: if cfg!(debug_assertions) {
                    "debug".to_string()
                } else {
                    "release".to_string()
                },
                platform: "windows-x64".to_string(),
            },
            generated_at: chrono::Utc::now().to_rfc3339(),
            vault: VaultInfoDTO {
                vault_path: vault_path.clone(),
                vault_id: None,
            },
        },
        ok: steps.iter().all(|s| s.ok),
        steps,
        manifest_path: manifest_path.to_string_lossy().to_string(),
        search_sample,
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        for s in &summary.steps {
            if s.ok {
                println!("OK: {}", s.name);
            } else if let Some(detail) = &s.detail {
                println!("ERR: {} {}", s.name, detail);
            } else {
                println!("ERR: {}", s.name);
            }
        }
    }

    if !summary.ok {
        anyhow::bail!("demo failed");
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let Cli { cmd, app_root } = Cli::parse();
    let resolved_app_root = match &cmd {
        Command::Demo { vault, .. } => resolve_demo_app_root(app_root.clone(), vault)?,
        _ => resolve_app_root(app_root.clone())?,
    };

    let result: Result<()> = async {
        match cmd {
            Command::Hash { vault } => {
                let vault_root = vault.canonicalize()?;
                let app_root = resolved_app_root.clone();

                // Global DB for all vaults (v0): app_root\db.sqlite
                let db_path = app_root.join("db.sqlite");
                let db = DbPool::new(&db_path).await?;

                // Vault identity lives in DB (unique by root_path). This makes reruns stable.
                let vault_id = ensure_vault(&db, &vault_root).await?;

                // Per-vault storage layout
                let vdir = app_root.join("vaults").join(vault_id.0.to_string());
                let cas_root = vdir.join("cas");
                tokio::fs::create_dir_all(&cas_root).await?;
                let cas = CasStore::new(cas_root);

                let pipe = cupola_indexer::pipeline::Pipeline::new(db, cas, vault_id, vault_root);
                let n = pipe.run_hash_all().await?;

                let vid = pipe.vault_id.0.to_string();
                let index_dir = vault_indexes_root(&app_root, &pipe.vault_id).join("tantivy");
                let _ =
                    rebuild_search_index_for_vault(&pipe.db, &pipe.cas, &vid, &index_dir).await?;

                println!("OK: hashed {} files", n);
            }
            Command::Blake3 { file } => {
                use std::io::Read;

                let path = file.canonicalize()?;
                let mut f = std::fs::File::open(&path)?;
                let mut h = blake3::Hasher::new();
                let mut buf = vec![0u8; 1024 * 1024];

                loop {
                    let n = f.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    h.update(&buf[..n]);
                }

                let hex = h.finalize().to_hex().to_string();
                println!("BLAKE3 {} {}", hex, path.display());
            }
            Command::Status { vault, json } => {
                let vault_root = vault.canonicalize()?;
                let app_root = resolved_app_root.clone();

                let db_path = app_root.join("db.sqlite");
                let db = DbPool::new(&db_path).await?;

                let vault_id = ensure_vault(&db, &vault_root).await?;
                let vid = vault_id.0.to_string();

                let artifacts: i64 =
                    sqlx::query_scalar("SELECT COUNT(*) FROM artifacts WHERE vault_id = ?1")
                        .bind(&vid)
                        .fetch_one(db.pool())
                        .await?;

                let versions: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM artifact_versions av
                 JOIN artifacts a ON a.id = av.artifact_id
                 WHERE a.vault_id = ?1",
                )
                .bind(&vid)
                .fetch_one(db.pool())
                .await?;

                let chunks: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM chunks c
                 JOIN artifact_versions av ON av.id = c.artifact_version_id
                 JOIN artifacts a ON a.id = av.artifact_id
                 WHERE a.vault_id = ?1",
                )
                .bind(&vid)
                .fetch_one(db.pool())
                .await?;

                let journal = sqlx::query(
                    "SELECT state, stage, updated_at FROM ingestion_journal
                 WHERE vault_id = ?1
                 ORDER BY updated_at DESC
                 LIMIT 1",
                )
                .bind(&vid)
                .fetch_optional(db.pool())
                .await?;
                if json {
                    // v0: hand-rolled JSON (no extra deps). Keep it stable.
                    let root_s = vault_root.to_string_lossy().replace('\\', "\\\\");
                    let (j_state, j_stage, j_updated_at) = if let Some(r) = &journal {
                        (
                            r.try_get::<String, _>("state")?,
                            r.try_get::<String, _>("stage")?,
                            r.try_get::<i64, _>("updated_at")?,
                        )
                    } else {
                        ("".to_string(), "".to_string(), 0i64)
                    };

                    println!(
                        "{{\"vault_id\":\"{}\",\"root\":\"{}\",\"artifacts\":{},\"artifact_versions\":{},\"chunks\":{},\"journal_state\":\"{}\",\"journal_stage\":\"{}\",\"journal_updated_at\":{}}}",
                        vid,
                        root_s,
                        artifacts,
                        versions,
                        chunks,
                        j_state,
                        j_stage,
                        j_updated_at
                    );
                    return Ok(());
                }
                println!("vault_id: {}", vid);
                println!("root: {}", vault_root.display());
                println!("artifacts: {}", artifacts);
                println!("artifact_versions: {}", versions);
                println!("chunks: {}", chunks);

                if let Some(r) = journal {
                    let state: String = r.try_get("state")?;
                    let stage: String = r.try_get("stage")?;
                    let updated_at: i64 = r.try_get("updated_at")?;
                    println!("journal_latest: {} / {} @ {}", state, stage, updated_at);
                } else {
                    println!("journal_latest: (none)");
                }
            }

            Command::Search {
                vault,
                q,
                limit,
                json,
            } => {
                let vault_root = vault.canonicalize()?;
                let vault_path = vault.to_string_lossy().to_string();
                let app_root = resolved_app_root.clone();

            // Global DB for all vaults (v0): app_root\db.sqlite
            let db_path = app_root.join("db.sqlite");
            let db = DbPool::new(&db_path).await?;

            let vault_id = ensure_vault(&db, &vault_root).await?;

            let vid = vault_id.0.to_string();
            let index_dir = vault_indexes_root(&app_root, &vault_id).join("tantivy");
            let mut hits: Vec<SearchHitDTO> = Vec::new();
            let make_env = || EnvelopeDTO {
                schema_version: "1.0.0".to_string(),
                tool: ToolInfoDTO {
                    name: "cupola-cli".to_string(),
                    version: Some(env!("CARGO_PKG_VERSION").to_string()),
                    build: if cfg!(debug_assertions) {
                        "debug".to_string()
                    } else {
                        "release".to_string()
                    },
                    platform: "windows-x64".to_string(),
                },
                generated_at: chrono::Utc::now().to_rfc3339(),
                vault: VaultInfoDTO {
                    vault_path: vault_path.clone(),
                    vault_id: None,
                },
            };

            if index_dir.join("meta.json").is_file() {
                let chunk_ids =
                    cupola_search::SearchIndex::new(&index_dir)?.search(&q, limit as usize)?;
                for chunk_id in chunk_ids {
                    let row = sqlx::query(
                        r#"
                        SELECT
                            a.rel_path as rel_path,
                            c.excerpt as excerpt,
                            c.id as chunk_id,
                            av.raw_blob_id as raw_blob_id,
                            c.chunk_blob_id as chunk_blob_id,
                            av.mtime_ns as mtime_ns,
                            av.file_type as file_type,
                            c.start_line as start_line,
                            c.end_line as end_line
                        FROM chunks c
                        JOIN artifact_versions av ON av.id = c.artifact_version_id
                        JOIN artifacts a ON a.id = av.artifact_id
                        WHERE a.vault_id = ?1 AND c.id = ?2
                        LIMIT 1
                        "#,
                    )
                    .bind(&vid)
                    .bind(&chunk_id)
                    .fetch_optional(db.pool())
                    .await?;

                    if let Some(r) = row {
                        let hit = row_to_search_hit(&r)?;
                        if json {
                            hits.push(hit);
                        } else {
                            print_search_hit(&hit);
                        }
                    }
                }
                if json {
                    let resp = SearchResponseDTO {
                        env: make_env(),
                        query: q.clone(),
                        limit,
                        hits,
                    };
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                }
                return Ok(());
            }

            let like = format!("%{}%", q);

            let rows = sqlx::query(
                r#"
                SELECT
                    a.rel_path as rel_path,
                    c.excerpt as excerpt,
                    c.id as chunk_id,
                    av.raw_blob_id as raw_blob_id,
                    c.chunk_blob_id as chunk_blob_id,
                    av.mtime_ns as mtime_ns,
                    av.file_type as file_type,
                    c.start_line as start_line,
                    c.end_line as end_line
                FROM chunks c
                JOIN artifact_versions av ON av.id = c.artifact_version_id
                JOIN artifacts a ON a.id = av.artifact_id
                WHERE a.vault_id = ?1 AND c.excerpt LIKE ?2
                ORDER BY c.created_at DESC
                LIMIT ?3
                "#,
            )
            .bind(vid)
            .bind(&like)
            .bind(limit as i64)
            .fetch_all(db.pool())
            .await?;

            for r in rows {
                let hit = row_to_search_hit(&r)?;
                if json {
                    hits.push(hit);
                } else {
                    print_search_hit(&hit);
                }
            }
            if json {
                let resp = SearchResponseDTO {
                    env: make_env(),
                    query: q.clone(),
                    limit,
                    hits,
                };
                println!("{}", serde_json::to_string_pretty(&resp)?);
            }
            }
            Command::Freeze { vault, out } => {
                let app_root = resolved_app_root.clone();
                freeze_vault_with_app_root(vault, out, app_root).await?;
            }
            Command::Verify {
                vault,
                manifest,
                json,
            } => {
                let app_root = resolved_app_root.clone();
                verify_vault_with_app_root(vault, manifest, app_root, json).await?;
            }
            Command::Replay {
                vault,
                manifest,
                json,
            } => {
                let app_root = resolved_app_root.clone();
                let report = replay_validation_report(vault, manifest, app_root);
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                if let Some(cas_check) = report.checks.iter().find(|c| c.name == "cas_blobs_exist")
                {
                    if cas_check.ok {
                        println!("OK: cas_blobs_exist");
                    } else {
                        let detail = cas_check.detail.as_deref().unwrap_or("");
                        if detail.is_empty() {
                            println!("ERR: cas_blobs_exist");
                        } else {
                            println!("ERR: cas_blobs_exist {detail}");
                        }
                    }
                }
                if report.ok {
                    println!("OK: replay validation passed");
                } else {
                    for e in &report.errors {
                        println!("ERR: {e}");
                    }
                    println!("ERR: replay validation failed");
                }
            }
                if !report.ok {
                    anyhow::bail!("replay failed: {} error(s)", report.errors.len());
                }
            }
            Command::Demo { vault, json } => {
                let app_root = resolved_app_root.clone();
                run_demo(vault, json, app_root).await?;
            }
        }
        Ok(())
    }
    .await;

    if let Err(e) = result {
        print_app_root_hint_if_relevant(&e, &resolved_app_root);
        return Err(e);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[tokio::test]
    async fn freeze_then_verify_passes_then_fails_after_modification() -> Result<()> {
        let vault = TempDir::new()?;
        let mut f = std::fs::File::create(vault.path().join("a.txt"))?;
        writeln!(f, "hello cupola")?;

        let app = TempDir::new()?;
        let app_root = app.path().join("Cupola");
        let manifest_path = app.path().join("manifest.json");

        freeze_vault_with_app_root(
            vault.path().to_path_buf(),
            manifest_path.clone(),
            app_root.clone(),
        )
        .await?;
        verify_vault_with_app_root(
            vault.path().to_path_buf(),
            manifest_path.clone(),
            app_root.clone(),
            false,
        )
        .await?;

        std::fs::write(vault.path().join("a.txt"), "changed content")?;

        let err =
            verify_vault_with_app_root(vault.path().to_path_buf(), manifest_path, app_root, false)
                .await
                .expect_err("verify should fail after file modification");
        let msg = format!("{err:#}");
        assert!(msg.contains("verify failed"));
        Ok(())
    }
}
