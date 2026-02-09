use anyhow::Result;
use clap::{Parser, Subcommand};
use cupola_cas::CasStore;
use cupola_core::{
    app_data_root, now_ns, vault_indexes_root, ManifestArtifactV0, ManifestV0, VaultId,
    VerifyDiffKind,
};
use cupola_db::DbPool;
use cupola_protocol::{SearchHitDTO, SearchResponseDTO};
use sqlx::Row;
use std::path::PathBuf;
#[derive(Parser, Debug)]
#[command(name = "cupola", version, about = "Cupola CLI (v0)")]
struct Cli {
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

    /// Compute BLAKE3 of a single file (v0 utility).
    Blake3 {
        /// Path to a file to hash.
        #[arg(long)]
        file: PathBuf,
    },
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

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Command::Hash { vault } => {
            let vault_root = vault.canonicalize()?;
            let app_root = app_data_root()?;

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
            let _ = rebuild_search_index_for_vault(&pipe.db, &pipe.cas, &vid, &index_dir).await?;

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
            let app_root = app_data_root()?;

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
            let app_root = app_data_root()?;

            // Global DB for all vaults (v0): app_root\db.sqlite
            let db_path = app_root.join("db.sqlite");
            let db = DbPool::new(&db_path).await?;

            let vault_id = ensure_vault(&db, &vault_root).await?;

            let vid = vault_id.0.to_string();
            let index_dir = vault_indexes_root(&app_root, &vault_id).join("tantivy");
            let mut hits: Vec<SearchHitDTO> = Vec::new();

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
                        query: q,
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
                    query: q,
                    limit,
                    hits,
                };
                println!("{}", serde_json::to_string_pretty(&resp)?);
            }
        }
        Command::Freeze { vault, out } => {
            let app_root = app_data_root()?;
            freeze_vault_with_app_root(vault, out, app_root).await?;
        }
        Command::Verify {
            vault,
            manifest,
            json,
        } => {
            let app_root = app_data_root()?;
            verify_vault_with_app_root(vault, manifest, app_root, json).await?;
        }
    }

    Ok(())
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
