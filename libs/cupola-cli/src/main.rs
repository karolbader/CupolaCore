use anyhow::Result;
use clap::{Parser, Subcommand};
use cupola_cas::CasStore;
use cupola_core::{app_data_root, now_ns, VaultId};
use cupola_db::DbPool;
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

    /// Search chunks.excerpt (v0 SQLite LIKE) within a vault.
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

        Command::Search { vault, q, limit } => {
            let vault_root = vault.canonicalize()?;
            let app_root = app_data_root()?;

            // Global DB for all vaults (v0): app_root\db.sqlite
            let db_path = app_root.join("db.sqlite");
            let db = DbPool::new(&db_path).await?;

            let vault_id = ensure_vault(&db, &vault_root).await?;

            let like = format!("%{}%", q);

            let rows = sqlx::query(
                r#"
                SELECT a.rel_path as rel_path, c.excerpt as excerpt
                FROM chunks c
                JOIN artifact_versions av ON av.id = c.artifact_version_id
                JOIN artifacts a ON a.id = av.artifact_id
                WHERE a.vault_id = ?1 AND c.excerpt LIKE ?2
                ORDER BY c.created_at DESC
                LIMIT ?3
                "#,
            )
            .bind(vault_id.0.to_string())
            .bind(&like)
            .bind(limit as i64)
            .fetch_all(db.pool())
            .await?;

            for r in rows {
                let p: String = r.try_get("rel_path")?;
                let ex: String = r.try_get("excerpt")?;
                println!("{} :: {}", p, ex.replace('\n', " "));
            }
        }
    }

    Ok(())
}
