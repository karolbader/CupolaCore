use anyhow::Result;
use std::path::PathBuf;

use cupola_cas::CasStore;
use cupola_core::{now_ns, VaultId};
use cupola_db::DbPool;

use crate::journal::{IngestionJournal, Stage as JournalStage, State};
use crate::stages::hash::HashStage;
use crate::stages::parse::ParseStage;
/// Minimal pipeline (v0): deterministic crawl -> HashStage for each file.
pub struct Pipeline {
    pub db: DbPool,
    pub cas: CasStore,
    pub journal: IngestionJournal,
    pub vault_id: VaultId,
    pub vault_root: PathBuf,
}

impl Pipeline {
    pub fn new(db: DbPool, cas: CasStore, vault_id: VaultId, vault_root: PathBuf) -> Self {
        Self {
            db,
            cas,
            journal: IngestionJournal::new(),
            vault_id,
            vault_root,
        }
    }

    /// Hash all files in vault_root in deterministic order.
    /// For v0 we only journal after HashStage returns an artifact_id.
    pub async fn run_hash_all(&self) -> Result<usize> {
        let items = crate::crawl_sorted(&self.vault_root)?;
        let mut ok_count = 0usize;

        for it in items {
            let abs = it.abs_path.clone();

            match HashStage::run(
                &self.db,
                &self.cas,
                &self.vault_id,
                self.vault_root.as_path(),
                abs.as_path(),
            )
            .await
            {
                Ok(out) => {
                    ok_count += 1;
                    if out.changed {
                        // Content changed -> re-parse/re-chunk
                        let _parse = ParseStage::run(&self.db, &self.cas, &out).await?;
                        let _ = self
                            .journal
                            .set_state(
                                &self.db,
                                &self.vault_id,
                                &out.artifact_id,
                                State::Completed,
                                JournalStage::Chunked,
                                None,
                                now_ns(),
                            )
                            .await;
                    }
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }

        Ok(ok_count)
    }
}
#[cfg(test)]
use sqlx::Row;
#[cfg(test)]
use std::io::Write;
#[cfg(test)]
use tempfile::TempDir;
#[tokio::test]
async fn pipeline_hashes_files_and_writes_db() -> Result<()> {
    // Vault root with a single file
    let vault = TempDir::new()?;
    let p = vault.path().join("a.txt");
    let mut f = std::fs::File::create(&p)?;
    writeln!(f, "hello cupola")?;

    // App root for db + cas
    let app = TempDir::new()?;
    let db_path = app.path().join("db.sqlite");
    let cas_root = app.path().join("cas");
    tokio::fs::create_dir_all(&cas_root).await?;

    let db = DbPool::new(&db_path).await?;
    let cas = CasStore::new(cas_root);

    let root_path = vault.path().to_string_lossy().to_string();
    let vault_id = {
        let mut h = blake3::Hasher::new();
        h.update(b"cupola:vault:v1\0");
        h.update(root_path.as_bytes());
        let out = h.finalize();
        let mut b = [0u8; 16];
        b.copy_from_slice(&out.as_bytes()[0..16]);
        b[6] = (b[6] & 0x0f) | 0x40; // version
        b[8] = (b[8] & 0x3f) | 0x80; // variant
        VaultId(uuid::Uuid::from_bytes(b))
    };

    // Seed vault row (FK requirement for artifacts/versions/journal)
    sqlx::query(
        "INSERT INTO vaults (id, root_path, name, created_at, config_json)
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )
    .bind(vault_id.0.to_string())
    .bind(&root_path)
    .bind("Test Vault")
    .bind(cupola_core::now_ns())
    .bind("{}")
    .execute(db.pool())
    .await?;
    let pipe = Pipeline::new(db, cas, vault_id, vault.path().to_path_buf());

    let n = pipe.run_hash_all().await?;
    assert_eq!(n, 1);

    // Verify artifacts row exists
    let row = sqlx::query("SELECT COUNT(1) as c FROM artifacts")
        .fetch_one(pipe.db.pool())
        .await?;
    let c: i64 = row.try_get("c")?;
    assert_eq!(c, 1);

    Ok(())
}

#[tokio::test]
async fn pipeline_is_idempotent_no_new_versions_or_chunks_on_rerun() -> Result<()> {
    // Vault root with a single file
    let vault = TempDir::new()?;
    let p = vault.path().join("a.txt");
    let mut f = std::fs::File::create(&p)?;
    writeln!(f, "hello cupola")?;

    // App root for db + cas (mirror baseline test)
    let app = TempDir::new()?;
    let db_path = app.path().join("db.sqlite");
    let cas_root = app.path().join("cas");
    tokio::fs::create_dir_all(&cas_root).await?;

    let db = DbPool::new(&db_path).await?;
    let cas = CasStore::new(cas_root);

    // Derive vault_id exactly like baseline test
    let root_path = vault.path().to_string_lossy().to_string();
    let vault_id = {
        let mut h = blake3::Hasher::new();
        h.update(b"cupola:vault:v1\0");
        h.update(root_path.as_bytes());
        let out = h.finalize();
        let mut b = [0u8; 16];
        b.copy_from_slice(&out.as_bytes()[0..16]);
        b[6] = (b[6] & 0x0f) | 0x40; // version
        b[8] = (b[8] & 0x3f) | 0x80; // variant
        VaultId(uuid::Uuid::from_bytes(b))
    };

    // Seed vault row (FK requirement for artifacts/versions/chunks/journal)
    sqlx::query(
        "INSERT INTO vaults (id, root_path, name, created_at, config_json)
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )
    .bind(vault_id.0.to_string())
    .bind(&root_path)
    .bind("Test Vault")
    .bind(cupola_core::now_ns())
    .bind("{}")
    .execute(db.pool())
    .await?;

    let pipe = Pipeline::new(db, cas, vault_id, vault.path().to_path_buf());

    // Run twice: second run must not create new versions or chunks
    let n1 = pipe.run_hash_all().await?;
    let n2 = pipe.run_hash_all().await?;
    assert_eq!(n1, 1);
    assert_eq!(n2, 1);

    // Counts must remain stable
    let artifacts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM artifacts")
        .fetch_one(pipe.db.pool())
        .await?;

    let versions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM artifact_versions")
        .fetch_one(pipe.db.pool())
        .await?;

    let chunks: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM chunks")
        .fetch_one(pipe.db.pool())
        .await?;

    assert_eq!(artifacts, 1);
    assert_eq!(versions, 1);
    assert_eq!(chunks, 1);

    Ok(())
}
