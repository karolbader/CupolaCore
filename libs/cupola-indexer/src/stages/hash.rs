use anyhow::Result;
use std::path::Path;

use cupola_cas::{BlobId, CasStore};
use cupola_core::{now_ns, VaultId};
use cupola_db::DbPool;
use sqlx::Row;
use uuid::Uuid;

/// HashStage:
/// - reads file bytes
/// - writes to CAS (dedup)
/// - upserts artifacts row
/// - inserts artifact_versions row (trigger updates artifacts.current_version_id)
pub struct HashStage;

pub struct HashOutput {
    pub artifact_id: String,
    pub artifact_version_id: String,
    pub raw_blob_id: BlobId,
    pub file_size: u64,
    pub mtime_ns: i64,
    pub file_type: String,
    pub changed: bool,
}

fn detect_file_type(abs_path: &Path) -> String {
    let ext = abs_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if ext.is_empty() {
        return "unknown".to_string();
    }
    ext
}

/// Convert SystemTime -> i64 ns
fn mtime_ns(meta: &std::fs::Metadata) -> i64 {
    use std::time::UNIX_EPOCH;
    match meta.modified() {
        Ok(t) => match t.duration_since(UNIX_EPOCH) {
            Ok(d) => (d.as_secs() as i64) * 1_000_000_000 + (d.subsec_nanos() as i64),
            Err(_) => 0,
        },
        Err(_) => 0,
    }
}

impl HashStage {
    pub async fn run(
        db: &DbPool,
        cas: &CasStore,
        vault_id: &VaultId,
        vault_root: &Path,
        abs_path: &Path,
    ) -> Result<HashOutput> {
        // 1) Read + CAS write (dedup)
        let bytes = tokio::fs::read(abs_path).await?;
        let file_size = bytes.len() as u64;
        let raw_blob_id = cas.put(&bytes).await?;

        // 2) Rel path (forward slashes)
        let rel = abs_path
            .strip_prefix(vault_root)
            .unwrap_or(abs_path)
            .to_string_lossy()
            .replace('\\', "/");

        // 3) Metadata (mtime)
        let meta = tokio::fs::metadata(abs_path).await?;
        let mtime_ns = mtime_ns(&meta);

        // 4) Upsert artifact (stable identity by (vault_id, rel_path))
        // Try fetch existing artifact id
        let existing =
            sqlx::query("SELECT id FROM artifacts WHERE vault_id = ?1 AND rel_path = ?2")
                .bind(vault_id.0.to_string())
                .bind(&rel)
                .fetch_optional(db.pool())
                .await?;

        let artifact_id = if let Some(row) = existing {
            row.try_get::<String, _>("id")?
        } else {
            let id = Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO artifacts (id, vault_id, rel_path, current_version_id) VALUES (?1, ?2, ?3, NULL)"
            )
            .bind(&id)
            .bind(vault_id.0.to_string())
            .bind(&rel)
            .execute(db.pool())
            .await?;
            id
        };
        // 5) If unchanged vs latest version, no-op (do not insert)
        let file_type = detect_file_type(abs_path);

        let latest = sqlx::query(
            "SELECT id, raw_blob_id, mtime_ns, file_size FROM artifact_versions WHERE artifact_id = ?1 ORDER BY created_at DESC LIMIT 1",
        )
        .bind(&artifact_id)
        .fetch_optional(db.pool())
        .await?;

        if let Some(row) = latest {
            let last_id: String = row.try_get("id")?;
            let last_blob: String = row.try_get("raw_blob_id")?;
            let last_mtime: i64 = row.try_get("mtime_ns")?;
            let last_size: i64 = row.try_get("file_size")?;

            if last_blob == raw_blob_id.as_str()
                && last_mtime == mtime_ns
                && last_size == file_size as i64
            {
                return Ok(HashOutput {
                    artifact_id,
                    artifact_version_id: last_id,
                    raw_blob_id,
                    file_size,
                    mtime_ns,
                    file_type,
                    changed: false,
                });
            }
        }

        // 6) Insert artifact version (changed)
        let artifact_version_id = Uuid::new_v4().to_string();
        let created_at = now_ns();
        let parser_version: i64 = 1;

        sqlx::query(
            r#"
            INSERT INTO artifact_versions
              (id, artifact_id, raw_blob_id, mtime_ns, file_size, file_type, parser_version, created_at)
            VALUES
              (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
        )
        .bind(&artifact_version_id)
        .bind(&artifact_id)
        .bind(raw_blob_id.as_str())
        .bind(mtime_ns)
        .bind(file_size as i64)
        .bind(&file_type)
        .bind(parser_version)
        .bind(created_at)
        .execute(db.pool())
        .await?;

        Ok(HashOutput {
            artifact_id,
            artifact_version_id,
            raw_blob_id,
            file_size,
            mtime_ns,
            file_type,
            changed: true,
        })
    }
}
