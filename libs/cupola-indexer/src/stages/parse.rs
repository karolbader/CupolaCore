use anyhow::Result;
use cupola_cas::CasStore;
use cupola_db::DbPool;

use crate::stages::hash::HashOutput;

pub struct ParseStage;

pub struct ParseOutput {
    pub artifact_version_id: String,
    pub parse_blob_id: String,
    pub bytes_len: i64,
}

impl ParseStage {
    pub async fn run(db: &DbPool, cas: &CasStore, hash: &HashOutput) -> Result<ParseOutput> {
        // v0 idempotency: if file unchanged, don't write blobs/chunks again
        if !hash.changed {
            return Ok(ParseOutput {
                artifact_version_id: hash.artifact_version_id.clone(),
                parse_blob_id: String::new(),
                bytes_len: 0,
            });
        }
        // 1) Load raw bytes from CAS
        let raw_id = hash.raw_blob_id.clone();
        let raw_bytes = cas.get(&raw_id).await?;

        // 2) v0 parse: treat as UTF-8 text (lossy)
        let text = String::from_utf8_lossy(&raw_bytes).to_string();
        let parse_bytes = text.as_bytes();

        // 3) Store parse output in CAS
        let parse_id = cas.put(parse_bytes).await?;
        let parse_hash = parse_id.as_str().to_string();
        let bytes_len = parse_bytes.len() as i64;

        // 4) Ensure blobs row exists
        sqlx::query("INSERT OR IGNORE INTO blobs (hash, size, cas_key) VALUES (?1, ?2, ?3)")
            .bind(&parse_hash)
            .bind(bytes_len)
            .bind(&parse_hash)
            .execute(db.pool())
            .await?;

        // 5) v0: single chunk per artifact_version
        let excerpt: String = text.chars().take(300).collect();
        let token_count: i64 = text.split_whitespace().count() as i64;
        let end_line: i64 = (text.lines().count().max(1)) as i64;
        let chunk_id = hash.artifact_version_id.clone();
        sqlx::query(
            "INSERT OR IGNORE INTO chunks (id, artifact_version_id, chunk_blob_id, excerpt, token_count, start_line, end_line, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )
        .bind(&chunk_id)
        .bind(&hash.artifact_version_id)
        .bind(&parse_hash)
        .bind(&excerpt)
        .bind(token_count)
        .bind(1i64)
        .bind(end_line)
        .bind(cupola_core::now_ns())
        .execute(db.pool())
        .await?;

        Ok(ParseOutput {
            artifact_version_id: hash.artifact_version_id.clone(),
            parse_blob_id: parse_hash,
            bytes_len,
        })
    }
}
