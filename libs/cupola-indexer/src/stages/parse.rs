use anyhow::Result;
use blake3;
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

        // 5) Chunking (v1): deterministic multi-chunk for txt/md, else single chunk.
        // NOTE: DB migration 004 adds chunk_ordinal and uniqueness on (artifact_version_id, chunk_ordinal).
        let created_at = cupola_core::now_ns();

        // Helper to compute a deterministic chunk id from (artifact_version_id, ordinal)
        fn chunk_id_for(ver: &str, ord: i64) -> String {
            let mut h = blake3::Hasher::new();
            h.update(b"cupola:chunk:v1\0");
            h.update(ver.as_bytes());
            h.update(b"\0");
            h.update(ord.to_string().as_bytes());
            h.finalize().to_hex().to_string()
        }

        let is_text = matches!(hash.file_type.as_str(), "txt" | "md");

        if !is_text {
            // Fallback: single chunk ordinal 0 for non-text
            let excerpt: String = text.chars().take(300).collect();
            let token_count: i64 = text.split_whitespace().count() as i64;
            let end_line: i64 = (text.lines().count().max(1)) as i64;

            let ord: i64 = 0;
            let chunk_id = chunk_id_for(&hash.artifact_version_id, ord);

            sqlx::query(
                "INSERT OR IGNORE INTO chunks (id, artifact_version_id, chunk_ordinal, chunk_blob_id, excerpt, token_count, start_line, end_line, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            )
            .bind(&chunk_id)
            .bind(&hash.artifact_version_id)
            .bind(ord)
            .bind(&parse_hash)
            .bind(&excerpt)
            .bind(token_count)
            .bind(1i64)
            .bind(end_line)
            .bind(created_at)
            .execute(db.pool())
            .await?;
        } else {
            // Deterministic line-window chunking
            const MAX_LINES: usize = 200;

            let lines: Vec<&str> = text.lines().collect();
            let total_lines = lines.len().max(1);

            let mut ord: i64 = 0;
            let mut start: usize = 0;
            while start < total_lines {
                let end = (start + MAX_LINES).min(total_lines);
                let chunk_text = lines[start..end].join("\n");
                let chunk_bytes = chunk_text.as_bytes();

                // Store chunk blob in CAS + ensure blobs row
                let chunk_blob_id = cas.put(chunk_bytes).await?;
                let chunk_hash = chunk_blob_id.as_str().to_string();
                let chunk_size = chunk_bytes.len() as i64;

                sqlx::query(
                    "INSERT OR IGNORE INTO blobs (hash, size, cas_key) VALUES (?1, ?2, ?3)",
                )
                .bind(&chunk_hash)
                .bind(chunk_size)
                .bind(&chunk_hash)
                .execute(db.pool())
                .await?;

                // DB fields
                let excerpt: String = chunk_text.chars().take(300).collect();
                let token_count: i64 = chunk_text.split_whitespace().count() as i64;
                let start_line: i64 = (start as i64) + 1;
                let end_line: i64 = end as i64;

                let chunk_id = chunk_id_for(&hash.artifact_version_id, ord);

                sqlx::query(
                    "INSERT OR IGNORE INTO chunks (id, artifact_version_id, chunk_ordinal, chunk_blob_id, excerpt, token_count, start_line, end_line, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                )
                .bind(&chunk_id)
                .bind(&hash.artifact_version_id)
                .bind(ord)
                .bind(&chunk_hash)
                .bind(&excerpt)
                .bind(token_count)
                .bind(start_line)
                .bind(end_line)
                .bind(created_at)
                .execute(db.pool())
                .await?;

                ord += 1;
                start = end;
            }
        }

        Ok(ParseOutput {
            artifact_version_id: hash.artifact_version_id.clone(),
            parse_blob_id: parse_hash,
            bytes_len,
        })
    }
}
