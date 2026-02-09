use anyhow::{anyhow, Result};
use cupola_cas::{BlobId, CasStore};
use sqlx::{Row, SqlitePool};
use std::path::Path;
use tantivy::collector::TopDocs;
use tantivy::query::QueryParser;
use tantivy::schema::{Field, Schema, Value, STORED, STRING, TEXT};
use tantivy::{doc, Index, TantivyDocument};

const FIELD_CHUNK_ID: &str = "chunk_id";
const FIELD_TEXT: &str = "text";

fn build_schema() -> Schema {
    let mut schema = Schema::builder();
    schema.add_text_field(FIELD_CHUNK_ID, STRING | STORED);
    schema.add_text_field(FIELD_TEXT, TEXT);
    schema.build()
}

fn get_fields(index: &Index) -> Result<(Field, Field)> {
    let schema = index.schema();
    let chunk_id = schema
        .get_field(FIELD_CHUNK_ID)
        .map_err(|_| anyhow!("missing field: {FIELD_CHUNK_ID}"))?;
    let text = schema
        .get_field(FIELD_TEXT)
        .map_err(|_| anyhow!("missing field: {FIELD_TEXT}"))?;
    Ok((chunk_id, text))
}

fn open_or_create_index(index_dir: &Path) -> Result<Index> {
    if let Ok(index) = Index::open_in_dir(index_dir) {
        if get_fields(&index).is_ok() {
            return Ok(index);
        }
        std::fs::remove_dir_all(index_dir)?;
    }
    std::fs::create_dir_all(index_dir)?;
    Ok(Index::create_in_dir(index_dir, build_schema())?)
}

pub fn index_exists(index_dir: &Path) -> bool {
    index_dir.join("meta.json").is_file()
}

pub async fn rebuild_vault_index(
    db: &SqlitePool,
    cas: &CasStore,
    vault_id: &str,
    index_dir: &Path,
) -> Result<usize> {
    let index = open_or_create_index(index_dir)?;
    let (field_chunk_id, field_text) = get_fields(&index)?;

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
    .fetch_all(db)
    .await?;

    let mut writer = index.writer(50_000_000)?;
    writer.delete_all_documents()?;

    for r in &rows {
        let chunk_id: String = r.try_get("chunk_id")?;
        let chunk_blob_id: String = r.try_get("chunk_blob_id")?;
        let excerpt: String = r.try_get("excerpt")?;

        let text = match cas.get(&BlobId::from_hash(chunk_blob_id)).await {
            Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
            Err(_) => excerpt,
        };

        writer.add_document(doc!(
            field_chunk_id => chunk_id,
            field_text => text,
        ))?;
    }
    writer.commit()?;
    Ok(rows.len())
}

pub fn search_chunk_ids(index_dir: &Path, query: &str, limit: usize) -> Result<Vec<String>> {
    let index = Index::open_in_dir(index_dir)?;
    let (field_chunk_id, field_text) = get_fields(&index)?;

    let reader = index.reader()?;
    let searcher = reader.searcher();
    let parser = QueryParser::for_index(&index, vec![field_text]);
    let q = parser.parse_query(query)?;
    let top = searcher.search(&q, &TopDocs::with_limit(limit))?;

    let mut scored: Vec<(f32, String)> = Vec::with_capacity(top.len());
    for (score, addr) in top {
        let doc: TantivyDocument = searcher.doc(addr)?;
        if let Some(chunk_id) = doc.get_first(field_chunk_id).and_then(|v| v.as_str()) {
            scored.push((score, chunk_id.to_string()));
        }
    }

    scored.sort_by(|a, b| b.0.total_cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    Ok(scored.into_iter().map(|(_, chunk_id)| chunk_id).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cupola_db::DbPool;
    use tempfile::TempDir;
    use uuid::Uuid;

    #[tokio::test]
    async fn rebuild_and_search_returns_expected_chunk_id() -> Result<()> {
        let td = TempDir::new()?;
        let db = DbPool::new(&td.path().join("db.sqlite")).await?;
        let cas = CasStore::new(td.path().join("cas"));
        tokio::fs::create_dir_all(td.path().join("cas")).await?;

        let vault_id = Uuid::new_v4().to_string();
        let artifact_id = "artifact-1".to_string();
        let version_id = "version-1".to_string();
        let chunk1_id = "chunk-1".to_string();
        let chunk2_id = "chunk-2".to_string();
        let blob1 = cas.put(b"alpha beta gamma").await?;
        let blob2 = cas.put(b"delta epsilon").await?;

        sqlx::query(
            "INSERT INTO vaults (id, root_path, name, created_at, config_json) VALUES (?1, ?2, ?3, ?4, '{}')",
        )
        .bind(&vault_id)
        .bind(td.path().to_string_lossy().to_string())
        .bind("test")
        .bind(1_i64)
        .execute(db.pool())
        .await?;

        sqlx::query("INSERT INTO artifacts (id, vault_id, rel_path) VALUES (?1, ?2, ?3)")
            .bind(&artifact_id)
            .bind(&vault_id)
            .bind("doc.txt")
            .execute(db.pool())
            .await?;

        sqlx::query(
            "INSERT INTO artifact_versions (id, artifact_id, raw_blob_id, mtime_ns, file_size, file_type, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .bind(&version_id)
        .bind(&artifact_id)
        .bind("raw")
        .bind(1_i64)
        .bind(10_i64)
        .bind("txt")
        .bind(1_i64)
        .execute(db.pool())
        .await?;

        sqlx::query(
            "INSERT INTO chunks (id, artifact_version_id, chunk_ordinal, chunk_blob_id, excerpt, token_count, start_line, end_line, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )
        .bind(&chunk1_id)
        .bind(&version_id)
        .bind(0_i64)
        .bind(blob1.as_str())
        .bind("alpha beta")
        .bind(2_i64)
        .bind(1_i64)
        .bind(1_i64)
        .bind(1_i64)
        .execute(db.pool())
        .await?;

        sqlx::query(
            "INSERT INTO chunks (id, artifact_version_id, chunk_ordinal, chunk_blob_id, excerpt, token_count, start_line, end_line, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )
        .bind(&chunk2_id)
        .bind(&version_id)
        .bind(1_i64)
        .bind(blob2.as_str())
        .bind("delta epsilon")
        .bind(2_i64)
        .bind(2_i64)
        .bind(2_i64)
        .bind(1_i64)
        .execute(db.pool())
        .await?;

        let index_dir = td.path().join("index");
        let count = rebuild_vault_index(db.pool(), &cas, &vault_id, &index_dir).await?;
        assert_eq!(count, 2);

        let hits = search_chunk_ids(&index_dir, "alpha", 10)?;
        assert_eq!(hits.first().map(|s| s.as_str()), Some("chunk-1"));
        Ok(())
    }
}
