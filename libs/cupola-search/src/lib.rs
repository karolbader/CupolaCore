use std::path::Path;

use tantivy::collector::TopDocs;
use tantivy::query::QueryParser;
use tantivy::schema::{Field, Schema, Value, STORED, STRING, TEXT};
use tantivy::{doc, Index, TantivyDocument};
use thiserror::Error;

const FIELD_CHUNK_ID: &str = "chunk_id";
const FIELD_CONTENT: &str = "content";
const FIELD_RAW_BLOB_ID: &str = "raw_blob_id";

#[derive(Debug, Error)]
pub enum SearchError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("tantivy error: {0}")]
    Tantivy(#[from] tantivy::TantivyError),
    #[error("missing field in schema: {0}")]
    MissingField(&'static str),
}

pub type Result<T> = std::result::Result<T, SearchError>;

pub struct SearchIndex {
    pub index: tantivy::Index,
    pub reader: tantivy::IndexReader,
}

fn schema_v0() -> Schema {
    let mut schema = Schema::builder();
    schema.add_text_field(FIELD_CHUNK_ID, STRING | STORED);
    schema.add_text_field(FIELD_CONTENT, TEXT);
    schema.add_text_field(FIELD_RAW_BLOB_ID, STRING | STORED);
    schema.build()
}

fn schema_fields(index: &Index) -> Result<(Field, Field, Field)> {
    let schema = index.schema();
    let chunk_id = schema
        .get_field(FIELD_CHUNK_ID)
        .map_err(|_| SearchError::MissingField(FIELD_CHUNK_ID))?;
    let content = schema
        .get_field(FIELD_CONTENT)
        .map_err(|_| SearchError::MissingField(FIELD_CONTENT))?;
    let raw_blob_id = schema
        .get_field(FIELD_RAW_BLOB_ID)
        .map_err(|_| SearchError::MissingField(FIELD_RAW_BLOB_ID))?;
    Ok((chunk_id, content, raw_blob_id))
}

impl SearchIndex {
    pub fn new(index_path: &Path) -> Result<Self> {
        std::fs::create_dir_all(index_path)?;

        let index = match Index::open_in_dir(index_path) {
            Ok(i) if schema_fields(&i).is_ok() => i,
            Ok(_) | Err(_) => {
                // v0 safety: if the on-disk index cannot be opened with the expected
                // schema, rebuild a fresh index directory rather than continuing with
                // a potentially incompatible layout.
                if index_path.exists() {
                    let _ = std::fs::remove_dir_all(index_path);
                }
                std::fs::create_dir_all(index_path)?;
                Index::create_in_dir(index_path, schema_v0())?
            }
        };

        let reader = index.reader()?;
        Ok(Self { index, reader })
    }

    pub fn ingest_document(&self, chunk_id: &str, content: &str) -> Result<u64> {
        let (field_chunk_id, field_content, _field_raw_blob_id) = schema_fields(&self.index)?;
        let mut writer = self.index.writer(50_000_000)?;
        let opstamp = writer.add_document(doc!(
            field_chunk_id => chunk_id.to_string(),
            field_content => content.to_string(),
        ))?;
        writer.commit()?;
        self.reader.reload()?;
        Ok(opstamp)
    }

    pub fn search(&self, query: &str, limit: usize) -> Result<Vec<String>> {
        let (field_chunk_id, field_content, _field_raw_blob_id) = schema_fields(&self.index)?;
        let searcher = self.reader.searcher();
        let parser = QueryParser::for_index(&self.index, vec![field_content]);
        let q = parser.parse_query(query).map_err(|e| {
            SearchError::Tantivy(tantivy::TantivyError::InvalidArgument(format!(
                "query parse error: {e}"
            )))
        })?;
        let top = searcher.search(&q, &TopDocs::with_limit(limit))?;

        let mut scored: Vec<(f32, String)> = Vec::with_capacity(top.len());
        for (score, addr) in top {
            let d: TantivyDocument = searcher.doc(addr)?;
            if let Some(cid) = d.get_first(field_chunk_id).and_then(|v| v.as_str()) {
                scored.push((score, cid.to_string()));
            }
        }

        scored.sort_by(|a, b| b.0.total_cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
        Ok(scored.into_iter().map(|(_, cid)| cid).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn new_ingest_and_search_roundtrip() -> Result<()> {
        let td = TempDir::new()?;
        let si = SearchIndex::new(td.path())?;
        let _ = si.ingest_document("chunk-a", "hello tantivy world")?;
        let hits = si.search("tantivy", 10)?;
        assert_eq!(hits, vec!["chunk-a".to_string()]);
        Ok(())
    }

    #[test]
    fn search_index_persists_across_reopen() -> Result<()> {
        let td = TempDir::new()?;
        let index_path = td.path().join("index");

        {
            let si = SearchIndex::new(&index_path)?;
            let _ = si.ingest_document("chunk-a", "alpha beta")?;
        }

        let reopened = SearchIndex::new(&index_path)?;
        let hits = reopened.search("alpha", 10)?;
        assert_eq!(hits, vec!["chunk-a".to_string()]);
        Ok(())
    }
}
