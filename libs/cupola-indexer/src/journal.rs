use anyhow::Result;
use cupola_core::VaultId;
use cupola_db::DbPool;
/// Crash-safe ingestion journal (v0).
/// Note: schema uses (vault_id, artifact_id) as PRIMARY KEY.
#[derive(Clone, Debug)]
pub struct IngestionJournal;

#[derive(Clone, Copy, Debug)]
pub enum State {
    Pending,
    Processing,
    Completed,
    Failed,
}

#[derive(Clone, Copy, Debug)]
pub enum Stage {
    Hashed,
    Parsed,
    Chunked,
    Indexed,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Pending => "PENDING",
            State::Processing => "PROCESSING",
            State::Completed => "COMPLETED",
            State::Failed => "FAILED",
        }
    }
}

impl Stage {
    pub fn as_str(self) -> &'static str {
        match self {
            Stage::Hashed => "HASHED",
            Stage::Parsed => "PARSED",
            Stage::Chunked => "CHUNKED",
            Stage::Indexed => "INDEXED",
        }
    }
}

impl IngestionJournal {
    pub fn new() -> Self {
        Self
    }
}

impl Default for IngestionJournal {
    fn default() -> Self {
        Self::new()
    }
}

impl IngestionJournal {
    #[allow(clippy::too_many_arguments)]
    pub async fn set_state(
        &self,
        db: &DbPool,
        vault_id: &VaultId,
        artifact_id: &str,
        state: State,
        stage: Stage,
        error: Option<&str>,
        updated_at_ns: i64,
    ) -> Result<()> {
        // SQLite UPSERT with monotonic stage progression (never downgrade stage).
        // SQLite UPSERT with monotonic stage progression (never downgrade stage).
        let q = r#"
        INSERT INTO ingestion_journal (vault_id, artifact_id, state, stage, error, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        ON CONFLICT(vault_id, artifact_id) DO UPDATE SET
          state = excluded.state,
          stage = CASE
            WHEN ingestion_journal.stage = 'INDEXED' THEN 'INDEXED'
            WHEN ingestion_journal.stage = 'CHUNKED' AND excluded.stage IN ('HASHED','PARSED') THEN 'CHUNKED'
            WHEN ingestion_journal.stage = 'PARSED' AND excluded.stage = 'HASHED' THEN 'PARSED'
            ELSE excluded.stage
          END,
          error = excluded.error,
  updated_at = CASE
    WHEN (
      state <> excluded.state
      OR error <> excluded.error
      OR stage <> (
        CASE
          WHEN ingestion_journal.stage = 'INDEXED' THEN 'INDEXED'
          WHEN ingestion_journal.stage = 'CHUNKED' AND excluded.stage IN ('HASHED','PARSED') THEN 'CHUNKED'
          WHEN ingestion_journal.stage = 'PARSED' AND excluded.stage = 'HASHED' THEN 'PARSED'
          ELSE excluded.stage
        END
      )
    )
    THEN excluded.updated_at
    ELSE ingestion_journal.updated_at
  END
        "#;
        sqlx::query(q)
            .bind(vault_id.0.to_string())
            .bind(artifact_id)
            .bind(state.as_str())
            .bind(stage.as_str())
            .bind(error.unwrap_or(""))
            .bind(updated_at_ns)
            .execute(db.pool())
            .await?;
        Ok(())
    }
}
