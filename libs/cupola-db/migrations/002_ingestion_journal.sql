-- Ingestion journaling (v0)
CREATE TABLE IF NOT EXISTS ingestion_runs (
    id TEXT PRIMARY KEY,
    vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    started_at INTEGER NOT NULL,
    finished_at INTEGER,
    status TEXT NOT NULL,               -- "running" | "completed" | "failed"
    files_total INTEGER NOT NULL DEFAULT 0,
    files_ok INTEGER NOT NULL DEFAULT 0,
    files_failed INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_ingestion_runs_vault_started ON ingestion_runs(vault_id, started_at);

CREATE TABLE IF NOT EXISTS ingestion_events (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES ingestion_runs(id) ON DELETE CASCADE,
    artifact_id TEXT,                   -- can be NULL if failure before artifact creation
    rel_path TEXT NOT NULL,
    stage TEXT NOT NULL,                -- e.g. "hash"
    state TEXT NOT NULL,                -- "started" | "completed" | "failed"
    message TEXT,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ingestion_events_run ON ingestion_events(run_id, created_at);
CREATE INDEX IF NOT EXISTS idx_ingestion_events_rel ON ingestion_events(rel_path);
