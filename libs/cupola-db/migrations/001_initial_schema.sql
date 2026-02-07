-- 001_initial_schema.sql
CREATE TABLE IF NOT EXISTS vaults (
    id TEXT PRIMARY KEY,
    root_path TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    config_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS artifacts (
    id TEXT PRIMARY KEY,
    vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    rel_path TEXT NOT NULL,
    current_version_id TEXT,
    UNIQUE(vault_id, rel_path)
);

CREATE TABLE IF NOT EXISTS artifact_versions (
    id TEXT PRIMARY KEY,
    artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    raw_blob_id TEXT NOT NULL,
    mtime_ns INTEGER NOT NULL,
    file_size INTEGER NOT NULL,
    file_type TEXT NOT NULL,
    parser_version INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS blobs (
    hash TEXT PRIMARY KEY,
    size INTEGER NOT NULL,
    cas_key TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS chunks (
    id TEXT PRIMARY KEY,
    artifact_version_id TEXT NOT NULL REFERENCES artifact_versions(id) ON DELETE CASCADE,
    chunk_blob_id TEXT NOT NULL,
    excerpt TEXT NOT NULL CHECK (length(excerpt) <= 512),
    token_count INTEGER,
    start_line INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS ingestion_journal (
    vault_id TEXT NOT NULL,
    artifact_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('PENDING','PROCESSING','COMPLETED','FAILED')),
    stage TEXT NOT NULL,
    error TEXT,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (vault_id, artifact_id)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS freezes (
    id TEXT PRIMARY KEY,
    vault_id TEXT NOT NULL REFERENCES vaults(id),
    created_at INTEGER NOT NULL,
    manifest_blob_id TEXT NOT NULL REFERENCES blobs(hash),
    UNIQUE(vault_id, created_at)
);

CREATE INDEX IF NOT EXISTS idx_artifacts_vault ON artifacts(vault_id);
CREATE INDEX IF NOT EXISTS idx_artifact_versions_artifact ON artifact_versions(artifact_id);
CREATE INDEX IF NOT EXISTS idx_chunks_artifact_version ON chunks(artifact_version_id);
CREATE INDEX IF NOT EXISTS idx_ingestion_journal_vault_state ON ingestion_journal(vault_id, state);

CREATE TRIGGER IF NOT EXISTS trg_artifact_version_insert
AFTER INSERT ON artifact_versions
BEGIN
    UPDATE artifacts SET current_version_id = NEW.id WHERE id = NEW.artifact_id;
END;


