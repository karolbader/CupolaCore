-- v0→v1: enable deterministic multi-chunk per artifact_version.
-- Adds chunk_ordinal and updates uniqueness constraint.

ALTER TABLE chunks ADD COLUMN chunk_ordinal INTEGER NOT NULL DEFAULT 0;

DROP INDEX IF EXISTS ux_chunks_artifact_version_id;

CREATE UNIQUE INDEX IF NOT EXISTS ux_chunks_version_ordinal
ON chunks(artifact_version_id, chunk_ordinal);
