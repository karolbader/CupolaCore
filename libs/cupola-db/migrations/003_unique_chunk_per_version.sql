-- v0: enforce idempotency (1 chunk per artifact_version)
CREATE UNIQUE INDEX IF NOT EXISTS ux_chunks_artifact_version_id
ON chunks(artifact_version_id);