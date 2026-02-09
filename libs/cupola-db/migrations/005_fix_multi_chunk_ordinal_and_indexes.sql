-- v1→v2: repair multi-chunk ordinals/indexes for existing databases.
-- Requires migration 004 to have added chunks.chunk_ordinal.

WITH ranked AS (
    SELECT
        id,
        ROW_NUMBER() OVER (
            PARTITION BY artifact_version_id
            ORDER BY created_at, id
        ) - 1 AS ordinal
    FROM chunks
)
UPDATE chunks
SET chunk_ordinal = (
    SELECT ranked.ordinal
    FROM ranked
    WHERE ranked.id = chunks.id
);

DROP INDEX IF EXISTS ux_chunks_artifact_version_id;

CREATE UNIQUE INDEX IF NOT EXISTS ux_chunks_version_ordinal
ON chunks(artifact_version_id, chunk_ordinal);
