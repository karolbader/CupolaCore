-- v2→v3: audit-grade schema invariants for deterministic multi-chunk support.
-- Intentionally fails migration if any invariant is violated.

-- Invariant 1: chunks.chunk_ordinal column must exist.
SELECT CASE
    WHEN EXISTS (
        SELECT 1
        FROM pragma_table_info('chunks')
        WHERE name = 'chunk_ordinal'
    ) THEN 1
    ELSE missing_chunk_ordinal_column()
END;

-- Invariant 2: legacy unique index must NOT exist.
SELECT CASE
    WHEN NOT EXISTS (
        SELECT 1
        FROM sqlite_master
        WHERE type = 'index'
          AND name = 'ux_chunks_artifact_version_id'
    ) THEN 1
    ELSE legacy_unique_index_present()
END;

-- Invariant 3a: ux_chunks_version_ordinal must exist and be UNIQUE.
SELECT CASE
    WHEN EXISTS (
        SELECT 1
        FROM pragma_index_list('chunks')
        WHERE name = 'ux_chunks_version_ordinal'
          AND "unique" = 1
    ) THEN 1
    ELSE missing_or_nonunique_chunks_version_ordinal_index()
END;

-- Invariant 3b: ux_chunks_version_ordinal key order must be
-- (artifact_version_id, chunk_ordinal).
SELECT CASE
    WHEN (
        SELECT group_concat(name, ',')
        FROM (
            SELECT ii.name
            FROM pragma_index_info('ux_chunks_version_ordinal') ii
            ORDER BY ii.seqno
        )
    ) = 'artifact_version_id,chunk_ordinal' THEN 1
    ELSE bad_chunks_version_ordinal_index_shape()
END;
