-- v2→v3: audit-grade schema invariants for deterministic multi-chunk support.
-- Intentionally fails migration if any invariant is violated.

CREATE TEMP TABLE IF NOT EXISTS __schema_invariant_check (
    id INTEGER
);

-- Invariant 1: chunks.chunk_ordinal exists and is INTEGER NOT NULL DEFAULT 0.
CREATE TEMP TRIGGER __schema_invariant_fail_1
BEFORE INSERT ON __schema_invariant_check
WHEN NOT EXISTS (
    SELECT 1
    FROM pragma_table_info('chunks')
    WHERE name = 'chunk_ordinal'
      AND lower(type) = 'integer'
      AND "notnull" = 1
      AND replace(ifnull(dflt_value, ''), '''', '') = '0'
)
BEGIN
    SELECT RAISE(ABORT, 'schema invariant failed: chunks.chunk_ordinal must be INTEGER NOT NULL DEFAULT 0');
END;
INSERT INTO __schema_invariant_check(id) VALUES (1);
DROP TRIGGER __schema_invariant_fail_1;

-- Invariant 2: legacy index must NOT exist.
CREATE TEMP TRIGGER __schema_invariant_fail_2
BEFORE INSERT ON __schema_invariant_check
WHEN EXISTS (
    SELECT 1
    FROM sqlite_master
    WHERE type = 'index'
      AND name = 'ux_chunks_artifact_version_id'
)
BEGIN
    SELECT RAISE(ABORT, 'schema invariant failed: ux_chunks_artifact_version_id must not exist');
END;
INSERT INTO __schema_invariant_check(id) VALUES (2);
DROP TRIGGER __schema_invariant_fail_2;

-- Invariant 3: ux_chunks_version_ordinal exists, is UNIQUE,
-- and has columns (artifact_version_id, chunk_ordinal) in that order.
CREATE TEMP TRIGGER __schema_invariant_fail_3
BEFORE INSERT ON __schema_invariant_check
WHEN NOT (
    EXISTS (
        SELECT 1
        FROM pragma_index_list('chunks')
        WHERE name = 'ux_chunks_version_ordinal'
          AND "unique" = 1
    )
    AND (
        SELECT COUNT(*)
        FROM pragma_index_info('ux_chunks_version_ordinal')
    ) = 2
    AND (
        SELECT group_concat(name, ',')
        FROM (
            SELECT name
            FROM pragma_index_info('ux_chunks_version_ordinal')
            ORDER BY seqno
        )
    ) = 'artifact_version_id,chunk_ordinal'
)
BEGIN
    SELECT RAISE(ABORT, 'schema invariant failed: ux_chunks_version_ordinal must be UNIQUE on (artifact_version_id, chunk_ordinal)');
END;
INSERT INTO __schema_invariant_check(id) VALUES (3);
DROP TRIGGER __schema_invariant_fail_3;

DROP TABLE __schema_invariant_check;
