# CUPOLA — BLUEPRINT (v0)
Anchor commit: 59b9ff624748ca826df31c98a16514adcb84b7db
Anchor date (repo): 2026-02-07
Author: Tibi

## 0) Completion Loop (Definition of Done)
ingest → parse/extract → chunk → index → search → freeze → replay/verify

## 1) Non-negotiable Invariants
1. Provenance always: every derived artifact must link to source (vault_id, rel_path, content_hash, artifact_version_id or equivalent).
2. Deterministic for frozen vaults: same inputs ⇒ same outputs (crawl order, chunk ids, index ids).
3. Freeze/replay = no silent rebuild: verify reports diffs; any repair is explicit and separate.
4. Idempotence: re-run ingest on unchanged vault ⇒ no new versions/chunks/journal stages.
5. Stable excludes: /.git/, /node_modules/, /target/, /.next/ etc never ingested.

## 2) Crate Ownership Map (Single Responsibility)
- libs/cupola-indexer: deterministic crawl + pipeline stages
- libs/cupola-cas: BLAKE3 CAS + shard layout + dedup
- libs/cupola-db: sqlite schema + migrations + query layer
- libs/cupola-core: domain types + shared contracts (manifest, verify report, ids)
- libs/cupola-protocol: externalizable structs/events for artifacts/reports
- libs/cupola-cli: thin CLI surface only (arg parsing + calls into libraries)

## 3) Database Contract Anchors (Migrations as truth)
- 001_initial_schema.sql: baseline schema (vaults/artifacts/versions/chunks/...)
- 002_ingestion_journal.sql: ingestion journal / stage tracking (auditable pipeline)
- 003_unique_chunk_per_version.sql: uniqueness guard to prevent duplicate chunks per version

## 4) Feb Gates (Engineering)
- Proof-ready: ingest→index→freeze→replay demo with CLI outputs (status --json + hashes + verification report).
- Sellable v0: deterministic CLI-only loop (ingest + search + verify) with provenance-first outputs.
