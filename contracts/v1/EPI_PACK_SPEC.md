# EPI Pack Spec v1 (Frozen)

This specification defines reviewer-facing verification behavior for `pack.zip`.

## 1) Mandatory files

The following files are required at zip root (exact names, case-sensitive):

- `epi.evidence_pack.v1.json`
- `epi.decision_pack.v1.json`
- `epi.runlog.v1.json`
- `epi.seal.v1.json`
- `epi.claims.v1.json`
- `epi.drift_report.v1.json`

Files with those names in nested folders do not satisfy this requirement.

## 2) Optional / extra files

Extra files are allowed and do not fail verification by themselves.

Common examples:

- `DecisionPack.html`
- `DecisionPack.manifest.json`
- `DecisionPack.seal.json`
- `REPLAY.md`
- `DataShareChecklist.md`
- `Quote.json`
- `Quote.md`
- `cupola.manifest.json`

Verifier reports extras deterministically.

## 3) Zip entry and path rules

- Only file entries are verified; directory entries are ignored.
- Canonical entry path uses `/` separators.
- Leading `./` and leading `/` are stripped.
- Entry processing order is deterministic: case-insensitive lexical, then case-sensitive lexical.

## 4) Schema version rule

Each mandatory JSON file must:

- parse as valid JSON
- contain top-level string `schema_version`
- have `schema_version` equal to its expected value:
  - `epi.evidence_pack.v1`
  - `epi.decision_pack.v1`
  - `epi.runlog.v1`
  - `epi.seal.v1`
  - `epi.claims.v1`
  - `epi.drift_report.v1`

## 5) Schema validation level

`epi-cli` performs minimal, deterministic schema validation against files under `contracts/v1`:

- top-level `required` keys
- top-level type checks
- top-level `const` and `enum` checks
- top-level `additionalProperties: false` enforcement

Nested JSON Schema behavior is not fully enforced in verifier mode.

## 6) Seal integrity rules

`epi.seal.v1.json` must contain `pack_files` entries with:

- `rel_path` (non-empty string)
- `sha256` (64 hex chars)

Verifier checks:

- `pack_files` is sorted by canonical path (deterministic ordering rule above)
- duplicate `rel_path` entries are rejected
- each listed `rel_path` exists in zip
- `sha256` matches actual zip entry bytes for listed files

Verifier also reports zip entries that are not listed in `pack_files` as `extras`.
Extras are informational and do not fail verification by themselves.

## 7) Verification outcome

`PASS` requires all of:

- no missing mandatory root files
- no schema errors
- no seal hash mismatches

`FAIL` occurs if any of those checks fail.

JSON output is stable and includes:

- `ok`
- `pack_path`
- `missing`
- `schema_errors`
- `hash_mismatches`
- `extras`
- `checked_entries_count`
- `timestamp_utc`
