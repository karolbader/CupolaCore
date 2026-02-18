# EPI Contracts v1

These files are JSON Schema (draft 2020-12) contracts for EPI `v1` payloads.

Pack-level verification contract:

- `EPI_PACK_SPEC.md`

Demo JSON instances live under:

- `demo_packs/v0/demo_pack/`

Current validation behavior:

- `epi-cli verify` and `epi-cli schema-validate` enforce deterministic top-level checks.
- Full nested JSON Schema rule enforcement is intentionally out of scope for Gate E/F.
