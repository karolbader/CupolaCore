# Cupola CLI Demo Script

## Prerequisites
- Rust toolchain installed (`cargo --version`)

## Setup
```bash
mkdir -p _tmp/demo-vault
printf "hello cupola\n" > _tmp/demo-vault/a.txt
```

## 1) Hash
```bash
cargo run -p cupola-cli -- hash --vault _tmp/demo-vault
```

## 2) Search (BM25)
```bash
cargo run -p cupola-cli -- search --vault _tmp/demo-vault --q hello --limit 5
```

Expected row shape:
`chunk_id | rel_path | [file_type] | mtime_ns | raw_blob_id | chunk_blob_id | lines | excerpt`

## 3) Freeze
```bash
cargo run -p cupola-cli -- freeze --vault _tmp/demo-vault --out _tmp/demo-vault.freeze.json
```

## 4) Verify (pass)
```bash
cargo run -p cupola-cli -- verify --vault _tmp/demo-vault --manifest _tmp/demo-vault.freeze.json
```

## 5) Verify fail case (MODIFIED)
```bash
printf "changed\n" >> _tmp/demo-vault/a.txt
cargo run -p cupola-cli -- verify --vault _tmp/demo-vault --manifest _tmp/demo-vault.freeze.json
```

Expected: verify exits non-zero and prints a line containing `MODIFIED a.txt`.
