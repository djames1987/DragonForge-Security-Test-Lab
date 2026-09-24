# Phase 9 Secret Leak Evidence Schema

Phase 9 uses schema version 1.

## secret-leak.json

Fields:

- `schema_version`;
- `scope` — `artifact-tree` or `process-dump`;
- `roots_scanned`;
- `files_scanned`;
- `bytes_scanned`;
- `skipped_oversized_files`;
- `clean`;
- `findings`.

Each finding contains only:

- `sentinel_id`;
- `relative_path`;
- `representation`;
- `offset`.

The sentinel value is never serialized.

## Sentinel representations

Stable representation labels:

- `raw`;
- `hex-lower`;
- `base64`;
- `utf16le`.

## Evidence bundle

Each scan bundle contains:

```text
secret-leak.json
secret-leak.txt
SHA256SUMS
```

The process dump itself is never copied into the evidence directory.

## Scope

This phase tests only synthetic sentinels supplied by the operator.

It does not attempt heuristic extraction of arbitrary real passwords, tokens, keys, cookies, or personal data from process memory.
