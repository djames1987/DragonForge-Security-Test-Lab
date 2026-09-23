# Encrypted Mutation Corpus JSON — Schema 1

Phase 4 writes `corpus.json` for every generated encrypted-format mutation corpus.

## Top-level fields

| Field | Type | Meaning |
| --- | --- | --- |
| schema_version | integer | Phase 4 emits 1 |
| format | string | Selected mutation profile |
| seed_sha256 | string | SHA-256 of the original unmodified seed |
| seed_size_bytes | integer | Original seed length |
| cases | array | Generated mutation records |

## Mutation record

Each mutation contains:

```json
{
  "id": "future-version",
  "description": "sets format version to u16::MAX",
  "file_name": "future-version.dfbackup",
  "sha256": "<64 lowercase hex>",
  "size_bytes": 78
}
```

## Determinism

For the same seed bytes and mutation profile:

- mutation IDs are stable;
- mutations are generated in stable order;
- each mutation's bytes and SHA-256 are deterministic;
- `corpus.json` and `corpus.txt` contain no wall-clock timestamp.

The output directory path itself is not embedded in `corpus.json`, allowing identical seeds to produce identical corpus metadata regardless of destination path.

## SHA256SUMS

`SHA256SUMS` contains hashes for:

- every file beneath `cases/`;
- `corpus.json`;
- `corpus.txt`.

The original seed is identified by `seed_sha256` but is never copied into the corpus.

## Safety

Mutation output is generated only after:

- the explicit seed is validated against the selected format profile;
- the output directory is confirmed absent;
- the caller explicitly authorizes Controlled-class execution.
