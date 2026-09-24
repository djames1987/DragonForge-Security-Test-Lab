# Phase 8 Fuzz Corpus Schema

Phase 8 uses schema version 1 for deterministic fuzz corpora and promoted regression metadata.

## corpus.json

Fields:

- `schema_version`
- `target`
- `rng_seed`
- `source_sha256`
- `cases`

Each case contains:

- stable ID;
- generated filename;
- SHA-256;
- byte size;
- mutation name.

## Regression metadata

Each promoted regression fixture has adjacent JSON metadata containing:

- schema version;
- target;
- fixture filename;
- full SHA-256;
- original candidate filename;
- review note.

Promotion refuses an existing fixture/metadata pair, making duplicate handling fail closed.

## Reproducibility

For the same:

- target;
- source bytes;
- RNG seed;
- case count;

the generated case sequence, bytes, IDs, and SHA-256 hashes are deterministic.

## Corpus hygiene

Permanent regression fixtures must be synthetic or sanitized. Do not commit:

- production vaults;
- bearer tokens;
- passwords;
- recovery secrets;
- real device private keys;
- user files;
- raw customer captures.
