# Phase 4 — Encrypted-Format Adversarial Testing

## Status

**Implementation Complete — Verification Pending**

Phase 4 adds bounded, structure-aware mutation corpora for DragonForge encrypted/protected file formats. Mutation is **Controlled-class** and requires explicit authorization.

## DragonForge Security Suite baseline

Phase 4 was designed against DragonForge Security Suite commit:

```text
6d74d8a61260420ce51cdf52d4da8a15d3c6b781
```

The mutation profiles track the current parser contracts for:

- File Vault `.dfvault`;
- Backup/Recovery `.dfbackup`;
- Secure Share `.dfshare`;
- Authenticator `.dfauth`;
- Password Manager persistent protected `.dfvault` JSON/envelope structure.

## Safety model

Encrypted-format mutation is classified as:

```text
Controlled
```

DFSTL does not enable it under the default Safe policy.

The dedicated command requires explicit `--controlled`:

```powershell
dfstl format mutate --format dfbackup --input .\seed.dfbackup --output .\results\backup-corpus --controlled
```

Without `--controlled`, DFSTL refuses the operation before creating output.

The normal runner also preserves central safety enforcement:

```powershell
dfstl run --output .\results
```

skips the Controlled Phase 4 test, while:

```powershell
dfstl run --controlled --output .\results-controlled
```

explicitly authorizes it.

## Mutation corpus safety

- seed path must be explicit;
- seed must be a regular file;
- symlink seeds are rejected;
- maximum seed size is 64 MiB;
- the seed is never modified;
- output directory must not already exist;
- corpus files use create-new writes;
- each mutation is SHA-256 recorded;
- corpus metadata and a `SHA256SUMS` manifest are generated;
- no target executable is launched by the mutation generator.

## File Vault and Authenticator profile

Current File Vault and Authenticator formats both use a 46-byte authenticated header containing:

- 4-byte magic;
- little-endian u16 format version;
- Argon2 memory;
- Argon2 iterations;
- Argon2 lanes;
- 16-byte salt;
- 12-byte nonce.

Phase 4 generates cases covering:

- empty input;
- one-byte truncation;
- header-minus-one truncation;
- exact-header truncation;
- midpoint truncation;
- bad magic;
- version zero;
- future/unsupported version;
- authenticated-header bit flip;
- ciphertext bit flip;
- final authentication-tag bit flip;
- trailing byte;
- Argon2 memory zero and u32::MAX;
- Argon2 iterations zero and u32::MAX;
- Argon2 lanes zero and u32::MAX.

This exercises the current defensive checks that reject unsupported format/KDF parameters before expensive cryptographic work.

## Backup and Secure Share profile

Current Backup and Secure Share formats also use a 46-byte authenticated header:

- 8-byte magic;
- little-endian u16 format version;
- 16-byte salt;
- 12-byte nonce;
- little-endian u64 ciphertext length.

Phase 4 covers the common truncation/version/tamper cases plus:

- ciphertext length zero;
- ciphertext length u64::MAX;
- length one byte below actual;
- length one byte above actual.

These cases specifically target the current pre-decryption length validation and the use of the complete header as AEAD AAD.

## Password Manager protected vault profile

Password Manager uses a JSON-structured persistent vault with encrypted envelopes rather than the binary 46-byte container header.

Phase 4 therefore uses a separate profile:

- empty file;
- one-byte truncation;
- midpoint truncation;
- malformed JSON;
- version zero;
- future version 65535;
- JSON-content bit flip;
- appended second JSON object.

The profile requires a UTF-8 JSON object containing a numeric `version` field before mutation begins.

This complements the product's existing defensive limits for vault size, item count, KDF parameters, envelope shapes, ciphertext sizes, UUIDs, revisions, and timestamp ordering.

## Corpus layout

A successful mutation run produces:

```text
<output>/
├── corpus.json
├── corpus.txt
├── SHA256SUMS
└── cases/
    ├── empty.<ext>
    ├── truncate-one.<ext>
    ├── ...
    └── format-specific-cases.<ext>
```

`corpus.json` records:

- schema version;
- mutation profile;
- original seed SHA-256;
- seed byte count;
- mutation case IDs;
- descriptions;
- output filenames;
- mutation SHA-256 values;
- mutation byte counts.

## Format names

Accepted CLI names include:

| Format | Accepted name |
| --- | --- |
| File Vault | `dfvault`, `file-vault` |
| Backup | `dfbackup`, `backup` |
| Secure Share | `dfshare`, `secure-share` |
| Authenticator | `dfauth`, `authenticator` |
| Password Manager vault | `password-manager`, `password-manager-dfvault`, `pm-vault` |

## Runner integration

Phase 4 registers:

```text
PARSER-MUTATE-001
```

with:

- category: `PARSER`;
- safety: `controlled`;
- execution model: `white-box`.

This makes the safety boundary visible in `dfstl list` and test evidence.

## Validation

Run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-phase4-tests.ps1 -Release
```

The validator uses disposable synthetic seeds only. It verifies:

- rustfmt;
- strict Clippy;
- debug and release tests;
- Phase 4 CLI capability markers;
- Controlled-class registration;
- refusal without `--controlled`;
- File Vault mutation matrix;
- Authenticator mutation matrix;
- Backup length mutation matrix;
- Secure Share length mutation matrix;
- Password Manager JSON/version mutation matrix;
- seed SHA-256 remains unchanged;
- existing output is never overwritten;
- corpus JSON and SHA-256 manifest correctness;
- Safe runner skips the Controlled test;
- Controlled runner executes the test;
- release build.

## Exit criteria

Phase 4 is verified when the release-mode validator ends with:

```text
Warnings: 0
Failures: 0

PHASE 4 VALIDATION: PASS
```
