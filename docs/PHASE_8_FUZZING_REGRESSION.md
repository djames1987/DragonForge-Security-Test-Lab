# Phase 8 — Fuzzing and Security Regression Corpus

## Status

**Implementation Complete — Verification Pending**

Phase 8 adds deterministic structure-aware fuzz corpus generation, cargo-fuzz targets, crash minimization support, and permanent regression promotion.

## Safety model

The built-in fuzz corpus generator and regression promotion commands are **Controlled-class**.

They only read explicit seed/candidate files and write to explicit output roots. They do not launch DragonForge applications, connect to network services, or mutate source inputs.

The cargo-fuzz targets are side-effect-free white-box entry points over bounded parser/shape logic.

## Fuzz targets

Phase 8 defines eight stable targets:

- `dfvault`
- `dfbackup`
- `dfshare`
- `dfauth`
- `password-manager-json`
- `agent-json`
- `sync-http`
- `windows-path`

## Deterministic corpus engine

Run:

```powershell
dfstl fuzz corpus \
  --target agent-json \
  --input .\corpus\seeds\agent-json.json \
  --output .\results\fuzz-agent-json \
  --controlled \
  --seed 42 \
  --count 32
```

The engine uses a deterministic XorShift64 PRNG plus a 12-operation mutation cycle:

- empty input;
- truncate to one byte;
- truncate to half;
- append zero;
- append 0xff;
- seeded bit flip;
- seeded zero-byte overwrite;
- seeded 0xff overwrite;
- structure-aware version mutation;
- structure-aware length mutation;
- structure-aware separator/boundary mutation;
- seeded byte insertion.

Structure-aware mutations differ by target family. Binary formats receive version/length/prefix boundary changes. JSON targets receive extreme version/length and concatenated-object shapes. Sync HTTP receives revision/content-length/header-boundary mutations. Windows paths receive traversal, reserved-device, long-segment, and empty-segment shapes.

Corpus generation is bounded to:

- maximum seed size: 2 MiB;
- maximum generated cases per command: 256;
- default generated cases: 32.

Every corpus writes:

```text
case-0000.bin
...
corpus.json
SHA256SUMS
```

## cargo-fuzz project

The repository contains an isolated `fuzz/` cargo-fuzz project, excluded from the normal workspace.

Targets:

```text
encrypted_formats
agent_json
sync_http
windows_path
```

Example:

```powershell
cargo install cargo-fuzz
cargo fuzz run --manifest-path .\fuzz\Cargo.toml agent_json
```

The targets call the side-effect-free `exercise_fuzz_input` API. They do not open sockets, alter runtime files, or write to product data.

## Crash minimization

The core library exposes:

```rust
minimize_with_oracle(input, predicate)
```

The deterministic minimizer:

1. verifies the original input preserves the oracle;
2. removes progressively smaller chunks;
3. reduces granularity when successful;
4. simplifies remaining bytes to canonical values when the oracle still holds.

This supports unit/integration minimization where DFSTL can express the failure predicate directly.

For native libFuzzer crashes, cargo-fuzz's built-in minimization may also be used before promotion.

## Permanent regression promotion

Run:

```powershell
dfstl fuzz promote \
  --target windows-path \
  --input .\candidate.bin \
  --regression-root .\corpus\regression \
  --controlled \
  --note "security invariant"
```

Promotion:

- hashes the candidate with SHA-256;
- groups fixtures by stable fuzz target;
- names the fixture from the first 16 SHA-256 hex characters;
- writes adjacent JSON metadata;
- refuses overwrite or duplicate promotion;
- never modifies the source candidate.

Only synthetic or sanitized cases belong in the checked-in regression corpus.

## Initial permanent regression

Phase 8 includes a synthetic Windows-path fixture:

```text
corpus/regression/windows-path/1db796ce72aa13d4.bin
```

It represents `../CON.txt` and permanently protects traversal plus Windows reserved-device-name rejection.

## Runner integration

Phase 8 registers:

```text
FUZZ-CORPUS-001
```

with:

- category: `FUZZ`;
- safety: `controlled`;
- execution model: `white-box`.

Safe mode skips it. Controlled and LabOnly policies permit the capability self-check.

## Validation

Run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-phase8-tests.ps1 -Release
```

The validator checks:

- rustfmt;
- strict Clippy;
- debug/release tests;
- deterministic same-seed corpus reproduction;
- all eight target names;
- minimizer regression;
- permanent regression promotion/no-overwrite;
- Phase 8 CLI model;
- Controlled authorization;
- generated corpus count and hashes;
- source seed immutability;
- checked-in permanent regression hash/metadata;
- cargo-fuzz project and four target files;
- Safe/Controlled/LabOnly runner behavior;
- release build.

## Exit criteria

Phase 8 is verified when the local validator ends with:

```text
Warnings: 0
Failures: 0

PHASE 8 VALIDATION: PASS
```
