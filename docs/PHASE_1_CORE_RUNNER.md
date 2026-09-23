# Phase 1 — Core Runner, Evidence Logging, and Reporting

## Status

**Implementation Complete — Verification Pending**

Phase 1 turns the Phase 0 foundation into an executable, safety-aware security-test controller.

## Delivered

### Test registry

- Stable test identifiers are centrally registered.
- Duplicate identifiers are rejected.
- Malformed identifiers are rejected before execution.
- Tests expose category, safety class, execution model, name, and stable ID.

### Core runner

- Executes registered tests through a central Runner.
- Enforces the Phase 0 ExecutionPolicy before test code is invoked.
- Tests above the active safety class are recorded as Skipped and are not executed.
- Test execution errors are recorded as InfrastructureError rather than target Fail.
- Run IDs include time, process identity, and an in-process monotonic counter.
- Run metadata records start/end time and the maximum allowed safety class.

### Result model

Phase 1 defines five distinct result states:

- Pass
- Fail
- Warning
- Skipped
- InfrastructureError

A target security failure and a test-framework/environment failure are intentionally not conflated.

### Evidence store

Each run is first written to an isolated staging directory.

The evidence layer:

- rejects absolute paths and traversal components;
- applies per-file, total-byte, and file-count limits;
- writes artifacts beneath per-test directories;
- rejects symlinks encountered while finalizing evidence;
- writes files through temporary siblings before rename;
- removes abandoned staging directories when an EvidenceSession is dropped;
- refuses to overwrite an existing finalized run directory;
- promotes a complete staging directory to the final run path only after reporting and manifest generation succeed.

Default evidence bounds:

| Limit | Default |
| --- | ---: |
| Per file | 1 MiB |
| Total run evidence | 8 MiB |
| File count | 128 |

Future phases may make these policy-configurable, but the runner is bounded from Phase 1 onward.

### Reporting

Every completed run produces:

- report.json — structured machine-readable report;
- report.txt — human-readable summary;
- SHA256SUMS — SHA-256 digest manifest;
- artifacts/<TEST-ID>/... — bounded test evidence.

The SHA-256 implementation is internal to dfstl-core and has known-answer tests for the empty input and "abc" vectors. This deliberately avoids introducing a dependency solely for report hashing.

### CLI

New commands:

```text
dfstl describe
dfstl list
dfstl run [--output PATH]
```

The default CLI run remains Safe-only.

Phase 1 includes two Safe internal validation tests:

- STATIC-RUNNER-001 — exercises the registered runner path and records synthetic evidence.
- STATIC-POLICY-001 — proves the default policy does not permit Controlled, Disruptive, or LabOnly execution.

No adversarial attack implementation is introduced by Phase 1.

## Evidence lifecycle

```text
results/
  .run-....staging/
       artifacts/
       report.json
       report.txt
       SHA256SUMS
             |
             | finalize succeeds
             v
  run-.... /
       artifacts/
       report.json
       report.txt
       SHA256SUMS
```

If finalization is abandoned, the staging directory is removed by the EvidenceSession cleanup lifecycle.

## Validation

Run on Windows:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-phase1-tests.ps1 -Release
```

The validator checks:

- repository branch and working-tree state;
- Phase 1 file presence;
- Cargo metadata;
- rustfmt;
- strict Clippy with warnings denied;
- debug tests;
- release tests;
- Phase 1 CLI model;
- registered built-in tests;
- a real Safe runner execution;
- JSON report parsing and result counts;
- finalized evidence layout;
- absence of abandoned staging directories;
- independent SHA-256 verification of every manifest entry;
- release build.

It writes:

```text
test-logs\phase1-validation-YYYYMMDD-HHMMSS.log
test-logs\phase1-validation-YYYYMMDD-HHMMSS.log.sha256
```

## Exit criteria

Phase 1 is verified when the full local validation harness completes with:

```text
Warnings: 0
Failures: 0

PHASE 1 VALIDATION: PASS
```
