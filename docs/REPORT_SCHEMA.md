# DFSTL Report Schema — Version 1

Phase 1 introduces the first stable machine-readable run report.

## Location

Each finalized evidence directory contains:

```text
report.json
report.txt
SHA256SUMS
artifacts/
```

## JSON document

The top-level fields are:

| Field | Type | Meaning |
| --- | --- | --- |
| schema_version | integer | Report schema version. Phase 1 emits 1. |
| run_id | string | Unique run identifier. |
| started_unix_ms | integer | Run start time in Unix milliseconds. |
| finished_unix_ms | integer | Run completion time in Unix milliseconds. |
| maximum_safety_class | string | Highest safety class authorized for the run. |
| counts | object | Aggregate result counters. |
| tests | array | Per-test result records. |

### counts

```json
{
  "pass": 2,
  "fail": 0,
  "warning": 0,
  "skipped": 0,
  "infrastructure_error": 0
}
```

### test record

Each entry contains:

| Field | Type | Meaning |
| --- | --- | --- |
| id | string | Stable test identifier. |
| name | string | Human-readable test name. |
| category | string | Stable taxonomy category code. |
| safety | string | Declared safety class. |
| model | string | black-box, white-box, or hybrid. |
| status | string | pass, fail, warning, skipped, or infrastructure-error. |
| summary | string | Bounded human-readable result summary. |
| duration_ms | integer | Individual execution duration. |
| artifact_count | integer | Number of artifacts persisted for the test. |

## Result semantics

**pass** means the expected security invariant held.

**fail** means the target violated the expected security invariant with sufficient evidence.

**warning** means execution completed but produced a condition requiring review.

**skipped** means the test was intentionally not executed, including safety-policy rejection.

**infrastructure-error** means DFSTL or its execution environment could not reliably complete the test. It must not be reported as a target vulnerability.

## Evidence manifest

SHA256SUMS contains lowercase hexadecimal SHA-256 digests followed by two spaces and a forward-slash-normalized relative path.

Example:

```text
<64 hex chars>  artifacts/STATIC-RUNNER-001/runner-self-check.txt
<64 hex chars>  report.json
<64 hex chars>  report.txt
```

The manifest does not hash itself.

The Phase 1 validation script independently recomputes every listed digest using Windows PowerShell Get-FileHash.

## Compatibility rule

Consumers must inspect schema_version before interpreting the report. Future incompatible report changes require a schema-version increment rather than silently changing Version 1 semantics.
