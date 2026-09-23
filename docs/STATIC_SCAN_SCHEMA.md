# Static Scan JSON — Schema 1

Phase 3 emits `static-scan.json` and may also print the same structure to stdout with `--json`.

## Top-level fields

| Field | Type | Meaning |
| --- | --- | --- |
| schema_version | integer | Phase 3 emits 1 |
| source_root | string | Explicit source directory scanned |
| source_fingerprint | string | SHA-256 fingerprint over scanned relative paths and file digests |
| counts | object | Aggregate scan counters |
| dependency_count | integer | Number of Cargo.lock package records |
| findings | array | Secret and supply-chain findings |

## Counts

```json
{
  "files_scanned": 42,
  "secret_findings": 0,
  "supply_chain_findings": 3,
  "high_findings": 0,
  "warning_findings": 3
}
```

## Finding record

```json
{
  "id": "SUPPLY-ACTION-UNPINNED",
  "severity": "warning",
  "path": ".github/workflows/ci.yml",
  "line": 12,
  "summary": "GitHub Action is not pinned to a full commit SHA: actions/checkout@v4"
}
```

Secret findings deliberately do not contain matched secret values.

## Dependency inventory

`dependency-inventory.json` has schema version 1 and an ordered `dependencies` array.

Each record contains:

- name;
- version;
- source or null;
- checksum or null.

## SPDX SBOM

`sbom.spdx.json` uses SPDX 2.3 JSON fields.

The SBOM is generated from Cargo.lock only. It does not infer license metadata that Cargo.lock does not contain.

## External tool results

When `--external` is used, `external/external-tools.json` records one object each for:

- cargo_audit;
- cargo_deny;
- gitleaks_history.

Each includes:

- tool;
- status;
- exit_code;
- bounded textual output.

Status is one of `passed`, `failed`, or `unavailable`.
