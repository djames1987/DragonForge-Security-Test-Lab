# Phase 3 — Static, Dependency, Supply-Chain, and Secret Scanning

## Status

**Implementation Complete — Verification Pending**

Phase 3 adds a Safe-class, read-only source security scanner plus explicit integrations for established Rust and Git-history security tools.

## DragonForge Security Suite baseline

Phase 3 was designed against the current Security Suite source layout and controls on 2026-09-23.

The Suite currently includes:

- a root Cargo workspace and Cargo.lock;
- a documented cargo-audit policy in `.cargo/audit.toml`;
- a scheduled Rust dependency audit workflow;
- GitHub Actions referenced by version tags such as `actions/checkout@v4`;
- a Password Manager Windows job using `runs-on: self-hosted`.

DFSTL records these repository facts as evidence. It does not silently rewrite the Suite's audit policy or treat an unavailable external tool as a successful scan.

## Built-in scanner

Run:

```powershell
dfstl source scan --source C:\DragonForge-Security-Suite --output .\results\suite-static
```

Machine-readable stdout:

```powershell
dfstl source scan --source C:\DragonForge-Security-Suite --output .\results\suite-static --json
```

The scan is bounded and read-only.

### Traversal limits

- maximum 25,000 discovered files;
- maximum 2 MiB per text file;
- symlinks are not followed;
- `.git`, `target`, `node_modules`, `dist`, `test-logs`, and `results` directories are skipped.

### Source fingerprint

Every readable scanned file contributes its relative path and SHA-256 to a deterministic source fingerprint.

The fingerprint correlates scan evidence with the exact source tree examined. It is not a source-authenticity signature.

## Dependency inventory

If a root Cargo.lock exists, Phase 3 extracts each package:

- name;
- version;
- source when present;
- checksum when present.

The resulting evidence is:

```text
dependency-inventory.json
```

Workspace/path packages without source/checksum are retained rather than discarded.

## SPDX SBOM

Phase 3 emits:

```text
sbom.spdx.json
```

using SPDX 2.3 JSON fields and one package record per Cargo.lock entry.

The Phase 3 SBOM intentionally records package identity and download source from Cargo.lock. License discovery/resolution is not inferred from Cargo.lock and therefore remains `NOASSERTION`.

The creation timestamp is fixed to the Unix epoch so identical dependency/source inputs produce deterministic SBOM bytes. The source fingerprint is embedded in the document namespace.

## Built-in secret scanning

Phase 3 includes high-confidence signatures for:

- PEM private-key headers;
- GitHub fine-grained PAT prefixes;
- GitHub classic token prefixes;
- AWS access-key identifiers.

Secret evidence contains only:

- rule ID;
- severity;
- relative file path;
- line number;
- generic finding summary.

The matched secret value is never copied into the report.

High-confidence secret findings are severity `high` and cause the CLI to exit with code 1.

## GitHub Actions supply-chain checks

Workflow files beneath `.github/workflows/` are checked for:

- external actions not pinned to a full 40-character Git commit SHA;
- `self-hosted` runners;
- `permissions: write-all`;
- `pull_request_target`.

Current behavior:

| Finding | Severity |
| --- | --- |
| Action ref not full commit SHA | warning |
| self-hosted runner | warning |
| write-all token permissions | high |
| pull_request_target | warning |

Warnings are evidence and do not by themselves cause a non-zero source-scan exit.

## External integrations

With explicit `--external`:

```powershell
dfstl source scan --source C:\DragonForge-Security-Suite --output .\results\suite-static --external
```

DFSTL attempts:

- `cargo audit --json`;
- `cargo deny check`;
- `gitleaks git --redact --report-format json`.

External output is bounded before being stored.

The integration distinguishes:

- `passed`;
- `failed`;
- `unavailable`.

An unavailable requested scanner is a coverage gap, not a pass.

### External exit behavior

- an external scanner failure returns exit code 1;
- one or more requested scanners unavailable returns exit code 5 when there are no failures/high findings;
- orchestration/I/O failures return exit code 3.

The Suite's existing `.cargo/audit.toml` is honored by cargo-audit because the command executes in the explicit source root. DFSTL does not override documented advisory exceptions.

## Evidence bundle

A built-in scan produces:

```text
<output>/
├── static-scan.json
├── static-scan.txt
├── dependency-inventory.json
└── sbom.spdx.json
```

With `--external`:

```text
<output>/external/
├── external-tools.json
└── gitleaks-history.json   # when produced by gitleaks
```

## CLI exit codes

| Code | Meaning |
| ---: | --- |
| 0 | built-in scan completed without high findings; requested external tools passed or were not requested |
| 1 | high finding or requested external scanner failure |
| 2 | CLI usage error |
| 3 | scan/orchestration/evidence I/O failure |
| 5 | requested external coverage incomplete because at least one tool is unavailable |

## Safe runner integration

Phase 3 adds:

```text
STATIC-SUPPLY-001
```

This Safe self-check confirms built-in static, dependency, SBOM, supply-chain, and secret-scanning capabilities are registered.

## Validation

Run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-phase3-tests.ps1 -Release
```

The validator uses disposable synthetic source repositories only. It verifies:

- rustfmt and strict Clippy;
- debug and release tests;
- Phase 3 CLI capability markers;
- clean source scan;
- Cargo.lock dependency inventory;
- SPDX 2.3 JSON parsing;
- deterministic source-fingerprint shape;
- unpinned-Action warning;
- self-hosted-runner warning;
- synthetic GitHub PAT detection;
- non-disclosure of the synthetic secret in evidence;
- Phase 3 Safe runner regression;
- release build.

External tools are integration capabilities, not mandatory validator prerequisites; the validator remains deterministic on workstations where cargo-audit, cargo-deny, or gitleaks are not installed.

## Exit criteria

Phase 3 is verified when the local release-mode validator reports:

```text
Warnings: 0
Failures: 0

PHASE 3 VALIDATION: PASS
```
