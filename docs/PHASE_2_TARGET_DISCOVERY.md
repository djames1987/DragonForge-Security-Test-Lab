# Phase 2 — DragonForge Discovery and Build Identification

## Status

**Implementation Complete — Verification Pending**

Phase 2 gives DFSTL a read-only target-discovery and build-identification layer before adversarial product testing begins.

## Product baseline

Phase 2 is aligned to the DragonForge Security Suite Windows packaging script on 2026-09-23 at Security Suite commit `0c551479d9051bede79108d01e3fccb3bc7a4b24`.

The current package contract contains 11 sibling executables:

1. `dragonforge-desktop.exe`
2. `dragonforge-security-center.exe`
3. `dragonforge-file-vault.exe`
4. `dragonforge-authenticator.exe`
5. `dragonforge-security-scanner.exe`
6. `dragonforge-integrity-monitor.exe`
7. `dragonforge-network-guard.exe`
8. `dragonforge-backup-recovery.exe`
9. `dragonforge-secure-share.exe`
10. `dragonforge-agent.exe`
11. `dragonforge-privileged-service.exe`

Some older release documentation still describes a ten-executable package because it predates the privileged service. DFSTL follows the current packaging script rather than that historical count.

## Delivered

### Explicit target selection

DFSTL does not scan the entire workstation for DragonForge installations.

The user supplies an explicit local path:

```powershell
cargo run -p dfstl-cli -- target inspect --target C:\DragonForge-Test-Build
```

The supplied path may be:

- the exact directory containing a DragonForge build; or
- a parent directory containing exactly one immediate DragonForge candidate.

If multiple candidate child directories exist, DFSTL refuses automatic selection and returns an ambiguity error.

### Build identification

For every expected executable that exists, Phase 2 records:

- exact package filename;
- byte size;
- SHA-256 digest.

A deterministic build fingerprint is calculated from the sorted executable identity records. The fingerprint identifies the inspected executable set; it is not a digital signature and does not establish publisher authenticity.

### Package completeness

A target is complete only when all 11 current expected executables are present as regular files.

Missing expected executables are listed explicitly.

Additional files matching `dragonforge-*.exe` that are not part of the current package contract are recorded as unexpected executables for review but do not silently replace expected components.

Expected executable symlinks are rejected rather than followed.

### BUILD-INFO metadata

When `BUILD-INFO.txt` exists, DFSTL parses the current package fields:

- Version
- Release channel
- Git commit
- Git tag
- Built (UTC)
- Platform
- Code signing

Build metadata is optional so development `target\release` directories can still be fingerprinted.

### Package manifest validation

When `SHA256SUMS.txt` exists, DFSTL checks that every present expected executable has a manifest entry and that the manifest hash matches DFSTL's independently calculated SHA-256.

Manifest states are:

- `absent` — no packaged checksum manifest exists;
- `valid` — all present expected executables match;
- `invalid` — malformed, duplicated, missing, or mismatched executable checksum data.

A complete development build with no package manifest may still be identified. An invalid manifest causes the CLI inspection to fail.

## CLI

Human-readable inspection:

```powershell
cargo run -p dfstl-cli -- target inspect --target C:\DragonForge-Test-Build
```

Machine-readable JSON:

```powershell
cargo run -p dfstl-cli -- target inspect --target C:\DragonForge-Test-Build --json
```

Target inspection is Safe-class behavior. DFSTL reads files and hashes bytes; it does not launch the DragonForge binaries.

## Exit behavior

| Exit code | Meaning |
| ---: | --- |
| 0 | target selected and package is complete; manifest is valid or absent |
| 1 | selected target is incomplete or has an invalid checksum manifest |
| 2 | CLI usage error |
| 3 | inspection/evidence I/O failure |
| 4 | target selection failure, including ambiguity |

## Safe runner integration

Phase 2 adds:

```text
STATIC-TARGET-001
```

This Safe self-check confirms the controller is tracking the current 11-executable target contract.

## Validation

Run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-phase2-tests.ps1 -Release
```

The validator checks:

- repository cleanliness and required files;
- rustfmt;
- strict Clippy with warnings denied;
- debug and release unit tests;
- Phase 2 CLI capability markers;
- Phase 2 Safe runner registration;
- complete synthetic package identification;
- parsing of synthetic version and commit metadata;
- validation of synthetic `SHA256SUMS.txt`;
- independent PowerShell SHA-256 comparison against DFSTL output;
- automatic selection of exactly one immediate child target;
- incomplete package detection after removing `dragonforge-agent.exe`;
- fail-closed behavior with two target candidates;
- Safe runner regression;
- release build.

The validation harness uses disposable synthetic executables only and writes its fixtures beneath ignored `results/`.

## Exit criteria

Phase 2 is verified when the release-mode validation ends with:

```text
Warnings: 0
Failures: 0

PHASE 2 VALIDATION: PASS
```
