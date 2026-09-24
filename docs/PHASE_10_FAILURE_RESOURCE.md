# Phase 10 — Failure Injection and Resource Exhaustion

## Status

**Verified Complete**

Phase 10 adds deterministic fault injection, recovery-consistency checks, bounded CPU/memory/loopback-socket stress, and a self-child-only process termination harness.

## DragonForge Security Suite baseline

Phase 10 was designed against DragonForge Security Suite commit:

```text
b81b41107698d1efe3d2ee7e1b99a23f10c37e7a
```

The reviewed product already has important failure-handling boundaries:

- bounded component logs with rotation;
- crash hooks that persist only sanitized public failure summaries;
- backup/restore flows that use staging locations and bounded archive/file/path limits;
- vault parsing limits that cap file size, item count, ciphertext size, and KDF parameters;
- Password Manager sync request limits and explicit timeout/rate-limit behavior;
- Agent health/shutdown paths that surface unavailable-service failures without arbitrary process control.

Phase 10 exercises the test-lab equivalents of these failure classes without filling disks, exhausting the host, or terminating DragonForge processes.

## Safety model

### Controlled deterministic fault injection

`failure inject` is **Controlled-class**.

It operates only beneath a brand-new explicit disposable root and uses synthetic fixtures.

It does not modify DragonForge installations, production vaults, or user data.

### LabOnly resource stress

`failure resource` is **LabOnly**.

Resource budgets are hard-capped by DFSTL:

- CPU iterations: maximum 2,000,000;
- memory allocation: maximum 64 MiB;
- loopback socket connections: maximum 256.

The default stress profile is intentionally lower:

- 100,000 CPU iterations;
- 8 MiB memory;
- 32 loopback connections.

### LabOnly process termination

`failure process-termination` is **LabOnly**.

It only spawns the current DFSTL executable with an internal helper command, verifies that helper is running, requests termination through the child handle, and waits for cleanup.

It never accepts a PID or executable path and therefore cannot target DragonForge or unrelated processes.

## Failure injection matrix

Run:

```powershell
dfstl failure inject \
  --root .\results\phase10-lab \
  --output .\results\phase10-failure-evidence \
  --controlled
```

The deterministic matrix contains:

### disk-full-write

Uses a synthetic writer that accepts a bounded prefix and then returns `StorageFull`.

No real disk is filled.

### permission-denied-write

Uses a synthetic writer that immediately returns `PermissionDenied`.

No real ACLs are changed.

### interrupted-atomic-write

Creates:

- a committed stable destination;
- a separate partial staging file.

Recovery verifies that:

- partial staging never replaces committed state;
- committed state remains byte-for-byte intact;
- stale staging is removed.

### interrupted-restore-recovery

Creates:

- an existing destination directory with committed content;
- a separate partial restore staging directory.

Recovery verifies that the existing destination remains intact and the partial staging directory is discarded.

## Bounded resource stress

Run:

```powershell
dfstl failure resource \
  --output .\results\phase10-resource \
  --lab-ack
```

Optional bounded overrides:

```text
--cpu N
--memory-bytes N
--sockets N
```

The stress path performs:

- repeated SHA-256 work for bounded CPU load;
- one bounded memory allocation with deterministic writes and hashing;
- bounded IPv4-loopback TCP connect/accept traffic.

No remote network target is accepted.

## Process termination

Run:

```powershell
dfstl failure process-termination --lab-ack
```

The harness:

1. locates the current DFSTL executable;
2. launches only its hidden Phase 10 worker mode;
3. waits briefly;
4. verifies the child is still running;
5. requests child termination;
6. waits for cleanup;
7. reports pass/fail.

## Evidence

Failure injection writes:

```text
failure-injection.json
SHA256SUMS
```

Resource stress writes:

```text
resource-stress.json
SHA256SUMS
```

Evidence includes only bounded synthetic test metadata.

## Runner integration

Phase 10 registers:

```text
FAULT-INJECT-001
RESOURCE-LAB-001
FAULT-KILL-001
```

### FAULT-INJECT-001

- category: `FAULT`;
- safety: `controlled`;
- execution model: `white-box`.

### RESOURCE-LAB-001

- category: `RESOURCE`;
- safety: `lab-only`;
- execution model: `hybrid`.

### FAULT-KILL-001

- category: `FAULT`;
- safety: `lab-only`;
- execution model: `black-box`.

Safe mode skips all three.

Controlled mode permits only `FAULT-INJECT-001`.

LabOnly mode permits all three.

## Validation

Run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-phase10-tests.ps1 -Release
```

The validator checks:

- rustfmt;
- strict Clippy;
- debug/release tests;
- deterministic fault matrix;
- recovery consistency;
- failure-evidence SHA-256 manifest;
- resource-budget refusal;
- bounded CPU/memory/socket stress;
- resource-evidence SHA-256 manifest;
- self-child process termination;
- Controlled/LabOnly command gates;
- Safe/Controlled/LabOnly runner policy behavior;
- release build.

## Verification record

Phase 10 was locally verified on Windows on 2026-09-23 against commit:

```text
47653dbadc1d24e0440f82630a147b0138667898
```

The release-mode validation completed with:

- a clean `main` branch;
- rustfmt passing;
- strict Clippy passing with warnings denied;
- 65 debug tests passing;
- 65 release tests passing;
- deterministic failure-injection regression passing;
- bounded resource-stress regression passing;
- failure-evidence manifest regression passing;
- a fresh Phase 10 release CLI build succeeding;
- Phase 10 capability markers and FAULT/RESOURCE registrations confirmed;
- Controlled failure-injection refusal without `--controlled`;
- LabOnly resource-stress refusal without `--lab-ack`;
- LabOnly self-child termination refusal without `--lab-ack`;
- all four deterministic failure cases passing;
- committed atomic state preserved and stale staging removed;
- interrupted restore destination preserved and partial staging removed;
- over-budget resource requests failing closed without evidence creation;
- bounded CPU/memory/loopback-socket stress passing with SHA-256 evidence;
- self-child process termination completing successfully;
- Safe runner skipping all Phase 10 higher-safety tests;
- Controlled runner passing failure injection while keeping LabOnly resource/kill tests skipped;
- LabOnly runner passing all 14 registered tests;
- release workspace build succeeding;
- zero warnings and zero failures.

Validation evidence:

```text
phase10-validation-20260923-224100.log
SHA-256: A3EF9C4C23B10959221A600FD27515F09BC7EEA221DAD9C3658F08DAD06C3E47
```
