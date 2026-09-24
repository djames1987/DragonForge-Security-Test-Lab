# Phase 7 — Password Manager Sync/API Security Testing

## Status

**Verified Complete**

Phase 7 adds bounded security testing for the DragonForge Password Manager synchronization API.

## DragonForge Security Suite baseline

Phase 7 was designed against DragonForge Security Suite commit:

```text
a0b0b2f7acc8bcf78806761cb9e5c00ba0fef19f
```

The reviewed live sync protocol is version 2.

Relevant product boundaries include:

- random 256-bit bearer sync tokens;
- ML-DSA-65 device enrollment and signed device requests;
- five-minute device timestamp freshness;
- optimistic vault revision checks;
- pending, active, and revoked device states;
- signed device approval and revocation;
- recovery generation checks;
- 256-bit recovery nonces with replay tracking;
- recovery-key rotation and sync-token rotation;
- request body limits;
- request timeouts;
- response security headers;
- per-credential request rate limiting.

## Safety model

The live harness is **Controlled-class** and only accepts a literal IPv4-loopback URL:

```text
http://127.0.0.1:PORT
```

It refuses remote hosts and HTTPS URLs because the live harness is intended for a local development/test instance, not a production TLS endpoint.

The live probe does not provision accounts, enroll devices, upload vaults, approve devices, revoke devices, or complete recovery.

State-changing replay and mutation work is generated **offline** from an explicit captured request.

## Live loopback probe

Run:

```powershell
dfstl sync-api probe --base-url http://127.0.0.1:8787 --controlled
```

The bounded live matrix checks:

- health endpoint availability;
- security response headers;
- missing bearer authentication rejection;
- malformed bearer authentication rejection;
- invalid admin provisioning token rejection;
- unknown route handling;
- wrong-method handling;
- malformed recovery JSON rejection;
- oversized recovery request rejection.

These probes do not require valid user credentials.

## Captured-request mutation corpus

Run:

```powershell
dfstl sync-api mutate \
  --input .\capture.http \
  --output .\results\sync-api-mutations \
  --controlled
```

The source capture is read-only.

Phase 7 generates 12 offline cases:

1. exact request replay;
2. missing bearer token;
3. wrong bearer token;
4. device-ID substitution;
5. stale device timestamp;
6. invalid device signature;
7. base revision changed to zero;
8. body bit flip;
9. body truncation;
10. invalid enrollment proof;
11. invalid/replayed recovery nonce authorization;
12. malformed recovery completion JSON.

Each generated request has a SHA-256 entry.

No generated request is automatically transmitted.

## Replay coverage

The sync service currently has two distinct replay models:

- normal signed device requests use timestamp freshness plus revision/body binding;
- recovery authorization additionally consumes a 256-bit nonce and rejects reuse.

The offline exact-replay fixture is retained as a permanent regression input for isolated proxy/manual replay testing.

Phase 7 does not automatically replay a potentially state-changing captured PUT/POST against a real vault.

## Enrollment and authorization misuse

Offline mutations exercise the request properties that the current server binds cryptographically:

- bearer account identity;
- device UUID;
- ML-DSA request signature;
- signed timestamp;
- signed body digest;
- signed base revision;
- enrollment proof-of-possession;
- recovery account/vault/generation/nonce/signature data.

## Revision-race coverage

The `base-revision-zero` mutation provides a deterministic optimistic-concurrency adversarial input.

The expected server behavior is conflict unless revision zero is actually the valid current base revision.

Actual simultaneous multi-client write racing remains a later fault/concurrency lab concern.

## Recovery abuse coverage

The mutation corpus includes recovery authorization and recovery-completion malformed inputs.

The target product already tracks recovery generations and consumed recovery nonces. The Phase 7 fixtures are designed to verify those boundaries through an isolated proxy/manual target run without requiring recovery credentials inside DFSTL.

## Deterministic loopback regression

The DFSTL core test suite includes a disposable mock HTTP server bound to IPv4 loopback.

It verifies the real raw-HTTP probe implementation and all eight expected status/header classifications without requiring:

- a DragonForge account;
- a sync token;
- a device key;
- a recovery key;
- a database;
- an installed Password Manager.

## Evidence

The offline mutation corpus writes:

```text
sync-api-mutations.json
01-exact-replay.http
...
12-recovery-malformed-json.http
SHA256SUMS
```

## Runner integration

Phase 7 registers:

```text
API-SYNC-001
```

with:

- category: `API`;
- safety: `controlled`;
- execution model: `black-box`.

Safe mode skips it. Controlled and LabOnly runner policies permit the capability self-check.

## Validation

Run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-phase7-tests.ps1 -Release
```

The validator checks:

- rustfmt;
- strict Clippy;
- debug and release tests;
- protocol-v2 baseline;
- deterministic loopback API regression;
- refusal of non-loopback live targets;
- Controlled authorization gates;
- 12-case offline request mutation corpus;
- source-capture immutability;
- SHA-256 evidence manifest;
- Safe/Controlled/LabOnly runner behavior;
- release build.

## Verification record

Phase 7 was locally verified on Windows on 2026-09-23 against commit:

```text
dc78993ebde6eccc4df1609c80a99c383b11ee73
```

The release-mode validation completed with:

- a clean `main` branch;
- rustfmt passing;
- strict Clippy passing with warnings denied;
- 52 debug tests passing;
- 52 release tests passing;
- the dedicated non-state-changing sync API loopback regression passing;
- the offline request mutation regression passing;
- a fresh Phase 7 release CLI build succeeding;
- protocol-v2 and loopback-only CLI capability markers passing;
- `API-SYNC-001` registration confirmed;
- live probe refusal without `--controlled` confirmed;
- offline mutation refusal without `--controlled` confirmed;
- non-loopback live target refusal confirmed;
- the 12-case offline mutation corpus generated successfully;
- source capture hash preserved;
- all mutation evidence SHA-256 entries independently validated;
- Safe runner skipping the Controlled sync API harness;
- Controlled runner passing the sync API harness while keeping the filesystem LabOnly test skipped;
- LabOnly runner passing all eight registered tests;
- release workspace build succeeding;
- zero warnings and zero failures.

Validation evidence:

```text
phase7-validation-20260923-212131.log
SHA-256: 7D27289F930DA1F739E59CEE6549CCA2CAA8514C7720ABB771030F84DB1AF5F5
```
