# Phase 9 — Secret Leak and Memory Lifecycle Testing

## Status

**Verified Complete**

Phase 9 adds synthetic-secret leak detection across DragonForge diagnostic artifacts plus LabOnly offline process-dump analysis and secret-lifecycle evidence.

## DragonForge Security Suite baseline

Phase 9 was designed against DragonForge Security Suite commit:

```text
6337d081ed3b07ec333ba079ee30e2015b0ae1ba
```

The reviewed product already contains several relevant protections:

- `dragonforge-crypto::SecretKey` derives `Zeroize` and `ZeroizeOnDrop`;
- Password Manager Windows sync-secret serialization buffers are explicitly zeroized;
- Password Manager sync-token/device-signing secrets are stored in Windows Credential Manager rather than the version-3 sidecar;
- the shared redaction wrapper prevents Debug/Display disclosure but explicitly does not claim memory zeroization;
- shared crash hooks intentionally do not persist panic payloads or stack-local values;
- support bundles intentionally contain bounded sanitized metadata instead of recursively copying user/application data.

Phase 9 verifies leak behavior with synthetic sentinels rather than production credentials.

## Safety model

Artifact scanning is **Controlled-class**.

Process-dump scanning is **LabOnly** because a process dump may contain unrelated credentials, user content, cryptographic material, paths, or other highly sensitive data even when the requested test uses only synthetic sentinels.

DFSTL does not create process dumps in Phase 9. It only analyzes one explicit existing dump in place and never copies that dump into evidence.

## Synthetic sentinel file

Sentinels use a simple line-oriented format:

```text
# comments are allowed
sync-token=DFSTL-PHASE9-SYNC-TOKEN-0123456789
recovery-kit=DFSTL-PHASE9-RECOVERY-KIT-0123456789
otp-seed=DFSTL-PHASE9-OTP-SEED-0123456789
```

Rules:

- IDs are 1 to 64 ASCII letters, digits, dash, or underscore;
- values are synthetic ASCII only;
- values are 12 to 512 bytes;
- maximum 64 sentinels;
- the sentinel definition file is bounded to 64 KiB;
- an empty sentinel set is rejected.

Sentinel values are held in dedicated buffers whose Drop implementation overwrites the bytes with zero. The original sentinel-file read buffer and temporary raw/hex/Base64/UTF-16LE search patterns are also overwritten before deallocation.

Reports never include sentinel values.

## Artifact scan

Run:

```powershell
dfstl secret-leak scan \
  --root C:\path\to\DragonForge\logs \
  --root C:\path\to\DragonForge\support-bundle \
  --sentinels .\corpus\seeds\phase9-sentinels.txt \
  --output .\results\phase9-artifact-scan \
  --controlled
```

The scanner can be pointed at explicit:

- component log directories;
- AppData component directories;
- test temp directories;
- support-bundle output;
- cloned/disposable configuration directories.

Phase 9 deliberately does not auto-discover or recursively scan an entire user profile.

## Representations detected

Each synthetic sentinel is searched as:

- raw ASCII bytes;
- lowercase hexadecimal;
- Base64;
- UTF-16LE.

Findings contain only:

- sentinel ID;
- relative path;
- representation;
- byte offset.

## Containment and bounds

Artifact scanning:

- refuses symlink roots;
- skips symlink entries;
- canonicalizes traversed entries;
- does not follow junction/reparse paths outside the explicit root;
- tracks visited canonical directories to avoid reparse cycles;
- scans at most 4,096 files;
- scans at most 16 MiB per artifact file;
- scans at most 256 MiB total.

Oversized artifact files are reported as skipped rather than silently treated as scanned.

## Offline process-dump scan

Run only in an authorized disposable lab:

```powershell
dfstl secret-leak dump-scan \
  --dump C:\lab\dragonforge-password-manager.dmp \
  --sentinels .\corpus\seeds\phase9-sentinels.txt \
  --output .\results\phase9-dump-scan \
  --lab-ack
```

The dump scanner:

- accepts one explicit regular file;
- refuses symlinks;
- scans read-only;
- never copies the dump;
- streams data in bounded chunks;
- detects sentinels crossing chunk boundaries;
- supports dumps up to 512 MiB;
- writes only redaction-safe finding metadata.

Dump creation is intentionally outside DFSTL Phase 9. A developer may capture a dump using an approved Windows lab workflow after inserting only synthetic test secrets, then scan it with DFSTL.

## Memory lifecycle self-check

Run:

```powershell
dfstl secret-leak memory-check --controlled
```

This deterministic self-check allocates a synthetic secret marker, verifies it is present, overwrites the same buffer in place with zero bytes, and verifies the marker is absent before the allocation is dropped.

This proves the DFSTL lifecycle check itself. It does not independently prove compiler/runtime behavior for every secret allocation in DragonForge.

## Evidence

Artifact and dump scans write:

```text
secret-leak.json
secret-leak.txt
SHA256SUMS
```

The evidence never includes sentinel values or dump contents.

A non-empty finding set causes the CLI scan to return exit code 1.

## Runner integration

Phase 9 registers:

```text
LEAK-SENTINEL-001
MEMORY-LIFE-001
```

`LEAK-SENTINEL-001`:

- category: `LEAK`;
- safety: `controlled`;
- model: `white-box`.

`MEMORY-LIFE-001`:

- category: `MEMORY`;
- safety: `lab-only`;
- model: `hybrid`.

Safe mode skips both. Controlled mode permits the artifact-leak capability but skips memory-dump capability. LabOnly permits both.

## Known product limitations observed during Phase 9 review

The shared `Secret<T>` redaction wrapper explicitly protects formatting only and is not a zeroizing secret-memory container.

Password Manager Phase 11 currently provides OS-backed sync-secret storage on Windows. Linux/macOS retain legacy sidecar behavior for compatibility and do not claim equivalent OS-backed protection yet.

Phase 9 records these as product design boundaries rather than silently treating them as failures of the test lab.

## Validation

Run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-phase9-tests.ps1 -Release
```

The validator checks:

- rustfmt;
- strict Clippy;
- debug/release tests;
- raw/hex/Base64/UTF-16LE detection;
- report redaction;
- clean artifact scan and evidence manifest;
- synthetic memory lifecycle self-check;
- process-dump sentinel detection;
- Controlled and LabOnly command gates;
- clean CLI artifact scan;
- intentionally leaky CLI scan returning failure without disclosing the sentinel;
- LabOnly dump scan behavior;
- Safe/Controlled/LabOnly runner policy boundaries;
- release build.

## Verification record

Phase 9 was locally verified on Windows on 2026-09-23 against commit:

```text
8cedeea60559906ae691d52182bb7b8d0cf980e9
```

The release-mode validation completed with:

- a clean `main` branch;
- rustfmt passing;
- strict Clippy passing with warnings denied;
- 61 debug tests passing;
- 61 release tests passing;
- secret representation regression passing;
- process-dump regression passing;
- synthetic memory lifecycle regression passing;
- a fresh Phase 9 release CLI build succeeding;
- Phase 9 capability markers and LEAK/MEMORY registrations confirmed;
- Controlled artifact-scan refusal without `--controlled`;
- LabOnly dump-scan refusal without `--lab-ack`;
- Controlled memory-check refusal without `--controlled`;
- clean artifact scan producing zero findings;
- intentional raw secret leak detection without echoing the secret value;
- redaction-safe JSON/text evidence and independently validated SHA-256 manifests;
- synthetic memory lifecycle check passing;
- UTF-16LE process-dump sentinel detection;
- process-dump contents not copied into evidence;
- Safe runner skipping both LEAK and MEMORY capabilities;
- Controlled runner passing LEAK while keeping MEMORY and filesystem LabOnly tests skipped;
- LabOnly runner passing all 11 registered tests;
- release workspace build succeeding;
- zero warnings and zero failures.

Validation evidence:

```text
phase9-validation-20260923-222308.log
SHA-256: 3B06F1F897CE1FCAC8E18FA793799A86B84E491C8CF7BB300707664DDB3A0232
```
