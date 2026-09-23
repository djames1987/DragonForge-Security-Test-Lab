# Phase 6 — Filesystem, Reparse-Point, and TOCTOU Lab

## Status

**Implementation Complete — Verification Pending**

Phase 6 adds a disposable LabOnly filesystem-security harness for Windows-oriented path containment, reparse points, hard links, and TOCTOU race behavior.

## DragonForge Security Suite baseline

Phase 6 was designed against DragonForge Security Suite commit:

```text
37544b7af94f6b7e61be5425a352d90280987405
```

The reviewed product boundaries include:

- File Vault sibling staging and final rename extraction;
- Backup/Recovery sibling staging and restore containment;
- Secure Share attachment extraction;
- source symlink rejection already present in product code;
- relative-path validation that rejects absolute/traversal-like archive paths.

## Safety model

The filesystem executor is **LabOnly**.

It requires:

```text
--lab-ack
```

and one explicit, non-existing lab root.

Example:

```powershell
dfstl filesystem lab --root C:\DFSTL-Lab\phase6-run --lab-ack
```

The lab refuses existing roots and does not intentionally operate outside the supplied root.

The deterministic path-policy corpus is read-only and may be run without LabOnly authorization:

```powershell
dfstl filesystem path-corpus
```

## Path-policy corpus

Phase 6 includes deterministic cases for:

- normal nested relative paths;
- Unicode paths;
- `.` and `..`;
- absolute paths;
- backslash traversal forms;
- drive prefixes;
- UNC syntax;
- alternate-data-stream colons;
- Windows reserved device names such as `CON`, `NUL`, `COM1`, and `LPT9`;
- trailing dots/spaces;
- empty components;
- controls;
- decomposed Unicode.

The Phase 6 policy intentionally rejects Windows-dangerous names even where the product's current container-level relative-path validator is less strict.

## Disposable filesystem matrix

The LabOnly executor covers:

- canonical staging containment;
- destination creation race after an absence check;
- hard-link alias semantics;
- source replacement between metadata observation and later read;
- Windows directory reparse/symlink creation where permitted;
- Windows file reparse/symlink creation where permitted.

Reparse creation is reported as **skipped** when the Windows token/policy does not permit symlink creation. It is never silently reported as a pass.

## TOCTOU model

Phase 6 does not race production files.

All race cases use disposable files beneath the new lab root and demonstrate security-relevant primitives:

- precheck-then-create races;
- source replacement after metadata observation;
- hard-link aliasing;
- staging-root containment.

Process-kill and live restore interruption remain reserved for later disruptive fault-injection phases.

## Evidence

A completed filesystem lab writes:

```text
filesystem-lab.json
filesystem-lab.txt
SHA256SUMS
```

plus the disposable objects used by the cases.

Symlink/reparse entries are excluded from recursive evidence reads so the manifest does not follow them outside their link node.

## Runner integration

Phase 6 registers:

```text
FS-LAB-001
```

with:

- category: `FS`;
- safety: `lab-only`;
- execution model: `hybrid`.

The Safe and Controlled runners skip it. Only:

```powershell
dfstl run --lab-ack
```

authorizes the LabOnly capability self-check.

## Validation

Run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-phase6-tests.ps1 -Release
```

The validator checks:

- rustfmt;
- strict Clippy;
- debug/release tests;
- deterministic path corpus;
- LabOnly refusal without acknowledgement;
- disposable lab execution;
- hard-link and TOCTOU cases;
- containment;
- reparse case reporting;
- evidence files and manifest;
- Safe/Controlled/LabOnly runner behavior;
- release build.

## Exit criteria

Phase 6 is verified when validation ends with:

```text
Warnings: 0
Failures: 0

PHASE 6 VALIDATION: PASS
```
