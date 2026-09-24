# Phase 11 — Windows Multi-User and ACL Testing

## Status

**Implementation Complete — Verification Pending**

Phase 11 adds Windows-local account boundary testing, ACL snapshot analysis, inherited-permission validation, and real cross-user read/write probes against disposable DragonForge-shaped fixtures.

## DragonForge Security Suite baseline

Phase 11 was designed against DragonForge Security Suite commit:

```text
8eb77b44027c9309ad28cc611deebf00ae5d52d6
```

The reviewed suite exposes concrete Windows permission boundaries:

- per-user Agent data under `%LOCALAPPDATA%\DragonForge\agent`;
- `agent-session.key`;
- `agent-runtime.json`;
- `agent.lock`;
- privileged-service configuration/audit/firewall state under `%ProgramData%\DragonForge\Security\privileged-service`;
- a virtual service identity `NT SERVICE\DragonForgePrivilegedService`;
- an explicit named-pipe DACL for the privileged service;
- a suite ACL review script that already treats Everyone, BUILTIN\Users, and Authenticated Users write access as findings.

Phase 11 tests those permission assumptions in a disposable lab rather than modifying live DragonForge data.

## Safety model

Phase 11 is **LabOnly**.

The active multi-user validator:

- must run on Windows;
- must run from an elevated Administrator PowerShell session;
- creates two temporary non-admin local users (owner and cross-user);
- creates a disposable ACL lab root under `C:\Users\Public`;
- never modifies live DragonForge directories;
- never grants the temporary user administrator rights;
- removes the temporary user and lab root during cleanup.

The CLI ACL analyzer is also LabOnly so ACL evidence from multi-user tests is not accidentally treated as an ordinary Safe scan.

## Active Windows ACL lab

The lab script is:

```powershell
scripts\invoke-phase11-acl-lab.ps1
```

It requires:

```text
-Root
-OwnerUser
-OtherUser
-Output
-LabAck
```

The two synthetic account passwords are passed only through the parent process environment as:

```text
DFSTL_PHASE11_OWNER_PASSWORD
DFSTL_PHASE11_OTHER_PASSWORD
```

Neither password is written into evidence.

## Restricted fixture

The lab creates DragonForge-shaped targets:

```text
agent\agent-runtime.json
agent\agent-session.key
agent\agent.lock
privileged-service\service-config.json
privileged-service\audit.jsonl
```

Restricted targets receive explicit ACLs for:

- the owner test user;
- `NT AUTHORITY\SYSTEM`;
- `BUILTIN\Administrators`.

Inheritance is disabled on the sensitive files.

The temporary non-admin owner account must be able to read and write `agent-session.key`.

The elevated Administrator running the lab must also retain read/write access.

A separate temporary non-admin account is then used to attempt:

- read access to `agent-session.key`;
- write access to `agent-session.key`.

Both cross-user operations must be denied.

## Inheritance regression fixture

The lab also creates an intentionally unsafe directory with:

```text
BUILTIN\Users : Modify
ContainerInherit,ObjectInherit
```

and places a synthetic `agent-session.key` below it.

This fixture proves that the analyzer detects:

- broad write access;
- inherited broad write access;
- unexpected inherited write access on a sensitive DragonForge-shaped target.

## ACL snapshot format

The active lab writes `acl-snapshot.tsv` with six tab-separated fields:

```text
target
owner
principal
access_type
rights
inherited
```

The Rust analyzer is bounded to:

- 256 ACL records;
- 2,048 path characters;
- 256 owner/principal characters.

## Read-only live DragonForge ACL capture

A real installation can be inspected without modifying it:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\capture-phase11-dragonforge-acls.ps1 -Output .\dragonforge-acls.tsv
```

The capture utility checks the known Agent paths under `%LOCALAPPDATA%` and privileged-service paths under `%ProgramData%`. It records only ACL metadata for targets that currently exist and does not change permissions.

## ACL analysis

Run:

```powershell
dfstl windows-acl analyze \
  --input .\acl-snapshot.tsv \
  --output .\results\phase11-acl-analysis \
  --lab-ack
```

The analyzer flags write-capable Allow ACEs for broad principals including:

- Everyone;
- BUILTIN\Users;
- Users;
- Authenticated Users;
- NT AUTHORITY\Authenticated Users.

It separately reports inherited broad writes and inherited unexpected writes on sensitive targets.

## Evidence

The active Windows lab writes:

```text
acl-snapshot.tsv
multi-user-results.json
SHA256SUMS
```

The Rust ACL analyzer writes:

```text
acl-analysis.json
SHA256SUMS
```

The multi-user result records only:

- owner user/SID;
- other user/SID;
- restricted target count;
- whether cross-user read was denied;
- whether cross-user write was denied;
- the synthetic inherited-broad-write fixture path;
- overall pass/fail.

No password is written to evidence.

## Runner integration

Phase 11 registers:

```text
ACL-WINDOWS-001
```

- category: `ACL`;
- safety: `lab-only`;
- model: `hybrid`.

Safe and Controlled modes skip it.

LabOnly mode permits it.

## Validation

Run from an **elevated Windows PowerShell** session:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-phase11-tests.ps1 -Release
```

The validator:

- checks elevation;
- provisions one temporary local non-admin account with a random synthetic password;
- validates rustfmt, strict Clippy, debug/release tests, and a fresh release CLI;
- runs the cross-user ACL lab;
- confirms cross-user read/write denial;
- independently validates lab SHA-256 evidence;
- runs the Rust ACL analyzer against the captured ACL snapshot;
- confirms the intentionally unsafe inherited fixture is detected;
- confirms Safe/Controlled/LabOnly runner boundaries;
- removes the temporary account and disposable lab state in cleanup.

## Exit criteria

Phase 11 is verified when the elevated Windows validation ends with:

```text
Warnings: 0
Failures: 0

PHASE 11 VALIDATION: PASS
```
