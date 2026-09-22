# DFSTL Threat Model

## Assets

DFSTL must protect:

- the workstation/lab running tests;
- systems outside the authorized target scope;
- synthetic test credentials and generated keys;
- test evidence and result integrity;
- the distinction between production and disposable lab state;
- the reliability of security conclusions.

## Threat actors and failure sources

DFSTL should assume:

- a malformed DragonForge build can return hostile output;
- a compromised target process can attempt to confuse the test harness;
- malformed files can exploit parser assumptions in DFSTL itself;
- a developer can accidentally point a risky test at the wrong target;
- dependency or CI compromise can alter test behavior;
- concurrent processes can race filesystem and IPC tests;
- result files can leak synthetic or accidentally supplied real secrets;
- an unreliable environment can create false positives or false negatives.

## Primary security goals

### Prevent unintended damage

Risky operations must be classified and centrally gated.

### Prevent scope escape

The framework must not automatically expand from configured targets to unrelated hosts, accounts, processes, or files.

### Preserve result integrity

A report should identify:
- target;
- target build/commit/version when available;
- test identifier;
- test implementation version;
- start/end time;
- execution class;
- evidence hashes where practical;
- whether the outcome is pass, fail, warning, skipped, or infrastructure error.

### Avoid secret leakage

Only synthetic secrets should be used. Output should be redacted before storage.

### Resist hostile target output

Treat process stdout/stderr, JSON, file metadata, network responses, and filenames as untrusted and bounded input.

## Out of scope for Phase 0

Phase 0 does not implement:

- exploit payloads;
- denial-of-service attacks;
- fuzz execution;
- process termination;
- ACL mutation;
- clock manipulation;
- VM control;
- remote network attacks;
- credential extraction.

Those capabilities require later phases and the appropriate safety gates.
