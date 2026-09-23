# DragonForge Security Test Lab Roadmap

## Phase 0 — Architecture, Safety Model, and Test Taxonomy

**Status: Verified Complete**

Deliverables:
- repository charter and architecture;
- threat model;
- safety classes and non-escalation rules;
- stable test taxonomy;
- minimal Rust workspace;
- CI baseline;
- example lab configuration;
- Phase 0 validation tests.

## Phase 1 — Core Runner, Evidence Logging, and Reporting

**Status: Verified Complete**

Delivered:
- test registry and runner;
- run IDs and deterministic metadata;
- structured JSON evidence;
- human-readable console reports;
- pass/fail/warning/skipped/infrastructure-error separation;
- bounded artifact directories;
- SHA-256 evidence manifest;
- safe cleanup lifecycle.

## Phase 2 — DragonForge Discovery and Build Identification

**Status: Verified Complete**

Delivered:
- discover explicit local DragonForge builds;
- record executable hashes;
- identify version/commit metadata when present;
- validate package completeness;
- refuse ambiguous target selection.

## Phase 3 — Static, Dependency, Supply-Chain, and Secret Scanning

Planned:
- cargo audit/deny integration;
- dependency inventory;
- Git history secret scanning integration;
- SBOM generation;
- CI action/provenance checks;
- release dependency evidence.

## Phase 4 — Encrypted-Format Adversarial Testing

Planned:
- .dfvault mutation;
- .dfbackup mutation;
- .dfshare mutation;
- .dfauth mutation;
- Password Manager protected-format mutation;
- truncation/length/version/tamper matrices.

## Phase 5 — DragonForge Agent Attack Harness

Planned:
- unauthenticated clients;
- invalid HMAC;
- replay;
- timestamp boundaries;
- malformed/oversized messages;
- idle socket and reconnect stress;
- runtime-file manipulation;
- startup race testing.

## Phase 6 — Filesystem, Reparse-Point, and TOCTOU Lab

Planned:
- symlinks;
- junctions/reparse points;
- hard links;
- reserved Windows names;
- Unicode/path edge cases;
- source/destination races;
- restore/extraction containment.

## Phase 7 — Password Manager Sync/API Attack Harness

Planned:
- authentication and authorization misuse;
- replay;
- enrollment attacks;
- revision races;
- recovery abuse cases;
- malformed/oversized requests;
- isolated proxy-driven mutation.

## Phase 8 — Fuzzing and Security Regression Corpus

Planned:
- cargo-fuzz harnesses;
- structure-aware mutators;
- corpus management;
- crash minimization;
- permanent regression fixtures.

## Phase 9 — Secret-Leak and Memory-Lifecycle Testing

Planned:
- synthetic sentinel secrets;
- log/AppData/temp/support-bundle scanning;
- controlled process-dump analysis in lab environments;
- secret-lifecycle evidence.

## Phase 10 — Failure Injection and Resource Exhaustion

Planned:
- controlled process termination;
- interrupted writes/restores;
- disk/permission failures;
- bounded CPU/memory/socket stress;
- recovery consistency checks.

## Phase 11 — Windows Multi-User and ACL Testing

Planned:
- normal/admin users;
- runtime file ACLs;
- protected data access boundaries;
- cross-user read/write attempts;
- inherited ACL validation.

## Phase 12 — VM and Multi-Machine Orchestration

Planned:
- disposable Windows 10/11 VMs;
- snapshots/reverts;
- reboot tests;
- dedicated attack VM;
- remote result collection;
- lab-state attestation.

## Phase 13 — CI Security Gates and Release Validation

Planned:
- release security profile;
- policy-based security gates;
- reproducible validation bundles;
- signed-release checks;
- release security summary and evidence manifest.
