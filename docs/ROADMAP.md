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

**Status: Verified Complete**

Delivered:
- cargo audit/deny integration;
- dependency inventory;
- Git history secret scanning integration;
- SBOM generation;
- CI action/provenance checks;
- release dependency evidence.

## Phase 4 — Encrypted-Format Adversarial Testing

**Status: Verified Complete**

Delivered:
- .dfvault mutation;
- .dfbackup mutation;
- .dfshare mutation;
- .dfauth mutation;
- Password Manager protected-format mutation;
- truncation/length/version/tamper matrices.

## Phase 5 — DragonForge Agent Attack Harness

**Status: Verified Complete**

Delivered:
- malformed and unauthenticated client behavior;
- invalid HMAC rejection;
- nonce replay testing;
- stale/future timestamp boundaries;
- malformed/oversized messages;
- bounded idle socket and reconnect stress;
- cloned runtime-file manipulation corpus;
- fresh/stale startup-lock race fixtures;
- deterministic loopback mock-Agent regression.

## Phase 6 — Filesystem, Reparse-Point, and TOCTOU Lab

**Status: Verified Complete**

Delivered:
- deterministic Windows path-policy corpus;
- symbolic/reparse-link detection and disposable creation attempts;
- hard-link alias testing;
- Windows reserved-name coverage;
- Unicode/path edge cases;
- source replacement and destination creation races;
- canonical staging/restore containment checks;
- LabOnly policy gating and evidence manifests.

## Phase 7 — Password Manager Sync/API Attack Harness

**Status: Verified Complete**

Delivered:
- bounded missing/malformed authentication probes;
- explicit account/admin authorization misuse checks;
- exact-request replay fixture;
- device-ID/timestamp/signature tamper fixtures;
- enrollment proof abuse fixture;
- base-revision conflict fixture;
- recovery nonce/generation/malformed-request abuse fixtures;
- malformed and oversized live request probes;
- isolated offline captured-request mutation corpus;
- deterministic IPv4-loopback mock-server regression.

## Phase 8 — Fuzzing and Security Regression Corpus

**Status: Verified Complete**

Delivered:
- isolated cargo-fuzz project with four harnesses;
- eight stable fuzz target domains;
- deterministic seeded structure-aware mutators;
- bounded corpus generation with SHA-256 manifests;
- deterministic oracle-based crash minimizer API;
- content-hash regression promotion with duplicate refusal;
- permanent checked-in regression fixture and metadata;
- seed corpus for binary, JSON, HTTP, and Windows path targets;
- FUZZ runner registration and safety-policy integration.

## Phase 9 — Secret-Leak and Memory-Lifecycle Testing

**Status: Implementation Complete — Verification Pending**

Delivered:
- synthetic ASCII sentinel definitions with zeroing-on-drop buffers;
- raw, lowercase-hex, Base64, and UTF-16LE leak detection;
- bounded explicit log/AppData/temp/support-root scanning;
- symlink refusal and canonical reparse/junction containment;
- redaction-safe JSON/text evidence plus SHA-256 manifests;
- clean and intentionally leaky artifact regression coverage;
- LabOnly bounded streaming analysis of explicit offline process dumps;
- synthetic in-place secret buffer lifecycle check;
- LEAK and MEMORY runner registrations with separate safety classes.

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
