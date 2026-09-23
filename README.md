# DragonForge Security Test Lab

DragonForge Security Test Lab (DFSTL) is an independent security-validation framework for the DragonForge Security Suite.

DFSTL is intentionally maintained as a separate project from the product it tests. Its purpose is to validate DragonForge from both white-box and black-box perspectives without implicitly trusting the product's own runtime, libraries, or assumptions.

## Project status

**Phase 6 — Filesystem, Reparse-Point, and TOCTOU Lab: Verified Complete**

Phases 0 through 5 are verified complete. Phase 6 adds a LabOnly disposable filesystem harness for Windows path policy, staging containment, hard links, reparse links, destination races, and source-replacement TOCTOU behavior.

Phase 6 introduces the first LabOnly execution path. It operates only beneath a brand-new explicit lab root and requires --lab-ack.

## Design principles

- Safe by default.
- Destructive or disruptive tests must require explicit opt-in.
- Tests must be reproducible and evidence-producing.
- The target must never be silently modified outside an explicitly authorized test scope.
- Black-box testing is preferred where integration behavior matters.
- White-box testing is allowed when it adds coverage that cannot be obtained externally.
- Security regressions become permanent test cases.
- Secrets used during testing must be synthetic.
- Test output must avoid leaking real credentials or protected data.
- Unsafe Rust is forbidden unless a future documented exception is approved.
- The framework must distinguish a test failure from an infrastructure failure.

## Initial workspace

```text
DragonForge-Security-Test-Lab/
├── apps/
│   └── dfstl-cli/          # Primary test-controller CLI
├── crates/
│   └── dfstl-core/         # Runner, safety, evidence, hashing, and reports
├── config/
│   └── lab.example.toml    # Example lab-only configuration
├── docs/
│   ├── ARCHITECTURE.md
│   ├── PHASE_0_FOUNDATION.md
│   ├── PHASE_1_CORE_RUNNER.md
│   ├── PHASE_2_TARGET_DISCOVERY.md
│   ├── PHASE_3_STATIC_SUPPLY_CHAIN.md
│   ├── PHASE_4_ENCRYPTED_FORMATS.md
│   ├── PHASE_5_AGENT_HARNESS.md
│   ├── PHASE_6_FILESYSTEM_LAB.md
│   ├── FILESYSTEM_LAB_SCHEMA.md
│   ├── AGENT_ATTACK_SCHEMA.md
│   ├── ENCRYPTED_MUTATION_SCHEMA.md
│   ├── REPORT_SCHEMA.md
│   ├── STATIC_SCAN_SCHEMA.md
│   ├── TARGET_IDENTIFICATION_SCHEMA.md
│   ├── ROADMAP.md
│   ├── TEST_TAXONOMY.md
│   └── THREAT_MODEL.md
├── .github/workflows/ci.yml
├── SAFETY.md
├── SECURITY.md
├── Cargo.toml
└── rust-toolchain.toml
```

## Safety classes

DFSTL defines four execution classes:

- **Safe** — read-only or isolated operations expected to be safe on a development workstation.
- **Controlled** — creates temporary attack inputs or local test resources and performs bounded adversarial interaction.
- **Disruptive** — may terminate test processes, consume significant resources, or alter temporary test state.
- **LabOnly** — requires an isolated/disposable lab such as a VM snapshot, dedicated test account, or dedicated network.

The Phase 0 core library deliberately prevents higher-risk classes from being treated as ordinary default tests.

See [SAFETY.md](SAFETY.md) and [docs/TEST_TAXONOMY.md](docs/TEST_TAXONOMY.md).

## Roadmap

- Phase 0 — Architecture, safety model, and test taxonomy: **Verified Complete**
- Phase 1 — Core runner, evidence logging, and reporting: **Verified Complete**
- Phase 2 — DragonForge discovery and build identification: **Verified Complete**
- Phase 3 — Static, dependency, supply-chain, and secret scanning: **Verified Complete**
- Phase 4 — Encrypted-format adversarial testing: **Verified Complete**
- Phase 5 — DragonForge Agent attack harness: **Verified Complete**
- Phase 6 — Filesystem, reparse-point, and TOCTOU laboratory: **Verified Complete**
- Phase 7 — Password Manager sync/API attack harness
- Phase 8 — Fuzzing and security-regression corpus
- Phase 9 — Secret-leak and memory-lifecycle testing
- Phase 10 — Failure injection and resource-exhaustion testing
- Phase 11 — Windows multi-user and ACL security testing
- Phase 12 — VM and multi-machine orchestration
- Phase 13 — CI security gates and release validation

See [docs/ROADMAP.md](docs/ROADMAP.md).

## Phase 1 runner

```powershell
cargo run -p dfstl-cli -- list
cargo run -p dfstl-cli -- run --output .\results
cargo run -p dfstl-cli -- target inspect --target C:\DragonForge-Test-Build
```

Each completed run creates a finalized evidence directory containing `report.json`, `report.txt`, `SHA256SUMS`, and any per-test artifacts.

See [docs/PHASE_1_CORE_RUNNER.md](docs/PHASE_1_CORE_RUNNER.md) and [docs/REPORT_SCHEMA.md](docs/REPORT_SCHEMA.md).

## Phase 2 target identification

```powershell
cargo run -p dfstl-cli -- target inspect --target C:\DragonForge-Test-Build
cargo run -p dfstl-cli -- target inspect --target C:\DragonForge-Test-Build --json
```

DFSTL reads and hashes the explicit target; it does not execute DragonForge binaries. The current Windows package contract contains 11 expected executables.

See [docs/PHASE_2_TARGET_DISCOVERY.md](docs/PHASE_2_TARGET_DISCOVERY.md) and [docs/TARGET_IDENTIFICATION_SCHEMA.md](docs/TARGET_IDENTIFICATION_SCHEMA.md).

## Phase 6 filesystem lab

```powershell
cargo run -p dfstl-cli -- filesystem path-corpus
cargo run -p dfstl-cli -- filesystem lab --root C:\DFSTL-Lab\phase6-run --lab-ack
```

The path corpus is read-only. The filesystem executor is LabOnly, requires an explicit acknowledgement, and refuses an existing lab root.

See [docs/PHASE_6_FILESYSTEM_LAB.md](docs/PHASE_6_FILESYSTEM_LAB.md) and [docs/FILESYSTEM_LAB_SCHEMA.md](docs/FILESYSTEM_LAB_SCHEMA.md).

## Local Phase 6 validation

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-phase6-tests.ps1 -Release
```

The validator uses a disposable root beneath ignored results and checks path policy, containment, hard-link semantics, TOCTOU races, reparse reporting, evidence hashes, and Safe/Controlled/LabOnly policy enforcement.

## Phase 5 Agent attack harness

```powershell
cargo run -p dfstl-cli -- agent attack --runtime-dir C:\Path\To\AgentRuntime --controlled
cargo run -p dfstl-cli -- agent runtime-mutate --runtime-dir C:\Path\To\AgentRuntime --output .\results\agent-runtime-corpus --controlled
```

The live harness is restricted to the explicit DragonForge Agent runtime descriptor and IPv4 loopback. Runtime-file mutation uses cloned fixtures and never overwrites the live runtime files.

See [docs/PHASE_5_AGENT_HARNESS.md](docs/PHASE_5_AGENT_HARNESS.md) and [docs/AGENT_ATTACK_SCHEMA.md](docs/AGENT_ATTACK_SCHEMA.md).

## Local Phase 5 validation

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-phase5-tests.ps1 -Release
```

The deterministic validator uses synthetic runtime files and an in-process loopback mock Agent; it does not require or alter a live DragonForge Agent.

## Phase 4 encrypted-format mutation

```powershell
cargo run -p dfstl-cli -- format mutate --format dfbackup --input C:\fixtures\seed.dfbackup --output .\results\backup-corpus --controlled
```

Mutation is Controlled-class and is refused unless `--controlled` is supplied. The original seed is read-only; DFSTL writes only to a new output directory and produces a SHA-256 manifest for the corpus.

See [docs/PHASE_4_ENCRYPTED_FORMATS.md](docs/PHASE_4_ENCRYPTED_FORMATS.md) and [docs/ENCRYPTED_MUTATION_SCHEMA.md](docs/ENCRYPTED_MUTATION_SCHEMA.md).

## Local Phase 4 validation

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-phase4-tests.ps1 -Release
```

The validator uses disposable synthetic seeds for all five format profiles and validates the Controlled safety gate, mutation matrices, non-overwrite behavior, seed immutability, corpus manifests, and runner policy behavior.

## Phase 3 source scanning

```powershell
cargo run -p dfstl-cli -- source scan --source C:\DragonForge-Security-Suite --output .\results\suite-static
cargo run -p dfstl-cli -- source scan --source C:\DragonForge-Security-Suite --output .\results\suite-static --external
```

Built-in scanning is read-only and produces `static-scan.json`, `static-scan.txt`, `dependency-inventory.json`, and `sbom.spdx.json`. External tool coverage is reported separately so missing tools are never treated as a clean pass.

See [docs/PHASE_3_STATIC_SUPPLY_CHAIN.md](docs/PHASE_3_STATIC_SUPPLY_CHAIN.md) and [docs/STATIC_SCAN_SCHEMA.md](docs/STATIC_SCAN_SCHEMA.md).

## Local Phase 3 validation

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-phase3-tests.ps1 -Release
```

The validator uses only disposable synthetic source fixtures and verifies dependency/SBOM output, workflow findings, secret detection/redaction, and the Safe runner regression.

## Local Phase 2 validation

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-phase2-tests.ps1 -Release
```

The validator builds only disposable synthetic target fixtures and proves complete, incomplete, single-candidate, and ambiguous-candidate behavior.

## Local Phase 1 validation

Run the full Windows validation harness:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-phase1-tests.ps1 -Release
```

The validator independently parses the generated JSON report and recomputes every evidence-manifest SHA-256. It writes a timestamped log and SHA-256 sidecar under `test-logs/`.

## Local Phase 0 validation

On Windows, run the complete validation harness from the repository root:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-phase0-tests.ps1
```

Or double-click/run:

```text
scripts\run-phase0-tests.cmd
```

For an additional release-mode test pass:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-phase0-tests.ps1 -Release
```

The validator records environment/tool versions, repository branch/commit/cleanliness, required Phase 0 files, Cargo metadata, rustfmt, strict Clippy, debug tests, optional release tests, CLI safety invariants, and a release build. It writes a timestamped log and SHA-256 sidecar under `test-logs/`.

Example:

```text
test-logs\phase0-validation-20260923-134500.log
test-logs\phase0-validation-20260923-134500.log.sha256
```

Upload the `.log` file for review if validation fails or when recording Phase 0 verification evidence.

## Development

```powershell
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p dfstl-cli -- describe
cargo run -p dfstl-cli -- list
cargo run -p dfstl-cli -- run --output .\results
```

## Important

DFSTL is a security-testing framework. Future phases will include tests that can intentionally crash processes, create malformed data, manipulate temporary filesystem objects, or stress local services. Those capabilities must remain gated behind the safety model defined in this repository.

Do not point future disruptive/lab-only tests at systems, services, accounts, or networks you do not own or have explicit authorization to test.
