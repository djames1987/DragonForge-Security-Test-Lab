# DragonForge Security Test Lab

DragonForge Security Test Lab (DFSTL) is an independent security-validation framework for the DragonForge Security Suite.

DFSTL is intentionally maintained as a separate project from the product it tests. Its purpose is to validate DragonForge from both white-box and black-box perspectives without implicitly trusting the product's own runtime, libraries, or assumptions.

## Project status

**Phase 1 — Core Runner, Evidence Logging, and Reporting: Implementation Complete — Verification Pending**

Phase 0 establishes the repository, security boundaries, safety classes, threat model, test taxonomy, roadmap, and a minimal Rust workspace that future phases will extend into the executable test controller.

No destructive security tests are implemented in Phase 0.

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
│   └── dfstl-cli/          # Future test-controller CLI
├── crates/
│   └── dfstl-core/         # Shared models, safety classes, and test metadata
├── config/
│   └── lab.example.toml    # Example lab-only configuration
├── docs/
│   ├── ARCHITECTURE.md
│   ├── PHASE_0_FOUNDATION.md
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
- Phase 1 — Core runner, evidence logging, and reporting: **Implementation Complete — Verification Pending**
- Phase 2 — DragonForge discovery and build identification
- Phase 3 — Static, dependency, supply-chain, and secret scanning
- Phase 4 — Encrypted-format adversarial testing
- Phase 5 — DragonForge Agent attack harness
- Phase 6 — Filesystem, reparse-point, and TOCTOU laboratory
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
```

Each completed run creates a finalized evidence directory containing `report.json`, `report.txt`, `SHA256SUMS`, and any per-test artifacts.

See [docs/PHASE_1_CORE_RUNNER.md](docs/PHASE_1_CORE_RUNNER.md) and [docs/REPORT_SCHEMA.md](docs/REPORT_SCHEMA.md).

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
```

## Important

DFSTL is a security-testing framework. Future phases will include tests that can intentionally crash processes, create malformed data, manipulate temporary filesystem objects, or stress local services. Those capabilities must remain gated behind the safety model defined in this repository.

Do not point future disruptive/lab-only tests at systems, services, accounts, or networks you do not own or have explicit authorization to test.
