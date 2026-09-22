# Phase 0 — Architecture, Safety Model, and Test Taxonomy

## Status

**Implementation Complete — Verification Pending**

Phase 0 establishes the foundation for DragonForge Security Test Lab without implementing destructive attack behavior.

## Delivered

- independent repository charter;
- Rust workspace with `dfstl-core` and `dfstl-cli`;
- workspace-wide `unsafe_code = "forbid"`;
- four-level safety model: Safe, Controlled, Disruptive, LabOnly;
- central `ExecutionPolicy` evaluation;
- stable test-category model;
- stable test-descriptor structure;
- black-box/white-box/hybrid architecture guidance;
- threat model;
- test taxonomy;
- roadmap through Phase 13;
- lab configuration example;
- CI for formatting, strict Clippy, tests, and CLI smoke validation;
- unit tests proving the default policy fails closed for higher-risk classes.

## Phase 0 invariants

1. Default execution policy permits Safe tests only.
2. Controlled, Disruptive, and LabOnly tests require progressively stronger explicit policy.
3. Unknown or unauthorized test scope must fail closed in future phases.
4. No Phase 0 code performs destructive or disruptive target actions.
5. Test IDs and categories are structured so future findings can become permanent regressions.
6. Target failures must remain distinguishable from DFSTL/infrastructure failures.

## Verification

Phase 0 is intended to pass:

```powershell
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p dfstl-cli -- describe
```

CI runs the equivalent checks on pushes and pull requests.

## Exit criteria

Phase 0 is complete when:
- the workspace compiles;
- safety policy unit tests pass;
- CLI smoke output identifies the project and default Safe-only policy;
- architecture/safety/threat/test-taxonomy documentation is present;
- no active disruptive test implementation exists.

The implementation criteria are satisfied by the Phase 0 repository state. Final verification remains pending because the initial GitHub-hosted workflow is failing before any job step starts; this is an execution-infrastructure issue rather than an observed Rust test failure.
