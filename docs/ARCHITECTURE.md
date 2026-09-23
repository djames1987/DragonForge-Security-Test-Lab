# DFSTL Architecture

## Purpose

DragonForge Security Test Lab is an independent adversarial validation framework for DragonForge Security Suite. Separation from the target repository is intentional: test logic should not depend on the target behaving correctly.

## Architectural layers

```text
CLI / future UI
      |
      v
Test Controller
      |
      +--> Safety Policy
      +--> Target Registry
      +--> Test Registry
      +--> Evidence Recorder
      |
      +--> Static/Supply-Chain Tests
      +--> Crypto/Format Tests
      +--> Parser/Fuzz Tests
      +--> Agent IPC Tests
      +--> Filesystem Tests
      +--> API/Sync Tests
      +--> Leak/Memory Tests
      +--> Fault/Resource Tests
      +--> ACL/Multi-user Tests
      +--> VM/Lab Orchestration
```

## Core components

### `dfstl-core`

Owns foundational data types that future runners must use:

- `SafetyClass`;
- `ExecutionPolicy`;
- `TestCategory`;
- `TestDescriptor`;
- policy decisions for whether a test may execute.

Phase 1 extends it with:

- `TestRegistry` and stable-ID validation;
- `Runner` and central safety-policy enforcement;
- five-state test results;
- bounded `EvidenceSession` staging/finalization;
- internal SHA-256 evidence hashing;
- JSON and text run reports;
- explicit local target discovery and build identification;
- package completeness and checksum-manifest validation;
- bounded source/static scanning;
- dependency inventory and SPDX SBOM generation;
- supply-chain and secret findings;
- optional external scanner orchestration;
- Controlled encrypted-format mutation corpus generation;
- deterministic mutation manifests and seed identity binding.

It intentionally does not contain adversarial attack implementations through Phase 1.

### `dfstl-cli`

The primary command-line controller. Phase 1 adds `list` and `run` commands, executes registered Safe tests, prints a human-readable summary, and points to the finalized evidence bundle.

## Trust boundaries

### Target boundary

The DragonForge build under test is untrusted from DFSTL's perspective. Output, files, sockets, logs, and exit codes are attacker-controlled inputs to the test controller.

### Test plugin/module boundary

Future test modules may perform risky actions. The controller must not infer safety from module names; each module must supply metadata and the controller must enforce policy centrally.

### Operating-system boundary

Windows APIs, filesystem semantics, ACLs, reparse points, process state, and networking can change underneath a test. Results must distinguish environmental uncertainty from a confirmed security failure.

### Evidence boundary

Reports can accidentally become a secret-exfiltration channel. Evidence collection must be bounded and redacted before persistence.

## White-box vs black-box

DFSTL supports both models.

**Black-box** testing is preferred for:
- executable launch/integration behavior;
- IPC;
- filesystem effects;
- API behavior;
- release-package validation.

**White-box** testing is useful for:
- parser entry points;
- deterministic format mutation;
- property tests;
- dedicated test-only instrumentation.

A test report must record which model was used.

## Controller invariants

1. Unknown safety state fails closed.
2. Default policy permits Safe tests only.
3. A higher-risk test cannot silently downgrade its metadata.
4. Target/source/seed paths must be explicit before scanning or adversarial testing; ambiguous target discovery fails closed.
5. Evidence must not intentionally contain real secrets.
6. Every test has a stable identifier.
7. A failed tester/infrastructure action is not reported as a target vulnerability.
8. Regression fixtures must remain reproducible.
