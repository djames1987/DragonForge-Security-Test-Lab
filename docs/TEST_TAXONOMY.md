# DFSTL Test Taxonomy

Every executable DFSTL test must have a stable ID, category, safety class, execution model, prerequisites, expected invariant, and evidence policy.

## Categories

| Code | Category | Examples |
| --- | --- | --- |
| STATIC | StaticAnalysis | format/lint/security-policy checks |
| SUPPLY | SupplyChain | dependency advisories, provenance, SBOM |
| CRYPTO | Cryptography | tamper rejection, nonce/KDF boundaries |
| PARSER | Parser | malformed container/protocol handling |
| FUZZ | Fuzzing | coverage-guided and structure-aware mutation |
| IPC | LocalIpc | Agent authentication/replay/protocol tests |
| FS | Filesystem | traversal, junction, symlink, TOCTOU |
| API | NetworkApi | sync/auth/recovery/API misuse |
| LEAK | SecretLeakage | sentinel secret searches |
| MEMORY | MemoryLifecycle | post-lock/test-process memory checks |
| FAULT | FaultInjection | kill/crash/interrupted operations |
| RESOURCE | ResourceExhaustion | bounded CPU/memory/socket/disk stress |
| ACL | AccessControl | Windows ACL and multi-user isolation |
| RELEASE | ReleaseIntegrity | signing, package authenticity, downgrade |
| LAB | LabOrchestration | VM snapshots, reboots, multi-machine runs |

## Execution models

- **BlackBox** — interact with the built target from outside its implementation.
- **WhiteBox** — exercise an internal test entry point/library with explicit instrumentation.
- **Hybrid** — combine external behavior with controlled instrumentation.

## Result states

- **Pass** — expected security invariant held.
- **Fail** — target violated the invariant with sufficient evidence.
- **Warning** — suspicious/limited result requiring review.
- **Skipped** — prerequisites intentionally not satisfied.
- **InfrastructureError** — test framework/environment failed; not a target security finding.

## Stable test identifiers

Identifiers should use:

```text
<CATEGORY>-<AREA>-<NNN>
```

Examples:

```text
IPC-AGENT-001
CRYPTO-DFSHARE-004
FS-RESTORE-012
API-RECOVERY-007
LEAK-DIAGNOSTICS-003
```

IDs are never reused for unrelated behavior.

## Safety mapping

Static/supply-chain tests normally begin as Safe.

Malformed local fixtures normally begin as Controlled.

Intentional process termination, resource exhaustion, clock changes, and active fault injection are Disruptive.

Cross-user ACL manipulation, reboot/snapshot tests, hostile-network topologies, and intentional system corruption are LabOnly unless a later design proves a narrower class is safe.

The declared class represents the highest-risk operation the test can perform, not its normal happy path.
