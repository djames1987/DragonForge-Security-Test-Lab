# DFSTL Safety Model

DFSTL is designed to eventually perform adversarial security testing. Safety controls are therefore part of the product architecture, not an optional wrapper.

## Safety classes

### Safe

Read-only or isolated checks expected to be appropriate on a normal development workstation.

Examples:
- static analysis;
- dependency inventory;
- source/release metadata inspection;
- parsing synthetic fixtures in a temporary directory.

### Controlled

Bounded adversarial behavior that may create temporary files, local sockets, malformed fixtures, or disposable local test state.

Requirements:
- explicit target scope;
- bounded resource use;
- cleanup plan;
- synthetic data.

### Disruptive

Tests that may kill test processes, intentionally induce failures, create high load, manipulate test clocks/state, or materially disrupt a target.

Requirements:
- explicit opt-in;
- dedicated target process/data;
- preflight validation;
- rollback/recovery plan;
- evidence that the target is not a production environment.

### LabOnly

Tests requiring an isolated lab such as a disposable VM, VM snapshot, dedicated Windows account, dedicated test network, or intentionally corrupted system state.

Requirements:
- explicit lab configuration;
- explicit acknowledgement;
- isolation checks;
- recovery mechanism;
- no production secrets or production data.

## Non-escalation invariant

A test declared as one safety class must never perform an operation belonging to a higher class without the controller rejecting execution and requiring a new explicitly authorized run.

## Default policy

The default execution policy permits only **Safe** tests.

Phase 0 implements the safety-class model and policy evaluation but does not implement disruptive test actions.

## Future execution acknowledgements

Future phases may add command-line acknowledgement flags. Flags alone are not sufficient for LabOnly operations; the runner should also validate environmental prerequisites such as a configured lab marker, isolated workspace, or VM orchestration context.

## Scope

Future target definitions must identify what DFSTL is authorized to test. A target outside that scope must fail closed.

Network testing must default to loopback/private lab endpoints. Public/remote targets require explicit configuration and must never be discovered and attacked automatically.

## Evidence and data handling

- Use generated sentinel secrets rather than real secrets.
- Redact sensitive values from logs.
- Bound retained artifacts.
- Hash evidence where practical.
- Preserve crashing/malformed fixtures only when they contain synthetic data.
- Never collect unrelated user files merely because they are accessible.
