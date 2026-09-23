# Phase 5 — DragonForge Agent Attack Harness

## Status

**Implementation Complete — Verification Pending**

Phase 5 adds a bounded, black-box, Controlled-class attack harness for the DragonForge Agent's authenticated loopback IPC boundary.

## DragonForge Security Suite baseline

Phase 5 was designed against DragonForge Security Suite commit:

```text
599ac25869842743464b4e7953329ba1c5ff077b
```

The reviewed Agent baseline uses:

- IPv4 loopback only;
- protocol version 1.1;
- a random 32-byte startup session credential;
- HMAC-SHA256 request authentication;
- 16-byte request nonces;
- ±60 second timestamp freshness;
- a 16 KiB request/response wire bound;
- a 4,096-entry nonce replay cache;
- two-second server read/write timeouts;
- authenticated `health` and `shutdown` actions;
- generic rejection responses for parsed but invalid requests.

## Safety model

The live Agent attack harness is **Controlled-class** and requires both:

1. an explicit Agent runtime directory; and
2. `--controlled`.

Example:

```powershell
dfstl agent attack --runtime-dir "$env:LOCALAPPDATA\DragonForge\agent" --controlled
```

DFSTL refuses to run the live harness without `--controlled`.

The harness never accepts a remote host or arbitrary socket address. It reads the explicit runtime descriptor and always connects to `127.0.0.1:<runtime-port>`.

## Live attack matrix

The bounded attack run covers:

- malformed JSON;
- a request at/above the 16 KiB wire boundary;
- an idle socket;
- eight sequential reconnect/rejection probes;
- invalid HMAC;
- unauthorized source component;
- incompatible protocol major;
- timestamp older than the allowed freshness window;
- timestamp newer than the allowed freshness window;
- invalid nonce length;
- one correctly authenticated health request;
- replay of that exact authenticated request.

Each test opens a bounded loopback connection with short connect/I/O timeouts. The harness does not send shutdown or privileged-service actions.

## Result semantics

For rejection cases, either of these outcomes is accepted:

- the Agent returns a parsed rejection response; or
- the Agent closes/times out without a response for malformed/oversized/idle wire input.

Transport errors are not reported as successful security rejection.

The valid authenticated health request must be accepted.

The replay of the same valid nonce/request must be rejected.

## HMAC implementation independence

DFSTL does not depend on the DragonForge Agent crate or its HMAC implementation.

Phase 5 includes its own HMAC-SHA256 implementation over the existing DFSTL SHA-256 primitive and validates it against RFC 4231 test material.

This preserves the black-box trust boundary between the tester and the product.

## Runtime-file manipulation

Live runtime files are never modified by the default Phase 5 corpus generator.

Instead:

```powershell
dfstl agent runtime-mutate \
  --runtime-dir "$env:LOCALAPPDATA\DragonForge\agent" \
  --output .\results\agent-runtime-corpus \
  --controlled
```

copies only the required baseline material and generates disposable fixtures for:

- empty runtime descriptor;
- malformed runtime descriptor;
- oversized runtime descriptor;
- empty session credential;
- malformed Base64 credential;
- wrong-length decoded credential;
- fresh-lock startup-race state;
- stale-lock startup-race state.

The source runtime descriptor and session credential remain unchanged.

## Startup race coverage

Phase 5 captures fresh-lock and stale-lock fixture states as permanent regression inputs for the Agent's startup-lock behavior.

It deliberately does not kill or race the user's live Agent process. Actual process termination/restart fault injection remains reserved for the later Disruptive/Lab phases.

## Deterministic loopback validation

The core test suite starts a disposable IPv4 loopback mock Agent and runs the real black-box harness against it.

That regression validates:

- the complete attack-case sequence;
- valid-vs-rejected result classification;
- replay handling;
- reconnect behavior;
- bounded idle handling;
- explicit loopback transport behavior.

No installed DragonForge Agent is required for the Phase 5 validation script.

## Runner integration

Phase 5 registers:

```text
IPC-AGENT-001
```

with:

- category: `IPC`;
- safety: `controlled`;
- execution model: `black-box`.

The ordinary Safe runner skips it. An explicitly Controlled runner executes the capability self-check.

## CLI

Live attack:

```powershell
dfstl agent attack --runtime-dir PATH --controlled [--json]
```

Runtime mutation corpus:

```powershell
dfstl agent runtime-mutate --runtime-dir PATH --output PATH --controlled [--json]
```

Exit behavior:

| Code | Meaning |
| ---: | --- |
| 0 | all expected outcomes observed |
| 1 | target behavior did not match the expected security outcome |
| 2 | CLI usage error |
| 3 | runtime/credential/transport setup failure |
| 6 | Controlled authorization was not supplied |

## Validation

Run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-phase5-tests.ps1 -Release
```

The validator checks:

- rustfmt;
- strict Clippy;
- debug and release tests;
- deterministic loopback harness regression;
- RFC 4231 HMAC vector;
- Phase 5 CLI markers;
- Controlled registration;
- refusal without `--controlled`;
- runtime mutation corpus generation;
- source runtime/credential immutability;
- all eight runtime/startup-race fixtures;
- Safe runner skip behavior;
- Controlled runner pass behavior;
- release build.

## Exit criteria

Phase 5 is verified when the release-mode validator ends with:

```text
Warnings: 0
Failures: 0

PHASE 5 VALIDATION: PASS
```
