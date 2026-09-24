# Phase 10 Failure and Resource Evidence Schema

Phase 10 uses schema version 1.

## failure-injection.json

Fields:

- `schema_version`;
- `all_passed`;
- `cases`.

Each failure case contains:

- `id`;
- `passed`;
- bounded public `detail`.

Stable case IDs:

- `disk-full-write`;
- `permission-denied-write`;
- `interrupted-atomic-write`;
- `interrupted-restore-recovery`.

## resource-stress.json

Fields:

- `schema_version`;
- `cpu_iterations`;
- `memory_bytes`;
- `socket_connections`;
- deterministic `checksum`;
- `elapsed_ms`;
- `passed`.

## Process termination result

The process-termination CLI emits bounded JSON containing:

- schema version;
- target = `self-child`;
- whether the helper was running before kill;
- whether kill was requested successfully;
- whether wait/cleanup completed;
- overall pass/fail.

No external PID or process path is accepted.

## Evidence manifests

Each on-disk evidence directory contains `SHA256SUMS`.

No real failure target data, process memory, user data, or remote socket payloads are retained.
