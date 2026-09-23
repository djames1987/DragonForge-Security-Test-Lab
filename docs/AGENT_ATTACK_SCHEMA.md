# Agent Attack Report JSON — Schema 1

Phase 5 emits a machine-readable Agent attack report with schema version 1.

## Top-level fields

| Field | Type | Meaning |
| --- | --- | --- |
| schema_version | integer | Phase 5 emits 1 |
| runtime | object | Agent protocol/port/process identity read from the explicit runtime descriptor |
| all_expected | boolean | True only when every bounded case matches the expected security outcome |
| cases | array | Individual attack-case results |

## Case record

```json
{
  "id": "invalid-hmac",
  "expected": "rejected",
  "outcome": "rejected",
  "detail": "agent returned an authenticated/generic rejection response"
}
```

Possible outcomes are:

- `rejected`;
- `accepted`;
- `no-response`;
- `transport-error`.

For malformed, oversized, and idle rejection tests, `no-response` is an acceptable rejection behavior.

A transport error is never silently converted into a target pass.

## Runtime mutation corpus

`agent runtime-mutate` emits `runtime-mutations.json` with stable IDs and SHA-256 hashes for generated fixture files.

Current fixture IDs are:

- `descriptor-empty`;
- `descriptor-malformed`;
- `descriptor-oversized`;
- `credential-empty`;
- `credential-malformed-base64`;
- `credential-wrong-length`;
- `startup-fresh-lock`;
- `startup-stale-lock`.

The live runtime files are not modified.
