# Password Manager Sync/API Mutation Schema

Phase 7 uses schema version 1 for both live probe results and offline request mutation evidence.

## Live probe report

Fields:

- `schema_version`;
- `protocol_version`;
- `endpoint`;
- `all_expected`;
- `cases`.

Each case records:

- stable case ID;
- expected HTTP status set;
- observed status;
- pass/fail classification;
- bounded detail text.

The live harness only permits literal IPv4 loopback.

## Offline mutation corpus

`sync-api-mutations.json` records:

- `schema_version`;
- SHA-256 of the source capture;
- stable mutation IDs;
- generated request filenames;
- per-request SHA-256;
- expected target behavior.

The mutation generator never transmits generated requests.

## Current mutation IDs

- exact-replay;
- missing-bearer;
- wrong-bearer;
- device-id-swap;
- stale-device-timestamp;
- invalid-device-signature;
- base-revision-zero;
- body-bitflip;
- body-truncate;
- enrollment-invalid-proof;
- recovery-invalid-or-replayed-nonce;
- recovery-malformed-json.

The source capture is not modified.
