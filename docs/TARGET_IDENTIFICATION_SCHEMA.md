# Target Identification JSON — Schema 1

Phase 2 exposes machine-readable target identification with:

```powershell
dfstl target inspect --target <PATH> --json
```

This document is separate from the Phase 1 run-report schema.

## Top-level fields

| Field | Type | Meaning |
| --- | --- | --- |
| schema_version | integer | Target identification schema version; Phase 2 emits 1 |
| root | string | Resolved local DragonForge target directory |
| complete | boolean | Whether all current expected executables are present |
| build_fingerprint | string | SHA-256 fingerprint derived from the executable identity set |
| manifest_status | string | absent, valid, or invalid |
| manifest_detail | string/null | Failure detail when the package manifest is invalid |
| build_info | object/null | Parsed BUILD-INFO.txt metadata when present |
| executables | array | Identified expected executables |
| missing_executables | array | Expected executable names not present as regular files |
| unexpected_dragonforge_executables | array | Additional dragonforge-*.exe files not in the package contract |

## Executable record

Each entry contains:

```json
{
  "name": "dragonforge-agent.exe",
  "size_bytes": 123456,
  "sha256": "<64 lowercase hexadecimal characters>"
}
```

The SHA-256 digest is calculated directly from the inspected file.

## Build fingerprint

The build fingerprint is derived deterministically from the sorted executable records using:

```text
filename NUL sha256 NUL decimal-size LF
```

for each present expected executable, followed by SHA-256 over the combined byte stream.

The fingerprint is useful for correlating test evidence to an exact executable set. It is not equivalent to Authenticode, signed release metadata, or publisher authentication.

## Build info object

Fields may be strings or null:

- version
- release_channel
- git_commit
- git_tag
- built_utc
- platform
- code_signing

DFSTL reports only metadata present in BUILD-INFO.txt. It does not infer a missing version or commit from filenames.

## Manifest status

`absent` means SHA256SUMS.txt was not supplied.

`valid` means every present expected executable had a matching manifest digest.

`invalid` means the manifest was malformed, duplicated an entry, omitted a present expected executable, or disagreed with DFSTL's independent SHA-256.

Package completeness and manifest validity are separate fields because development builds may legitimately have no package manifest.
