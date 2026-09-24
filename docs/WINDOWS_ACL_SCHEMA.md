# Phase 11 Windows ACL Evidence Schema

Phase 11 uses schema version 1.

## acl-snapshot.tsv

Tab-separated columns:

1. `target`
2. `owner`
3. `principal`
4. `access_type`
5. `rights`
6. `inherited`

The parser accepts at most 256 records.

## multi-user-results.json

Fields:

- `schema_version`;
- `owner_user`;
- `owner_sid`;
- `other_user`;
- `other_sid`;
- `restricted_targets`;
- `owner_user_read_allowed`;
- `owner_user_write_allowed`;
- `administrator_read_allowed`;
- `administrator_write_allowed`;
- `other_user_read_denied`;
- `other_user_write_denied`;
- `inherited_broad_write_fixture`;
- `passed`.

The temporary users' passwords are never serialized.

## acl-analysis.json

Fields:

- `schema_version`;
- `records`;
- `clean`;
- `findings`.

Each finding contains:

- `target`;
- `principal`;
- `severity`;
- `code`;
- bounded public `detail`.

Stable finding codes:

- `broad-write`;
- `inherited-broad-write`;
- `sensitive-inherited-write`.

## Manifests

Both the active lab and the ACL analyzer produce `SHA256SUMS`.

All Phase 11 data is synthetic and disposable.
