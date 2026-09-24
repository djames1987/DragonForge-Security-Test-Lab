# Permanent Security Regression Corpus

This directory stores minimized, reviewed fuzz/security regression fixtures promoted by DFSTL.

Rules:

- fixtures are grouped by stable Phase 8 fuzz target;
- filenames are derived from the first 16 hexadecimal characters of SHA-256;
- each binary fixture has adjacent JSON metadata;
- promotion refuses overwrite/duplicate content;
- only synthetic or sanitized inputs may be committed;
- never commit production vaults, credentials, secrets, personal data, or raw user captures;
- a promoted fixture should retain a short note describing the bug/security invariant it protects.

Use:

```powershell
dfstl fuzz promote --target NAME --input PATH --regression-root .\corpus\regression --controlled --note "reason"
```

Crash minimization is performed through cargo-fuzz or the core `minimize_with_oracle` API before promotion.
