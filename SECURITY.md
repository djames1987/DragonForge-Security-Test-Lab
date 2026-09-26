# DragonForge Security Test Lab Security Policy

DragonForge Security Test Lab (DFSTL) is security-sensitive validation tooling. Reports involving DFSTL itself should be handled privately when they could allow unsafe test execution, escape a configured test scope, expose secrets, undermine evidence integrity, or weaken safety-class enforcement.

## Current status

DFSTL is pre-release development software. Phases 0–10 have recorded verification in the project history; Phase 11 — Windows Multi-User & ACL Security Testing — is implementation complete with verification pending at the current public-readiness baseline. This status is not a claim of independent audit, certification, or production readiness.

## Security principles

- Synthetic test secrets only.
- No real credentials in tests, fixtures, logs, reports, or issue attachments.
- Fail closed when authorization, scope, or safety state is ambiguous.
- Never silently escalate a test into a higher safety class.
- Preserve a distinction between target failure, tester failure, and environment failure.
- Security-sensitive formats and protocols must be versioned.
- Test evidence should be bounded, attributable, and reproducible.
- Unsafe Rust is forbidden at the workspace level unless an exception is explicitly documented and reviewed.
- Dependencies should be minimized and audited.
- Disruptive or LabOnly capabilities must remain isolated and explicitly enabled.

## Reporting a vulnerability

Use GitHub's private security-advisory reporting flow when available:

`https://github.com/djames1987/DragonForge-Security-Test-Lab/security/advisories/new`

If that private flow is unavailable, contact the repository owner through a private GitHub channel. Do **not** publish exploit details in a public issue.

A useful report includes the affected version/commit, component and safety class, reproduction steps using synthetic data, expected and observed behavior, potential impact, and sanitized evidence.

Do not include real passwords, OTP seeds, recovery material, production vaults, private signing keys, tokens, personal data, sensitive user files, or evidence collected from systems you are not authorized to test.

Only test systems and data you own or have explicit authorization to test.