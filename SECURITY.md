# Security Policy

DragonForge Security Test Lab is security-sensitive tooling. Reports involving DFSTL itself should be handled as security reports when they could allow unsafe test execution, escape a configured test scope, expose secrets, or undermine test evidence.

## Current status

DFSTL is pre-release development software. Phase 0 contains architecture, policy, and a minimal non-destructive Rust foundation only.

## Security principles

- Synthetic test secrets only.
- No real credentials in tests, fixtures, logs, reports, or issue attachments.
- Fail closed when authorization, scope, or safety state is ambiguous.
- Never silently escalate a test into a higher safety class.
- Preserve a distinction between target failure, tester failure, and environment failure.
- Security-sensitive formats and protocols must be versioned.
- Test evidence should be bounded, attributable, and reproducible.
- Unsafe Rust is forbidden at the workspace level unless a future exception is explicitly documented and reviewed.
- Dependencies should be minimized and audited.
- Future destructive test capabilities must be isolated and explicitly enabled.

## Reporting

When reporting a vulnerability in DFSTL, include:

- affected version/commit;
- component and safety class;
- reproduction steps using synthetic data;
- expected and observed behavior;
- potential impact;
- sanitized evidence.

Do not include real passwords, OTP seeds, recovery material, production vaults, private signing keys, or sensitive user files.
