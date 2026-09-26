# Public Visual Capture Checklist

DragonForge Security Test Lab is primarily a CLI/evidence framework. Phase 5 does not fabricate a graphical dashboard or present offensive test output as a portfolio screenshot. Public captures must come from real, safe executions using synthetic fixtures.

## Capture set

1. `docs/assets/readme/safe-list.png` — CLI `list` output showing test IDs/categories/safety classes without local paths.
2. `docs/assets/readme/safe-run-summary.png` — finalized **Safe** test summary using a synthetic/demo target.
3. `docs/assets/readme/evidence-report.png` — rendered human-readable evidence/report excerpt containing only synthetic identifiers and bounded findings.
4. Optional `docs/assets/readme/safety-policy.png` — controller decision output that demonstrates Safe / Controlled / Disruptive / LabOnly gating without operational exploit instructions.

## Rules

- Use only checked-in synthetic fixtures or purpose-built demo data; never use production credentials, real vault data, real secrets, or private target material.
- Do not capture step-by-step attack commands, mutation payloads, secret-like corpus contents, destructive procedures, or environment-specific lab credentials.
- Exclude usernames, hostnames, filesystem paths, private repository URLs, network identifiers, tokens, account IDs, and unrelated terminal history.
- Prefer tightly cropped PNGs at readable terminal/report scale and optimize before committing.
- Record source commit, command category, synthetic dataset, dimensions, optimized size, and reviewer in the public-readiness report.
