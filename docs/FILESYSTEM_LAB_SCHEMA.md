# Filesystem Lab Report Schema

Phase 6 writes a machine-readable filesystem lab report with schema version 1.

## Filesystem lab report

Top-level fields:

- schema_version
- platform
- lab_root
- has_failures
- cases

Each case records:

- id
- status
- detail

Supported case status values are pass, fail, and skipped.

A skipped reparse-link case means the operating system did not permit creation in the disposable lab. It is distinct from a passing security result.

## Path policy corpus

The read-only path corpus records:

- id
- value
- expected_safe
- accepted
- reason

The corpus is deterministic and covers traversal, Windows device names, drive and UNC syntax, alternate stream syntax, trailing dots and spaces, controls, and Unicode edge cases.

## Evidence

A completed lab writes filesystem-lab.json, filesystem-lab.txt, and SHA256SUMS beneath the explicit disposable lab root. Reparse-link entries are not followed while creating the evidence manifest.
