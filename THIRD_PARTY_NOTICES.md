# Third-Party Notices

This repository is proprietary DragonForge source. The DragonForge `LICENSE` applies to original DragonForge material only; third-party material, if introduced, remains governed by its own terms and independently granted rights.

## Dependency inventory

The current Cargo workspace contains only the first-party `dfstl-cli` and `dfstl-core` packages. Their current manifests declare only a path dependency from the CLI to `dfstl-core`, and the committed `Cargo.lock` does not represent a third-party registry dependency graph.

Reproducible verification command:

```powershell
cargo metadata --locked --format-version 1 > dependency-metadata.json
```

For future changes, inspect every package whose metadata `source` is non-null and record its `license` or `license_file`. Any missing, uncertain, or incompatible license is a publication blocker until reviewed. Do not treat a dependency's license as changing the proprietary license of original DragonForge source.

## Regression corpus and fixtures

The files under `corpus/` are project regression seeds and generated/synthetic test material used by DragonForge Security Test Lab. They are not a third-party credential or sample-data pack. Their secret-like contents are intentional security-test fixtures and must not be removed merely because they resemble credentials.

If future corpus material is copied or adapted from an external project, its source, copyright, license, and required attribution must be recorded here before it is committed for redistribution.

## Bundled assets

No third-party font set, icon library, artwork collection, screenshot pack, npm dependency tree, Python package tree, vendored dependency directory, or copied upstream source bundle was identified in the current tree during the Phase 3 inspection.

## Release rule

Re-run the locked Cargo metadata inventory whenever dependencies change and before public release. Preserve required upstream notices for any future dependencies or external fixtures. Missing or uncertain redistribution rights block the affected material rather than being treated as implicitly permitted.
