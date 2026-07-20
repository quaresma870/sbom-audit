# Changelog

All notable changes to this project are documented here. See the
[README](README.md) for current features and usage.

### v0.1.0
- feat: **initial release** — SBOM generation & dependency vulnerability scanning CLI.
- feat: **`generate`** — real, schema-valid CycloneDX 1.5 JSON SBOM generation from
  requirements.txt/pyproject.toml. Found and fixed a real schema error while building this: an
  invalid `vendor` field on the tool metadata component, caught by validating against the official
  CycloneDX JSON schema via `cyclonedx-python-lib`, not just an internal shape assumption.
- feat: **`scan`** — OSV.dev dependency vulnerability checking, query pattern adapted directly from
  the sibling secureaudit repo's already-proven CVE plugin.
- test: 15 tests, including real schema validation against the official CycloneDX 1.5 spec.
