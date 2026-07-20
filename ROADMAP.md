# Roadmap

## Shipped

### v0.1.0
- `generate` — real, schema-valid CycloneDX 1.5 JSON SBOM generation
  from requirements.txt/pyproject.toml, validated against the official
  CycloneDX JSON schema in this repo's own tests.
- `scan` — OSV.dev dependency vulnerability checking, adapted from the
  sibling secureaudit repo's already-proven CVE plugin.
- CI: builds the real wheel, installs it in a clean venv, and runs a
  real `scan` against real OSV.dev.

## Next

### More ecosystems
v0.1 only parses Python manifests (requirements.txt, pyproject.toml).
Node.js (package.json/package-lock.json) and Go (go.sum) support
already exists as a proven pattern in the sibling secureaudit repo's
own CVE plugin — porting that parsing logic here is the natural next
step, not a new design.

### sigstore/cosign provenance verification
Verifying that a package's supply-chain provenance is signed/attested,
not just checking for known CVEs — a real, separate concern from
vulnerability scanning. This was part of the original idea for this
tool and deliberately deferred out of v0.1 to keep the first release
focused and shippable.

### CRA compliance report mapping
A report format that explicitly maps findings to specific EU Cyber
Resilience Act requirements, rather than a generic vulnerability list —
useful for anyone using this tool specifically for compliance
documentation, not just security review.

### Lock file support
requirements.txt/pyproject.toml give declared version *constraints*,
not necessarily the exact resolved versions actually installed
(`>=2.31.0` doesn't tell you if 2.31.0 or 2.35.2 is what's really in
the environment). Parsing `requirements.txt` output from `pip freeze`,
or a proper lock file format (Poetry's poetry.lock, PDM's pdm.lock),
would give exact-version accuracy that a version-constraint-only scan
can't.
