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

### More ecosystems
`generate`/`scan` now also parse Node.js manifests (package.json
declared ranges, package-lock.json exact resolved versions — both the
current "packages" lockfile format and the legacy nested
"dependencies" v1 format) and Go manifests (go.mod require directives,
go.sum exact resolved versions). `parse_manifests` checks for all of
these alongside requirements.txt/pyproject.toml and unions whatever it
finds, so a polyglot repo gets a single combined SBOM/scan.

### CRA compliance report mapping
`cra-report` maps SBOM + `scan` results to the vulnerability-handling
requirements in Annex I Part II of the EU Cyber Resilience Act
(Regulation (EU) 2024/2847). Scoped deliberately: points 1-3 (SBOM,
remediation, testing) are things a manifest scan can actually observe
and are marked SATISFIED/ATTENTION_NEEDED; points 4-8 (disclosure
policy, security contact, update distribution, patch dissemination)
are organizational/process requirements no static tool can verify, and
are always reported NOT_AUTOMATABLE rather than guessed at. Output
carries an explicit disclaimer — informational only, not legal advice
or a compliance certification.

### Lock file support
`generate`/`scan` now also parse Poetry's `poetry.lock` and PDM's
`pdm.lock` — both share the same `[[package]]` TOML structure, so one
parser (`_parse_toml_lock`) covers both. These give exact resolved
versions rather than requirements.txt/pyproject.toml's declared
constraints (`>=2.31.0` doesn't tell you if 2.31.0 or 2.35.2 is what's
really installed). `pip freeze` output was already covered by the
existing requirements.txt parser, since its pinned `==` lines match
the same regex.

### sigstore/cosign provenance verification
`provenance-check` reports whether npm/PyPI dependencies have a
Sigstore-backed provenance attestation on file with the registry —
npm's `/-/npm/v1/attestations/{name}@{version}` endpoint, and PyPI's
Simple Repository API (PEP 691 JSON), which is the only PyPI API
surface that actually carries the PEP 740 `provenance` field (the
legacy `/pypi/{name}/{version}/json` metadata endpoint doesn't have
it at all — confirmed against a real attested package, `pip`
26.1.2, before settling on the Simple API). Scoped deliberately: this
checks that the registry itself already validated the attestation
against Sigstore at publish time, not a from-scratch client-side
Rekor/Fulcio re-verification of the raw bundle (that would mean
downloading every artifact and adding the full sigstore-python stack
as a dependency). Go modules have no standard Sigstore-based
provenance mechanism yet and are reported as `UNSUPPORTED_ECOSYSTEM`
rather than guessed at.

### SARIF output for `scan`
`scan --sarif results.sarif` writes SARIF 2.1.0, for GitHub's
code-scanning upload — findings show up as inline PR annotations in
the Security tab instead of a JSON file nobody opens. Each result's
location points at the manifest/lockfile the dependency was declared
in (a small addition to `Package` — `source_file`, populated from
files already being read, not a new data-collection step) rather than
a specific line, the same convention other SCA tools use for
dependency-level findings. INFO-level "scan came back clean" results
are excluded from SARIF output since they aren't actionable alerts.

## Next

### License field in the SBOM
CycloneDX supports a `licenses` array per component that `generate`
doesn't populate at all today. Useful in its own right and for
compliance workflows that need to know not just what's a dependency
but what it's licensed under.

### More ecosystems: Rust and Ruby
`Cargo.lock` (Rust) and `Gemfile.lock` (Ruby) are the next most common
gaps — same shape of work as the existing npm/Go parsers, porting a
proven pattern rather than a new design.

### Independent sigstore/cosign re-verification
`provenance-check` currently trusts that npm/PyPI already validated a
package's attestation against Sigstore at publish time. A deeper pass
would add real client-side Rekor/Fulcio re-verification (via
sigstore-python) for packages that report ATTESTED, closing the gap
between "the registry says this is verified" and "this tool
independently confirmed it" — at the cost of a much heavier dependency
and downloading each artifact.
