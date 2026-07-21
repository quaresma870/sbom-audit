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

## Next

Nothing currently queued — all planned items have shipped. Next
candidates would build on `provenance-check`: full client-side
Rekor/Fulcio bundle re-verification (via sigstore-python) for packages
that already report ATTESTED, if independent re-verification (rather
than trusting the registry's own check) turns out to matter in
practice.
