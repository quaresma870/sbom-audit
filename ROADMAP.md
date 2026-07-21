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

### License field in the SBOM
`generate --licenses` populates each component's CycloneDX `licenses`
array. None of the local manifest/lockfile formats this tool parses
carry license metadata, so it comes from one registry call per
dependency (PyPI's legacy `/pypi/{name}/{version}/json`, npm's lean
per-version `/{name}/{version}` endpoint) — a real trade-off, so it's
opt-in rather than changing `generate`'s default fast/offline
behavior. CycloneDX validates `license.id` against the official SPDX
list, so `id` is only emitted for an exact match against a curated set
of common, unambiguous SPDX identifiers; everything else (a full
license-text dump — confirmed real, `numpy`'s `info.license` is over
46KB — a compound expression like "Apache-2.0 OR BSD-3-Clause", a
generic classifier label like "BSD License" that doesn't specify which
BSD variant) goes into the free-text `name` field instead of being
guessed at. Go has no equivalent central license registry and is
skipped without a network call.

### More ecosystems: Rust and Ruby
`generate`/`scan` now also parse Rust's `Cargo.lock` (same `[[package]]`
TOML array-of-tables structure as poetry.lock/pdm.lock, so
`_parse_toml_lock` gained an `ecosystem` parameter and covers all
three) and Ruby's `Gemfile.lock` (a custom format: 4-space-indented
`name (version)` lines under each `GIT`/`GEM` section's `specs:` block
are the resolved gems; their own 6-space-indented declared dependencies
are skipped, since those same gems already appear as their own
top-level spec entries elsewhere in the file). Ecosystem strings match
OSV.dev's naming (`crates.io`, `RubyGems`); purls use `cargo`/`gem` per
the package-url spec. License lookup (`--licenses`) doesn't cover
these two yet — no equivalent lean per-version registry endpoint was
established for either, so they're skipped without a network call,
same as Go.

### Independent sigstore/cosign re-verification
`provenance-check --verify` re-verifies ATTESTED packages' Sigstore
bundles for real via sigstore-python/pypi-attestations (an optional
`[verify]` extra — heavy dependency, so it's opt-in), rather than
trusting the registry's own claim. Confirmed against real, live
attestation data before writing this: npm's attestations endpoint
returns two attestation types per package, and only the
`https://slsa.dev/provenance/v1` one carries a real Fulcio certificate
(the other, npm's own "publish/v0.1" predicate, uses a static key hint
instead); PyPI's PEP 740 provenance bundle is a different wrapper
format entirely, handled via the official `pypi-attestations` library
rather than hand-rolled. Deliberately does NOT use sigstore-python's
`UnsafeNoOp` policy — its own docs call it "fundamentally insecure...
must only be used for testing purposes", since it skips checking *who*
signed a bundle, and anyone can obtain a validly-chained Fulcio
certificate. Instead: for PyPI, the expected publisher identity comes
from `AttestationBundle.publisher`, which PyPI's own Trusted
Publishing config already ties to the project server-side (a stronger
signal than anything read from the package's own metadata); for npm,
there's no equivalent public "expected publisher" record, so the
expected GitHub repository is read from the package's own npm registry
`repository` field instead — weaker (a malicious package could declare
any repository), but still confirms a real GitHub Actions OIDC
signing identity for *some* concrete repository. Both paths need
network access to Sigstore's own infrastructure
(tuf-repo-cdn.sigstore.dev for the trust root) in addition to the
registry APIs — like api.osv.dev, unreachable from this repo's own
sandboxed dev environment, so exercised for real in CI. Results
degrade to `CHECK_FAILED` rather than crashing when that trust-root
fetch fails (a real bug caught during manual testing: the fetch call
was originally outside the try/except).

## Next

Nothing currently queued — all items raised in the last recommendation
pass have shipped.
