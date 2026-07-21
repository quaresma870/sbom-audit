"""
Independent client-side re-verification of Sigstore-backed provenance
attestations that check_provenance() already reported ATTESTED —
confirms the registry's claim by cryptographically re-verifying the
actual bundle (Fulcio certificate chain + Rekor transparency log
inclusion, via sigstore-python's real verifier) and checking the
signing identity against declared publisher metadata, rather than
trusting the registry's own "yes, we validated this" response at face
value.

npm and PyPI use genuinely different attestation formats, confirmed
against real, live registry responses before writing this:
- npm's `/-/npm/v1/attestations/{name}@{version}` returns two
  attestations; only the `https://slsa.dev/provenance/v1` one carries
  a real Fulcio certificate in `verificationMaterial` (the other, npm's
  own "publish/v0.1" predicate, uses a static key hint instead and
  isn't independently re-verifiable the same way). That one loads
  directly as a `sigstore.models.Bundle`.
- PyPI's PEP 740 provenance bundle (fetched from the Simple API's
  per-file `provenance` URL) is PyPI's own wrapper format, not a raw
  Sigstore bundle — the official `pypi-attestations` library handles
  parsing and verification, and its `AttestationBundle.publisher`
  already carries the expected identity (repository/workflow) as
  configured server-side in PyPI's Trusted Publishing setup for that
  project, which is a stronger identity signal than anything read from
  the package's own (spoofable) metadata.

For npm there's no equivalent server-side "expected publisher" record
exposed via a public API, so the expected identity is read from the
package's own npm registry `repository` field instead — weaker than
PyPI's case (a malicious package could declare any repository in its
own metadata), but still confirms the attestation was signed via a
real GitHub Actions OIDC identity for *some* concrete repository,
not merely that *some* validly-Fulcio-issued certificate exists
(sigstore-python's own `UnsafeNoOp` policy — skipping identity checks
entirely — is documented as "fundamentally insecure... must only be
used for testing purposes", so it is deliberately not used here).

Both real verification paths require network access to Sigstore's own
infrastructure (tuf-repo-cdn.sigstore.dev for the trust root) in
addition to the registry APIs — like api.osv.dev, this isn't reachable
from this repo's own sandboxed dev environment, so it's exercised for
real in CI, not locally.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from enum import StrEnum

from sbom_audit.core.manifest_parser import Package
from sbom_audit.core.provenance_check import ProvenanceResult, ProvenanceStatus

_GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
_NPM_VERSION_URL = "https://registry.npmjs.org/{name}/{version}"
_NPM_ATTESTATIONS_URL = "https://registry.npmjs.org/-/npm/v1/attestations/{spec}"
_SLSA_PROVENANCE_PREDICATE = "https://slsa.dev/provenance/v1"

_PYPI_SIMPLE_URL = "https://pypi.org/simple/{name}/"
_PYPI_SIMPLE_ACCEPT = "application/vnd.pypi.simple.v1+json"
_PYPI_INTEGRITY_URL = "https://pypi.org/integrity/{name}/{version}/{filename}/provenance"


class VerificationStatus(StrEnum):
    VERIFIED = "VERIFIED"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"
    SKIPPED = "SKIPPED"
    CHECK_FAILED = "CHECK_FAILED"


@dataclass
class VerificationResult:
    package: Package
    status: VerificationStatus
    detail: str


def verify_provenance(
    results: list[ProvenanceResult], timeout: float = 20.0, urlopen_fn=None, verifier=None, pypi_verify_fn=None,
) -> list[VerificationResult]:
    """Only re-verifies packages check_provenance() already reported
    ATTESTED — there's nothing to independently re-verify for a
    package with no attestation on file. `verifier`, if given, must
    expose a `verify_dsse(bundle, policy)` method matching
    sigstore.verify.Verifier (used for the npm path). `pypi_verify_fn`,
    if given, replaces the call to `Attestation.verify(publisher,
    dist)` (used for the PyPI path) — both exist so tests can inject a
    fake in place of the real cryptographic verifier."""
    urlopen_fn = urlopen_fn or urllib.request.urlopen
    output = []
    for result in results:
        if result.status != ProvenanceStatus.ATTESTED:
            continue
        pkg = result.package
        if pkg.ecosystem == "npm":
            output.append(_verify_npm(pkg, timeout, urlopen_fn, verifier))
        elif pkg.ecosystem == "PyPI":
            output.append(_verify_pypi(pkg, timeout, urlopen_fn, pypi_verify_fn))
    return output


def _npm_repo_to_owner_repo(repo_field) -> str | None:
    if isinstance(repo_field, dict):
        url = repo_field.get("url", "")
    elif isinstance(repo_field, str):
        url = repo_field
    else:
        return None

    m = re.match(r"^github:([^/]+)/([^/]+?)(?:\.git)?$", url)
    if m:
        return f"{m.group(1)}/{m.group(2)}"

    m = re.search(r"github\.com[:/]+([^/]+)/([^/.]+?)(?:\.git)?/?$", url)
    return f"{m.group(1)}/{m.group(2)}" if m else None


def _verify_npm(pkg: Package, timeout: float, urlopen_fn, verifier) -> VerificationResult:
    try:
        req = urllib.request.Request(
            _NPM_ATTESTATIONS_URL.format(spec=f"{pkg.name}@{pkg.version}"),
            headers={"Accept": "application/json"},
        )
        with urlopen_fn(req, timeout=timeout) as resp:
            attestations = json.loads(resp.read()).get("attestations", [])

        version_req = urllib.request.Request(
            _NPM_VERSION_URL.format(name=pkg.name, version=pkg.version), headers={"Accept": "application/json"},
        )
        with urlopen_fn(version_req, timeout=timeout) as resp:
            repository = json.loads(resp.read()).get("repository")
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        return VerificationResult(pkg, VerificationStatus.CHECK_FAILED, f"Could not fetch attestation data: {exc}")

    slsa_bundle = next(
        (a["bundle"] for a in attestations if a.get("predicateType") == _SLSA_PROVENANCE_PREDICATE), None,
    )
    if slsa_bundle is None:
        return VerificationResult(
            pkg, VerificationStatus.SKIPPED, "No SLSA provenance attestation with a re-verifiable certificate found.",
        )

    owner_repo = _npm_repo_to_owner_repo(repository)
    if owner_repo is None:
        return VerificationResult(
            pkg, VerificationStatus.SKIPPED,
            "Package has no declared GitHub repository to check the signing identity against.",
        )

    from sigstore.errors import Error as SigstoreError
    from sigstore.errors import VerificationError as SigstoreVerificationError
    from sigstore.models import Bundle
    from sigstore.verify import Verifier
    from sigstore.verify.policy import AllOf, GitHubWorkflowRepository, OIDCIssuer

    policy = AllOf([OIDCIssuer(_GITHUB_OIDC_ISSUER), GitHubWorkflowRepository(owner_repo)])

    try:
        verifier = verifier or Verifier.production()
        bundle = Bundle.from_json(json.dumps(slsa_bundle))
        verifier.verify_dsse(bundle, policy)
    except SigstoreVerificationError as exc:
        return VerificationResult(pkg, VerificationStatus.VERIFICATION_FAILED, str(exc))
    except SigstoreError as exc:
        return VerificationResult(pkg, VerificationStatus.CHECK_FAILED, f"Could not complete verification: {exc}")

    return VerificationResult(
        pkg, VerificationStatus.VERIFIED, f"Signature, Rekor log entry, and repository ({owner_repo}) confirmed.",
    )


def _verify_pypi(pkg: Package, timeout: float, urlopen_fn, verify_fn=None) -> VerificationResult:
    try:
        req = urllib.request.Request(
            _PYPI_SIMPLE_URL.format(name=pkg.name), headers={"Accept": _PYPI_SIMPLE_ACCEPT},
        )
        with urlopen_fn(req, timeout=timeout) as resp:
            files = json.loads(resp.read()).get("files", [])
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        return VerificationResult(pkg, VerificationStatus.CHECK_FAILED, f"Could not fetch package file list: {exc}")

    from sbom_audit.core.provenance_check import _file_matches_version

    attested_file = next(
        (f for f in files if _file_matches_version(f["filename"], pkg.name, pkg.version) and f.get("provenance")),
        None,
    )
    if attested_file is None:
        return VerificationResult(pkg, VerificationStatus.SKIPPED, "No attested file found for this version.")

    try:
        prov_req = urllib.request.Request(attested_file["provenance"], headers={"Accept": "application/json"})
        with urlopen_fn(prov_req, timeout=timeout) as resp:
            provenance_json = resp.read()
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        return VerificationResult(pkg, VerificationStatus.CHECK_FAILED, f"Could not fetch provenance bundle: {exc}")

    from pypi_attestations import AttestationError, Distribution, Provenance
    from pypi_attestations import VerificationError as PyPIVerificationError
    from sigstore.errors import Error as SigstoreError

    try:
        provenance = Provenance.model_validate_json(provenance_json)
        digest = attested_file["hashes"]["sha256"]
        dist = Distribution(name=attested_file["filename"], digest=digest)

        for bundle in provenance.attestation_bundles:
            for attestation in bundle.attestations:
                fn = verify_fn or attestation.verify
                fn(bundle.publisher, dist)
    except PyPIVerificationError as exc:
        return VerificationResult(pkg, VerificationStatus.VERIFICATION_FAILED, str(exc))
    except (AttestationError, SigstoreError) as exc:
        # Attestation.verify() calls sigstore-python's Verifier.production()
        # internally, unguarded -- a raw sigstore.errors.Error (e.g. TUFError
        # from a trust-root fetch failure) can propagate straight through
        # pypi-attestations' own AttestationError hierarchy, confirmed by
        # reading Attestation.verify()'s source rather than assumed.
        return VerificationResult(pkg, VerificationStatus.CHECK_FAILED, f"Could not complete verification: {exc}")

    return VerificationResult(pkg, VerificationStatus.VERIFIED, "Signature, Rekor log entry, and publisher confirmed.")
