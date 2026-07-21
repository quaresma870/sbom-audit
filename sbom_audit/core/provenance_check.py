"""
Supply-chain provenance checking — a real, separate concern from OSV
vulnerability scanning: not "does this package have known CVEs" but
"can we tell who published it, verifiably."

Scope: this checks whether npm/PyPI's own registries already have a
Sigstore-backed provenance attestation on file for the exact package
version (both registries verify the attestation against Sigstore
before accepting it at publish time). That is a real, meaningful
signal, but it is a narrower claim than "this tool independently
re-verified the raw Sigstore bundle (Rekor inclusion, Fulcio cert
chain) client-side" — doing that would mean downloading every
package's actual artifact and adding the full sigstore-python
verification stack as a dependency, out of scope for this first pass.
Go modules have no standard Sigstore-based provenance mechanism yet
and are reported as unsupported rather than guessed at.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from enum import StrEnum

from sbom_audit.core.manifest_parser import Package

_NPM_ATTESTATIONS_URL = "https://registry.npmjs.org/-/npm/v1/attestations/{spec}"
# PEP 740 provenance is only exposed via the Simple Repository API (PEP
# 691 JSON) -- confirmed the legacy /pypi/{name}/{version}/json metadata
# API does NOT carry a "provenance" field at all, by checking a real
# response (pip 26.1.2) against both endpoints before writing this.
_PYPI_SIMPLE_URL = "https://pypi.org/simple/{name}/"
_PYPI_SIMPLE_ACCEPT = "application/vnd.pypi.simple.v1+json"


class ProvenanceStatus(StrEnum):
    ATTESTED = "ATTESTED"
    NOT_ATTESTED = "NOT_ATTESTED"
    UNSUPPORTED_ECOSYSTEM = "UNSUPPORTED_ECOSYSTEM"
    CHECK_FAILED = "CHECK_FAILED"


@dataclass
class ProvenanceResult:
    package: Package
    status: ProvenanceStatus
    detail: str

    def to_dict(self) -> dict:
        return {
            "package": self.package.name,
            "version": self.package.version,
            "ecosystem": self.package.ecosystem,
            "status": self.status.value,
            "detail": self.detail,
        }


def check_provenance(
    packages: list[Package], timeout: float = 15.0, urlopen_fn=None,
) -> list[ProvenanceResult]:
    urlopen_fn = urlopen_fn or urllib.request.urlopen
    results = []
    for pkg in packages:
        if pkg.ecosystem == "npm":
            results.append(_check_npm(pkg, timeout, urlopen_fn))
        elif pkg.ecosystem == "PyPI":
            results.append(_check_pypi(pkg, timeout, urlopen_fn))
        else:
            results.append(ProvenanceResult(
                package=pkg,
                status=ProvenanceStatus.UNSUPPORTED_ECOSYSTEM,
                detail=f"{pkg.ecosystem} has no standard Sigstore-based provenance mechanism yet.",
            ))
    return results


def _check_npm(pkg: Package, timeout: float, urlopen_fn) -> ProvenanceResult:
    url = _NPM_ATTESTATIONS_URL.format(spec=f"{pkg.name}@{pkg.version}")
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urlopen_fn(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return ProvenanceResult(pkg, ProvenanceStatus.NOT_ATTESTED, "No attestations published on npm registry.")
        return ProvenanceResult(pkg, ProvenanceStatus.CHECK_FAILED, f"npm registry query failed: {exc}")
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        return ProvenanceResult(pkg, ProvenanceStatus.CHECK_FAILED, f"npm registry query failed: {exc}")

    attestations = data.get("attestations", [])
    if attestations:
        return ProvenanceResult(
            pkg, ProvenanceStatus.ATTESTED, f"{len(attestations)} attestation(s) published on npm registry."
        )
    return ProvenanceResult(pkg, ProvenanceStatus.NOT_ATTESTED, "No attestations published on npm registry.")


def _normalize_pypi_name(name: str) -> str:
    """PEP 503 normalization: PyPI treats runs of -_. as equivalent."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _file_matches_version(filename: str, name: str, version: str) -> bool:
    prefix = f"{_normalize_pypi_name(name)}-{version}"
    normalized_filename = filename.replace("_", "-").lower()
    return normalized_filename.startswith(f"{prefix}-") or normalized_filename.startswith(f"{prefix}.")


def _check_pypi(pkg: Package, timeout: float, urlopen_fn) -> ProvenanceResult:
    url = _PYPI_SIMPLE_URL.format(name=pkg.name)
    try:
        req = urllib.request.Request(url, headers={"Accept": _PYPI_SIMPLE_ACCEPT})
        with urlopen_fn(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return ProvenanceResult(pkg, ProvenanceStatus.CHECK_FAILED, f"Package not found on PyPI: {pkg.name}")
        return ProvenanceResult(pkg, ProvenanceStatus.CHECK_FAILED, f"PyPI query failed: {exc}")
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        return ProvenanceResult(pkg, ProvenanceStatus.CHECK_FAILED, f"PyPI query failed: {exc}")

    files = [f for f in data.get("files", []) if _file_matches_version(f["filename"], pkg.name, pkg.version)]
    if not files:
        return ProvenanceResult(
            pkg, ProvenanceStatus.CHECK_FAILED, f"Version not found on PyPI: {pkg.name}=={pkg.version}"
        )

    attested_files = [f for f in files if f.get("provenance")]
    if attested_files:
        return ProvenanceResult(
            pkg, ProvenanceStatus.ATTESTED, f"{len(attested_files)} file(s) with PEP 740 provenance on PyPI."
        )
    return ProvenanceResult(pkg, ProvenanceStatus.NOT_ATTESTED, "No PEP 740 provenance published on PyPI.")
