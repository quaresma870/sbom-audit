"""
License lookup for SBOM enrichment. CycloneDX supports a per-component
`licenses` array, but none of the local manifest/lockfile formats this
tool parses carry license metadata — it has to come from the registry,
one network call per dependency. `generate` doesn't do this by
default (a real trade-off: it stays fast and offline unless you opt in
with `--licenses`).

CycloneDX's schema validates `license.id` against the official SPDX
license list — an arbitrary string there fails schema validation. So
`id` is only ever emitted for a value that's an exact match against a
curated set of common, unambiguous SPDX identifiers; everything else
(a free-text description, a compound expression like "Apache-2.0 OR
BSD-3-Clause", a generic classifier label like "BSD License" that
doesn't specify which BSD variant) goes into the free-text `name`
field instead of being guessed at.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass

from sbom_audit.core.manifest_parser import Package

_PYPI_JSON_URL = "https://pypi.org/pypi/{name}/{version}/json"
_NPM_VERSION_URL = "https://registry.npmjs.org/{name}/{version}"

# A registry's raw license field is sometimes the full license TEXT
# (confirmed against real PyPI data -- numpy's `info.license` is over
# 46KB), not a short identifier. Above this length it's never usable
# as a short name and classifiers are checked instead.
_MAX_USABLE_LICENSE_TEXT_LENGTH = 200

_KNOWN_SPDX_IDS = {
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "0BSD",
    "MPL-2.0", "LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-3.0-only",
    "LGPL-3.0-or-later", "GPL-2.0-only", "GPL-2.0-or-later",
    "GPL-3.0-only", "GPL-3.0-or-later", "AGPL-3.0-only",
    "AGPL-3.0-or-later", "Unlicense", "Zlib", "BSL-1.0", "CC0-1.0",
    "PSF-2.0", "WTFPL", "Artistic-2.0",
}


@dataclass
class LicenseResult:
    package: Package
    spdx_id: str | None
    name: str | None  # free-text; set only when spdx_id is None but some license text is known


def check_licenses(packages: list[Package], timeout: float = 15.0, urlopen_fn=None) -> list[LicenseResult]:
    urlopen_fn = urlopen_fn or urllib.request.urlopen
    results = []
    for pkg in packages:
        if pkg.ecosystem == "PyPI":
            results.append(_check_pypi_license(pkg, timeout, urlopen_fn))
        elif pkg.ecosystem == "npm":
            results.append(_check_npm_license(pkg, timeout, urlopen_fn))
        else:
            results.append(LicenseResult(pkg, None, None))
    return results


def _classify(raw: str) -> tuple[str | None, str | None]:
    raw = raw.strip()
    if not raw:
        return None, None
    if raw in _KNOWN_SPDX_IDS:
        return raw, None
    return None, raw


def _check_pypi_license(pkg: Package, timeout: float, urlopen_fn) -> LicenseResult:
    url = _PYPI_JSON_URL.format(name=pkg.name, version=pkg.version)
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urlopen_fn(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
    except (urllib.error.URLError, TimeoutError, ValueError):
        return LicenseResult(pkg, None, None)

    info = data.get("info", {})
    raw_license = info.get("license") or ""
    if raw_license and len(raw_license) <= _MAX_USABLE_LICENSE_TEXT_LENGTH:
        spdx_id, name = _classify(raw_license)
        return LicenseResult(pkg, spdx_id, name)

    for classifier in info.get("classifiers", []):
        if classifier.startswith("License :: OSI Approved :: "):
            label = classifier.removeprefix("License :: OSI Approved :: ")
            spdx_id, name = _classify(label)
            return LicenseResult(pkg, spdx_id, name)

    return LicenseResult(pkg, None, None)


def _check_npm_license(pkg: Package, timeout: float, urlopen_fn) -> LicenseResult:
    url = _NPM_VERSION_URL.format(name=pkg.name, version=pkg.version)
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urlopen_fn(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
    except (urllib.error.URLError, TimeoutError, ValueError):
        return LicenseResult(pkg, None, None)

    raw_license = data.get("license")
    if isinstance(raw_license, dict):
        raw_license = raw_license.get("type")
    if not isinstance(raw_license, str) or not raw_license:
        return LicenseResult(pkg, None, None)

    spdx_id, name = _classify(raw_license)
    return LicenseResult(pkg, spdx_id, name)
