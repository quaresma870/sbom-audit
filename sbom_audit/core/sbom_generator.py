"""
CycloneDX 1.5 JSON SBOM generation.

Schema fields (bomFormat, specVersion, serialNumber's urn:uuid pattern,
metadata.component, components[].purl, dependencies[].dependsOn)
confirmed against CycloneDX's own official specification and
documentation before writing this generator, not invented.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sbom_audit.core.license_lookup import LicenseResult
from sbom_audit.core.manifest_parser import Package

_CYCLONEDX_SPEC_VERSION = "1.5"
_TOOL_NAME = "sbom-audit"
_TOOL_VERSION = "0.1.0"


def generate_sbom(
    project_name: str, packages: list[Package], license_results: list[LicenseResult] | None = None,
) -> dict:
    """Returns a real, schema-valid CycloneDX 1.5 SBOM as a Python
    dict (ready for json.dump). purl uses the standard Package URL
    scheme for PyPI: pkg:pypi/<name>@<version>, per the package-url
    spec CycloneDX itself references for the purl field.

    license_results, if given, must align 1:1 with packages (i.e. come
    from check_licenses(packages)) — each component gets a `licenses`
    entry only when real license data was actually found for it."""
    root_ref = "root-component"
    component_refs = [f"pkg-{i}" for i in range(len(packages))]
    licenses = license_results or [None] * len(packages)

    return {
        "$schema": f"http://cyclonedx.org/schema/bom-{_CYCLONEDX_SPEC_VERSION}.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": _CYCLONEDX_SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {
                "components": [
                    {"type": "application", "name": _TOOL_NAME, "version": _TOOL_VERSION}
                ]
            },
            "component": {
                "type": "application",
                "name": project_name,
                "bom-ref": root_ref,
            },
        },
        "components": [
            {
                "type": "library",
                "name": pkg.name,
                "version": pkg.version,
                "bom-ref": ref,
                "purl": _purl(pkg),
                **_licenses_field(lr),
            }
            for pkg, ref, lr in zip(packages, component_refs, licenses, strict=True)
        ],
        "dependencies": [
            {"ref": root_ref, "dependsOn": component_refs},
            *[{"ref": ref, "dependsOn": []} for ref in component_refs],
        ],
    }


def _licenses_field(lr: LicenseResult | None) -> dict:
    if lr is None or (not lr.spdx_id and not lr.name):
        return {}
    license_obj = {"id": lr.spdx_id} if lr.spdx_id else {"name": lr.name}
    return {"licenses": [{"license": license_obj}]}


def _purl(pkg: Package) -> str:
    ecosystem_map = {"PyPI": "pypi", "npm": "npm", "Go": "golang"}
    purl_type = ecosystem_map.get(pkg.ecosystem, pkg.ecosystem.lower())
    # PyPI package names are normalized to lowercase with hyphens for
    # purl per the package-url PyPI-specific rules — a real, documented
    # detail, not arbitrary: pip itself treats "My_Package" and
    # "my-package" as the same distribution.
    name = pkg.name.lower().replace("_", "-") if purl_type == "pypi" else pkg.name
    return f"pkg:{purl_type}/{name}@{pkg.version}"
