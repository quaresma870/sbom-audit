"""
Dependency vulnerability checking via OSV.dev's batch query API.

Query pattern adapted directly from the already-proven secureaudit CVE
plugin (secureaudit/plugins/cve.py) — no API key required, OSV.dev is
free and open.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from sbom_audit.core.manifest_parser import Package
from sbom_audit.core.models import Finding, Severity

_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


class OSVQueryError(Exception):
    """Raised when the OSV.dev query itself fails — distinct from "the
    query succeeded and found zero vulnerabilities," which is itself a
    normal, valid, good result."""


def check_vulnerabilities(
    packages: list[Package], timeout: float = 20.0, urlopen_fn=None,
) -> list[Finding]:
    if not packages:
        return []

    urlopen_fn = urlopen_fn or urllib.request.urlopen
    try:
        queries = [
            {"package": {"name": pkg.name, "ecosystem": pkg.ecosystem}, "version": pkg.version}
            for pkg in packages
        ]
        payload = json.dumps({"queries": queries}).encode()
        req = urllib.request.Request(
            _OSV_BATCH_URL, data=payload, headers={"Content-Type": "application/json"}, method="POST",
        )
        with urlopen_fn(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise OSVQueryError(f"Could not query OSV.dev: {exc}") from exc

    findings: list[Finding] = []
    for pkg, batch_result in zip(packages, data.get("results", []), strict=True):
        vulns = batch_result.get("vulns", [])
        for vuln in vulns:
            findings.append(_finding_from_vuln(pkg, vuln))

    if not findings:
        findings.append(Finding(
            module="osv_check",
            title="No known vulnerabilities found",
            severity=Severity.INFO,
            target=f"{len(packages)} package(s)",
            description=f"Checked {len(packages)} dependencies against OSV.dev — all clean.",
        ))

    return findings


def _finding_from_vuln(pkg: Package, vuln: dict) -> Finding:
    vuln_id = vuln.get("id", "UNKNOWN")
    summary = vuln.get("summary") or vuln.get("details", "No description available")[:300]

    severity_raw = "MEDIUM"
    for sev_entry in vuln.get("severity", []):
        if "CVSS" in sev_entry.get("type", ""):
            score = str(sev_entry.get("score", ""))
            for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                if level in score.upper():
                    severity_raw = level
                    break

    refs = vuln.get("references", [])
    ref_url = refs[0]["url"] if refs else f"https://osv.dev/vulnerability/{vuln_id}"

    return Finding(
        module="osv_check",
        title=f"{vuln_id} in {pkg.name} {pkg.version}",
        severity=_SEVERITY_MAP.get(severity_raw, Severity.MEDIUM),
        target=f"{pkg.name}=={pkg.version}",
        description=summary,
        evidence=f"{pkg.ecosystem}: {pkg.name}=={pkg.version}",
        remediation=f"Update {pkg.name} to a patched version. Check {ref_url}",
        reference=ref_url,
        extra={"vuln_id": vuln_id, "ecosystem": pkg.ecosystem, "package": pkg.name, "version": pkg.version},
    )
