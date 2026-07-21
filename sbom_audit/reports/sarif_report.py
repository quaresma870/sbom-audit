"""
SARIF 2.1.0 output for `scan` findings — GitHub natively renders SARIF
uploaded via its code-scanning API in the Security tab, surfacing
findings as inline PR annotations instead of a JSON file nobody opens.

Locations point at the manifest/lockfile a dependency was declared
in (tracked on Package.source_file at parse time), not a specific
line within it — the same convention other SCA tools use for
dependency-level findings, since a vulnerability belongs to a
declared dependency, not a specific source line the way a static
analysis finding would.
"""

from __future__ import annotations

from sbom_audit.core.models import Finding, Severity

_TOOL_NAME = "sbom-audit"
_TOOL_VERSION = "0.1.0"
_INFORMATION_URI = "https://github.com/quaresma870/sbom-audit"

_LEVEL_MAP = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}


def build_sarif(findings: list[Finding]) -> dict:
    """INFO-level findings (e.g. the "no known vulnerabilities" result)
    aren't real alerts and are excluded — SARIF results are meant to be
    actionable, not a restatement that a scan ran clean."""
    reportable = [f for f in findings if f.severity != Severity.INFO]

    rules = {}
    results = []
    for finding in reportable:
        vuln_id = finding.extra.get("vuln_id", finding.title)
        if vuln_id not in rules:
            rules[vuln_id] = {
                "id": vuln_id,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description or finding.title},
                "helpUri": finding.reference or _INFORMATION_URI,
            }

        location = {}
        source_file = finding.extra.get("source_file")
        if source_file:
            location = {
                "physicalLocation": {
                    "artifactLocation": {"uri": source_file},
                    "region": {"startLine": 1},
                }
            }

        results.append({
            "ruleId": vuln_id,
            "level": _LEVEL_MAP.get(finding.severity, "warning"),
            "message": {"text": finding.description or finding.title},
            "locations": [location] if location else [],
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": _TOOL_NAME,
                        "version": _TOOL_VERSION,
                        "informationUri": _INFORMATION_URI,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
