"""
Maps SBOM/scan output to the vulnerability-handling requirements in
Annex I, Part II of the EU Cyber Resilience Act (Regulation (EU)
2024/2847). Requirement text below is a good-faith paraphrase for
readability, not the verbatim regulation — check the official text
(Annex I, Part II) before relying on this for actual compliance
documentation. This tool can only attest to what a static scan of
manifest files can observe; several requirements are inherently
organizational/process matters (a disclosure policy, a security
contact address) that no scan can verify, and are marked accordingly
rather than guessed at.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from sbom_audit.core.models import Finding, Severity


class CRAStatus(StrEnum):
    SATISFIED = "SATISFIED"
    ATTENTION_NEEDED = "ATTENTION_NEEDED"
    NOT_AUTOMATABLE = "NOT_AUTOMATABLE"


@dataclass
class CRARequirement:
    point: str
    title: str
    status: CRAStatus
    evidence: str

    def to_dict(self) -> dict:
        return {
            "point": self.point, "title": self.title,
            "status": self.status.value, "evidence": self.evidence,
        }


DISCLAIMER = (
    "This mapping is informational, based on a paraphrase of Annex I Part II "
    "of Regulation (EU) 2024/2847. It is not legal advice and is not a "
    "compliance certification — verify against the official regulation text "
    "and consult counsel before using it for compliance documentation."
)


def map_findings_to_cra(
    component_count: int, findings: list[Finding], scanned: bool,
) -> list[CRARequirement]:
    """Evaluates the subset of Annex I Part II points that a manifest
    scan can actually speak to (1-3), and reports the rest (4-8) as
    NOT_AUTOMATABLE — organizational/process requirements no static
    tool can verify, rather than silently omitting them."""
    open_findings = [f for f in findings if f.severity != Severity.INFO]
    critical_or_high = [f for f in open_findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]

    requirements = [
        CRARequirement(
            point="1",
            title="Identify and document vulnerabilities and components (SBOM)",
            status=CRAStatus.SATISFIED if component_count > 0 else CRAStatus.ATTENTION_NEEDED,
            evidence=(
                f"CycloneDX SBOM generated with {component_count} component(s)."
                if component_count > 0
                else "No components found in project manifests — nothing to document."
            ),
        ),
        CRARequirement(
            point="2",
            title="Address and remediate vulnerabilities without delay",
            status=CRAStatus.ATTENTION_NEEDED if critical_or_high else CRAStatus.SATISFIED,
            evidence=(
                f"{len(critical_or_high)} CRITICAL/HIGH vulnerability finding(s) require remediation."
                if critical_or_high
                else f"No CRITICAL/HIGH findings among {len(open_findings)} open finding(s)."
            ),
        ),
        CRARequirement(
            point="3",
            title="Apply effective and regular security tests and reviews",
            status=CRAStatus.SATISFIED if scanned else CRAStatus.ATTENTION_NEEDED,
            evidence=(
                f"OSV.dev dependency scan run at {datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')}."
                if scanned
                else "No scan was run — this report only reflects SBOM generation."
            ),
        ),
        CRARequirement(
            point="4",
            title="Publicly disclose fixed-vulnerability information once patched",
            status=CRAStatus.NOT_AUTOMATABLE,
            evidence="Requires a public disclosure process; not observable from a manifest scan.",
        ),
        CRARequirement(
            point="5",
            title="Maintain a coordinated vulnerability disclosure policy",
            status=CRAStatus.NOT_AUTOMATABLE,
            evidence="Requires an organizational policy document; not observable from a manifest scan.",
        ),
        CRARequirement(
            point="6",
            title="Provide a contact address for reporting vulnerabilities",
            status=CRAStatus.NOT_AUTOMATABLE,
            evidence="Requires a published security contact; not observable from a manifest scan.",
        ),
        CRARequirement(
            point="7",
            title="Provide mechanisms to securely distribute updates",
            status=CRAStatus.NOT_AUTOMATABLE,
            evidence="Requires a distribution/update mechanism; not observable from a manifest scan.",
        ),
        CRARequirement(
            point="8",
            title="Disseminate security patches without delay, with advisory information",
            status=CRAStatus.NOT_AUTOMATABLE,
            evidence="Requires a patch-release process; not observable from a manifest scan.",
        ),
    ]
    return requirements
