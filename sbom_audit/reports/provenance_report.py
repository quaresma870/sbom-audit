"""Provenance report rendering — Rich-based, matching the visual style
already established in reports/terminal.py."""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.table import Table

from sbom_audit.core.provenance_check import ProvenanceResult, ProvenanceStatus
from sbom_audit.core.provenance_verify import VerificationResult, VerificationStatus

_STATUS_STYLE = {
    ProvenanceStatus.ATTESTED: "green",
    ProvenanceStatus.NOT_ATTESTED: "yellow",
    ProvenanceStatus.UNSUPPORTED_ECOSYSTEM: "dim",
    ProvenanceStatus.CHECK_FAILED: "red",
}

_VERIFICATION_STYLE = {
    VerificationStatus.VERIFIED: "green",
    VerificationStatus.VERIFICATION_FAILED: "bold red",
    VerificationStatus.SKIPPED: "dim",
    VerificationStatus.CHECK_FAILED: "red",
}

console = Console()


def print_provenance_report(target: str, results: list[ProvenanceResult]) -> None:
    console.print(f"\n[bold]── Provenance: {target} ──[/bold]\n")

    if not results:
        console.print("  No packages to check.")
        return

    table = Table(box=box.SIMPLE_HEAD)
    table.add_column("Package")
    table.add_column("Status")
    table.add_column("Detail")

    for result in results:
        style = _STATUS_STYLE[result.status]
        target_name = f"{result.package.name}=={result.package.version}"
        table.add_row(target_name, f"[{style}]{result.status.value}[/{style}]", result.detail)
    console.print(table)

    counts = {status: 0 for status in ProvenanceStatus}
    for result in results:
        counts[result.status] += 1
    summary = "  ".join(
        f"[{_STATUS_STYLE[status]}]{counts[status]} {status.value}[/{_STATUS_STYLE[status]}]"
        for status in ProvenanceStatus if counts[status] > 0
    )
    console.print(f"\n{summary}\n")


def print_verification_report(target: str, results: list[VerificationResult]) -> None:
    console.print(f"\n[bold]── Independent re-verification: {target} ──[/bold]\n")

    if not results:
        console.print("  No attested packages to re-verify.")
        return

    table = Table(box=box.SIMPLE_HEAD)
    table.add_column("Package")
    table.add_column("Status")
    table.add_column("Detail")

    for result in results:
        style = _VERIFICATION_STYLE[result.status]
        target_name = f"{result.package.name}=={result.package.version}"
        table.add_row(target_name, f"[{style}]{result.status.value}[/{style}]", result.detail)
    console.print(table)

    counts = {status: 0 for status in VerificationStatus}
    for result in results:
        counts[result.status] += 1
    summary = "  ".join(
        f"[{_VERIFICATION_STYLE[status]}]{counts[status]} {status.value}[/{_VERIFICATION_STYLE[status]}]"
        for status in VerificationStatus if counts[status] > 0
    )
    console.print(f"\n{summary}\n")
