"""Terminal report rendering — Rich-based, matching the visual style
already established across this portfolio's other CLI tools."""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.table import Table

from sbom_audit.core.models import Finding, Severity

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

console = Console()


def print_findings(target: str, findings: list[Finding]) -> None:
    console.print(f"\n[bold]── {target} ──[/bold]\n")

    if not findings:
        console.print("  No findings.")
        return

    counts = {sev: 0 for sev in Severity}
    for f in findings:
        counts[f.severity] += 1

    table = Table(box=box.SIMPLE_HEAD)
    table.add_column("Severity")
    table.add_column("Title")
    table.add_column("Target")

    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    for finding in sorted(findings, key=lambda f: order.index(f.severity)):
        style = _SEVERITY_STYLE[finding.severity]
        table.add_row(f"[{style}]{finding.severity.value}[/{style}]", finding.title, finding.target)
    console.print(table)

    summary = "  ".join(
        f"[{_SEVERITY_STYLE[sev]}]{counts[sev]} {sev.value}[/{_SEVERITY_STYLE[sev]}]"
        for sev in order if counts[sev] > 0
    )
    console.print(f"\n{summary}\n")
