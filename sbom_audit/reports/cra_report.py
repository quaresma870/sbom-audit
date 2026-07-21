"""CRA requirement-mapping report rendering — terminal (Rich) and JSON,
matching the visual style already established in reports/terminal.py."""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.table import Table

from sbom_audit.core.cra_mapping import DISCLAIMER, CRARequirement, CRAStatus

_STATUS_STYLE = {
    CRAStatus.SATISFIED: "green",
    CRAStatus.ATTENTION_NEEDED: "bold red",
    CRAStatus.NOT_AUTOMATABLE: "dim",
}

console = Console()


def print_cra_report(project_name: str, requirements: list[CRARequirement]) -> None:
    console.print(f"\n[bold]── CRA Annex I Part II mapping: {project_name} ──[/bold]\n")

    table = Table(box=box.SIMPLE_HEAD)
    table.add_column("Point")
    table.add_column("Requirement")
    table.add_column("Status")
    table.add_column("Evidence")

    for req in requirements:
        style = _STATUS_STYLE[req.status]
        table.add_row(req.point, req.title, f"[{style}]{req.status.value}[/{style}]", req.evidence)
    console.print(table)

    console.print(f"\n[dim]{DISCLAIMER}[/dim]\n")


def build_cra_report_dict(project_name: str, requirements: list[CRARequirement]) -> dict:
    return {
        "project": project_name,
        "framework": "EU Cyber Resilience Act — Regulation (EU) 2024/2847, Annex I Part II",
        "disclaimer": DISCLAIMER,
        "requirements": [req.to_dict() for req in requirements],
    }
