"""sbom-audit CLI. No authorization.yml / Engagement gate — this tool
analyzes local project files and queries public vulnerability/CT-log-style
databases, not a live target's own infrastructure, matching the same
reasoning already applied to the sibling voipaudit repo's analyze-cdr
and camara-audit's analyze-token commands."""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console

console = Console()


@click.group()
@click.version_option(package_name="sbom-audit")
def cli():
    """📦 sbom-audit — SBOM generation & dependency vulnerability scanning."""


@cli.command(name="generate")
@click.argument("project_dir", type=click.Path(exists=True, file_okay=False))
@click.option("--output", "-o", default="sbom.json", show_default=True)
@click.option("--name", default=None, help="Project name for the SBOM metadata (default: directory name).")
def generate(project_dir, output, name):
    """Generate a CycloneDX 1.5 JSON SBOM from a project's dependency manifests."""
    import json

    from sbom_audit.core.manifest_parser import parse_manifests
    from sbom_audit.core.sbom_generator import generate_sbom

    project_dir = Path(project_dir)
    project_name = name or project_dir.resolve().name

    packages = parse_manifests(project_dir)
    if not packages:
        console.print(
            "[yellow]⚠[/yellow] No dependencies found in requirements.txt or pyproject.toml "
            f"under {project_dir}."
        )

    sbom = generate_sbom(project_name, packages)
    Path(output).write_text(json.dumps(sbom, indent=2))
    console.print(f"[green]✔[/green] Generated SBOM with {len(packages)} component(s): [bold]{output}[/bold]")


@cli.command()
@click.argument("project_dir", type=click.Path(exists=True, file_okay=False))
@click.option("--json", "json_output", default=None, type=click.Path())
@click.option("--sarif", "sarif_output", default=None, type=click.Path(),
              help="Write results as SARIF 2.1.0, for GitHub code scanning upload.")
def scan(project_dir, json_output, sarif_output):
    """Check a project's dependencies against OSV.dev for known vulnerabilities."""
    from sbom_audit.core.manifest_parser import parse_manifests
    from sbom_audit.core.vuln_check import OSVQueryError, check_vulnerabilities
    from sbom_audit.reports.terminal import print_findings

    project_dir = Path(project_dir)
    packages = parse_manifests(project_dir)

    if not packages:
        console.print(f"[yellow]⚠[/yellow] No dependencies found under {project_dir}.")
        sys.exit(0)

    console.print(f"Checking {len(packages)} dependencies against OSV.dev...")
    try:
        findings = check_vulnerabilities(packages)
    except OSVQueryError as exc:
        console.print(f"[red]✘ {exc}[/red]")
        sys.exit(1)

    print_findings(str(project_dir), findings)

    if json_output:
        import json as json_module
        with open(json_output, "w") as f:
            json_module.dump([f.to_dict() for f in findings], f, indent=2)
        console.print(f"[green]✔[/green] Wrote {len(findings)} finding(s) to {json_output}")

    if sarif_output:
        import json as json_module

        from sbom_audit.reports.sarif_report import build_sarif

        with open(sarif_output, "w") as f:
            json_module.dump(build_sarif(findings), f, indent=2)
        console.print(f"[green]✔[/green] Wrote SARIF report to {sarif_output}")

    if any(f.severity.value in ("CRITICAL", "HIGH") for f in findings):
        sys.exit(1)


@cli.command(name="cra-report")
@click.argument("project_dir", type=click.Path(exists=True, file_okay=False))
@click.option("--output", "-o", default=None, type=click.Path())
@click.option("--name", default=None, help="Project name for the report (default: directory name).")
def cra_report(project_dir, output, name):
    """Map SBOM + OSV.dev scan results to the EU Cyber Resilience Act's
    Annex I Part II vulnerability-handling requirements. Informational
    only — not legal advice or a compliance certification."""
    from sbom_audit.core.cra_mapping import map_findings_to_cra
    from sbom_audit.core.manifest_parser import parse_manifests
    from sbom_audit.core.sbom_generator import generate_sbom
    from sbom_audit.core.vuln_check import OSVQueryError, check_vulnerabilities
    from sbom_audit.reports.cra_report import build_cra_report_dict, print_cra_report

    project_dir = Path(project_dir)
    project_name = name or project_dir.resolve().name

    packages = parse_manifests(project_dir)
    sbom = generate_sbom(project_name, packages)

    findings = []
    scanned = False
    if packages:
        console.print(f"Checking {len(packages)} dependencies against OSV.dev...")
        try:
            findings = check_vulnerabilities(packages)
            scanned = True
        except OSVQueryError as exc:
            console.print(f"[yellow]⚠[/yellow] Could not complete OSV.dev scan: {exc}")

    requirements = map_findings_to_cra(len(sbom["components"]), findings, scanned)
    print_cra_report(project_name, requirements)

    if output:
        import json

        report = build_cra_report_dict(project_name, requirements)
        Path(output).write_text(json.dumps(report, indent=2))
        console.print(f"[green]✔[/green] Wrote CRA mapping report to [bold]{output}[/bold]")


@cli.command(name="provenance-check")
@click.argument("project_dir", type=click.Path(exists=True, file_okay=False))
@click.option("--json", "json_output", default=None, type=click.Path())
def provenance_check(project_dir, json_output):
    """Check whether npm/PyPI dependencies have a Sigstore-backed
    provenance attestation on file with the registry. Checks registry
    metadata, not a from-scratch client-side Rekor/Fulcio re-verification
    of the raw attestation bundle."""
    from sbom_audit.core.manifest_parser import parse_manifests
    from sbom_audit.core.provenance_check import check_provenance
    from sbom_audit.reports.provenance_report import print_provenance_report

    project_dir = Path(project_dir)
    packages = parse_manifests(project_dir)

    if not packages:
        console.print(f"[yellow]⚠[/yellow] No dependencies found under {project_dir}.")
        sys.exit(0)

    console.print(f"Checking provenance for {len(packages)} dependencies...")
    results = check_provenance(packages)
    print_provenance_report(str(project_dir), results)

    if json_output:
        import json

        with open(json_output, "w") as f:
            json.dump([r.to_dict() for r in results], f, indent=2)
        console.print(f"[green]✔[/green] Wrote {len(results)} result(s) to {json_output}")


def main():
    cli()


if __name__ == "__main__":
    main()
