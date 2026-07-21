# 📦 sbom-audit

SBOM generation & dependency vulnerability scanning.

Given the EU Cyber Resilience Act's enforcement ramping up through
2026–2027, SBOM generation is moving from "good practice" to a real
compliance requirement for a lot of EU-based software.

No `authorization.yml` needed — unlike the other live-scanning repos in
this portfolio (voipaudit, camara-audit, certwatch), this tool analyzes
local project files and queries public databases (OSV.dev), not a live
target's own infrastructure.

## Status

Early, actively developed. Currently covers:

- **`generate`** — produces a real, schema-valid CycloneDX 1.5 JSON SBOM
  from a project's dependency manifests: Python (`requirements.txt`,
  `pyproject.toml`, `poetry.lock`, `pdm.lock`), Node.js (`package.json`,
  `package-lock.json`), and Go (`go.mod`, `go.sum`). Validated against
  the official CycloneDX JSON schema (via `cyclonedx-python-lib`) in
  this repo's own test suite, not just an internal shape assumption.
- **`scan`** — checks a project's dependencies (across all supported
  ecosystems above) against [OSV.dev](https://osv.dev)'s free, open
  vulnerability database. Query pattern adapted directly from the
  sibling [secureaudit](https://github.com/quaresma870/secureaudit)
  repo's already-proven CVE plugin.
- **`cra-report`** — maps SBOM + `scan` results to the vulnerability-
  handling requirements in Annex I Part II of the EU Cyber Resilience
  Act (Regulation (EU) 2024/2847). Only reports SATISFIED/
  ATTENTION_NEEDED for the points a manifest scan can actually observe
  (SBOM presence, open CRITICAL/HIGH findings, whether a scan ran);
  organizational/process requirements (disclosure policy, security
  contact, update distribution) are always reported NOT_AUTOMATABLE.
  Informational only — not legal advice or a compliance certification.

See [ROADMAP.md](ROADMAP.md) for what's planned next.

## Installation

```bash
git clone https://github.com/quaresma870/sbom-audit.git
cd sbom-audit
pip install .
```

## Quickstart

```bash
sbom-audit generate /path/to/your/project --output sbom.json
sbom-audit scan /path/to/your/project
sbom-audit scan /path/to/your/project --json findings.json
sbom-audit cra-report /path/to/your/project --output cra.json
```

## Project structure

```
sbom-audit/
├── sbom_audit/
│   ├── cli.py                  # generate, scan, cra-report
│   ├── core/
│   │   ├── manifest_parser.py  # Python/npm/Go manifests -> normalized packages
│   │   ├── sbom_generator.py   # real CycloneDX 1.5 JSON generation
│   │   ├── vuln_check.py       # OSV.dev batch vulnerability query
│   │   ├── cra_mapping.py      # SBOM/scan results -> CRA Annex I Part II mapping
│   │   └── models.py
│   └── reports/
│       ├── terminal.py         # scan findings table
│       └── cra_report.py       # CRA mapping table + JSON
├── tests/test_sbom_audit.py    # includes real CycloneDX schema validation
└── .github/workflows/ci.yml
```

## CI

Builds the real wheel, installs it in a clean venv, and runs every
documented command — including a real `scan` against real OSV.dev (this
repo's own dependencies), since that specific network call can't be
tested from a sandboxed local dev environment without broader network
access.

---

## License

MIT — see [LICENSE](LICENSE).
