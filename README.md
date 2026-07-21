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
  `pyproject.toml`), Node.js (`package.json`, `package-lock.json`), and
  Go (`go.mod`, `go.sum`). Validated against the official CycloneDX
  JSON schema (via `cyclonedx-python-lib`) in this repo's own test
  suite, not just an internal shape assumption.
- **`scan`** — checks a project's dependencies (across all supported
  ecosystems above) against [OSV.dev](https://osv.dev)'s free, open
  vulnerability database. Query pattern adapted directly from the
  sibling [secureaudit](https://github.com/quaresma870/secureaudit)
  repo's already-proven CVE plugin.

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
```

## Project structure

```
sbom-audit/
├── sbom_audit/
│   ├── cli.py                  # generate, scan
│   ├── core/
│   │   ├── manifest_parser.py  # Python/npm/Go manifests -> normalized packages
│   │   ├── sbom_generator.py   # real CycloneDX 1.5 JSON generation
│   │   ├── vuln_check.py       # OSV.dev batch vulnerability query
│   │   └── models.py
│   └── reports/terminal.py
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
