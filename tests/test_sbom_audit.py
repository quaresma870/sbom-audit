from __future__ import annotations

import json

import pytest

from sbom_audit.core.manifest_parser import Package, parse_manifests
from sbom_audit.core.sbom_generator import generate_sbom
from sbom_audit.core.vuln_check import OSVQueryError, check_vulnerabilities


class TestManifestParsing:
    def test_parses_requirements_txt(self, tmp_path):
        (tmp_path / "requirements.txt").write_text(
            "click>=8.1.0\nrich>=13.7.0\n# a comment\npyyaml==6.0.1\n-e .\nhttp://example.com/x.whl\n"
        )
        packages = parse_manifests(tmp_path)
        names = {p.name for p in packages}
        assert names == {"click", "rich", "pyyaml"}

    def test_parses_pyproject_toml(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "x"\ndependencies = ["fastapi>=0.110.0"]\n\n'
            '[project.optional-dependencies]\ndev = ["pytest>=8.2.0"]\n'
        )
        packages = parse_manifests(tmp_path)
        names = {p.name for p in packages}
        assert names == {"fastapi", "pytest"}

    def test_both_manifests_combined(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("click>=8.1.0\n")
        (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = ["rich>=13.7.0"]\n')
        packages = parse_manifests(tmp_path)
        names = {p.name for p in packages}
        assert names == {"click", "rich"}

    def test_no_manifests_returns_empty(self, tmp_path):
        assert parse_manifests(tmp_path) == []

    def test_malformed_pyproject_toml_does_not_crash(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text("this is not [ valid toml")
        assert parse_manifests(tmp_path) == []

    def test_dependency_with_no_version_specifier_skipped(self, tmp_path):
        """A bare 'requests' with no version constraint has nothing
        concrete to check against OSV.dev, so it's correctly excluded
        rather than guessed at."""
        (tmp_path / "requirements.txt").write_text("requests\nclick>=8.1.0\n")
        packages = parse_manifests(tmp_path)
        assert {p.name for p in packages} == {"click"}

    def test_parses_package_json(self, tmp_path):
        (tmp_path / "package.json").write_text(json.dumps({
            "name": "x",
            "dependencies": {"express": "^4.18.2", "lodash": "4.17.21"},
            "devDependencies": {"jest": "~29.7.0"},
            "optionalDependencies": {"fsevents": "*"},
        }))
        packages = parse_manifests(tmp_path)
        by_name = {p.name: p for p in packages}
        assert set(by_name) == {"express", "lodash", "jest"}
        assert by_name["express"].version == "4.18.2"
        assert by_name["express"].ecosystem == "npm"
        assert by_name["lodash"].version == "4.17.21"
        assert by_name["jest"].version == "29.7.0"

    def test_package_json_malformed_does_not_crash(self, tmp_path):
        (tmp_path / "package.json").write_text("not valid json {")
        assert parse_manifests(tmp_path) == []

    def test_parses_package_lock_json_v3(self, tmp_path):
        (tmp_path / "package-lock.json").write_text(json.dumps({
            "name": "x", "lockfileVersion": 3,
            "packages": {
                "": {"name": "x", "version": "1.0.0"},
                "node_modules/express": {"version": "4.18.2"},
                "node_modules/express/node_modules/debug": {"version": "2.6.9"},
            },
        }))
        packages = parse_manifests(tmp_path)
        by_name = {p.name: p for p in packages}
        assert by_name["express"].version == "4.18.2"
        assert by_name["debug"].version == "2.6.9"
        assert all(p.ecosystem == "npm" for p in packages)

    def test_parses_package_lock_json_v1(self, tmp_path):
        (tmp_path / "package-lock.json").write_text(json.dumps({
            "name": "x", "lockfileVersion": 1,
            "dependencies": {
                "express": {"version": "4.18.2", "dependencies": {
                    "debug": {"version": "2.6.9"},
                }},
            },
        }))
        packages = parse_manifests(tmp_path)
        by_name = {p.name: p for p in packages}
        assert by_name["express"].version == "4.18.2"
        assert by_name["debug"].version == "2.6.9"

    def test_parses_go_mod(self, tmp_path):
        (tmp_path / "go.mod").write_text(
            "module example.com/foo\n\ngo 1.22\n\n"
            "require github.com/pkg/errors v0.9.1\n\n"
            "require (\n"
            "\tgithub.com/stretchr/testify v1.9.0\n"
            "\tgolang.org/x/text v0.3.7 // indirect\n"
            ")\n"
        )
        packages = parse_manifests(tmp_path)
        by_name = {p.name: p for p in packages}
        assert by_name["github.com/pkg/errors"].version == "v0.9.1"
        assert by_name["github.com/stretchr/testify"].version == "v1.9.0"
        assert by_name["golang.org/x/text"].version == "v0.3.7"
        assert all(p.ecosystem == "Go" for p in packages)

    def test_parses_go_sum_dedupes_go_mod_hash_lines(self, tmp_path):
        (tmp_path / "go.sum").write_text(
            "github.com/pkg/errors v0.9.1 h1:xxxxx=\n"
            "github.com/pkg/errors v0.9.1/go.mod h1:yyyyy=\n"
        )
        packages = parse_manifests(tmp_path)
        assert len(packages) == 1
        assert packages[0].name == "github.com/pkg/errors"
        assert packages[0].version == "v0.9.1"
        assert packages[0].ecosystem == "Go"


class TestSBOMGeneration:
    def test_generates_valid_cyclonedx_1_5_schema(self):
        """Validated against the REAL, official CycloneDX 1.5 JSON
        schema via the cyclonedx-python-lib package — not just an
        internal shape assumption. Confirmed this matters: an earlier
        version included an invalid 'vendor' field on the tool
        component and only this real schema validation caught it, not
        a hand-written structural test."""
        from cyclonedx.schema import SchemaVersion
        from cyclonedx.validation.json import JsonStrictValidator

        packages = [Package(name="click", version="8.1.0"), Package(name="rich", version="13.7.0")]
        sbom = generate_sbom("test-project", packages)

        validator = JsonStrictValidator(SchemaVersion.V1_5)
        errors = validator.validate_str(json.dumps(sbom))
        assert not errors, f"Schema validation failed: {errors}"

    def test_empty_package_list_still_produces_valid_sbom(self):
        from cyclonedx.schema import SchemaVersion
        from cyclonedx.validation.json import JsonStrictValidator

        sbom = generate_sbom("empty-project", [])
        validator = JsonStrictValidator(SchemaVersion.V1_5)
        errors = validator.validate_str(json.dumps(sbom))
        assert not errors, f"Schema validation failed: {errors}"
        assert sbom["components"] == []

    def test_serial_number_is_valid_uuid_urn(self):
        import re

        sbom = generate_sbom("x", [])
        assert re.match(
            r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            sbom["serialNumber"],
        )

    def test_purl_format_for_pypi_package(self):
        sbom = generate_sbom("x", [Package(name="Click", version="8.1.0")])
        # PyPI purl names are normalized lowercase with hyphens, per
        # the package-url PyPI-specific rules -- confirmed this
        # matters since pip itself treats "Click"/"click" as the same
        # distribution.
        assert sbom["components"][0]["purl"] == "pkg:pypi/click@8.1.0"

    def test_dependencies_graph_references_all_components(self):
        packages = [Package(name="a", version="1.0"), Package(name="b", version="2.0")]
        sbom = generate_sbom("x", packages)
        root_deps = sbom["dependencies"][0]
        assert root_deps["ref"] == "root-component"
        assert len(root_deps["dependsOn"]) == 2


class TestVulnerabilityCheck:
    """OSV.dev is a real, external, third-party service — tests here
    use an injected fake urlopen function (mocking only the HTTP
    transport, not the request-building/response-parsing logic
    itself), matching the same pattern already used for crt.sh queries
    in the sibling certwatch repo."""

    def test_finds_real_shaped_vulnerability(self):
        class FakeResponse:
            def read(self):
                return json.dumps({
                    "results": [{"vulns": [{
                        "id": "GHSA-xxxx-yyyy-zzzz",
                        "summary": "A test vulnerability",
                        "severity": [{"type": "CVSS_V3", "score": "CRITICAL"}],
                        "references": [{"url": "https://example.com/advisory"}],
                    }]}]
                }).encode()
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False

        def fake_urlopen(req, timeout):
            return FakeResponse()

        findings = check_vulnerabilities(
            [Package(name="vulnerable-pkg", version="1.0.0")], urlopen_fn=fake_urlopen,
        )
        assert len(findings) == 1
        assert findings[0].severity.value == "CRITICAL"
        assert "GHSA-xxxx-yyyy-zzzz" in findings[0].title

    def test_no_vulnerabilities_reports_info(self):
        class FakeResponse:
            def read(self):
                return json.dumps({"results": [{"vulns": []}]}).encode()
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False

        def fake_urlopen(req, timeout):
            return FakeResponse()

        findings = check_vulnerabilities([Package(name="clean-pkg", version="1.0.0")], urlopen_fn=fake_urlopen)
        assert len(findings) == 1
        assert findings[0].severity.value == "INFO"

    def test_empty_package_list_returns_empty_without_network_call(self):
        def fake_urlopen(req, timeout):
            raise AssertionError("should not be called for an empty package list")

        findings = check_vulnerabilities([], urlopen_fn=fake_urlopen)
        assert findings == []

    def test_network_error_raises_osv_query_error(self):
        import urllib.error

        def fake_urlopen(req, timeout):
            raise urllib.error.URLError("simulated network failure")

        with pytest.raises(OSVQueryError, match="Could not query OSV.dev"):
            check_vulnerabilities([Package(name="x", version="1.0")], urlopen_fn=fake_urlopen)
