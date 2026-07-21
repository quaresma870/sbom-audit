from __future__ import annotations

import json

import pytest

from sbom_audit.core.cra_mapping import CRAStatus, map_findings_to_cra
from sbom_audit.core.license_lookup import LicenseResult, check_licenses
from sbom_audit.core.manifest_parser import Package, parse_manifests
from sbom_audit.core.models import Finding, Severity
from sbom_audit.core.provenance_check import ProvenanceStatus, check_provenance
from sbom_audit.core.sbom_generator import generate_sbom
from sbom_audit.core.vuln_check import OSVQueryError, check_vulnerabilities
from sbom_audit.reports.sarif_report import build_sarif


class TestManifestParsing:
    def test_parses_requirements_txt(self, tmp_path):
        (tmp_path / "requirements.txt").write_text(
            "click>=8.1.0\nrich>=13.7.0\n# a comment\npyyaml==6.0.1\n-e .\nhttp://example.com/x.whl\n"
        )
        packages = parse_manifests(tmp_path)
        names = {p.name for p in packages}
        assert names == {"click", "rich", "pyyaml"}

    def test_parsed_packages_track_source_file(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("click>=8.1.0\n")
        (tmp_path / "package.json").write_text('{"dependencies": {"express": "^4.18.2"}}')
        packages = parse_manifests(tmp_path)
        by_name = {p.name: p.source_file for p in packages}
        assert by_name == {"click": "requirements.txt", "express": "package.json"}

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

    def test_parses_poetry_lock(self, tmp_path):
        (tmp_path / "poetry.lock").write_text(
            '[[package]]\nname = "requests"\nversion = "2.31.0"\n'
            'description = "..."\ncategory = "main"\n\n'
            '[[package]]\nname = "urllib3"\nversion = "2.2.1"\n'
        )
        packages = parse_manifests(tmp_path)
        by_name = {p.name: p for p in packages}
        assert by_name["requests"].version == "2.31.0"
        assert by_name["urllib3"].version == "2.2.1"
        assert all(p.ecosystem == "PyPI" for p in packages)

    def test_parses_pdm_lock(self, tmp_path):
        (tmp_path / "pdm.lock").write_text(
            '[[package]]\nname = "click"\nversion = "8.1.7"\nrequires_python = ">=3.7"\n'
        )
        packages = parse_manifests(tmp_path)
        assert {p.name: p.version for p in packages} == {"click": "8.1.7"}

    def test_malformed_toml_lock_does_not_crash(self, tmp_path):
        (tmp_path / "poetry.lock").write_text("this is not [ valid toml")
        (tmp_path / "pdm.lock").write_text("this is not [ valid toml")
        assert parse_manifests(tmp_path) == []

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

    def test_parses_cargo_lock(self, tmp_path):
        (tmp_path / "Cargo.lock").write_text(
            '# This file is automatically @generated by Cargo.\nversion = 3\n\n'
            '[[package]]\nname = "serde"\nversion = "1.0.197"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
            'checksum = "3rd_party_hash"\n\n'
            '[[package]]\nname = "libc"\nversion = "0.2.153"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        )
        packages = parse_manifests(tmp_path)
        by_name = {p.name: p for p in packages}
        assert by_name["serde"].version == "1.0.197"
        assert by_name["libc"].version == "0.2.153"
        assert all(p.ecosystem == "crates.io" for p in packages)

    def test_parses_gemfile_lock(self, tmp_path):
        (tmp_path / "Gemfile.lock").write_text(
            "GEM\n"
            "  remote: https://rubygems.org/\n"
            "  specs:\n"
            "    actionpack (7.0.4)\n"
            "      actionview (= 7.0.4)\n"
            "      rack (~> 2.0)\n"
            "    actionview (7.0.4)\n"
            "    rack (2.2.6.4)\n"
            "\n"
            "PLATFORMS\n"
            "  ruby\n"
            "\n"
            "DEPENDENCIES\n"
            "  actionpack\n"
            "\n"
            "BUNDLED WITH\n"
            "   2.4.6\n"
        )
        packages = parse_manifests(tmp_path)
        by_name = {p.name: p.version for p in packages}
        assert by_name == {"actionpack": "7.0.4", "actionview": "7.0.4", "rack": "2.2.6.4"}
        ecosystems = {p.ecosystem for p in parse_manifests(tmp_path)}
        assert ecosystems == {"RubyGems"}

    def test_gemfile_lock_with_git_and_gem_sections(self, tmp_path):
        (tmp_path / "Gemfile.lock").write_text(
            "GIT\n"
            "  remote: https://github.com/foo/bar.git\n"
            "  revision: abc123\n"
            "  specs:\n"
            "    bar (1.0.0)\n"
            "\n"
            "GEM\n"
            "  remote: https://rubygems.org/\n"
            "  specs:\n"
            "    rails (7.0.4)\n"
            "\n"
            "PLATFORMS\n"
            "  ruby\n"
        )
        packages = parse_manifests(tmp_path)
        names = {p.name for p in packages}
        assert names == {"bar", "rails"}


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

    def test_purl_format_for_crates_io_and_rubygems_packages(self):
        sbom = generate_sbom("x", [
            Package(name="serde", version="1.0.197", ecosystem="crates.io"),
            Package(name="rails", version="7.0.4", ecosystem="RubyGems"),
        ])
        assert sbom["components"][0]["purl"] == "pkg:cargo/serde@1.0.197"
        assert sbom["components"][1]["purl"] == "pkg:gem/rails@7.0.4"

    def test_dependencies_graph_references_all_components(self):
        packages = [Package(name="a", version="1.0"), Package(name="b", version="2.0")]
        sbom = generate_sbom("x", packages)
        root_deps = sbom["dependencies"][0]
        assert root_deps["ref"] == "root-component"
        assert len(root_deps["dependsOn"]) == 2

    def test_license_spdx_id_produces_valid_schema(self):
        from cyclonedx.schema import SchemaVersion
        from cyclonedx.validation.json import JsonStrictValidator

        pkg = Package(name="click", version="8.1.0")
        license_results = [LicenseResult(pkg, spdx_id="BSD-3-Clause", name=None)]
        sbom = generate_sbom("x", [pkg], license_results=license_results)

        assert sbom["components"][0]["licenses"] == [{"license": {"id": "BSD-3-Clause"}}]
        validator = JsonStrictValidator(SchemaVersion.V1_5)
        errors = validator.validate_str(json.dumps(sbom))
        assert not errors, f"Schema validation failed: {errors}"

    def test_license_free_text_name_produces_valid_schema(self):
        from cyclonedx.schema import SchemaVersion
        from cyclonedx.validation.json import JsonStrictValidator

        pkg = Package(name="cryptography", version="42.0.5")
        license_results = [LicenseResult(pkg, spdx_id=None, name="Apache-2.0 OR BSD-3-Clause")]
        sbom = generate_sbom("x", [pkg], license_results=license_results)

        assert sbom["components"][0]["licenses"] == [{"license": {"name": "Apache-2.0 OR BSD-3-Clause"}}]
        validator = JsonStrictValidator(SchemaVersion.V1_5)
        errors = validator.validate_str(json.dumps(sbom))
        assert not errors, f"Schema validation failed: {errors}"

    def test_no_license_result_omits_licenses_field(self):
        pkg = Package(name="click", version="8.1.0")
        sbom = generate_sbom("x", [pkg], license_results=[LicenseResult(pkg, None, None)])
        assert "licenses" not in sbom["components"][0]

    def test_no_license_results_passed_omits_licenses_field(self):
        sbom = generate_sbom("x", [Package(name="click", version="8.1.0")])
        assert "licenses" not in sbom["components"][0]


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


class TestCRAMapping:
    """Only points 1-3 of Annex I Part II are things a manifest scan can
    actually observe; points 4-8 are organizational/process requirements
    and must always report NOT_AUTOMATABLE rather than a guessed status."""

    def test_no_components_flags_attention_needed_on_point_1(self):
        requirements = map_findings_to_cra(component_count=0, findings=[], scanned=False)
        by_point = {r.point: r for r in requirements}
        assert by_point["1"].status == CRAStatus.ATTENTION_NEEDED

    def test_components_present_satisfies_point_1(self):
        requirements = map_findings_to_cra(component_count=5, findings=[], scanned=True)
        by_point = {r.point: r for r in requirements}
        assert by_point["1"].status == CRAStatus.SATISFIED

    def test_critical_finding_flags_attention_needed_on_point_2(self):
        findings = [Finding(module="osv_check", title="x", severity=Severity.CRITICAL, target="pkg==1.0")]
        requirements = map_findings_to_cra(component_count=1, findings=findings, scanned=True)
        by_point = {r.point: r for r in requirements}
        assert by_point["2"].status == CRAStatus.ATTENTION_NEEDED

    def test_only_info_findings_satisfies_point_2(self):
        findings = [Finding(module="osv_check", title="clean", severity=Severity.INFO, target="1 package(s)")]
        requirements = map_findings_to_cra(component_count=1, findings=findings, scanned=True)
        by_point = {r.point: r for r in requirements}
        assert by_point["2"].status == CRAStatus.SATISFIED

    def test_no_scan_flags_attention_needed_on_point_3(self):
        requirements = map_findings_to_cra(component_count=1, findings=[], scanned=False)
        by_point = {r.point: r for r in requirements}
        assert by_point["3"].status == CRAStatus.ATTENTION_NEEDED

    def test_points_4_through_8_are_not_automatable(self):
        requirements = map_findings_to_cra(component_count=5, findings=[], scanned=True)
        by_point = {r.point: r for r in requirements}
        for point in ("4", "5", "6", "7", "8"):
            assert by_point[point].status == CRAStatus.NOT_AUTOMATABLE


class TestProvenanceCheck:
    """Registry attestation queries are mocked at the HTTP transport
    layer only (same pattern as OSV.dev in TestVulnerabilityCheck), not
    at the parsing/decision logic."""

    def test_npm_package_with_attestations_is_attested(self):
        class FakeResponse:
            def read(self):
                return json.dumps({"attestations": [{"predicateType": "https://slsa.dev/provenance/v1"}]}).encode()
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False

        results = check_provenance(
            [Package(name="express", version="4.18.2", ecosystem="npm")],
            urlopen_fn=lambda req, timeout: FakeResponse(),
        )
        assert results[0].status == ProvenanceStatus.ATTESTED

    def test_npm_package_without_attestations_returns_404(self):
        import urllib.error

        def fake_urlopen(req, timeout):
            raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, None)

        results = check_provenance(
            [Package(name="left-pad", version="1.3.0", ecosystem="npm")], urlopen_fn=fake_urlopen,
        )
        assert results[0].status == ProvenanceStatus.NOT_ATTESTED

    def test_npm_network_error_is_check_failed(self):
        import urllib.error

        def fake_urlopen(req, timeout):
            raise urllib.error.URLError("simulated network failure")

        results = check_provenance(
            [Package(name="express", version="4.18.2", ecosystem="npm")], urlopen_fn=fake_urlopen,
        )
        assert results[0].status == ProvenanceStatus.CHECK_FAILED

    def test_pypi_package_with_provenance_is_attested(self):
        class FakeResponse:
            def read(self):
                return json.dumps({"files": [
                    {"filename": "sampleproject-1.0.0-py3-none-any.whl", "provenance": "https://pypi.org/x"},
                    {"filename": "sampleproject-1.0.0.tar.gz", "provenance": "https://pypi.org/y"},
                ]}).encode()
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False

        results = check_provenance(
            [Package(name="sampleproject", version="1.0.0", ecosystem="PyPI")],
            urlopen_fn=lambda req, timeout: FakeResponse(),
        )
        assert results[0].status == ProvenanceStatus.ATTESTED

    def test_pypi_package_without_provenance_is_not_attested(self):
        class FakeResponse:
            def read(self):
                return json.dumps({"files": [
                    {"filename": "requests-2.31.0-py3-none-any.whl", "provenance": None},
                    {"filename": "requests-2.31.0.tar.gz", "provenance": None},
                ]}).encode()
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False

        results = check_provenance(
            [Package(name="requests", version="2.31.0", ecosystem="PyPI")],
            urlopen_fn=lambda req, timeout: FakeResponse(),
        )
        assert results[0].status == ProvenanceStatus.NOT_ATTESTED

    def test_pypi_version_not_in_file_list_is_check_failed(self):
        class FakeResponse:
            def read(self):
                return json.dumps({"files": [
                    {"filename": "requests-2.30.0-py3-none-any.whl", "provenance": None},
                ]}).encode()
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False

        results = check_provenance(
            [Package(name="requests", version="2.31.0", ecosystem="PyPI")],
            urlopen_fn=lambda req, timeout: FakeResponse(),
        )
        assert results[0].status == ProvenanceStatus.CHECK_FAILED

    def test_go_ecosystem_is_unsupported(self):
        results = check_provenance([Package(name="github.com/pkg/errors", version="v0.9.1", ecosystem="Go")])
        assert results[0].status == ProvenanceStatus.UNSUPPORTED_ECOSYSTEM


class TestSarifReport:
    def _finding(self, severity, vuln_id="GHSA-xxxx-yyyy-zzzz", source_file="requirements.txt"):
        return Finding(
            module="osv_check", title=f"{vuln_id} in pkg 1.0", severity=severity, target="pkg==1.0",
            description="A test vulnerability", reference="https://osv.dev/GHSA-xxxx-yyyy-zzzz",
            extra={"vuln_id": vuln_id, "ecosystem": "PyPI", "package": "pkg", "version": "1.0",
                   "source_file": source_file},
        )

    def test_info_findings_excluded_from_results(self):
        info_finding = Finding(module="osv_check", title="clean", severity=Severity.INFO, target="1 package(s)")
        sarif = build_sarif([info_finding])
        assert sarif["runs"][0]["results"] == []

    def test_critical_and_high_map_to_error(self):
        sarif = build_sarif([self._finding(Severity.CRITICAL), self._finding(Severity.HIGH)])
        levels = {r["level"] for r in sarif["runs"][0]["results"]}
        assert levels == {"error"}

    def test_medium_maps_to_warning_and_low_to_note(self):
        sarif = build_sarif([self._finding(Severity.MEDIUM), self._finding(Severity.LOW)])
        levels = [r["level"] for r in sarif["runs"][0]["results"]]
        assert levels == ["warning", "note"]

    def test_location_uses_source_file(self):
        sarif = build_sarif([self._finding(Severity.HIGH, source_file="poetry.lock")])
        location = sarif["runs"][0]["results"][0]["locations"][0]
        assert location["physicalLocation"]["artifactLocation"]["uri"] == "poetry.lock"

    def test_duplicate_vuln_id_produces_one_rule(self):
        sarif = build_sarif([self._finding(Severity.HIGH), self._finding(Severity.HIGH)])
        assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 1
        assert len(sarif["runs"][0]["results"]) == 2

    def test_output_is_valid_sarif_2_1_0_shape(self):
        sarif = build_sarif([self._finding(Severity.CRITICAL)])
        assert sarif["version"] == "2.1.0"
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "sbom-audit"


class TestLicenseLookup:
    """Registry queries are mocked at the HTTP transport layer only,
    same pattern as OSV.dev/provenance-check."""

    class _FakeResponse:
        def __init__(self, payload):
            self._payload = payload
        def read(self):
            return json.dumps(self._payload).encode()
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    def test_pypi_known_spdx_id_in_license_field(self):
        results = check_licenses(
            [Package(name="click", version="8.1.7", ecosystem="PyPI")],
            urlopen_fn=lambda req, timeout: self._FakeResponse({"info": {"license": "BSD-3-Clause"}}),
        )
        assert results[0].spdx_id == "BSD-3-Clause"
        assert results[0].name is None

    def test_pypi_non_spdx_license_field_becomes_free_text_name(self):
        results = check_licenses(
            [Package(name="requests", version="2.31.0", ecosystem="PyPI")],
            urlopen_fn=lambda req, timeout: self._FakeResponse({"info": {"license": "Apache 2.0"}}),
        )
        assert results[0].spdx_id is None
        assert results[0].name == "Apache 2.0"

    def test_pypi_oversized_license_text_falls_back_to_classifier(self):
        huge_text = "x" * 500
        results = check_licenses(
            [Package(name="numpy", version="1.26.4", ecosystem="PyPI")],
            urlopen_fn=lambda req, timeout: self._FakeResponse({
                "info": {
                    "license": huge_text,
                    "classifiers": ["License :: OSI Approved :: BSD License"],
                }
            }),
        )
        assert results[0].spdx_id is None
        assert results[0].name == "BSD License"

    def test_pypi_no_license_data_returns_none(self):
        results = check_licenses(
            [Package(name="x", version="1.0", ecosystem="PyPI")],
            urlopen_fn=lambda req, timeout: self._FakeResponse({"info": {}}),
        )
        assert results[0].spdx_id is None
        assert results[0].name is None

    def test_pypi_network_error_returns_none_without_crashing(self):
        import urllib.error

        def fake_urlopen(req, timeout):
            raise urllib.error.URLError("simulated network failure")

        results = check_licenses(
            [Package(name="x", version="1.0", ecosystem="PyPI")], urlopen_fn=fake_urlopen,
        )
        assert results[0].spdx_id is None
        assert results[0].name is None

    def test_npm_string_license_field(self):
        results = check_licenses(
            [Package(name="express", version="4.18.2", ecosystem="npm")],
            urlopen_fn=lambda req, timeout: self._FakeResponse({"license": "MIT"}),
        )
        assert results[0].spdx_id == "MIT"

    def test_npm_legacy_object_license_field(self):
        results = check_licenses(
            [Package(name="old-pkg", version="1.0.0", ecosystem="npm")],
            urlopen_fn=lambda req, timeout: self._FakeResponse({"license": {"type": "MIT", "url": "https://x"}}),
        )
        assert results[0].spdx_id == "MIT"

    def test_go_ecosystem_skips_network_call(self):
        def fake_urlopen(req, timeout):
            raise AssertionError("should not be called for an unsupported ecosystem")

        results = check_licenses(
            [Package(name="github.com/pkg/errors", version="v0.9.1", ecosystem="Go")], urlopen_fn=fake_urlopen,
        )
        assert results[0].spdx_id is None
        assert results[0].name is None
