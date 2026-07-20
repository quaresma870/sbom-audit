"""
Dependency manifest parsing — requirements.txt and pyproject.toml into a
normalized [(name, version, ecosystem), ...] list.

requirements.txt parsing regex adapted directly from the already-proven
pattern in the sibling secureaudit repo's CVE plugin, not rewritten from
scratch.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Package:
    name: str
    version: str
    ecosystem: str = "PyPI"


def _parse_requirements_txt(path: Path) -> list[Package]:
    packages = []
    for line in path.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-", "http")):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(?:==|>=|<=|~=|!=|>|<)\s*([^\s;#,]+)", line)
        if m:
            packages.append(Package(name=m.group(1), version=m.group(2).strip(",")))
    return packages


def _parse_pyproject_toml(path: Path) -> list[Package]:
    """Extracts pinned/minimum versions from [project.dependencies] and
    [project.optional-dependencies] — the standard PEP 621 locations.
    Only entries with an explicit version specifier contribute a
    checkable package (a bare 'requests' with no version constraint at
    all has nothing concrete to look up against OSV.dev)."""
    try:
        data = tomllib.loads(path.read_text(errors="ignore"))
    except tomllib.TOMLDecodeError:
        return []

    project = data.get("project", {})
    raw_deps: list[str] = list(project.get("dependencies", []))
    for extra_deps in project.get("optional-dependencies", {}).values():
        raw_deps.extend(extra_deps)

    packages = []
    for dep in raw_deps:
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(?:==|>=|<=|~=|!=)\s*([^\s;,]+)", dep)
        if m:
            packages.append(Package(name=m.group(1), version=m.group(2).strip(",")))
    return packages


def parse_manifests(project_dir: str | Path) -> list[Package]:
    """Parses every supported manifest file found directly in
    project_dir, returning the union of packages found (a project
    could reasonably have both requirements.txt and pyproject.toml;
    both are checked, not just the first one found)."""
    project_dir = Path(project_dir)
    packages: list[Package] = []

    req_txt = project_dir / "requirements.txt"
    if req_txt.exists():
        packages.extend(_parse_requirements_txt(req_txt))

    pyproject = project_dir / "pyproject.toml"
    if pyproject.exists():
        packages.extend(_parse_pyproject_toml(pyproject))

    return packages
