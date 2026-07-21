"""
Dependency manifest parsing — requirements.txt/pyproject.toml/
poetry.lock/pdm.lock (Python), package.json/package-lock.json (npm),
and go.mod/go.sum (Go) into a normalized
[(name, version, ecosystem), ...] list.

requirements.txt parsing regex adapted directly from the already-proven
pattern in the sibling secureaudit repo's CVE plugin, not rewritten from
scratch.
"""

from __future__ import annotations

import json
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


def _parse_package_json(path: Path) -> list[Package]:
    """Extracts version specifiers from dependencies/devDependencies/
    optionalDependencies — the standard package.json locations. Only
    specifiers that start with a concrete version number contribute a
    checkable package; "*", "latest", "git+https://...", "file:../x",
    and "workspace:*" have nothing concrete to look up against OSV.dev."""
    try:
        data = json.loads(path.read_text(errors="ignore"))
    except json.JSONDecodeError:
        return []

    raw_deps: dict[str, str] = {}
    for key in ("dependencies", "devDependencies", "optionalDependencies"):
        raw_deps.update(data.get(key) or {})

    packages = []
    for name, spec in raw_deps.items():
        m = re.match(r"^(?:\^|~|>=|<=|>|<|=)*\s*(\d[\w.\-]*)", spec.strip())
        if m:
            packages.append(Package(name=name, version=m.group(1), ecosystem="npm"))
    return packages


def _parse_package_lock_json(path: Path) -> list[Package]:
    """Extracts exact resolved versions from package-lock.json. Handles
    both the current lockfile format (lockfileVersion 2/3, a flat
    "packages" map keyed by node_modules path) and the legacy
    lockfileVersion 1 format (a nested "dependencies" tree)."""
    try:
        data = json.loads(path.read_text(errors="ignore"))
    except json.JSONDecodeError:
        return []

    if "packages" in data:
        packages = []
        for pkg_path, info in data["packages"].items():
            if not pkg_path or "version" not in info:
                continue
            name = pkg_path.rsplit("node_modules/", 1)[-1]
            packages.append(Package(name=name, version=info["version"], ecosystem="npm"))
        return packages

    return _walk_lockfile_v1_deps(data.get("dependencies") or {})


def _walk_lockfile_v1_deps(deps: dict) -> list[Package]:
    packages = []
    for name, info in deps.items():
        version = info.get("version")
        if version:
            packages.append(Package(name=name, version=version, ecosystem="npm"))
        nested = info.get("dependencies")
        if nested:
            packages.extend(_walk_lockfile_v1_deps(nested))
    return packages


def _parse_toml_lock(path: Path) -> list[Package]:
    """Shared parser for poetry.lock and pdm.lock — both use the same
    [[package]] array-of-tables TOML structure with name/version keys,
    giving exact resolved versions rather than requirements.txt/
    pyproject.toml's declared constraints."""
    try:
        data = tomllib.loads(path.read_text(errors="ignore"))
    except tomllib.TOMLDecodeError:
        return []

    packages = []
    for pkg in data.get("package", []):
        name, version = pkg.get("name"), pkg.get("version")
        if name and version:
            packages.append(Package(name=name, version=version))
    return packages


def _parse_go_mod(path: Path) -> list[Package]:
    """Parses require directives — both the block form (`require (...)`)
    and single-line form (`require module version`). Unlike Python/npm
    version ranges, go.mod versions are already exact (Go's Minimal
    Version Selection has no concept of a range specifier)."""
    packages = []
    in_block = False
    for line in path.read_text(errors="ignore").splitlines():
        stripped = line.strip()
        if stripped.startswith("require") and stripped.endswith("("):
            in_block = True
            continue
        if in_block:
            if stripped.startswith(")"):
                in_block = False
                continue
            m = re.match(r"^(\S+)\s+(v\S+)", stripped)
        else:
            m = re.match(r"^require\s+(\S+)\s+(v\S+)", stripped)
        if m:
            packages.append(Package(name=m.group(1), version=m.group(2), ecosystem="Go"))
    return packages


def _parse_go_sum(path: Path) -> list[Package]:
    """Parses go.sum for exact resolved module versions. Each module
    normally appears twice (once for the module zip, once for its
    /go.mod file) — only the module-zip line is kept, so a module
    doesn't get queried against OSV.dev twice."""
    packages = []
    seen = set()
    for line in path.read_text(errors="ignore").splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        module, version = parts[0], parts[1]
        if version.endswith("/go.mod"):
            continue
        if (module, version) in seen:
            continue
        seen.add((module, version))
        packages.append(Package(name=module, version=version, ecosystem="Go"))
    return packages


def parse_manifests(project_dir: str | Path) -> list[Package]:
    """Parses every supported manifest file found directly in
    project_dir, returning the union of packages found (a project
    could reasonably have manifests from more than one ecosystem, or
    more than one manifest within the same ecosystem; all are checked,
    not just the first one found)."""
    project_dir = Path(project_dir)
    packages: list[Package] = []

    req_txt = project_dir / "requirements.txt"
    if req_txt.exists():
        packages.extend(_parse_requirements_txt(req_txt))

    pyproject = project_dir / "pyproject.toml"
    if pyproject.exists():
        packages.extend(_parse_pyproject_toml(pyproject))

    poetry_lock = project_dir / "poetry.lock"
    if poetry_lock.exists():
        packages.extend(_parse_toml_lock(poetry_lock))

    pdm_lock = project_dir / "pdm.lock"
    if pdm_lock.exists():
        packages.extend(_parse_toml_lock(pdm_lock))

    package_json = project_dir / "package.json"
    if package_json.exists():
        packages.extend(_parse_package_json(package_json))

    package_lock = project_dir / "package-lock.json"
    if package_lock.exists():
        packages.extend(_parse_package_lock_json(package_lock))

    go_mod = project_dir / "go.mod"
    if go_mod.exists():
        packages.extend(_parse_go_mod(go_mod))

    go_sum = project_dir / "go.sum"
    if go_sum.exists():
        packages.extend(_parse_go_sum(go_sum))

    return packages
