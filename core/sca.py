"""
Offline-first software composition analysis (SCA).

Dependencies are read from lockfiles/manifests and matched against OSV data.
The default mode is fully offline: load a JSON snapshot and never touch the
network.  ``online=True`` performs the public OSV.dev batch query, which needs
no API key.  Network failures become warnings so a scan still completes.
"""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.dep_graph import _read_text, _repo_files
from core.scanner import Finding

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"
DEFAULT_SNAPSHOT = ".commit_guard_osv.json"

_VERSION_RE = re.compile(r"^v?[0-9][0-9A-Za-z.+!_-]*$")
_EXACT_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[^\]]*\])?\s*===?\s*"
    r"(?P<version>[^\s;,]+)"
)
_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "moderate": "medium",
    "medium": "medium",
    "low": "low",
    "info": "info",
}


class SCAError(RuntimeError):
    """Raised when dependency or advisory data cannot be loaded."""


@dataclass(frozen=True)
class Package:
    ecosystem: str
    name: str
    version: str
    manifest: str

    @property
    def key(self) -> str:
        return f"{self.ecosystem}:{self.name}@{self.version}"


@dataclass(frozen=True)
class Vulnerability:
    id: str
    aliases: tuple[str, ...]
    summary: str
    severity: str
    package_name: str
    ecosystem: str
    version: str
    fixed_versions: tuple[str, ...]
    advisory_url: str
    manifest: str

    @property
    def label(self) -> str:
        return f"{self.package_name} {self.version}"

    def to_finding(self) -> Finding:
        aliases = tuple(alias for alias in self.aliases if alias != self.id)
        fixed = (
            " Fixed in " + ", ".join(self.fixed_versions) + "."
            if self.fixed_versions
            else ""
        )
        alias_text = f" ({', '.join(aliases)})" if aliases else ""
        description = (
            f"Vulnerable dependency {self.package_name} {self.version} "
            f"is affected by {self.id}{alias_text}.{fixed} {self.summary}"
        ).strip()
        digest = hashlib.sha256(
            f"sca\0{self.id}\0{self.manifest}\0{self.package_name}\0{self.version}".encode()
        ).hexdigest()[:16]
        return Finding(
            file=self.manifest,
            line_number=1,
            rule_id=f"sca-{self.id}",
            description=description,
            severity=self.severity,
            source="sca",
            flagged_code=f"{self.package_name}=={self.version}",
            redacted_code=f"{self.package_name}=={self.version}",
            fingerprint=digest,
            tags=("sca", "dependency", self.ecosystem.lower()),
            cwe="CWE-1104",
            fixed_versions=self.fixed_versions,
            aliases=aliases,
            advisory_url=self.advisory_url,
        )


@dataclass(frozen=True)
class SCAResult:
    packages: tuple[Package, ...]
    vulnerabilities: tuple[Vulnerability, ...]
    warnings: tuple[str, ...] = ()
    mode: str = "offline"

    @property
    def package_names(self) -> set[str]:
        return {vulnerability.package_name for vulnerability in self.vulnerabilities}

    def to_findings(self) -> list[Finding]:
        return [vulnerability.to_finding() for vulnerability in self.vulnerabilities]


def _clean_version(raw: str) -> str | None:
    version = raw.strip().strip("\"'")
    version = version.removeprefix("==")
    if version.startswith("v") and version[1:2].isdigit():
        version = version.removeprefix("v")
    version = version.split(";", 1)[0].strip()
    if not version or any(char in version for char in "<>~^*{}"):
        return None
    if any(part.lower() == "x" for part in version.split(".")):
        return None
    return version if _VERSION_RE.match(version) else None


def _add(
    found: list[Package],
    seen: set[tuple[str, str, str, str]],
    ecosystem: str,
    name: str,
    version: str | None,
    manifest: str,
) -> None:
    if not name or not version:
        return
    name = name.strip()
    cleaned = _clean_version(version)
    if not name or not cleaned:
        return
    key = (ecosystem, name, cleaned, manifest)
    if key in seen:
        return
    seen.add(key)
    found.append(Package(ecosystem, name, cleaned, manifest))


def _parse_requirements(path: str, text: str, found: list[Package], seen: set) -> None:
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip().replace("\\", " ")
        if not line or line.startswith(("-", "git+", "http:", "https:", "file:")):
            continue
        match = _EXACT_RE.match(line)
        if match:
            _add(found, seen, "PyPI", match.group("name"), match.group("version"), path)


def _parse_pyproject(path: str, text: str, found: list[Package], seen: set) -> None:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return
    project = data.get("project")
    if isinstance(project, dict):
        dependencies = project.get("dependencies")
        groups = [dependencies] if isinstance(dependencies, list) else []
        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            groups.extend(value for value in optional.values() if isinstance(value, list))
        for group in groups:
            for entry in group:
                if not isinstance(entry, str):
                    continue
                match = _EXACT_RE.match(entry)
                if match:
                    _add(found, seen, "PyPI", match.group("name"), match.group("version"), path)
    poetry = ((data.get("tool") or {}).get("poetry") or {})
    if isinstance(poetry, dict):
        for section in ("dependencies", "dev-dependencies"):
            dependencies = poetry.get(section)
            if not isinstance(dependencies, dict):
                continue
            for name, value in dependencies.items():
                if name.lower() == "python":
                    continue
                version = value.get("version") if isinstance(value, dict) else value
                if isinstance(version, str) and _VERSION_RE.match(version.strip().lstrip("^~")):
                    _add(found, seen, "PyPI", str(name), version, path)


def _parse_pipfile_lock(path: str, text: str, found: list[Package], seen: set) -> None:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return
    for section in ("default", "develop"):
        entries = data.get(section)
        if not isinstance(entries, dict):
            continue
        for name, metadata in entries.items():
            version = metadata.get("version") if isinstance(metadata, dict) else None
            if isinstance(version, str):
                _add(found, seen, "PyPI", name, version, path)


def _parse_poetry_lock(path: str, text: str, found: list[Package], seen: set) -> None:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return
    for entry in data.get("package", []):
        if isinstance(entry, dict):
            _add(
                found,
                seen,
                "PyPI",
                str(entry.get("name", "")),
                str(entry.get("version", "")),
                path,
            )


def _walk_npm_dependencies(
    dependencies: dict,
    path: str,
    found: list[Package],
    seen: set,
) -> None:
    for name, metadata in dependencies.items():
        if not isinstance(metadata, dict):
            continue
        _add(found, seen, "npm", str(name), metadata.get("version"), path)
        nested = metadata.get("dependencies")
        if isinstance(nested, dict):
            _walk_npm_dependencies(nested, path, found, seen)


def _parse_package_lock(path: str, text: str, found: list[Package], seen: set) -> None:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return
    packages = data.get("packages")
    if isinstance(packages, dict):
        for location, metadata in packages.items():
            if not location or not isinstance(metadata, dict) or metadata.get("link"):
                continue
            name = location.rsplit("node_modules/", 1)[-1]
            if name and "/" in name and not name.startswith("@"):
                name = name.rsplit("/", 1)[-1]
            _add(found, seen, "npm", name, metadata.get("version"), path)
    dependencies = data.get("dependencies")
    if isinstance(dependencies, dict):
        _walk_npm_dependencies(dependencies, path, found, seen)


def _parse_package_json(path: str, text: str, found: list[Package], seen: set) -> None:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return
    for section in (
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ):
        dependencies = data.get(section)
        if not isinstance(dependencies, dict):
            continue
        for name, version in dependencies.items():
            if isinstance(version, str):
                _add(found, seen, "npm", str(name), version, path)


def _parse_go_mod(path: str, text: str, found: list[Package], seen: set) -> None:
    blocks = re.findall(r"require\s*\((.*?)\)", text, re.DOTALL)
    blocks.append(
        "\n".join(
            line
            for line in text.splitlines()
            if re.match(r"^\s*require\s+\S+\s+v", line)
        )
    )
    for block in blocks:
        for line in block.splitlines():
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            match = re.match(r"^(\S+)\s+(v\S+)", line)
            if match:
                _add(found, seen, "Go", match.group(1), match.group(2), path)


def _parse_cargo_lock(path: str, text: str, found: list[Package], seen: set) -> None:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return
    for entry in data.get("package", []):
        if isinstance(entry, dict):
            _add(
                found,
                seen,
                "crates.io",
                str(entry.get("name", "")),
                str(entry.get("version", "")),
                path,
            )


def _parse_cargo_toml(path: str, text: str, found: list[Package], seen: set) -> None:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return
    sections = [data]
    workspace = data.get("workspace")
    if isinstance(workspace, dict):
        sections.append(workspace)
    for section in sections:
        for key in ("dependencies", "dev-dependencies", "build-dependencies"):
            dependencies = section.get(key)
            if not isinstance(dependencies, dict):
                continue
            for name, value in dependencies.items():
                version = value.get("version") if isinstance(value, dict) else value
                if isinstance(version, str):
                    _add(found, seen, "crates.io", str(name), version, path)


def _parse_gemfile_lock(path: str, text: str, found: list[Package], seen: set) -> None:
    in_specs = False
    for line in text.splitlines():
        if line.strip() == "specs:":
            in_specs = True
            continue
        if in_specs and line and not line.startswith(" "):
            in_specs = False
        if not in_specs:
            continue
        match = re.match(r"^\s{4}([A-Za-z0-9_.-]+) \(([^)]+)\)", line)
        if match:
            _add(found, seen, "RubyGems", match.group(1), match.group(2), path)


def _parse_composer_lock(path: str, text: str, found: list[Package], seen: set) -> None:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return
    for section in ("packages", "packages-dev"):
        packages = data.get(section)
        if not isinstance(packages, list):
            continue
        for entry in packages:
            if isinstance(entry, dict):
                _add(
                    found,
                    seen,
                    "Packagist",
                    str(entry.get("name", "")),
                    str(entry.get("version", "")),
                    path,
                )


def _parse_pom(path: str, text: str, found: list[Package], seen: set) -> None:
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return
    for dependency in root.iter():
        if dependency.tag.rsplit("}", 1)[-1] != "dependency":
            continue
        fields: dict[str, str] = {}
        for child in dependency:
            fields[child.tag.rsplit("}", 1)[-1]] = (child.text or "").strip()
        if fields.get("scope") == "provided":
            continue
        name = f"{fields.get('groupId', '')}:{fields.get('artifactId', '')}".strip(":")
        _add(found, seen, "Maven", name, fields.get("version"), path)


def _parse_gradle_lock(path: str, text: str, found: list[Package], seen: set) -> None:
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("empty="):
            continue
        coordinate = line.split("=", 1)[0]
        parts = coordinate.split(":")
        if len(parts) >= 3:
            _add(found, seen, "Maven", f"{parts[0]}:{parts[1]}", parts[2], path)


def _parse_yarn_lock(path: str, text: str, found: list[Package], seen: set) -> None:
    current: str | None = None
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" ") and line.rstrip().endswith(":"):
            spec = line.rstrip()[:-1].strip().strip('"')
            first = spec.split(",", 1)[0].strip().strip('"')
            current = first.rsplit("@", 1)[0] if "@" in first[1:] else first
        elif current and line.strip().startswith("version "):
            version = line.strip().split(" ", 1)[1].strip().strip('"')
            _add(found, seen, "npm", current, version, path)
            current = None


def _parse_packages_config(path: str, text: str, found: list[Package], seen: set) -> None:
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return
    for package in root.iter():
        if package.tag.rsplit("}", 1)[-1] != "package":
            continue
        _add(
            found,
            seen,
            "NuGet",
            package.attrib.get("id", ""),
            package.attrib.get("version"),
            path,
        )


def collect_packages(repo_root: Path) -> tuple[Package, ...]:
    """Reads exact dependency versions from supported manifests and lockfiles."""
    root = Path(repo_root).resolve()
    found: list[Package] = []
    seen: set[tuple[str, str, str, str]] = set()
    for path in _repo_files(root):
        name = Path(path).name
        lower = name.lower()
        if not (
            lower.startswith("requirements") and lower.endswith(".txt")
            or lower in {
                "pyproject.toml",
                "pipfile.lock",
                "poetry.lock",
                "package-lock.json",
                "npm-shrinkwrap.json",
                "package.json",
                "go.mod",
                "cargo.lock",
                "cargo.toml",
                "gemfile.lock",
                "composer.lock",
                "pom.xml",
                "gradle.lockfile",
                "yarn.lock",
                "packages.config",
            }
        ):
            continue
        text = _read_text(root / path)
        if text is None:
            continue
        if lower.startswith("requirements"):
            _parse_requirements(path, text, found, seen)
        elif lower == "pyproject.toml":
            _parse_pyproject(path, text, found, seen)
        elif lower == "pipfile.lock":
            _parse_pipfile_lock(path, text, found, seen)
        elif lower == "poetry.lock":
            _parse_poetry_lock(path, text, found, seen)
        elif lower in {"package-lock.json", "npm-shrinkwrap.json"}:
            _parse_package_lock(path, text, found, seen)
        elif lower == "package.json":
            _parse_package_json(path, text, found, seen)
        elif lower == "go.mod":
            _parse_go_mod(path, text, found, seen)
        elif lower == "cargo.lock":
            _parse_cargo_lock(path, text, found, seen)
        elif lower == "cargo.toml":
            _parse_cargo_toml(path, text, found, seen)
        elif lower == "gemfile.lock":
            _parse_gemfile_lock(path, text, found, seen)
        elif lower == "composer.lock":
            _parse_composer_lock(path, text, found, seen)
        elif lower == "pom.xml":
            _parse_pom(path, text, found, seen)
        elif lower == "gradle.lockfile":
            _parse_gradle_lock(path, text, found, seen)
        elif lower == "yarn.lock":
            _parse_yarn_lock(path, text, found, seen)
        elif lower == "packages.config":
            _parse_packages_config(path, text, found, seen)
    return tuple(sorted(found, key=lambda item: (item.ecosystem, item.name, item.version, item.manifest)))


def _version_tokens(version: str) -> tuple:
    return tuple(
        int(part) if part.isdigit() else part.lower()
        for part in re.findall(r"\d+|[A-Za-z]+", version)
    )


def _version_cmp(left: str, right: str) -> int:
    left_tokens = _version_tokens(left)
    right_tokens = _version_tokens(right)
    for index in range(max(len(left_tokens), len(right_tokens))):
        left_part = left_tokens[index] if index < len(left_tokens) else 0
        right_part = right_tokens[index] if index < len(right_tokens) else 0
        if left_part == right_part:
            continue
        if isinstance(left_part, int) and isinstance(right_part, int):
            return -1 if left_part < right_part else 1
        left_text = str(left_part)
        right_text = str(right_part)
        return -1 if left_text < right_text else 1
    return 0


def _is_affected(version: str, affected: dict) -> bool:
    if version in {str(item) for item in affected.get("versions", [])}:
        return True
    for range_entry in affected.get("ranges", []):
        if not isinstance(range_entry, dict):
            continue
        vulnerable = False
        for event in range_entry.get("events", []):
            if not isinstance(event, dict):
                continue
            introduced = event.get("introduced")
            fixed = event.get("fixed")
            last_affected = event.get("last_affected")
            if isinstance(introduced, str):
                vulnerable = introduced == "0" or _version_cmp(version, introduced) >= 0
            if vulnerable and isinstance(fixed, str) and _version_cmp(version, fixed) >= 0:
                vulnerable = False
            if vulnerable and isinstance(last_affected, str) and _version_cmp(version, last_affected) > 0:
                vulnerable = False
        if vulnerable:
            return True
    return False


def _matches_package(vulnerability: dict, package: Package) -> bool:
    affected = vulnerability.get("affected")
    if isinstance(affected, list):
        for entry in affected:
            if not isinstance(entry, dict):
                continue
            package_data = entry.get("package") or {}
            ecosystem = str(package_data.get("ecosystem", ""))
            name = str(package_data.get("name", ""))
            if ecosystem and ecosystem != package.ecosystem:
                continue
            if name and name.lower() != package.name.lower():
                continue
            if _is_affected(package.version, entry):
                return True
        return False
    package_data = vulnerability.get("package") or {}
    ecosystem = str(package_data.get("ecosystem", ""))
    name = str(package_data.get("name", ""))
    return (
        (not ecosystem or ecosystem == package.ecosystem)
        and bool(name)
        and name.lower() == package.name.lower()
    )


def _severity(vulnerability: dict) -> str:
    database = vulnerability.get("database_specific") or {}
    severity = str(database.get("severity", "")).lower()
    if severity in _SEVERITY_MAP:
        return _SEVERITY_MAP[severity]
    return "high"


def _fixed_versions(vulnerability: dict, package: Package) -> tuple[str, ...]:
    fixed: set[str] = set()
    for affected in vulnerability.get("affected", []):
        if not isinstance(affected, dict):
            continue
        name = str((affected.get("package") or {}).get("name", ""))
        if name and name.lower() != package.name.lower():
            continue
        database = affected.get("database_specific") or {}
        direct = database.get("fixed_version")
        if isinstance(direct, str):
            fixed.add(direct)
        for range_entry in affected.get("ranges", []):
            if not isinstance(range_entry, dict):
                continue
            for event in range_entry.get("events", []):
                if isinstance(event, dict) and isinstance(event.get("fixed"), str):
                    fixed.add(event["fixed"])
    return tuple(sorted(fixed, key=_version_tokens))


def _advisory_url(vulnerability_id: str, aliases: tuple[str, ...]) -> str:
    for alias in aliases:
        if alias.startswith("GHSA-"):
            return f"https://github.com/advisories/{alias}"
    return f"https://osv.dev/vulnerability/{vulnerability_id}"


def _to_vulnerability(raw: dict, package: Package) -> Vulnerability:
    vuln_id = str(raw.get("id", "OSV-unknown"))
    aliases = tuple(str(alias) for alias in raw.get("aliases", []) if alias)
    summary = str(raw.get("summary") or raw.get("details") or "Known vulnerable dependency.")
    summary = " ".join(summary.split())
    if len(summary) > 400:
        summary = summary[:397] + "…"
    return Vulnerability(
        id=vuln_id,
        aliases=aliases,
        summary=summary,
        severity=_severity(raw),
        package_name=package.name,
        ecosystem=package.ecosystem,
        version=package.version,
        fixed_versions=_fixed_versions(raw, package),
        advisory_url=_advisory_url(vuln_id, aliases),
        manifest=package.manifest,
    )


def _load_snapshot(path: Path) -> dict[str, list[dict]] | list[dict]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SCAError(f"Could not read OSV snapshot '{path}': {exc}") from exc
    if isinstance(data, dict) and isinstance(data.get("packages"), dict):
        return {
            str(key): [entry for entry in value if isinstance(entry, dict)]
            for key, value in data["packages"].items()
            if isinstance(value, list)
        }
    if isinstance(data, dict) and isinstance(data.get("vulnerabilities"), list):
        return [entry for entry in data["vulnerabilities"] if isinstance(entry, dict)]
    if isinstance(data, list):
        return [entry for entry in data if isinstance(entry, dict)]
    raise SCAError(
        "OSV snapshot must be a vulnerability list or an object with "
        "'vulnerabilities' or 'packages'."
    )


class OSVClient:
    def __init__(
        self,
        *,
        batch_url: str = OSV_BATCH_URL,
        vuln_url: str = OSV_VULN_URL,
        timeout: int = 20,
    ) -> None:
        self.batch_url = batch_url
        self.vuln_url = vuln_url.rstrip("/")
        self.timeout = timeout

    def _request(self, url: str, payload: dict | None = None) -> Any:
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {
            "Accept": "application/json",
            "User-Agent": "CommitGuard/2",
        }
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = response.read()
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
            raise SCAError(f"OSV request failed: {exc}") from exc
        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            raise SCAError("OSV returned a non-JSON response.") from exc

    def query(self, packages: tuple[Package, ...]) -> dict[str, list[dict]]:
        results: dict[str, list[dict]] = {}
        details: dict[str, dict] = {}
        for start in range(0, len(packages), 1000):
            chunk = packages[start : start + 1000]
            payload = {
                "queries": [
                    {
                        "package": {
                            "name": package.name,
                            "ecosystem": package.ecosystem,
                        },
                        "version": package.version,
                    }
                    for package in chunk
                ]
            }
            response = self._request(self.batch_url, payload)
            batch_results = response.get("results", []) if isinstance(response, dict) else []
            for package, item in zip(chunk, batch_results, strict=False):
                raw_vulns = item.get("vulns", []) if isinstance(item, dict) else []
                package_vulns: list[dict] = []
                for raw in raw_vulns:
                    if not isinstance(raw, dict):
                        continue
                    vuln_id = str(raw.get("id", ""))
                    if not vuln_id:
                        continue
                    if "affected" not in raw:
                        if vuln_id not in details:
                            details[vuln_id] = self._request(
                                f"{self.vuln_url}/{urllib.parse.quote(vuln_id, safe='')}"
                            )
                        raw = details[vuln_id]
                    if _matches_package(raw, package):
                        package_vulns.append(raw)
                if package_vulns:
                    results[package.key] = package_vulns
        return results


def scan_dependencies(
    repo_root: Path,
    *,
    online: bool = False,
    snapshot_path: Path | None = None,
    timeout: int = 20,
) -> SCAResult:
    """Collects packages and returns matched vulnerabilities; never raises for I/O."""
    packages = collect_packages(repo_root)
    warnings: list[str] = []
    if not packages:
        return SCAResult(packages=(), vulnerabilities=(), warnings=("No pinned dependencies found.",))
    mapping: dict[str, list[dict]] = {}
    mode = "online" if online else "offline"
    if online:
        try:
            mapping = OSVClient(timeout=timeout).query(packages)
        except SCAError as exc:
            warnings.append(str(exc))
    else:
        path = snapshot_path or (Path(repo_root) / DEFAULT_SNAPSHOT)
        path = Path(path)
        if not path.is_file():
            warnings.append(
                f"No OSV snapshot at {path}; SCA skipped (run with --sca-online or provide --sca-snapshot)."
            )
            return SCAResult(packages=packages, vulnerabilities=(), warnings=tuple(warnings))
        try:
            snapshot = _load_snapshot(path)
        except SCAError as exc:
            return SCAResult(packages=packages, vulnerabilities=(), warnings=(str(exc),))
        if isinstance(snapshot, dict):
            mapping = snapshot
        else:
            for package in packages:
                matches = [
                    raw for raw in snapshot if _matches_package(raw, package)
                ]
                if matches:
                    mapping[package.key] = matches

    vulnerabilities: list[Vulnerability] = []
    by_key = {package.key: package for package in packages}
    for key, raw_vulns in mapping.items():
        package = by_key.get(key)
        if package is None:
            continue
        for raw in raw_vulns:
            if _matches_package(raw, package):
                vulnerabilities.append(_to_vulnerability(raw, package))
    unique: dict[tuple[str, str, str], Vulnerability] = {}
    for vulnerability in vulnerabilities:
        unique[(vulnerability.id, vulnerability.package_name, vulnerability.version)] = vulnerability
    return SCAResult(
        packages=packages,
        vulnerabilities=tuple(sorted(unique.values(), key=lambda item: (item.package_name, item.id))),
        warnings=tuple(warnings),
        mode=mode,
    )
