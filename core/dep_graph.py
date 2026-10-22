"""
Dependency and blast-radius graph construction.

The graph is intentionally file-oriented and dependency-light: Python uses
``ast`` while other languages use conservative import/require parsers.  Every
edge points from an importer to the imported repo file, so reverse traversal
answers "which files are exposed if this file is compromised?".
"""

from __future__ import annotations

import ast
import json
import re
import subprocess
import tomllib
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

_MAX_FILE_BYTES = 2 * 1024 * 1024
_MAX_FILES = 5000
_MAX_GRAPH_NODES = 250

_LANGUAGE_BY_SUFFIX = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".vue": "vue",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".rb": "ruby",
    ".php": "php",
}

_JS_IMPORT_RE = re.compile(
    r"""(?:
        \bimport\s+(?:[^'";]+?\s+from\s+)?['"](?P<import>[^'"]+)['"]
      | \bexport\s+[^'";]+?\s+from\s+['"](?P<export>[^'"]+)['"]
      | \brequire\s*\(\s*['"](?P<require>[^'"]+)['"]\s*\)
      | \bimport\s*\(\s*['"](?P<dynamic>[^'"]+)['"]\s*\)
    )""",
    re.VERBOSE,
)
_GO_IMPORT_SINGLE_RE = re.compile(r'^\s*import\s+(?:[\w.]+\s+)?["`]([^"`]+)["`]', re.MULTILINE)
_GO_IMPORT_BLOCK_RE = re.compile(r"^\s*import\s*\((.*?)\)", re.MULTILINE | re.DOTALL)
_GO_IMPORT_LINE_RE = re.compile(r'(?:[\w.]+\s+)?["`]([^"`]+)["`]')
_RS_MOD_RE = re.compile(r"^\s*(?:pub\s+)?mod\s+([A-Za-z_]\w*)\s*;", re.MULTILINE)
_RS_USE_RE = re.compile(r"^\s*(?:pub\s+)?use\s+([^;]+);", re.MULTILINE)
_JAVA_PACKAGE_RE = re.compile(r"^\s*package\s+([\w.]+)\s*;", re.MULTILINE)
_JAVA_IMPORT_RE = re.compile(r"^\s*import\s+(?:static\s+)?([\w.]+)(?:\.\*)?\s*;", re.MULTILINE)
_RUBY_REQUIRE_RE = re.compile(
    r"""^\s*require(?P<relative>_relative)?\s*\(?\s*['"]([^'"]+)['"]""",
    re.MULTILINE,
)
_PHP_REQUIRE_RE = re.compile(
    r"""\b(?:require|include)(?:_once)?\s*\(?\s*['"]([^'"]+)['"]""",
    re.MULTILINE,
)

_MANIFEST_NAMES = {"requirements.txt", "package.json", "go.mod", "Cargo.toml"}


@dataclass(frozen=True)
class DependencyNode:
    path: str
    language: str
    imports: tuple[str, ...] = ()
    external: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()


@dataclass
class DependencyGraph:
    nodes: dict[str, DependencyNode] = field(default_factory=dict)
    reverse: dict[str, set[str]] = field(default_factory=dict)

    def dependents(self, path: str, max_depth: int | None = None) -> tuple[str, ...]:
        """Returns transitive importers of ``path`` using reverse edges."""
        seen: set[str] = set()
        queue: deque[tuple[str, int]] = deque([(path, 0)])
        while queue:
            current, depth = queue.popleft()
            if max_depth is not None and depth >= max_depth:
                continue
            for parent in sorted(self.reverse.get(current, ())):
                if parent == path or parent in seen:
                    continue
                seen.add(parent)
                queue.append((parent, depth + 1))
        return tuple(sorted(seen))

    def blast_radius(self) -> dict[str, dict[str, object]]:
        return {
            path: {
                "count": len(dependents),
                "dependents": list(dependents),
            }
            for path in sorted(self.nodes)
            if (dependents := self.dependents(path))
        }

    def to_json(
        self,
        *,
        vulnerable_files: set[str] | None = None,
        vulnerable_packages: set[str] | None = None,
    ) -> str:
        vulnerable_files = vulnerable_files or set()
        vulnerable_packages = vulnerable_packages or set()
        payload = {
            "schema_version": 1,
            "tool": {"name": "CommitGuard"},
            "nodes": [
                {
                    "path": node.path,
                    "language": node.language,
                    "imports": list(node.imports),
                    "external": list(node.external),
                    "dependencies": list(node.dependencies),
                    "vulnerable": node.path in vulnerable_files,
                }
                for node in sorted(self.nodes.values(), key=lambda item: item.path)
            ],
            "edges": [
                {"from": node.path, "to": target}
                for node in sorted(self.nodes.values(), key=lambda item: item.path)
                for target in node.imports
            ],
            "vulnerable_files": sorted(vulnerable_files),
            "vulnerable_packages": sorted(vulnerable_packages),
            "blast_radius": self.blast_radius(),
        }
        return json.dumps(payload, indent=2, sort_keys=False) + "\n"

    def _selected_nodes(
        self,
        vulnerable_files: set[str],
        max_nodes: int,
    ) -> list[str]:
        if len(self.nodes) <= max_nodes:
            return sorted(self.nodes)
        ranked: list[str] = []
        for path in sorted(vulnerable_files):
            if path not in self.nodes:
                continue
            for candidate in [path, *self.dependents(path)]:
                if candidate not in ranked:
                    ranked.append(candidate)
        for path in sorted(self.nodes):
            if path not in ranked:
                ranked.append(path)
            if len(ranked) >= max_nodes:
                break
        return ranked[:max_nodes]

    def to_mermaid(
        self,
        *,
        vulnerable_files: set[str] | None = None,
        vulnerable_packages: set[str] | None = None,
        max_nodes: int = _MAX_GRAPH_NODES,
    ) -> str:
        vulnerable_files = vulnerable_files or set()
        vulnerable_packages = vulnerable_packages or set()
        selected = self._selected_nodes(vulnerable_files, max_nodes)
        selected_set = set(selected)
        ids = {path: f"n{index}" for index, path in enumerate(selected)}
        direct: set[str] = set()
        transitive: set[str] = set()
        for path in vulnerable_files:
            for dependent in self.dependents(path, max_depth=1):
                direct.add(dependent)
            for dependent in self.dependents(path):
                if dependent not in direct:
                    transitive.add(dependent)

        lines = ["graph TD"]
        for path in selected:
            label = _mermaid_label(path)
            lines.append(f'    {ids[path]}["{label}"]')
        for node in sorted(self.nodes.values(), key=lambda item: item.path):
            if node.path not in selected_set:
                continue
            for target in node.imports:
                if target in selected_set:
                    lines.append(f"    {ids[node.path]} --> {ids[target]}")
        if vulnerable_packages:
            for index, package in enumerate(sorted(vulnerable_packages)):
                package_id = f"p{index}"
                lines.append(f'    {package_id}(["📦 {_mermaid_label(package)}"])')
        for index, package in enumerate(sorted(vulnerable_packages)):
            for node in self.nodes.values():
                if package in node.dependencies and node.path in selected_set:
                    lines.append(f"    {ids[node.path]} --> p{index}")
        if vulnerable_files or direct or transitive or vulnerable_packages:
            lines.append(
                "    classDef vulnerable fill:#7f1d1d,stroke:#fecaca,color:#fff,"
                "stroke-width:2px"
            )
            lines.append(
                "    classDef direct fill:#9a3412,stroke:#fdba74,color:#fff"
            )
            lines.append(
                "    classDef transitive fill:#854d0e,stroke:#fde68a,color:#fff"
            )
            for path in sorted(vulnerable_files):
                if path in ids:
                    lines.append(f"    class {ids[path]} vulnerable")
            for path in sorted(direct):
                if path in ids:
                    lines.append(f"    class {ids[path]} direct")
            for path in sorted(transitive):
                if path in ids:
                    lines.append(f"    class {ids[path]} transitive")
        if len(self.nodes) > len(selected):
            lines.append(
                f'    omitted["{len(self.nodes) - len(selected)} more file(s) omitted"]'
            )
        return "\n".join(lines) + "\n"

    def to_dot(
        self,
        *,
        vulnerable_files: set[str] | None = None,
        vulnerable_packages: set[str] | None = None,
        max_nodes: int = _MAX_GRAPH_NODES,
    ) -> str:
        vulnerable_files = vulnerable_files or set()
        vulnerable_packages = vulnerable_packages or set()
        selected = self._selected_nodes(vulnerable_files, max_nodes)
        selected_set = set(selected)
        direct: set[str] = set()
        transitive: set[str] = set()
        for path in vulnerable_files:
            for dependent in self.dependents(path, max_depth=1):
                direct.add(dependent)
            for dependent in self.dependents(path):
                if dependent not in direct:
                    transitive.add(dependent)
        lines = ["digraph commitguard {", "  rankdir=LR;", '  node [shape=box, fontname="Helvetica"];']
        for path in selected:
            color = "#7f1d1d" if path in vulnerable_files else (
                "#9a3412" if path in direct else "#854d0e" if path in transitive else "#1f2937"
            )
            lines.append(
                f'  "{_dot_escape(path)}" [label="{_dot_escape(path)}", '
                f'style=filled, fillcolor="{color}", fontcolor="white"];'
            )
        for node in sorted(self.nodes.values(), key=lambda item: item.path):
            if node.path not in selected_set:
                continue
            for target in node.imports:
                if target in selected_set:
                    lines.append(
                        f'  "{_dot_escape(node.path)}" -> "{_dot_escape(target)}";'
                    )
        for package in sorted(vulnerable_packages):
            lines.append(
                f'  "pkg:{_dot_escape(package)}" [label="📦 {_dot_escape(package)}", '
                'shape=component, style=filled, fillcolor="#7f1d1d", fontcolor="white"];'
            )
            for node in sorted(self.nodes.values(), key=lambda item: item.path):
                if package in node.dependencies and node.path in selected_set:
                    lines.append(
                        f'  "{_dot_escape(node.path)}" -> "pkg:{_dot_escape(package)}";'
                    )
        lines.append("}")
        return "\n".join(lines) + "\n"


def _mermaid_label(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', "&quot;").replace("\n", " ")


def _dot_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')


def _read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def _repo_files(repo_root: Path) -> list[str]:
    try:
        result = subprocess.run(
            [
                "git",
                "-c",
                "core.quotePath=false",
                "--no-pager",
                "ls-files",
                "-z",
                "--cached",
                "--others",
                "--exclude-standard",
            ],
            cwd=str(repo_root),
            capture_output=True,
            check=False,
        )
    except OSError:
        result = None
    if result is not None and result.returncode == 0:
        paths = [
            path
            for path in result.stdout.decode("utf-8", "replace").split("\0")
            if path
        ]
    else:
        paths = [
            path.relative_to(repo_root).as_posix()
            for path in repo_root.rglob("*")
            if path.is_file()
            and ".git" not in path.parts
            and ".commit_guard" not in path.parts
            and "commit_guard_reports" not in path.parts
        ]
    return sorted(set(paths))[:_MAX_FILES]


def _module_name(path: str) -> str:
    pure = Path(path)
    parts = list(pure.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _python_candidates(module: str) -> tuple[str, ...]:
    base = module.replace(".", "/")
    return (f"{base}.py", f"{base}/__init__.py", f"{base}.pyi")


def _resolve_python(
    current: str,
    raw_module: str,
    level: int,
    module_map: dict[str, str],
    existing: set[str],
) -> str | None:
    current_dir = Path(current).parent.as_posix()
    if current_dir == ".":
        current_dir = ""
    if level:
        parts = current_dir.split("/") if current_dir else []
        if level > 1:
            parts = parts[: -(level - 1)] if level - 1 <= len(parts) else []
        base_dir = "/".join(parts)
        module = ".".join(part for part in [base_dir.replace("/", "."), raw_module] if part)
    else:
        module = raw_module
    module = module.strip(".")
    if not module:
        return None
    for candidate in _python_candidates(module):
        if candidate in existing:
            return candidate
    # `from package import module` may target a submodule rather than __init__.
    for suffix in ("",):
        candidate = module_map.get(module + suffix)
        if candidate:
            return candidate
    return None


def _parse_python(path: str, text: str, module_map: dict[str, str], existing: set[str]) -> tuple[set[str], set[str]]:
    imports: set[str] = set()
    external: set[str] = set()
    try:
        tree = ast.parse(text, filename=path)
    except SyntaxError:
        return imports, external
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                target = _resolve_python(path, alias.name, 0, module_map, existing)
                if target and target != path:
                    imports.add(target)
                else:
                    external.add(alias.name.split(".", 1)[0])
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            target = _resolve_python(path, module, node.level, module_map, existing)
            if target and target != path:
                imports.add(target)
            elif not node.level:
                external.add(module.split(".", 1)[0] if module else "")
            for alias in node.names:
                if alias.name == "*":
                    continue
                full = f"{module}.{alias.name}" if module else alias.name
                sub = _resolve_python(path, full, node.level, module_map, existing)
                if sub and sub != path:
                    imports.add(sub)
    external.discard("")
    return imports, external


def _resolve_relative(
    current: str,
    spec: str,
    existing: set[str],
    extensions: tuple[str, ...],
) -> str | None:
    base = (Path(current).parent / spec).as_posix()
    candidates = [base]
    candidates.extend(f"{base}{suffix}" for suffix in extensions)
    candidates.extend(f"{base}/index{suffix}" for suffix in extensions)
    for candidate in candidates:
        normalized = _normalize(candidate)
        if normalized in existing:
            return normalized
    return None


def _normalize(path: str) -> str:
    parts: list[str] = []
    for part in path.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return "/".join(parts)


def _parse_javascript(path: str, text: str, existing: set[str]) -> tuple[set[str], set[str]]:
    imports: set[str] = set()
    external: set[str] = set()
    extensions = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".vue")
    for match in _JS_IMPORT_RE.finditer(text):
        spec = next(group for group in match.groups() if group)
        if spec.startswith((".", "/")):
            target = _resolve_relative(path, spec, existing, extensions)
            if target and target != path:
                imports.add(target)
        else:
            external.add(_package_name(spec))
    return imports, external


def _package_name(spec: str) -> str:
    spec = spec.strip()
    if spec.startswith("@"):
        parts = spec.split("/")
        return "/".join(parts[:2])
    return spec.split("/", 1)[0]


def _go_module(repo_root: Path) -> str:
    path = repo_root / "go.mod"
    text = _read_text(path) if path.is_file() else None
    if not text:
        return ""
    match = re.search(r"^\s*module\s+(\S+)", text, re.MULTILINE)
    return match.group(1) if match else ""


def _parse_go(
    path: str,
    text: str,
    existing: set[str],
    module: str,
) -> tuple[set[str], set[str]]:
    specs: set[str] = set()
    specs.update(_GO_IMPORT_SINGLE_RE.findall(text))
    for block in _GO_IMPORT_BLOCK_RE.findall(text):
        specs.update(_GO_IMPORT_LINE_RE.findall(block))
    imports: set[str] = set()
    external: set[str] = set()
    for spec in specs:
        if module and (spec == module or spec.startswith(module + "/")):
            directory = _normalize(spec[len(module) :].lstrip("/"))
            candidates = sorted(
                candidate
                for candidate in existing
                if candidate.endswith(".go")
                and not candidate.endswith("_test.go")
                and (Path(candidate).parent.as_posix() == (directory or "."))
            )
            imports.update(candidate for candidate in candidates if candidate != path)
        else:
            external.add(_package_name(spec))
    return imports, external


def _parse_rust(path: str, text: str, existing: set[str]) -> tuple[set[str], set[str]]:
    imports: set[str] = set()
    external: set[str] = set()
    for name in _RS_MOD_RE.findall(text):
        base = Path(path).parent
        candidates = {
            (base / f"{name}.rs").as_posix(),
            (base / name / "mod.rs").as_posix(),
        }
        for candidate in candidates:
            if candidate in existing:
                imports.add(candidate)
    for statement in _RS_USE_RE.findall(text):
        statement = statement.strip()
        root = statement.split("::", 1)[0]
        if root in {"crate", "self", "super"}:
            parts = [part for part in statement.split("::") if part not in {"crate", "self", "super", "*", "{", "}"}]
            for index in range(len(parts), 0, -1):
                suffix = "/".join(parts[:index])
                for candidate in (
                    f"src/{suffix}.rs",
                    f"src/{suffix}/mod.rs",
                    suffix + ".rs",
                    suffix + "/mod.rs",
                ):
                    if candidate in existing:
                        imports.add(candidate)
                        break
                else:
                    continue
                break
        else:
            external.add(root)
    return imports, external


def _parse_java_like(
    path: str,
    text: str,
    existing: set[str],
    package_index: dict[str, str],
) -> tuple[set[str], set[str]]:
    imports: set[str] = set()
    external: set[str] = set()
    for name in _JAVA_IMPORT_RE.findall(text):
        if name in package_index:
            imports.add(package_index[name])
        else:
            external.add(name.rsplit(".", 1)[0] if "." in name else name)
    return imports, external


def _parse_ruby(path: str, text: str, existing: set[str]) -> tuple[set[str], set[str]]:
    imports: set[str] = set()
    external: set[str] = set()
    for relative, spec in _RUBY_REQUIRE_RE.findall(text):
        if relative or spec.startswith((".", "/")):
            target = _resolve_relative(path, spec, existing, (".rb",))
            if target and target != path:
                imports.add(target)
        else:
            target = f"{spec}.rb"
            if target in existing:
                imports.add(target)
            else:
                external.add(spec.split("/", 1)[0])
    return imports, external


def _parse_php(path: str, text: str, existing: set[str]) -> tuple[set[str], set[str]]:
    imports: set[str] = set()
    external: set[str] = set()
    for spec in _PHP_REQUIRE_RE.findall(text):
        normalized = _normalize(spec)
        if spec.startswith((".", "/")):
            target = _resolve_relative(path, spec, existing, (".php",))
        elif normalized in existing:
            target = normalized
        else:
            target = _resolve_relative(path, spec, existing, (".php",))
        if target and target != path:
            imports.add(target)
        elif not spec.startswith((".", "/")):
            external.add(spec.split("/", 1)[0])
    return imports, external


def _manifest_dependencies(path: str, text: str) -> tuple[str, ...]:
    name = Path(path).name
    dependencies: set[str] = set()
    if name == "requirements.txt":
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line or line.startswith(("-", "http:", "https:", "git+")):
                continue
            match = re.match(r"([A-Za-z0-9_.-]+)", line)
            if match:
                dependencies.add(match.group(1))
    elif name == "package.json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return ()
        for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            section = data.get(key)
            if isinstance(section, dict):
                dependencies.update(str(item) for item in section)
    elif name == "go.mod":
        for match in re.finditer(
            r"^\s*(?:require\s+)?([a-z0-9.-]+\.[a-z]{2,}/\S+)\s+v",
            text,
            re.MULTILINE,
        ):
            dependencies.add(match.group(1))
        for block in re.findall(r"require\s*\((.*?)\)", text, re.DOTALL):
            for match in re.finditer(
                r"^\s*([a-z0-9.-]+\.[a-z]{2,}/\S+)\s+v", block, re.MULTILINE
            ):
                dependencies.add(match.group(1))
    elif name == "Cargo.toml":
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            return ()
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            value = data.get(section)
            if isinstance(value, dict):
                dependencies.update(str(item) for item in value)
        workspace = data.get("workspace")
        if isinstance(workspace, dict):
            value = workspace.get("dependencies")
            if isinstance(value, dict):
                dependencies.update(str(item) for item in value)
    return tuple(sorted(dependencies))


def _parse_java_packages(repo_root: Path, paths: list[str]) -> dict[str, str]:
    index: dict[str, str] = {}
    for path in paths:
        if Path(path).suffix.lower() not in {".java", ".kt", ".kts"}:
            continue
        text = _read_text(repo_root / path)
        if not text:
            continue
        match = _JAVA_PACKAGE_RE.search(text)
        package = match.group(1) if match else ""
        symbol = Path(path).stem
        if symbol in {"module-info", "package-info"}:
            continue
        index[f"{package}.{symbol}" if package else symbol] = path
    return index


def build_dependency_graph(repo_root: Path, *, max_files: int = _MAX_FILES) -> DependencyGraph:
    """Parses an entire repo into a file-level import graph."""
    root = Path(repo_root).resolve()
    paths = _repo_files(root)[:max_files]
    existing = set(paths)
    module_map: dict[str, str] = {}
    for path in paths:
        if Path(path).suffix.lower() in {".py", ".pyi"}:
            module_map[_module_name(path)] = path
    go_module = _go_module(root)
    package_index = _parse_java_packages(root, paths)

    nodes: dict[str, DependencyNode] = {}
    for path in paths:
        name = Path(path).name
        language = _LANGUAGE_BY_SUFFIX.get(Path(path).suffix.lower())
        is_manifest = name in _MANIFEST_NAMES
        if not language and not is_manifest:
            continue
        text = _read_text(root / path)
        if text is None:
            continue
        if is_manifest:
            nodes[path] = DependencyNode(
                path=path,
                language="manifest",
                dependencies=_manifest_dependencies(path, text),
            )
            continue
        if language == "python":
            imports, external = _parse_python(path, text, module_map, existing)
        elif language in {"javascript", "typescript", "vue"}:
            imports, external = _parse_javascript(path, text, existing)
        elif language == "go":
            imports, external = _parse_go(path, text, existing, go_module)
        elif language == "rust":
            imports, external = _parse_rust(path, text, existing)
        elif language in {"java", "kotlin"}:
            imports, external = _parse_java_like(path, text, existing, package_index)
        elif language == "ruby":
            imports, external = _parse_ruby(path, text, existing)
        elif language == "php":
            imports, external = _parse_php(path, text, existing)
        else:
            imports, external = set(), set()
        nodes[path] = DependencyNode(
            path=path,
            language=language,
            imports=tuple(sorted(imports)),
            external=tuple(sorted(item for item in external if item)),
        )

    reverse: dict[str, set[str]] = {}
    for node in nodes.values():
        for target in node.imports:
            if target in nodes:
                reverse.setdefault(target, set()).add(node.path)
    return DependencyGraph(nodes=nodes, reverse=reverse)


def write_dependency_graph(
    graph: DependencyGraph,
    output_dir: Path,
    fmt: str = "mermaid",
    *,
    vulnerable_files: set[str] | None = None,
    vulnerable_packages: set[str] | None = None,
    max_nodes: int = _MAX_GRAPH_NODES,
) -> list[Path]:
    """Writes mermaid/json/dot graph files and returns their paths."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    formats = ("mermaid", "json", "dot") if fmt == "all" else (fmt,)
    written: list[Path] = []
    for format_name in formats:
        if format_name == "mermaid":
            text = graph.to_mermaid(
                vulnerable_files=vulnerable_files,
                vulnerable_packages=vulnerable_packages,
                max_nodes=max_nodes,
            )
            path = output_dir / "dependency-graph.mmd"
        elif format_name == "json":
            text = graph.to_json(
                vulnerable_files=vulnerable_files,
                vulnerable_packages=vulnerable_packages,
            )
            path = output_dir / "dependency-graph.json"
        elif format_name == "dot":
            text = graph.to_dot(
                vulnerable_files=vulnerable_files,
                vulnerable_packages=vulnerable_packages,
                max_nodes=max_nodes,
            )
            path = output_dir / "dependency-graph.dot"
        else:
            raise ValueError(f"Unsupported dependency graph format: {fmt}")
        path.write_text(text, encoding="utf-8")
        written.append(path.resolve())
    return written
