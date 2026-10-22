"""Conservative, intraprocedural Python AST taint checks."""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass

from core.scanner import Finding

TAINT_RULES = {
    "cg-python-ast-sqli-taint": {
        "description": "Request-controlled data reaches a SQL execute() query; use query parameters.",
        "severity": "high",
        "cwe": "CWE-89",
        "tags": ("sqli", "injection", "taint", "ast"),
    },
    "cg-python-ast-shell-taint": {
        "description": "Request-controlled data reaches a shell command; avoid shell execution or validate arguments.",
        "severity": "high",
        "cwe": "CWE-78",
        "tags": ("command-injection", "taint", "ast"),
    },
}

_REQUEST_INPUTS = {
    "args",
    "form",
    "values",
    "json",
    "data",
    "headers",
    "cookies",
    "FILES",
    "GET",
    "POST",
    "META",
    "path_params",
    "view_args",
    "query_params",
}
_SUBPROCESS_FUNCTIONS = {
    "run",
    "call",
    "Popen",
    "check_call",
    "check_output",
}


@dataclass(frozen=True)
class TaintMatch:
    finding: Finding
    sink_line: int


@dataclass(frozen=True)
class TaintResult:
    matches: tuple[TaintMatch, ...] = ()
    warnings: tuple[str, ...] = ()


def _attribute_chain(node: ast.AST) -> list[str]:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return list(reversed(parts))


def _is_request_source(node: ast.AST) -> bool:
    if isinstance(node, ast.Attribute):
        chain = _attribute_chain(node)
        return (
            len(chain) >= 2
            and chain[0] in {"request", "req"}
            and any(part in _REQUEST_INPUTS for part in chain[1:])
        )
    if isinstance(node, ast.Call):
        function = node.func
        return (
            isinstance(function, ast.Name)
            and function.id == "input"
        ) or (
            isinstance(function, ast.Attribute)
            and _attribute_chain(function) == ["builtins", "input"]
        )
    return False


def _is_tainted(node: ast.AST, tainted: dict[str, set[int]]) -> set[int]:
    if _is_request_source(node):
        return {getattr(node, "lineno", 1)}
    if isinstance(node, ast.Name):
        return set(tainted.get(node.id, ()))
    sources: set[int] = set()
    for child in ast.iter_child_nodes(node):
        sources.update(_is_tainted(child, tainted))
    return sources


def _call_argument(call: ast.Call, keyword_names: set[str]) -> ast.AST | None:
    if call.args:
        return call.args[0]
    return next(
        (keyword.value for keyword in call.keywords if keyword.arg in keyword_names),
        None,
    )


def _target_names(target: ast.AST) -> set[str]:
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, (ast.Tuple, ast.List)):
        return set().union(*(_target_names(item) for item in target.elts))
    return set()


def _merge_states(*states: dict[str, set[int]]) -> dict[str, set[int]]:
    merged: dict[str, set[int]] = {}
    for state in states:
        for name, sources in state.items():
            merged.setdefault(name, set()).update(sources)
    return merged


class _TaintAnalyzer:
    def __init__(self, path: str, lines: list[str], changed: set[int]) -> None:
        self.path = path
        self.lines = lines
        self.changed = changed
        self.matches: dict[tuple[str, int], TaintMatch] = {}

    def _record(
        self,
        call: ast.Call,
        rule_id: str,
        sources: set[int],
    ) -> None:
        if not sources:
            return
        sink_line = getattr(call, "lineno", 1)
        sink_end = getattr(call, "end_lineno", sink_line)
        changed_sink_lines = sorted(
            line for line in self.changed if sink_line <= line <= sink_end
        )
        changed_source_lines = sorted(sources & self.changed)
        if not changed_sink_lines and not changed_source_lines:
            return

        finding_line = (
            changed_sink_lines[0]
            if changed_sink_lines
            else changed_source_lines[-1]
        )
        if not 1 <= finding_line <= len(self.lines):
            return
        flagged = self.lines[finding_line - 1].strip()
        if not flagged:
            return
        details = TAINT_RULES[rule_id]
        description = (
            f"{details['description']} (sink at line {sink_line}; "
            f"tainted source at line {min(sources)})."
        )
        fingerprint = hashlib.sha256(
            f"{rule_id}\0{self.path}\0{sink_line}\0{flagged}".encode(
                "utf-8", "replace"
            )
        ).hexdigest()[:16]
        match = TaintMatch(
            Finding(
                file=self.path,
                line_number=finding_line,
                rule_id=rule_id,
                description=description,
                severity=str(details["severity"]),
                source="python_ast",
                flagged_code=flagged,
                redacted_code=flagged,
                fingerprint=fingerprint,
                tags=details["tags"],
                cwe=str(details["cwe"]),
            ),
            sink_line,
        )
        self.matches[(rule_id, sink_line)] = match

    def _check_expression(self, node: ast.AST, tainted: dict[str, set[int]]) -> None:
        for candidate in ast.walk(node):
            if not isinstance(candidate, ast.Call):
                continue
            sources = self._sink_sources(candidate, tainted)
            if sources:
                rule_id, taint = sources
                self._record(candidate, rule_id, taint)

    def _sink_sources(
        self, call: ast.Call, tainted: dict[str, set[int]]
    ) -> tuple[str, set[int]] | None:
        function = call.func
        chain = _attribute_chain(function) if isinstance(
            function, (ast.Attribute, ast.Name)
        ) else []

        if isinstance(function, ast.Attribute) and function.attr in {
            "execute",
            "executemany",
        }:
            query = _call_argument(call, {"sql", "query"})
            sources = _is_tainted(query, tainted) if query is not None else set()
            return ("cg-python-ast-sqli-taint", sources) if sources else None

        is_os_shell = (
            isinstance(function, ast.Attribute)
            and chain in (["os", "system"], ["os", "popen"])
        )
        is_subprocess = (
            isinstance(function, ast.Attribute)
            and len(chain) == 2
            and chain[0] == "subprocess"
            and chain[1] in _SUBPROCESS_FUNCTIONS
        )
        if is_os_shell:
            command = _call_argument(call, {"command"})
            sources = _is_tainted(command, tainted) if command is not None else set()
            return ("cg-python-ast-shell-taint", sources) if sources else None
        if is_subprocess and any(
            keyword.arg == "shell"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in call.keywords
        ):
            command = _call_argument(call, {"args"})
            sources = _is_tainted(command, tainted) if command is not None else set()
            return ("cg-python-ast-shell-taint", sources) if sources else None
        return None

    def _assign(self, target: ast.AST, sources: set[int], state: dict[str, set[int]]) -> None:
        for name in _target_names(target):
            if sources:
                state[name] = set(sources)
            else:
                state.pop(name, None)

    def _block(
        self, statements: list[ast.stmt], state: dict[str, set[int]]
    ) -> dict[str, set[int]]:
        current = {name: set(sources) for name, sources in state.items()}
        for statement in statements:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for default in (*statement.args.defaults, *statement.args.kw_defaults):
                    if default is not None:
                        self._check_expression(default, current)
                self._block(statement.body, current.copy())
                continue
            if isinstance(statement, ast.ClassDef):
                self._block(statement.body, current.copy())
                continue
            if isinstance(statement, ast.Assign):
                self._check_expression(statement.value, current)
                sources = _is_tainted(statement.value, current)
                for target in statement.targets:
                    self._assign(target, sources, current)
            elif isinstance(statement, ast.AnnAssign):
                if statement.value is not None:
                    self._check_expression(statement.value, current)
                    self._assign(
                        statement.target, _is_tainted(statement.value, current), current
                    )
            elif isinstance(statement, ast.AugAssign):
                self._check_expression(statement.value, current)
                sources = _is_tainted(statement.target, current)
                sources.update(_is_tainted(statement.value, current))
                self._assign(statement.target, sources, current)
            elif isinstance(statement, ast.If):
                self._check_expression(statement.test, current)
                body = self._block(statement.body, current.copy())
                otherwise = self._block(statement.orelse, current.copy())
                current = _merge_states(body, otherwise)
            elif isinstance(statement, (ast.For, ast.AsyncFor)):
                self._check_expression(statement.iter, current)
                body_state = current.copy()
                self._assign(
                    statement.target, _is_tainted(statement.iter, current), body_state
                )
                body_state = self._block(statement.body, body_state)
                else_state = self._block(statement.orelse, current.copy())
                current = _merge_states(current, body_state, else_state)
            elif isinstance(statement, ast.While):
                self._check_expression(statement.test, current)
                body_state = self._block(statement.body, current.copy())
                else_state = self._block(statement.orelse, current.copy())
                current = _merge_states(current, body_state, else_state)
            elif isinstance(statement, (ast.With, ast.AsyncWith)):
                for item in statement.items:
                    self._check_expression(item.context_expr, current)
                    if item.optional_vars is not None:
                        self._assign(
                            item.optional_vars,
                            _is_tainted(item.context_expr, current),
                            current,
                        )
                current = self._block(statement.body, current)
            elif isinstance(statement, ast.Try):
                branches = [self._block(statement.body, current.copy())]
                branches.extend(
                    self._block(handler.body, current.copy())
                    for handler in statement.handlers
                )
                if statement.orelse:
                    branches.append(
                        self._block(statement.orelse, branches[0].copy())
                    )
                current = self._block(statement.finalbody, _merge_states(*branches))
            elif isinstance(statement, ast.Expr):
                self._check_expression(statement.value, current)
            else:
                self._check_expression(statement, current)
        return current

    def analyze(self) -> tuple[TaintMatch, ...]:
        try:
            tree = ast.parse("\n".join(self.lines), filename=self.path)
        except (SyntaxError, ValueError, RecursionError) as exc:
            raise ValueError(f"could not parse Python syntax: {exc}") from exc
        self._block(tree.body, {})
        return tuple(self.matches.values())


def scan_python_taint(
    files: dict[str, list[str]],
    changed_lines: dict[str, set[int]],
) -> TaintResult:
    """Find changed Python flows from request/input data into SQL or shell sinks."""
    matches: list[TaintMatch] = []
    warnings: list[str] = []
    for path, changed in sorted(changed_lines.items()):
        if not path.endswith((".py", ".pyi")):
            continue
        lines = files.get(path)
        if lines is None:
            warnings.append(f"{path}: staged/current file content was unavailable")
            continue
        try:
            matches.extend(_TaintAnalyzer(path, lines, changed).analyze())
        except ValueError as exc:
            warnings.append(f"{path}: {exc}")
    return TaintResult(tuple(matches), tuple(warnings))
