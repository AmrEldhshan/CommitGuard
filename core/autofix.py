"""Safe, regex-based auto-fixes for line-oriented findings.

Only rules that explicitly provide both ``fix_pattern`` and
``fix_replacement`` are eligible.  Fixes are applied from the bottom of each
file upwards so line numbers remain stable, then modified files are staged.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from core.rule_loader import Rule
from core.scanner import Finding


class AutoFixError(RuntimeError):
    """Raised when a requested fix cannot be applied safely."""


@dataclass(frozen=True)
class FixOutcome:
    file: str
    line: int
    rule_id: str
    before: str
    after: str
    applied: bool


@dataclass
class AutoFixResult:
    outcomes: tuple[FixOutcome, ...] = ()
    files_modified: tuple[str, ...] = ()
    fixed_fingerprints: set[str] = field(default_factory=set)
    dry_run: bool = False

    @property
    def applied_count(self) -> int:
        return sum(1 for outcome in self.outcomes if outcome.applied)


def _safe_path(repo_root: Path, relative: str) -> Path:
    raw = repo_root / relative
    if raw.is_symlink():
        raise AutoFixError(f"Refusing to modify a symlink: {relative}")
    path = raw.resolve()
    try:
        path.relative_to(repo_root)
    except ValueError as exc:
        raise AutoFixError(f"Refusing to modify a path outside the repository: {relative}") from exc
    if not path.is_file():
        raise AutoFixError(f"Auto-fix target is not a file: {relative}")
    return path


def apply_fixes(
    repo_root: Path,
    findings: list[Finding],
    rules: tuple[Rule, ...] | list[Rule],
    *,
    dry_run: bool = False,
    restage: bool = True,
) -> AutoFixResult:
    """Applies eligible fixes and optionally stages the modified files."""
    root = Path(repo_root).resolve()
    rules_by_id = {rule.rule_id: rule for rule in rules if rule.fix_pattern and rule.fix_replacement is not None}
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        rule = rules_by_id.get(finding.rule_id)
        if rule is None or rule.is_secret:
            continue
        grouped.setdefault(finding.file, []).append(finding)

    outcomes: list[FixOutcome] = []
    modified: list[str] = []
    fixed_fingerprints: set[str] = set()
    for relative, file_findings in sorted(grouped.items()):
        path = _safe_path(root, relative)
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise AutoFixError(f"Could not read '{relative}' for auto-fix: {exc}") from exc
        lines = text.splitlines(keepends=True)
        changed = False
        for finding in sorted(
            file_findings,
            key=lambda item: (item.line_number, item.rule_id),
            reverse=True,
        ):
            rule = rules_by_id[finding.rule_id]
            index = finding.line_number - 1
            if index < 0 or index >= len(lines):
                continue
            before = lines[index]
            try:
                after = rule.fix_pattern.sub(rule.fix_replacement, before, count=1)
            except (re.error, IndexError) as exc:
                raise AutoFixError(
                    f"Invalid replacement for '{finding.rule_id}' in '{relative}': {exc}"
                ) from exc
            if after == before:
                continue
            if not dry_run:
                lines[index] = after
                changed = True
                fixed_fingerprints.add(finding.fingerprint)
            outcomes.append(
                FixOutcome(
                    file=relative,
                    line=finding.line_number,
                    rule_id=finding.rule_id,
                    before=before.rstrip("\r\n"),
                    after=after.rstrip("\r\n"),
                    applied=not dry_run,
                )
            )
        if changed:
            try:
                path.write_text("".join(lines), encoding="utf-8")
            except OSError as exc:
                raise AutoFixError(f"Could not write fixed file '{relative}': {exc}") from exc
            modified.append(relative)

    if modified and restage and not dry_run:
        result = subprocess.run(
            ["git", "add", "--", *modified],
            cwd=str(root),
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise AutoFixError(
                "Could not stage auto-fixed files: "
                + (result.stderr.strip() or result.stdout.strip() or "git add failed")
            )

    return AutoFixResult(
        outcomes=tuple(outcomes),
        files_modified=tuple(modified),
        fixed_fingerprints=fixed_fingerprints,
        dry_run=dry_run,
    )
