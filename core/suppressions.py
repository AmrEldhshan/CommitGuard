"""
Parsing, writing, and auditing of `.commit_guard_ignore` entries.

Fingerprint entries may carry optional metadata after a comment marker:

    fingerprint:0123456789abcdef # owner=security expiry=2026-12-31

Expired entries stop suppressing findings. `suppressions audit` reports
expired, stale, unknown-rule, and unmatched-path entries.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from core.scanner import Baseline

_META_RE = re.compile(r"(owner|expiry)\s*=\s*([^\s#]+)", re.IGNORECASE)


@dataclass(frozen=True)
class BaselineEntry:
    kind: str
    value: str
    owner: str | None
    expiry: date | None
    line_number: int
    raw: str


def _parse_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def parse_baseline_entries(path: Path) -> list[BaselineEntry]:
    if not path.is_file():
        return []
    entries: list[BaselineEntry] = []
    text = path.read_text(encoding="utf-8", errors="ignore")
    for number, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        content, _, comment = stripped.partition("#")
        content = content.strip()
        if not content:
            continue
        lower = content.lower()
        if lower.startswith("path:"):
            kind, value = "path", content.split(":", 1)[1].strip()
        elif lower.startswith("fingerprint:"):
            kind, value = "fingerprint", content.split(":", 1)[1].strip()
        elif lower.startswith("rule:"):
            kind, value = "rule", content.split(":", 1)[1].strip()
        else:
            kind, value = "rule", content
        if not value:
            continue
        metadata = {
            match.group(1).lower(): match.group(2) for match in _META_RE.finditer(comment)
        }
        entries.append(
            BaselineEntry(
                kind=kind,
                value=value,
                owner=metadata.get("owner"),
                expiry=_parse_date(metadata.get("expiry")),
                line_number=number,
                raw=stripped,
            )
        )
    return entries


def build_baseline(entries: list[BaselineEntry], today: date | None = None) -> Baseline:
    today = today or date.today()
    rule_ids: set[str] = set()
    path_globs: list[str] = []
    fingerprints: set[str] = set()
    for entry in entries:
        if entry.expiry is not None and entry.expiry < today:
            continue
        if entry.kind == "rule":
            rule_ids.add(entry.value)
        elif entry.kind == "path":
            path_globs.append(entry.value)
        else:
            fingerprints.add(entry.value)
    return Baseline(
        rule_ids=rule_ids,
        path_globs=tuple(path_globs),
        fingerprints=fingerprints,
    )


def add_fingerprints(
    path: Path,
    fingerprints: list[str] | tuple[str, ...] | set[str],
    *,
    owner: str | None = None,
    expiry: str | None = None,
) -> int:
    """Appends new fingerprints, skipping duplicates. Returns the count added."""
    existing = {entry.value for entry in parse_baseline_entries(path)}
    new_values = sorted({value for value in fingerprints if value not in existing})
    if not new_values:
        return 0
    try:
        current = path.read_text(encoding="utf-8") if path.is_file() else ""
    except OSError:
        current = ""
    if current and not current.endswith("\n"):
        current += "\n"
    if not current:
        current = "# Commit Guard baseline\n"
    elif "# Commit Guard baseline" not in current:
        current += "\n# Added by commit-guard scan --update-baseline\n"
    metadata_parts = []
    if owner:
        metadata_parts.append(f"owner={owner}")
    if expiry:
        metadata_parts.append(f"expiry={expiry}")
    metadata = f" # {' '.join(metadata_parts)}" if metadata_parts else ""
    for value in new_values:
        current += f"fingerprint:{value}{metadata}\n"
    path.write_text(current, encoding="utf-8")
    return len(new_values)


def audit_entries(
    entries: list[BaselineEntry],
    *,
    known_rule_ids: set[str],
    tracked_paths: set[str],
    current_fingerprints: set[str] | None = None,
    today: date | None = None,
) -> list[str]:
    """Returns human-readable hygiene issues; an empty list means clean."""
    from core.paths import glob_to_regex

    today = today or date.today()
    issues: list[str] = []
    for entry in entries:
        label = f"line {entry.line_number}: {entry.raw}"
        if entry.expiry is not None and entry.expiry < today:
            issues.append(f"expired ({entry.expiry.isoformat()}) — {label}")
        elif entry.kind == "fingerprint" and entry.expiry is None:
            issues.append(f"fingerprint has no expiry — {label}")
        if entry.kind == "rule" and entry.value not in known_rule_ids:
            issues.append(f"unknown rule id '{entry.value}' — {label}")
        elif entry.kind == "path":
            regex = glob_to_regex(entry.value)
            if not any(regex.search(path) for path in tracked_paths):
                issues.append(f"path glob matches no tracked files — {label}")
        elif (
            entry.kind == "fingerprint"
            and current_fingerprints is not None
            and entry.value not in current_fingerprints
        ):
            issues.append(f"stale fingerprint (no current finding) — {label}")
    return issues
