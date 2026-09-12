"""
core/scanner.py
----------------
Applies the loaded rule set against the parsed staged diff lines and
produces a list of Finding objects.

This module is intentionally "dumb": it does no I/O and no printing —
it just matches regex patterns against text. That keeps it trivially
unit-testable.
"""

from __future__ import annotations

from dataclasses import dataclass

from core.git_diff import DiffLine
from core.rule_loader import SEVERITY_ORDER, Rule, rules_for_file

# Lines longer than this are truncated in the "flagged_code" field of a
# finding purely for readability in the report — the full line is still
# scanned in full.
_MAX_FLAGGED_SNIPPET_LEN = 200


@dataclass(frozen=True)
class Finding:
    """A single rule match against a single staged line."""
    file: str
    line_number: int
    rule_id: str
    description: str
    severity: str
    source: str
    flagged_code: str


def _truncate(text: str, limit: int = _MAX_FLAGGED_SNIPPET_LEN) -> str:
    stripped = text.strip()
    if len(stripped) <= limit:
        return stripped
    return stripped[:limit] + "…"


def scan_diff(diff_lines: list[DiffLine], rules: list[Rule]) -> list[Finding]:
    """
    Matches every staged added line against the rules applicable to its
    file type, returning all findings in the order they were discovered.

    A single line may trigger multiple findings (e.g. it both looks like
    a secret AND matches a SQLi pattern) — all matches are reported so
    the developer has full visibility.
    """
    findings: list[Finding] = []

    # Cache per-file-extension rule subsets so we don't re-filter the
    # entire rule list for every single line in a large diff.
    rules_cache: dict[str, list[Rule]] = {}

    for diff_line in diff_lines:
        if diff_line.file_path not in rules_cache:
            rules_cache[diff_line.file_path] = rules_for_file(rules, diff_line.file_path)
        applicable_rules = rules_cache[diff_line.file_path]

        for rule in applicable_rules:
            if rule.pattern.search(diff_line.code_content):
                findings.append(
                    Finding(
                        file=diff_line.file_path,
                        line_number=diff_line.line_number,
                        rule_id=rule.rule_id,
                        description=rule.description,
                        severity=rule.severity,
                        source=rule.source,
                        flagged_code=_truncate(diff_line.code_content),
                    )
                )

    return findings


def has_blocking_findings(findings: list[Finding], block_threshold: str = "high") -> bool:
    """
    Determines whether the finding set should block the commit.

    block_threshold: the minimum severity (inclusive) that causes a
    block. Defaults to "high", meaning both "high" and "critical"
    findings block the commit, while "medium"/"low"/"info" do not.
    """
    threshold_value = SEVERITY_ORDER.get(block_threshold, SEVERITY_ORDER["high"])
    return any(SEVERITY_ORDER.get(f.severity, 0) >= threshold_value for f in findings)


def sort_findings_by_severity(findings: list[Finding]) -> list[Finding]:
    """Returns findings sorted most-severe-first, stable on discovery order."""
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 0), reverse=True)
