"""
core/scanner.py
----------------
Applies the loaded rule set against parsed staged diff lines and produces
Finding objects.

This module is intentionally "dumb": it performs no file I/O and no
printing, which keeps it trivially unit-testable.  All rule loading,
config handling, and report writing live elsewhere.

Suppression
-----------
Four layers, each narrower than the last:

1. Inline, next line:
       # commit-guard-ignore-next-line
       api_key = "not-a-real-secret"

2. Inline, same line (all rules, or a comma-separated rule-id list):
       api_key = "not-a-real-secret"  # commit-guard-ignore
       api_key = "not-a-real-secret"  # commit-guard-ignore: gitleaks-generic-api-key

3. Inline, whole file (main.py reads persistent directives from the index/HEAD;
   an added directive line also works):
       # commit-guard-ignore-file

4. Repo-level config / baseline, loaded by main.py:
       `.commit_guard.toml` [allowlist] rules/paths, and
       `.commit_guard_ignore` rule ids / path globs / fingerprints.

A bare `commit-guard-ignore` suppresses every rule match on that line; a
colon form only suppresses the listed rule ids.  Suppression comments are
never a substitute for removing a real secret.
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass, field, replace

from core.entropy import shannon_entropy
from core.git_diff import DiffLine
from core.paths import PathMatcher
from core.rule_loader import SEVERITY_ORDER, Rule, rules_for_file


@dataclass(frozen=True)
class Baseline:
    """A parsed `.commit_guard_ignore` file."""
    rule_ids: set[str] = field(default_factory=set)
    path_globs: tuple[str, ...] = ()
    fingerprints: set[str] = field(default_factory=set)

_MAX_FLAGGED_SNIPPET_LEN = 200
_MAX_MATCHES_PER_LINE = 1

_IGNORE_COMMENT_RE = re.compile(
    r"commit-guard-ignore(?:\s*:\s*(?P<rule_ids>[\w.\-,\s]+))?",
    re.IGNORECASE,
)
_IGNORE_NEXT_LINE_RE = re.compile(r"commit-guard-ignore-next-line", re.IGNORECASE)
_IGNORE_FILE_RE = re.compile(r"commit-guard-ignore-file", re.IGNORECASE)

_PLACEHOLDER_WORDS = (
    "your_",
    "your-",
    "yourkey",
    "example",
    "sample",
    "dummy",
    "placeholder",
    "changeme",
    "change-me",
    "change_me",
    "not-a-real",
    "not_real",
    "notreal",
    "fake",
    "redacted",
    "<",
    "${",
    "{{",
    "xxxx",
    "****",
)
_PLACEHOLDER_EXACT = {
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "api-key",
    "test",
    "testing",
    "none",
    "null",
    "true",
    "false",
    "todo",
    "n/a",
}
_HEX_CHARS = set("0123456789abcdefABCDEF")
_BASE64_CHARS = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-"
)


def looks_like_placeholder(secret: str) -> bool:
    """Conservative filter for obvious documentation/example values."""
    value = secret.strip().strip("\"'`")
    if not value:
        return True
    lowered = value.lower()
    if lowered in _PLACEHOLDER_EXACT:
        return True
    if len(set(value)) == 1:
        return True
    if any(marker in lowered for marker in _PLACEHOLDER_WORDS):
        return True
    return bool(re.fullmatch(r"(?:0+|1+|1234567890|abcdef0123456789)", lowered))


def adjusted_entropy_threshold(base: float, secret: str) -> float:
    """
    Caps a rule's entropy threshold to what the observed character class can
    actually reach. A hexadecimal token can never reach 5 bits/char, so a
    rule written for base64 secrets otherwise misses legitimate hex keys.
    """
    characters = {char for char in secret if not char.isspace()}
    if not characters:
        return base
    if characters <= _HEX_CHARS:
        maximum = 4.0
    elif characters <= _BASE64_CHARS:
        maximum = 6.0
    elif all(char.isalnum() for char in characters):
        maximum = math.log2(max(2, len(characters))) + 1.0
        maximum = min(maximum, 5.95)
    else:
        maximum = 6.5
    return min(base, max(1.5, maximum - 0.15))


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
    redacted_code: str = ""
    fingerprint: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)
    cwe: str | None = None
    blocking: bool = True
    baseline_state: str = "new"
    fixed_versions: tuple[str, ...] = field(default_factory=tuple)
    aliases: tuple[str, ...] = field(default_factory=tuple)
    advisory_url: str | None = None

    def display_code(self, show_secrets: bool = False) -> str:
        """Returns the snippet to put in a report, redacted by default."""
        if show_secrets or not self.redacted_code:
            return self.flagged_code
        return self.redacted_code


def _truncate(text: str, limit: int = _MAX_FLAGGED_SNIPPET_LEN) -> str:
    stripped = text.strip()
    if len(stripped) <= limit:
        return stripped
    return stripped[:limit] + "…"


def _mask_secret(secret: str) -> str:
    """Masks a secret while leaving a tiny visual hint of its shape."""
    if len(secret) <= 4:
        return "****"
    if len(secret) <= 8:
        return secret[0] + "****" + secret[-1]
    return secret[:2] + "********" + secret[-2:]


def redact_span(text: str, start: int, end: int) -> str:
    """
    Replaces text[start:end] with a masked version.  Offsets are clamped
    so a rule with unusual group semantics can never raise.
    """
    start = max(0, min(start, len(text)))
    end = max(start, min(end, len(text)))
    secret = text[start:end]
    if not secret:
        return text
    return text[:start] + _mask_secret(secret) + text[end:]


def _parse_inline_suppression(line_text: str) -> tuple[bool, set[str]]:
    """
    Returns (suppress_all, specific_rule_ids) for one line of code.
    `ignore-next-line` and `ignore-file` are handled separately.
    """
    if _IGNORE_NEXT_LINE_RE.search(line_text) or _IGNORE_FILE_RE.search(line_text):
        return False, set()

    match = _IGNORE_COMMENT_RE.search(line_text)
    if not match:
        return False, set()

    raw_ids = match.group("rule_ids")
    if not raw_ids:
        return True, set()

    rule_ids = {item.strip() for item in raw_ids.split(",") if item.strip()}
    return False, rule_ids


def is_inline_suppressed(
    lines: list[str],
    line_number: int,
    rule_id: str,
    *,
    changed_lines: set[int] | None = None,
    ignore_inline: bool = True,
) -> bool:
    """Checks inline suppression for a finding anchored to a source line."""
    if not ignore_inline or not 1 <= line_number <= len(lines):
        return False
    suppress_all, suppressed_ids = _parse_inline_suppression(lines[line_number - 1])
    if suppress_all or rule_id in suppressed_ids:
        return True
    previous_line = line_number - 1
    return (
        previous_line >= 1
        and (changed_lines is None or previous_line in changed_lines)
        and bool(_IGNORE_NEXT_LINE_RE.search(lines[previous_line - 1]))
    )


def _matched_span(match: re.Match[str], secret_group: int) -> tuple[int, int, str]:
    """
    Returns the (start, end, text) for the secret portion of a match,
    falling back to the whole match if the configured group is absent or
    did not participate.
    """
    if secret_group:
        try:
            group_text = match.group(secret_group)
            if group_text is not None:
                return (*match.span(secret_group), group_text)
        except (IndexError, re.error):  # pragma: no cover - defensive
            pass
    return (*match.span(0), match.group(0))


def _redaction_span(match: re.Match[str], secret_group: int) -> tuple[int, int]:
    """
    Chooses the portion of a match to mask.

    gitleaks rules often report the whole `name = value` expression but
    capture the actual value in a group; masking the whole expression is
    technically safe but destroys useful context.  Use an explicit
    secretGroup when configured, otherwise the last non-trivial capture
    group, otherwise the whole match.
    """
    if secret_group:
        try:
            if match.group(secret_group) is not None:
                return match.span(secret_group)
        except (IndexError, re.error):
            pass
    if match.lastindex:
        for index in range(match.lastindex, 0, -1):
            try:
                text = match.group(index)
            except (IndexError, re.error):
                continue
            if text and len(text.strip()) >= 6:
                return match.span(index)
    return match.span(0)


def _path_matches(path: str, regexes: tuple[re.Pattern[str], ...]) -> bool:
    return any(regex.search(path) for regex in regexes)


def _fingerprint(rule_id: str, file_path: str, code: str) -> str:
    payload = f"{rule_id}\0{file_path}\0{code.strip()}".encode("utf-8", "replace")
    return hashlib.sha256(payload).hexdigest()[:16]


def _line_allowed(secret: str, allowlist_regexes: tuple[re.Pattern[str], ...]) -> bool:
    return any(regex.search(secret) for regex in allowlist_regexes)


def _context_satisfied(
    rule: Rule,
    file_path: str,
    line_number: int,
    context_lines: dict[str, dict[int, str]],
) -> bool:
    if not rule.context_regexes:
        return True
    lines = context_lines.get(file_path, {})
    if not lines:
        return False
    first = max(1, line_number - rule.context_before)
    last = line_number + rule.context_after
    for number in range(first, last + 1):
        if number == line_number:
            continue
        text = lines.get(number)
        if text is None:
            continue
        if any(regex.search(text) for regex in rule.context_regexes):
            return True
    return False


def scan_diff(
    diff_lines: list[DiffLine],
    rules: list[Rule] | tuple[Rule, ...],
    ignored_rule_ids: set[str] | None = None,
    *,
    allowlist_regexes: tuple[re.Pattern[str], ...] = (),
    allowlist_path_regexes: tuple[re.Pattern[str], ...] = (),
    path_excludes: tuple[str, ...] | PathMatcher = (),
    ignore_inline: bool = True,
    max_findings: int = 0,
    ignored_files: set[str] | None = None,
    filter_placeholders: bool = True,
    file_lines: dict[str, list[str]] | None = None,
    detect_ignore_file: bool = True,
) -> list[Finding]:
    """
    Matches every staged added line against applicable rules.

    Each line may trigger multiple findings (different rules).  Findings
    suppressed by inline comments, repo allowlists, entropy checks, or the
    `ignored_rule_ids` baseline are omitted entirely.
    """
    findings: list[Finding] = []
    ignored_rule_ids = ignored_rule_ids or set()
    excludes = path_excludes if isinstance(path_excludes, PathMatcher) else PathMatcher(path_excludes)

    ignored_files = set(ignored_files or ())
    if ignore_inline and detect_ignore_file:
        for diff_line in diff_lines:
            if _IGNORE_FILE_RE.search(diff_line.code_content):
                ignored_files.add(diff_line.file_path)

    context_lines: dict[str, dict[int, str]] = {}
    for diff_line in diff_lines:
        context_lines.setdefault(diff_line.file_path, {})[
            diff_line.line_number
        ] = diff_line.code_content
    for file_path, lines in (file_lines or {}).items():
        context_lines[file_path] = {
            number: text for number, text in enumerate(lines, start=1)
        }

    rules_cache: dict[str, tuple[Rule, ...]] = {}
    suppress_next_line: set[tuple[str, int]] = set()

    def rules_for_path(file_path: str) -> tuple[Rule, ...]:
        if file_path in rules_cache:
            return rules_cache[file_path]
        if allowlist_path_regexes and _path_matches(file_path, allowlist_path_regexes):
            rules_cache[file_path] = ()
            return ()
        applicable = tuple(
            rule
            for rule in rules_for_file(rules, file_path)
            if (not rule.path_regexes or _path_matches(file_path, rule.path_regexes))
            and not (
                rule.allowlist_path_regexes
                and _path_matches(file_path, rule.allowlist_path_regexes)
            )
        )
        rules_cache[file_path] = applicable
        return applicable

    for diff_line in diff_lines:
        file_path = diff_line.file_path
        if file_path in ignored_files or excludes.matches(file_path):
            continue

        if (file_path, diff_line.line_number) in suppress_next_line:
            continue

        if ignore_inline and _IGNORE_NEXT_LINE_RE.search(diff_line.code_content):
            suppress_next_line.add((file_path, diff_line.line_number + 1))
            continue

        suppress_all, suppressed_ids = (
            _parse_inline_suppression(diff_line.code_content) if ignore_inline else (False, set())
        )
        if suppress_all:
            continue

        applicable_rules = rules_for_path(file_path)
        if not applicable_rules:
            continue

        for rule in applicable_rules:
            if rule.rule_id in ignored_rule_ids or rule.rule_id in suppressed_ids:
                continue
            if rule.keywords and not any(
                keyword in diff_line.code_content.lower() for keyword in rule.keywords
            ):
                continue

            if not _context_satisfied(
                rule, file_path, diff_line.line_number, context_lines
            ):
                continue

            matches = 0
            for match in rule.pattern.finditer(diff_line.code_content):
                _, _, secret = _matched_span(match, rule.secret_group)

                threshold = rule.entropy
                if threshold is not None:
                    threshold = adjusted_entropy_threshold(threshold, secret)
                    if shannon_entropy(secret) < threshold:
                        continue
                if filter_placeholders and rule.is_secret and looks_like_placeholder(secret):
                    continue
                if _line_allowed(secret, rule.allowlist_regexes):
                    continue
                if _line_allowed(secret, allowlist_regexes):
                    continue

                flagged = _truncate(diff_line.code_content)
                redacted = flagged
                if rule.is_secret:
                    mask_start, mask_end = _redaction_span(match, rule.secret_group)
                    redacted = _truncate(
                        redact_span(diff_line.code_content, mask_start, mask_end)
                    )

                findings.append(
                    Finding(
                        file=file_path,
                        line_number=diff_line.line_number,
                        rule_id=rule.rule_id,
                        description=rule.description,
                        severity=rule.severity,
                        source=rule.source,
                        flagged_code=flagged,
                        redacted_code=redacted,
                        fingerprint=_fingerprint(rule.rule_id, file_path, diff_line.code_content),
                        tags=rule.tags,
                        cwe=rule.cwe,
                    )
                )
                matches += 1
                if max_findings and len(findings) >= max_findings:
                    return findings
                if matches >= _MAX_MATCHES_PER_LINE:
                    break

    return findings


def has_blocking_findings(
    findings: list[Finding],
    block_threshold: str = "high",
) -> bool:
    """True when any non-allowlisted finding meets the severity threshold."""
    threshold_value = SEVERITY_ORDER.get(block_threshold, SEVERITY_ORDER["high"])
    return any(
        finding.blocking
        and SEVERITY_ORDER.get(finding.severity, 0) >= threshold_value
        for finding in findings
    )


def sort_findings_by_severity(findings: list[Finding]) -> list[Finding]:
    """Returns findings sorted most-severe-first, stable on discovery order."""
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 0), reverse=True)


def apply_report_allowlist(
    findings: list[Finding],
    patterns: tuple[str, ...] | PathMatcher,
) -> list[Finding]:
    """
    Marks findings in `report_allowlist` paths as non-blocking while still
    reporting them, so they remain visible in the report.
    """
    matcher = patterns if isinstance(patterns, PathMatcher) else PathMatcher(patterns)
    if not matcher:
        return findings

    return [
        replace(finding, blocking=False) if matcher.matches(finding.file) else finding
        for finding in findings
    ]


def _is_baselined(finding: Finding, baseline: Baseline, path_matcher: PathMatcher) -> bool:
    if finding.rule_id in baseline.rule_ids:
        return True
    if finding.fingerprint in baseline.fingerprints:
        return True
    return bool(path_matcher and path_matcher.matches(finding.file))


def apply_baseline(findings: list[Finding], baseline: Baseline) -> list[Finding]:
    """Drops findings that match a parsed `.commit_guard_ignore` baseline."""
    path_matcher = PathMatcher(baseline.path_globs)
    return [
        finding for finding in findings
        if not _is_baselined(finding, baseline, path_matcher)
    ]


def annotate_baseline(findings: list[Finding], baseline: Baseline) -> list[Finding]:
    """
    Keeps baselined findings in reports but marks them non-blocking and
    `baseline_state="unchanged"`, as required for SARIF and --fail-on new.
    """
    path_matcher = PathMatcher(baseline.path_globs)
    return [
        replace(finding, baseline_state="unchanged", blocking=False)
        if _is_baselined(finding, baseline, path_matcher)
        else finding
        for finding in findings
    ]
