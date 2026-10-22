"""
core/paths.py
--------------
Path globbing and default exclusions.

Commit Guard deliberately avoids depending on third-party glob libraries.
`pathlib.PurePath.match()` has surprising "right-anchored" semantics
(`vendor/**` does not match `vendor/a/b.py`), so this module ships a small,
predictable glob engine used for include/exclude decisions.

Pattern rules (all case-insensitive, forward-slash normalized):

    vendor/**            matches `vendor/a.py` and `src/vendor/a/b.py`
    **/*.lock            matches `a/b.lock` and `b.lock`
    *.lock               matches any file named `*.lock`, at any depth
    src/*.py             matches `src/app.py`, not `src/pkg/app.py`
    /src/config.*        a leading `/` anchors the pattern to the repo root

Every pattern may be prefixed with `!` to negate it (re-include).  For
example, excluding `**/*.js` but re-including `src/**` lets teams scan
hand-written source while skipping generated bundles.
"""

from __future__ import annotations

import re
from pathlib import Path

# High-volume paths that almost never contain first-party secrets and can
# make a pre-commit hook painfully slow (or noisy).  Users can re-include
# any of these with a `!pattern` entry in config.
DEFAULT_EXCLUDES: tuple[str, ...] = (
    "**/node_modules/**",
    "**/vendor/**",
    "**/bower_components/**",
    "**/.venv/**",
    "**/venv/**",
    "**/__pycache__/**",
    "**/*.min.js",
    "**/*.min.css",
    "**/*.map",
    "**/*.lock",
    "**/package-lock.json",
    "**/pnpm-lock.yaml",
    "**/yarn.lock",
    "**/Pipfile.lock",
    "**/poetry.lock",
    "**/Cargo.lock",
    "**/go.sum",
    "**/composer.lock",
    "**/Gemfile.lock",
    "**/.commit_guard/**",
    "commit_guard_reports/**",
)

_BINARY_EXTENSIONS = frozenset(
    {
        ".bmp", ".class", ".dll", ".eot", ".exe", ".gif", ".ico", ".jar",
        ".jpeg", ".jpg", ".lockb", ".otf", ".pdf", ".png", ".pyc", ".pyd",
        ".so", ".svg", ".tiff", ".ttf", ".webp", ".woff", ".woff2", ".zip",
    }
)


def normalize_path(path: str | Path) -> str:
    """Returns a forward-slash path without a leading './'."""
    text = str(path).replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    return text.lstrip("/") if text.startswith("//") else text


def _segment_to_regex(segment: str) -> str:
    out: list[str] = []
    for char in segment:
        if char == "*":
            out.append("[^/]*")
        elif char == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(char))
    return "".join(out)


def glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Compiles a Commit Guard glob into an anchored regular expression."""
    pattern = normalize_path(pattern.strip())
    anchored = pattern.startswith("/")
    pattern = pattern.lstrip("/")

    if "/" not in pattern:
        body = _segment_to_regex(pattern)
        prefix = r"^(?:.*/)?" if not anchored else r"^"
        return re.compile(prefix + body + r"$", re.IGNORECASE)

    segments = pattern.split("/")
    parts: list[str] = []
    for index, segment in enumerate(segments):
        last = index == len(segments) - 1
        if segment == "**":
            parts.append(".*" if last else "(?:.*/)?")
        else:
            parts.append(_segment_to_regex(segment))
            if not last:
                parts.append("/")
    body = "".join(parts)
    prefix = r"^" if anchored else r"^(?:.*/)?"
    return re.compile(prefix + body + r"$", re.IGNORECASE)


class PathMatcher:
    """Matches repo-relative paths against an ordered include/exclude list."""

    def __init__(self, patterns: tuple[str, ...] | list[str] = ()) -> None:
        self._rules: list[tuple[bool, re.Pattern[str]]] = []
        for raw in patterns:
            text = raw.strip()
            if not text or text.startswith("#"):
                continue
            negated = text.startswith("!")
            if negated:
                text = text[1:].strip()
            if text:
                self._rules.append((negated, glob_to_regex(text)))

    def __bool__(self) -> bool:
        return bool(self._rules)

    def matches(self, path: str | Path) -> bool:
        """
        Returns True when `path` matches the patterns, honoring negation
        order (the last matching pattern wins).
        """
        normalized = normalize_path(path)
        matched = False
        for negated, regex in self._rules:
            if regex.match(normalized):
                matched = not negated
        return matched


def is_binary_path(path: str | Path) -> bool:
    """Cheap extension-based check; git already marks binary hunks as such."""
    return Path(str(path)).suffix.lower() in _BINARY_EXTENSIONS


def is_excluded(path: str | Path, patterns: tuple[str, ...] | list[str]) -> bool:
    """Convenience wrapper for one-off checks."""
    return PathMatcher(patterns).matches(path)
