"""
core/git_diff.py
-----------------
Responsible for invoking `git diff --cached --unified=0` and parsing the
output into structured records of only the *added* lines in the staged
changeset. Commit Guard never scans the full repository — only what is
about to be committed.

Public API:
    get_staged_diff() -> list[DiffLine]
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class DiffLine:
    """A single added line from the staged diff."""
    file_path: str
    line_number: int
    code_content: str


# Matches the hunk header, e.g. "@@ -12,0 +13,2 @@"
# We only care about the "+start" part to know where added lines begin.
_HUNK_HEADER_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")

# Matches the "diff --git a/path b/path" line to recover file paths
# even when a file has no hunks shown yet (renames, binary, etc.).
_DIFF_HEADER_RE = re.compile(r"^diff --git a/(.+?) b/(.+)$")


class GitDiffError(RuntimeError):
    """Raised when git is unavailable or the diff command fails."""


def _run_git_diff(repo_dir: Path | None = None) -> str:
    """
    Executes `git diff --cached --unified=0` and returns raw stdout.

    --unified=0 removes context lines so we only ever see the lines that
    actually changed, which keeps false positives from unrelated
    surrounding code to a minimum and keeps scans fast.
    """
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--unified=0", "--no-color"],
            cwd=str(repo_dir) if repo_dir else None,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise GitDiffError(
            "git executable not found on PATH. Commit Guard requires git."
        ) from exc

    if result.returncode not in (0, 1):
        # git diff returns 1 when there ARE differences in some modes,
        # but with `diff --cached` a non-zero/non-one code indicates a
        # real error (e.g. not a git repository).
        raise GitDiffError(
            f"git diff failed (exit {result.returncode}): {result.stderr.strip()}"
        )

    return result.stdout


def _parse_diff(raw_diff: str) -> list[DiffLine]:
    """
    Parses raw unified diff text (unified=0) into a list of DiffLine
    records representing only newly added ('+') lines.

    Lines starting with '+++' are file headers, not content, and are
    always skipped.
    """
    diff_lines: list[DiffLine] = []

    current_file: str | None = None
    current_line_number: int | None = None

    for raw_line in raw_diff.splitlines():
        diff_header_match = _DIFF_HEADER_RE.match(raw_line)
        if diff_header_match:
            # New file section begins; reset tracking state.
            current_file = diff_header_match.group(2)
            current_line_number = None
            continue

        hunk_match = _HUNK_HEADER_RE.match(raw_line)
        if hunk_match:
            current_line_number = int(hunk_match.group(1))
            continue

        if raw_line.startswith("+++") or raw_line.startswith("---"):
            # File header lines (old/new path markers) — never content.
            continue

        if raw_line.startswith("+"):
            if current_file is None or current_line_number is None:
                # Malformed/unexpected state — skip defensively rather
                # than crash the whole scan.
                continue

            code_content = raw_line[1:]  # strip the leading '+'
            diff_lines.append(
                DiffLine(
                    file_path=current_file,
                    line_number=current_line_number,
                    code_content=code_content,
                )
            )
            current_line_number += 1
        elif raw_line.startswith("-"):
            # Removed line — does not consume a "new file" line number.
            continue
        # Any other line (e.g. "\ No newline at end of file") is ignored.

    return diff_lines


def get_staged_diff(repo_dir: Path | None = None) -> list[DiffLine]:
    """
    High-level entry point: fetch and parse the currently staged diff.

    Returns:
        A list of DiffLine objects, one per added line, in file order.
    """
    raw_diff = _run_git_diff(repo_dir=repo_dir)
    return _parse_diff(raw_diff)


def is_inside_git_repo(path: Path | None = None) -> bool:
    """Utility used by main.py to fail fast with a clear error message."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
            cwd=str(path) if path else None,
            check=False,
        )
    except FileNotFoundError:
        return False
    return result.returncode == 0 and result.stdout.strip() == "true"
