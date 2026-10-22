"""
core/git_diff.py
-----------------
Invokes `git diff --cached --unified=0` and parses only the *added* lines
from the staged changeset.  Commit Guard never scans the full repository
by default — only what is about to be committed.

Public API:
    get_staged_diff() -> list[DiffLine]
    get_diff(revision) -> list[DiffLine]
    get_history_diff(revisions, max_commits=0) -> list[DiffLine]
    get_all_files() -> list[DiffLine]
    get_context_lines(paths, source="index") -> dict[str, list[str]]
    get_ignored_files(revision=None) -> set[str]
    is_inside_git_repo()
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

_MAX_CONTEXT_FILE_BYTES = 2 * 1024 * 1024
_MAX_CONTEXT_LINES = 50_000


@dataclass(frozen=True)
class DiffLine:
    """A single added line from the staged diff."""
    file_path: str
    line_number: int
    code_content: str


# "@@ -12,0 +13,2 @@" — only the "+start" is needed.
_HUNK_HEADER_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")

# "diff --git a/path b/path" — fallback when no +++ header is present.
_DIFF_HEADER_RE = re.compile(r'^diff --git "?a/(.+?)"? "?b/(.+?)"?$')

# "+++ b/path" / '+++ "b/path"' — the authoritative new-file path.
_NEW_FILE_RE = re.compile(r'^\+\+\+ (?:b/)?(.+)$')


class GitDiffError(RuntimeError):
    """Raised when git is unavailable or the diff command fails."""


def get_ignored_files(
    repo_dir: Path | None = None,
    revision: str | None = None,
    paths: list[str] | tuple[str, ...] | None = None,
) -> set[str]:
    """
    Returns repo-relative paths whose contents contain
    `commit-guard-ignore-file`.

    Staged content is searched by default; pass `revision` for CI scans so a
    file-wide directive keeps working on later commits. Paths are read from
    git's index/tree, not the working tree, so partially staged files behave
    correctly. Pass `paths` to limit the search to files present in the diff.
    """
    if paths is not None and not paths:
        return set()
    command = [
        "git",
        "-c",
        "core.quotePath=false",
        "--no-pager",
        "grep",
        "-l",
        "-z",
        "-i",
        "-F",
        "-e",
        "commit-guard-ignore-file",
    ]
    if revision is None:
        command.append("--cached")
    else:
        command.append(revision)
    command.append("--")
    if paths is None:
        command.append(".")
    else:
        command.extend(f":(literal){path}" for path in paths)

    try:
        result = subprocess.run(
            command,
            cwd=str(repo_dir) if repo_dir else None,
            capture_output=True,
            check=False,
        )
    except OSError as exc:
        raise GitDiffError(f"could not run git grep: {exc}") from exc

    if result.returncode == 1:
        return set()
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise GitDiffError(f"git grep failed: {message or 'unknown error'}")

    raw = result.stdout.decode("utf-8", errors="replace")
    return {path for path in raw.split("\0") if path}


def _git_command(*args: str) -> list[str]:
    # core.quotePath=false keeps non-ASCII paths readable instead of
    # emitting C-style octal escapes. --no-ext-diff/--no-textconv ensure
    # user-configured diff drivers cannot change what we scan.
    return [
        "git",
        "-c",
        "core.quotePath=false",
        "--no-pager",
        "diff",
        "--cached",
        "--unified=0",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        "--diff-filter=ACMR",
        *args,
    ]


def _run_git_diff(repo_dir: Path | None = None) -> str:
    try:
        result = subprocess.run(
            _git_command(),
            cwd=str(repo_dir) if repo_dir else None,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except FileNotFoundError as exc:
        raise GitDiffError(
            "git executable not found on PATH. Commit Guard requires git."
        ) from exc

    if result.returncode not in (0, 1):
        raise GitDiffError(
            f"git diff failed (exit {result.returncode}): {result.stderr.strip()}"
        )

    return result.stdout


def _unquote_git_path(path: str) -> str:
    """Decodes git's C-style quoted paths when core.quotePath could not help."""
    path = path.strip()
    if len(path) >= 2 and path.startswith('"') and path.endswith('"'):
        try:
            return bytes(path[1:-1], "utf-8").decode("unicode_escape")
        except (UnicodeDecodeError, UnicodeEncodeError):
            return path[1:-1]
    return path


def _parse_diff(raw_diff: str) -> list[DiffLine]:
    """
    Parses raw unified diff text into DiffLine records for '+' lines only.

    File paths come from the `+++ b/...` header when present (authoritative
    even when a path contains spaces), falling back to `diff --git`.
    """
    diff_lines: list[DiffLine] = []

    current_file: str | None = None
    pending_file: str | None = None
    current_line_number: int | None = None

    for raw_line in raw_diff.splitlines():
        diff_header_match = _DIFF_HEADER_RE.match(raw_line)
        if diff_header_match:
            pending_file = _unquote_git_path(diff_header_match.group(2))
            current_file = None
            current_line_number = None
            continue

        if raw_line.startswith("+++"):
            new_file_match = _NEW_FILE_RE.match(raw_line)
            if new_file_match:
                candidate = _unquote_git_path(new_file_match.group(1))
                current_file = None if candidate == "/dev/null" else candidate
            else:
                current_file = None
            current_line_number = None
            continue

        if raw_line.startswith("---"):
            continue

        hunk_match = _HUNK_HEADER_RE.match(raw_line)
        if hunk_match:
            if current_file is None:
                current_file = pending_file
            current_line_number = int(hunk_match.group(1))
            continue

        if raw_line.startswith("+"):
            if current_file is None or current_line_number is None:
                continue
            diff_lines.append(
                DiffLine(
                    file_path=current_file,
                    line_number=current_line_number,
                    code_content=raw_line[1:],
                )
            )
            current_line_number += 1
        elif raw_line.startswith(" "):
            # Context line — only present when a caller asked for context,
            # but it still consumes a line number in the new file.
            if current_line_number is not None:
                current_line_number += 1
        elif raw_line.startswith("-"):
            continue

    return diff_lines


def get_staged_diff(repo_dir: Path | None = None) -> list[DiffLine]:
    """Fetches and parses the currently staged diff."""
    return _parse_diff(_run_git_diff(repo_dir=repo_dir))


def get_diff(repo_dir: Path, revision: str) -> list[DiffLine]:
    """
    Returns added lines for an arbitrary revision range, e.g. `HEAD~1..HEAD`
    or `origin/main...HEAD`.  Used by `--diff` for CI pipelines.
    """
    try:
        result = subprocess.run(
            [
                "git",
                "-c",
                "core.quotePath=false",
                "--no-pager",
                "diff",
                "--unified=0",
                "--no-color",
                "--no-ext-diff",
                "--no-textconv",
                "--diff-filter=ACMR",
                revision,
            ],
            cwd=str(repo_dir),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except FileNotFoundError as exc:
        raise GitDiffError("git executable not found on PATH.") from exc

    if result.returncode != 0:
        raise GitDiffError(
            f"git diff failed for '{revision}' (exit {result.returncode}): "
            f"{result.stderr.strip()}"
        )
    return _parse_diff(result.stdout)


def get_history_diff(
    repo_dir: Path,
    revisions: str | list[str] | tuple[str, ...],
    max_commits: int = 0,
) -> list[DiffLine]:
    """
    Returns added lines from every non-merge commit in one or more revision
    ranges, using `git log -p`. This catches secrets that were added in an
    intermediate commit and removed again before the branch tip.
    """
    if isinstance(revisions, str):
        revisions = [revisions]
    revisions = [revision for revision in revisions if revision]
    if not revisions:
        return []
    command = [
        "git",
        "-c",
        "core.quotePath=false",
        "--no-pager",
        "log",
        "-p",
        "--unified=0",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        "--diff-filter=ACMR",
        "--no-merges",
        "--format=",
    ]
    if max_commits > 0:
        command.append(f"--max-count={max_commits}")
    command.extend(revisions)
    try:
        result = subprocess.run(
            command,
            cwd=str(repo_dir),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except FileNotFoundError as exc:
        raise GitDiffError("git executable not found on PATH.") from exc
    if result.returncode != 0:
        raise GitDiffError(
            f"git log failed (exit {result.returncode}): {result.stderr.strip()}"
        )
    return _parse_diff(result.stdout)


def get_all_files(repo_dir: Path) -> list[DiffLine]:
    """Returns every line of every tracked/untracked, non-ignored text file."""
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
            cwd=str(repo_dir),
            capture_output=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise GitDiffError("git executable not found on PATH.") from exc
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise GitDiffError(f"git ls-files failed: {message or 'unknown error'}")

    paths = sorted({path for path in result.stdout.decode("utf-8", "replace").split("\0") if path})
    lines: list[DiffLine] = []
    for relative in paths:
        full_path = repo_dir / relative
        try:
            if not full_path.is_file() or full_path.stat().st_size > _MAX_CONTEXT_FILE_BYTES:
                continue
            data = full_path.read_bytes()
        except OSError:
            continue
        if b"\0" in data[:8192]:
            continue
        text = data.decode("utf-8", errors="replace")
        for number, content in enumerate(text.splitlines(), start=1):
            lines.append(DiffLine(relative, number, content))
            if number >= _MAX_CONTEXT_LINES:
                break
    return lines


def get_context_lines(
    repo_dir: Path,
    paths: list[str] | tuple[str, ...] | set[str],
    source: str = "index",
) -> dict[str, list[str]]:
    """
    Reads bounded file context for multi-line rules. `source` is `index`
    (staged content), `worktree`, or a git revision. Missing/oversized files
    are skipped rather than breaking the scan.
    """
    contexts: dict[str, list[str]] = {}
    for relative in sorted(set(paths)):
        if source == "worktree":
            full_path = repo_dir / relative
            try:
                if not full_path.is_file() or full_path.stat().st_size > _MAX_CONTEXT_FILE_BYTES:
                    continue
                data = full_path.read_bytes()
            except OSError:
                continue
        else:
            spec = f":{relative}" if source == "index" else f"{source}:{relative}"
            try:
                result = subprocess.run(
                    ["git", "show", spec],
                    cwd=str(repo_dir),
                    capture_output=True,
                    check=False,
                )
            except FileNotFoundError as exc:
                raise GitDiffError("git executable not found on PATH.") from exc
            if result.returncode != 0 or len(result.stdout) > _MAX_CONTEXT_FILE_BYTES:
                continue
            data = result.stdout
        if b"\0" in data[:8192]:
            continue
        text = data.decode("utf-8", errors="replace")
        contexts[relative] = text.splitlines()[:_MAX_CONTEXT_LINES]
    return contexts


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


def find_repo_root(path: Path | None = None) -> Path | None:
    """Returns the work-tree root, or None when not inside a repository."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            cwd=str(path) if path else None,
            check=False,
        )
    except FileNotFoundError:
        return None
    if result.returncode != 0:
        return None
    return Path(result.stdout.strip())
