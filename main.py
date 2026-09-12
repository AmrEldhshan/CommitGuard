#!/usr/bin/env python3
"""
main.py — Commit Guard scan engine.

This file has exactly one job: scan a repository's staged changes and
report the results. All install/uninstall/enable/disable/status logic
lives in install_hook.py — main.py never needs to know about hooks.

It is called two ways:
    1. Automatically, by the pre-commit hook that install_hook.py wrote.
    2. Manually, either directly (`python main.py`) or via the
       `commit-guard` / `commit-guard.bat` wrapper that install_hook.py
       places at the root of the repo it was installed into.

Usage:
    python main.py                          Scan the repo containing the CWD
    python main.py --repo /path/to/repo      Scan a specific repo
    python main.py --threshold medium        Block on medium+ severity (default: high)
    python main.py --quiet                   Suppress the terminal summary

Exit codes:
    0 — scan completed, no blocking findings
    1 — blocking findings were detected (commit should be aborted)
    2 — Commit Guard failed to run (bad repo, missing/broken rules, etc.)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Ensure this file's own directory is importable regardless of the
# caller's CWD — critical since this file is invoked from a git hook
# with an arbitrary working directory.
_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from core.git_diff import GitDiffError, get_staged_diff, is_inside_git_repo
from core.reporter import print_cli_summary, write_markdown_report
from core.rule_loader import RuleLoadError, load_all_rules
from core.scanner import has_blocking_findings, scan_diff

# Rules always ship alongside this file (main.py's own directory), so a
# self-contained install under some_repo/.commit_guard/ automatically
# finds some_repo/.commit_guard/rules/ with zero extra configuration.
DEFAULT_RULES_DIR = _PROJECT_ROOT / "rules"
VALID_THRESHOLDS = ("critical", "high", "medium", "low", "info")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="commit-guard-scan",
        description=(
            "Commit Guard scan engine — inspects staged git changes for "
            "secrets, SAST issues, and misconfigurations using local rule "
            "files only. Fully offline."
        ),
    )
    parser.add_argument(
        "--repo",
        type=Path,
        default=None,
        help="Path to the target git repository (default: current directory).",
    )
    parser.add_argument(
        "--rules-dir",
        type=Path,
        default=DEFAULT_RULES_DIR,
        help=f"Path to the rules directory (default: {DEFAULT_RULES_DIR}).",
    )
    parser.add_argument(
        "--report-path",
        type=Path,
        default=None,
        help="Where to write the Markdown report (default: <repo>/commit_guard_reports/report.md).",
    )
    parser.add_argument(
        "--threshold",
        choices=VALID_THRESHOLDS,
        default="high",
        help="Minimum severity that blocks the commit (default: high).",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress the CLI summary; only the exit code and report file are produced.",
    )
    # Accepted for backwards compatibility with older hooks; scanning is
    # now the only thing this file does, so the flag is a no-op.
    parser.add_argument("--scan", action="store_true", help=argparse.SUPPRESS)
    return parser


def run_scan(
    rules_dir: Path,
    report_path: Path | None,
    threshold: str,
    quiet: bool,
    repo_dir: Path | None = None,
) -> int:
    """Executes a full scan cycle on the target repository. Returns the process exit code."""
    target_repo = (repo_dir or Path.cwd()).resolve()

    if not is_inside_git_repo(target_repo):
        print(f"[commit-guard] ERROR: '{target_repo}' is not inside a git repository.", file=sys.stderr)
        return 2

    actual_report_path = report_path or (target_repo / "commit_guard_reports" / "report.md")

    try:
        diff_lines = get_staged_diff(repo_dir=target_repo)
    except GitDiffError as exc:
        print(f"[commit-guard] ERROR: {exc}", file=sys.stderr)
        return 2

    if not diff_lines:
        if not quiet:
            print(f"[commit-guard] [{target_repo.name}] No staged changes to scan. STATUS: PASSED ✅")
        write_markdown_report([], actual_report_path, threshold)
        return 0

    try:
        rules = load_all_rules(rules_dir)
    except RuleLoadError as exc:
        print(f"[commit-guard] ERROR: {exc}", file=sys.stderr)
        return 2

    findings = scan_diff(diff_lines, rules)
    written_path = write_markdown_report(findings, actual_report_path, threshold)

    if not quiet:
        print_cli_summary(findings, written_path, threshold)

    return 1 if has_blocking_findings(findings, threshold) else 0


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    return run_scan(
        rules_dir=args.rules_dir,
        report_path=args.report_path,
        threshold=args.threshold,
        quiet=args.quiet,
        repo_dir=args.repo,
    )


if __name__ == "__main__":
    sys.exit(main())
