#!/usr/bin/env python3
"""
main.py — Commit Guard scan engine.

This file has exactly one job: scan a diff and report the results. All
install/uninstall/enable/disable/status logic lives in install_hook.py —
main.py never needs to know about hooks.

It is called two ways:
    1. Automatically, by the pre-commit hook that install_hook.py wrote.
    2. Manually, either directly (`python main.py`) or via the
       `commit-guard` / `commit-guard.bat` wrapper installed at the repo root.

Usage:
    python main.py                          Scan staged changes
    python main.py --repo /path/to/repo      Scan a specific repo
    python main.py --diff origin/main...HEAD Scan a CI revision range
    python main.py --history 50              Audit the last 50 commits
    python main.py --all                     Audit the whole working tree
    python main.py --pre-push                Audit refs supplied on stdin
    python main.py --threshold medium        Block on medium+ (default: high)
    python main.py --format both             Write report.md + report.json
    python main.py --format junit            Write report.junit.xml
    python main.py --update-baseline         Accept current findings into the baseline
    python main.py --format sarif            Write report.sarif
    python main.py --show-secrets            Do not redact secret values locally
    python main.py --init-config             Create .commit_guard.toml
    python main.py --list-rules              Print loaded rule IDs and exit
    python main.py --check-rules             Validate rules and corpus
    python main.py --explain RULE_ID         Show one rule's details

Configuration:
    `.commit_guard.toml` at the repo root (see docs/CONFIGURATION.md).
    CLI flags always win over the config file.

Baseline / allowlist:
    `.commit_guard_ignore` supports, one entry per line:
        rule-id                       suppress a rule everywhere
        rule:rule-id                  same, explicit form
        path:tests/fixtures/**        suppress every finding in matching paths
        fingerprint:0123456789abcdef  suppress one exact finding
        # comment

Inline suppression:
    # commit-guard-ignore
    # commit-guard-ignore: rule-id-one, rule-id-two
    # commit-guard-ignore-next-line
    # commit-guard-ignore-file

Exit codes:
    0 — no blocking findings
    1 — blocking findings detected (abort the commit)
    2 — Commit Guard failed to run (bad repo/config/rules)
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import time
from dataclasses import replace
from datetime import date
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

try:
    from core import __version__
    from core.ast_taint import TAINT_RULES, scan_python_taint
    from core.autofix import AutoFixError, apply_fixes
    from core.config import (
        CONFIG_FILENAME,
        VALID_DEP_GRAPH_FORMATS,
        VALID_FORMATS,
        VALID_THRESHOLDS,
        Config,
        ConfigError,
        default_config_text,
        load_config,
    )
    from core.dep_graph import build_dependency_graph, write_dependency_graph
    from core.git_diff import (
        DiffLine,
        GitDiffError,
        get_all_files,
        get_context_lines,
        get_diff,
        get_history_diff,
        get_ignored_files,
        get_staged_diff,
        is_inside_git_repo,
    )
    from core.pr_creator import (
        GitHubAPIError,
        GitHubClient,
        build_pr_body,
        options_from_environment,
        publish_inline_review,
        publish_report_pr,
        pull_request_context_from_environment,
    )
    from core.paths import PathMatcher
    from core.reporter import (
        build_markdown_report,
        print_cli_summary,
        print_github_annotations,
        write_checkstyle_report,
        write_gitlab_report,
        write_json_report,
        write_junit_report,
        write_markdown_report,
        write_sarif_report,
    )
    from core.rule_check import check_rules, explain_rule
    from core.rule_loader import (
        RuleLoadError,
        apply_severity_overrides,
        load_ruleset,
    )
    from core.sca import scan_dependencies
    from core.scanner import (
        Baseline,
        Finding,
        annotate_baseline,
        apply_baseline,
        apply_report_allowlist,
        has_blocking_findings,
        is_inline_suppressed,
        scan_diff,
    )
    from core.suppressions import (
        add_fingerprints,
        audit_entries,
        build_baseline,
        parse_baseline_entries,
    )
    from core.trends import (
        HISTORY_FILENAME,
        build_dependency_svg,
        load_history,
        make_trend_entry,
        record_history,
        write_html_report,
    )
except ImportError as exc:  # missing PyYAML or a corrupted install
    print(
        f"[commit-guard] ERROR: cannot load the scan engine ({exc}).",
        file=sys.stderr,
    )
    print(
        "Install dependencies with: python -m pip install pyyaml",
        file=sys.stderr,
    )
    raise SystemExit(2) from exc

DEFAULT_RULES_DIR = _PROJECT_ROOT / "rules"
BASELINE_FILENAME = ".commit_guard_ignore"



def load_baseline(path: Path) -> Baseline:
    """Parses a baseline/allowlist file. Missing file = empty baseline."""
    return build_baseline(parse_baseline_entries(path))


def _resolve_rules_dir(repo_root: Path, explicit: Path | None, config: Config) -> Path:
    if explicit is not None:
        return explicit.expanduser().resolve()
    if config.rules_dir is not None:
        path = config.rules_dir.expanduser()
        return path if path.is_absolute() else (repo_root / path).resolve()
    return DEFAULT_RULES_DIR


def _report_targets(
    repo_root: Path,
    config: Config,
    fmt: str,
    explicit_path: Path | None,
) -> dict[str, Path]:
    """
    Returns a mapping of format -> output path. `both` produces Markdown
    and JSON; an explicit --report-path is honored for single formats and
    gains sibling extensions for `both`.
    """
    suffixes = {
        "markdown": ".md",
        "json": ".json",
        "sarif": ".sarif",
        "junit": ".junit.xml",
        "gitlab": ".gitlab.json",
        "checkstyle": ".checkstyle.xml",
        "html": ".html",
    }
    if explicit_path is not None:
        path = explicit_path.expanduser()
        if fmt == "both":
            stem = path.with_suffix("")
            return {"markdown": stem.with_suffix(".md"), "json": stem.with_suffix(".json")}
        if path.suffix:
            return {fmt: path}
        return {fmt: path.with_suffix(suffixes[fmt])}

    report_dir = repo_root / config.report_dir
    if fmt == "both":
        return {"markdown": report_dir / "report.md", "json": report_dir / "report.json"}
    return {fmt: report_dir / f"report{suffixes[fmt]}"}


def _write_reports(
    targets: dict[str, Path],
    findings: list,
    threshold: str,
    *,
    show_secrets: bool,
    truncated: bool,
    dependency_graph: str | None = None,
) -> list[Path]:
    written: list[Path] = []
    if "markdown" in targets:
        written.append(
            write_markdown_report(
                findings,
                targets["markdown"],
                threshold,
                show_secrets=show_secrets,
                truncated=truncated,
                dependency_graph=dependency_graph,
            )
        )
    if "json" in targets:
        written.append(
            write_json_report(
                findings,
                targets["json"],
                threshold,
                show_secrets=show_secrets,
                truncated=truncated,
            )
        )
    if "sarif" in targets:
        written.append(
            write_sarif_report(
                findings,
                targets["sarif"],
                threshold,
                show_secrets=show_secrets,
            )
        )
    if "junit" in targets:
        written.append(
            write_junit_report(
                findings,
                targets["junit"],
                threshold,
                show_secrets=show_secrets,
            )
        )
    if "gitlab" in targets:
        written.append(
            write_gitlab_report(
                findings,
                targets["gitlab"],
                threshold,
                show_secrets=show_secrets,
            )
        )
    if "checkstyle" in targets:
        written.append(
            write_checkstyle_report(
                findings,
                targets["checkstyle"],
                threshold,
                show_secrets=show_secrets,
            )
        )
    return written


def _write_dependency_outputs(
    repo_root: Path,
    config: Config,
    findings: list,
    vulnerable_packages: set[str] | None = None,
) -> tuple[list[Path], str | None, object | None]:
    """Builds the graph once and returns (written files, markdown, graph)."""
    if not config.dep_graph:
        return [], None, None
    graph = build_dependency_graph(repo_root)
    vulnerable_files = {finding.file for finding in findings}
    vulnerable_packages = vulnerable_packages or set()
    output_dir = repo_root / config.report_dir
    written = write_dependency_graph(
        graph,
        output_dir,
        config.dep_graph_format,
        vulnerable_files=vulnerable_files,
        vulnerable_packages=vulnerable_packages,
        max_nodes=config.dep_graph_max_nodes,
    )
    markdown = graph.to_mermaid(
        vulnerable_files=vulnerable_files,
        vulnerable_packages=vulnerable_packages,
        max_nodes=config.dep_graph_max_nodes,
    )
    return written, markdown, graph


def _write_html_outputs(
    repo_root: Path,
    targets: dict[str, Path],
    findings: list,
    threshold: str,
    *,
    show_secrets: bool,
    truncated: bool,
    dependency_graph: object | None,
) -> list[Path]:
    if "html" not in targets:
        return []
    history_path = targets["html"].parent / HISTORY_FILENAME
    history = load_history(history_path)
    history = record_history(history_path, make_trend_entry(findings, threshold))
    graph = dependency_graph or build_dependency_graph(repo_root)
    dependency_svg = None
    if getattr(graph, "nodes", None):
        dependency_svg = build_dependency_svg(
            graph,
            vulnerable_files={finding.file for finding in findings},
        )
    written = write_html_report(
        findings,
        targets["html"],
        threshold,
        history=history,
        dependency_svg=dependency_svg,
        show_secrets=show_secrets,
        truncated=truncated,
    )
    return [written]


def _maybe_create_pr(
    findings: list,
    dependency_markdown: str | None,
    threshold: str,
    *,
    base: str | None,
    branch: str | None,
    title: str | None,
    report_dir: str,
) -> int:
    """Publishes a report PR and returns 0 on success, 2 on failure."""
    try:
        options = options_from_environment(
            base=base,
            branch=branch,
            title=title,
            report_path=f"{report_dir.rstrip('/')}/report.md",
        )
        client = GitHubClient(options.token, api_url=options.api_url)
        body = build_pr_body(
            findings,
            dependency_graph=dependency_markdown,
            block_threshold=threshold,
        )
        report_content = build_markdown_report(
            findings,
            threshold,
            show_secrets=False,
            dependency_graph=dependency_markdown,
        )
        result = publish_report_pr(
            client,
            options,
            findings=findings,
            report_content=report_content,
            body=body,
        )
    except GitHubAPIError as exc:
        print(f"[commit-guard] ERROR: could not create PR: {exc}", file=sys.stderr)
        return 2
    for warning in result.warnings:
        print(f"[commit-guard] WARNING: {warning}", file=sys.stderr)
    action = "Created" if result.created else "Updated"
    print(
        f"[commit-guard] {action} {'draft ' if result.draft else ''}PR "
        f"#{result.number}: {result.url or '(no URL returned)'}"
    )
    return 0


def _maybe_review_pr(findings: list, rules: tuple) -> int:
    """Posts inline suggestions on the originating PR and returns 0 or 2."""
    try:
        options = options_from_environment()
        context = pull_request_context_from_environment()
        if context.number is None:
            raise GitHubAPIError(
                "Could not determine the pull request number from GITHUB_EVENT_PATH "
                "or GITHUB_REF."
            )
        client = GitHubClient(options.token, api_url=options.api_url)
        result = publish_inline_review(
            client,
            options.repository,
            context.number,
            findings=findings,
            rules=rules,
            commit_id=context.commit_id,
        )
    except GitHubAPIError as exc:
        print(
            f"[commit-guard] ERROR: could not post inline review: {exc}",
            file=sys.stderr,
        )
        return 2
    for warning in result.warnings:
        print(f"[commit-guard] WARNING: {warning}", file=sys.stderr)
    if result.posted:
        print(
            f"[commit-guard] Posted {result.posted} inline suggestion(s) "
            f"on PR #{context.number}."
        )
    elif result.skipped:
        print(
            f"[commit-guard] Inline review already up to date "
            f"({result.skipped} suggestion(s) skipped)."
        )
    else:
        print("[commit-guard] No auto-fixable inline suggestions.")
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="commit-guard-scan",
        description=(
            "Commit Guard scan engine — inspects git changes for secrets, SAST "
            "issues, and misconfigurations using local rule files. Fully offline."
        ),
    )
    parser.add_argument("--repo", type=Path, default=None,
                        help="Path to the target git repository (default: current directory).")
    parser.add_argument("--rules-dir", type=Path, default=None,
                        help=f"Rules directory (default: {DEFAULT_RULES_DIR}).")
    parser.add_argument("--config", type=Path, default=None,
                        help=f"Config file (default: <repo>/{CONFIG_FILENAME}).")
    parser.add_argument("--no-config", action="store_true",
                        help="Ignore .commit_guard.toml and use defaults.")
    parser.add_argument("--report-path", type=Path, default=None,
                        help="Explicit report path (extension derived for --format both).")
    parser.add_argument("--format", choices=VALID_FORMATS, default=None,
                        help="Report format: markdown, json, sarif, both, junit, gitlab, checkstyle.")
    parser.add_argument("--threshold", choices=VALID_THRESHOLDS, default=None,
                        help="Minimum severity that blocks the commit (default: high).")
    scan_modes = parser.add_mutually_exclusive_group()
    scan_modes.add_argument("--diff", metavar="REV",
                        help="Scan a revision range instead of staged changes, e.g. origin/main...HEAD.")
    scan_modes.add_argument("--history", type=int, metavar="N", default=None,
                        help="Audit commits (N=0 means full history).")
    scan_modes.add_argument("--all", action="store_true",
                        help="Audit every tracked/untracked text file in the working tree.")
    scan_modes.add_argument("--pre-push", action="store_true",
                        help="Read ref lines from stdin and audit every commit being pushed.")
    parser.add_argument("--baseline", type=Path, default=None,
                        help=f"Baseline file (default: <repo>/{BASELINE_FILENAME}).")
    parser.add_argument("--no-baseline", action="store_true",
                        help="Ignore the baseline/allowlist file entirely.")
    parser.add_argument("--soft-fail", action="store_true",
                        help="Report findings but exit 0 (operational errors still exit 2).")
    parser.add_argument("--fail-on", choices=("all", "new"), default=None,
                        help="Block on all findings (default) or only findings new to the baseline.")
    parser.add_argument("--update-baseline", action="store_true",
                        help="Add current findings to .commit_guard_ignore and exit 0.")
    parser.add_argument("--baseline-owner", metavar="NAME",
                        help="Owner metadata to attach to newly baselined fingerprints.")
    parser.add_argument("--baseline-expiry", metavar="YYYY-MM-DD",
                        help="Expiry metadata to attach to newly baselined fingerprints.")
    parser.add_argument("--no-placeholder-filter", action="store_true",
                        help="Report obvious example/dummy secret values too.")
    dep_graph_group = parser.add_mutually_exclusive_group()
    dep_graph_group.add_argument("--dep-graph", action="store_true", dest="dep_graph",
                        default=None, help="Write a dependency/blast-radius graph.")
    dep_graph_group.add_argument("--no-dep-graph", action="store_false", dest="dep_graph",
                        default=None, help="Disable dependency graph generation.")
    parser.add_argument("--dep-graph-format", choices=VALID_DEP_GRAPH_FORMATS, default=None,
                        help="Dependency graph format: mermaid, json, dot, or all.")
    parser.add_argument("--dep-graph-max-nodes", type=int, metavar="N", default=None,
                        help="Maximum nodes rendered in Mermaid/DOT output (default: 250).")
    sca_group = parser.add_mutually_exclusive_group()
    sca_group.add_argument("--sca", action="store_true", dest="sca", default=None,
                        help="Check pinned dependencies against OSV advisory data.")
    sca_group.add_argument("--no-sca", action="store_false", dest="sca", default=None,
                        help="Disable software composition analysis.")
    parser.add_argument("--sca-online", action="store_true", default=None,
                        help="Query the free OSV.dev API instead of an offline snapshot.")
    parser.add_argument("--sca-snapshot", type=Path, default=None,
                        help="Offline OSV JSON snapshot (default: <repo>/.commit_guard_osv.json).")
    parser.add_argument("--sca-timeout", type=int, metavar="SECONDS", default=None,
                        help="Timeout for OSV.dev requests (default: 20).")
    fix_group = parser.add_mutually_exclusive_group()
    fix_group.add_argument("--fix", action="store_true", dest="fix", default=None,
                        help="Apply safe rule auto-fixes and re-stage modified files.")
    fix_group.add_argument("--fix-dry-run", action="store_true", dest="fix_dry_run",
                        default=None, help="Preview auto-fixes without writing files.")
    parser.add_argument("--create-pr", action="store_true",
                        help="Create or update a report-only GitHub PR (needs GITHUB_TOKEN).")
    parser.add_argument("--pr-base", metavar="BRANCH", default=None,
                        help="Target branch for --create-pr (default: GITHUB_BASE_REF or main).")
    parser.add_argument("--pr-branch", metavar="BRANCH", default=None,
                        help="Report branch for --create-pr (default: commitguard/security-report).")
    parser.add_argument("--pr-title", metavar="TITLE", default=None,
                        help="Title for the generated pull request.")
    parser.add_argument("--review-pr", action="store_true",
                        help="Post inline auto-fix suggestions on the originating pull request.")
    parser.add_argument("--audit-suppressions", action="store_true",
                        help="Audit .commit_guard_ignore entries for expiry/staleness.")
    parser.add_argument("--strict", action="store_true",
                        help="With --audit-suppressions, exit 1 when issues are found.")
    parser.add_argument("--show-secrets", action="store_true",
                        help="Include raw secret values in local reports (redacted by default).")
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress the CLI summary; exit code and report files remain.")
    parser.add_argument("--verbose-rules", action="store_true",
                        help="List every skipped rule and why (diagnostics).")
    parser.add_argument("--no-cache", action="store_true",
                        help="Disable the parsed-rule disk cache.")
    parser.add_argument("--github-annotations", action="store_true",
                        help="Emit GitHub Actions annotations (automatic when GITHUB_ACTIONS=true).")
    parser.add_argument("--init-config", action="store_true",
                        help=f"Write a commented {CONFIG_FILENAME} template and exit.")
    parser.add_argument("--force", action="store_true",
                        help="With --init-config, overwrite an existing config file.")
    parser.add_argument("--list-rules", action="store_true",
                        help="Print loaded rule IDs grouped by source and exit.")
    parser.add_argument("--check-rules", action="store_true",
                        help="Validate rule schema and positive/negative corpus samples and exit.")
    parser.add_argument("--corpus", type=Path, default=None,
                        help="Corpus YAML for --check-rules (default: <rules>/corpus.yaml).")
    parser.add_argument("--explain", metavar="RULE_ID", default=None,
                        help="Show details for one rule and exit.")
    parser.add_argument("--version", action="version", version=f"Commit Guard {__version__}")
    # Backwards compatibility with older hooks.
    parser.add_argument("--scan", action="store_true", help=argparse.SUPPRESS)
    return parser


def _list_rules(rules_dir: Path, verbose: bool, use_cache: bool) -> int:
    try:
        ruleset = load_ruleset(
            rules_dir, warn=False, verbose=verbose, use_cache=use_cache
        )
    except RuleLoadError as exc:
        print(f"[commit-guard] ERROR: {exc}", file=sys.stderr)
        return 2

    by_source: dict[str, list[str]] = {}
    for rule in ruleset.rules:
        by_source.setdefault(rule.source, []).append(rule.rule_id)
    by_source["python_ast"] = list(TAINT_RULES)
    for source in sorted(by_source):
        ids = by_source[source]
        print(f"{source} ({len(ids)}):")
        for rule_id in sorted(ids):
            print(f"  {rule_id}")
    print(f"\nTotal active rules: {len(ruleset.rules) + len(TAINT_RULES)}")
    if ruleset.skipped:
        print(f"Skipped entries: {len(ruleset.skipped)} (use --verbose-rules for details)")
    return 0


def _init_config(repo_root: Path, force: bool) -> int:
    path = repo_root / CONFIG_FILENAME
    if path.exists() and not force:
        print(f"[commit-guard] {path} already exists (use --init-config --force to overwrite).")
        return 0
    try:
        path.write_text(default_config_text(), encoding="utf-8")
    except OSError as exc:
        print(f"[commit-guard] ERROR: could not write {path}: {exc}", file=sys.stderr)
        return 2
    print(f"[commit-guard] Wrote {path}")
    return 0


def _pre_push_ranges(text: str) -> list[tuple[str, int]]:
    """Parses pre-push stdin into (revision-range, commit-limit) pairs."""
    ranges: list[tuple[str, int]] = []
    saw_ref = False
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        saw_ref = True
        local_sha, remote_sha = parts[1], parts[3]
        if not local_sha or all(char == "0" for char in local_sha):
            continue
        if all(char == "0" for char in remote_sha):
            ranges.append((local_sha, 0))
        else:
            ranges.append((f"{remote_sha}..{local_sha}", 0))
    if saw_ref:
        return ranges
    return [("HEAD", 100)]


def _dedupe_diff_lines(lines: list) -> list:
    seen: set[tuple[str, int, str]] = set()
    unique: list = []
    for line in lines:
        key = (line.file_path, line.line_number, line.code_content)
        if key in seen:
            continue
        seen.add(key)
        unique.append(line)
    return unique


def _scan_python_taint(
    files: dict[str, list[str]] | None,
    diff_lines: list[DiffLine],
    *,
    ignore_inline: bool,
    ignored_files: set[str],
    ignored_rule_ids: set[str],
    path_excludes: tuple[str, ...],
    path_allowlist_regexes: tuple[re.Pattern[str], ...],
    severity_overrides: dict[str, str],
) -> list[Finding]:
    changed_lines: dict[str, set[int]] = {}
    for diff_line in diff_lines:
        changed_lines.setdefault(diff_line.file_path, set()).add(diff_line.line_number)
    result = scan_python_taint(files or {}, changed_lines)
    for warning in result.warnings:
        print(f"[commit-guard] AST WARNING: {warning}", file=sys.stderr)

    excluded = PathMatcher(path_excludes)
    findings: list[Finding] = []
    for match in result.matches:
        finding = match.finding
        lines = (files or {}).get(finding.file, [])
        changed = changed_lines.get(finding.file, set())
        if (
            finding.file in ignored_files
            or finding.rule_id in ignored_rule_ids
            or excluded.matches(finding.file)
            or any(pattern.search(finding.file) for pattern in path_allowlist_regexes)
        ):
            continue
        if is_inline_suppressed(
            lines,
            finding.line_number,
            finding.rule_id,
            changed_lines=changed,
            ignore_inline=ignore_inline,
        ) or is_inline_suppressed(
            lines,
            match.sink_line,
            finding.rule_id,
            changed_lines=changed,
            ignore_inline=ignore_inline,
        ):
            continue
        findings.append(
            replace(
                finding,
                severity=severity_overrides.get(finding.rule_id, finding.severity),
            )
        )
    return findings


def run_scan(
    rules_dir: Path | None = None,
    report_path: Path | None = None,
    threshold: str | None = None,
    quiet: bool = False,
    repo_dir: Path | None = None,
    fmt: str | None = None,
    use_baseline: bool = True,
    *,
    config_file: Path | None = None,
    use_config: bool = True,
    show_secrets: bool = False,
    verbose_rules: bool = False,
    use_cache: bool = True,
    diff_revision: str | None = None,
    history: int | None = None,
    scan_all: bool = False,
    pre_push: bool = False,
    baseline_path: Path | None = None,
    github_annotations: bool = False,
    soft_fail: bool | None = None,
    fail_on: str | None = None,
    update_baseline: bool = False,
    baseline_owner: str | None = None,
    baseline_expiry: str | None = None,
    audit_suppressions: bool = False,
    strict: bool = False,
    filter_placeholders: bool | None = None,
    dep_graph: bool | None = None,
    dep_graph_format: str | None = None,
    dep_graph_max_nodes: int | None = None,
    sca: bool | None = None,
    sca_online: bool | None = None,
    sca_snapshot: Path | None = None,
    sca_timeout: int | None = None,
    fix: bool | None = None,
    fix_dry_run: bool | None = None,
    create_pr: bool = False,
    pr_base: str | None = None,
    pr_branch: str | None = None,
    pr_title: str | None = None,
    review_pr: bool = False,
) -> int:
    """Executes a full scan cycle. Returns the process exit code."""
    started = time.perf_counter()
    target_repo = (repo_dir or Path.cwd()).resolve()

    if not is_inside_git_repo(target_repo):
        print(f"[commit-guard] ERROR: '{target_repo}' is not inside a git repository.", file=sys.stderr)
        return 2

    if baseline_expiry:
        try:
            date.fromisoformat(baseline_expiry)
        except ValueError:
            print(
                "[commit-guard] ERROR: --baseline-expiry must use YYYY-MM-DD.",
                file=sys.stderr,
            )
            return 2

    resolved_config_path = config_file
    if resolved_config_path is not None:
        resolved_config_path = resolved_config_path.expanduser()
        if not resolved_config_path.is_absolute():
            resolved_config_path = (target_repo / resolved_config_path).resolve()

    try:
        config = load_config(
            target_repo,
            explicit_path=resolved_config_path,
            use_config=use_config,
        )
    except ConfigError as exc:
        print(f"[commit-guard] ERROR: {exc}", file=sys.stderr)
        return 2

    config = config.with_overrides(
        threshold=threshold,
        format=fmt,
        report_path=report_path,
        redact=(False if show_secrets else None),
        soft_fail=(True if soft_fail else None),
        fail_on=fail_on,
        filter_placeholders=filter_placeholders,
        dep_graph=dep_graph,
        dep_graph_format=dep_graph_format,
        dep_graph_max_nodes=dep_graph_max_nodes,
        sca=sca,
        sca_online=sca_online,
        sca_snapshot=sca_snapshot,
        sca_timeout=sca_timeout,
        fix=fix,
        fix_dry_run=fix_dry_run,
    )
    if config.dep_graph_max_nodes < 1:
        print(
            "[commit-guard] ERROR: --dep-graph-max-nodes must be a positive integer.",
            file=sys.stderr,
        )
        return 2
    if config.sca_timeout < 1:
        print(
            "[commit-guard] ERROR: --sca-timeout must be a positive integer.",
            file=sys.stderr,
        )
        return 2
    effective_fix = config.fix or config.fix_dry_run
    if effective_fix and update_baseline:
        print(
            "[commit-guard] ERROR: --fix cannot be combined with --update-baseline.",
            file=sys.stderr,
        )
        return 2
    effective_threshold = config.threshold
    effective_format = config.format
    effective_show_secrets = show_secrets or not config.redact
    effective_soft_fail = bool(config.soft_fail)

    resolved_rules_dir = _resolve_rules_dir(target_repo, rules_dir, config)
    effective_report_path = config.report_path
    if effective_report_path is not None and not effective_report_path.is_absolute():
        effective_report_path = (target_repo / effective_report_path).resolve()
    targets = _report_targets(target_repo, config, effective_format, effective_report_path)

    resolved_baseline_path = baseline_path
    if resolved_baseline_path is not None:
        resolved_baseline_path = resolved_baseline_path.expanduser()
        if not resolved_baseline_path.is_absolute():
            resolved_baseline_path = (target_repo / resolved_baseline_path).resolve()
    else:
        resolved_baseline_path = target_repo / BASELINE_FILENAME

    baseline = Baseline()
    if use_baseline or update_baseline or audit_suppressions:
        try:
            baseline = load_baseline(resolved_baseline_path)
        except OSError as exc:
            print(
                f"[commit-guard] ERROR: could not read baseline "
                f"{resolved_baseline_path}: {exc}",
                file=sys.stderr,
            )
            return 2

    staged_scan = not (diff_revision or history is not None or scan_all or pre_push)
    if audit_suppressions:
        staged_scan = False
        scan_all = True

    try:
        if pre_push:
            stdin_text = "" if sys.stdin.isatty() else sys.stdin.read()
            collected = []
            for revision, limit in _pre_push_ranges(stdin_text):
                collected.extend(
                    get_history_diff(target_repo, revision, max_commits=limit)
                )
            diff_lines = _dedupe_diff_lines(collected)
        elif history is not None:
            if history < 0:
                print("[commit-guard] ERROR: --history must be zero or positive.", file=sys.stderr)
                return 2
            diff_lines = get_history_diff(
                target_repo, "HEAD", max_commits=history
            )
        elif scan_all:
            diff_lines = get_all_files(target_repo)
        elif diff_revision:
            diff_lines = get_diff(target_repo, diff_revision)
        else:
            diff_lines = get_staged_diff(repo_dir=target_repo)
        changed_paths = sorted({line.file_path for line in diff_lines})
        ignored_files = set()
        if config.ignore_inline:
            try:
                ignored_files = get_ignored_files(
                    target_repo,
                    revision=None if staged_scan else "HEAD",
                    paths=changed_paths,
                )
            except GitDiffError:
                if staged_scan:
                    raise
                ignored_files = set()
    except GitDiffError as exc:
        print(f"[commit-guard] ERROR: {exc}", file=sys.stderr)
        return 2

    try:
        ruleset = load_ruleset(
            resolved_rules_dir,
            warn=config.warn_skipped_rules and not quiet,
            verbose=verbose_rules,
            use_cache=use_cache,
        )
    except RuleLoadError as exc:
        print(f"[commit-guard] ERROR: {exc}", file=sys.stderr)
        return 2

    ruleset = apply_severity_overrides(ruleset, config.severity_overrides)

    if audit_suppressions:
        findings = scan_diff(
            diff_lines,
            ruleset.rules,
            allowlist_regexes=ruleset.line_allowlist,
            allowlist_path_regexes=ruleset.path_allowlist,
            path_excludes=config.exclude,
            ignore_inline=config.ignore_inline,
            ignored_files=ignored_files,
            filter_placeholders=config.filter_placeholders,
        )
        python_paths = [
            path for path in changed_paths if path.lower().endswith((".py", ".pyi"))
        ]
        if python_paths:
            try:
                audit_file_lines = get_context_lines(
                    target_repo, python_paths, source="worktree"
                )
            except GitDiffError as exc:
                print(
                    f"[commit-guard] ERROR: could not read Python files for AST analysis: {exc}",
                    file=sys.stderr,
                )
                return 2
            findings.extend(
                _scan_python_taint(
                    audit_file_lines,
                    diff_lines,
                    ignore_inline=config.ignore_inline,
                    ignored_files=ignored_files,
                    ignored_rule_ids=set(),
                    path_excludes=config.exclude,
                    path_allowlist_regexes=ruleset.path_allowlist,
                    severity_overrides=config.severity_overrides,
                )
            )
        entries = parse_baseline_entries(resolved_baseline_path)
        issues = audit_entries(
            entries,
            known_rule_ids={rule.rule_id for rule in ruleset.rules} | set(TAINT_RULES),
            tracked_paths=set(changed_paths),
            current_fingerprints={finding.fingerprint for finding in findings},
        )
        print(
            f"[commit-guard] Suppression audit: {len(entries)} entries, "
            f"{len(issues)} issue(s)."
        )
        for issue in issues:
            print(f"  - {issue}")
        return 1 if (strict and issues) else 0

    if not diff_lines and not config.sca:
        dependency_paths: list[Path] = []
        dependency_markdown = None
        dependency_graph = None
        try:
            dependency_paths, dependency_markdown, dependency_graph = (
                _write_dependency_outputs(target_repo, config, [])
            )
        except (OSError, ValueError) as exc:
            print(
                f"[commit-guard] WARNING: could not write dependency graph: {exc}",
                file=sys.stderr,
            )
        try:
            written = _write_reports(
                targets,
                [],
                effective_threshold,
                show_secrets=effective_show_secrets,
                truncated=False,
                dependency_graph=dependency_markdown,
            )
            written.extend(
                _write_html_outputs(
                    target_repo,
                    targets,
                    [],
                    effective_threshold,
                    show_secrets=effective_show_secrets,
                    truncated=False,
                    dependency_graph=dependency_graph,
                )
            )
        except OSError as exc:
            print(f"[commit-guard] ERROR: could not write report: {exc}", file=sys.stderr)
            return 2
        written.extend(dependency_paths)
        if not quiet:
            label = f" [{target_repo.name}]"
            print(
                f"[commit-guard]{label} No changed lines to scan. "
                f"STATUS: PASSED ✅"
            )
        if written and not quiet:
            print(f"[commit-guard] Report: {written[0]}")
            for path in written[1:]:
                print(f"[commit-guard] Report: {path}")
        if create_pr:
            pr_code = _maybe_create_pr(
                [],
                dependency_markdown,
                effective_threshold,
                base=pr_base,
                branch=pr_branch,
                title=pr_title,
                report_dir=config.report_dir,
            )
            if pr_code:
                return pr_code
        return 0

    changed_python_paths = {
        path for path in changed_paths if path.lower().endswith((".py", ".pyi"))
    }
    python_paths = (
        changed_python_paths if history is None and not pre_push else set()
    )
    if changed_python_paths and not python_paths:
        print(
            "[commit-guard] AST INFO: Python taint analysis is skipped for "
            "history and pre-push scans.",
            file=sys.stderr,
        )
    file_lines = None
    if any(rule.context_regexes for rule in ruleset.rules) or python_paths:
        try:
            file_lines = get_context_lines(
                target_repo,
                changed_paths,
                source="index" if staged_scan else "worktree",
            )
        except GitDiffError as exc:
            if python_paths:
                print(
                    f"[commit-guard] ERROR: could not read Python files for AST analysis: {exc}",
                    file=sys.stderr,
                )
                return 2
            file_lines = None

    ignored_rule_ids = set(baseline.rule_ids) | set(config.allowlist_rules)
    scan_limit = config.max_findings + 1 if config.max_findings else 0

    findings = scan_diff(
        diff_lines,
        ruleset.rules,
        ignored_rule_ids=ignored_rule_ids,
        allowlist_regexes=ruleset.line_allowlist,
        allowlist_path_regexes=ruleset.path_allowlist,
        path_excludes=config.exclude,
        ignore_inline=config.ignore_inline,
        max_findings=scan_limit,
        ignored_files=ignored_files,
        filter_placeholders=config.filter_placeholders,
        file_lines=file_lines,
        detect_ignore_file=history is None and not pre_push,
    )

    if python_paths and history is None and not pre_push:
        findings.extend(
            _scan_python_taint(
                file_lines,
                diff_lines,
                ignore_inline=config.ignore_inline,
                ignored_files=ignored_files,
                ignored_rule_ids=ignored_rule_ids,
                path_excludes=config.exclude,
                path_allowlist_regexes=ruleset.path_allowlist,
                severity_overrides=config.severity_overrides,
            )
        )

    sca_result = None
    if config.sca:
        sca_snapshot_path = config.sca_snapshot
        if sca_snapshot_path is not None:
            sca_snapshot_path = sca_snapshot_path.expanduser()
            if not sca_snapshot_path.is_absolute():
                sca_snapshot_path = (target_repo / sca_snapshot_path).resolve()
        sca_result = scan_dependencies(
            target_repo,
            online=config.sca_online,
            snapshot_path=sca_snapshot_path,
            timeout=config.sca_timeout,
        )
        findings.extend(sca_result.to_findings())
        if not quiet:
            print(
                f"[commit-guard] SCA: {len(sca_result.packages)} pinned package(s), "
                f"{len(sca_result.vulnerabilities)} vulnerable "
                f"({'online' if config.sca_online else 'offline'})."
            )
            for warning in sca_result.warnings:
                print(f"[commit-guard] SCA WARNING: {warning}", file=sys.stderr)

    truncated = bool(config.max_findings and len(findings) > config.max_findings)
    if truncated:
        findings = findings[: config.max_findings]

    findings = apply_report_allowlist(findings, config.report_allowlist)

    combined_globs = tuple(baseline.path_globs) + tuple(config.allowlist_paths)
    effective_baseline = Baseline(
        rule_ids=set(baseline.rule_ids),
        path_globs=combined_globs,
        fingerprints=set(baseline.fingerprints),
    )
    has_baseline = bool(
        effective_baseline.rule_ids
        or effective_baseline.path_globs
        or effective_baseline.fingerprints
    )

    if update_baseline:
        try:
            remaining = apply_baseline(findings, effective_baseline)
            added = add_fingerprints(
                resolved_baseline_path,
                [finding.fingerprint for finding in remaining],
                owner=baseline_owner,
                expiry=baseline_expiry,
            )
            baseline = load_baseline(resolved_baseline_path)
        except OSError as exc:
            print(
                f"[commit-guard] ERROR: could not update baseline "
                f"{resolved_baseline_path}: {exc}",
                file=sys.stderr,
            )
            return 2
        effective_baseline = Baseline(
            rule_ids=set(baseline.rule_ids),
            path_globs=tuple(baseline.path_globs) + tuple(config.allowlist_paths),
            fingerprints=set(baseline.fingerprints),
        )
        has_baseline = True
        findings = annotate_baseline(findings, effective_baseline)
        if not quiet:
            print(
                f"[commit-guard] Baseline updated with {added} new fingerprint(s): "
                f"{resolved_baseline_path}"
            )
    elif has_baseline and (config.fail_on == "new"):
        findings = annotate_baseline(findings, effective_baseline)
    elif has_baseline:
        findings = apply_baseline(findings, effective_baseline)

    autofix_result = None
    if effective_fix:
        try:
            autofix_result = apply_fixes(
                target_repo,
                findings,
                ruleset.rules,
                dry_run=config.fix_dry_run,
            )
        except AutoFixError as exc:
            print(f"[commit-guard] ERROR: auto-fix failed: {exc}", file=sys.stderr)
            return 2
        if not config.fix_dry_run:
            findings = [
                finding
                for finding in findings
                if finding.fingerprint not in autofix_result.fixed_fingerprints
            ]
        if not quiet and autofix_result.outcomes:
            verb = "Would fix" if config.fix_dry_run else "Fixed"
            print(
                f"[commit-guard] {verb} {len(autofix_result.outcomes)} finding(s) "
                f"in {len({item.file for item in autofix_result.outcomes})} file(s)."
            )
            for outcome in autofix_result.outcomes[:20]:
                print(
                    f"  - {outcome.file}:{outcome.line} {outcome.rule_id}: "
                    f"{outcome.before.strip()} -> {outcome.after.strip()}"
                )
        elif not quiet:
            print("[commit-guard] No auto-fixable findings.")

    dependency_paths = []
    dependency_markdown = None
    dependency_graph = None
    try:
        dependency_paths, dependency_markdown, dependency_graph = (
            _write_dependency_outputs(
                target_repo,
                config,
                findings,
                sca_result.package_names if sca_result else None,
            )
        )
    except (OSError, ValueError) as exc:
        print(
            f"[commit-guard] WARNING: could not write dependency graph: {exc}",
            file=sys.stderr,
        )

    try:
        written = _write_reports(
            targets,
            findings,
            effective_threshold,
            show_secrets=effective_show_secrets,
            truncated=truncated,
            dependency_graph=dependency_markdown,
        )
        written.extend(
            _write_html_outputs(
                target_repo,
                targets,
                findings,
                effective_threshold,
                show_secrets=effective_show_secrets,
                truncated=truncated,
                dependency_graph=dependency_graph,
            )
        )
    except OSError as exc:
        print(f"[commit-guard] ERROR: could not write report: {exc}", file=sys.stderr)
        return 2
    written.extend(dependency_paths)

    blocked = has_blocking_findings(findings, effective_threshold)
    if not quiet:
        print_cli_summary(
            findings,
            written[0] if written else None,
            effective_threshold,
            show_secrets=effective_show_secrets,
            truncated=truncated,
            extra_report_paths=tuple(written[1:]),
        )
        if effective_soft_fail and blocked:
            print("  Soft-fail enabled: returning exit code 0.")
        elapsed = time.perf_counter() - started
        print(f"  Scanned {len(diff_lines)} line(s) in {elapsed:.2f}s")

    emit_annotations = (
        github_annotations
        or config.github_annotations
        or os.environ.get("GITHUB_ACTIONS", "").lower() == "true"
    )
    if emit_annotations:
        print_github_annotations(
            findings, effective_threshold, show_secrets=effective_show_secrets
        )

    if create_pr:
        pr_code = _maybe_create_pr(
            findings,
            dependency_markdown,
            effective_threshold,
            base=pr_base,
            branch=pr_branch,
            title=pr_title,
            report_dir=config.report_dir,
        )
        if pr_code:
            return pr_code

    if review_pr:
        review_code = _maybe_review_pr(findings, ruleset.rules)
        if review_code:
            return review_code

    if update_baseline:
        return 0
    if effective_soft_fail:
        return 0
    return 1 if blocked else 0


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    target_repo = (args.repo or Path.cwd()).expanduser().resolve()

    if args.init_config:
        if not is_inside_git_repo(target_repo):
            print(f"[commit-guard] ERROR: '{target_repo}' is not inside a git repository.", file=sys.stderr)
            return 2
        return _init_config(target_repo, force=args.force)

    if args.list_rules or args.check_rules or args.explain:
        resolved_config_path = args.config
        if resolved_config_path is not None:
            resolved_config_path = resolved_config_path.expanduser()
            if not resolved_config_path.is_absolute():
                resolved_config_path = (target_repo / resolved_config_path).resolve()
        try:
            config = load_config(
                target_repo,
                explicit_path=resolved_config_path,
                use_config=not args.no_config,
            )
        except ConfigError as exc:
            print(f"[commit-guard] ERROR: {exc}", file=sys.stderr)
            return 2
        rules_dir = _resolve_rules_dir(target_repo, args.rules_dir, config)
        if args.check_rules:
            corpus = args.corpus
            if corpus is not None and not corpus.is_absolute():
                corpus = (target_repo / corpus).resolve()
            return check_rules(rules_dir, corpus, use_cache=not args.no_cache)
        if args.explain:
            return explain_rule(args.explain, rules_dir, use_cache=not args.no_cache)
        return _list_rules(rules_dir, args.verbose_rules, not args.no_cache)

    return run_scan(
        rules_dir=args.rules_dir,
        report_path=args.report_path,
        threshold=args.threshold,
        quiet=args.quiet,
        repo_dir=args.repo,
        fmt=args.format,
        use_baseline=not args.no_baseline,
        config_file=args.config,
        use_config=not args.no_config,
        show_secrets=args.show_secrets,
        verbose_rules=args.verbose_rules,
        use_cache=not args.no_cache,
        diff_revision=args.diff,
        history=args.history,
        scan_all=args.all,
        pre_push=args.pre_push,
        baseline_path=args.baseline,
        github_annotations=args.github_annotations,
        soft_fail=(True if args.soft_fail else None),
        fail_on=args.fail_on,
        update_baseline=args.update_baseline,
        baseline_owner=args.baseline_owner,
        baseline_expiry=args.baseline_expiry,
        audit_suppressions=args.audit_suppressions,
        strict=args.strict,
        filter_placeholders=(False if args.no_placeholder_filter else None),
        dep_graph=args.dep_graph,
        dep_graph_format=args.dep_graph_format,
        dep_graph_max_nodes=args.dep_graph_max_nodes,
        sca=args.sca,
        sca_online=args.sca_online,
        sca_snapshot=args.sca_snapshot,
        sca_timeout=args.sca_timeout,
        fix=args.fix,
        fix_dry_run=args.fix_dry_run,
        create_pr=args.create_pr,
        pr_base=args.pr_base,
        pr_branch=args.pr_branch,
        pr_title=args.pr_title,
        review_pr=args.review_pr,
    )


if __name__ == "__main__":
    sys.exit(main())
