"""
core/reporter.py
-----------------
Turns Finding objects into:

  1. A Markdown report         commit_guard_reports/report.md
  2. A JSON report             commit_guard_reports/report.json
  3. A SARIF 2.1.0 report      commit_guard_reports/report.sarif
     (uploadable to GitHub code scanning, Azure DevOps, etc.)
  4. JUnit XML, GitLab Code Quality JSON, and Checkstyle XML
  5. GitHub Actions workflow annotations (`::error file=...`)
  6. A concise, colored-free CLI summary.

Secrets are redacted by default everywhere.  Raw matched text is only
included when the caller explicitly asks for it (`--show-secrets`), and
even then it is never sent anywhere — Commit Guard is fully offline.
"""

from __future__ import annotations

import json
import os
import sys
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path

from core import __version__
from core.rule_loader import SEVERITY_ORDER
from core.scanner import Finding, has_blocking_findings, sort_findings_by_severity

_SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}

_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

def _timestamp() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def _source_counts(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.source] = counts.get(finding.source, 0) + 1
    return counts


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(
        sort_findings_by_severity(findings),
        key=lambda f: (f.file, f.line_number, f.rule_id),
    )


def build_markdown_report(
    findings: list[Finding],
    block_threshold: str,
    *,
    show_secrets: bool = False,
    truncated: bool = False,
    dependency_graph: str | None = None,
) -> str:
    """Renders the full Markdown report as a string."""
    counts = _severity_counts(findings)
    blocked = has_blocking_findings(findings, block_threshold)

    lines: list[str] = []
    lines.append("# Commit Guard Report")
    lines.append("")
    lines.append(f"**Generated:** {_timestamp()}")
    lines.append(f"**Commit Guard:** v{__version__}")
    lines.append(f"**Status:** {'❌ FAILED (commit blocked)' if blocked else '✅ PASSED'}")
    lines.append(f"**Block threshold:** `{block_threshold}` and above")
    if not show_secrets and findings:
        lines.append(
            "**Secrets:** redacted (run `commit-guard scan --show-secrets` to display them locally)"
        )
    if truncated:
        lines.append("**Note:** findings were truncated by `scan.max_findings`.")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for severity in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {_SEVERITY_EMOJI[severity]} {severity.capitalize()} | {counts[severity]} |")
    lines.append(f"| **Total** | **{len(findings)}** |")
    lines.append("")

    if findings:
        sources = _source_counts(findings)
        if sources:
            lines.append("### By source")
            lines.append("")
            for source, count in sorted(sources.items(), key=lambda item: (-item[1], item[0])):
                lines.append(f"- `{source}`: {count}")
            lines.append("")

    if dependency_graph:
        lines.append("## Dependency Blast Radius")
        lines.append("")
        lines.append(
            "Vulnerable files are red, direct importers orange, and transitive "
            "importers amber. Vulnerable packages appear as red dependency nodes."
        )
        lines.append("")
        lines.append("```mermaid")
        lines.append(dependency_graph.rstrip())
        lines.append("```")
        lines.append("")

    if not findings:
        lines.append("No issues detected in staged changes. ✅")
        return "\n".join(lines) + "\n"

    lines.append("## Findings")
    lines.append("")
    for finding in _sorted(findings):
        emoji = _SEVERITY_EMOJI.get(finding.severity, "⚪")
        blocked_marker = "" if finding.blocking else " — *non-blocking*"
        if finding.baseline_state == "unchanged":
            blocked_marker = " — *baselined (unchanged)*"
        lines.append(
            f"### {emoji} [{finding.severity.upper()}] `{finding.rule_id}`{blocked_marker}"
        )
        lines.append("")
        lines.append(f"- **File:** `{finding.file}`")
        lines.append(f"- **Line:** {finding.line_number}")
        lines.append(f"- **Source:** `{finding.source}`")
        if finding.cwe:
            lines.append(f"- **CWE:** {finding.cwe}")
        if finding.tags:
            lines.append(f"- **Tags:** {', '.join(finding.tags)}")
        if finding.aliases:
            lines.append(f"- **Advisory IDs:** {', '.join(finding.aliases)}")
        if finding.fixed_versions:
            lines.append(f"- **Fixed in:** {', '.join(finding.fixed_versions)}")
        if finding.advisory_url:
            lines.append(f"- **Advisory:** {finding.advisory_url}")
        lines.append(f"- **Description:** {finding.description}")
        lines.append(f"- **Fingerprint:** `{finding.fingerprint}`")
        lines.append("- **Flagged code:**")
        lines.append("  ```")
        lines.append(f"  {finding.display_code(show_secrets)}")
        lines.append("  ```")
        lines.append("")

    return "\n".join(lines) + "\n"


def build_json_report(
    findings: list[Finding],
    block_threshold: str,
    *,
    show_secrets: bool = False,
    truncated: bool = False,
) -> str:
    """
    Renders findings as stable, CI-friendly JSON.  Structure is documented
    in docs/CI.md.
    """
    counts = _severity_counts(findings)
    blocked = has_blocking_findings(findings, block_threshold)

    payload = {
        "schema_version": 2,
        "tool": {"name": "CommitGuard", "version": __version__},
        "generated": _timestamp(),
        "block_threshold": block_threshold,
        "blocked": blocked,
        "truncated": truncated,
        "redacted": not show_secrets,
        "summary": counts,
        "total": len(findings),
        "findings": [
            {
                "file": finding.file,
                "line": finding.line_number,
                "rule_id": finding.rule_id,
                "severity": finding.severity,
                "source": finding.source,
                "description": finding.description,
                "cwe": finding.cwe,
                "tags": list(finding.tags),
                "fingerprint": finding.fingerprint,
                "blocking": finding.blocking,
                "baseline_state": finding.baseline_state,
                "fixed_versions": list(finding.fixed_versions),
                "aliases": list(finding.aliases),
                "advisory_url": finding.advisory_url,
                "flagged_code": finding.display_code(show_secrets),
            }
            for finding in _sorted(findings)
        ],
    }
    return json.dumps(payload, indent=2) + "\n"


def build_sarif_report(
    findings: list[Finding],
    block_threshold: str,
    *,
    show_secrets: bool = False,
) -> str:
    """Renders a SARIF 2.1.0 document for GitHub/Azure code scanning."""
    rule_indexes: dict[str, int] = {}
    rules: list[dict] = []
    for finding in _sorted(findings):
        if finding.rule_id in rule_indexes:
            continue
        rule_indexes[finding.rule_id] = len(rules)
        rule = {
            "id": finding.rule_id,
            "name": finding.rule_id,
            "shortDescription": {"text": finding.description},
            "defaultConfiguration": {"level": _SARIF_LEVEL.get(finding.severity, "warning")},
            "properties": {
                "severity": finding.severity,
                "source": finding.source,
                "tags": list(finding.tags),
            },
        }
        if finding.cwe:
            rule["properties"]["cwe"] = finding.cwe
        if finding.aliases:
            rule["properties"]["aliases"] = list(finding.aliases)
        if finding.fixed_versions:
            rule["properties"]["fixedVersions"] = list(finding.fixed_versions)
        rules.append(rule)

    results = []
    for finding in _sorted(findings):
        region = {
            "startLine": finding.line_number,
            "snippet": {"text": finding.display_code(show_secrets)},
        }
        results.append(
            {
                "ruleId": finding.rule_id,
                "ruleIndex": rule_indexes[finding.rule_id],
                "level": _SARIF_LEVEL.get(finding.severity, "warning"),
                "message": {"text": f"{finding.description} ({finding.rule_id})"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.file.replace("\\", "/"),
                            },
                            "region": region,
                        }
                    }
                ],
                "baselineState": finding.baseline_state,
                "partialFingerprints": {
                    "primaryLocationLineHash": finding.fingerprint,
                },
                "properties": {
                    "severity": finding.severity,
                    "source": finding.source,
                    "blocking": finding.blocking,
                    "aliases": list(finding.aliases),
                    "fixedVersions": list(finding.fixed_versions),
                    "advisoryUrl": finding.advisory_url,
                },
            }
        )

    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CommitGuard",
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {"blockThreshold": block_threshold},
                    }
                ],
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2) + "\n"


_GITLAB_SEVERITY = {
    "critical": "critical",
    "high": "major",
    "medium": "minor",
    "low": "info",
    "info": "info",
}

_CHECKSTYLE_SEVERITY = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "info",
    "info": "info",
}


def build_junit_report(
    findings: list[Finding],
    block_threshold: str,
    *,
    show_secrets: bool = False,
) -> str:
    """Renders JUnit XML suitable for GitHub/GitLab/Jenkins test reports."""
    sorted_findings = _sorted(findings)
    failures = sum(
        1
        for finding in sorted_findings
        if finding.blocking
        and SEVERITY_ORDER.get(finding.severity, 0)
        >= SEVERITY_ORDER.get(block_threshold, SEVERITY_ORDER["high"])
    )
    suite = ET.Element(
        "testsuite",
        {
            "name": "Commit Guard",
            "tests": str(len(sorted_findings)),
            "failures": str(failures),
            "errors": "0",
        },
    )
    for finding in sorted_findings:
        case = ET.SubElement(
            suite,
            "testcase",
            {
                "classname": finding.file,
                "name": f"{finding.rule_id}:{finding.line_number}:{finding.fingerprint}",
            },
        )
        failed = (
            finding.blocking
            and SEVERITY_ORDER.get(finding.severity, 0)
            >= SEVERITY_ORDER.get(block_threshold, SEVERITY_ORDER["high"])
        )
        if failed:
            failure = ET.SubElement(
                case,
                "failure",
                {"message": finding.description, "type": finding.severity},
            )
            failure.text = (
                f"{finding.file}:{finding.line_number}\n"
                f"{finding.display_code(show_secrets)}\n"
                f"fingerprint={finding.fingerprint}"
            )
            if finding.fixed_versions:
                failure.text += "\nfixed_in=" + ", ".join(finding.fixed_versions)
            if finding.advisory_url:
                failure.text += "\nadvisory=" + finding.advisory_url
    root = ET.Element("testsuites")
    root.append(suite)
    return ET.tostring(root, encoding="unicode", xml_declaration=True) + "\n"


def build_gitlab_report(
    findings: list[Finding],
    block_threshold: str,
    *,
    show_secrets: bool = False,
) -> str:
    """Renders GitLab Code Quality JSON (CodeClimate-compatible subset)."""
    payload = [
        {
            "description": f"[{finding.severity}] {finding.description} ({finding.rule_id})",
            "check_name": finding.rule_id,
            "fingerprint": finding.fingerprint,
            "severity": _GITLAB_SEVERITY.get(finding.severity, "minor"),
            "location": {
                "path": finding.file,
                "lines": {"begin": finding.line_number},
            },
            "categories": ["Security"],
        }
        for finding in _sorted(findings)
    ]
    return json.dumps(payload, indent=2) + "\n"


def build_checkstyle_report(
    findings: list[Finding],
    block_threshold: str,
    *,
    show_secrets: bool = False,
) -> str:
    """Renders Checkstyle XML for CI dashboards and IDE plugins."""
    root = ET.Element("checkstyle", {"version": "10.0"})
    by_file: dict[str, list[Finding]] = {}
    for finding in _sorted(findings):
        by_file.setdefault(finding.file, []).append(finding)
    for file_path, file_findings in by_file.items():
        file_element = ET.SubElement(root, "file", {"name": file_path})
        for finding in file_findings:
            error = ET.SubElement(
                file_element,
                "error",
                {
                    "line": str(finding.line_number),
                    "column": "1",
                    "severity": _CHECKSTYLE_SEVERITY.get(finding.severity, "warning"),
                    "message": f"{finding.description} ({finding.rule_id})",
                    "source": f"commitguard.{finding.rule_id}",
                },
            )
            error.text = finding.display_code(show_secrets)
    return ET.tostring(root, encoding="unicode", xml_declaration=True) + "\n"


def _write(output_path: Path, text: str) -> Path:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(text, encoding="utf-8")
    return output_path.resolve()


def write_markdown_report(
    findings: list[Finding],
    output_path: Path,
    block_threshold: str = "high",
    *,
    show_secrets: bool = False,
    truncated: bool = False,
    dependency_graph: str | None = None,
) -> Path:
    return _write(
        output_path,
        build_markdown_report(
            findings,
            block_threshold,
            show_secrets=show_secrets,
            truncated=truncated,
            dependency_graph=dependency_graph,
        ),
    )


def write_json_report(
    findings: list[Finding],
    output_path: Path,
    block_threshold: str = "high",
    *,
    show_secrets: bool = False,
    truncated: bool = False,
) -> Path:
    return _write(
        output_path,
        build_json_report(
            findings, block_threshold, show_secrets=show_secrets, truncated=truncated  # commit-guard-ignore
        ),
    )


def write_sarif_report(
    findings: list[Finding],
    output_path: Path,
    block_threshold: str = "high",
    *,
    show_secrets: bool = False,
) -> Path:
    return _write(
        output_path,
        build_sarif_report(findings, block_threshold, show_secrets=show_secrets),
    )


def write_junit_report(
    findings: list[Finding],
    output_path: Path,
    block_threshold: str = "high",
    *,
    show_secrets: bool = False,
) -> Path:
    return _write(
        output_path,
        build_junit_report(findings, block_threshold, show_secrets=show_secrets),
    )


def write_gitlab_report(
    findings: list[Finding],
    output_path: Path,
    block_threshold: str = "high",
    *,
    show_secrets: bool = False,
) -> Path:
    return _write(
        output_path,
        build_gitlab_report(findings, block_threshold, show_secrets=show_secrets),
    )


def write_checkstyle_report(
    findings: list[Finding],
    output_path: Path,
    block_threshold: str = "high",
    *,
    show_secrets: bool = False,
) -> Path:
    return _write(
        output_path,
        build_checkstyle_report(findings, block_threshold, show_secrets=show_secrets),
    )


_ANSI = {
    "critical": "\033[1;31m",
    "high": "\033[1;33m",
    "medium": "\033[0;33m",
    "low": "\033[1;34m",
    "info": "\033[0;37m",
    "header": "\033[1;36m",
    "pass": "\033[1;32m",
    "fail": "\033[1;31m",
    "dim": "\033[2m",
    "reset": "\033[0m",
}


def _colors_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR", "").lower() in {"1", "true", "yes"}:
        return True
    return bool(getattr(sys.stdout, "isatty", lambda: False)())


def _paint(text: str, style: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{_ANSI[style]}{text}{_ANSI['reset']}"


def print_cli_summary(
    findings: list[Finding],
    report_path: Path | None,
    block_threshold: str = "high",
    *,
    show_secrets: bool = False,
    truncated: bool = False,
    extra_report_paths: tuple[Path, ...] = (),
) -> None:
    """Prints a concise, greppable summary to the terminal."""
    counts = _severity_counts(findings)
    blocked = has_blocking_findings(findings, block_threshold)
    color = _colors_enabled()

    print("=" * 62)
    print(_paint("  COMMIT GUARD — Scan Summary", "header", color))
    print("=" * 62)
    print(f"  Total findings : {len(findings)}")
    breakdown = "  ".join(
        _paint(f"{severity}={counts[severity]}", severity, color)
        for severity in ("critical", "high", "medium", "low", "info")
    )
    print(f"  Breakdown      : {breakdown}")
    if findings and not show_secrets:
        print("  Secrets        : redacted (use --show-secrets to display)")
    if truncated:
        print("  Note           : report truncated by scan.max_findings")
    if report_path:
        print(f"  Report         : {_paint(str(report_path), 'dim', color)}")
    for path in extra_report_paths:
        print(f"                 : {_paint(str(path), 'dim', color)}")
    print("-" * 62)
    if blocked:
        print(
            _paint(
                f"  STATUS: FAILED ❌  (>= {block_threshold} severity findings present)",
                "fail",
                color,
            )
        )
    else:
        print(_paint("  STATUS: PASSED ✅", "pass", color))
    print("=" * 62)


def _escape_workflow(text: str) -> str:
    return (
        text.replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
    )


def _escape_property(text: str) -> str:
    return _escape_workflow(text).replace(":", "%3A").replace(",", "%2C")


def print_github_annotations(
    findings: list[Finding],
    block_threshold: str = "high",
    *,
    show_secrets: bool = False,
) -> None:
    """
    Emits GitHub Actions workflow commands.  Safe to call outside Actions
    (the lines are simply ignored), but main.py only enables it when the
    GITHUB_ACTIONS environment variable is set or config asks for it.
    """
    threshold = SEVERITY_ORDER.get(block_threshold, SEVERITY_ORDER["high"])

    for finding in _sorted(findings):
        is_error = finding.blocking and SEVERITY_ORDER.get(finding.severity, 0) >= threshold
        command = "error" if is_error else "warning"
        title = _escape_property(f"[{finding.severity.upper()}] {finding.rule_id}")
        message = _escape_workflow(
            f"{finding.description} — {finding.display_code(show_secrets)}"
        )
        print(
            f"::{command} file={_escape_property(finding.file)},"
            f"line={finding.line_number},title={title}::{message}"
        )
