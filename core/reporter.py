"""
core/reporter.py
-----------------
Turns a list of Finding objects into:
  1. A Markdown report written to commit_guard_reports/report.md
  2. A concise, human-readable CLI summary printed to stdout.

No findings data is sent anywhere — everything stays on disk locally.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from core.scanner import Finding, has_blocking_findings, sort_findings_by_severity

_SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def build_markdown_report(findings: list[Finding], block_threshold: str) -> str:
    """Renders the full Markdown report as a string."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    counts = _severity_counts(findings)
    blocked = has_blocking_findings(findings, block_threshold)

    lines: list[str] = []
    lines.append("# Commit Guard Report")
    lines.append("")
    lines.append(f"**Generated:** {timestamp}")
    lines.append(f"**Status:** {'❌ FAILED (commit blocked)' if blocked else '✅ PASSED'}")
    lines.append(f"**Block threshold:** `{block_threshold}` and above")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {_SEVERITY_EMOJI[sev]} {sev.capitalize()} | {counts[sev]} |")
    lines.append(f"| **Total** | **{len(findings)}** |")
    lines.append("")

    if not findings:
        lines.append("No issues detected in staged changes. ✅")
        return "\n".join(lines) + "\n"

    lines.append("## Findings")
    lines.append("")

    sorted_findings = sort_findings_by_severity(findings)
    for finding in sorted_findings:
        emoji = _SEVERITY_EMOJI.get(finding.severity, "⚪")
        lines.append(f"### {emoji} [{finding.severity.upper()}] `{finding.rule_id}`")
        lines.append("")
        lines.append(f"- **File:** `{finding.file}`")
        lines.append(f"- **Line:** {finding.line_number}")
        lines.append(f"- **Source:** {finding.source}")
        lines.append(f"- **Description:** {finding.description}")
        lines.append("- **Flagged code:**")
        lines.append("  ```")
        lines.append(f"  {finding.flagged_code}")
        lines.append("  ```")
        lines.append("")

    return "\n".join(lines) + "\n"


def write_markdown_report(
    findings: list[Finding],
    output_path: Path,
    block_threshold: str = "high",
) -> Path:
    """
    Writes the Markdown report to disk, creating parent directories as
    needed. Returns the resolved path written to.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    report_text = build_markdown_report(findings, block_threshold)
    output_path.write_text(report_text, encoding="utf-8")
    return output_path.resolve()


def print_cli_summary(
    findings: list[Finding],
    report_path: Path,
    block_threshold: str = "high",
) -> None:
    """Prints a concise, greppable summary to the terminal."""
    counts = _severity_counts(findings)
    blocked = has_blocking_findings(findings, block_threshold)

    print("=" * 60)
    print("  COMMIT GUARD — Scan Summary")
    print("=" * 60)
    print(f"  Total findings : {len(findings)}")
    print(
        "  Breakdown      : "
        f"critical={counts['critical']}  high={counts['high']}  "
        f"medium={counts['medium']}  low={counts['low']}  info={counts['info']}"
    )
    print(f"  Report written : {report_path}")
    print("-" * 60)
    if blocked:
        print(f"  STATUS: FAILED ❌  (>= {block_threshold} severity findings present)")
    else:
        print("  STATUS: PASSED ✅")
    print("=" * 60)
