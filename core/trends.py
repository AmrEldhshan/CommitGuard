"""Zero-dependency terminal and HTML reporting helpers.

The HTML report is fully self-contained: inline CSS, inline SVG dependency
graph, and an inline SVG trend line. No scripts, CDNs, fonts, or telemetry
are loaded. History files are local JSON written next to the report.
"""

from __future__ import annotations

import html
import json
import math
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from core import __version__
from core.dep_graph import DependencyGraph
from core.scanner import Finding, has_blocking_findings

HISTORY_FILENAME = "history.json"
HISTORY_LIMIT = 100


@dataclass(frozen=True)
class TrendEntry:
    timestamp: str
    total: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    blocked: bool
    threshold: str


def make_trend_entry(findings: list[Finding], threshold: str) -> TrendEntry:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        if finding.severity in counts:
            counts[finding.severity] += 1
    return TrendEntry(
        timestamp=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        total=len(findings),
        blocked=has_blocking_findings(findings, threshold),
        threshold=threshold,
        **counts,
    )


def load_history(path: Path) -> list[TrendEntry]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    raw_entries = payload.get("entries") if isinstance(payload, dict) else payload
    if not isinstance(raw_entries, list):
        return []
    entries: list[TrendEntry] = []
    for raw in raw_entries:
        if not isinstance(raw, dict):
            continue
        try:
            entries.append(
                TrendEntry(
                    timestamp=str(raw["timestamp"]),
                    total=int(raw["total"]),
                    critical=int(raw.get("critical", 0)),
                    high=int(raw.get("high", 0)),
                    medium=int(raw.get("medium", 0)),
                    low=int(raw.get("low", 0)),
                    info=int(raw.get("info", 0)),
                    blocked=bool(raw.get("blocked", False)),
                    threshold=str(raw.get("threshold", "high")),
                )
            )
        except (KeyError, TypeError, ValueError):
            continue
    return entries


def record_history(
    path: Path,
    entry: TrendEntry,
    *,
    limit: int = HISTORY_LIMIT,
) -> list[TrendEntry]:
    entries = load_history(path)
    entries.append(entry)
    if limit > 0:
        entries = entries[-limit:]
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": 1,
        "entries": [asdict(item) for item in entries],
    }
    temporary = output.with_name(f".{output.name}.tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    temporary.replace(output)
    return entries


def build_trend_svg(
    entries: list[TrendEntry],
    *,
    width: int = 720,
    height: int = 180,
) -> str:
    padding = 28
    chart_width = max(width - padding * 2, 1)
    chart_height = max(height - padding * 2, 1)
    max_total = max((entry.total for entry in entries), default=0)
    ceiling = max(max_total, 1)
    points: list[tuple[float, float]] = []
    if entries:
        denominator = max(len(entries) - 1, 1)
        for index, entry in enumerate(entries):
            x = padding + (chart_width * index / denominator if len(entries) > 1 else chart_width / 2)
            y = padding + chart_height - (chart_height * entry.total / ceiling)
            points.append((round(x, 2), round(y, 2)))

    parts = [
        (
            f'<svg class="trend" viewBox="0 0 {width} {height}" role="img" '
            f'aria-label="CommitGuard finding trend">'
        ),
        "<title>CommitGuard finding trend</title>",
        (
            f'<line x1="{padding}" y1="{padding + chart_height}" '
            f'x2="{width - padding}" y2="{padding + chart_height}" '
            'stroke="#cbd5e1"/>'
        ),
        (
            f'<line x1="{padding}" y1="{padding}" x2="{padding}" '
            f'y2="{padding + chart_height}" stroke="#cbd5e1"/>'
        ),
    ]
    if len(points) > 1:
        polyline = " ".join(f"{x},{y}" for x, y in points)
        parts.append(
            f'<polyline fill="none" stroke="#2563eb" stroke-width="3" '
            f'stroke-linejoin="round" points="{polyline}"/>'
        )
    for index, ((x, y), entry) in enumerate(zip(points, entries)):
        color = "#dc2626" if entry.blocked else "#16a34a"
        parts.append(
            f'<circle cx="{x}" cy="{y}" r="4" fill="{color}">'
            f"<title>{html.escape(entry.timestamp)}: {entry.total} finding(s)</title>"
            "</circle>"
        )
    if points:
        last_x, last_y = points[-1]
        parts.append(
            f'<text x="{last_x}" y="{max(last_y - 9, 12)}" text-anchor="end" '
            'font-size="12" fill="#334155">'
            f"{entries[-1].total}</text>"
        )
    parts.append("</svg>")
    return "".join(parts)


def build_dependency_svg(
    graph: DependencyGraph,
    *,
    vulnerable_files: set[str] | None = None,
    max_nodes: int = 30,
) -> str:
    vulnerable = vulnerable_files or set()
    selected = sorted(
        graph.nodes,
        key=lambda path: (path not in vulnerable, path),
    )[:max_nodes]
    selected_set = set(selected)
    columns = max(math.ceil(math.sqrt(len(selected))), 1)
    cell_width, cell_height = 180, 64
    box_width, box_height = 150, 30
    width = max(columns * cell_width, cell_width)
    rows = max(math.ceil(len(selected) / columns), 1)
    height = rows * cell_height
    positions: dict[str, tuple[int, int]] = {}
    for index, path in enumerate(selected):
        column = index % columns
        row = index // columns
        positions[path] = (column * cell_width + 15, row * cell_height + 17)

    parts = [
        (
            f'<svg class="depgraph" viewBox="0 0 {width} {height}" role="img" '
            f'aria-label="Dependency graph ({len(selected)} files)">'
        ),
        "<title>Dependency graph</title>",
        (
            "<defs><marker id=\"cg-arrow\" markerWidth=\"8\" markerHeight=\"8\" "
            "refX=\"7\" refY=\"3\" orient=\"auto\"><path d=\"M0,0 L0,6 L7,3 z\" "
            "fill=\"#94a3b8\"/></marker></defs>"
        ),
    ]
    for path in selected:
        node = graph.nodes[path]
        x1, y1 = positions[path]
        for target in node.imports:
            if target not in selected_set:
                continue
            x2, y2 = positions[target]
            parts.append(
                f'<line x1="{x1 + box_width // 2}" y1="{y1 + box_height // 2}" '
                f'x2="{x2 + box_width // 2}" y2="{y2 + box_height // 2}" '
                'stroke="#cbd5e1" stroke-width="1.3" marker-end="url(#cg-arrow)"/>'
            )
    for path in selected:
        x, y = positions[path]
        fill, stroke = (
            ("#fee2e2", "#dc2626") if path in vulnerable else ("#f8fafc", "#94a3b8")
        )
        label = path if len(path) <= 24 else "…" + path[-23:]
        parts.append(
            f'<g><rect x="{x}" y="{y}" width="{box_width}" height="{box_height}" '
            f'rx="5" fill="{fill}" stroke="{stroke}"/>'
            f'<text x="{x + box_width // 2}" y="{y + 19}" text-anchor="middle" '
            f'font-size="10" fill="#0f172a">{html.escape(label)}</text></g>'
        )
    parts.append("</svg>")
    return "".join(parts)


def build_html_report(
    findings: list[Finding],
    block_threshold: str,
    *,
    history: list[TrendEntry] | None = None,
    dependency_svg: str | None = None,
    show_secrets: bool = False,
    truncated: bool = False,
) -> str:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        if finding.severity in counts:
            counts[finding.severity] += 1
    blocked = has_blocking_findings(findings, block_threshold)
    history = history or []
    trend = build_trend_svg(history) if history else ""

    rows: list[str] = []
    for finding in findings:
        rows.append(
            "<tr>"
            f'<td class="sev {html.escape(finding.severity)}">'
            f"{html.escape(finding.severity)}</td>"
            f"<td><code>{html.escape(finding.rule_id)}</code></td>"
            f"<td><code>{html.escape(finding.file)}:{finding.line_number}</code></td>"
            f"<td>{html.escape(finding.description)}</td>"
            f"<td><code>{html.escape(finding.display_code(show_secrets))}</code></td>"
            "</tr>"
        )
    if not rows:
        rows.append('<tr><td colspan="5" class="empty">No issues detected.</td></tr>')

    history_rows = "".join(
        "<tr>"
        f"<td>{html.escape(entry.timestamp)}</td>"
        f"<td>{entry.total}</td>"
        f"<td>{entry.critical}</td>"
        f"<td>{entry.high}</td>"
        f"<td>{entry.medium}</td>"
        f"<td>{'yes' if entry.blocked else 'no'}</td>"
        "</tr>"
        for entry in history[-10:]
    )

    status = "FAILED" if blocked else "PASSED"
    status_class = "failed" if blocked else "passed"
    critical_count = counts["critical"]
    high_count = counts["high"]
    medium_count = counts["medium"]
    low_count = counts["low"]
    info_count = counts["info"]
    rows_html = "".join(rows)
    generated_at = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    truncation = (
        '<p class="note">Findings were truncated by <code>scan.max_findings</code>.</p>'
        if truncated
        else ""
    )
    graph_section = (
        f'<section><h2>Dependency graph</h2>{dependency_svg}</section>'
        if dependency_svg
        else ""
    )
    trend_section = (
        f"<section><h2>Finding trend</h2>{trend}"
        "<table><thead><tr><th>Timestamp</th><th>Total</th><th>Critical</th>"
        "<th>High</th><th>Medium</th><th>Blocked</th></tr></thead>"
        f"<tbody>{history_rows}</tbody></table></section>"
        if history
        else ""
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CommitGuard security report</title>
<style>
:root {{ color-scheme: light; }}
body {{ margin: 0; padding: 2rem; font-family: system-ui, -apple-system, Segoe UI, sans-serif;
  color: #0f172a; background: #f1f5f9; }}
main {{ max-width: 1100px; margin: 0 auto; }}
header, section {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 12px;
  padding: 1.25rem 1.5rem; margin-bottom: 1rem; }}
h1 {{ margin: 0 0 .25rem; font-size: 1.6rem; }}
h2 {{ margin-top: 0; font-size: 1.15rem; }}
.meta {{ color: #475569; font-size: .9rem; }}
.status {{ display: inline-block; margin-top: .75rem; padding: .25rem .6rem;
  border-radius: 999px; font-weight: 700; font-size: .8rem; }}
.passed {{ color: #166534; background: #dcfce7; }}
.failed {{ color: #991b1b; background: #fee2e2; }}
.cards {{ display: flex; flex-wrap: wrap; gap: .75rem; margin-top: 1rem; }}
.card {{ min-width: 110px; border: 1px solid #e2e8f0; border-radius: 8px;
  padding: .6rem .8rem; }}
.card b {{ display: block; font-size: 1.4rem; }}
table {{ width: 100%; border-collapse: collapse; font-size: .85rem; }}
th, td {{ text-align: left; padding: .45rem .35rem; border-bottom: 1px solid #e2e8f0;
  vertical-align: top; }}
th {{ color: #475569; }}
code {{ font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: .82rem; }}
.sev {{ font-weight: 700; text-transform: uppercase; }}
.sev.critical {{ color: #991b1b; }} .sev.high {{ color: #c2410c; }}
.sev.medium {{ color: #a16207; }} .sev.low {{ color: #1d4ed8; }}
.sev.info {{ color: #475569; }}
.empty, .note {{ color: #475569; }}
.trend, .depgraph {{ width: 100%; height: auto; margin-top: .5rem; }}
</style>
</head>
<body>
<main>
<header>
<h1>CommitGuard security report</h1>
<p class="meta">Generated {html.escape(generated_at)}
 · CommitGuard v{html.escape(__version__)} · Threshold
 <code>{html.escape(block_threshold)}</code></p>
<span class="status {status_class}">{status}</span>
{truncation}
<div class="cards">
<div class="card"><b>{critical_count}</b>Critical</div>
<div class="card"><b>{high_count}</b>High</div>
<div class="card"><b>{medium_count}</b>Medium</div>
<div class="card"><b>{low_count}</b>Low</div>
<div class="card"><b>{info_count}</b>Info</div>
</div>
</header>
<section>
<h2>Findings ({len(findings)})</h2>
<table>
<thead><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Description</th>
<th>Code</th></tr></thead>
<tbody>{rows_html}</tbody>
</table>
</section>
{graph_section}
{trend_section}
</main>
</body>
</html>
"""


def write_html_report(
    findings: list[Finding],
    output_path: Path,
    block_threshold: str,
    *,
    history: list[TrendEntry] | None = None,
    dependency_svg: str | None = None,
    show_secrets: bool = False,
    truncated: bool = False,
) -> Path:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        build_html_report(
            findings,
            block_threshold,
            history=history,
            dependency_svg=dependency_svg,
            show_secrets=show_secrets,
            truncated=truncated,
        ),
        encoding="utf-8",
    )
    return output.resolve()
