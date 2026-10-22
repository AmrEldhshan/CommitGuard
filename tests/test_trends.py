from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from core.dep_graph import DependencyGraph, DependencyNode
from core.reporter import print_cli_summary
from core.scanner import Finding
from core.trends import (
    TrendEntry,
    build_dependency_svg,
    build_html_report,
    build_trend_svg,
    load_history,
    make_trend_entry,
    record_history,
)

SECRET = "ghp_Ab9xK2mQ7pR4sT8vW1yZ6nC3dF5gH0jL2kM9"  # commit-guard-ignore


def finding(
    *,
    severity: str = "high",
    rule_id: str = "gitleaks-github-pat",
    code: str = f'TOKEN = "{SECRET}"',
) -> Finding:
    return Finding(
        file="app.py",
        line_number=3,
        rule_id=rule_id,
        description="GitHub token detected <script>",
        severity=severity,
        source="gitleaks",
        flagged_code=code,
        redacted_code='TOKEN = "gh********M9"',
        fingerprint="abc123",
        blocking=True,
    )


class TrendTests(unittest.TestCase):
    def test_history_records_limits_and_tolerates_corruption(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "history.json"
            for count in range(3):
                entry = TrendEntry(
                    timestamp=f"2026-01-0{count + 1}T00:00:00Z",
                    total=count,
                    critical=count,
                    high=0,
                    medium=0,
                    low=0,
                    info=0,
                    blocked=count > 0,
                    threshold="high",
                )
                entries = record_history(path, entry, limit=2)
            self.assertEqual(len(entries), 2)
            self.assertEqual([entry.total for entry in load_history(path)], [1, 2])
            path.write_text("not json", encoding="utf-8")
            self.assertEqual(load_history(path), [])
            path.write_text(json.dumps({"entries": [{"bad": "entry"}]}), encoding="utf-8")
            self.assertEqual(load_history(path), [])

    def test_make_trend_entry_counts_findings(self):
        entry = make_trend_entry([finding(), finding(severity="critical")], "high")
        self.assertEqual(entry.total, 2)
        self.assertEqual(entry.high, 1)
        self.assertEqual(entry.critical, 1)
        self.assertTrue(entry.blocked)

    def test_trend_svg_handles_empty_and_populated_history(self):
        self.assertIn("<svg", build_trend_svg([]))
        entries = [
            TrendEntry("2026-01-01T00:00:00Z", 1, 0, 1, 0, 0, 0, True, "high"),
            TrendEntry("2026-01-02T00:00:00Z", 0, 0, 0, 0, 0, 0, False, "high"),
        ]
        svg = build_trend_svg(entries)
        self.assertIn("<polyline", svg)
        self.assertIn("finding trend", svg)

    def test_dependency_svg_marks_vulnerable_nodes(self):
        graph = DependencyGraph(
            nodes={
                "app.py": DependencyNode("app.py", "python", imports=("lib.py",)),
                "lib.py": DependencyNode("lib.py", "python"),
            }
        )
        svg = build_dependency_svg(graph, vulnerable_files={"lib.py"})
        self.assertIn("app.py", svg)
        self.assertIn("lib.py", svg)
        self.assertIn("#dc2626", svg)
        self.assertIn("cg-arrow", svg)

    def test_html_report_is_self_contained_and_redacts_secrets(self):
        html = build_html_report(
            [finding()],
            "high",
            history=[make_trend_entry([finding()], "high")],
            dependency_svg='<svg class="depgraph"></svg>',
            show_secrets=False,
        )
        self.assertIn("CommitGuard security report", html)
        self.assertIn("Finding trend", html)
        self.assertIn("Dependency graph", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<script src", html)
        self.assertNotIn(SECRET, html)
        self.assertIn("gh********M9", html)

    def test_cli_summary_uses_ansi_when_forced(self):
        output = io.StringIO()
        with (
            mock.patch.dict(os.environ, {"FORCE_COLOR": "1"}, clear=True),
            contextlib.redirect_stdout(output),
        ):
            print_cli_summary([finding()], None, "high")
        self.assertIn("\033[1;31m", output.getvalue())

        output = io.StringIO()
        with (
            mock.patch.dict(os.environ, {"NO_COLOR": "1", "FORCE_COLOR": "1"}, clear=True),
            contextlib.redirect_stdout(output),
        ):
            print_cli_summary([finding()], None, "high")
        self.assertNotIn("\033[", output.getvalue())


if __name__ == "__main__":
    unittest.main()
