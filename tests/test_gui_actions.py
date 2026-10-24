from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import gui_actions as actions

GIT = shutil.which("git")
TOOLKIT = Path(__file__).resolve().parents[1]


def git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=str(root),
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


FAKE_ENGINE = """\
import json
import os
import sys
from pathlib import Path

args = sys.argv[1:]
report_path = None
for index, value in enumerate(args):
    if value == "--report-path":
        report_path = Path(args[index + 1])

payload = {
    "schema_version": 2,
    "tool": {"name": "CommitGuard", "version": "test"},
    "generated": "2026-01-01 00:00:00 UTC",
    "block_threshold": "high",
    "blocked": False,
    "truncated": False,
    "redacted": True,
    "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
    "total": 0,
    "findings": [],
}
if os.environ.get("FAKE_FINDING"):
    finding = {
        "file": "app.py",
        "line": 1,
        "rule_id": "cg-python-yaml-unsafe-load",
        "severity": "high",
        "source": "custom",
        "description": "Unsafe yaml.load() call",
        "cwe": "CWE-502",
        "tags": ["yaml"],
        "fingerprint": "abc123",
        "blocking": True,
        "baseline_state": "new",
        "fixed_versions": [],
        "aliases": [],
        "advisory_url": None,
        "flagged_code": "yaml.load(data)",
    }
    payload["findings"] = [finding]
    payload["total"] = 1
    payload["summary"]["high"] = 1
    payload["blocked"] = True
if report_path is not None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(payload), encoding="utf-8")
sys.exit(int(os.environ.get("FAKE_EXIT", "0")))
"""


class GuiActionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        if GIT:
            git(self.root, "init", "-q")
            git(self.root, "config", "user.email", "test@example.com")
            git(self.root, "config", "user.name", "Test")
        self.engine = self.root / "fake_main.py"
        self.engine.write_text(FAKE_ENGINE, encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    @unittest.skipUnless(GIT, "git is required")
    def test_repo_validation_and_info(self):
        self.assertEqual(actions.find_repo_root(self.root), self.root.resolve())
        plain = Path(tempfile.mkdtemp())
        try:
            with self.assertRaises(actions.ActionError):
                actions.find_repo_root(plain)
        finally:
            shutil.rmtree(plain, ignore_errors=True)
        info = actions.repo_info(self.root, self.engine)
        self.assertEqual(info["root"], str(self.root.resolve()))
        self.assertFalse(info["installed"])
        self.assertEqual(info["hook"], "missing")

    def test_parse_github_slug(self):
        cases = {
            "git@github.com:owner/repo.git": "owner/repo",
            "https://github.com/owner/repo.git": "owner/repo",
            "https://github.com/owner/repo": "owner/repo",
            "owner/repo": "owner/repo",
            "https://gitlab.com/owner/repo": None,
            "": None,
        }
        for remote, expected in cases.items():
            self.assertEqual(actions.parse_github_slug(remote), expected, remote)

    @unittest.skipUnless(GIT, "git is required")
    def test_build_scan_command_modes_and_flags(self):
        engine = self.root / "main.py"
        report = self.root / "report.json"
        base = actions.build_scan_command(engine, self.root, report, {"mode": "staged"})
        self.assertIn("--threshold", base)
        self.assertNotIn("--all", base)
        self.assertNotIn("--diff", base)
        history = actions.build_scan_command(
            engine, self.root, report, {"mode": "history", "history": "5"}
        )
        self.assertEqual(history[history.index("--history") + 1], "5")
        diff = actions.build_scan_command(
            engine, self.root, report, {"mode": "diff", "diff": "origin/main...HEAD"}
        )
        self.assertEqual(diff[diff.index("--diff") + 1], "origin/main...HEAD")
        full = actions.build_scan_command(
            engine,
            self.root,
            report,
            {
                "mode": "all",
                "show_secrets": True,
                "no_baseline": True,
                "no_cache": True,
                "no_placeholder_filter": True,
                "dep_graph": True,
                "dep_graph_format": "json",
                "sca": True,
                "sca_online": True,
                "sca_snapshot": "osv.json",
                "sca_timeout": 7,
            },
        )
        for flag in (
            "--all",
            "--show-secrets",
            "--no-baseline",
            "--no-cache",
            "--no-placeholder-filter",
            "--dep-graph",
            "--sca",
            "--sca-online",
        ):
            self.assertIn(flag, full)
        self.assertEqual(full[full.index("--dep-graph-format") + 1], "json")
        self.assertEqual(full[full.index("--sca-timeout") + 1], "7")
        with self.assertRaises(actions.ActionError):
            actions.build_scan_command(engine, self.root, report, {"mode": "nope"})
        with self.assertRaises(actions.ActionError):
            actions.build_scan_command(engine, self.root, report, {"threshold": "nope"})
        with self.assertRaises(actions.ActionError):
            actions.build_scan_command(engine, self.root, report, {"mode": "diff"})

    @unittest.skipUnless(GIT, "git is required")
    def test_scan_with_engine_and_export(self):
        result = actions.run_scan(self.root, {"mode": "staged"}, engine=self.engine)
        self.assertTrue(result["ok"])
        self.assertEqual(result["report"]["total"], 0)
        self.assertEqual(result["exit_code"], 0)
        for fmt in ("json", "markdown", "sarif", "junit", "gitlab", "checkstyle", "html"):
            exported = actions.export_report(self.root, result["report"], fmt)
            self.assertTrue(exported["content"])
            self.assertEqual(exported["format"], fmt)
        with self.assertRaises(actions.ActionError):
            actions.export_report(self.root, result["report"], "nope")

    @unittest.skipUnless(GIT, "git is required")
    def test_scan_failure_raises(self):
        import os

        old = os.environ.get("FAKE_EXIT")
        os.environ["FAKE_EXIT"] = "2"
        try:
            with self.assertRaises(actions.ActionError):
                actions.run_scan(self.root, {"mode": "staged"}, engine=self.engine)
        finally:
            if old is None:
                os.environ.pop("FAKE_EXIT", None)
            else:
                os.environ["FAKE_EXIT"] = old

    @unittest.skipUnless(GIT, "git is required")
    def test_config_validation_and_backup(self):
        initial = actions.config_get(self.root)
        self.assertFalse(initial["exists"])
        self.assertTrue(initial["default_text"])
        saved = actions.config_save(self.root, '[scan]\nthreshold = "medium"\n')
        self.assertEqual(saved["summary"]["threshold"], "medium")
        actions.config_save(self.root, '[scan]\nthreshold = "low"\n')
        self.assertTrue((self.root / ".commit_guard.toml.bak").is_file())
        with self.assertRaises(actions.ActionError):
            actions.config_save(self.root, '[scan]\nthreshold = "bogus"\n')
        restored = actions.config_restore(self.root)
        self.assertEqual(restored["summary"]["threshold"], "medium")

    @unittest.skipUnless(GIT, "git is required")
    def test_baseline_suppress_audit_and_entries(self):
        self.assertEqual(actions.baseline_entries(self.root)["entries"], [])
        result = actions.suppress_findings(
            self.root, ["deadbeef"], owner="team", expiry="2030-01-01"
        )
        self.assertEqual(result["added"], 1)
        entries = actions.baseline_entries(self.root)["entries"]
        self.assertEqual(entries[0]["value"], "deadbeef")
        self.assertEqual(entries[0]["owner"], "team")
        with self.assertRaises(actions.ActionError):
            actions.suppress_findings(self.root, ["x"], expiry="not-a-date")
        audit = actions.audit_suppressions(self.root, engine=self.engine)
        self.assertEqual(audit["entries"], 1)

    @unittest.skipUnless(GIT, "git is required")
    def test_maintenance_requires_uninstall_confirmation(self):
        with self.assertRaises(actions.ActionError):
            actions.maintenance(self.root, "uninstall", {"confirm": "wrong"})
        with self.assertRaises(actions.ActionError):
            actions.maintenance(self.root, "nope")


class GuiFixTests(unittest.TestCase):
    """End-to-end fix preview/apply using the real engine and rules."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        if not GIT:
            self.skipTest("git is required")
        git(self.root, "init", "-q")
        git(self.root, "config", "user.email", "test@example.com")
        git(self.root, "config", "user.name", "Test")
        (self.root / "app.py").write_text(
            "import yaml\ndata = yaml.load(open('x'))\n", encoding="utf-8"
        )
        git(self.root, "add", "app.py")

    def tearDown(self):
        self.temp.cleanup()

    def test_preview_and_apply_fixes(self):
        engine = TOOLKIT / "main.py"
        result = actions.run_scan(self.root, {"mode": "staged"}, engine=engine)
        self.assertTrue(result["report"]["findings"])
        preview = actions.preview_fixes(self.root, result["report"], engine=engine)
        self.assertGreaterEqual(preview["count"], 1)
        fingerprint = preview["outcomes"][0]["fingerprint"]
        self.assertTrue(fingerprint)
        applied = actions.apply_fixes_action(
            self.root, result["report"], [fingerprint], engine=engine
        )
        self.assertEqual(applied["count"], 1)
        self.assertIn("yaml.safe_load", (self.root / "app.py").read_text())
        staged = subprocess.run(
            ["git", "diff", "--cached"],
            cwd=self.root,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertIn("yaml.safe_load", staged.stdout)

    def test_inline_suggestions_preview(self):
        engine = TOOLKIT / "main.py"
        result = actions.run_scan(self.root, {"mode": "staged"}, engine=engine)
        suggestions = actions.inline_suggestions(self.root, result["report"], engine=engine)
        self.assertGreaterEqual(suggestions["count"], 1)
        self.assertIn("suggestion", suggestions["suggestions"][0]["body"])


if __name__ == "__main__":
    unittest.main()
