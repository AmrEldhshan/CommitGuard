from __future__ import annotations

import contextlib
import io
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import main as main_module
from main import load_baseline, run_scan

GIT = shutil.which("git")


def git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=str(root),
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


@unittest.skipUnless(GIT, "git is required for integration tests")
class MainIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        git(self.root, "init", "-q")
        git(self.root, "config", "user.email", "test@example.com")
        git(self.root, "config", "user.name", "Test")

    def tearDown(self):
        self.temp.cleanup()

    def stage(self, name: str, content: str) -> None:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        git(self.root, "add", name)

    def scan(self, **kwargs) -> int:
        if "format" in kwargs:
            kwargs["fmt"] = kwargs.pop("format")
        options = {"repo_dir": self.root, "quiet": True}
        options.update(kwargs)
        return run_scan(**options)

    def test_clean_staged_change_passes(self):
        self.stage("app.py", "print('hello')\n")
        self.assertEqual(self.scan(), 0)
        report = self.root / "commit_guard_reports" / "report.md"
        self.assertTrue(report.is_file())
        self.assertIn("No issues detected", report.read_text())

    def test_python_ast_taint_finding_blocks_and_can_be_suppressed(self):
        self.stage(
            "app.py",
            "def lookup(request, cursor):\n"
            "    user_id = request.args.get('id')\n"
            "    query = 'SELECT * FROM users WHERE id=' + user_id\n"
            "    cursor.execute(query)\n",
        )
        self.assertEqual(self.scan(format="json"), 1)
        report = json.loads(
            (self.root / "commit_guard_reports" / "report.json").read_text()
        )
        finding = next(
            item
            for item in report["findings"]
            if item["rule_id"] == "cg-python-ast-sqli-taint"
        )
        self.assertEqual(finding["source"], "python_ast")
        self.assertEqual(finding["line"], 4)

        self.stage(
            "app.py",
            "def lookup(request, cursor):\n"
            "    user_id = request.args.get('id')\n"
            "    query = 'SELECT * FROM users WHERE id=' + user_id\n"
            "    cursor.execute(query)  # commit-guard-ignore\n",
        )
        self.assertEqual(self.scan(), 0)

    def test_suppression_audit_recognizes_python_ast_rules(self):
        self.stage(
            "app.py",
            "def lookup(request, cursor):\n"
            "    user_id = request.args.get('id')\n"
            "    query = 'SELECT * FROM users WHERE id=' + user_id\n"
            "    cursor.execute(query)\n",
        )
        self.assertEqual(self.scan(format="json"), 1)
        report = json.loads(
            (self.root / "commit_guard_reports" / "report.json").read_text()
        )
        fingerprint = next(
            finding["fingerprint"]
            for finding in report["findings"]
            if finding["rule_id"] == "cg-python-ast-sqli-taint"
        )
        (self.root / ".commit_guard_ignore").write_text(
            f"fingerprint:{fingerprint} # expiry=2030-01-01\n", encoding="utf-8"
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(
                self.scan(audit_suppressions=True, strict=True, use_baseline=True),
                0,
            )
        self.assertIn("0 issue(s)", output.getvalue())

    def test_secret_blocks_and_is_redacted(self):
        self.stage("app.py", 'API_KEY = "aB3xQ9zL0mN2pR7vT4yU6iO8"\n')
        self.assertEqual(self.scan(format="both"), 1)

        markdown = (self.root / "commit_guard_reports" / "report.md").read_text()
        payload = json.loads((self.root / "commit_guard_reports" / "report.json").read_text())
        self.assertNotIn("aB3xQ9zL0mN2pR7vT4yU6iO8", markdown)
        self.assertNotIn("aB3xQ9zL0mN2pR7vT4yU6iO8", json.dumps(payload))
        self.assertTrue(payload["blocked"])
        self.assertTrue(payload["findings"])

    def test_html_report_embeds_graph_trend_and_redacts_secrets(self):
        self.stage("lib.py", "VALUE = 1\n")
        self.stage("app.py", 'import lib\nAPI_KEY = "aB3xQ9zL0mN2pR7vT4yU6iO8"\n')
        self.assertEqual(self.scan(format="html"), 1)
        html = (self.root / "commit_guard_reports" / "report.html").read_text()
        history_path = self.root / "commit_guard_reports" / "history.json"
        self.assertIn('class="depgraph"', html)
        self.assertIn('class="trend"', html)
        self.assertNotIn("aB3xQ9zL0mN2pR7vT4yU6iO8", html)
        self.assertNotIn("<script src", html)
        self.assertEqual(len(json.loads(history_path.read_text())["entries"]), 1)

        self.assertEqual(self.scan(format="html"), 1)
        self.assertEqual(len(json.loads(history_path.read_text())["entries"]), 2)

    def test_show_secrets_opt_in(self):
        self.stage("app.py", 'API_KEY = "aB3xQ9zL0mN2pR7vT4yU6iO8"\n')
        self.assertEqual(self.scan(show_secrets=True), 1)
        markdown = (self.root / "commit_guard_reports" / "report.md").read_text()
        self.assertIn("aB3xQ9zL0mN2pR7vT4yU6iO8", markdown)

    def test_config_threshold_is_honored(self):
        (self.root / ".commit_guard.toml").write_text('[scan]\nthreshold = "critical"\n')
        self.stage("app.py", 'API_KEY = "aB3xQ9zL0mN2pR7vT4yU6iO8"\n')
        self.assertEqual(self.scan(), 0)

    def test_cli_threshold_overrides_config(self):
        (self.root / ".commit_guard.toml").write_text('[scan]\nthreshold = "critical"\n')
        self.stage("app.py", 'API_KEY = "aB3xQ9zL0mN2pR7vT4yU6iO8"\n')
        self.assertEqual(self.scan(threshold="high"), 1)

    def test_inline_suppression(self):
        self.stage(
            "app.py",
            'API_KEY = "aB3xQ9zL0mN2pR7vT4yU6iO8"  # commit-guard-ignore\n',
        )
        self.assertEqual(self.scan(), 0)

    def test_ignore_file_directive_persists_across_commits(self):
        self.stage("app.py", "# commit-guard-ignore-file\nvalue = 1\n")
        git(self.root, "commit", "-qm", "add directive")
        self.stage(
            "app.py",
            "# commit-guard-ignore-file\n"
            'API_KEY = "aB3xQ9zL0mN2pR7vT4yU6iO8"\n',
        )
        self.assertEqual(self.scan(), 0)

    def test_ignore_inline_false_disables_file_directive(self):
        (self.root / ".commit_guard.toml").write_text(
            "[scan]\nignore_inline = false\n"
        )
        self.stage(
            "app.py",
            "# commit-guard-ignore-file\n"
            'API_KEY = "aB3xQ9zL0mN2pR7vT4yU6iO8"\n',
        )
        self.assertEqual(self.scan(), 1)

    def test_path_exclude_from_config(self):
        (self.root / ".commit_guard.toml").write_text(
            '[paths]\nexclude = ["fixtures/**"]\n'
        )
        self.stage("fixtures/app.py", 'API_KEY = "aB3xQ9zL0mN2pR7vT4yU6iO8"\n')
        self.assertEqual(self.scan(), 0)

    def test_report_allowlist_is_non_blocking_but_reported(self):
        (self.root / ".commit_guard.toml").write_text(
            '[paths]\nreport_allowlist = ["docs/**"]\n'
        )
        self.stage("docs/example.py", 'API_KEY = "aB3xQ9zL0mN2pR7vT4yU6iO8"\n')
        self.assertEqual(self.scan(), 0)
        report = (self.root / "commit_guard_reports" / "report.md").read_text()
        self.assertIn("non-blocking", report)

    def test_config_allowlist_paths_suppress_findings(self):
        (self.root / ".commit_guard.toml").write_text(
            '[allowlist]\npaths = ["vendor/**"]\n'
        )
        self.stage("vendor/lib.py", 'API_KEY = "aB3xQ9zL0mN2pR7vT4yU6iO8"\n')
        self.assertEqual(self.scan(), 0)
        report = (self.root / "commit_guard_reports" / "report.md").read_text()
        self.assertIn("No issues detected", report)

    def test_config_report_path_resolves_against_repo(self):
        (self.root / ".commit_guard.toml").write_text(
            '[scan]\nformat = "json"\nreport_path = "build/scan.json"\n'
        )
        self.stage("app.py", 'API_KEY = "aB3xQ9zL0mN2pR7vT4yU6iO8"\n')
        self.assertEqual(self.scan(), 1)
        self.assertTrue((self.root / "build" / "scan.json").is_file())

    def test_baseline_fingerprint_suppresses_existing_finding(self):
        self.stage("app.py", 'API_KEY = "aB3xQ9zL0mN2pR7vT4yU6iO8"\n')
        self.assertEqual(self.scan(format="json"), 1)
        payload = json.loads((self.root / "commit_guard_reports" / "report.json").read_text())
        fingerprint = payload["findings"][0]["fingerprint"]
        (self.root / ".commit_guard_ignore").write_text(
            f"# accepted\nfingerprint:{fingerprint}\n"
        )
        self.assertEqual(self.scan(format="json"), 0)

    def test_diff_revision_scans_named_range(self):
        self.stage("app.py", "print('safe')\n")
        git(self.root, "commit", "-qm", "base")
        self.stage("leak.py", 'API_KEY = "aB3xQ9zL0mN2pR7vT4yU6iO8"\n')
        git(self.root, "commit", "-qm", "leak", "--no-verify")
        self.assertEqual(self.scan(diff_revision="HEAD~1..HEAD"), 1)
        report = (self.root / "commit_guard_reports" / "report.md").read_text()
        self.assertIn("leak.py", report)

    def test_baseline_parser_supports_all_prefixes(self):
        path = self.root / ".commit_guard_ignore"
        path.write_text(
            "# comment\n"
            "plain-rule\n"
            "rule:explicit-rule\n"
            "path:tests/**\n"
            "fingerprint:abcdef0123456789\n"
        )
        baseline = load_baseline(path)
        self.assertEqual(baseline.rule_ids, {"plain-rule", "explicit-rule"})
        self.assertEqual(baseline.path_globs, ("tests/**",))
        self.assertEqual(baseline.fingerprints, {"abcdef0123456789"})

    def test_sarif_output(self):
        self.stage("app.py", 'API_KEY = "aB3xQ9zL0mN2pR7vT4yU6iO8"\n')
        self.assertEqual(self.scan(format="sarif"), 1)
        path = self.root / "commit_guard_reports" / "report.sarif"
        payload = json.loads(path.read_text())
        self.assertEqual(payload["version"], "2.1.0")
        self.assertEqual(payload["runs"][0]["results"][0]["level"], "error")

    def test_init_config(self):
        with contextlib.redirect_stdout(io.StringIO()):
            exit_code = main_module.main(
                ["--repo", str(self.root), "--init-config"]
            )
        self.assertEqual(exit_code, 0)
        self.assertTrue((self.root / ".commit_guard.toml").is_file())

    def test_no_staged_changes_still_writes_reports(self):
        self.assertEqual(self.scan(format="both"), 0)
        self.assertTrue((self.root / "commit_guard_reports" / "report.md").is_file())
        self.assertTrue((self.root / "commit_guard_reports" / "report.json").is_file())

    def test_not_a_git_repo_returns_2(self):
        with (
            tempfile.TemporaryDirectory() as outside,
            contextlib.redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(
                run_scan(
                    repo_dir=Path(outside),
                    quiet=True,
                    use_config=False,
                ),
                2,
            )


if __name__ == "__main__":
    unittest.main()
