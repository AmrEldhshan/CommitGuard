from __future__ import annotations

import contextlib
import io
import json
import re
import shutil
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest import mock

import yaml

import install_hook
from core.git_diff import DiffLine
from core.rule_check import check_rules, explain_rule
from core.rule_loader import Rule
from core.scanner import scan_diff
from main import _pre_push_ranges, run_scan

GIT = shutil.which("git")
ROOT = Path(__file__).resolve().parents[1]
SECRET = "ghp_Ab9xK2mQ7pR4sT8vW1yZ6nC3dF5gH0jL2kM9"  # commit-guard-ignore
SECRET2 = "ghp_Zz8Yy7Xx6Ww5Vv4Uu3Tt2Ss1Rr0Qq9Pp8Oo7"  # commit-guard-ignore


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=str(root),
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


@unittest.skipUnless(GIT, "git is required for integration tests")
class EnhancementTests(unittest.TestCase):
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
        options = {
            "repo_dir": self.root,
            "quiet": True,
            "use_baseline": False,
        }
        options.update(kwargs)
        return run_scan(**options)

    def test_pre_push_range_parsing_handles_new_and_deleted_refs(self):
        zero = "0" * 40
        new_branch = f"refs/heads/main {'a' * 40} refs/heads/main {zero}\n"
        self.assertEqual(_pre_push_ranges(new_branch), [("a" * 40, 0)])
        deleted = f"(delete) {zero} refs/heads/old {'b' * 40}\n"
        self.assertEqual(_pre_push_ranges(deleted), [])
        self.assertEqual(_pre_push_ranges(""), [("HEAD", 100)])

    def test_history_all_and_pre_push_modes(self):
        self.stage("base.txt", "safe\n")
        git(self.root, "commit", "-qm", "base")
        self.stage("leak.py", f'TOKEN = "{SECRET}"\n')
        git(self.root, "commit", "-qm", "leak")
        self.assertEqual(self.scan(history=1), 1)
        self.assertEqual(self.scan(scan_all=True), 1)

        local = git(self.root, "rev-parse", "HEAD").strip()
        remote = git(self.root, "rev-parse", "HEAD~1").strip()
        stdin = io.StringIO(f"refs/heads/main {local} refs/heads/main {remote}\n")
        with mock.patch("sys.stdin", stdin):
            self.assertEqual(self.scan(pre_push=True), 1)

    def test_soft_fail_returns_zero_but_reports(self):
        self.stage("app.py", f'TOKEN = "{SECRET}"\n')
        self.assertEqual(self.scan(soft_fail=True, fmt="json"), 0)
        payload = json.loads(
            (self.root / "commit_guard_reports" / "report.json").read_text()
        )
        self.assertTrue(payload["findings"])

    def test_update_baseline_and_suppression_audit(self):
        self.stage("app.py", f'TOKEN = "{SECRET}"\n')
        self.assertEqual(
            self.scan(
                update_baseline=True,
                baseline_owner="security",
                baseline_expiry="2030-01-01",
            ),
            0,
        )
        baseline = (self.root / ".commit_guard_ignore").read_text()
        self.assertIn("owner=security", baseline)
        self.assertIn("expiry=2030-01-01", baseline)
        self.assertEqual(self.scan(use_baseline=True), 0)

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(
                self.scan(audit_suppressions=True, use_baseline=True), 0
            )
        self.assertIn("0 issue(s)", output.getvalue())

    def test_update_baseline_does_not_duplicate_path_suppressions(self):
        self.stage("docs/notes.md", f'TOKEN = "{SECRET}"\n')
        (self.root / ".commit_guard_ignore").write_text("path:docs/**\n")
        self.assertEqual(self.scan(update_baseline=True, use_baseline=True), 0)
        baseline = (self.root / ".commit_guard_ignore").read_text()
        self.assertNotIn("fingerprint:", baseline)

    def test_expired_suppression_stops_suppressing(self):
        self.stage("app.py", f'TOKEN = "{SECRET}"\n')
        self.assertEqual(self.scan(fmt="json"), 1)
        payload = json.loads(
            (self.root / "commit_guard_reports" / "report.json").read_text()
        )
        fingerprint = payload["findings"][0]["fingerprint"]
        (self.root / ".commit_guard_ignore").write_text(
            f"fingerprint:{fingerprint} # expiry=2000-01-01\n"
        )
        self.assertEqual(self.scan(use_baseline=True), 1)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(
                self.scan(audit_suppressions=True, strict=True, use_baseline=True), 1
            )
        self.assertIn("expired", output.getvalue())

    def test_fail_on_new_and_sarif_baseline_state(self):
        self.stage("app.py", f'TOKEN = "{SECRET}"\n')
        self.assertEqual(self.scan(update_baseline=True), 0)
        self.assertEqual(
            self.scan(fmt="sarif", fail_on="new", use_baseline=True), 0
        )
        payload = json.loads(
            (self.root / "commit_guard_reports" / "report.sarif").read_text()
        )
        states = {result["baselineState"] for result in payload["runs"][0]["results"]}
        self.assertEqual(states, {"unchanged"})

        self.stage("new.py", f'TOKEN = "{SECRET2}"\n')
        self.assertEqual(
            self.scan(fmt="json", fail_on="new", use_baseline=True), 1
        )
        report = json.loads(
            (self.root / "commit_guard_reports" / "report.json").read_text()
        )
        self.assertTrue(any(f["baseline_state"] == "new" for f in report["findings"]))

    def test_junit_gitlab_and_checkstyle_reports(self):
        self.stage("app.py", f'TOKEN = "{SECRET}"\n')
        for fmt, name in (
            ("junit", "report.junit.xml"),
            ("gitlab", "report.gitlab.json"),
            ("checkstyle", "report.checkstyle.xml"),
        ):
            self.assertEqual(self.scan(fmt=fmt), 1)
            path = self.root / "commit_guard_reports" / name
            self.assertTrue(path.is_file(), name)
            if fmt == "gitlab":
                self.assertIsInstance(json.loads(path.read_text()), list)
            else:
                self.assertIsNotNone(ET.parse(path).getroot())

    def test_context_rule_requires_nearby_line(self):
        rule = Rule(
            rule_id="context-test",
            description="context",
            severity="high",
            pattern=re.compile(r"\.execute\s*\("),
            source="test",
            languages=(".py",),
            context_regexes=(re.compile(r"query\s*="),),
            context_before=2,
        )
        diff = [DiffLine("app.py", 3, "cursor.execute(query)")]
        with_context = {"app.py": ["query = 'SELECT 1'", "", "cursor.execute(query)"]}
        self.assertEqual(
            len(scan_diff(diff, [rule], file_lines=with_context)), 1
        )
        self.assertEqual(len(scan_diff(diff, [rule])), 0)

    def test_placeholder_filter_and_entropy_by_character_class(self):
        rule = Rule(
            rule_id="secret-test",
            description="secret",
            severity="high",
            pattern=re.compile(r"TOKEN\s*=\s*[\"']([^\"']+)[\"']"),
            source="test",
            secret_group=1,
            is_secret=True,
        )
        placeholder = [DiffLine("app.py", 1, 'TOKEN = "your_token_here"')]
        self.assertEqual(scan_diff(placeholder, [rule]), [])
        self.assertEqual(
            len(scan_diff(placeholder, [rule], filter_placeholders=False)), 1
        )

        hex_rule = Rule(
            rule_id="entropy-test",
            description="hex",
            severity="high",
            pattern=re.compile(r"([0-9a-f]{32})"),
            source="test",
            entropy=4.2,
        )
        high_hex = [DiffLine("app.py", 1, "0123456789abcdef0123456789abcdef")]
        self.assertEqual(len(scan_diff(high_hex, [hex_rule])), 1)

    def test_check_rules_and_explain(self):
        rules_dir = ROOT / "rules"
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(check_rules(rules_dir), 0)
        self.assertIn("schema/corpus issues: 0", output.getvalue())

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(explain_rule("cg-python-eval", rules_dir), 0)
        self.assertIn("Rule:        cg-python-eval", output.getvalue())

    def test_pre_commit_manifest_is_valid(self):
        manifest = yaml.safe_load((ROOT / ".pre-commit-hooks.yaml").read_text())
        self.assertEqual([hook["id"] for hook in manifest], ["commit-guard", "commit-guard-push"])
        for hook in manifest:
            self.assertIn(".commit_guard/main.py", hook["entry"])
            self.assertFalse(hook["pass_filenames"])
            self.assertTrue(hook["always_run"])


@unittest.skipUnless(GIT, "git is required for installer tests")
class InstallerEnhancementTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        git(self.root, "init", "-q")
        git(self.root, "config", "user.email", "test@example.com")
        git(self.root, "config", "user.name", "Test")

    def tearDown(self):
        self.temp.cleanup()

    def test_no_hook_leaves_framework_hook_untouched(self):
        hook = self.root / ".git" / "hooks" / "pre-commit"
        hook.parent.mkdir(parents=True, exist_ok=True)
        hook.write_text("#!/bin/sh\necho framework\n", encoding="utf-8")
        hook.chmod(0o755)
        with contextlib.redirect_stdout(io.StringIO()):
            install_hook.install(self.root, pre_commit_hook=False)
        self.assertIn("framework", hook.read_text())
        with contextlib.redirect_stdout(io.StringIO()):
            install_hook.update(self.root)
        self.assertIn("framework", hook.read_text())
        with contextlib.redirect_stdout(io.StringIO()):
            install_hook.uninstall(self.root)
        self.assertTrue(hook.exists())
        self.assertIn("framework", hook.read_text())

    def test_pre_push_hook_catches_pushed_secret(self):
        (self.root / "base.txt").write_text("safe\n", encoding="utf-8")
        git(self.root, "add", "base.txt")
        git(self.root, "commit", "-qm", "base")
        with contextlib.redirect_stdout(io.StringIO()):
            install_hook.install(
                self.root, pre_push=True, pre_commit_hook=False
            )
        (self.root / "leak.py").write_text(f'TOKEN = "{SECRET}"\n', encoding="utf-8")
        git(self.root, "add", "leak.py")
        git(self.root, "commit", "-qm", "leak")
        local = git(self.root, "rev-parse", "HEAD").strip()
        remote = git(self.root, "rev-parse", "HEAD~1").strip()
        hook = self.root / ".git" / "hooks" / "pre-push"
        result = subprocess.run(
            [str(hook)],
            cwd=str(self.root),
            input=f"refs/heads/main {local} refs/heads/main {remote}\n",
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_pre_push_profile_no_native_hook_and_uninstall(self):
        with contextlib.redirect_stdout(io.StringIO()):
            install_hook.install(
                self.root,
                pre_push=True,
                profile="audit",
                pre_commit_hook=False,
            )
        hooks = self.root / ".git" / "hooks"
        self.assertFalse((hooks / "pre-commit").exists())
        self.assertTrue((hooks / "pre-push").exists())
        config = (self.root / ".commit_guard.toml").read_text()
        self.assertIn("soft_fail = true", config)
        self.assertIn("threshold = \"high\"", config)

        with contextlib.redirect_stdout(io.StringIO()):
            install_hook.disable(self.root)
        self.assertTrue((hooks / "pre-push.disabled").exists())
        with contextlib.redirect_stdout(io.StringIO()):
            install_hook.update(self.root)
        self.assertTrue((hooks / "pre-push.disabled").exists())
        self.assertFalse((hooks / "pre-push").exists())
        with contextlib.redirect_stdout(io.StringIO()):
            install_hook.enable(self.root)
        self.assertTrue((hooks / "pre-push").exists())
        with contextlib.redirect_stdout(io.StringIO()):
            install_hook.uninstall(self.root)
        self.assertFalse((hooks / "pre-push").exists())


if __name__ == "__main__":
    unittest.main()
