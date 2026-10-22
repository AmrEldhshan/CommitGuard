from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from main import run_scan

GIT = shutil.which("git")


@unittest.skipUnless(GIT, "git is required for integration tests")
class FixIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)
        subprocess.run(
            ["git", "config", "user.email", "test@example.com"],
            cwd=self.root,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Test"], cwd=self.root, check=True
        )

    def tearDown(self):
        self.temp.cleanup()

    def stage(self, name: str, text: str) -> None:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        subprocess.run(["git", "add", name], cwd=self.root, check=True)

    def test_fix_updates_file_restages_and_passes(self):
        self.stage("app.py", "requests.get(url, verify=False)\n")
        code = run_scan(
            repo_dir=self.root,
            quiet=True,
            use_baseline=False,
            threshold="medium",
            fix=True,
        )
        self.assertEqual(code, 0)
        self.assertIn("verify=True", (self.root / "app.py").read_text())
        staged = subprocess.run(
            ["git", "diff", "--cached", "--", "app.py"],
            cwd=self.root,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        self.assertIn("verify=True", staged)
        report = (self.root / "commit_guard_reports/report.md").read_text()
        self.assertNotIn("cg-python-tls-verify-disabled", report)

    def test_fix_dry_run_does_not_write_and_still_fails(self):
        self.stage("app.py", "requests.get(url, verify=False)\n")
        code = run_scan(
            repo_dir=self.root,
            quiet=True,
            use_baseline=False,
            threshold="medium",
            fix_dry_run=True,
        )
        self.assertEqual(code, 1)
        self.assertIn("verify=False", (self.root / "app.py").read_text())
        report = (self.root / "commit_guard_reports/report.md").read_text()
        self.assertIn("cg-python-tls-verify-disabled", report)

    def test_fix_and_update_baseline_are_rejected(self):
        self.stage("app.py", "print('safe')\n")
        code = run_scan(
            repo_dir=self.root,
            quiet=True,
            use_baseline=False,
            fix=True,
            update_baseline=True,
        )
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
