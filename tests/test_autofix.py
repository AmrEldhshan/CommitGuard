from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from core.autofix import AutoFixError, apply_fixes
from core.rule_loader import Rule
from core.scanner import Finding


def rule(
    rule_id: str = "fix-verify",
    *,
    fix_pattern: str | None = r"verify\s*=\s*False",
    fix_replacement: str | None = "verify=True",
    is_secret: bool = False,
) -> Rule:
    import re

    return Rule(
        rule_id=rule_id,
        description="test",
        severity="medium",
        pattern=re.compile(r"verify\s*=\s*False"),
        source="custom",
        fix_pattern=re.compile(fix_pattern) if fix_pattern else None,
        fix_replacement=fix_replacement,
        is_secret=is_secret,
    )


def finding(path: str, line: int, rule_id: str, fingerprint: str) -> Finding:
    return Finding(
        file=path,
        line_number=line,
        rule_id=rule_id,
        description="test",
        severity="medium",
        source="custom",
        flagged_code="verify=False",
        fingerprint=fingerprint,
    )


class AutoFixTests(unittest.TestCase):
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

    def write(self, name: str, text: str) -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def test_applies_bottom_up_and_stages(self):
        path = self.write("app.py", "a = verify=False\nb = 2\nc = verify=False\n")
        findings = [
            finding("app.py", 1, "fix-verify", "f1"),
            finding("app.py", 3, "fix-verify", "f2"),
        ]
        result = apply_fixes(self.root, findings, [rule()])
        self.assertEqual(result.applied_count, 2)
        self.assertEqual(result.fixed_fingerprints, {"f1", "f2"})
        self.assertEqual(
            path.read_text(),
            "a = verify=True\nb = 2\nc = verify=True\n",
        )
        staged = subprocess.run(
            ["git", "diff", "--cached", "--", "app.py"],
            cwd=self.root,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        self.assertIn("verify=True", staged)

    def test_dry_run_does_not_write_or_stage(self):
        path = self.write("app.py", "a = verify=False\n")
        result = apply_fixes(
            self.root,
            [finding("app.py", 1, "fix-verify", "f1")],
            [rule()],
            dry_run=True,
        )
        self.assertEqual(result.applied_count, 0)
        self.assertEqual(len(result.outcomes), 1)
        self.assertFalse(result.outcomes[0].applied)
        self.assertIn("verify=False", path.read_text())
        staged = subprocess.run(
            ["git", "diff", "--cached", "--", "app.py"],
            cwd=self.root,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        self.assertEqual(staged, "")

    def test_skips_non_matching_lines_and_rules_without_fix(self):
        path = self.write("app.py", "a = verify=True\n")
        result = apply_fixes(
            self.root,
            [finding("app.py", 1, "fix-verify", "f1")],
            [rule()],
        )
        self.assertEqual(result.outcomes, ())
        self.assertIn("verify=True", path.read_text())
        no_fix = rule("no-fix", fix_pattern=None, fix_replacement=None)
        path.write_text("a = verify=False\n")
        result = apply_fixes(
            self.root,
            [finding("app.py", 1, "no-fix", "f2")],
            [no_fix],
        )
        self.assertEqual(result.outcomes, ())

    def test_secret_rules_are_never_auto_fixed(self):
        path = self.write("app.py", "token = verify=False\n")  # commit-guard-ignore
        result = apply_fixes(
            self.root,
            [finding("app.py", 1, "fix-verify", "f1")],
            [rule(is_secret=True)],
        )
        self.assertEqual(result.outcomes, ())
        self.assertIn("verify=False", path.read_text())

    def test_rejects_paths_outside_repo_and_symlinks(self):
        self.write("app.py", "verify=False\n")
        outside = Path(self.temp.name).parent / "outside-fix-test.py"
        outside.write_text("verify=False\n")
        try:
            with self.assertRaises(AutoFixError):
                apply_fixes(
                    self.root,
                    [finding("../" + outside.name, 1, "fix-verify", "f1")],
                    [rule()],
                )
            os.symlink(outside, self.root / "link.py")
            with self.assertRaises(AutoFixError):
                apply_fixes(
                    self.root,
                    [finding("link.py", 1, "fix-verify", "f2")],
                    [rule()],
                )
        finally:
            outside.unlink(missing_ok=True)

    def test_missing_target_file_is_operational_error(self):
        with self.assertRaises(AutoFixError):
            apply_fixes(
                self.root,
                [finding("missing.py", 1, "fix-verify", "f1")],
                [rule()],
            )


if __name__ == "__main__":
    unittest.main()
