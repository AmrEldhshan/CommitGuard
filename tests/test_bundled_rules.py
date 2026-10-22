from __future__ import annotations

import unittest
from pathlib import Path

from core.git_diff import DiffLine
from core.rule_loader import load_ruleset
from core.scanner import scan_diff

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


class BundledRuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ruleset = load_ruleset(RULES_DIR, warn=False)

    def test_global_allowlist_does_not_match_false_inside_code(self):
        findings = scan_diff(
            [
                DiffLine(
                    file_path="app.py",
                    line_number=1,
                    code_content="requests.get(url, verify=False)",
                )
            ],
            self.ruleset.rules,
            allowlist_regexes=self.ruleset.line_allowlist,
            allowlist_path_regexes=self.ruleset.path_allowlist,
        )
        self.assertIn("cg-python-tls-verify-disabled", [f.rule_id for f in findings])

    def test_global_allowlist_still_matches_boolean_literals(self):
        line = "False"
        self.assertTrue(any(p.search(line) for p in self.ruleset.line_allowlist))


if __name__ == "__main__":
    unittest.main()
