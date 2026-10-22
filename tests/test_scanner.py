from __future__ import annotations

import re
import unittest

from core.git_diff import DiffLine
from core.rule_loader import Rule
from core.scanner import (
    Baseline,
    apply_baseline,
    apply_report_allowlist,
    has_blocking_findings,
    redact_span,
    scan_diff,
)


def make_rule(
    *,
    rule_id: str = "test-secret",
    regex: str = r'(?i)api[_-]?key\s*=\s*["\']([^"\']+)',
    severity: str = "high",
    source: str = "gitleaks",
    secret_group: int = 1,
    is_secret: bool = True,
    **kwargs,
) -> Rule:
    return Rule(
        rule_id=rule_id,
        description="test rule",
        severity=severity,
        pattern=re.compile(regex),
        source=source,
        secret_group=secret_group,
        is_secret=is_secret,
        **kwargs,
    )


def line(code: str, number: int = 1, path: str = "app.py") -> DiffLine:
    return DiffLine(file_path=path, line_number=number, code_content=code)


class ScannerTests(unittest.TestCase):
    def test_basic_match_and_redaction(self):
        findings = scan_diff([line('API_KEY = "supersecret123"')], [make_rule()])
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "test-secret")
        self.assertIn("supersecret123", finding.flagged_code)
        self.assertNotIn("supersecret123", finding.redacted_code)
        self.assertEqual(finding.redacted_code, 'API_KEY = "su********23"')
        self.assertEqual(len(finding.fingerprint), 16)

    def test_display_code_respects_show_secrets(self):
        finding = scan_diff([line('API_KEY = "supersecret123"')], [make_rule()])[0]
        self.assertNotIn("supersecret123", finding.display_code(False))
        self.assertIn("supersecret123", finding.display_code(True))

    def test_inline_suppression_all(self):
        findings = scan_diff(
            [line('API_KEY = "supersecret123"  # commit-guard-ignore')],
            [make_rule()],
        )
        self.assertEqual(findings, [])

    def test_inline_suppression_specific_rule(self):
        code = 'API_KEY = "supersecret123"  # commit-guard-ignore: other-rule'
        self.assertEqual(len(scan_diff([line(code)], [make_rule()])), 1)
        code = 'API_KEY = "supersecret123"  # commit-guard-ignore: test-secret'
        self.assertEqual(scan_diff([line(code)], [make_rule()]), [])

    def test_ignore_next_line(self):
        lines = [
            line("# commit-guard-ignore-next-line", 1),
            line('API_KEY = "supersecret123"', 2),
            line('API_KEY = "anothersecret123"', 3),
        ]
        findings = scan_diff(lines, [make_rule()])
        self.assertEqual([f.line_number for f in findings], [3])

    def test_ignore_file(self):
        lines = [
            line("# commit-guard-ignore-file", 1, "fixture.py"),
            line('API_KEY = "supersecret123"', 2, "fixture.py"),
            line('API_KEY = "othersecret123"', 1, "app.py"),
        ]
        findings = scan_diff(lines, [make_rule()])
        self.assertEqual([f.file for f in findings], ["app.py"])

    def test_ignore_inline_disabled(self):
        code = 'API_KEY = "supersecret123"  # commit-guard-ignore'
        self.assertEqual(
            len(scan_diff([line(code)], [make_rule()], ignore_inline=False)),
            1,
        )

    def test_ignored_rule_ids(self):
        self.assertEqual(
            scan_diff([line('API_KEY = "supersecret123"')], [make_rule()],
                      ignored_rule_ids={"test-secret"}),
            [],
        )

    def test_entropy_threshold_filters_low_entropy(self):
        rule = make_rule(regex=r'secret\s*=\s*(\w+)', entropy=3.5)
        self.assertEqual(scan_diff([line("secret = aaaaaaaaaaaa")], [rule]), [])
        self.assertEqual(len(scan_diff([line("secret = aB3xQ9zL0mN2pR7")], [rule])), 1)

    def test_keywords_are_case_insensitive(self):
        rule = make_rule(regex=r"([A-Za-z0-9]{12,})", keywords=["token"])
        self.assertEqual(scan_diff([line("value = abcdefghijkl")], [rule]), [])
        self.assertEqual(len(scan_diff([line("TOKEN = abcdefghijkl")], [rule])), 1)

    def test_rule_path_restriction(self):
        rule = make_rule(path_regexes=(re.compile(r"\.env$"),))
        self.assertEqual(scan_diff([line('API_KEY = "supersecret123"')], [rule]), [])
        self.assertEqual(
            len(scan_diff([line('API_KEY = "supersecret123"', path=".env")], [rule])),
            1,
        )

    def test_allowlist_regexes(self):
        rule = make_rule(allowlist_regexes=(re.compile(r"^supersecret"),))
        self.assertEqual(scan_diff([line('API_KEY = "supersecret123"')], [rule]), [])

    def test_global_allowlist_and_path_allowlist(self):
        rule = make_rule()
        self.assertEqual(
            scan_diff(
                [line('API_KEY = "supersecret123"')],
                [rule],
                allowlist_regexes=(re.compile(r"supersecret"),),
            ),
            [],
        )
        self.assertEqual(
            scan_diff(
                [line('API_KEY = "supersecret123"')],
                [rule],
                allowlist_path_regexes=(re.compile(r"^app\.py$"),),
            ),
            [],
        )

    def test_path_excludes(self):
        findings = scan_diff(
            [line('API_KEY = "supersecret123"', path="tests/fixture.py")],
            [make_rule()],
            path_excludes=("tests/**",),
        )
        self.assertEqual(findings, [])

    def test_language_filtering(self):
        rule = make_rule(languages=(".py",))
        self.assertEqual(scan_diff([line('API_KEY = "supersecret123"', path="a.js")], [rule]), [])
        self.assertEqual(len(scan_diff([line('API_KEY = "supersecret123"', path="a.py")], [rule])), 1)

    def test_max_findings(self):
        lines = [line(f'API_KEY = "supersecret{n}"', n) for n in range(1, 6)]
        self.assertEqual(len(scan_diff(lines, [make_rule()], max_findings=2)), 2)

    def test_blocking_threshold(self):
        medium = scan_diff([line('API_KEY = "supersecret123"')], [make_rule(severity="medium")])
        self.assertFalse(has_blocking_findings(medium, "high"))
        self.assertTrue(has_blocking_findings(medium, "medium"))

    def test_report_allowlist_marks_non_blocking(self):
        findings = scan_diff([line('API_KEY = "supersecret123"', path="docs/a.py")], [make_rule()])
        marked = apply_report_allowlist(findings, ("docs/**",))
        self.assertFalse(marked[0].blocking)
        self.assertFalse(has_blocking_findings(marked, "high"))
        self.assertTrue(marked[0].flagged_code)  # still reported

    def test_baseline_rule_path_and_fingerprint(self):
        findings = scan_diff([line('API_KEY = "supersecret123"', path="a.py")], [make_rule()])
        self.assertEqual(apply_baseline(findings, Baseline(rule_ids={"test-secret"})), [])
        self.assertEqual(
            apply_baseline(findings, Baseline(fingerprints={findings[0].fingerprint})), []
        )
        self.assertEqual(apply_baseline(findings, Baseline(path_globs=("a.py",))), [])
        self.assertEqual(len(apply_baseline(findings, Baseline(path_globs=("b.py",)))), 1)

    def test_redact_span_clamps(self):
        self.assertEqual(redact_span("abc", -5, 99), "****")
        self.assertEqual(redact_span("abc", 2, 2), "abc")

    def test_multiple_rules_same_line(self):
        rules = [
            make_rule(rule_id="one"),
            make_rule(rule_id="two", source="custom"),
        ]
        findings = scan_diff([line('API_KEY = "supersecret123"')], rules)
        self.assertEqual({f.rule_id for f in findings}, {"one", "two"})


if __name__ == "__main__":
    unittest.main()
