from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stdout

from core.reporter import (
    build_json_report,
    build_markdown_report,
    build_sarif_report,
    print_github_annotations,
)
from core.scanner import Finding


def finding(**overrides) -> Finding:
    defaults = {
        "file": "src/app.py",
        "line_number": 7,
        "rule_id": "test-secret",
        "description": "A secret was found.",
        "severity": "high",
        "source": "gitleaks",
        "flagged_code": 'API_KEY = "supersecret123"',  # commit-guard-ignore
        "redacted_code": 'API_KEY = "su********23"',
        "fingerprint": "1234567890abcdef",
        "tags": ("secret",),
        "cwe": "CWE-798",
    }
    defaults.update(overrides)
    return Finding(**defaults)


class ReporterTests(unittest.TestCase):
    def test_markdown_redacts_by_default(self):
        text = build_markdown_report([finding()], "high")
        self.assertIn("FAILED", text)
        self.assertNotIn("supersecret123", text)
        self.assertIn("su********23", text)
        self.assertIn("CWE-798", text)

    def test_markdown_show_secrets(self):
        text = build_markdown_report([finding()], "high", show_secrets=True)
        self.assertIn("supersecret123", text)

    def test_markdown_empty(self):
        text = build_markdown_report([], "high")
        self.assertIn("No issues detected", text)
        self.assertIn("PASSED", text)

    def test_markdown_non_blocking_marker(self):
        text = build_markdown_report([finding(blocking=False)], "high")
        self.assertIn("non-blocking", text)
        self.assertIn("PASSED", text)

    def test_json_structure_and_redaction(self):
        payload = json.loads(build_json_report([finding()], "high"))
        self.assertEqual(payload["schema_version"], 2)
        self.assertTrue(payload["blocked"])
        self.assertTrue(payload["redacted"])
        self.assertEqual(payload["summary"]["high"], 1)
        self.assertEqual(payload["total"], 1)
        item = payload["findings"][0]
        self.assertEqual(item["fingerprint"], "1234567890abcdef")
        self.assertNotIn("supersecret123", item["flagged_code"])
        self.assertTrue(item["blocking"])

    def test_json_show_secrets(self):
        payload = json.loads(build_json_report([finding()], "high", show_secrets=True))
        self.assertIn("supersecret123", payload["findings"][0]["flagged_code"])
        self.assertFalse(payload["redacted"])

    def test_sarif_structure(self):
        payload = json.loads(build_sarif_report([finding()], "high"))
        self.assertEqual(payload["version"], "2.1.0")
        run = payload["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "CommitGuard")
        self.assertEqual(run["results"][0]["level"], "error")
        self.assertEqual(run["results"][0]["ruleId"], "test-secret")
        self.assertEqual(
            run["results"][0]["partialFingerprints"]["primaryLocationLineHash"],
            "1234567890abcdef",
        )
        self.assertNotIn("supersecret123", json.dumps(payload))

    def test_sarif_severity_levels(self):
        for severity, expected in (("critical", "error"), ("high", "error"),
                                   ("medium", "warning"), ("low", "note"), ("info", "note")):
            payload = json.loads(build_sarif_report([finding(severity=severity)], "high"))
            self.assertEqual(payload["runs"][0]["results"][0]["level"], expected)

    def test_github_annotations(self):
        output = io.StringIO()
        with redirect_stdout(output):
            print_github_annotations([finding()], "high")
        text = output.getvalue()
        self.assertIn("::error file=src/app.py,line=7", text)
        self.assertIn("test-secret", text)
        self.assertNotIn("supersecret123", text)

    def test_github_annotation_escaping(self):
        output = io.StringIO()
        with redirect_stdout(output):
            print_github_annotations(
                [
                    finding(
                        file="a,b:c.py",
                        flagged_code="line\nnext%",
                        redacted_code="line\nnext%",
                    )
                ],
                "high",
            )
        text = output.getvalue()
        self.assertIn("a%2Cb%3Ac.py", text)
        self.assertIn("%25", text)


if __name__ == "__main__":
    unittest.main()
