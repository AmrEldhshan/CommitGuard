from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from main import run_scan

GIT = shutil.which("git")
VULN = {
    "id": "GHSA-requests-test",
    "aliases": ["CVE-2024-0001"],
    "summary": "Requests test vulnerability.",
    "database_specific": {"severity": "HIGH"},
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "requests"},
            "ranges": [
                {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.32.0"}]}
            ],
        }
    ],
}


@unittest.skipUnless(GIT, "git is required for integration tests")
class SCAIntegrationTests(unittest.TestCase):
    def test_sca_runs_without_changes_and_marks_graph(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            (root / "requirements.txt").write_text("requests==2.19.0\n", encoding="utf-8")
            (root / ".commit_guard_osv.json").write_text(
                json.dumps({"vulnerabilities": [VULN]}), encoding="utf-8"
            )
            code = run_scan(
                repo_dir=root,
                quiet=True,
                use_baseline=False,
                sca=True,
                dep_graph=True,
                fmt="both",
            )
            self.assertEqual(code, 1)
            report = (root / "commit_guard_reports/report.md").read_text()
            payload = json.loads(
                (root / "commit_guard_reports/report.json").read_text()
            )
            graph = (root / "commit_guard_reports/dependency-graph.mmd").read_text()
            self.assertIn("sca-GHSA-requests-test", report)
            self.assertIn("CVE-2024-0001", report)
            self.assertIn("2.32.0", report)
            self.assertEqual(payload["findings"][0]["fixed_versions"], ["2.32.0"])
            self.assertIn("📦 requests", graph)
            self.assertIn("vulnerable", graph)


if __name__ == "__main__":
    unittest.main()
