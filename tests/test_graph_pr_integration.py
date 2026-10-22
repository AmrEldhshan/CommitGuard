from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from core.pr_creator import (
    GitHubAPIError,
    InlineReviewResult,
    PullRequestContext,
    PullRequestOptions,
    PullRequestResult,
)
from main import run_scan

GIT = shutil.which("git")
SECRET = "ghp_Ab9xK2mQ7pR4sT8vW1yZ6nC3dF5gH0jL2kM9"  # commit-guard-ignore


@unittest.skipUnless(GIT, "git is required for integration tests")
class GraphAndPullRequestIntegrationTests(unittest.TestCase):
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

    def stage(self, name: str, content: str) -> None:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        subprocess.run(["git", "add", name], cwd=self.root, check=True)

    def test_scan_writes_graph_embeds_it_and_creates_redacted_pr(self):
        self.stage("lib.py", "VALUE = 1\n")
        self.stage("app.py", f'import lib\nTOKEN = "{SECRET}"\n')
        published = {}

        def fake_publish(client, options, *, findings, report_content, body):
            published.update(
                {
                    "options": options,
                    "findings": findings,
                    "report_content": report_content,
                    "body": body,
                }
            )
            return PullRequestResult(
                number=12,
                url="https://github.com/acme/demo/pull/12",
                branch=options.branch,
                created=True,
                updated=False,
                draft=False,
            )

        with (
            mock.patch(
                "main.options_from_environment",
                return_value=PullRequestOptions(
                    repository="acme/demo",
                    token="token",
                ),
            ),
            mock.patch("main.GitHubClient", return_value=object()),
            mock.patch("main.publish_report_pr", side_effect=fake_publish),
        ):
            code = run_scan(
                repo_dir=self.root,
                quiet=True,
                use_baseline=False,
                dep_graph=True,
                dep_graph_format="all",
                create_pr=True,
            )

        self.assertEqual(code, 1)
        graph = self.root / "commit_guard_reports/dependency-graph.mmd"
        payload = self.root / "commit_guard_reports/dependency-graph.json"
        dot = self.root / "commit_guard_reports/dependency-graph.dot"
        self.assertTrue(graph.is_file())
        self.assertTrue(payload.is_file())
        self.assertTrue(dot.is_file())
        self.assertIn("app.py", graph.read_text())
        report = (self.root / "commit_guard_reports/report.md").read_text()
        self.assertIn("Dependency Blast Radius", report)
        self.assertIn("```mermaid", report)
        self.assertGreaterEqual(len(published["findings"]), 1)
        self.assertNotIn(SECRET, published["report_content"])
        self.assertNotIn(SECRET, published["body"])
        self.assertIn("Dependency blast radius", published["body"])

    def test_scan_posts_inline_suggestions_on_originating_pr(self):
        self.stage("app.py", "requests.get(url, verify=False)\n")
        published = {}

        def fake_review(client, repository, number, *, findings, rules, commit_id):
            published.update(
                {
                    "repository": repository,
                    "number": number,
                    "findings": findings,
                    "rules": rules,
                    "commit_id": commit_id,
                }
            )
            return InlineReviewResult(reviewed=True, posted=1, skipped=0, review_id=5)

        with (
            mock.patch(
                "main.options_from_environment",
                return_value=PullRequestOptions(
                    repository="acme/demo",
                    token="token",
                ),
            ),
            mock.patch("main.GitHubClient", return_value=object()),
            mock.patch(
                "main.pull_request_context_from_environment",
                return_value=PullRequestContext(number=17, commit_id="head-sha"),
            ),
            mock.patch("main.publish_inline_review", side_effect=fake_review),
        ):
            code = run_scan(
                repo_dir=self.root,
                quiet=True,
                threshold="medium",
                use_baseline=False,
                review_pr=True,
            )

        self.assertEqual(code, 1)
        self.assertEqual(published["repository"], "acme/demo")
        self.assertEqual(published["number"], 17)
        self.assertEqual(published["commit_id"], "head-sha")
        self.assertIn(
            "cg-python-tls-verify-disabled",
            [finding.rule_id for finding in published["findings"]],
        )

    def test_review_without_pull_request_context_returns_operational_failure(self):
        self.stage("app.py", "requests.get(url, verify=False)\n")
        with (
            mock.patch(
                "main.options_from_environment",
                return_value=PullRequestOptions(
                    repository="acme/demo",
                    token="token",
                ),
            ),
            mock.patch(
                "main.pull_request_context_from_environment",
                return_value=PullRequestContext(number=None),
            ),
        ):
            code = run_scan(
                repo_dir=self.root,
                quiet=True,
                use_baseline=False,
                review_pr=True,
            )
        self.assertEqual(code, 2)

    def test_pr_configuration_error_returns_operational_failure(self):
        self.stage("app.py", "print('safe')\n")
        with mock.patch(
            "main.options_from_environment",
            side_effect=GitHubAPIError("GITHUB_TOKEN is missing"),
        ):
            code = run_scan(
                repo_dir=self.root,
                quiet=True,
                use_baseline=False,
                create_pr=True,
            )
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
