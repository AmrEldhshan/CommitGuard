from __future__ import annotations

import base64
import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from core.pr_creator import (
    GitHubAPIError,
    GitHubClient,
    PullRequestOptions,
    build_inline_suggestions,
    build_pr_body,
    options_from_environment,
    publish_inline_review,
    publish_report_pr,
    pull_request_context_from_environment,
)

SECRET = "ghp_Ab9xK2mQ7pR4sT8vW1yZ6nC3dF5gH0jL2kM9"  # commit-guard-ignore


def finding(severity: str = "high", blocking: bool = True) -> SimpleNamespace:
    return SimpleNamespace(
        file="app.py",
        line_number=3,
        rule_id="gitleaks-github-pat",
        description="GitHub token detected",
        severity=severity,
        blocking=blocking,
        flagged_code=f'TOKEN = "{SECRET}"',
        redacted_code='TOKEN = "gh********M9"',
    )


def inline_finding(
    *,
    rule_id: str = "fix-verify",
    line: int = 3,
    flagged_code: str = "requests.get(url, verify=False)",
    redacted_code: str | None = None,
    severity: str = "medium",
) -> SimpleNamespace:
    return SimpleNamespace(
        file="app.py",
        line_number=line,
        rule_id=rule_id,
        description="TLS verification disabled",
        severity=severity,
        blocking=True,
        flagged_code=flagged_code,
        redacted_code=flagged_code if redacted_code is None else redacted_code,
    )


def fix_rule(
    rule_id: str = "fix-verify",
    *,
    is_secret: bool = False,
    fix_replacement: str | None = "verify=True",
) -> SimpleNamespace:
    return SimpleNamespace(
        rule_id=rule_id,
        is_secret=is_secret,
        fix_pattern=re.compile(r"verify\s*=\s*False"),
        fix_replacement=fix_replacement,
    )


class FakeClient:
    def __init__(self, *, base_exists: bool = True, branch_exists: bool = False):
        self.refs = {"main": {"object": {"sha": "base-sha"}}} if base_exists else {}
        if branch_exists:
            self.refs["commitguard/security-report"] = {"object": {"sha": "branch-sha"}}
        self.files: dict[str, dict] = {}
        self.pulls: list[dict] = []
        self.labels: list[tuple[int, tuple[str, ...]]] = []
        self.draft_calls: list[bool] = []
        self.created_refs: list[tuple[str, str]] = []
        self.content_calls: list[dict] = []
        self.review_comments: list[dict] = []
        self.reviews: list[dict] = []
        self.pull_files: list[dict] = [
            {
                "filename": "app.py",
                "patch": (
                    "@@ -1,3 +1,4 @@\n"
                    " line1\n"
                    " line2\n"
                    "+requests.get(url, verify=False)\n"
                    " line4"
                ),
            }
        ]

    def get_ref(self, repository, branch):
        return self.refs.get(branch)

    def create_ref(self, repository, branch, sha):
        self.refs[branch] = {"object": {"sha": sha}}
        self.created_refs.append((branch, sha))
        return self.refs[branch]

    def get_content(self, repository, path, branch):
        return self.files.get(path)

    def put_content(self, repository, path, *, content, message, branch, sha=None):
        self.content_calls.append(
            {"path": path, "content": content, "branch": branch, "sha": sha}
        )
        self.files[path] = {"sha": "file-sha", "content": content}
        return {"commit": {"sha": "commit-sha"}, "content": {"sha": "file-sha"}}

    def find_pull(self, repository, *, head_branch, base):
        return self.pulls[0] if self.pulls else None

    def create_pull(self, repository, *, title, head, base, body, draft):
        pull = {
            "number": 7,
            "html_url": "https://github.com/acme/demo/pull/7",
            "title": title,
            "body": body,
            "draft": draft,
            "node_id": "PR_node",
        }
        self.pulls.append(pull)
        return pull

    def update_pull(self, repository, number, *, title, body):
        pull = self.pulls[0]
        pull.update({"title": title, "body": body})
        return pull

    def add_labels(self, repository, number, labels):
        self.labels.append((number, labels))

    def set_draft(self, repository, pull, draft):
        self.draft_calls.append(draft)
        pull["draft"] = draft

    def list_review_comments(self, repository, number):
        return self.review_comments

    def list_pull_files(self, repository, number):
        return self.pull_files

    def create_review(self, repository, number, *, body, comments, commit_id=None):
        review = {
            "id": 99,
            "body": body,
            "comments": comments,
            "commit_id": commit_id,
        }
        self.reviews.append(review)
        self.review_comments.extend(comments)
        return review


class PullRequestTests(unittest.TestCase):
    def options(self, **overrides):
        values = {
            "repository": "acme/demo",
            "token": "token",
            "base": "main",
            "branch": "commitguard/security-report",
            "report_path": "commit_guard_reports/report.md",
        }
        values.update(overrides)
        return PullRequestOptions(**values)

    def test_body_contains_metadata_but_never_flagged_code(self):
        body = build_pr_body(
            [finding()],
            dependency_graph="graph TD\n  a --> b",
            block_threshold="high",
        )
        self.assertIn("CommitGuard security report", body)
        self.assertIn("gitleaks-github-pat", body)
        self.assertIn("```mermaid", body)
        self.assertIn("Blocking findings detected", body)
        self.assertNotIn(SECRET, body)

    def test_inline_suggestions_are_safe_and_deduplicated(self):
        suggestions = build_inline_suggestions(
            [
                inline_finding(),
                inline_finding(),
                inline_finding(rule_id="no-fix"),
            ],
            [fix_rule(), SimpleNamespace(
                rule_id="no-fix",
                is_secret=False,
                fix_pattern=None,
                fix_replacement=None,
            )],
        )
        self.assertEqual(len(suggestions), 1)
        self.assertEqual(suggestions[0].path, "app.py")
        self.assertEqual(suggestions[0].line, 3)
        self.assertIn(
            "```suggestion\nrequests.get(url, verify=True)\n```",
            suggestions[0].body,
        )
        self.assertIn("commitguard-inline", suggestions[0].body)
        self.assertNotIn(SECRET, suggestions[0].body)

    def test_inline_suggestions_skip_secret_lines_and_multiline_replacements(self):
        self.assertEqual(
            build_inline_suggestions(
                [inline_finding(rule_id="secret")],
                [fix_rule("secret", is_secret=True)],
            ),
            [],
        )
        self.assertEqual(
            build_inline_suggestions(
                [inline_finding(redacted_code='requests.get(url, verify="***")')],
                [fix_rule()],
            ),
            [],
        )
        self.assertEqual(
            build_inline_suggestions(
                [inline_finding()],
                [fix_rule(fix_replacement="verify=True\nextra")],
            ),
            [],
        )
        off_diff = publish_inline_review(
            FakeClient(),
            "acme/demo",
            7,
            findings=[inline_finding(line=10)],
            rules=[fix_rule()],
        )
        self.assertFalse(off_diff.reviewed)
        self.assertEqual(off_diff.skipped, 1)

    def test_publish_inline_review_deduplicates_comments(self):
        client = FakeClient()
        findings = [inline_finding()]
        rules = [fix_rule()]
        first = publish_inline_review(
            client,
            "acme/demo",
            7,
            findings=findings,
            rules=rules,
            commit_id="head-sha",
        )
        self.assertTrue(first.reviewed)
        self.assertEqual(first.posted, 1)
        self.assertEqual(first.review_id, 99)
        self.assertEqual(client.reviews[0]["commit_id"], "head-sha")
        self.assertEqual(client.reviews[0]["comments"][0]["side"], "RIGHT")

        second = publish_inline_review(
            client,
            "acme/demo",
            7,
            findings=findings,
            rules=rules,
            commit_id="head-sha",
        )
        self.assertFalse(second.reviewed)
        self.assertEqual(second.posted, 0)
        self.assertEqual(second.skipped, 1)
        self.assertEqual(len(client.reviews), 1)

    def test_pull_request_context_reads_event_then_ref(self):
        with tempfile.TemporaryDirectory() as directory:
            event_path = Path(directory) / "event.json"
            event_path.write_text(
                json.dumps(
                    {
                        "number": 11,
                        "pull_request": {
                            "number": 11,
                            "head": {"sha": "head-sha"},
                        },
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch.dict(
                os.environ,
                {"GITHUB_EVENT_PATH": str(event_path), "GITHUB_REF": "refs/pull/99/merge"},
                clear=True,
            ):
                context = pull_request_context_from_environment()
        self.assertEqual(context.number, 11)
        self.assertEqual(context.commit_id, "head-sha")

        with mock.patch.dict(
            os.environ,
            {"GITHUB_REF": "refs/pull/99/merge"},
            clear=True,
        ):
            context = pull_request_context_from_environment()
        self.assertEqual(context.number, 99)
        self.assertIsNone(context.commit_id)

    def test_creates_branch_file_and_full_pr_for_blocking_findings(self):
        client = FakeClient()
        result = publish_report_pr(
            client,
            self.options(),
            findings=[finding()],
            report_content="# redacted report\n",
            body="body",
        )
        self.assertTrue(result.created)
        self.assertFalse(result.draft)
        self.assertEqual(result.number, 7)
        self.assertEqual(result.commit_sha, "commit-sha")
        self.assertEqual(client.created_refs, [("commitguard/security-report", "base-sha")])
        self.assertEqual(client.labels, [(7, ("security",))])
        self.assertEqual(client.content_calls[0]["sha"], None)
        self.assertIn("redacted", client.content_calls[0]["content"])

    def test_updates_existing_pr_and_uses_existing_file_sha(self):
        client = FakeClient(branch_exists=True)
        client.files["commit_guard_reports/report.md"] = {"sha": "old-file"}
        client.pulls.append(
            {
                "number": 9,
                "html_url": "https://github.com/acme/demo/pull/9",
                "draft": True,
                "node_id": "PR_9",
            }
        )
        result = publish_report_pr(
            client,
            self.options(),
            findings=[finding(severity="medium", blocking=False)],
            report_content="# report\n",
            body="body",
        )
        self.assertFalse(result.created)
        self.assertTrue(result.updated)
        self.assertTrue(result.draft)
        self.assertEqual(result.number, 9)
        self.assertEqual(client.content_calls[0]["sha"], "old-file")
        self.assertEqual(client.created_refs, [])
        self.assertEqual(client.draft_calls, [True])
        self.assertEqual(client.labels, [])

    def test_draft_pr_when_no_blocking_findings(self):
        client = FakeClient()
        result = publish_report_pr(
            client,
            self.options(),
            findings=[finding(severity="low", blocking=False)],
            report_content="# report\n",
            body="body",
        )
        self.assertTrue(result.draft)
        self.assertTrue(client.pulls[0]["draft"])
        self.assertEqual(client.labels, [])

    def test_missing_base_branch_fails(self):
        client = FakeClient(base_exists=False)
        with self.assertRaises(GitHubAPIError):
            publish_report_pr(
                client,
                self.options(),
                findings=[],
                report_content="",
                body="",
            )

    def test_environment_options_and_token_validation(self):
        with mock.patch.dict(
            os.environ,
            {
                "GITHUB_REPOSITORY": "acme/demo",
                "GITHUB_TOKEN": "abc",
                "GITHUB_BASE_REF": "develop",
            },
            clear=True,
        ):
            options = options_from_environment()
        self.assertEqual(options.repository, "acme/demo")
        self.assertEqual(options.token, "abc")
        self.assertEqual(options.base, "develop")

        with (
            mock.patch.dict(os.environ, {"GITHUB_REPOSITORY": "acme/demo"}, clear=True),
            self.assertRaises(GitHubAPIError),
        ):
            options_from_environment()
        with mock.patch.dict(os.environ, {}, clear=True), self.assertRaises(GitHubAPIError):
            options_from_environment()

    def test_rest_client_encodes_content_and_parses_errors(self):
        response = mock.MagicMock()
        response.read.return_value = json.dumps({"ok": True}).encode()
        response.__enter__.return_value = response
        response.__exit__.return_value = None
        with mock.patch("urllib.request.urlopen", return_value=response) as opener:
            client = GitHubClient("token", api_url="https://api.example")
            result = client.put_content(
                "acme/demo",
                "reports/a b.md",
                content="hello",
                message="msg",
                branch="feature/x",
            )
        self.assertTrue(result["ok"])
        request = opener.call_args.args[0]
        self.assertTrue(request.full_url.endswith("/contents/reports/a%20b.md"))
        self.assertEqual(request.get_method(), "PUT")
        payload = json.loads(request.data)
        self.assertEqual(base64.b64decode(payload["content"]), b"hello")
        self.assertEqual(payload["branch"], "feature/x")
        self.assertEqual(request.headers["Authorization"], "Bearer token")


if __name__ == "__main__":
    unittest.main()
