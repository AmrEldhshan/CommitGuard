"""
GitHub pull-request automation using only the Python standard library.

No third-party client, OAuth app, or telemetry is involved.  The default
GitHub Actions ``GITHUB_TOKEN`` works for same-repository report PRs; a PAT
can be supplied locally through ``GITHUB_TOKEN`` or ``GH_TOKEN``.

Secrets are never copied into PR bodies or report commits: callers pass a
redacted report and the body builder only renders metadata.
"""

from __future__ import annotations

import base64
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

API_URL = "https://api.github.com"
_USER_AGENT = "CommitGuard/2"
_TIMEOUT_SECONDS = 20
_INLINE_MARKER = "<!-- commitguard-inline -->"
_PULL_REF_RE = re.compile(r"^refs/pull/(\d+)/")


class GitHubAPIError(RuntimeError):
    """Raised for GitHub API/network failures."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class PullRequestOptions:
    repository: str
    token: str
    base: str = "main"
    branch: str = "commitguard/security-report"
    title: str = "CommitGuard security report"
    report_path: str = "commit_guard_reports/report.md"
    api_url: str = API_URL
    labels: tuple[str, ...] = ("security",)
    draft: bool | None = None


@dataclass(frozen=True)
class PullRequestResult:
    number: int | None
    url: str | None
    branch: str
    created: bool
    updated: bool
    draft: bool
    commit_sha: str | None = None
    warnings: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class InlineSuggestion:
    path: str
    line: int
    rule_id: str
    body: str


@dataclass(frozen=True)
class InlineReviewResult:
    reviewed: bool
    posted: int
    skipped: int
    review_id: int | None = None
    warnings: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class PullRequestContext:
    number: int | None
    commit_id: str | None = None


class GitHubClient:
    """Small, mockable GitHub REST client."""

    def __init__(
        self,
        token: str,
        *,
        api_url: str = API_URL,
        timeout: int = _TIMEOUT_SECONDS,
    ) -> None:
        if not token:
            raise ValueError("A GitHub token is required.")
        self.token = token
        self.api_url = api_url.rstrip("/")
        self.timeout = timeout

    def _request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
    ) -> Any:
        url = f"{self.api_url}{path}"
        data = None
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.token}",
            "User-Agent": _USER_AGENT,
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = response.read()
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            message = raw
            try:
                parsed = json.loads(raw)
                message = parsed.get("message", raw)
            except json.JSONDecodeError:
                pass
            raise GitHubAPIError(
                f"GitHub {method} {path} failed ({exc.code}): {message}",
                status=exc.code,
            ) from exc
        except urllib.error.URLError as exc:
            raise GitHubAPIError(f"Could not reach GitHub: {exc.reason}") from exc
        if not body:
            return None
        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            raise GitHubAPIError("GitHub returned a non-JSON response.") from exc

    def get_ref(self, repository: str, branch: str) -> dict[str, Any] | None:
        path = f"/repos/{repository}/git/ref/heads/{_branch_path(branch)}"
        try:
            return self._request("GET", path)
        except GitHubAPIError as exc:
            if exc.status == 404:
                return None
            raise

    def create_ref(self, repository: str, branch: str, sha: str) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/repos/{repository}/git/refs",
            {"ref": f"refs/heads/{branch}", "sha": sha},
        )

    def get_content(
        self,
        repository: str,
        path: str,
        branch: str,
    ) -> dict[str, Any] | None:
        quoted = urllib.parse.quote(path, safe="/")
        try:
            return self._request(
                "GET",
                f"/repos/{repository}/contents/{quoted}?ref={urllib.parse.quote(branch, safe='')}",
            )
        except GitHubAPIError as exc:
            if exc.status == 404:
                return None
            raise

    def put_content(
        self,
        repository: str,
        path: str,
        *,
        content: str,
        message: str,
        branch: str,
        sha: str | None = None,
    ) -> dict[str, Any]:
        quoted = urllib.parse.quote(path, safe="/")
        payload: dict[str, Any] = {
            "message": message,
            "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
            "branch": branch,
        }
        if sha:
            payload["sha"] = sha
        return self._request(
            "PUT",
            f"/repos/{repository}/contents/{quoted}",
            payload,
        )

    def find_pull(
        self,
        repository: str,
        *,
        head_branch: str,
        base: str,
    ) -> dict[str, Any] | None:
        owner = repository.split("/", 1)[0]
        query = urllib.parse.urlencode(
            {"state": "open", "head": f"{owner}:{head_branch}", "base": base}
        )
        pulls = self._request("GET", f"/repos/{repository}/pulls?{query}")
        if isinstance(pulls, list) and pulls:
            return pulls[0]
        return None

    def create_pull(
        self,
        repository: str,
        *,
        title: str,
        head: str,
        base: str,
        body: str,
        draft: bool,
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/repos/{repository}/pulls",
            {
                "title": title,
                "head": head,
                "base": base,
                "body": body,
                "draft": draft,
            },
        )

    def update_pull(
        self,
        repository: str,
        number: int,
        *,
        title: str,
        body: str,
    ) -> dict[str, Any]:
        return self._request(
            "PATCH",
            f"/repos/{repository}/pulls/{number}",
            {"title": title, "body": body},
        )

    def add_labels(
        self,
        repository: str,
        number: int,
        labels: tuple[str, ...],
    ) -> Any:
        return self._request(
            "POST",
            f"/repos/{repository}/issues/{number}/labels",
            {"labels": list(labels)},
        )

    def set_draft(self, repository: str, pull: dict[str, Any], draft: bool) -> None:
        """Best-effort draft/ready transition through the GraphQL API."""
        current = bool(pull.get("draft"))
        if current == draft:
            return
        node_id = pull.get("node_id")
        if not node_id:
            raise GitHubAPIError("GitHub did not return a pull-request node_id.")
        mutation = (
            "convertPullRequestToDraft"
            if draft
            else "markPullRequestReadyForReview"
        )
        query = (
            f"mutation($id: ID!) {{ {mutation}(input: {{pullRequestId: $id}}) "
            "{ pullRequest { isDraft } } }"
        )
        self._request(
            "POST",
            "/graphql",
            {"query": query, "variables": {"id": node_id}},
        )

    def list_review_comments(
        self,
        repository: str,
        number: int,
    ) -> list[dict[str, Any]]:
        comments = self._request(
            "GET",
            f"/repos/{repository}/pulls/{number}/comments?per_page=100",
        )
        return comments if isinstance(comments, list) else []

    def list_pull_files(
        self,
        repository: str,
        number: int,
    ) -> list[dict[str, Any]]:
        files: list[dict[str, Any]] = []
        for page in range(1, 11):
            batch = self._request(
                "GET",
                f"/repos/{repository}/pulls/{number}/files?per_page=100&page={page}",
            )
            if not isinstance(batch, list):
                break
            files.extend(batch)
            if len(batch) < 100:
                break
        return files

    def create_review(
        self,
        repository: str,
        number: int,
        *,
        body: str,
        comments: list[dict[str, Any]],
        commit_id: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "body": body,
            "event": "COMMENT",
            "comments": comments,
        }
        if commit_id:
            payload["commit_id"] = commit_id
        return self._request(
            "POST",
            f"/repos/{repository}/pulls/{number}/reviews",
            payload,
        )


def _branch_path(branch: str) -> str:
    return urllib.parse.quote(branch, safe="/")


def _severity_counts(findings: list) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        severity = getattr(finding, "severity", "info")
        if severity in counts:
            counts[severity] += 1
    return counts


def build_pr_body(
    findings: list,
    *,
    dependency_graph: str | None = None,
    block_threshold: str = "high",
    max_findings: int = 25,
) -> str:
    """Builds a PR description without ever including flagged code."""
    counts = _severity_counts(findings)
    blocking = any(getattr(finding, "blocking", False) for finding in findings)
    lines = [
        "## 🛡️ CommitGuard security report",
        "",
        (
            "This PR was generated automatically. It contains a report only and "
            "does not modify application code."
        ),
        "",
        f"**Status:** {'❌ Blocking findings detected' if blocking else '✅ No blocking findings'}",
        f"**Block threshold:** `{block_threshold}` and above",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for severity in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {severity.capitalize()} | {counts[severity]} |")
    lines.append(f"| **Total** | **{len(findings)}** |")
    lines.append("")

    if findings:
        lines.append("### Findings")
        lines.append("")
        lines.append("| Severity | Rule | File | Line |")
        lines.append("|----------|------|------|------|")
        for finding in findings[:max_findings]:
            rule = str(getattr(finding, "rule_id", "unknown")).replace("|", "\\|")
            file_path = str(getattr(finding, "file", "unknown")).replace("|", "\\|")
            lines.append(
                f"| {finding.severity} | `{rule}` | `{file_path}` | "
                f"{getattr(finding, 'line_number', 0)} |"
            )
        if len(findings) > max_findings:
            lines.append(
                f"| … | {len(findings) - max_findings} more | | |"
            )
        lines.append("")

    if dependency_graph:
        lines.append("### Dependency blast radius")
        lines.append("")
        lines.append("```mermaid")
        lines.append(dependency_graph.rstrip())
        lines.append("```")
        lines.append("")

    lines.extend(
        [
            "---",
            (
                "Generated by [CommitGuard](https://github.com/) — offline-first, "
                "no telemetry, secrets redacted."
            ),
        ]
    )
    return "\n".join(lines) + "\n"


def _right_side_lines(patch: str) -> set[int]:
    lines: set[int] = set()
    new_line: int | None = None
    for raw in patch.splitlines():
        if raw.startswith("@@"):
            match = re.search(r"\+(\d+)(?:,\d+)?", raw)
            new_line = int(match.group(1)) if match else None
            continue
        if new_line is None or raw.startswith("\\"):
            continue
        if raw.startswith("-"):
            continue
        lines.add(new_line)
        new_line += 1
    return lines


def build_inline_suggestions(
    findings: list,
    rules: tuple | list,
    *,
    max_suggestions: int = 50,
) -> list[InlineSuggestion]:
    """Builds safe click-to-commit suggestions for auto-fixable findings."""
    if max_suggestions < 1:
        return []
    rules_by_id = {getattr(rule, "rule_id", ""): rule for rule in rules}
    secret_locations = {
        (getattr(finding, "file", ""), getattr(finding, "line_number", 0))
        for finding in findings
        if getattr(rules_by_id.get(getattr(finding, "rule_id", "")), "is_secret", False)
    }
    suggestions: list[InlineSuggestion] = []
    seen_locations: set[tuple[str, int]] = set()
    for finding in findings:
        rule = rules_by_id.get(getattr(finding, "rule_id", ""))
        if rule is None or getattr(rule, "is_secret", False):
            continue
        fix_pattern = getattr(rule, "fix_pattern", None)
        fix_replacement = getattr(rule, "fix_replacement", None)
        if fix_pattern is None or fix_replacement is None:
            continue
        path = str(getattr(finding, "file", ""))
        line = int(getattr(finding, "line_number", 0) or 0)
        if not path or line < 1:
            continue
        location = (path, line)
        if location in secret_locations or location in seen_locations:
            continue
        source = str(getattr(finding, "flagged_code", ""))
        if not source or source != str(getattr(finding, "redacted_code", source)):
            continue
        try:
            replacement = fix_pattern.sub(fix_replacement, source, count=1)
        except (re.error, IndexError):
            continue
        if replacement == source or "\n" in replacement or "\r" in replacement:
            continue
        if "```" in replacement:
            continue
        description = str(getattr(finding, "description", "Security finding"))
        severity = str(getattr(finding, "severity", "info"))
        body = "\n".join(
            [
                _INLINE_MARKER,
                f"🚨 **CommitGuard Finding** [`{finding.rule_id}`]",
                "",
                f"**Severity:** {severity}",
                "",
                description,
                "",
                "```suggestion",
                replacement,
                "```",
            ]
        )
        suggestions.append(
            InlineSuggestion(
                path=path,
                line=line,
                rule_id=str(finding.rule_id),
                body=body,
            )
        )
        seen_locations.add(location)
        if len(suggestions) >= max_suggestions:
            break
    return suggestions


def publish_inline_review(
    client: GitHubClient,
    repository: str,
    number: int,
    *,
    findings: list,
    rules: tuple | list,
    commit_id: str | None = None,
    max_suggestions: int = 50,
) -> InlineReviewResult:
    """Posts de-duplicated inline suggestions on an existing pull request."""
    suggestions = build_inline_suggestions(
        findings, rules, max_suggestions=max_suggestions
    )
    if not suggestions:
        return InlineReviewResult(reviewed=False, posted=0, skipped=0)

    warnings: list[str] = []
    try:
        existing = client.list_review_comments(repository, number)
    except GitHubAPIError as exc:
        warnings.append(f"Could not list existing review comments: {exc}")
        existing = []
    existing_keys = {
        (
            str(comment.get("path", "")),
            int(comment.get("line") or comment.get("original_line") or 0),
            str(comment.get("body", "")),
        )
        for comment in existing
    }
    fresh = [
        suggestion
        for suggestion in suggestions
        if (suggestion.path, suggestion.line, suggestion.body) not in existing_keys
    ]
    skipped = len(suggestions) - len(fresh)
    try:
        pull_files = client.list_pull_files(repository, number)
    except GitHubAPIError as exc:
        warnings.append(f"Could not verify pull-request diff lines: {exc}")
    else:
        valid_lines = {
            (str(item.get("filename", "")), line)
            for item in pull_files
            for line in _right_side_lines(str(item.get("patch") or ""))
        }
        filtered = [
            suggestion
            for suggestion in fresh
            if (suggestion.path, suggestion.line) in valid_lines
        ]
        skipped += len(fresh) - len(filtered)
        fresh = filtered
    if not fresh:
        return InlineReviewResult(
            reviewed=False,
            posted=0,
            skipped=skipped,
            warnings=tuple(warnings),
        )

    review = client.create_review(
        repository,
        number,
        body="CommitGuard inline suggestions",
        comments=[
            {
                "path": suggestion.path,
                "line": suggestion.line,
                "side": "RIGHT",
                "body": suggestion.body,
            }
            for suggestion in fresh
        ],
        commit_id=commit_id,
    )
    review_id = review.get("id") if isinstance(review, dict) else None
    return InlineReviewResult(
        reviewed=True,
        posted=len(fresh),
        skipped=skipped,
        review_id=int(review_id) if review_id else None,
        warnings=tuple(warnings),
    )


def pull_request_context_from_environment() -> PullRequestContext:
    """Reads the current pull-request number and head SHA from Actions."""
    payload: dict[str, Any] = {}
    event_path = os.environ.get("GITHUB_EVENT_PATH", "")
    if event_path:
        try:
            with open(event_path, encoding="utf-8") as handle:
                parsed = json.load(handle)
            if isinstance(parsed, dict):
                payload = parsed
        except (OSError, json.JSONDecodeError):
            payload = {}

    number: int | None = None
    commit_id: str | None = None
    pull_request = payload.get("pull_request")
    if isinstance(pull_request, dict):
        raw_number = pull_request.get("number") or payload.get("number")
        number = _positive_int(raw_number)
        head = pull_request.get("head")
        if isinstance(head, dict):
            commit_id = str(head.get("sha") or "") or None
    if number is None:
        number = _positive_int(payload.get("number"))
    if number is None:
        match = _PULL_REF_RE.match(os.environ.get("GITHUB_REF", ""))
        if match:
            number = int(match.group(1))
    if number is None:
        number = _positive_int(os.environ.get("GITHUB_PR_NUMBER"))
    return PullRequestContext(number=number, commit_id=commit_id)


def _positive_int(value: object) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def publish_report_pr(
    client: GitHubClient,
    options: PullRequestOptions,
    *,
    findings: list,
    report_content: str,
    body: str,
) -> PullRequestResult:
    """
    Creates or updates a report-only PR.

    The branch is created from the configured base when absent.  The report
    file is committed to that branch, then the open PR (if any) is updated.
    Draft state is derived from blocking findings unless explicitly supplied.
    """
    repository = options.repository
    warnings: list[str] = []
    base_ref = client.get_ref(repository, options.base)
    if not base_ref:
        raise GitHubAPIError(f"Base branch not found: {options.base}", status=404)

    branch_ref = client.get_ref(repository, options.branch)
    if not branch_ref:
        base_sha = (base_ref.get("object") or {}).get("sha")
        if not base_sha:
            raise GitHubAPIError("GitHub did not return the base branch SHA.")
        client.create_ref(repository, options.branch, base_sha)

    existing_file = client.get_content(repository, options.report_path, options.branch)
    existing_sha = existing_file.get("sha") if existing_file else None
    commit = client.put_content(
        repository,
        options.report_path,
        content=report_content,
        message="chore(commitguard): update security report",
        branch=options.branch,
        sha=existing_sha,
    )
    commit_sha = (commit.get("commit") or {}).get("sha")
    if not commit_sha:
        commit_sha = (commit.get("content") or {}).get("sha")

    blocking = any(getattr(finding, "blocking", False) for finding in findings)
    critical_or_high = any(
        getattr(finding, "severity", "") in {"critical", "high"}
        for finding in findings
    )
    draft = options.draft if options.draft is not None else not blocking
    existing_pull = client.find_pull(
        repository, head_branch=options.branch, base=options.base
    )
    if existing_pull:
        number = int(existing_pull["number"])
        updated = client.update_pull(
            repository,
            number,
            title=options.title,
            body=body,
        )
        pull = {**existing_pull, **updated}
        created = False
    else:
        owner = repository.split("/", 1)[0]
        created_pull = client.create_pull(
            repository,
            title=options.title,
            head=f"{owner}:{options.branch}",
            base=options.base,
            body=body,
            draft=draft,
        )
        number = int(created_pull["number"])
        pull = created_pull
        created = True

    try:
        client.set_draft(repository, pull, draft)
    except GitHubAPIError as exc:
        warnings.append(f"Could not set draft state: {exc}")

    labels = options.labels if critical_or_high else ()
    if labels:
        try:
            client.add_labels(repository, number, labels)
        except GitHubAPIError as exc:
            warnings.append(f"Could not add labels: {exc}")

    return PullRequestResult(
        number=number,
        url=pull.get("html_url"),
        branch=options.branch,
        created=created,
        updated=not created,
        draft=draft,
        commit_sha=commit_sha,
        warnings=tuple(warnings),
    )


def options_from_environment(
    *,
    base: str | None = None,
    branch: str | None = None,
    title: str | None = None,
    report_path: str = "commit_guard_reports/report.md",
) -> PullRequestOptions:
    """Builds options from Actions/local environment variables."""
    repository = os.environ.get("GITHUB_REPOSITORY", "").strip()
    token = (
        os.environ.get("GITHUB_TOKEN")
        or os.environ.get("GH_TOKEN")
        or ""
    ).strip()
    if not repository:
        raise GitHubAPIError(
            "GITHUB_REPOSITORY is required (format: owner/repository)."
        )
    if not token:
        raise GitHubAPIError("GITHUB_TOKEN or GH_TOKEN is required for --create-pr.")
    return PullRequestOptions(
        repository=repository,
        token=token,
        base=base or os.environ.get("GITHUB_BASE_REF") or "main",
        branch=branch or "commitguard/security-report",
        title=title or "CommitGuard security report",
        report_path=report_path,
    )
