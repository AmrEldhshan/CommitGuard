# CI integration

Commit Guard is designed to produce machine-readable results and stable exit
codes, so it can gate a pull request without any service dependency.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed; no finding met the blocking threshold. |
| `1` | Blocking finding(s) found. |
| `2` | Commit Guard could not run: not a git repo, invalid config, unreadable rules, missing PyYAML, etc. |

Treat `2` as a failed job. It means the scanner did not actually validate the
change.

---

## Reports from CI

```bash
python .commit_guard/main.py \
    --repo . \
    --diff origin/main...HEAD \
    --format sarif \
    --quiet
```

The report is written to `commit_guard_reports/report.sarif` unless
`--report-path` is given. Use `--format both` for Markdown + JSON, `--format
junit` for test-summary widgets, `--format gitlab` for GitLab Code Quality, or
`--format checkstyle` for CI dashboards.

History and full-tree audits use the same reporters:

```bash
python .commit_guard/main.py --repo . --history 50 --format sarif
python .commit_guard/main.py --repo . --all --format gitlab --quiet
python .commit_guard/main.py --repo . --fail-on new --format sarif
```

`--fail-on new` keeps baselined findings in the SARIF output as
`baselineState: "unchanged"` and only fails on newly introduced findings.

`--quiet` suppresses the terminal summary but does **not** suppress the report
or change the exit code.

---

## HTML dashboard artifact

CI runners cannot host the local GUI, but the same self-contained HTML dashboard
can be uploaded as a build artifact and opened by anyone with access to the run:

```yaml
- uses: AmrEldhshan/CommitGuard@main
  with:
    format: html
    scan-mode: all

- uses: actions/upload-artifact@v4
  with:
    name: commitguard-report
    path: commit_guard_reports/report.html
```

The HTML report contains inline CSS and SVG only — no scripts, CDNs, or fonts —
and secret values remain redacted. Locally, `./commit-guard gui` provides the
interactive version of the same results.

---

## JSON schema

```json
{
  "schema_version": 2,
  "tool": {"name": "CommitGuard", "version": "2.1.0"},
  "generated": "2026-01-01 12:00:00 UTC",
  "block_threshold": "high",
  "blocked": true,
  "truncated": false,
  "redacted": true,
  "summary": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
  "total": 1,
  "findings": [
    {
      "file": "src/app.py",
      "line": 12,
      "rule_id": "generic-api-key",
      "severity": "high",
      "source": "gitleaks",
      "description": "Detected a Generic API Key...",
      "cwe": "CWE-798",
      "tags": ["secret"],
      "fingerprint": "0123456789abcdef",
      "blocking": true,
      "baseline_state": "new",
      "flagged_code": "API_KEY = \"AK********LE\""
    }
  ]
}
```

`findings[].flagged_code` is redacted unless `--show-secrets` was passed.
`blocking` is `false` for findings in `[paths].report_allowlist`; those still
appear in the report. `baseline_state` is `"new"` or `"unchanged"` and maps
directly to SARIF `baselineState`.

---

## GitHub Actions with SARIF upload

```yaml
name: commit-guard

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write   # required for SARIF upload

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Check out the target repository
        uses: actions/checkout@v4
        with:
          path: target
          fetch-depth: 0       # needed for a revision-range scan

      - name: Check out Commit Guard
        uses: actions/checkout@v4
        with:
          repository: AmrEldhshan/CommitGuard
          path: commitguard

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install dependencies
        run: pip install pyyaml

      - name: Install Commit Guard into the checkout
        run: python commitguard/install_hook.py install target --no-gitignore

      - name: Scan the pull request diff
        working-directory: target
        run: |
          python .commit_guard/main.py \
            --repo . \
            --diff "origin/${{ github.base_ref }}...HEAD" \
            --format sarif \
            --quiet

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: target/commit_guard_reports/report.sarif
          category: commit-guard
```

Notes:

- `fetch-depth: 0` is important for `origin/<base>...HEAD`.
- If you prefer annotations in the workflow log instead of/alongside SARIF,
  set `github_annotations = true` or rely on `GITHUB_ACTIONS=true` (automatic).
- `if: always()` uploads results even when the scan exits `1`.
- Pin third-party actions to a commit SHA if your organization requires it.

For a push event, use `${{ github.event.before }}...${{ github.sha }}`; for a
PR event, the base-ref form above is usually easiest.

---

## Pre-commit framework

Commit Guard ships a tested `.pre-commit-hooks.yaml`. Install the engine
without a native hook, then use the framework:

```bash
python install_hook.py install . --no-hook
```

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/AmrEldhshan/CommitGuard
    rev: v2.1.0
    hooks:
      - id: commit-guard
      - id: commit-guard-push   # optional; runs on git push
```

The hook entry runs `python .commit_guard/main.py` from the target repository,
so both the rules and reports stay local. Choose either the native installer
hook or the framework hook; `--no-hook` avoids conflicts.

---

## GitLab CI

```yaml
commit-guard:
  image: python:3.12
  variables:
    GIT_DEPTH: "0"
  before_script:
    - pip install pyyaml
    - python commitguard/install_hook.py install . --no-gitignore
  script:
    - |
      python .commit_guard/main.py \
        --repo . \
        --diff "origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME...HEAD" \
        --format gitlab \
        --report-path gl-code-quality-report.json \
        --quiet
  artifacts:
    when: always
    reports:
      codequality: gl-code-quality-report.json
    paths:
      - commit_guard_reports/
```

A non-zero exit code fails the job. If you vendor Commit Guard as a git
submodule, check it out before `before_script`.

---

## Jenkins

```groovy
stage('Commit Guard') {
    steps {
        sh 'pip install pyyaml'
        sh 'python commitguard/install_hook.py install . --no-gitignore'
        sh 'python .commit_guard/main.py --repo . --diff origin/main...HEAD --format both'
    }
    post {
        always {
            archiveArtifacts artifacts: 'commit_guard_reports/**', allowEmptyArchive: true
        }
    }
}
```

---

## Generic CI shell

```bash
set -eu
pip install pyyaml
python /path/to/CommitGuard/install_hook.py install . --no-gitignore
python .commit_guard/main.py --repo . --diff "$BASE...HEAD" --format both
```

Prefer scanning a revision range (`--diff`) in CI rather than the staging area,
because clean CI checkouts usually have nothing staged.

---

## Caching the rule cache

The parsed-rule cache lives in the user cache directory. In ephemeral CI it
starts cold (a few seconds). To cache it between runs, point
`COMMIT_GUARD_CACHE_DIR` at a persisted directory:

```yaml
env:
  COMMIT_GUARD_CACHE_DIR: ${{ github.workspace }}/.cache/commit-guard
```

Cache invalidation is automatic when any rule file changes, so a stale cache
cannot mask a rule update.

---

## Handling findings as a team

- **Fix** the finding when it is real.
- **Rotate** any committed credential; a redacted report does not undo the
  leak.
- **Suppress narrowly** with inline comments or fingerprints in
  `.commit_guard_ignore`, and review those suppressions periodically.
- **Use `report_allowlist`** for paths you want visible but non-blocking.
- **Raise/lower severity** in `.commit_guard.toml` rather than editing upstream
  packs.

Run `python .commit_guard/main.py --no-baseline` and
`python .commit_guard/main.py --audit-suppressions --strict` periodically to
audit what your allowlists hide.
