# Changelog

## 2.1.0

### Added

- Pre-push scanning with `install --pre-push`; audits every commit in each
  pushed ref range and catches secrets added then removed within the range.
- Audit modes: `scan --history N` (including full history with `0`) and
  `scan --all` for the entire tracked/untracked working tree.
- Baseline automation: `scan --update-baseline`, `--baseline-owner`,
  `--baseline-expiry`, and `suppressions audit` for expired, stale,
  unknown-rule, and unmatched-path entries.
- Optional fingerprint metadata (`# owner=... expiry=...`); expired entries
  stop suppressing findings.
- `--soft-fail` and installer profiles (`--profile strict|balanced|audit`).
- `check-rules`: schema validation, regex compilation checks, and a
  positive/negative corpus (`rules/corpus.yaml`); `explain RULE_ID`.
- SARIF `baselineState`, JSON `baseline_state`, and `--fail-on new` to block
  only findings not accepted in the baseline.
- JUnit XML, GitLab Code Quality JSON, and Checkstyle XML reporters.
- Bounded multi-line context rules (`context.before`, `context.after`,
  `context.regex`) with staged/working-tree content and a curated SQLi example.
- Placeholder filtering for obvious example/dummy secrets and entropy
  thresholds capped to the observed character class (hex vs base64).
- `.pre-commit-hooks.yaml` with tested pre-commit and pre-push hook IDs;
  `install --no-hook` avoids conflicts with the pre-commit framework.
- 112-test stdlib `unittest` suite.

### Changed

- Rule cache format version bumped to `7` for context-window metadata and
  stricter custom-rule validation.
- Version bumped to `2.1.0`.
- Documentation expanded for audit modes, profiles, suppression hygiene, rule
  corpus/context, new reporters, and pre-commit framework usage.

### Fixed

- `--diff`/history scans tolerate repositories with no `HEAD` when persistent
  ignore files are unavailable.
- History/pre-push scans no longer let an `ignore-file` directive from one
  historical commit suppress unrelated commits in the range.
- Global path allowlists are now evaluated once per file instead of once per
  rule per line, keeping `--all` and `suppressions audit` practical.
- `update` preserves the enabled/disabled state of managed hooks and, together
  with `uninstall`/`disable`/`enable`, leaves pre-commit framework hooks
  untouched when Commit Guard was installed with `--no-hook`.

## 2.0.0

### Added

- Config file support (`.commit_guard.toml`): threshold, report format/dir/path,
  redaction, inline suppression toggle, max findings, excludes, report
  allowlists, rule/path allowlists, severity overrides, custom rules directory.
- SARIF 2.1.0 reports for GitHub/Azure code scanning.
- GitHub Actions workflow annotations (automatic under `GITHUB_ACTIONS=true`).
- Secret redaction by default across Markdown, JSON, SARIF, CLI, and
  annotations; `--show-secrets` opts out locally.
- Baseline fingerprints (`fingerprint:`), path suppressions (`path:`), and
  explicit rule entries (`rule:`) in `.commit_guard_ignore`.
- Inline `commit-guard-ignore-next-line` and `commit-guard-ignore-file`.
- `--diff REV` for CI revision-range scans.
- `--list-rules`, `--verbose-rules`, `--no-cache`, `--init-config`, `--version`.
- `update`, `doctor`, and `init` lifecycle commands.
- Curated native rule pack (`rules/custom_rules.yaml`) covering common Python,
  JavaScript, shell, Docker, Kubernetes, and secret patterns.
- Valid nuclei connection-string template (the previous file was an HTTP 404
  page).
- Disk cache for parsed rules: warm scans load in milliseconds instead of
  re-parsing ~100k lines of upstream YAML every commit.
- Full gitleaks field support: `secretGroup`, entropy, keywords, path filters,
  tags, and nested/global allowlists.
- Semgrep `pattern-either` extraction when every branch is a regex.
- Robust unified-diff parsing for paths with spaces and context lines.
- `core.hooksPath` and worktree support in the installer.
- Python/PyYAML/interpreter fallbacks in generated hooks and wrappers.
- 96-test stdlib `unittest` suite (unit + git integration).
- Expanded documentation: configuration, rules, CI, architecture, and
  troubleshooting guides.

### Changed

- Rule loading diagnostics are compact; AST-only semgrep rules no longer spam
  every scan. Use `--verbose-rules` for details.
- Rule cache lives in the user cache directory (override with
  `COMMIT_GUARD_CACHE_DIR`).
- Installer copies docs and ignores bytecode/cache files.
- Uninstall preserves user config, baseline, and reports.
- Reinstalling over Commit Guard's own hook no longer clobbers the original
  hook backup.

### Fixed

- Secrets were written verbatim into reports and JSON.
- Inline global regex flags (`foo(?i)bar`) caused valid gitleaks rules to be
  dropped.
- The OWASP CRS request-signature pack produced severe source-code false
  positives; it is now reference-only under `rules/experimental/`.
- `nuclei_generic_key.yaml` was a 404 error page.
- Context lines were not advancing new-file line numbers (latent parser bug).
- `.gitignore` contained `.commit_guard*`, which would ignore
  `.commit_guard.toml` and `.commit_guard_ignore`.

### Removed

- Default loading of `owasp_sqli.conf` (moved to `rules/experimental/`).
- `bandit_exec_rule.py` from `rules/` (moved to `rules/experimental/` as
  reference; equivalent regex rules ship in `custom_rules.yaml`).
