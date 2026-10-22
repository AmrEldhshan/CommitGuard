# CommitGuard

**Find security issues in your changes before you commit or merge them.**

CommitGuard is a local-first security scanner for Git repositories. It helps
developers catch accidentally committed secrets, risky code patterns, and
common misconfigurations early, then use the same checks in CI. Optional
features add dependency vulnerability checks and focused Python taint analysis.

By default, source scanning is local and offline, with no account, telemetry,
or cloud service. Online dependency checks and GitHub PR features are opt-in.

[Quick start](#quick-start) · [What it checks](#what-it-checks) ·
[GitHub Actions](#github-actions) · [Configuration](#configuration) ·
[Documentation](#documentation)

## Documentation

| Guide | What you’ll learn |
|---|---|
| [Architecture](docs/ARCHITECTURE.md) | How scanning works and why it is designed around changed files. |
| [Configuration](docs/CONFIGURATION.md) | All settings, defaults, profiles, and precedence. |
| [Rule authoring](docs/RULES.md) | Rule formats, suppression, validation, and current matcher support. |
| [CI integrations](docs/CI.md) | GitHub Actions, SARIF, pre-commit, GitLab, and Jenkins examples. |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Common setup, hook, reporting, and false-positive issues. |
| [Contributing](CONTRIBUTING.md) | Development setup, tests, and contribution workflow. |
| [Changelog](CHANGELOG.md) | Version history and notable changes. |

```text
$ git commit -m "add payment client"
==============================================================
  COMMIT GUARD — Scan Summary
==============================================================
  Total findings : 2
  Breakdown      : critical=1  high=1  medium=0  low=0  info=0
  Secrets        : redacted (use --show-secrets to display)
  Report         : commit_guard_reports/report.md
--------------------------------------------------------------
  STATUS: FAILED ❌  (>= high severity findings present)
==============================================================
```

---

## Why Commit Guard?

- **Targets your changes.** Line-based rules scan `git diff --cached` additions;
  Python AST checks read only changed Python files and report flows involving a
  changed source or sink. It never scans the whole repository by default.
- **Self-contained install.** `install` copies the engine, rules, and docs into
  `<repo>/.commit_guard/`. Move or delete the original toolkit afterwards —
  installed repos keep working.
- **Private by default.** Local scans need no account or network connection.
  Online SCA and GitHub API features are opt-in; secret values are
  **redacted by default**.
- **Batteries included.** 300+ active rules from gitleaks, semgrep
  `pattern-regex`, nuclei-style templates, and a curated Commit Guard pack.
- **Efficient for repeated scans.** Parsed rules are cached by file signature,
  avoiding a full rule-pack parse on every commit.
- **Team friendly.** `.commit_guard.toml`, `.commit_guard_ignore`, inline
  suppressions, fingerprints, per-path allowlists, and severity overrides.
- **CI ready.** Markdown, JSON, SARIF 2.1.0, JUnit, GitLab Code Quality, and
  Checkstyle output; GitHub Actions annotations; revision-range, history, and
  full-tree scans; stable exit codes.
- **Audit without surprises.** Pre-push hooks, baseline updates with
  owner/expiry metadata, stale-suppression audits, SARIF `baselineState`, and
  `--fail-on new`.
- **Built-in rule QA.** `check-rules` validates schemas, compiles every regex,
  and runs positive/negative corpus samples; `explain` shows any rule's logic.
- **Cross-platform.** Linux, macOS, Windows (Git Bash/PowerShell), worktrees,
  and custom `core.hooksPath`.

---

## What it checks

| Capability | Purpose |
|---|---|
| Secret detection | Catch credentials added in a change; reports redact secret values by default. |
| SAST and misconfiguration rules | Flag selected risky code patterns and configuration using bundled and project-defined rules. |
| Python taint checks | Track common request/input values within a changed Python file into SQL and shell sinks. |
| Dependency scanning (SCA) | Compare pinned dependencies with an offline OSV snapshot, or opt in to querying OSV.dev. |
| Dependency graph | Show relationships between repository files and highlight potential blast radius. |
| Reports and CI | Emit SARIF, JSON, Markdown, HTML, JUnit, GitLab Code Quality, or Checkstyle output. |

CommitGuard is intended as a fast, high-signal local/CI check that complements
broader security platforms. It does not claim complete semantic or
interprocedural analysis. See [Known limitations](#known-limitations) and the
[architecture guide](docs/ARCHITECTURE.md) for scope and design details.

---

## Contents

- [Requirements](#requirements)
- [Quick start](#quick-start)
- [What it checks](#what-it-checks)
- [GitHub Actions](#github-actions)
- [Everyday commands](#everyday-commands)
- [What gets scanned](#what-gets-scanned)
- [Reports and redaction](#reports-and-redaction)
- [Configuration](#configuration)
- [Suppressing findings](#suppressing-findings)
- [Rule packs](#rule-packs)
- [Using Commit Guard in CI](#using-commit-guard-in-ci)
- [How it works](#how-it-works)
- [Performance](#performance)
- [Security and privacy](#security-and-privacy)
- [Known limitations](#known-limitations)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [Project layout](#project-layout)
- [Documentation](#documentation)
- [Related projects and standards](#related-projects-and-standards)

---

## Requirements

| Requirement | Notes |
|---|---|
| Python **3.11+** | Uses the standard-library `tomllib`. |
| PyYAML 6+ | `pip install pyyaml` (needed for semgrep/nuclei/custom YAML rules). |
| git | Any reasonably modern git. |

Everything else is Python standard library. Routine local scans need no network
access; online SCA is opt-in. No build step is required when installing from a
checkout.

---

## Quick start

Clone CommitGuard, then install it into the repository you want to scan:

```bash
git clone https://github.com/AmrEldhshan/CommitGuard.git
python CommitGuard/install_hook.py install /path/to/your/repo
```

Or install into the current repository:

```bash
cd /path/to/your/repo
python /path/to/CommitGuard/install_hook.py install
```

This will:

1. Copy the engine, rules, `README.md`, and `docs/` into
   `<repo>/.commit_guard/`.
2. Install a `pre-commit` hook (honoring `core.hooksPath` and worktrees).
3. Create `./commit-guard` (Linux/macOS/Git Bash) and `commit-guard.bat`
   (Windows).
4. Add local artifacts to `.gitignore`.

From then on, every `git commit` scans staged added lines. To verify:

```bash
./commit-guard status
./commit-guard doctor
./commit-guard scan
```

The installer never overwrites an existing `.commit_guard.toml` or
`.commit_guard_ignore`; those are yours to commit and share with the team.

> **Release note:** The repository contains PyPI packaging metadata, but
> published package availability depends on a release. Until then, install
> from a checkout as shown above.

### Install options

| Flag | Effect |
|---|---|
| `--source PATH` | Copy from a different toolkit checkout. |
| `--force` | Also replace an already-installed `rules/` directory. |
| `--no-gitignore` | Leave `.gitignore` untouched. |
| `--pre-push` | Also install a pre-push hook that audits pushed commits. |
| `--profile strict\|balanced\|audit` | Write a starting config profile. |
| `--no-hook` | Install the engine/wrappers but leave hooks to pre-commit. |

### Using the pre-commit framework

Commit Guard ships a tested `.pre-commit-hooks.yaml`. Install the engine
without its native hook, then let the framework manage the hook:

```bash
python install_hook.py install /path/to/repo --no-hook
```

```yaml
repos:
  - repo: https://github.com/AmrEldhshan/CommitGuard
    rev: <release-tag-or-commit-sha>
    hooks:
      - id: commit-guard
```

The manifest runs the installed, self-contained `.commit_guard/main.py` in the
target repository; scans remain fully offline. Replace the revision placeholder
with a published tag or reviewed commit SHA.

---

## Everyday commands

Run these from inside an installed repository:

| Command | What it does |
|---|---|
| `./commit-guard scan` | Manual scan of staged changes. |
| `./commit-guard status` | Version, rule count, hook state, config/baseline state. |
| `./commit-guard doctor` | Diagnose git/Python/PyYAML/rules/hook problems. |
| `./commit-guard init` | Write a commented `.commit_guard.toml`. |
| `./commit-guard disable` | Pause auto-scan-on-commit; manual scans still work. |
| `./commit-guard enable` | Re-enable auto-scan-on-commit. |
| `./commit-guard update --source PATH` | Refresh the installed engine from a toolkit checkout (`--force` also replaces rules). |
| `./commit-guard uninstall` | Remove everything Commit Guard installed. |
| `./commit-guard check-rules` | Validate all rules and corpus samples. |
| `./commit-guard explain RULE_ID` | Show one rule's pattern, paths, and context. |
| `./commit-guard suppressions audit` | Report expired/stale baseline entries. |

On Windows without Git Bash, use `commit-guard.bat`. Running the manager with
no subcommand opens an interactive menu.

### Manual scan options

```bash
./commit-guard scan --threshold medium       # block on medium+ (default: high)
./commit-guard scan --format both            # report.md + report.json
./commit-guard scan --format sarif           # report.sarif
./commit-guard scan --format junit           # report.junit.xml
./commit-guard scan --report-path out/x.sarif --format sarif
./commit-guard scan --show-secrets           # do not redact locally
./commit-guard scan --diff origin/main...HEAD
./commit-guard scan --history 50             # audit the last 50 commits
./commit-guard scan --all                    # audit the whole working tree
./commit-guard scan --pre-push               # audit refs supplied on stdin
./commit-guard scan --sca                    # check dependencies against a local OSV snapshot
./commit-guard scan --sca --sca-online       # explicitly query OSV.dev
./commit-guard scan --dep-graph              # write dependency/blast-radius output
./commit-guard scan --format html            # self-contained report and trends
./commit-guard scan --fix-dry-run            # preview eligible rule-provided fixes
./commit-guard scan --fix                    # apply eligible fixes and re-stage files
./commit-guard scan --soft-fail              # report, but exit 0
./commit-guard scan --fail-on new            # block only findings new to baseline
./commit-guard scan --update-baseline        # accept current findings
./commit-guard scan --no-baseline
./commit-guard scan --verbose-rules          # explain every skipped rule
./commit-guard scan --quiet
```

The scan engine can also be called directly:

```bash
python .commit_guard/main.py --repo . --format both
python .commit_guard/main.py --list-rules
python .commit_guard/main.py --version
```

Severity order: `info < low < medium < high < critical`. `--threshold` is the
minimum severity that **blocks** the scan. Lower-severity findings still
appear in reports.

SCA is disabled unless requested. Offline mode reads `.commit_guard_osv.json`
or the file passed with `--sca-snapshot`; a missing snapshot produces a
warning rather than implying dependencies are safe. Online mode sends package
coordinates to OSV.dev. See the [configuration guide](docs/CONFIGURATION.md)
and [CI guide](docs/CI.md) for options and examples.

---

## What gets scanned

Line-based rules inspect only **added lines** in the staged diff
(`git diff --cached --unified=0`). Python AST taint checks also parse the full
staged content of changed `.py`/`.pyi` files so they can connect changed input
or sink code to the corresponding SQL/shell flow. They do not analyze
unchanged files, and history/pre-push modes skip this AST pass. Deleted lines
and binary files are ignored. Default exclusions also skip lockfiles, vendored
dependencies, `node_modules`, minified bundles, `.commit_guard/`, and report
directories; these can be adjusted with `[paths].exclude`.

High-volume or generated paths can be excluded without hiding first-party
source:

```toml
[paths]
exclude = [
    "**/fixtures/**",
    "**/*.generated.ts",
]
```

Path globs are case-insensitive, support `**`, and may be negated with `!`
(the last matching pattern wins).

---

## Reports and redaction

Every scan writes to `commit_guard_reports/` by default:

| Format | File | Use |
|---|---|---|
| Markdown | `report.md` | Human review, commit-message attachments. |
| JSON | `report.json` | Dashboards, custom tooling, artifacts. |
| SARIF 2.1.0 | `report.sarif` | GitHub code scanning, Azure DevOps. |
| JUnit XML | `report.junit.xml` | Jenkins, GitLab, GitHub test summaries. |
| GitLab Code Quality | `report.gitlab.json` | GitLab merge-request widgets. |
| Checkstyle XML | `report.checkstyle.xml` | CI dashboards and IDE integrations. |

Reports include severity, file, line, rule ID, source, CWE, tags, a stable
fingerprint, and the flagged snippet.

**Secrets are masked by default** (`AK********LE`). Use `--show-secrets`
(or `redact = false` in config) only when you intentionally need the raw value
locally. Reports are written to a gitignored directory, but redaction is the
real safeguard.

---

## Configuration

Commit Guard works with zero configuration. To customize behavior, create
`.commit_guard.toml` at the repository root:

```bash
./commit-guard init
```

```toml
[scan]
threshold = "high"        # critical | high | medium | low | info
format = "markdown"       # markdown | json | sarif | both | junit | gitlab | checkstyle
report_dir = "commit_guard_reports"
redact = true
filter_placeholders = true  # ignore obvious example/dummy secret values
soft_fail = false          # report findings but exit 0
fail_on = "all"            # all | new (requires a baseline)
max_findings = 500

[paths]
exclude = ["**/fixtures/**"]
report_allowlist = ["docs/**"]   # visible but never blocking

[allowlist]
rules = ["some-noisy-rule"]
paths = ["tests/fixtures/**"]

[severity]
"some-rule-id" = "low"
```

CLI flags override config values, which override built-in defaults. See
[docs/CONFIGURATION.md](docs/CONFIGURATION.md) for the complete schema,
precedence rules, and examples.

---

## Suppressing findings

Use the narrowest mechanism that fits.

### Inline

```python
api_key = "not-a-real-secret"          # commit-guard-ignore
api_key = "not-a-real-secret"          # commit-guard-ignore: generic-api-key
```

```python
# commit-guard-ignore-next-line
password = "test-fixture-value"
```

```python
# commit-guard-ignore-file
```

`ignore-file` is persistent: Commit Guard checks the staged/index content (or
`HEAD` in `--diff` mode), so the directive does not need to be part of the
current diff. `ignore-next-line` applies when its directive line is itself in
the diff.

### Project-level `.commit_guard_ignore`

Commit this file to share accepted suppressions:

```text
# Disable a rule everywhere
some-noisy-rule
rule:another-rule

# Ignore all findings under a path
path:tests/fixtures/**

# Accept one exact finding (stable across line moves)
fingerprint:0123456789abcdef # owner=security expiry=2026-12-31
```

Fingerprint metadata is optional. Expired entries stop suppressing findings,
and `suppressions audit` reports expired, stale, unknown-rule, and
unmatched-path entries. `scan --update-baseline --baseline-owner NAME
--baseline-expiry YYYY-MM-DD` adds every current finding with review metadata.

Fingerprints are printed in every report and are based on the rule, file, and
flagged line content. If the content changes, the fingerprint changes and the
finding is reported again.

### Config allowlists

- `[allowlist].rules` — global rule disablement.
- `[allowlist].paths` — suppress findings entirely for matching paths.
- `[paths].report_allowlist` — keep findings visible but never block.

Prefer inline comments and fingerprints over broad rule disabling. A broad
allowlist can hide a real regression forever.

---

## Rule packs

| Source | Location | Notes |
|---|---|---|
| gitleaks | `rules/gitleaks.toml` | 200+ secret rules with entropy, keywords, path filters, and allowlists. |
| Semgrep | `rules/semgrep_rules/*.yaml` | Only regex-backed rules run. AST-only rules are counted as skipped, never approximated. |
| Commit Guard native | `rules/custom_rules.yaml`, `rules/custom/*.yaml` | Curated high-signal rules, including bounded multi-line context checks. |
| Rule corpus | `rules/corpus.yaml` | Positive/negative samples exercised by `check-rules`. |
| nuclei | `rules/nuclei_generic_key.yaml` | Regex file templates; capture group 1 is treated as the secret. |
| Experimental | `rules/experimental/` | Reference material, not loaded (e.g. the OWASP CRS request-signature pack). |

Rules are loaded fresh on every scan and cached by file signature. Edit them
any time — no reinstall needed for an installed repo, provided you edit the
copy under `.commit_guard/rules/`.

To add a project rule, drop a file under `rules/custom/` (or edit
`custom_rules.yaml`):

```yaml
rules:
  - id: no-insecure-deserialization
    description: Unsafe YAML load detected.
    severity: high
    languages: [python]
    paths: ["src/**"]
    tags: [deserialization]
    cwe: CWE-502
    regex: 'yaml\.load\s*\('
```

Add `context` to a native rule when a line only matters near another line:

```yaml
    regex: '\.execute\s*\('
    context:
      before: 5
      after: 0
      regex: '(?i)(?:query|sql)\s*='
```

Validate all rules and corpus samples with `./commit-guard check-rules`; inspect
one rule with `./commit-guard explain cg-python-eval`.

See [docs/RULES.md](docs/RULES.md) for the full native schema, gitleaks field
mapping, entropy semantics, context windows, and semgrep limitations.

---

## Using Commit Guard in CI

Scan a revision range instead of the staging area:

```bash
python .commit_guard/main.py --diff origin/main...HEAD --format sarif --quiet
python .commit_guard/main.py --all --format gitlab --report-path gl-code-quality.json
python .commit_guard/main.py --history 50 --fail-on new --format sarif
```

Exit codes are stable:

| Code | Meaning |
|---|---|
| `0` | Clean, or all findings below the threshold. |
| `1` | Blocking findings. |
| `2` | Commit Guard could not run (bad repo/config/rules). |

A GitHub Actions example that uploads SARIF to code scanning, plus
pre-commit/GitLab/Jenkins snippets, lives in [docs/CI.md](docs/CI.md).

---

## GitHub Actions

The repository includes a composite Action so you can run the same checks in
CI as you do before committing. Once the Action is available on the referenced
branch or release, a basic workflow looks like this:

```yaml
name: CommitGuard

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write # needed only to upload SARIF

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: AmrEldhshan/CommitGuard@main
        with:
          threshold: high
          format: sarif
          scan-mode: all
          dep-graph: true
      - name: Upload SARIF to GitHub code scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: commit_guard_reports/report.sarif
```

For production, prefer a reviewed release tag or commit SHA over the moving
`main` reference. `security-events: write` is needed for SARIF upload; omit it
if you only need the Action's job result and local report. Optional PR creation
or inline suggestions also require suitable `pull-requests: write` permissions.
See the [CI integration guide](docs/CI.md) for report, permission, and
pre-commit/GitLab/Jenkins examples.

---

## How it works

```text
git diff --cached --unified=0
            │
            ▼
core/git_diff.py     parse only added lines + new-file line numbers
            │
            ▼
core/config.py       .commit_guard.toml + CLI overrides
core/rule_loader.py  gitleaks / semgrep / custom / nuclei → compiled rules
core/ast_taint.py    changed Python files → focused SQL/shell taint checks
core/sca.py          pinned dependencies → offline snapshot or optional OSV query
            │
            ▼
core/scanner.py      path/context filters, entropy, allowlists, suppression, redaction
            │
            ▼
core/reporter.py     Markdown, JSON, SARIF, HTML, JUnit, GitLab, Checkstyle
```

- **Config** is read before scanning; invalid values fail with exit code `2`.
- **Rules** are parsed once and cached under the user cache directory, keyed by
  the path, size, and mtime of every rule file. Corrupt or read-only caches
  fall back to a normal parse.
- **Suppression** happens before a finding is created, so suppressed matches
  never reach reports or CI annotations.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for module-by-module details
and design tradeoffs.

---

## Performance

The first scan after a rule change parses ~100k lines of upstream YAML and
takes a few seconds. After that, parsed rules load from cache in roughly
10–50 ms. Total scan time also depends on the number of changed lines, enabled
features, and repository size.

If you need to bypass the cache (debugging or a read-only environment):

```bash
./commit-guard scan --no-cache
```

The cache is enabled by default and invalidates automatically when any rule
file changes. Set `COMMIT_GUARD_CACHE_DIR` to relocate it.

---

## Security and privacy

- No network calls, no accounts, no telemetry, no LLM.
- Only changed paths are read by default. Changed Python files are read in full
  (up to the scanner's per-file size limit) for local AST analysis; other
  line-based checks inspect selected diff lines.
- Secret values are redacted in Markdown, JSON, SARIF, CLI output, and GitHub
  annotations unless you explicitly opt out.
- Reports are written locally and the installer adds `commit_guard_reports/`
  to `.gitignore`.
- Redaction is a reporting safeguard, not encryption. A real leaked credential
  should be **rotated**, not merely suppressed.

If you find a security issue in Commit Guard itself, please open a private
report with the maintainers rather than filing a public issue containing
exploit details.

---

## Known limitations

- **Limited taint analysis.** Python uses a standard-library AST pass for
  common request/input-to-SQL and shell flows within one function. It does not
  follow data across functions/modules or model sanitizers and is not a
  replacement for full interprocedural analysis. Other checks remain mostly
  line-oriented; AST-only semgrep rules still require semgrep. AST taint checks
  are skipped for history and pre-push scans because those modes may analyze
  revisions that do not match the current worktree.
- **Regex, not AST.** Most semgrep rules rely on AST matching. Only
  `pattern-regex` rules (and `pattern-either` branches that are entirely
  regexes) run. This is documented in `status` output and can be inspected
  with `--verbose-rules`.
- **Upstream pack drift.** gitleaks/semgrep rules occasionally use PCRE
  features Python's `re` cannot compile. Those entries are counted and listed
  as skipped rather than silently ignored.
- **Heuristic filtering.** Entropy thresholds are capped to what the observed
  character class can reach, and obvious placeholders are skipped. Neither is
  a proof of randomness or safety.
- The OWASP CRS SQLi pack is **not** loaded by default: it targets HTTP request
  values, not source code, and produces heavy false positives when applied
  line-by-line. Curated SQLi source rules ship in `custom_rules.yaml`.

---

## Development

```bash
# Run the full test suite (stdlib unittest; no pytest required)
python -m unittest discover -s tests -v

# Quick manual checks
python main.py --version
python main.py --list-rules
python main.py --check-rules
python main.py --explain cg-python-eval
python main.py --explain cg-python-ast-sqli-taint
python main.py --repo /path/to/repo --format both
```

The project intentionally depends only on the Python standard library and
PyYAML. Contributions should keep the scanner deterministic, offline, and
unit-testable. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Troubleshooting

Start here:

```bash
./commit-guard doctor
./commit-guard status
```

Common fixes (hook not running, `core.hooksPath`, missing PyYAML, Windows
paths, false positives, cache issues, emergency commit bypass) are covered in
[docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).

---

## Project layout

```text
CommitGuard/
├── main.py                  # scan engine / CLI
├── install_hook.py          # install, update, status, doctor, uninstall
├── core/
│   ├── ast_taint.py         # focused Python source-to-sink checks
│   ├── autofix.py           # explicit, opt-in rule fixes
│   ├── config.py            # .commit_guard.toml
│   ├── dep_graph.py         # dependency graph and blast radius
│   ├── entropy.py           # Shannon entropy
│   ├── git_diff.py          # staged diff parsing
│   ├── paths.py             # glob engine + default excludes
│   ├── pr_creator.py        # GitHub report PRs and inline suggestions
│   ├── reporter.py          # Markdown / JSON / SARIF / HTML / CI formats
│   ├── rule_check.py        # schema/corpus validation + explain
│   ├── rule_loader.py       # rule packs + disk cache
│   ├── sca.py               # dependency/advisory checks
│   ├── scanner.py           # matching, context, suppression, redaction
│   ├── suppressions.py      # baseline metadata + audit
│   └── trends.py            # HTML report history and visualizations
├── rules/
│   ├── ai_security/         # AI provider and LLM security checks
│   ├── corpus.yaml          # positive/negative rule samples
│   ├── gitleaks.toml
│   ├── custom_rules.yaml
│   ├── custom/              # optional project rule packs
│   ├── nuclei_generic_key.yaml
│   ├── semgrep_rules/
│   ├── iac/                 # infrastructure-as-code checks
│   └── experimental/        # reference only, not loaded
├── action.yml              # GitHub composite Action
├── .pre-commit-hooks.yaml  # pre-commit framework hooks
├── docs/
└── tests/
```

---

## Related projects and standards

CommitGuard bundles or integrates with ideas and formats from these projects:

- [Gitleaks](https://github.com/gitleaks/gitleaks) — upstream-style secret
  detection rules.
- [Semgrep](https://semgrep.dev/) — source for regex-compatible rule packs;
  AST-only Semgrep rules are not executed by CommitGuard.
- [OSV.dev](https://osv.dev/) — vulnerability data for optional dependency
  scanning.
- [SARIF](https://github.com/oasis-tcs/sarif-spec) — standard format for
  static-analysis results and GitHub code scanning.
- [pre-commit](https://pre-commit.com/) — framework integration for Git hooks.
- [GitHub code scanning](https://docs.github.com/en/code-security/code-scanning)
  — consume SARIF results in a repository's Security tab.

For questions, bug reports, and feature requests, visit the
[GitHub Issues](https://github.com/AmrEldhshan/CommitGuard/issues).

---

## Uninstalling

```bash
./commit-guard uninstall
```

This removes both hooks (restoring any prior `pre-commit`/`pre-push` hooks it
backed up), the `.commit_guard/` copy, and the wrapper scripts. It intentionally keeps your
`.commit_guard.toml`, `.commit_guard_ignore`, and existing reports.
