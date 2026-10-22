# Configuration reference

Commit Guard reads `.commit_guard.toml` from the repository root. The file is
optional; every option has a safe default. Create one with:

```bash
./commit-guard init
```

You can point at a different file with `--config path/to/file.toml`, or ignore
configuration entirely with `--no-config`. CLI flags always win over the file.

---

## Precedence

```text
CLI flag  >  .commit_guard.toml  >  built-in default
```

Examples:

- `./commit-guard scan --threshold critical` blocks only on critical findings
  even if the file says `threshold = "medium"`.
- `--show-secrets` overrides `[scan].redact = true`. There is no `--redact`
  flag; set `redact = true` in the file (the default) and omit
  `--show-secrets` to guarantee redaction.
- `--rules-dir` beats `[scan].rules_dir`.

Environment variables:

| Variable | Effect |
|---|---|
| `COMMIT_GUARD_PYTHON` | Interpreter used by the installed hook/wrapper. |
| `COMMIT_GUARD_THRESHOLD` | Threshold used by the installed hook. |
| `COMMIT_GUARD_CACHE_DIR` | Location for the parsed-rule cache. |
| `GITHUB_ACTIONS=true` | Automatically emits GitHub workflow annotations. |

---

## Complete schema

```toml
[scan]
threshold = "high"                 # critical | high | medium | low | info
format = "markdown"                # markdown | json | sarif | both | junit | gitlab | checkstyle
report_dir = "commit_guard_reports"
report_path = ""                   # optional exact file; extension derived
redact = true                      # mask secret values in all outputs
ignore_inline = true               # honor commit-guard-ignore comments
max_findings = 0                   # 0 = unlimited
github_annotations = false         # ::error/::warning lines (auto in Actions)
warn_skipped_rules = true          # surface broken (not AST-only) rule files
soft_fail = false                  # report findings but exit 0
fail_on = "all"                    # all | new (new requires a baseline)
filter_placeholders = true         # skip obvious example/dummy secret values
rules_dir = ""                     # optional; relative to the repo root

[paths]
exclude = []                       # extra globs to skip entirely
report_allowlist = []              # visible in reports, never blocking

[allowlist]
rules = []                         # rule IDs disabled everywhere
paths = []                         # findings in these paths are suppressed

[severity]
# rule-id = "critical" | "high" | "medium" | "low" | "info"
```

### `[scan]`

| Key | Type | Default | Description |
|---|---|---|---|
| `threshold` | string | `"high"` | Minimum severity that makes the scan exit `1`. |
| `format` | string | `"markdown"` | Report format. `both` means Markdown + JSON. |
| `report_dir` | string | `"commit_guard_reports"` | Directory for default report names. |
| `report_path` | string | unset | Exact report path. For `both`, sibling `.md`/`.json` files are derived. Relative paths resolve against the repo root. |
| `redact` | bool | `true` | Mask the secret portion of secret-rule matches. Set `false` only if you understand the risk. |
| `ignore_inline` | bool | `true` | Honor inline suppression comments. |
| `max_findings` | int | `0` | Cap reported findings. `0` means unlimited. Truncation is noted in reports. |
| `github_annotations` | bool | `false` | Emit GitHub Actions workflow commands. Also enabled automatically when `GITHUB_ACTIONS=true`. |
| `warn_skipped_rules` | bool | `true` | Print a warning when a rule pack is broken. AST-only semgrep rules are expected and do not trigger a warning. |
| `soft_fail` | bool | `false` | Report findings but return exit `0`. Operational errors still return `2`. |
| `fail_on` | string | `"all"` | `all` blocks every finding. `new` blocks only findings not present in `.commit_guard_ignore`; baselined findings stay visible with `baselineState: unchanged`. |
| `filter_placeholders` | bool | `true` | Drop secret matches whose value is an obvious placeholder (`your_token_here`, `changeme`, `<...>`). |
| `rules_dir` | string | unset | Alternate rules directory. Relative paths resolve against the repo root. |

### `[paths]`

| Key | Type | Description |
|---|---|---|
| `exclude` | list of globs | Added to the built-in exclusions. Excluded paths are not scanned at all. |
| `report_allowlist` | list of globs | Findings are still reported (marked non-blocking) but cannot fail a commit. |

### `[allowlist]`

| Key | Type | Description |
|---|---|---|
| `rules` | list of rule IDs | Same as listing a rule in `.commit_guard_ignore`. Findings are dropped. |
| `paths` | list of globs | Findings are dropped. Prefer `report_allowlist` when you want visibility. |

### `[severity]`

Override a rule's severity without editing the upstream rule pack:

```toml
[severity]
"generic-api-key" = "medium"
"cg-docker-privileged" = "critical"
```

The value must be one of the five severity names.

---

## Path glob syntax

Globs are case-insensitive and use `/` separators on every platform.

| Pattern | Matches |
|---|---|
| `vendor/**` | `vendor/a.py`, `src/vendor/a/b.py` |
| `**/*.lock` | Any `.lock` file at any depth |
| `*.lock` | Same as above (patterns without `/` match basenames anywhere) |
| `src/*.py` | `src/app.py`, not `src/pkg/app.py` |
| `/src/config.*` | Only the repo-root `src/config.*` |
| `!src/vendor/**` | Negates an earlier exclude (last match wins) |

Default exclusions include lockfiles, `node_modules/`, `vendor/`,
`bower_components/`, virtualenvs, `__pycache__/`, minified bundles, source maps,
`.commit_guard/`, and `commit_guard_reports/`.

---

## Baselines and fingerprints

`.commit_guard_ignore` is a committed allowlist file:

```text
# one entry per line, comments start with '#'

# rule IDs
some-noisy-rule
rule:another-rule

# path globs
path:tests/fixtures/**
path:generated/**

# exact findings (stable across line moves), with optional review metadata
fingerprint:0123456789abcdef # owner=security expiry=2026-12-31
```

Fingerprints are printed in Markdown, JSON, and SARIF. They hash the rule ID,
file path, and flagged line content. Changing the content produces a new
fingerprint, so an accepted baseline never hides a modified secret.

Metadata is optional but recommended. Expired entries stop suppressing
findings. Audit entries with:

```bash
./commit-guard suppressions audit --strict
```

The audit flags expired entries, fingerprints without an expiry, unknown rule
IDs, path globs that match no tracked file, and stale fingerprints that no
longer correspond to a current finding. Accept all current findings with review
metadata using:

```bash
./commit-guard scan --update-baseline --baseline-owner security --baseline-expiry 2026-12-31
```

Use `--no-baseline` for a full audit, `--fail-on new` to block only
regressions, or `--baseline path` to use a different file.

---

## Reports

Default targets:

| Format | File |
|---|---|
| `markdown` | `commit_guard_reports/report.md` |
| `json` | `commit_guard_reports/report.json` |
| `sarif` | `commit_guard_reports/report.sarif` |
| `junit` | `commit_guard_reports/report.junit.xml` |
| `gitlab` | `commit_guard_reports/report.gitlab.json` |
| `checkstyle` | `commit_guard_reports/report.checkstyle.xml` |
| `both` | `report.md` + `report.json` |

With `--report-path out/results.json`:

- single format → exactly that path;
- `--format both` → `out/results.md` and `out/results.json`;
- `--format sarif` → `.sarif` is appended if the path has no suffix;
- other single formats append `.junit.xml`, `.gitlab.json`, or
  `.checkstyle.xml` when the path has no suffix.

JSON schema, field meanings, and CI examples are in [CI.md](CI.md).

---

## GitHub annotations

When `github_annotations = true`, `--github-annotations` is passed, or the
`GITHUB_ACTIONS` environment variable is `true`, Commit Guard prints workflow
commands:

```text
::error file=src/app.py,line=12,title=[HIGH] generic-api-key::Detected a Generic API Key...
::warning file=src/app.py,line=20,title=[MEDIUM] cg-python-eval::Use of eval() detected...
```

These are escaped per the GitHub workflow-command specification and respect
redaction.

---

## Full example

```toml
[scan]
threshold = "high"
format = "both"
report_dir = "commit_guard_reports"
redact = true
max_findings = 1000

[paths]
exclude = [
    "**/fixtures/**",
    "**/testdata/**",
    "**/*.generated.ts",
    "!**/testdata/README.md",
]
report_allowlist = [
    "migrations/**",   # reviewed manually
]

[allowlist]
rules = [
    "generic-api-key", # too noisy for this public test fixture repo
]
paths = [
    "docs/**",
]

[severity]
"generic-api-key" = "medium"
"cg-python-exec" = "medium"
```

Prefer short, commented allowlists. Re-run `./commit-guard scan --no-baseline`
and `./commit-guard suppressions audit` periodically to audit what your
suppressions are hiding.

---

## Profiles

`install --profile` writes a starting configuration:

| Profile | Threshold | Behavior |
|---|---|---|
| `strict` | `medium` | Block medium+ findings; best for new/small repos. |
| `balanced` | `high` | Default behavior; block high/critical only. |
| `audit` | `high` + `soft_fail = true` | Report everything but never block. |

The installer keeps an existing config unless you add `--force`.
