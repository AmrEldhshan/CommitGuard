# Architecture

Commit Guard is deliberately small: a scan engine, a lifecycle installer, and
local rule packs. This page explains the flow, data model, caching strategy, and
the tradeoffs behind them.

---

## Scan flow

```text
┌─────────────────────────────┐
│ install_hook.py install     │ copies engine + rules into .commit_guard/
└──────────────┬──────────────┘
               │ git commit
               ▼
┌─────────────────────────────┐
│ .git/hooks/pre-commit       │ finds Python, runs .commit_guard/main.py
└──────────────┬──────────────┘
               ▼
┌─────────────────────────────┐
│ main.py                     │ CLI + config precedence + orchestration
│  ├── core.config            │ .commit_guard.toml (validated)
│  ├── core.git_diff          │ staged/diff/history/all + line numbers
│  ├── core.rule_loader       │ pack parsing + signature-keyed cache
│  ├── core.scanner           │ match → context/filter → suppress → Finding
│  ├── core.ast_taint         │ intraprocedural Python source → SQL/shell checks
│  ├── core.suppressions      │ baseline metadata + audit
│  ├── core.rule_check        │ schema/corpus validation + explain
│  └── core.reporter          │ Markdown / JSON / SARIF / JUnit / GitLab / Checkstyle
└──────────────┬──────────────┘
               ▼
      exit 0 / 1 / 2 + reports
```

`main.py` never manages hooks. `install_hook.py` never scans. This split keeps
the scan engine safe to call from CI and trivial to test.

---

## Modules

### `core/git_diff.py`

- Runs `git -c core.quotePath=false diff --cached --unified=0 --no-ext-diff
  --no-textconv --diff-filter=ACMR`.
- Parses only `+` lines and tracks the new-file line number from hunk headers.
- Uses `+++ b/<path>` as the authoritative path so spaces/non-ASCII names work.
- `get_diff(repo, revision)` supports CI revision ranges.
- `get_history_diff()` uses `git log -p` over non-merge commits, which catches
  secrets added in an intermediate commit even if a later commit removed them.
- `get_all_files()` combines tracked and untracked, non-ignored text files for
  full-tree audits.
- `get_context_lines()` reads bounded staged/working-tree content for
  multi-line rules.
- `--unified=0` means unchanged context lines are not scanned; context-window
  rules read file content separately when they need it.
- `--no-ext-diff`/`--no-textconv` prevent user-configured diff drivers from
  changing what is scanned.

### `core/paths.py`

- Predictable glob engine (`**`, `*`, `?`, negation, root anchoring).
- `DEFAULT_EXCLUDES` avoids lockfiles, vendored code, minified assets, and the
  install/report directories.
- Implemented locally because `pathlib.PurePath.match()` is right-anchored and
  behaves surprisingly for patterns like `vendor/**`.

### `core/config.py`

- `tomllib` (standard library, Python 3.11+) parses `.commit_guard.toml`.
- Every value is validated; invalid config exits `2` rather than silently
  falling back.
- `Config.with_overrides()` applies only non-`None` CLI values, preserving the
  documented precedence: CLI > file > defaults.
- `default_config_text()` powers `commit-guard init` and `--init-config`.
- `profile_defaults()` supplies `install --profile strict|balanced|audit`.

### `core/entropy.py`

- Shannon entropy in bits per character.
- Used only when a rule declares `entropy`; filters generic regex matches whose
  captured value is too repetitive to be a plausible secret.

### `core/rule_loader.py`

- Normalizes four pack formats into a single frozen `Rule` dataclass:
  - gitleaks TOML: regex, path, `secretGroup`, entropy, keywords, tags,
    nested allowlists, global path/regex allowlists;
  - semgrep YAML: top-level `pattern-regex`, plus `pattern-either` when all
    branches are regexes;
  - native YAML: project rules with globs/languages/tags;
  - nuclei YAML: regex file matchers/extractors.
- Hoists inline global regex flags (`foo(?i)bar` → `(?i)foobar`) so upstream
  patterns compile under Python's stricter `re` parser.
- Records every skip with a reason; expected AST-only semgrep skips are
  summarized only with `--verbose-rules` or when a whole pack fails.
- Loads native `context` windows (`before`, `after`, `regex`) and serializes
  them in the cache.
- Raises `RuleLoadError` if the final rule set is empty.

### `core/scanner.py`

Pure, no I/O:

1. Build the set of files with a `commit-guard-ignore-file` directive from
   staged content (`git grep --cached`) or `HEAD` for `--diff` scans, plus any
   directive present in the diff itself.
2. For each added line: apply path excludes, next-line/file suppression, inline
   rule-id suppression.
3. Filter rules by language and rule path restrictions.
4. For each regex match: apply entropy, rule allowlists, global allowlists, and
   path allowlists.
5. Apply bounded context rules using staged/working-tree line maps.
6. Filter obvious placeholder secrets and cap entropy to the observed character
   class.
7. Create a `Finding` with raw and redacted snippets, tags/CWE, and a stable
   fingerprint.
8. Duplicate findings are avoided in history/pre-push aggregation by a
   `(file, line, content)` dedupe.

Post-processing helpers mark `report_allowlist` findings non-blocking, drop
baseline matches by default, or annotate them `baseline_state="unchanged"` and
non-blocking for SARIF/`--fail-on new`. Baseline fingerprints may carry
`owner`/`expiry` metadata; expired entries stop suppressing findings.

### `core/ast_taint.py`

- Parses changed Python files from staged index content (or the selected
  worktree content for non-staged scans) with the standard-library `ast`
  module.
- Tracks common request/input values through local assignments and basic
  control-flow branches into SQL `execute`/`executemany`, `os.system`/
  `os.popen`, and `subprocess` calls with literal `shell=True`.
- Reports only when the sink or one of its tracked source lines is in the
  selected diff. Findings participate in normal baseline, severity, and report
  handling; inline suppressions are honored at the changed anchor and sink.
- Skips history and pre-push scans because those modes may refer to earlier
  file contents that are not available to this worktree-based analysis; the
  CLI reports this explicitly.
- This is a conservative intraprocedural MVP, not interprocedural analysis.
  It does not follow values across function calls/modules or model sanitizers,
  and only recognizes the documented source/sink shapes.

### `core/suppressions.py`

- Parses `.commit_guard_ignore` without losing trailing `# owner=... expiry=...`
  metadata.
- Builds the effective baseline, dropping expired entries.
- Appends new fingerprints for `--update-baseline`.
- Audits expired, stale, unknown-rule, and unmatched-path entries.

### `core/rule_check.py`

- Validates duplicate custom IDs, descriptions, severities, sources, and
  zero-width context windows.
- Runs positive/negative samples from `rules/corpus.yaml`.
- Renders one rule for `--explain`.

### `core/reporter.py`

- Markdown for humans, JSON for tooling, SARIF 2.1.0 for code scanning.
- JUnit XML, GitLab Code Quality JSON, and Checkstyle XML for CI dashboards.
- SARIF results carry `baselineState` from the finding (`new`/`unchanged`).
- Central redaction decision: `Finding.display_code(show_secrets)`.
- GitHub annotations escape `%`, newlines, `:`, and `,` per the workflow-command
  spec.
- Severity mapping for SARIF: critical/high → `error`, medium → `warning`,
  low/info → `note`.

### `install_hook.py`

- Copies `main.py`, `core/`, `rules/`, `README.md`, and `docs/` into
  `<repo>/.commit_guard/` (ignoring `__pycache__` and bytecode).
- Installs pre-commit and optional pre-push shell hooks that prefer
  `COMMIT_GUARD_PYTHON`, then the interpreter used for installation, then
  `python3`/`python`.
- Honors `core.hooksPath` and worktrees via `git rev-parse --git-path hooks`.
- Backs up existing non-Commit-Guard `pre-commit`/`pre-push` hooks; reinstall
  does not overwrite those backups.
- Provides `update`, `doctor`, `init`, `status`, `disable`/`enable`,
  `check-rules`, `explain`, `suppressions audit`, and `uninstall`.
- Supports `--profile`, `--pre-push`, and `--no-hook` for pre-commit framework
  users.

---

## Rule cache

The upstream YAML packs total ~100k lines. Parsing them on every commit would
add seconds to each commit. The loader therefore:

1. Computes a SHA-256 key over the absolute rules path, every rule file's
   relative path, size, and `mtime_ns`, plus a cache schema version.
2. Reads `<cache>/<key>.json` and reconstructs `Rule` objects (regex recompiled
   from source strings).
3. On a miss, parses everything, writes the cache atomically (temp file +
   `os.replace`), and returns.
4. On any cache read/write error, silently falls back to parsing. A read-only
   home directory never breaks a scan.

The cache stores no secret values and no compiled code — only rule metadata and
regex strings. It lives under `$XDG_CACHE_HOME` (or `%LOCALAPPDATA%` on
Windows), not in the repository. `COMMIT_GUARD_CACHE_DIR` overrides it; the
`--no-cache` flag bypasses it.

---

## Suppression layers

From narrowest to broadest:

1. inline same line / next line / file;
2. rule-level allowlist regex / path;
3. `.commit_guard.toml` `[allowlist]` and `[paths].report_allowlist`;
4. `.commit_guard_ignore` rule IDs, path globs, fingerprints.

Everything except `report_allowlist` drops the finding before reporting.
`report_allowlist` keeps visibility but sets `blocking = False`. In
`--fail-on new` mode, baseline matches are also retained (as non-blocking,
`baseline_state="unchanged"`) so SARIF consumers can distinguish regressions.

---

## Design decisions and tradeoffs

| Decision | Why | Cost |
|---|---|---|
| Scan added lines by default | Fast, low noise, only blocks what you introduce | Cross-line vulnerabilities need explicit context rules |
| Regex-only engine | No semgrep/bandit runtime, fully offline, instant startup | AST rules cannot run |
| Self-contained copy | Installed repos survive toolkit relocation | Updates require `commit-guard update --source PATH` |
| Redaction by default | Reports are easy to share and less likely to leak | Raw value requires explicit `--show-secrets` |
| Disk rule cache | Makes pre-commit latency acceptable | Extra cache invalidation logic |
| Stable exit codes | Works in any CI without plugins | `2` must be treated as failure, not “no findings” |
| Curated over maximal rules | A blocking hook must be trustworthy | Fewer low-level checks than a full SAST suite |

---

## Testing strategy

- Pure modules (`paths`, `entropy`, `scanner`, `reporter`, `config`,
  `rule_loader`) are unit-tested directly.
- Integration tests create throwaway git repositories, stage files, and assert
  exit codes, report contents, redaction, config precedence, baseline
  suppression/expiry, history/all/pre-push modes, soft-fail, SARIF
  `baselineState`, and the extra reporters.
- The real rule pack is loaded in a test to catch malformed upstream entries.
- Run everything with:

```bash
python -m unittest discover -s tests -v
```

No network access is required.
