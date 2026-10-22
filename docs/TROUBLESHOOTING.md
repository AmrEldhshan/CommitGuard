# Troubleshooting

Start with the built-in diagnostics:

```bash
./commit-guard doctor
./commit-guard status
./commit-guard scan --verbose-rules
```

`doctor` checks git, Python, PyYAML, the installed copy, rule loading, hook
executability, and config parsing. `status` shows versions, rule counts, hook
state, and whether config/baseline files are present.

---

## The hook is not running

1. Confirm the hook exists and is executable:

   ```bash
   ls -l .git/hooks/pre-commit
   ls -l .git/hooks/pre-push      # optional
   ./commit-guard status
   ```

2. Check `core.hooksPath`. If it is set, git ignores `.git/hooks`:

   ```bash
   git config --get core.hooksPath
   ```

   Commit Guard installs into the configured path automatically. If you later
   change `core.hooksPath`, reinstall with `./commit-guard install` (or
   `python install_hook.py install .`).

3. Check whether the hook was disabled:

   ```bash
   ./commit-guard enable
   ```

4. Verify the installed engine exists:

   ```bash
   ls .commit_guard/main.py
   ```

   If it is missing, the hook prints a warning and allows the commit. Reinstall,
   or refresh from a toolkit checkout:

   ```bash
   ./commit-guard update --source /path/to/CommitGuard --force
   ```

---

## The pre-push hook is not running

Pre-push scanning is opt-in. Install it with:

```bash
./commit-guard install --pre-push
# or, if already installed:
python install_hook.py install . --pre-push
```

The hook reads git's ref lines from stdin and audits every commit in the pushed
range. If it was disabled, run `./commit-guard enable`; both pre-commit and
pre-push hooks are toggled together.

If you use the pre-commit framework instead, install with `--no-hook` and add
the `commit-guard-push` hook from `.pre-commit-hooks.yaml`.

---

## `python: command not found` or the wrong interpreter

The hook tries, in order:

1. `COMMIT_GUARD_PYTHON` (if set),
2. the interpreter used during installation,
3. `python3`,
4. `python`.

Set an explicit interpreter if your environment is unusual:

```bash
export COMMIT_GUARD_PYTHON=/path/to/python
```

On Windows, set it before using `commit-guard.bat`:

```bat
set COMMIT_GUARD_PYTHON=C:\Python312\python.exe
```

Reinstall after moving/removing a virtualenv that provided the original
interpreter.

---

## `PyYAML is required` / exit code 2

```bash
python -m pip install pyyaml
```

Confirm the interpreter running Commit Guard has it:

```bash
"$COMMIT_GUARD_PYTHON" -c "import yaml; print(yaml.__version__)"
```

If the hook uses a different interpreter than your shell, set
`COMMIT_GUARD_PYTHON` to the one with PyYAML installed.

---

## Python version errors (`tomllib`)

Commit Guard requires Python 3.11+ because it uses the standard-library
`tomllib`. Check with `python --version` / `python3 --version`. Point
`COMMIT_GUARD_PYTHON` at a 3.11+ interpreter.

---

## `No usable rules were loaded`

- Confirm `.commit_guard/rules/` exists and is non-empty.
- Check that `gitleaks.toml`, `custom_rules.yaml`,
  `nuclei_generic_key.yaml`, and/or `semgrep_rules/*.yaml` are readable.
- Run with `--verbose-rules` to see per-rule parse errors.
- Reinstall/update the engine to restore the bundled packs.

---

## Too many skipped rules

Skipped semgrep entries are expected: Commit Guard only runs regex-backed
semgrep rules and has no AST engine. Use `--verbose-rules` to inspect them.
A skipped gitleaks rule usually means the upstream regex uses a PCRE feature
Python cannot compile; the scanner reports it rather than silently losing
coverage.

---

## False positives

Use the narrowest suppression that works:

- same line: `# commit-guard-ignore` or
  `# commit-guard-ignore: rule-id`
- next line: `# commit-guard-ignore-next-line` (the directive must be an added
  line in the current diff)
- whole file: `# commit-guard-ignore-file` (persists across commits)
- exact finding: add its fingerprint to `.commit_guard_ignore`
- path: add a glob to `[allowlist].paths` or `.commit_guard_ignore`
  (`path:...`)
- rule everywhere: `[allowlist].rules` or a bare rule ID in
  `.commit_guard_ignore`

Prefer lower severity over deletion when a rule is useful but noisy:

```toml
[severity]
"generic-api-key" = "medium"
```

Then audit periodically:

```bash
python .commit_guard/main.py --no-baseline
python .commit_guard/main.py --audit-suppressions --strict
```

`--audit-suppressions` flags expired entries, fingerprints without an expiry,
unknown rule IDs, unmatched path globs, and stale fingerprints. Add owner/expiry
metadata when accepting a finding:

```bash
python .commit_guard/main.py --update-baseline \
  --baseline-owner security --baseline-expiry 2026-12-31
```

---

## A secret appears in a report

By default secrets are redacted. Check that you did not pass
`--show-secrets`, set `redact = false`, or set `--format` in a way that uses an
old report.

If a raw secret was ever committed, **rotate it**. Removing it from a report or
from a later commit does not undo the exposure. Then clean history if required
by your security policy.

---

## The scan is slow the first time

The initial run parses ~100k lines of upstream YAML (a few seconds). Later
scans use the disk cache and typically take a few hundred milliseconds.
`--history 0` and `--all` intentionally scan far more content and can take
minutes on large repositories; start with a bounded `--history 50`. If the
cache directory is read-only or blocked, the parser runs every time. Set a
writable location:

```bash
export COMMIT_GUARD_CACHE_DIR=/tmp/commit-guard-cache
```

To force a reparse:

```bash
./commit-guard scan --no-cache
```

---

## The scan says “No changed lines to scan”

Commit Guard scans **staged** changes by default. Stage files first:

```bash
git add .
./commit-guard scan
```

In CI, use a revision range instead:

```bash
python .commit_guard/main.py --diff origin/main...HEAD
```

To audit the last commits or the whole tree explicitly:

```bash
python .commit_guard/main.py --history 50
python .commit_guard/main.py --all
```

---

## Windows issues

- Use `commit-guard.bat` from PowerShell/CMD, or `./commit-guard` from Git Bash.
- If the repo path contains spaces, keep the generated wrappers intact — they
  quote paths.
- If line endings or quoting cause problems with `core.hooksPath`, run the hook
  manually to see the error:

  ```bash
  sh .git/hooks/pre-commit
  ```

- Ensure `python`/`py`/`COMMIT_GUARD_PYTHON` points to a 3.11+ interpreter with
  PyYAML.

---

## Emergency bypass

For a one-off commit that you have reviewed manually:

```bash
git commit --no-verify -m "message"
```

Use sparingly and never in automated pipelines. If a hook is repeatedly wrong,
fix the rule/config instead of normalizing `--no-verify`.

---

## Uninstall issues

```bash
./commit-guard uninstall
```

If the wrapper is already gone, run the installed manager directly:

```bash
python .commit_guard/install_hook.py uninstall .
```

If `.commit_guard/` was deleted manually but a hook remains, remove
`.git/hooks/pre-commit` and `.git/hooks/pre-push` (or the files in your
`core.hooksPath` directory). Backups may exist as `pre-commit.bak` and
`pre-push.bak`; rename one back if you want it restored.

Uninstall intentionally keeps `.commit_guard.toml`, `.commit_guard_ignore`, and
`commit_guard_reports/`.

If you use the pre-commit framework, `--no-hook` left its hook untouched;
uninstall Commit Guard normally and remove the manifest entries separately.

---

## Getting useful bug reports

Include:

- `./commit-guard doctor`
- `./commit-guard status`
- the command you ran and its full output
- Python/git versions
- the rule ID and a **redacted** sample line that triggered the issue

Never paste real secrets into an issue.
