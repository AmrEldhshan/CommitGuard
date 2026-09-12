# Commit Guard

A local, offline, cross-platform git pre-commit security scanner. It inspects
your **staged** changes (`git diff --cached`) for hardcoded secrets, SAST
issues, and misconfigurations using local rule files — no LLM, no external
APIs, nothing leaves your machine.

Once installed into a repo, Commit Guard is **fully self-contained**: it
copies itself into `.commit_guard/` inside that repo. Deleting, moving, or
losing wherever you originally installed it from has **zero effect** on
repos you've already set up.

---

## Install into a repo

From the folder where you keep the Commit Guard toolkit (this one — the one
with `main.py`, `core/`, `install_hook.py`, and your `rules/`):

```bash
python install_hook.py install /path/to/your/repo
```

Or `cd` into your repo first and run it with no path (defaults to `.`):

```bash
cd /path/to/your/repo
python /path/to/toolkit/install_hook.py install
```

This will:

1. Copy `main.py`, `core/`, `install_hook.py`, and `rules/` into
   `<your-repo>/.commit_guard/`.
2. Install a `pre-commit` git hook that calls that local copy — never the
   original toolkit.
3. Drop two small manual-command scripts at the root of your repo:
   `commit-guard` (Linux/macOS/Git Bash) and `commit-guard.bat` (Windows).
4. Add `.commit_guard/` and `commit_guard_reports/` to `.gitignore`.

From then on, every `git commit` scans your staged changes automatically.

**Options:**
| Flag | What it does |
|---|---|
| `--source PATH` | Copy from a different toolkit location than the one you're running |
| `--force` | Also overwrite an already-installed `rules/` if you re-run install |
| `--no-gitignore` | Don't touch the repo's `.gitignore` |

---

## Everyday use (the `commit-guard` command)

Once installed, run these from inside the target repo — they never touch
the original toolkit, only the local `.commit_guard/` copy:

```bash
./commit-guard scan        # Manual scan of staged changes, no commit needed
./commit-guard status      # What's installed, hook state, rule count
./commit-guard disable     # Pause auto-scan-on-commit (manual scan still works)
./commit-guard enable      # Turn auto-scan back on
./commit-guard uninstall   # Remove everything Commit Guard put in this repo
```

On Windows without Git Bash, use `commit-guard.bat` instead of `./commit-guard`.

Running `install_hook.py` (or `./commit-guard`) with **no subcommand** opens
an interactive menu.

---

## Manual scan options

```bash
./commit-guard scan --threshold medium   # Block on medium+ severity (default: high)
./commit-guard scan --quiet              # Suppress the terminal summary
```

Severity levels, low to high: `info < low < medium < high < critical`.
`--threshold` sets the minimum severity that causes a non-zero exit code
(and therefore blocks the commit, when run via the hook).

---

## What it checks

Rules live in `rules/` and are loaded fresh on every scan — edit them any
time, no reinstall needed (edit the copy inside `.commit_guard/rules/` for
an already-installed repo, or in the source toolkit before installing
elsewhere):

| File | Detects |
|---|---|
| `rules/gitleaks.toml` | Hardcoded secrets & credentials (gitleaks-style regex rules) |
| `rules/semgrep_rules/*.yaml` | Language-specific SAST patterns (only rules using semgrep's `pattern-regex` field — Commit Guard is pure-regex, no semgrep engine required) |
| `rules/nuclei_generic_key.yaml` | Generic exposed keys/tokens |
| `rules/owasp_sqli.conf` | SQL-injection signatures (ModSecurity/OWASP CRS style) |

Only **added lines** in the staged diff are scanned — never the whole repo,
and never unchanged context lines.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean, or findings all below the threshold |
| `1` | Blocking findings — commit should be (and, via the hook, is) aborted |
| `2` | Commit Guard itself failed to run (not a git repo, no rules found, etc.) |

---

## Reports

Every scan writes `commit_guard_reports/report.md` inside the repo it ran
against, with a severity breakdown and, per finding: file, line number,
rule ID, description, and the flagged code snippet.

---

## Known limitations

- Scanning is line-by-line on the staged diff. A vulnerability split across
  two lines (e.g. a query string built on one line, `execute()` called on
  the next) won't be caught — this is a direct tradeoff of only scanning
  changed lines rather than whole files.
- Semgrep rules that rely on AST matching (most of them) are skipped; only
  rules exposing a `pattern-regex` field are usable, since Commit Guard has
  no semgrep engine dependency by design.
- `rules/bandit_exec_rule.py` (Bandit-style Python AST rules) is not parsed
  — Commit Guard's rule loader only supports TOML/YAML/`.conf` sources.

---

## Uninstalling entirely

```bash
./commit-guard uninstall
```

This removes the hook (restoring whatever pre-commit hook was there before,
if any), the `.commit_guard/` copy, and the `commit-guard` / `commit-guard.bat`
wrapper scripts — leaving the repo exactly as it was.
