# Rule authoring and rule packs

Commit Guard normalizes every rule source into one shape and applies it to a
single added line at a time. This page explains what is supported, how to add
rules, and how to test them.

---

## Active sources

| Source | Loaded from | Count (approx.) | Strengths |
|---|---|---|---|
| gitleaks | `rules/gitleaks.toml` | 220+ | Secrets, entropy, keywords, per-rule allowlists. |
| Semgrep regex | `rules/semgrep_rules/*.yaml` | 60+ | Language-scoped regex SAST patterns. |
| Commit Guard native | `rules/custom_rules.yaml`, `rules/custom/**` | 28+ | Curated high-signal SAST/misconfiguration checks. |
| Python AST taint | Built into `core/ast_taint.py` | 2 | Intraprocedural request/input-to-SQL and shell checks; no extra parser dependency. |
| nuclei | `rules/nuclei_generic_key.yaml` | 2+ | Regex file templates for exposed credentials. |
| Experimental | `rules/experimental/**` | not loaded | Reference packs kept for study/opt-in. |

Counts change as upstream packs evolve. `./commit-guard status` reports the
exact number for your installed copy, and `--list-rules` prints every active
rule ID.

The AST checks are `cg-python-ast-sqli-taint` and
`cg-python-ast-shell-taint`. Use `./commit-guard explain RULE_ID` for their
description and scope. They track common `request`/`req` inputs and `input()`
through local assignments; they do not perform interprocedural analysis or
model sanitizers.

---

## Downloading and enabling rule packs

The GUI **Rules** tab can fetch packs on demand. Network access is never
automatic and hooks/CI never download rules.

| Pack type | Installed file | Notes |
|---|---|---|
| Gitleaks upstream (TOML) | `rules/gitleaks.toml` | Replaces the bundled gitleaks file; the previous copy is kept as `.bak`. |
| Semgrep YAML | `rules/semgrep_rules/downloaded-<name>.yaml` | Only top-level `pattern-regex` / regex-only `pattern-either` rules become active. |
| Native YAML | `rules/custom/downloaded-<name>.yaml` | Uses the native `rules:` schema shown below. |

Safety and validation:

- Only public `http`/`https` URLs are accepted. Credentials, `localhost`,
  `.local` names, and private/link-local/reserved IPs are rejected (including
  redirect targets).
- Responses are capped at 5 MB and downloads time out.
- The file is written to a temporary path, then checked with the normal rule
  loader before it becomes active.
- Semgrep/native packs that add no usable regex rules are rejected and the
  previous file is restored. Updates also restore the old file if loading
  fails after replacement.
- Rule packs are trusted input for the regex engine; only download from
  sources you trust.

Use `./commit-guard check-rules` after a download to validate the whole
ruleset and corpus. Downloads do not make AST-only Semgrep rules executable;
those remain in the skipped count.

---

## Severity

| Level | Typical meaning | Blocks at default `high` |
|---|---|---|
| `critical` | Confirmed credential, private key, RCE | yes |
| `high` | Exploitable secret or injection | yes |
| `medium` | Dangerous API, weak configuration | no |
| `low` | Hardening opportunity | no |
| `info` | Contextual note | no |

Semgrep's `ERROR`/`WARNING`/`INFO` map to `high`/`medium`/`info`. Missing
severity defaults to `medium`.

Override any rule without editing upstream packs:

```toml
[severity]
"generic-api-key" = "medium"
"cg-python-exec" = "high"
```

---

## Native rule format

Put project rules in `rules/custom_rules.yaml` or any `rules/custom/*.yaml`:

```yaml
rules:
  - id: cg-no-insecure-random
    description: Python's random module is not cryptographically secure.
    severity: medium
    languages: [python]
    paths: ["src/**"]              # optional globs; empty = all files
    tags: [crypto]
    cwe: CWE-338
    regex: '\brandom\.(?:random|randint|choice)\s*\('
```

### Fields

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | Stable unique identifier shown in reports/suppressions. |
| `description` | recommended | Human-readable explanation. |
| `severity` | no | Defaults to `medium`. |
| `regex` / `pattern` | yes | Python `re` pattern applied per line. |
| `languages` | no | Semgrep-style language names (`python`, `javascript`, `dockerfile`, `yaml`, ...). Empty = every file. |
| `paths` | no | Glob list restricting the rule to matching repo paths. |
| `tags` | no | Free-form labels included in reports/SARIF. |
| `cwe` | no | CWE identifier included in reports/SARIF. |
| `secret` | no | `true` masks the matched value (or capture group 1) in reports. |
| `entropy` | no | Minimum Shannon entropy for the matched secret. |
| `secret_group` | no | Capture-group index to treat as the secret. |
| `keywords` | no | At least one must appear (case-insensitive) for the rule to run. |
| `allowlist_regexes` | no | If any matches the matched secret, the finding is dropped. |
| `context` | no | Bounded nearby-line requirement: `before`, `after`, and `regex` (or a list). A match is reported only if a line in the window matches. |

### Regex tips

- Patterns run against **one line at a time**; `^`/`$` mean line boundaries.
- Use non-greedy quantifiers and anchored character classes to avoid matching
  the rest of the file.
- Use `(?i)` anywhere for case-insensitivity; Commit Guard hoists inline global
  flags to the start so patterns copied from gitleaks/semgrep compile.
- Avoid catastrophic backtracking: no nested unbounded quantifiers such as
  `(.*)+`.
- Use a capture group for the value when the rule is a secret rule:

```yaml
  - id: cg-internal-token
    description: Internal service token.
    severity: critical
    secret: true
    regex: '\bint_tok_([A-Za-z0-9]{32})\b'
```

Group 1 is masked in reports while the surrounding expression stays readable.

### Multi-line context

A rule can require another pattern within a bounded window. This is useful for
correlating a sink with a nearby source without full data-flow analysis:

```yaml
  - id: cg-python-sql-tainted-execute
    description: SQL execute follows a constructed query.
    severity: high
    languages: [python]
    regex: '\.(?:execute|executemany)\s*\('
    context:
      before: 5
      after: 0
      regex: '(?i)(?:query|sql|statement)\s*=\s*(?:f["\x27]|["\x27].*["\x27]\s*(?:%|\+))'
```

`before` and `after` are capped at 50 lines. Context is read from staged/index
content for normal scans and from the working tree for revision/history modes.
If no context line is available, the rule does not fire; this is deliberate.

---

## Rule validation and corpus

`rules/corpus.yaml` contains small positive and negative samples:

```yaml
samples:
  - rule_id: cg-python-eval
    path: sample.py
    positive: 'result = eval(user_input)'
    negative: 'result = ast.literal_eval(user_input)'

  - rule_id: cg-python-sql-tainted-execute
    path: sample.py
    context:
      - 'query = "SELECT * FROM users WHERE id = " + user_id'
    positive: 'cursor.execute(query)'
    negative: 'cursor.execute("SELECT 1")'
```

Run all schema checks and samples:

```bash
./commit-guard check-rules
./commit-guard check-rules --corpus path/to/corpus.yaml
```

Schema checks cover duplicate custom rule IDs, empty descriptions, invalid
severities, missing sources, and zero-width context windows. Duplicate upstream
IDs are reported as warnings because the bundled packs contain intentional
overlaps. Inspect one rule with `./commit-guard explain <rule-id>`.

---

## gitleaks compatibility

`rules/gitleaks.toml` is read directly. Supported fields:

| gitleaks field | Support |
|---|---|
| `id`, `description`, `regex` | yes |
| `secretGroup` | yes (masking + entropy) |
| `entropy` | yes (Shannon, bits/char) |
| `keywords` | yes (case-insensitive pre-filter) |
| `path` | yes (regex restriction) |
| `tags` | yes |
| `[rules.allowlist]` / `[[rules.allowlists]]` | `paths`, `regexes` supported |
| global `[allowlist]` | `paths` and `regexes` supported |
| `[[rules]]` with no `regex` | counted as skipped (path-only upstream rule) |
| PCRE-only constructs | counted as skipped |

Inline global flags in the middle of a regex (`foo(?i)bar`) are normalized to
the front so more upstream rules compile. Rules that still fail are listed by
`--verbose-rules`, never silently ignored.

---

## Semgrep compatibility

Commit Guard has **no semgrep engine dependency**. It extracts only regex
patterns:

- a top-level `pattern-regex`;
- a `pattern-either` where every branch is itself a regex (combined with `|`).

Everything else (`pattern`, `patterns`, taint mode, metavariable comparisons)
requires AST matching and is counted as an expected skip. This is why the
active semgrep count is much smaller than the number of upstream rules.

If you need an AST rule, translate its high-signal subset into a native regex
rule with a conservative severity, or run semgrep separately in CI.

---

## nuclei compatibility

The loader understands the `file:` → `matchers`/`extractors` → `type: regex`
shape:

```yaml
id: exposed-connection-string
info:
  name: Exposed connection string
  severity: high
file:
  - matchers:
      - type: regex
        regex:
          - '(?i)postgres://[^:\s]+:([^@\s]{3,})@' # commit-guard-ignore
```

Nuclei rules are treated as secret rules; capture group 1 is masked. Other
nuclei template types are ignored.

---

## Entropy

For generic secret rules, entropy filters patterns like
`[A-Za-z0-9]{20,}` that match ordinary text. The entropy of the captured secret
is compared with the rule's threshold:

```text
aaaaaaaaaaaaaaaa  → 0.0  (filtered)
aB3xQ9zL0mN2pR7   → 3.8  (kept)
```

gitleaks rules commonly use `entropy = 3.5` or higher. Lowering entropy raises
recall but also false positives. Prefer a specific regex over a low threshold.

Commit Guard caps the required entropy to what the observed character class can
actually reach. A hexadecimal value can never exceed 4 bits/char, so a rule
written for base64 secrets does not silently miss legitimate hex keys.
Obvious placeholders (`your_token_here`, `changeme`, `<...>`, `dummy`,
`example`) are filtered before reporting; disable this with
`--no-placeholder-filter` or `filter_placeholders = false`.

---

## Allowlists

Three layers, from narrowest to broadest:

1. **Rule allowlist regex** in a native/gitleaks rule — the matched secret is
   ignored when it matches.
2. **Inline suppression** — one line, next line, or whole file. `ignore-file`
   is read from staged/`HEAD` content, so it persists across commits.
3. **Repo config/baseline** — rule IDs, paths, or fingerprints.

The scanner applies rule-level and global gitleaks allowlists before creating a
finding, so suppressed values never appear in reports.

---

## Testing a rule

Use the scanner directly in a test or a scratch repo:

```python
import re
from core.scanner import scan_diff
from core.git_diff import DiffLine
from core.rule_loader import Rule

rule = Rule(
    rule_id="my-rule",
    description="test",
    severity="high",
    pattern=re.compile(r"danger\("),
    source="custom",
    languages=(".py",),
)
findings = scan_diff(
    [DiffLine("app.py", 1, 'danger("x")')],
    [rule],
)
assert len(findings) == 1
```

Or exercise the real pack end to end:

```bash
python main.py --list-rules | grep my-rule
printf 'danger("x")\n' > app.py
git add app.py
python main.py --format both
```

Add a unit test under `tests/` when contributing a rule, and add positive and
negative samples to `rules/corpus.yaml`. A rule without a test is likely to
regress silently. Run `python main.py --check-rules` before committing rule
changes.

---

## Rule quality checklist

- Does it match a concrete, harmful pattern rather than a keyword?
- Is the severity honest? A noisy rule at `high` will block commits and erode
  trust.
- Does it avoid matching comments/docs in common cases?
- Are secrets captured in group 1 and marked `secret: true`?
- Is there a positive test (finding detected) and a negative test (safe code
  not flagged)?
- Does it compile on the minimum supported Python (3.11)?
