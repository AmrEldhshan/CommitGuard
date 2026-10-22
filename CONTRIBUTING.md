# Contributing

Thanks for helping make Commit Guard better. The project has a deliberately
small dependency footprint and a strong preference for predictable, testable
behavior.

---

## Development setup

```bash
git clone <your-fork>
cd CommitGuard
python -m pip install pyyaml
python -m unittest discover -s tests -v
```

No build step. Python 3.11+ is required. There is no network access in the test
suite.

---

## Ground rules

- **Offline first.** Do not add network calls, telemetry, or cloud APIs.
- **Standard library + PyYAML only.** Avoid new runtime dependencies; justify
  any exception in the pull request.
- **Keep scanning fast.** Warm scans must stay sub-second for typical diffs.
  Do not parse rules on every scan without using the cache.
- **Never log raw secrets.** New output paths must respect
  `Finding.display_code()` redaction.
- **Deterministic output.** Sort findings and rules; do not rely on dict/set
  iteration order in reports.
- **No silent coverage loss.** A rule that cannot be loaded must be recorded as
  a skipped entry with a reason.

---

## Code style

- Match the existing style: type hints, small pure functions, docstrings that
  explain *why* rather than restating the code.
- Keep `core/` modules free of printing and file I/O except where the module is
  specifically about I/O (`reporter`, `git_diff`, `rule_loader`, `config`).
- Prefer dataclasses for data boundaries (`Rule`, `Finding`, `Config`).
- Do not add comments that merely narrate the next line.
- Keep CLI behavior documented in `README.md` and `docs/`.

---

## Adding a rule

1. Put project rules in `rules/custom_rules.yaml` or a new
   `rules/custom/<pack>.yaml`.
2. Follow the native schema in [docs/RULES.md](docs/RULES.md).
3. Choose an honest severity; a noisy `high` rule blocks commits and damages
   trust.
4. For secret rules, capture the value in group 1 and set `secret: true`.
5. Add tests:
   - a positive case (the harmful line is flagged),
   - a negative case (ordinary code is not flagged),
   - a path/language filter or context-window case if the rule uses them.
6. Add positive/negative samples to `rules/corpus.yaml` for `check-rules`.
7. Verify the real pack loads:

   ```bash
   python main.py --list-rules | grep <your-rule-id>
   python main.py --check-rules
   python main.py --explain <your-rule-id>
   python main.py --verbose-rules
   ```

8. Run the full suite.

---

## Changing the scanner

- Add a unit test in `tests/test_scanner.py` for every new filter or
  suppression path.
- Preserve the public `scan_diff(...)` compatibility where possible; new
  parameters should be keyword-only with safe defaults.
- Findings must remain immutable (`@dataclass(frozen=True)`).
- If you change fingerprint semantics, document it — baselines depend on stable
  fingerprints.

---

## Changing the loader

- Bump `_CACHE_VERSION` in `core/rule_loader.py` whenever the serialized rule
  shape changes.
- Ensure a malformed file or invalid regex is recorded, not raised, unless the
  entire rule set is unusable.
- Add a fixture-based test in `tests/test_rule_loader.py` (do not depend on
  mutable upstream files for behavior tests; the real pack is loaded once as a
  smoke test).
- Keep gitleaks/semgrep/nuclei field support documented in `docs/RULES.md`.

---

## Changing the installer

- Test `install`, `status`, `doctor`, `scan`, `update`, and `uninstall` in a
  throwaway git repo.
- Preserve existing `pre-commit` and `pre-push` hooks as `.bak`; never
  overwrite an existing backup.
- Keep `--no-hook`, `--pre-push`, and `--profile` behavior tested.
- Honor `core.hooksPath` and worktrees.
- Keep generated wrappers path-safe on Linux, macOS, Git Bash, and Windows.
- Do not delete user files (`.commit_guard.toml`, `.commit_guard_ignore`,
  reports) on uninstall.

---

## Documentation

- Update `README.md` for user-visible behavior.
- Update the relevant `docs/` page for configuration, rules, CI, architecture,
  or troubleshooting changes.
- Keep claims measurable (e.g. “300+ active rules” rather than “thousands”).
- Never include a real secret in docs, tests, fixtures, or screenshots. Use
  obviously fake values such as `AKIAIOSFODNN7EXAMPLE`.

---

## Pull requests

Include:

- a concise description of the problem and the fix,
- tests proving the behavior,
- any tradeoffs or new limitations,
- docs updates.

Run before submitting:

```bash
python -m unittest discover -s tests -v
python -m py_compile main.py install_hook.py core/*.py
ruff check main.py install_hook.py core tests
python main.py --check-rules
```

By contributing, you agree that your contribution is provided under the same
terms as the project’s existing code and rule packs.
