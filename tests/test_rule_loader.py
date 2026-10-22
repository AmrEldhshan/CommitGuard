from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from core.rule_loader import (
    RuleLoadError,
    _extract_semgrep_regex,
    _normalize_inline_flags,
    apply_severity_overrides,
    load_ruleset,
    rules_for_file,
)

GITLEAKS = """
title = "test"

[allowlist]
paths = ['''vendor/.*''']

[[rules]]
id = "inline-flag-key"
description = "key"
regex = '''key(?i)\\s*=\\s*([a-z0-9]{8,})'''
entropy = 2.0
secretGroup = 1
keywords = ["key"]
tags = ["secret"]

[rules.allowlist]
regexes = ['''^example''']
"""

CUSTOM = """
rules:
  - id: custom-eval
    description: eval detected
    severity: high
    languages: [python]
    paths: ["src/**"]
    tags: [injection]
    cwe: CWE-95
    regex: '\\beval\\s*\\('
  - id: custom-secret
    description: token
    severity: critical
    secret: true
    regex: 'token=([A-Za-z0-9]{10,})'
"""

SEMGREP = """
rules:
  - id: regex-rule
    message: regex match
    severity: WARNING
    languages: [python]
    pattern-regex: 'dangerous_call\\('
  - id: either-rule
    message: either
    severity: ERROR
    languages: [generic]
    pattern-either:
      - pattern-regex: 'foo\\('
      - pattern-regex: 'bar\\('
  - id: ast-only
    message: ast
    severity: WARNING
    languages: [python]
    patterns:
      - pattern: eval(...)
"""

NUCLEI = """
id: test-connection
info:
  name: connection
  severity: high
file:
  - matchers:
      - type: regex
        regex:
          - '(?i)token=([A-Za-z0-9]{10,})'
"""


class NormalizeFlagTests(unittest.TestCase):
    def test_hoists_inline_flags(self):
        self.assertEqual(_normalize_inline_flags("key(?i)value"), "(?i)keyvalue")

    def test_leaves_scoped_flags(self):
        self.assertEqual(_normalize_inline_flags("(?i:foo)"), "(?i:foo)")


class SemgrepExtractionTests(unittest.TestCase):
    def test_direct_regex(self):
        self.assertEqual(_extract_semgrep_regex({"pattern-regex": "foo"}), "foo")

    def test_pattern_either_all_regex(self):
        entry = {"pattern-either": [{"pattern-regex": "a"}, {"pattern-regex": "b"}]}
        self.assertEqual(_extract_semgrep_regex(entry), "(?:a)|(?:b)")

    def test_mixed_pattern_either_is_skipped(self):
        entry = {"pattern-either": [{"pattern-regex": "a"}, {"pattern": "b"}]}
        self.assertIsNone(_extract_semgrep_regex(entry))


class RuleLoaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.rules_dir = Path(self.temp.name)
        (self.rules_dir / "semgrep_rules").mkdir()
        (self.rules_dir / "gitleaks.toml").write_text(GITLEAKS)
        (self.rules_dir / "custom_rules.yaml").write_text(CUSTOM)
        (self.rules_dir / "semgrep_rules" / "test.yaml").write_text(SEMGREP)
        (self.rules_dir / "nuclei_generic_key.yaml").write_text(NUCLEI)

    def tearDown(self):
        self.temp.cleanup()

    def _load(self, **kwargs):
        # Isolate cache writes from the developer's real cache.
        with (
            tempfile.TemporaryDirectory() as cache,
            mock.patch.dict(os.environ, {"COMMIT_GUARD_CACHE_DIR": cache}),
        ):
            return load_ruleset(self.rules_dir, warn=False, **kwargs)

    def test_loads_all_sources(self):
        ruleset = self._load()
        sources = {rule.source for rule in ruleset.rules}
        self.assertIn("gitleaks", sources)
        self.assertIn("custom", sources)
        self.assertIn("semgrep:test", sources)
        self.assertIn("nuclei", sources)
        self.assertEqual(
            {rule.rule_id for rule in ruleset.rules},
            {
                "inline-flag-key",
                "custom-eval",
                "custom-secret",
                "regex-rule",
                "either-rule",
                "test-connection-0",
            },
        )

    def test_skips_ast_only_with_diagnostic(self):
        ruleset = self._load()
        self.assertTrue(any(s.rule_id == "ast-only" for s in ruleset.skipped))

    def test_gitleaks_fields(self):
        rule = next(r for r in self._load().rules if r.rule_id == "inline-flag-key")
        self.assertEqual(rule.secret_group, 1)
        self.assertEqual(rule.entropy, 2.0)
        self.assertEqual(rule.keywords, ("key",))
        self.assertEqual(rule.tags, ("secret",))
        self.assertTrue(rule.is_secret)
        self.assertEqual(len(rule.allowlist_regexes), 1)

    def test_global_path_allowlist(self):
        ruleset = self._load()
        self.assertEqual(len(ruleset.path_allowlist), 1)
        self.assertTrue(ruleset.path_allowlist[0].search("vendor/lib.py"))

    def test_custom_rule_fields(self):
        rules = {r.rule_id: r for r in self._load().rules}
        self.assertEqual(rules["custom-eval"].cwe, "CWE-95")
        self.assertTrue(rules["custom-eval"].path_regexes)
        self.assertTrue(rules["custom-secret"].is_secret)
        self.assertEqual(rules["custom-eval"].severity, "high")

    def test_semgrep_severity_mapping(self):
        rules = {r.rule_id: r for r in self._load().rules}
        self.assertEqual(rules["regex-rule"].severity, "medium")
        self.assertEqual(rules["either-rule"].severity, "high")

    def test_custom_fix_metadata_round_trips_cache(self):
        (self.rules_dir / "custom").mkdir()
        (self.rules_dir / "custom" / "fixes.yaml").write_text(
            "rules:\n"
            "  - id: fix-tls\n"
            "    description: fix tls\n"
            "    severity: medium\n"
            "    regex: 'verify=False'\n"
            "    fix_pattern: 'verify\\s*=\\s*False'\n"
            "    fix_replacement: 'verify=True'\n"
        )
        first = self._load(use_cache=False)
        second = self._load()
        for ruleset in (first, second):
            fix = next(rule for rule in ruleset.rules if rule.rule_id == "fix-tls")
            self.assertIsNotNone(fix.fix_pattern)
            self.assertTrue(fix.fix_pattern.search("verify=False"))
            self.assertEqual(fix.fix_replacement, "verify=True")

    def test_invalid_custom_severity_is_skipped(self):
        (self.rules_dir / "custom_rules.yaml").write_text(
            CUSTOM
            + """
  - id: bad-severity
    description: broken
    severity: urgent
    regex: 'nope'
"""
        )
        ruleset = self._load()
        self.assertNotIn("bad-severity", {r.rule_id for r in ruleset.rules})
        skipped = next(s for s in ruleset.skipped if s.rule_id == "bad-severity")
        self.assertIn("invalid severity", skipped.reason)

    def test_language_filtering(self):
        ruleset = self._load()
        py_rules = rules_for_file(list(ruleset.rules), "src/app.py")
        js_rules = rules_for_file(list(ruleset.rules), "src/app.js")
        self.assertTrue(any(r.rule_id == "custom-eval" for r in py_rules))
        self.assertFalse(any(r.rule_id == "custom-eval" for r in js_rules))
        docker_rules = rules_for_file(list(ruleset.rules), "docker/Dockerfile.prod")
        self.assertFalse(any(r.rule_id == "custom-eval" for r in docker_rules))

    def test_loads_ai_security_and_iac_pack_directories(self):
        ai_dir = self.rules_dir / "ai_security"
        ai_dir.mkdir()
        (ai_dir / "nested").mkdir()
        (ai_dir / "nested" / "rules.yaml").write_text(
            "rules:\n"
            "  - id: pack-ai\n"
            "    description: pack rule\n"
            "    severity: high\n"
            "    regex: 'sk-test-([A-Za-z0-9]{8,})'\n"
        )
        iac_dir = self.rules_dir / "iac"
        iac_dir.mkdir()
        (iac_dir / "rules.yaml").write_text(
            "rules:\n"
            "  - id: pack-iac\n"
            "    description: pack rule\n"
            "    severity: low\n"
            "    languages: [dockerfile]\n"
            "    regex: 'USER root'\n"
        )
        ruleset = self._load()
        rules = {rule.rule_id: rule for rule in ruleset.rules}
        self.assertIn("pack-ai", rules)
        self.assertIn("pack-iac", rules)
        self.assertEqual(rules_for_file([rules["pack-iac"]], "Dockerfile.dev")[0].rule_id, "pack-iac")

    def test_severity_override(self):
        ruleset = self._load()
        updated = apply_severity_overrides(ruleset, {"regex-rule": "low"})
        rule = next(r for r in updated.rules if r.rule_id == "regex-rule")
        self.assertEqual(rule.severity, "low")
        self.assertEqual(len(updated.rules), len(ruleset.rules))

    def test_cache_hit_and_invalidation(self):
        first = self._load()
        second = self._load()
        self.assertEqual(len(first.rules), len(second.rules))

        gitleaks = self.rules_dir / "gitleaks.toml"
        gitleaks.write_text(GITLEAKS + '\n[[rules]]\nid = "extra"\nregex = "extra_key"\n')
        third = self._load()
        self.assertIn("extra", {r.rule_id for r in third.rules})

    def test_empty_rule_dir_raises(self):
        with tempfile.TemporaryDirectory() as empty, mock.patch.dict(
            os.environ, {"COMMIT_GUARD_CACHE_DIR": empty}
        ), self.assertRaises(RuleLoadError):
            load_ruleset(Path(empty), warn=False)

    def test_real_toolkit_loads(self):
        repo_rules = Path(__file__).resolve().parent.parent / "rules"
        with (
            tempfile.TemporaryDirectory() as cache,
            mock.patch.dict(os.environ, {"COMMIT_GUARD_CACHE_DIR": cache}),
        ):
            ruleset = load_ruleset(repo_rules, warn=False)
        self.assertGreater(len(ruleset.rules), 200)
        self.assertTrue(any(r.source == "custom" for r in ruleset.rules))
        self.assertTrue(any(r.rule_id == "generic-api-key" for r in ruleset.rules))


if __name__ == "__main__":
    unittest.main()
