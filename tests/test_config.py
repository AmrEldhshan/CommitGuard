from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from core.config import Config, ConfigError, default_config_text, load_config
from core.paths import DEFAULT_EXCLUDES


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_defaults_without_file(self):
        config = load_config(self.root)
        self.assertEqual(config.threshold, "high")
        self.assertEqual(config.format, "markdown")
        self.assertTrue(config.redact)
        self.assertEqual(config.exclude, DEFAULT_EXCLUDES)

    def test_parses_full_file(self):
        (self.root / ".commit_guard.toml").write_text(
            """
[scan]
threshold = "medium"
format = "both"
report_dir = "reports"
redact = false
ignore_inline = false
max_findings = 10
github_annotations = true
rules_dir = "local-rules"

[paths]
exclude = ["**/fixtures/**"]
report_allowlist = ["docs/**"]

[allowlist]
rules = ["some-rule"]
paths = ["tests/**"]

[severity]
"rule-a" = "low"
"""
        )
        config = load_config(self.root)
        self.assertEqual(config.threshold, "medium")
        self.assertEqual(config.format, "both")
        self.assertEqual(config.report_dir, "reports")
        self.assertFalse(config.redact)
        self.assertFalse(config.ignore_inline)
        self.assertEqual(config.max_findings, 10)
        self.assertTrue(config.github_annotations)
        self.assertEqual(config.rules_dir, Path("local-rules"))
        self.assertIn("**/fixtures/**", config.exclude)
        self.assertEqual(config.report_allowlist, ("docs/**",))
        self.assertEqual(config.allowlist_rules, ("some-rule",))
        self.assertEqual(config.allowlist_paths, ("tests/**",))
        self.assertEqual(config.severity_overrides["rule-a"], "low")

    def test_invalid_threshold(self):
        (self.root / ".commit_guard.toml").write_text('[scan]\nthreshold = "nope"\n')
        with self.assertRaises(ConfigError):
            load_config(self.root)

    def test_invalid_format(self):
        (self.root / ".commit_guard.toml").write_text('[scan]\nformat = "xml"\n')
        with self.assertRaises(ConfigError):
            load_config(self.root)

    def test_invalid_severity_override(self):
        (self.root / ".commit_guard.toml").write_text('[severity]\n"r" = "severe"\n')
        with self.assertRaises(ConfigError):
            load_config(self.root)

    def test_negative_max_findings_rejected(self):
        (self.root / ".commit_guard.toml").write_text("[scan]\nmax_findings = -1\n")
        with self.assertRaises(ConfigError):
            load_config(self.root)

    def test_non_integer_max_findings_rejected(self):
        (self.root / ".commit_guard.toml").write_text('[scan]\nmax_findings = "many"\n')
        with self.assertRaises(ConfigError):
            load_config(self.root)

    def test_bad_toml(self):
        (self.root / ".commit_guard.toml").write_text("[scan\nthreshold=")
        with self.assertRaises(ConfigError):
            load_config(self.root)

    def test_explicit_missing_config_raises(self):
        with self.assertRaises(ConfigError):
            load_config(self.root, explicit_path=self.root / "missing.toml")

    def test_no_config_ignores_file(self):
        (self.root / ".commit_guard.toml").write_text('[scan]\nthreshold = "low"\n')
        config = load_config(self.root, use_config=False)
        self.assertEqual(config.threshold, "high")

    def test_with_overrides(self):
        config = Config().with_overrides(threshold="medium", format=None)
        self.assertEqual(config.threshold, "medium")
        self.assertEqual(config.format, "markdown")

    def test_template_is_valid_and_round_trips(self):
        (self.root / ".commit_guard.toml").write_text(default_config_text())
        config = load_config(self.root)
        self.assertEqual(config.threshold, "high")
        self.assertTrue(config.redact)


if __name__ == "__main__":
    unittest.main()
