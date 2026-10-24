from __future__ import annotations

import re
import unittest
from collections import Counter
from html.parser import HTMLParser

import gui_page


class _IdCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: list[str] = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if "id" in values:
            self.ids.append(values["id"])


class GuiPageMarkupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.page = gui_page.PAGE
        cls.html = cls.page
        cls.script = re.search(r"<script>\n(.*?)\n</script>", cls.html, re.DOTALL).group(1)
        collector = _IdCollector()
        collector.feed(cls.html)
        cls.ids = collector.ids

    def test_ids_are_unique(self):
        duplicates = [key for key, count in Counter(self.ids).items() if count > 1]
        self.assertEqual(duplicates, [])

    def test_referenced_static_ids_exist(self):
        generated = set(re.findall(r'id="([A-Za-z0-9_-]+)"', self.script))
        referenced = set(re.findall(r'\$\("#([A-Za-z0-9_-]+)"\)', self.script))
        referenced.update(re.findall(r'getElementById\("([A-Za-z0-9_-]+)"\)', self.script))
        self.assertEqual(sorted(referenced - set(self.ids) - generated), [])

    def test_critical_controls_are_present(self):
        required = {
            "themeToggle",
            "pageTitle",
            "pageSubtitle",
            "gitRefreshBtn",
            "gitFilesBody",
            "gitCommitBtn",
            "gitBranchesOut",
            "gitDoctorBtn",
            "buildGraphBtn",
            "saveGraphBtn",
            "graphOut",
            "optFixApply",
            "optFixDryRun",
            "baselinePathInfo",
        }
        self.assertTrue(required.issubset(set(self.ids)), sorted(required - set(self.ids)))

    def test_advanced_scan_controls_are_collected(self):
        match = re.search(r"function gatherOptions\(\)\{(.*?)\n\}", self.script, re.DOTALL)
        self.assertIsNotNone(match)
        keys = set(re.findall(r"^\s{4}([a-z_]+):", match.group(1), re.MULTILINE))
        required = {
            "no_config",
            "strict",
            "soft_fail",
            "github_annotations",
            "verbose_rules",
            "config_path",
            "rules_dir",
            "baseline_path",
            "fix",
            "fix_dry_run",
        }
        self.assertTrue(required.issubset(keys), sorted(required - keys))

    def test_every_nav_tab_has_page_metadata(self):
        tabs = set(re.findall(r'data-tab="([A-Za-z0-9_-]+)"', self.html))
        meta = set(re.findall(r'^\s{2}([A-Za-z0-9_-]+): \[', self.script, re.MULTILINE))
        self.assertEqual(tabs - meta, set())
        self.assertEqual(meta - tabs, set())


if __name__ == "__main__":
    unittest.main()
