from __future__ import annotations

import unittest

from core.paths import PathMatcher, glob_to_regex, is_binary_path, normalize_path


class PathMatcherTests(unittest.TestCase):
    def test_globstar_matches_at_any_depth(self):
        matcher = PathMatcher(["vendor/**"])
        self.assertTrue(matcher.matches("vendor/a.py"))
        self.assertTrue(matcher.matches("src/vendor/a/b.py"))
        self.assertFalse(matcher.matches("src/vendored/a.py"))

    def test_basename_pattern_matches_anywhere(self):
        matcher = PathMatcher(["*.lock"])
        self.assertTrue(matcher.matches("package.lock"))
        self.assertTrue(matcher.matches("a/b/package.lock"))
        self.assertFalse(matcher.matches("package.lock.txt"))

    def test_anchored_pattern(self):
        matcher = PathMatcher(["/src/*.py"])
        self.assertTrue(matcher.matches("src/app.py"))
        self.assertFalse(matcher.matches("pkg/src/app.py"))

    def test_negation_last_match_wins(self):
        matcher = PathMatcher(["**/*.js", "!src/**"])
        self.assertTrue(matcher.matches("dist/app.js"))
        self.assertFalse(matcher.matches("src/app.js"))
        self.assertTrue(matcher.matches("other/app.js"))

    def test_question_mark_and_character_literals(self):
        matcher = PathMatcher(["config.?aml"])
        self.assertTrue(matcher.matches("config.yaml"))
        self.assertFalse(matcher.matches("config.yamlx"))

    def test_empty_matcher_is_false(self):
        self.assertFalse(bool(PathMatcher([])))
        self.assertFalse(PathMatcher([]).matches("anything"))

    def test_normalize_path(self):
        self.assertEqual(normalize_path("./a\\b/c.py"), "a/b/c.py")

    def test_glob_compiles_case_insensitively(self):
        self.assertTrue(glob_to_regex("*.PEM").match("key.pem"))

    def test_binary_extensions(self):
        self.assertTrue(is_binary_path("logo.PNG"))
        self.assertFalse(is_binary_path("main.py"))


if __name__ == "__main__":
    unittest.main()
