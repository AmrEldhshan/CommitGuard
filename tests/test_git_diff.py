from __future__ import annotations

import unittest

from core.git_diff import _parse_diff

SAMPLE = """diff --git a/src/app.py b/src/app.py
index 1111111..2222222 100644
--- a/src/app.py
+++ b/src/app.py
@@ -1,2 +1,3 @@
-old
 context
+first added
+second added
@@ -10,0 +12,1 @@
+after gap
diff --git a/docs/with space.md b/docs/with space.md
new file mode 100644
--- /dev/null
+++ b/docs/with space.md
@@ -0,0 +1,2 @@
+# Title
+secret line
diff --git a/deleted.py b/deleted.py
deleted file mode 100644
--- a/deleted.py
+++ /dev/null
@@ -1,2 +0,0 @@
-gone
-also gone
"""


class DiffParseTests(unittest.TestCase):
    def test_added_lines_and_line_numbers(self):
        lines = _parse_diff(SAMPLE)
        self.assertEqual(
            [(line.file_path, line.line_number, line.code_content) for line in lines],
            [
                ("src/app.py", 2, "first added"),
                ("src/app.py", 3, "second added"),
                ("src/app.py", 12, "after gap"),
                ("docs/with space.md", 1, "# Title"),
                ("docs/with space.md", 2, "secret line"),
            ],
        )

    def test_deleted_files_produce_no_added_lines(self):
        lines = _parse_diff(SAMPLE)
        self.assertFalse(any(line.file_path == "deleted.py" for line in lines))

    def test_empty_diff(self):
        self.assertEqual(_parse_diff(""), [])

    def test_malformed_hunk_without_file_is_skipped(self):
        raw = "@@ -1,0 +1,1 @@\n+orphan\n"
        self.assertEqual(_parse_diff(raw), [])


if __name__ == "__main__":
    unittest.main()
