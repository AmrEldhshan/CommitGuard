from __future__ import annotations

import unittest

from core.ast_taint import scan_python_taint


class PythonAstTaintTests(unittest.TestCase):
    def scan(self, source: str, changed: set[int]):
        lines = source.splitlines()
        return scan_python_taint(
            {"app.py": lines},
            {"app.py": changed},
        )

    def test_request_value_flow_to_sql_reports_changed_source(self):
        result = self.scan(
            "def lookup(request, cursor):\n"
            "    user_id = request.args.get('id')\n"
            "    query = 'SELECT * FROM users WHERE id=' + user_id\n"
            "    cursor.execute(query)\n",  # commit-guard-ignore
            {2},
        )
        self.assertEqual(len(result.matches), 1)
        match = result.matches[0]
        self.assertEqual(match.finding.rule_id, "cg-python-ast-sqli-taint")
        self.assertEqual(match.finding.line_number, 2)
        self.assertEqual(match.sink_line, 4)
        self.assertEqual(match.finding.source, "python_ast")
        self.assertEqual(match.finding.cwe, "CWE-89")

    def test_request_value_flow_to_sql_reports_changed_sink(self):
        result = self.scan(
            "def lookup(request, cursor):\n"
            "    query = 'SELECT * FROM users WHERE id=' + request.args['id']\n"
            "    cursor.execute(query)\n",  # commit-guard-ignore
            {3},
        )
        self.assertEqual(len(result.matches), 1)
        self.assertEqual(result.matches[0].finding.line_number, 3)

    def test_parameterized_sql_query_does_not_report_bound_value(self):
        result = self.scan(
            "def lookup(request, cursor):\n"
            "    cursor.execute('SELECT * FROM users WHERE id=?', "
            "(request.args.get('id'),))\n",
            {2},
        )
        self.assertEqual(result.matches, ())

    def test_keyword_query_and_subprocess_arguments_are_tracked(self):
        sql = self.scan(
            "def lookup(request, cursor):\n"
            "    cursor.execute(sql=request.args.get('id'))\n",
            {2},
        )
        shell = self.scan(
            "def run(request):\n"
            "    command = request.args.get('command')\n"
            "    subprocess.run(args=command, shell=True)\n",  # commit-guard-ignore
            {3},
        )
        self.assertEqual(
            sql.matches[0].finding.rule_id, "cg-python-ast-sqli-taint"
        )
        self.assertEqual(
            shell.matches[0].finding.rule_id, "cg-python-ast-shell-taint"
        )

    def test_tainted_shell_command_requires_shell_execution(self):
        vulnerable = self.scan(
            "def run(request):\n"
            "    command = 'echo ' + request.args.get('value')\n"
            "    subprocess.run(command, shell=True)\n",  # commit-guard-ignore
            {3},
        )
        safe_mode = self.scan(
            "def run(request):\n"
            "    command = 'echo ' + request.args.get('value')\n"
            "    subprocess.run(command, shell=False)\n",
            {3},
        )
        self.assertEqual(len(vulnerable.matches), 1)
        self.assertEqual(
            vulnerable.matches[0].finding.rule_id, "cg-python-ast-shell-taint"
        )
        self.assertEqual(safe_mode.matches, ())

    def test_os_system_is_a_shell_sink(self):
        result = self.scan(
            "def run(request):\n"
            "    os.system('echo ' + input())\n",
            {2},
        )
        self.assertEqual(len(result.matches), 1)
        self.assertEqual(result.matches[0].finding.rule_id, "cg-python-ast-shell-taint")

    def test_reassignment_to_constant_clears_taint(self):
        result = self.scan(
            "def lookup(request, cursor):\n"
            "    query = request.args.get('id')\n"
            "    query = 'SELECT 1'\n"
            "    cursor.execute(query)\n",  # commit-guard-ignore
            {2, 3},
        )
        self.assertEqual(result.matches, ())

    def test_only_changed_flow_or_sink_is_reported(self):
        result = self.scan(
            "def lookup(request, cursor):\n"
            "    query = request.args.get('id')\n"
            "    cursor.execute(query)\n",  # commit-guard-ignore
            {1},
        )
        self.assertEqual(result.matches, ())

    def test_invalid_python_is_reported_as_warning(self):
        result = scan_python_taint(
            {"app.py": ["def broken(:"]},
            {"app.py": {1}},
        )
        self.assertEqual(result.matches, ())
        self.assertIn("could not parse Python syntax", result.warnings[0])

    def test_non_python_files_are_ignored(self):
        result = scan_python_taint({"app.js": ["eval(input)"]}, {"app.js": {1}})
        self.assertEqual(result, result.__class__())


if __name__ == "__main__":
    unittest.main()
