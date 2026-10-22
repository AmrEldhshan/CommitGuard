from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from core.dep_graph import build_dependency_graph, write_dependency_graph


class DependencyGraphTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)

    def tearDown(self):
        self.temp.cleanup()

    def write(self, path: str, text: str) -> None:
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    def test_python_imports_reverse_edges_and_blast_radius(self):
        self.write("pkg/__init__.py", "")
        self.write("pkg/db.py", "import os\nimport pkg.models\n")
        self.write("pkg/models.py", "from . import db\n")
        self.write("app.py", "from pkg.db import connect\n")
        self.write("script.py", "import app\n")
        graph = build_dependency_graph(self.root)

        self.assertIn("pkg/models.py", graph.nodes["pkg/db.py"].imports)
        self.assertIn("pkg/db.py", graph.nodes["pkg/models.py"].imports)
        self.assertIn("pkg/db.py", graph.nodes["app.py"].imports)
        self.assertIn("os", graph.nodes["pkg/db.py"].external)
        self.assertEqual(
            graph.dependents("pkg/db.py"),
            ("app.py", "pkg/models.py", "script.py"),
        )
        self.assertEqual(
            graph.dependents("script.py"),
            (),
        )

    def test_javascript_imports_and_package_manifest(self):
        self.write(
            "package.json",
            json.dumps({"dependencies": {"react": "^18.0.0"}}),
        )
        self.write("src/lib.js", "export const x = 1;\n")
        self.write(
            "src/app.tsx",
            "import React from 'react';\n"
            "import { x } from './lib';\n"
            "const y = require('./lib.js');\n",
        )
        graph = build_dependency_graph(self.root)
        self.assertEqual(graph.nodes["src/app.tsx"].imports, ("src/lib.js",))
        self.assertIn("react", graph.nodes["src/app.tsx"].external)
        self.assertEqual(graph.nodes["package.json"].dependencies, ("react",))
        self.assertEqual(graph.dependents("src/lib.js"), ("src/app.tsx",))

    def test_go_rust_ruby_php_and_manifests(self):
        self.write("go.mod", "module example.com/demo\n\nrequire (\n  github.com/x/y v1.2.3\n)\n")
        self.write("main.go", 'package main\nimport (\n  "example.com/demo/store"\n  "fmt"\n)\n')
        self.write("store/store.go", "package store\n")
        self.write("Cargo.toml", '[package]\nname = "demo"\n[dependencies]\nserde = "1"\n')
        self.write("src/main.rs", "mod util;\nuse crate::util::run;\nuse serde::Serialize;\n")
        self.write("src/util.rs", "pub fn run() {}\n")
        self.write("lib/a.rb", "require_relative 'b'\n")
        self.write("lib/b.rb", "puts 'b'\n")
        self.write("web/index.php", "<?php require 'lib/a.php'; ?>\n")
        self.write("lib/a.php", "<?php\n")
        graph = build_dependency_graph(self.root)

        self.assertIn("store/store.go", graph.nodes["main.go"].imports)
        self.assertIn("fmt", graph.nodes["main.go"].external)
        self.assertIn("github.com/x/y", graph.nodes["go.mod"].dependencies)
        self.assertIn("serde", graph.nodes["Cargo.toml"].dependencies)
        self.assertIn("src/util.rs", graph.nodes["src/main.rs"].imports)
        self.assertIn("serde", graph.nodes["src/main.rs"].external)
        self.assertIn("lib/b.rb", graph.nodes["lib/a.rb"].imports)
        self.assertIn("lib/a.php", graph.nodes["web/index.php"].imports)

    def test_java_import_resolution(self):
        self.write("src/com/acme/Service.java", "package com.acme;\npublic class Service {}\n")
        self.write(
            "src/com/acme/App.java",
            "package com.acme;\nimport com.acme.Service;\nimport java.util.List;\n",
        )
        graph = build_dependency_graph(self.root)
        self.assertIn("src/com/acme/Service.java", graph.nodes["src/com/acme/App.java"].imports)
        self.assertIn("java.util", graph.nodes["src/com/acme/App.java"].external)

    def test_renderers_mark_vulnerable_and_dependents(self):
        self.write("a.py", "import b\n")
        self.write("b.py", "import c\n")
        self.write("c.py", "x = 1\n")
        graph = build_dependency_graph(self.root)
        vulnerable = {"c.py"}
        packages = {"requests"}
        mermaid = graph.to_mermaid(vulnerable_files=vulnerable, vulnerable_packages=packages)
        dot = graph.to_dot(vulnerable_files=vulnerable, vulnerable_packages=packages)
        payload = json.loads(
            graph.to_json(vulnerable_files=vulnerable, vulnerable_packages=packages)
        )
        self.assertIn("class n", mermaid)
        self.assertIn("vulnerable", mermaid)
        self.assertIn("📦 requests", mermaid)
        self.assertIn('fillcolor="#7f1d1d"', dot)
        self.assertEqual(payload["vulnerable_files"], ["c.py"])
        self.assertEqual(payload["blast_radius"]["c.py"]["dependents"], ["a.py", "b.py"])

    def test_writes_all_formats(self):
        self.write("a.py", "import b\n")
        self.write("b.py", "x = 1\n")
        graph = build_dependency_graph(self.root)
        written = write_dependency_graph(
            graph,
            self.root / "reports",
            "all",
            vulnerable_files={"b.py"},
        )
        self.assertEqual(len(written), 3)
        self.assertTrue((self.root / "reports/dependency-graph.mmd").is_file())
        self.assertTrue((self.root / "reports/dependency-graph.json").is_file())
        self.assertTrue((self.root / "reports/dependency-graph.dot").is_file())

    def test_invalid_format_rejected(self):
        graph = build_dependency_graph(self.root)
        with self.assertRaises(ValueError):
            write_dependency_graph(graph, self.root / "reports", "png")


if __name__ == "__main__":
    unittest.main()
