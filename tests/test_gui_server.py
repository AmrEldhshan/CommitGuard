from __future__ import annotations

import http.client
import json
import shutil
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from unittest import mock

import gui_server

GIT = shutil.which("git")
FAKE_ENGINE = """\
import json
import sys
from pathlib import Path

args = sys.argv[1:]
report_path = None
for index, value in enumerate(args):
    if value == "--report-path":
        report_path = Path(args[index + 1])

finding = {
    "file": "app.py",
    "line": 3,
    "rule_id": "test-rule",
    "severity": "high",
    "source": "custom",
    "description": "Example finding",
    "cwe": "CWE-1",
    "tags": ["test"],
    "fingerprint": "fingerprint-1",
    "blocking": True,
    "baseline_state": "new",
    "fixed_versions": [],
    "aliases": [],
    "advisory_url": None,
    "flagged_code": "secret = 'x'",
}
payload = {
    "schema_version": 2,
    "tool": {"name": "CommitGuard", "version": "test"},
    "generated": "2026-01-01 00:00:00 UTC",
    "block_threshold": "high",
    "blocked": True,
    "truncated": False,
    "redacted": True,
    "summary": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
    "total": 1,
    "findings": [finding],
}
if report_path is not None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(payload), encoding="utf-8")
sys.exit(0)
"""


@unittest.skipUnless(GIT, "git is required")
class GuiServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        subprocess.run(["git", "init", "-q"], cwd=cls.root, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=cls.root, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=cls.root, check=True)
        (cls.root / "app.py").write_text("print('hi')\n", encoding="utf-8")
        subprocess.run(["git", "add", "app.py"], cwd=cls.root, check=True)
        cls.engine = cls.root / "fake_main.py"
        cls.engine.write_text(FAKE_ENGINE, encoding="utf-8")
        cls.server, cls.token, cls.state = gui_server.create_server(
            "127.0.0.1",
            0,
            engine=str(cls.engine),
            timeout=30,
            token="test-token",
        )
        cls.state.repo = str(cls.root)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.temp.cleanup()

    def _request(self, path, payload=None, method=None, token="test-token"):
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(
            self.base + path,
            data=data,
            method=method or ("POST" if data is not None else "GET"),
        )
        if token:
            request.add_header("X-CG-Token", token)
        if data is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                body = response.read()
                content_type = response.headers.get("Content-Type", "")
                if "application/json" in content_type:
                    return response.status, json.loads(body.decode("utf-8")), response.headers
                return response.status, body, response.headers
        except urllib.error.HTTPError as exc:
            body = exc.read()
            try:
                return exc.code, json.loads(body.decode("utf-8")), exc.headers
            except (ValueError, UnicodeDecodeError):
                return exc.code, body, exc.headers

    def test_page_requires_token_and_embeds_it(self):
        status, body, _ = self._request("/", token=None)
        self.assertEqual(status, 403)
        status, body, headers = self._request("/?t=test-token", token=None)
        self.assertEqual(status, 200)
        text = body.decode("utf-8")
        self.assertIn("test-token", text)
        self.assertNotIn("__TOKEN__", text)
        self.assertIn("text/html", headers.get("Content-Type", ""))

    def test_host_header_is_validated(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        connection.putrequest("GET", "/?t=test-token", skip_host=True)
        connection.putheader("Host", "evil.example")
        connection.endheaders()
        response = connection.getresponse()
        self.assertEqual(response.status, 403)
        response.read()
        connection.close()

    def test_scan_state_and_export(self):
        status, data, _ = self._request(
            "/api/scan", {"repo": str(self.root), "options": {"mode": "staged"}}
        )
        self.assertEqual(status, 200, data)
        self.assertEqual(data["report"]["total"], 1)
        self.assertEqual(data["report"]["findings"][0]["rule_id"], "test-rule")

        status, snapshot, _ = self._request(
            "/api/state?repo=" + urllib.parse.quote(str(self.root))
        )
        self.assertEqual(status, 200)
        self.assertIsNotNone(snapshot["report"])
        status, other, _ = self._request("/api/state?repo=/some/other/repo")
        self.assertIsNone(other["report"])

        status, exported, _ = self._request(
            "/api/export", {"repo": str(self.root), "format": "json", "save": False}
        )
        self.assertEqual(status, 200)
        self.assertIn("test-rule", exported["content"])
        status, saved, _ = self._request(
            "/api/export", {"repo": str(self.root), "format": "html", "save": True}
        )
        self.assertEqual(status, 200)
        self.assertTrue(Path(saved["saved_path"]).is_file())

        status, listing, _ = self._request(
            "/api/reports?repo=" + urllib.parse.quote(str(self.root))
        )
        self.assertEqual(status, 200)
        names = {item["name"] for item in listing["files"]}
        self.assertIn("report.html", names)

    def test_report_download_and_traversal(self):
        self._request(
            "/api/scan", {"repo": str(self.root), "options": {"mode": "staged"}}
        )
        self._request(
            "/api/export", {"repo": str(self.root), "format": "html", "save": True}
        )
        status, _data, headers = self._request(
            "/api/reports/download?repo="
            + urllib.parse.quote(str(self.root))
            + "&name=report.html"
        )
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers.get("Content-Type", ""))
        status, _, _ = self._request(
            "/api/reports/download?repo="
            + urllib.parse.quote(str(self.root))
            + "&name=../secret.txt"
        )
        self.assertEqual(status, 404)

    def test_auth_and_body_limits(self):
        status, _, _ = self._request(
            "/api/scan", {"repo": str(self.root)}, token=None
        )
        self.assertEqual(status, 403)
        large = {"repo": str(self.root), "pad": "x" * 70000}
        status, _, _ = self._request("/api/scan", large)
        self.assertEqual(status, 413)
        status, _, _ = self._request("/api/unknown", {})
        self.assertEqual(status, 404)
        status, _, _ = self._request("/api/maintenance/nope", {"repo": str(self.root)})
        self.assertEqual(status, 404)

    def test_config_validation_and_rules(self):
        status, config, _ = self._request(
            "/api/config?repo=" + urllib.parse.quote(str(self.root))
        )
        self.assertEqual(status, 200)
        self.assertIn("default_text", config)
        status, data, _ = self._request(
            "/api/config", {"repo": str(self.root), "text": "[scan]\nthreshold = 'medium'\n"}, method="PUT"
        )
        self.assertEqual(status, 200)
        self.assertEqual(data["summary"]["threshold"], "medium")
        status, data, _ = self._request(
            "/api/config", {"repo": str(self.root), "text": "[scan]\nthreshold = 'nope'\n"}, method="PUT"
        )
        self.assertEqual(status, 400)
        rules_dir = self.root / "rules"
        rules_dir.mkdir(exist_ok=True)
        (rules_dir / "custom_rules.yaml").write_text(
            "rules:\n  - id: test-rule\n    description: Test rule\n    severity: high\n    pattern: 'secret'\n",
            encoding="utf-8",
        )
        status, rules, _ = self._request(
            "/api/rules?repo=" + urllib.parse.quote(str(self.root))
        )
        self.assertEqual(status, 200, rules)
        self.assertIn("total", rules)

    def test_rule_pack_download_route(self):
        payload = (
            b"rules:\n  - id: server-download\n    description: Downloaded\n"
            b"    severity: high\n    regex: 'server-download-[0-9]+'\n"
        )
        with (
            mock.patch.object(gui_server.actions, "_validate_rule_url", side_effect=lambda value: value),
            mock.patch.object(
                gui_server.actions,
                "_fetch_rule_url",
                return_value=(payload, "text/yaml", "https://example.com/pack.yaml"),
            ),
        ):
            status, data, _ = self._request(
                "/api/rules/download",
                {
                    "repo": str(self.root),
                    "options": {
                        "source": "custom",
                        "url": "https://example.com/pack.yaml",
                        "name": "server-pack",
                    },
                },
            )
        self.assertEqual(status, 200, data)
        self.assertTrue(data["ok"])
        self.assertEqual(data["rules_added"], 1)
        self.assertTrue(Path(data["path"]).is_file())
        self.assertIn("downloaded-server-pack.yaml", data["path"])

    def test_version_health(self):
        status, health, _ = self._request("/api/health")
        self.assertEqual(status, 200)
        self.assertTrue(health["ok"])
        self.assertIn("version", health)


if __name__ == "__main__":
    unittest.main()
