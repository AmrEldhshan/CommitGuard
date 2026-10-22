from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from core.sca import (
    OSVClient,
    Package,
    SCAResult,
    Vulnerability,
    collect_packages,
    scan_dependencies,
)


def write(root: Path, name: str, text: str) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


REQUESTS_VULN = {
    "id": "GHSA-requests-test",
    "aliases": ["CVE-2024-0001", "GHSA-requests-test"],
    "summary": "Requests has a test vulnerability.",
    "database_specific": {"severity": "HIGH"},
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "requests"},
            "ranges": [
                {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.32.0"}]}
            ],
        }
    ],
}

LODASH_VULN = {
    "id": "GHSA-lodash-test",
    "aliases": ["CVE-2024-0002"],
    "summary": "Lodash prototype pollution.",
    "database_specific": {"severity": "MODERATE"},
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "lodash"},
            "ranges": [
                {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}
            ],
        }
    ],
}


class CollectPackagesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_collects_lockfile_versions(self):
        write(self.root, "requirements.txt", "requests==2.19.0\nflask>=2\n-r other.txt\n")
        write(
            self.root,
            "package-lock.json",
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"name": "demo"},
                        "node_modules/lodash": {"version": "4.17.20"},
                        "node_modules/@scope/pkg": {"version": "1.0.0"},
                    },
                }
            ),
        )
        write(
            self.root,
            "go.mod",
            "module example.com/demo\nrequire (\n  golang.org/x/text v0.3.0\n)\n",
        )
        write(
            self.root,
            "Cargo.lock",
            '[[package]]\nname = "serde"\nversion = "1.0.0"\n',
        )
        write(
            self.root,
            "Gemfile.lock",
            "GEM\n  specs:\n    rack (3.0.0)\n\nPLATFORMS\n  ruby\n",
        )
        write(
            self.root,
            "composer.lock",
            json.dumps({"packages": [{"name": "monolog/monolog", "version": "v3.0.0"}]}),
        )
        write(
            self.root,
            "pom.xml",
            "<project><dependencies><dependency>"
            "<groupId>org.example</groupId><artifactId>demo</artifactId>"
            "<version>1.2.3</version></dependency></dependencies></project>",
        )
        packages = collect_packages(self.root)
        by_name = {package.name: package for package in packages}
        self.assertEqual(by_name["requests"].version, "2.19.0")
        self.assertEqual(by_name["lodash"].ecosystem, "npm")
        self.assertEqual(by_name["@scope/pkg"].version, "1.0.0")
        self.assertEqual(by_name["golang.org/x/text"].ecosystem, "Go")
        self.assertEqual(by_name["golang.org/x/text"].version, "0.3.0")
        self.assertEqual(by_name["serde"].ecosystem, "crates.io")
        self.assertEqual(by_name["rack"].ecosystem, "RubyGems")
        self.assertEqual(by_name["monolog/monolog"].version, "3.0.0")
        self.assertEqual(by_name["org.example:demo"].ecosystem, "Maven")
        self.assertNotIn("flask", by_name)

    def test_pyproject_poetry_and_yarn_lock(self):
        write(
            self.root,
            "pyproject.toml",
            '[project]\ndependencies = ["requests==2.19.0"]\n'
            '[tool.poetry.dependencies]\nflask = "2.0.1"\n',
        )
        write(
            self.root,
            "yarn.lock",
            'lodash@^4.17.0:\n  version "4.17.20"\n',
        )
        names = {package.name: package.version for package in collect_packages(self.root)}
        self.assertEqual(names["requests"], "2.19.0")
        self.assertEqual(names["flask"], "2.0.1")
        self.assertEqual(names["lodash"], "4.17.20")


class SCATests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        write(self.root, "requirements.txt", "requests==2.19.0\n")
        write(
            self.root,
            "package-lock.json",
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {"node_modules/lodash": {"version": "4.17.20"}},
                }
            ),
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_offline_snapshot_matches_ranges_and_builds_findings(self):
        write(
            self.root,
            ".commit_guard_osv.json",
            json.dumps({"vulnerabilities": [REQUESTS_VULN, LODASH_VULN]}),
        )
        result = scan_dependencies(self.root)
        self.assertEqual(result.mode, "offline")
        self.assertEqual(len(result.vulnerabilities), 2)
        self.assertEqual(result.package_names, {"requests", "lodash"})
        finding = next(
            item.to_finding()
            for item in result.vulnerabilities
            if item.package_name == "requests"
        )
        self.assertEqual(finding.rule_id, "sca-GHSA-requests-test")
        self.assertEqual(finding.severity, "high")
        self.assertEqual(finding.fixed_versions, ("2.32.0",))
        self.assertIn("CVE-2024-0001", finding.aliases)
        self.assertIn("2.32.0", finding.description)
        self.assertEqual(
            finding.advisory_url, "https://github.com/advisories/GHSA-requests-test"
        )
        self.assertNotIn("CVE-2024-0002", finding.description)

    def test_fixed_version_is_not_reported(self):
        write(self.root, "requirements.txt", "requests==2.32.0\n")
        write(
            self.root,
            ".commit_guard_osv.json",
            json.dumps({"vulnerabilities": [REQUESTS_VULN]}),
        )
        result = scan_dependencies(self.root)
        self.assertEqual(len(result.vulnerabilities), 0)

    def test_package_key_snapshot(self):
        write(
            self.root,
            "snapshot.json",
            json.dumps(
                {
                    "packages": {
                        "PyPI:requests@2.19.0": [REQUESTS_VULN],
                    }
                }
            ),
        )
        result = scan_dependencies(self.root, snapshot_path=self.root / "snapshot.json")
        self.assertEqual(len(result.vulnerabilities), 1)
        self.assertEqual(result.vulnerabilities[0].package_name, "requests")

    def test_missing_snapshot_degrades_with_warning(self):
        result = scan_dependencies(self.root)
        self.assertEqual(result.vulnerabilities, ())
        self.assertTrue(result.warnings)
        self.assertIn("No OSV snapshot", result.warnings[0])

    def test_online_batch_fetches_details(self):
        package = Package("PyPI", "requests", "2.19.0", "requirements.txt")
        calls = []

        def fake_request(url, payload=None):
            calls.append((url, payload))
            if url.endswith("/querybatch"):
                return {"results": [{"vulns": [{"id": "GHSA-requests-test"}]}]}
            return REQUESTS_VULN

        client = OSVClient()
        with mock.patch.object(client, "_request", side_effect=fake_request):
            results = client.query((package,))
        self.assertEqual(len(results[package.key]), 1)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][1]["queries"][0]["package"]["ecosystem"], "PyPI")

    def test_online_failure_is_warning_not_exception(self):
        with mock.patch.object(
            OSVClient, "query", side_effect=__import__("core.sca", fromlist=["SCAError"]).SCAError("offline")
        ):
            result = scan_dependencies(self.root, online=True)
        self.assertEqual(result.mode, "online")
        self.assertEqual(result.vulnerabilities, ())
        self.assertIn("offline", result.warnings[0])

    def test_vulnerability_finding_contains_no_secret_code(self):
        vuln = Vulnerability(
            id="OSV-1",
            aliases=("GHSA-abcd",),
            summary="summary",
            severity="medium",
            package_name="pkg",
            ecosystem="PyPI",
            version="1.0.0",
            fixed_versions=("1.0.1",),
            advisory_url="https://osv.dev/vulnerability/OSV-1",
            manifest="requirements.txt",
        )
        self.assertEqual(SCAResult((), (vuln,)).to_findings()[0].file, "requirements.txt")


if __name__ == "__main__":
    unittest.main()
