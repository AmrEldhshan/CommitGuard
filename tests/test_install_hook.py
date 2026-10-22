from __future__ import annotations

import contextlib
import io
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import install_hook

GIT = shutil.which("git")


def git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=str(root),
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


@unittest.skipUnless(GIT, "git is required for installer tests")
class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        git(self.root, "init", "-q")
        git(self.root, "config", "user.email", "test@example.com")
        git(self.root, "config", "user.name", "Test")

    def tearDown(self):
        self.temp.cleanup()

    def quiet_install(self):
        with contextlib.redirect_stdout(io.StringIO()):
            install_hook.install(self.root)
        return self.root / ".commit_guard"

    def test_install_disable_enable_uninstall_preserves_user_files(self):
        prior_hook = self.root / ".git" / "hooks" / "pre-commit"
        prior_hook.parent.mkdir(parents=True, exist_ok=True)
        prior_hook.write_text("#!/bin/sh\necho prior\n", encoding="utf-8")
        prior_hook.chmod(0o755)
        (self.root / ".commit_guard.toml").write_text("[scan]\n", encoding="utf-8")

        install_dir = self.quiet_install()
        hook = self.root / ".git" / "hooks" / "pre-commit"
        self.assertTrue((install_dir / "main.py").is_file())
        self.assertTrue((self.root / "commit-guard").is_file())
        self.assertTrue(os.access(hook, os.X_OK))
        self.assertIn(".commit_guard/", (self.root / ".gitignore").read_text())

        with contextlib.redirect_stdout(io.StringIO()):
            install_hook.disable(self.root)
        self.assertFalse(hook.exists())
        self.assertTrue((hook.parent / "pre-commit.disabled").exists())

        with contextlib.redirect_stdout(io.StringIO()):
            install_hook.enable(self.root)
        self.assertTrue(hook.exists())

        with contextlib.redirect_stdout(io.StringIO()):
            install_hook.uninstall(self.root)
        self.assertFalse(install_dir.exists())
        self.assertFalse((self.root / "commit-guard").exists())
        self.assertIn("echo prior", hook.read_text())
        self.assertTrue((self.root / ".commit_guard.toml").is_file())

    def test_install_honors_core_hookspath(self):
        hooks_dir = self.root / ".githooks"
        git(self.root, "config", "core.hooksPath", ".githooks")
        install_dir = self.quiet_install()
        hook = hooks_dir / "pre-commit"
        self.assertTrue((install_dir / "main.py").is_file())
        self.assertTrue(os.access(hook, os.X_OK))
        self.assertIn(".commit_guard", hook.read_text())


if __name__ == "__main__":
    unittest.main()
