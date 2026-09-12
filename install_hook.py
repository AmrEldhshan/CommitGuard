#!/usr/bin/env python3
"""
install_hook.py — Commit Guard lifecycle manager.

Unlike a normal git hook installer, this one does NOT just point the
target repo's hook at wherever this toolkit happens to live. Running
`install` COPIES the full engine (main.py + core/ + rules/) into the
target repo itself, under `<repo>/.commit_guard/`. The hook — and the
`commit-guard` / `commit-guard.bat` wrapper scripts this also installs
at the repo root — both call that local copy.

The result: once installed, a repo's Commit Guard setup is fully
self-contained. Deleting, moving, or renaming wherever you originally
ran `install` from has zero effect on repos you've already installed
into.

Subcommands (run `python install_hook.py <command> --help` for details):
    install     Copy the toolkit into a repo and wire up the hook.
    uninstall   Remove everything Commit Guard put in a repo.
    enable      Re-enable a previously disabled hook.
    disable     Pause auto-scan-on-commit without uninstalling.
    status      Show what's currently installed in a repo.
    scan        Run a manual scan without committing.

Running this file with no subcommand opens an interactive menu.
"""

from __future__ import annotations

import argparse
import shutil
import stat
import subprocess
import sys
from pathlib import Path

_TOOLKIT_DIR = Path(__file__).resolve().parent  # where THIS copy of install_hook.py lives

_INSTALL_DIRNAME = ".commit_guard"
_HOOK_NAME = "pre-commit"
_DISABLED_HOOK_NAME = "pre-commit.disabled"
_BACKUP_HOOK_NAME = "pre-commit.bak"

_WRAPPER_SH_NAME = "commit-guard"
_WRAPPER_BAT_NAME = "commit-guard.bat"

_RULE_FILE_GLOBS = ("*.toml", "*.yaml", "*.yml", "*.conf")

GITIGNORE_ENTRIES = [
    "# Commit Guard (local security scanner) — safe to delete anytime",
    f"{_INSTALL_DIRNAME}/",
    "commit_guard_reports/",
    _WRAPPER_SH_NAME,
    _WRAPPER_BAT_NAME,
]


class HookError(RuntimeError):
    """Raised when an operation fails."""


# --------------------------------------------------------------------------
# Path resolution helpers
# --------------------------------------------------------------------------

def find_repo_root(target_path: Path) -> Path:
    target_path = Path(target_path).expanduser().resolve()
    if not target_path.exists():
        raise HookError(f"Target path does not exist: {target_path}")
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=str(target_path),
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise HookError("git executable not found on PATH.") from exc
    if result.returncode != 0:
        raise HookError(f"'{target_path}' does not appear to be inside a git repository.")
    return Path(result.stdout.strip()).resolve()


def find_git_dir(target_path: Path) -> Path:
    target_path = Path(target_path).expanduser().resolve()
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--git-dir"],
            cwd=str(target_path),
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise HookError("git executable not found on PATH.") from exc
    if result.returncode != 0:
        raise HookError(f"'{target_path}' does not appear to be inside a git repository.")
    git_dir = Path(result.stdout.strip())
    if not git_dir.is_absolute():
        git_dir = (target_path / git_dir).resolve()
    return git_dir


def get_install_dir(repo_root: Path) -> Path:
    return repo_root / _INSTALL_DIRNAME


# --------------------------------------------------------------------------
# Copying the toolkit into the target repo
# --------------------------------------------------------------------------

def copy_toolkit(repo_root: Path, source_root: Path, force: bool = False) -> Path:
    """
    Copies main.py, core/, install_hook.py, and rules/ from `source_root`
    into `<repo_root>/.commit_guard/`, making the install self-contained.

    If `source_root` already IS the installed copy (e.g. re-running
    `./commit-guard install` from inside an already-installed repo), the
    file copy is skipped — that mode is purely for repairing the hook,
    wrapper scripts, or .gitignore without needing the original toolkit.
    """
    install_dir = get_install_dir(repo_root)
    install_dir.mkdir(parents=True, exist_ok=True)

    source_root = Path(source_root).expanduser().resolve()
    if source_root == install_dir.resolve():
        print("  [install] Source is the already-installed copy — skipping file copy (repair mode).")
        return install_dir

    source_main = source_root / "main.py"
    source_install_hook = source_root / "install_hook.py"
    source_core = source_root / "core"
    source_rules = source_root / "rules"

    if not source_main.is_file() or not source_core.is_dir():
        raise HookError(
            f"'{source_root}' doesn't look like a Commit Guard toolkit "
            "(expected main.py and core/ there). Pass --source to point "
            "at the right directory."
        )

    shutil.copy2(source_main, install_dir / "main.py")
    if source_install_hook.is_file():
        shutil.copy2(source_install_hook, install_dir / "install_hook.py")

    dest_core = install_dir / "core"
    if dest_core.exists():
        shutil.rmtree(dest_core)
    shutil.copytree(source_core, dest_core)
    print(f"  [install] Copied engine (main.py + core/) into {install_dir}")

    dest_rules = install_dir / "rules"
    if source_rules.is_dir():
        if dest_rules.exists() and not force:
            print(f"  [install] Existing rules/ found — keeping as-is (pass --force to overwrite).")
        else:
            if dest_rules.exists():
                shutil.rmtree(dest_rules)
            shutil.copytree(source_rules, dest_rules)
            print(f"  [install] Copied rules/ into {dest_rules}")
    elif not dest_rules.exists():
        print(
            f"  [install] WARNING: no rules/ directory found at '{source_root}' and "
            f"none is installed yet — scans will fail until rule files exist at {dest_rules}"
        )

    return install_dir


def count_rule_files(rules_dir: Path) -> int:
    if not rules_dir.is_dir():
        return 0
    count = 0
    for pattern in _RULE_FILE_GLOBS:
        count += len(list(rules_dir.rglob(pattern)))
    return count


# --------------------------------------------------------------------------
# .gitignore
# --------------------------------------------------------------------------

def update_gitignore(repo_root: Path) -> bool:
    gitignore_path = repo_root / ".gitignore"
    existing_content = ""
    if gitignore_path.exists():
        existing_content = gitignore_path.read_text(encoding="utf-8", errors="replace")

    missing_entries = [e for e in GITIGNORE_ENTRIES if e.startswith("#") is False and e not in existing_content]
    if not missing_entries:
        return False

    with open(gitignore_path, "a", encoding="utf-8") as f:
        if existing_content and not existing_content.endswith("\n"):
            f.write("\n")
        f.write("\n" + "\n".join(GITIGNORE_ENTRIES) + "\n")

    print(f"  [install] Added Commit Guard entries to {gitignore_path.name}")
    return True


# --------------------------------------------------------------------------
# Hook script
# --------------------------------------------------------------------------

def _render_hook_script(install_dir: Path) -> str:
    python_exe = sys.executable.replace("\\", "/")
    main_py = str((install_dir / "main.py").resolve()).replace("\\", "/")
    return (
        "#!/bin/sh\n"
        "# Auto-generated by Commit Guard.\n"
        "# This hook calls the SELF-CONTAINED copy in .commit_guard/ — it does\n"
        "# not depend on wherever Commit Guard was originally installed from.\n"
        "# Manage it with: ./commit-guard status | disable | enable | uninstall\n"
        "\n"
        'REPO_DIR="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"\n'
        "\n"
        f'"{python_exe}" "{main_py}" --repo "$REPO_DIR"\n'
        "exit $?\n"
    )


def write_hook(repo_root: Path, install_dir: Path) -> Path:
    git_dir = find_git_dir(repo_root)
    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)

    hook_path = hooks_dir / _HOOK_NAME
    disabled_path = hooks_dir / _DISABLED_HOOK_NAME

    if disabled_path.exists():
        disabled_path.unlink()

    if hook_path.exists():
        backup_path = hooks_dir / _BACKUP_HOOK_NAME
        if not backup_path.exists():
            print(f"  [install] Existing pre-commit hook found — backing up to {backup_path.name}")
            hook_path.replace(backup_path)
        else:
            hook_path.unlink()

    hook_path.write_text(_render_hook_script(install_dir), encoding="utf-8")
    hook_path.chmod(hook_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    print(f"  [install] Pre-commit hook installed at {hook_path}")
    return hook_path


# --------------------------------------------------------------------------
# Wrapper scripts (manual commands inside the target repo)
# --------------------------------------------------------------------------

def _render_wrapper_sh(install_dir: Path) -> str:
    python_exe = sys.executable.replace("\\", "/")
    manager = str((install_dir / "install_hook.py").resolve()).replace("\\", "/")
    return (
        "#!/bin/sh\n"
        "# Commit Guard manual CLI. Safe to delete along with .commit_guard/.\n"
        "# Examples: ./commit-guard scan | status | disable | enable | uninstall\n"
        f'"{python_exe}" "{manager}" "$@"\n'
    )


def _render_wrapper_bat(install_dir: Path) -> str:
    python_exe = sys.executable
    manager = str((install_dir / "install_hook.py").resolve())
    return (
        "@echo off\r\n"
        "REM Commit Guard manual CLI. Safe to delete along with .commit_guard\\.\r\n"
        "REM Examples: commit-guard.bat scan / status / disable / enable / uninstall\r\n"
        f'"{python_exe}" "{manager}" %*\r\n'
    )


def write_wrapper_scripts(repo_root: Path, install_dir: Path) -> None:
    sh_path = repo_root / _WRAPPER_SH_NAME
    sh_path.write_text(_render_wrapper_sh(install_dir), encoding="utf-8")
    sh_path.chmod(sh_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    bat_path = repo_root / _WRAPPER_BAT_NAME
    bat_path.write_text(_render_wrapper_bat(install_dir), encoding="utf-8")

    print(f"  [install] Manual CLI ready: ./{_WRAPPER_SH_NAME} (or {_WRAPPER_BAT_NAME} on Windows)")


def remove_wrapper_scripts(repo_root: Path) -> bool:
    removed = False
    for name in (_WRAPPER_SH_NAME, _WRAPPER_BAT_NAME):
        path = repo_root / name
        if path.exists():
            path.unlink()
            removed = True
    return removed


# --------------------------------------------------------------------------
# Lifecycle actions
# --------------------------------------------------------------------------

def install(target_path: Path, source_root: Path | None = None, force: bool = False,
            update_gitignore_flag: bool = True) -> Path:
    repo_root = find_repo_root(target_path)
    source_root = source_root or _TOOLKIT_DIR

    print(f"[commit-guard] Installing into: {repo_root}")
    install_dir = copy_toolkit(repo_root, source_root, force=force)
    write_wrapper_scripts(repo_root, install_dir)
    write_hook(repo_root, install_dir)
    if update_gitignore_flag:
        update_gitignore(repo_root)

    print(
        f"\n✅ Commit Guard is installed and self-contained in this repo.\n"
        f"   Scans now run automatically on every `git commit`.\n"
        f"   Manual commands: ./{_WRAPPER_SH_NAME} scan | status | disable | enable | uninstall\n"
    )
    return install_dir


def uninstall(target_path: Path) -> bool:
    repo_root = find_repo_root(target_path)
    git_dir = find_git_dir(target_path)
    hooks_dir = git_dir / "hooks"
    hook_path = hooks_dir / _HOOK_NAME
    disabled_path = hooks_dir / _DISABLED_HOOK_NAME
    backup_path = hooks_dir / _BACKUP_HOOK_NAME
    install_dir = get_install_dir(repo_root)

    removed_anything = False

    if hook_path.exists():
        hook_path.unlink()
        print(f"  [uninstall] Removed active hook.")
        removed_anything = True

    if disabled_path.exists():
        disabled_path.unlink()
        print(f"  [uninstall] Removed disabled hook.")
        removed_anything = True

    if backup_path.exists():
        backup_path.replace(hook_path)
        print(f"  [uninstall] Restored the pre-commit hook that was here before Commit Guard.")
        removed_anything = True

    if remove_wrapper_scripts(repo_root):
        print(f"  [uninstall] Removed ./{_WRAPPER_SH_NAME} and ./{_WRAPPER_BAT_NAME}")
        removed_anything = True

    if install_dir.exists():
        shutil.rmtree(install_dir)
        print(f"  [uninstall] Removed {install_dir}")
        removed_anything = True

    if not removed_anything:
        print("  [uninstall] Nothing to remove — Commit Guard isn't installed here.")
        return False

    print("  [uninstall] Commit Guard fully removed from this repository.")
    return True


def disable(target_path: Path) -> bool:
    git_dir = find_git_dir(target_path)
    hooks_dir = git_dir / "hooks"
    hook_path = hooks_dir / _HOOK_NAME
    disabled_path = hooks_dir / _DISABLED_HOOK_NAME

    if not hook_path.exists():
        if disabled_path.exists():
            print("  [disable] Already disabled.")
            return True
        print("  [disable] No active hook found — nothing to disable. Run `install` first.")
        return False

    hook_path.replace(disabled_path)
    print("  [disable] Auto-scan-on-commit turned OFF. Manual scans still work.")
    return True


def enable(target_path: Path) -> bool:
    git_dir = find_git_dir(target_path)
    hooks_dir = git_dir / "hooks"
    hook_path = hooks_dir / _HOOK_NAME
    disabled_path = hooks_dir / _DISABLED_HOOK_NAME

    if hook_path.exists():
        print("  [enable] Already enabled and active.")
        return True

    if not disabled_path.exists():
        print("  [enable] No installed hook found. Run `install` first.")
        return False

    disabled_path.replace(hook_path)
    hook_path.chmod(hook_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    print("  [enable] Auto-scan-on-commit turned back ON.")
    return True


def status(target_path: Path) -> None:
    repo_root = find_repo_root(target_path)
    git_dir = find_git_dir(target_path)
    hooks_dir = git_dir / "hooks"
    hook_path = hooks_dir / _HOOK_NAME
    disabled_path = hooks_dir / _DISABLED_HOOK_NAME
    backup_path = hooks_dir / _BACKUP_HOOK_NAME
    install_dir = get_install_dir(repo_root)
    rules_dir = install_dir / "rules"

    print("\n" + "=" * 62)
    print("  COMMIT GUARD — Status")
    print("=" * 62)
    print(f"  Repository      : {repo_root}")

    if install_dir.exists():
        rule_count = count_rule_files(rules_dir)
        print(f"  Toolkit copy    : ✅ self-contained at {_INSTALL_DIRNAME}/")
        if rule_count:
            print(f"  Rule files      : {rule_count} found")
        else:
            print(f"  Rule files      : ⚠️  none found — scans will report 0 findings (add files under {rules_dir})")
    else:
        print("  Toolkit copy    : ❌ not installed")

    if hook_path.exists():
        print("  Auto-scan hook  : ✅ ACTIVE (runs on every git commit)")
    elif disabled_path.exists():
        print("  Auto-scan hook  : ⏸️  DISABLED (run `enable` to turn back on)")
    else:
        print("  Auto-scan hook  : ❌ not installed")

    if backup_path.exists():
        print(f"  Prior hook      : backed up as {backup_path.name} (restored on uninstall)")

    wrapper_present = (repo_root / _WRAPPER_SH_NAME).exists()
    print(f"  Manual CLI      : {'✅ ./' + _WRAPPER_SH_NAME + ' available' if wrapper_present else '❌ not installed'}")

    gitignore_path = repo_root / ".gitignore"
    ignored = gitignore_path.exists() and _INSTALL_DIRNAME in gitignore_path.read_text(encoding="utf-8", errors="ignore")
    print(f"  .gitignore      : {'✅ configured' if ignored else '⚠️  not configured'}")
    print("=" * 62 + "\n")


def run_manual_scan(target_path: Path, threshold: str = "high", quiet: bool = False) -> int:
    repo_root = find_repo_root(target_path)
    install_dir = get_install_dir(repo_root)
    main_py = install_dir / "main.py"

    if not main_py.is_file():
        print(
            "[commit-guard] ERROR: Commit Guard isn't installed in this repo yet. "
            "Run `install` first.",
            file=sys.stderr,
        )
        return 2

    cmd = [sys.executable, str(main_py), "--repo", str(repo_root), "--threshold", threshold]
    if quiet:
        cmd.append("--quiet")
    result = subprocess.run(cmd, cwd=str(repo_root))
    return result.returncode


# --------------------------------------------------------------------------
# Interactive menu (used when the script is run with no subcommand)
# --------------------------------------------------------------------------

def interactive_menu(default_path: str | None = None) -> None:
    print("\n" + "=" * 62)
    print("      🛡️   COMMIT GUARD — Interactive Manager")
    print("=" * 62)

    target_input = default_path or input("Target repository [Enter = current dir]: ").strip() or "."

    try:
        repo_root = find_repo_root(Path(target_input))
    except HookError as exc:
        print(f"\n❌ {exc}\n")
        return

    actions = {
        "1": ("Install Commit Guard here", lambda: install(repo_root)),
        "2": ("Run a manual scan now", lambda: run_manual_scan(repo_root)),
        "3": ("Show status", lambda: status(repo_root)),
        "4": ("Disable auto-scan-on-commit", lambda: disable(repo_root)),
        "5": ("Enable auto-scan-on-commit", lambda: enable(repo_root)),
        "6": ("Uninstall completely", lambda: _confirm_uninstall(repo_root)),
        "7": ("Change target repository", None),
        "0": ("Exit", None),
    }

    while True:
        print(f"\nTarget: {repo_root}")
        print("-" * 62)
        for key, (label, _) in actions.items():
            print(f"  [{key}] {label}")
        print("-" * 62)

        choice = input("Select an option: ").strip()

        if choice == "0":
            print("Goodbye! 👋\n")
            return
        if choice == "7":
            new_input = input("New repository path: ").strip()
            if new_input:
                try:
                    repo_root = find_repo_root(Path(new_input))
                except HookError as exc:
                    print(f"❌ {exc}")
            continue
        if choice in actions and actions[choice][1] is not None:
            try:
                actions[choice][1]()
            except HookError as exc:
                print(f"❌ {exc}")
        else:
            print("Invalid choice.")


def _confirm_uninstall(repo_root: Path) -> None:
    confirm = input(f"Remove Commit Guard completely from {repo_root}? [y/N]: ").strip().lower()
    if confirm in ("y", "yes"):
        uninstall(repo_root)
    else:
        print("Aborted.")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="commit-guard",
        description="Install, manage, or run Commit Guard on a local git repository.",
    )
    sub = parser.add_subparsers(dest="command")

    p_install = sub.add_parser("install", help="Copy Commit Guard into a repo and wire up the pre-commit hook.")
    p_install.add_argument("repo", nargs="?", default=".", help="Target repository (default: current directory).")
    p_install.add_argument("--source", type=Path, default=None,
                            help="Path to the Commit Guard toolkit to copy from (default: this script's own directory).")
    p_install.add_argument("--force", action="store_true", help="Overwrite an already-installed rules/ directory too.")
    p_install.add_argument("--no-gitignore", action="store_true", help="Don't touch the target repo's .gitignore.")

    p_uninstall = sub.add_parser("uninstall", help="Remove everything Commit Guard put in a repo.")
    p_uninstall.add_argument("repo", nargs="?", default=".")

    p_enable = sub.add_parser("enable", help="Re-enable a previously disabled hook.")
    p_enable.add_argument("repo", nargs="?", default=".")

    p_disable = sub.add_parser("disable", help="Pause auto-scan-on-commit without uninstalling.")
    p_disable.add_argument("repo", nargs="?", default=".")

    p_status = sub.add_parser("status", help="Show what's currently installed in a repo.")
    p_status.add_argument("repo", nargs="?", default=".")

    p_scan = sub.add_parser("scan", help="Run a manual scan without committing.")
    p_scan.add_argument("repo", nargs="?", default=".")
    p_scan.add_argument("--threshold", choices=("critical", "high", "medium", "low", "info"), default="high")
    p_scan.add_argument("--quiet", action="store_true")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        interactive_menu()
        return 0

    target = Path(args.repo).expanduser().resolve()

    try:
        if args.command == "install":
            source = args.source or _TOOLKIT_DIR
            install(target, source_root=source, force=args.force, update_gitignore_flag=not args.no_gitignore)
        elif args.command == "uninstall":
            uninstall(target)
        elif args.command == "enable":
            enable(target)
        elif args.command == "disable":
            disable(target)
        elif args.command == "status":
            status(target)
        elif args.command == "scan":
            return run_manual_scan(target, threshold=args.threshold, quiet=args.quiet)
    except HookError as exc:
        print(f"[commit-guard] ERROR: {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
