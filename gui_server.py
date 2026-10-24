#!/usr/bin/env python3
"""
gui_server.py — local web control center for Commit Guard.

Runs a stdlib HTTP server bound to loopback by default. The browser page is a
thin client: every action is forwarded to the same ``main.py`` /
``install_hook.py`` engine used by hooks and CI, so behaviour never diverges.

Security model
--------------
* Loopback bind by default; ``--allow-remote`` is required for anything else.
* Per-run random token required for the page and every API call.
* ``Host`` header validation mitigates DNS rebinding.
* Request bodies are capped; secrets stay redacted unless explicitly enabled.
* No telemetry, no external assets, no CDN.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import sys
import threading
import time
import traceback
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import gui_actions as actions
from gui_page import PAGE

MAX_BODY_BYTES = 64 * 1024
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
API_ACTIONS = {
    "status",
    "doctor",
    "init",
    "enable",
    "disable",
    "install",
    "update",
    "uninstall",
}


class AppState:
    def __init__(self, *, engine: str | None, timeout: int) -> None:
        self.engine = engine
        self.timeout = timeout
        self.lock = threading.Lock()
        self.repo: str | None = None
        self.report: dict | None = None
        self.options: dict | None = None

    def remember(self, repo: str, report: dict, options: dict) -> None:
        self.repo = repo
        self.report = report
        self.options = options

    def snapshot(self, repo: str | None = None) -> dict:
        if repo and self.repo and repo != self.repo:
            return {"repo": repo, "report": None, "options": None}
        return {"repo": self.repo, "report": self.report, "options": self.options}


def _version() -> str:
    try:
        from core import __version__

        return __version__
    except Exception:  # noqa: BLE001  # pragma: no cover - broken install
        return "unknown"


def _make_handler(state: AppState, token: str):
    class Handler(BaseHTTPRequestHandler):
        server_version = "CommitGuardGUI"
        protocol_version = "HTTP/1.1"

        # -- response helpers -------------------------------------------------
        def _headers(self, status: int, content_type: str, length: int, extra=None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(length))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()

        def _send_bytes(self, data: bytes, status: int = 200, content_type: str = "application/octet-stream", extra=None) -> None:
            self._headers(status, content_type, len(data), extra)
            if self.command != "HEAD":
                self.wfile.write(data)

        def _send_json(self, payload: object, status: int = 200) -> None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self._send_bytes(data, status, "application/json; charset=utf-8")

        def _send_text(self, text: str, status: int = 200, content_type: str = "text/plain; charset=utf-8") -> None:
            self._send_bytes(text.encode("utf-8"), status, content_type)

        def _send_error_json(self, message: str, status: int = 400, detail=None) -> None:
            self._send_json({"error": message, "detail": detail or {}}, status)

        # -- security ---------------------------------------------------------
        def _host_ok(self) -> bool:
            host = (self.headers.get("Host") or "").strip().lower()
            if host.startswith("["):
                host = host.split("]")[0].lstrip("[")
            else:
                host = host.rsplit(":", 1)[0]
            return host in LOOPBACK_HOSTS

        def _token_ok(self) -> bool:
            supplied = self.headers.get("X-CG-Token", "")
            if not supplied:
                query = parse_qs(urlparse(self.path).query)
                supplied = (query.get("t") or [""])[0]
            return bool(supplied) and secrets.compare_digest(str(supplied), token)

        def _guard(self) -> bool:
            if not self._host_ok():
                self._send_error_json("Invalid Host header.", 403)
                return False
            if not self._token_ok():
                self._send_error_json("Missing or invalid token.", 403)
                return False
            return True

        # -- body -------------------------------------------------------------
        def _read_json(self) -> dict | None:
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                self._send_error_json("Invalid Content-Length.", 400)
                return None
            if length > MAX_BODY_BYTES:
                self.close_connection = True
                self._send_error_json("Request body is too large.", 413)
                return None
            if length <= 0:
                return {}
            raw = self.rfile.read(length)
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._send_error_json("Request body must be valid JSON.", 400)
                return None
            if not isinstance(payload, dict):
                self._send_error_json("Request body must be a JSON object.", 400)
                return None
            return payload

        def _query(self) -> dict:
            return {key: values[0] for key, values in parse_qs(urlparse(self.path).query).items()}

        def _lock(self) -> bool:
            if state.lock.acquire(blocking=False):
                return True
            self._send_error_json("Another Commit Guard operation is already running.", 409)
            return False

        def _unlock(self) -> None:
            state.lock.release()

        # -- dispatch ---------------------------------------------------------
        def do_HEAD(self) -> None:
            self.do_GET()

        def do_GET(self) -> None:
            if not self._guard():
                return
            path = urlparse(self.path).path
            query = self._query()
            try:
                if path == "/":
                    page = PAGE.replace("__TOKEN__", token).replace(
                        "__REPO__", _js_string(state.repo or query.get("repo", ""))
                    )
                    self._send_text(
                        page,
                        200,
                        "text/html; charset=utf-8",
                    )
                    return
                if path == "/api/health":
                    self._send_json(_health(state))
                    return
                if path == "/api/state":
                    self._send_json(state.snapshot(query.get("repo")))
                    return
                if path == "/api/repo/info":
                    repo = query.get("repo") or state.repo
                    if not repo:
                        self._send_error_json("A repository path is required.", 400)
                        return
                    self._send_json(actions.repo_info(repo, state.engine))
                    return
                if path == "/api/config":
                    self._send_json(actions.config_get(query.get("repo") or state.repo or ""))
                    return
                if path == "/api/rules":
                    self._send_json(actions.list_rules(query.get("repo") or state.repo or "", state.engine))
                    return
                if path == "/api/rules/explain":
                    repo = query.get("repo") or state.repo or ""
                    rule_id = query.get("id") or ""
                    if not rule_id:
                        self._send_error_json("A rule id is required.", 400)
                        return
                    self._send_json(actions.explain_rule(repo, rule_id, state.engine))
                    return
                if path == "/api/baseline/entries":
                    self._send_json(actions.baseline_entries(query.get("repo") or state.repo or ""))
                    return
                if path == "/api/reports":
                    self._send_json(actions.list_reports(query.get("repo") or state.repo or ""))
                    return
                if path == "/api/reports/download":
                    self._serve_report(query.get("repo") or state.repo or "", query.get("name") or "")
                    return
                self._send_error_json("Not found.", 404)
            except actions.ActionError as exc:
                self._send_error_json(str(exc), exc.status, exc.detail)
            except Exception as exc:  # noqa: BLE001  # pragma: no cover - defensive
                traceback.print_exc()
                self._send_error_json(f"Unexpected error: {exc}", 500)

        def do_POST(self) -> None:
            if not self._guard():
                return
            path = urlparse(self.path).path
            payload = self._read_json()
            if payload is None:
                return
            try:
                self._handle_post(path, payload)
            except actions.ActionError as exc:
                self._send_error_json(str(exc), exc.status, exc.detail)
            except Exception as exc:  # noqa: BLE001  # pragma: no cover - defensive
                traceback.print_exc()
                self._send_error_json(f"Unexpected error: {exc}", 500)

        def do_PUT(self) -> None:
            if not self._guard():
                return
            path = urlparse(self.path).path
            payload = self._read_json()
            if payload is None:
                return
            try:
                if path == "/api/config":
                    self._send_json(
                        actions.config_save(payload.get("repo") or "", str(payload.get("text") or ""))
                    )
                    return
                self._send_error_json("Not found.", 404)
            except actions.ActionError as exc:
                self._send_error_json(str(exc), exc.status, exc.detail)
            except Exception as exc:  # noqa: BLE001  # pragma: no cover - defensive
                traceback.print_exc()
                self._send_error_json(f"Unexpected error: {exc}", 500)

        def do_OPTIONS(self) -> None:
            self._send_error_json("Method not allowed.", 405)

        def do_DELETE(self) -> None:
            self._send_error_json("Method not allowed.", 405)

        # -- handlers ---------------------------------------------------------
        def _repo(self, payload: dict) -> str:
            repo = str(payload.get("repo") or state.repo or "").strip()
            if not repo:
                raise actions.ActionError("A repository path is required.")
            return repo

        def _handle_post(self, path: str, payload: dict) -> None:
            if path == "/api/scan":
                repo = self._repo(payload)
                options = payload.get("options") or {}
                if not isinstance(options, dict):
                    raise actions.ActionError("Scan options must be an object.")
                if not self._lock():
                    return
                try:
                    result = actions.run_scan(repo, options, engine=state.engine, timeout=state.timeout)
                    state.remember(result["repo"], result["report"], options)
                    self._send_json(result)
                finally:
                    self._unlock()
                return

            if path == "/api/fixes/preview":
                repo = self._repo(payload)
                report = payload.get("report") or state.report
                if not isinstance(report, dict):
                    raise actions.ActionError("Run a scan first.")
                if not self._lock():
                    return
                try:
                    self._send_json(
                        actions.preview_fixes(
                            repo, report, payload.get("fingerprints"), engine=state.engine
                        )
                    )
                finally:
                    self._unlock()
                return

            if path == "/api/fixes/apply":
                repo = self._repo(payload)
                report = payload.get("report") or state.report
                if not isinstance(report, dict):
                    raise actions.ActionError("Run a scan first.")
                if not self._lock():
                    return
                try:
                    self._send_json(
                        actions.apply_fixes_action(
                            repo,
                            report,
                            payload.get("fingerprints") or [],
                            engine=state.engine,
                        )
                    )
                finally:
                    self._unlock()
                return

            if path == "/api/baseline/update":
                report = payload.get("report") or state.report
                if not isinstance(report, dict):
                    raise actions.ActionError("Run a scan first.")
                if not self._lock():
                    return
                try:
                    self._send_json(
                        actions.update_baseline(
                            self._repo(payload),
                            report,
                            owner=payload.get("owner"),
                            expiry=payload.get("expiry"),
                        )
                    )
                finally:
                    self._unlock()
                return

            if path == "/api/baseline/audit":
                report = payload.get("report") or state.report
                self._send_json(
                    actions.audit_suppressions(
                        self._repo(payload),
                        report if isinstance(report, dict) else None,
                        engine=state.engine,
                    )
                )
                return

            if path == "/api/baseline/suppress":
                if not self._lock():
                    return
                try:
                    self._send_json(
                        actions.suppress_findings(
                            self._repo(payload),
                            payload.get("fingerprints") or [],
                            owner=payload.get("owner"),
                            expiry=payload.get("expiry"),
                        )
                    )
                finally:
                    self._unlock()
                return

            if path == "/api/github/pr":
                if not self._lock():
                    return
                try:
                    self._send_json(
                        actions.create_pr(
                            self._repo(payload),
                            payload.get("options") or {},
                            token=str(payload.get("token") or ""),
                            repository=payload.get("repository"),
                            base=payload.get("base"),
                            branch=payload.get("branch"),
                            title=payload.get("title"),
                            engine=state.engine,
                            timeout=state.timeout,
                        )
                    )
                finally:
                    self._unlock()
                return

            if path == "/api/github/review":
                if not self._lock():
                    return
                try:
                    self._send_json(
                        actions.review_pr(
                            self._repo(payload),
                            payload.get("options") or {},
                            token=str(payload.get("token") or ""),
                            repository=payload.get("repository"),
                            pr_number=payload.get("pr_number") or "",
                            engine=state.engine,
                            timeout=state.timeout,
                        )
                    )
                finally:
                    self._unlock()
                return

            if path == "/api/github/suggestions":
                report = payload.get("report") or state.report
                if not isinstance(report, dict):
                    raise actions.ActionError("Run a scan first.")
                self._send_json(
                    actions.inline_suggestions(self._repo(payload), report, engine=state.engine)
                )
                return

            if path.startswith("/api/maintenance/"):
                action = path.rsplit("/", 1)[-1]
                if action not in API_ACTIONS:
                    raise actions.ActionError("Unknown maintenance action.", status=404)
                if not self._lock():
                    return
                try:
                    self._send_json(
                        actions.maintenance(
                            self._repo(payload),
                            action,
                            payload.get("options") or {},
                        )
                    )
                finally:
                    self._unlock()
                return

            if path == "/api/rules/check":
                self._send_json(actions.check_rules(self._repo(payload), state.engine))
                return

            if path == "/api/config/restore":
                if not self._lock():
                    return
                try:
                    self._send_json(actions.config_restore(self._repo(payload)))
                finally:
                    self._unlock()
                return

            if path == "/api/export":
                report = payload.get("report") or state.report
                if not isinstance(report, dict):
                    raise actions.ActionError("Run a scan first.")
                self._send_json(
                    actions.export_report(
                        self._repo(payload),
                        report,
                        str(payload.get("format") or "json"),
                        save=bool(payload.get("save")),
                    )
                )
                return

            self._send_error_json("Not found.", 404)

        def _serve_report(self, repo: str, name: str) -> None:
            if not repo or not name:
                self._send_error_json("A report name is required.", 400)
                return
            listing = actions.list_reports(repo)
            allowed = {item["name"] for item in listing["files"]}
            if name not in allowed:
                self._send_error_json("Report not found.", 404)
                return
            path = Path(listing["dir"]) / name
            try:
                data = path.read_bytes()
            except OSError as exc:
                self._send_error_json(f"Could not read the report: {exc}", 500)
                return
            if name.endswith(".html"):
                self._send_bytes(
                    data,
                    200,
                    "text/html; charset=utf-8",
                    {"Content-Security-Policy": (
                        "default-src 'none'; script-src 'unsafe-inline'; "
                        "style-src 'unsafe-inline'; img-src data:; font-src data:; "
                        "connect-src 'self'; base-uri 'none'; form-action 'none'"
                    )},
                )
            else:
                self._send_bytes(
                    data,
                    200,
                    "application/octet-stream",
                    {"Content-Disposition": f'attachment; filename="{name}"'},
                )

        def log_message(self, fmt: str, *args) -> None:
            # Never log URLs or headers: the token appears in query strings.
            return

    return Handler


def _js_string(value: str) -> str:
    """Escapes a value for safe insertion inside a JS string literal."""
    return (
        value.replace("\\", "\\\\")
        .replace("'", "\\'")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("</", "<\\/")
    )


def _health(state: AppState) -> dict:
    try:
        import yaml  # noqa: F401

        pyyaml = True
    except ImportError:
        pyyaml = False
    return {
        "ok": True,
        "version": _version(),
        "engine": state.engine,
        "timeout": state.timeout,
        "git": shutil.which("git") is not None,
        "pyyaml": pyyaml,
        "pid": os.getpid(),
        "time": int(time.time()),
    }


def create_server(
    host: str = "127.0.0.1",
    port: int = 8765,
    *,
    engine: str | None = None,
    timeout: int = actions.DEFAULT_TIMEOUT,
    token: str | None = None,
) -> tuple[ThreadingHTTPServer, str, AppState]:
    token = token or secrets.token_urlsafe(32)
    state = AppState(engine=engine, timeout=timeout)
    handler = _make_handler(state, token)
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    return server, token, state


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="commit-guard-gui",
        description="Local-only web control center for Commit Guard.",
    )
    parser.add_argument("--repo", default=".", help="Initial repository (default: current directory).")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (loopback only by default).")
    parser.add_argument("--port", type=int, default=8765, help="Port (0 chooses a free port).")
    parser.add_argument("--no-open", action="store_true", help="Do not open a browser automatically.")
    parser.add_argument("--allow-remote", action="store_true", help="Allow binding to a non-loopback address.")
    parser.add_argument("--engine", default=None, help="Explicit path to main.py.")
    parser.add_argument("--timeout", type=int, default=actions.DEFAULT_TIMEOUT, help="Per-operation timeout in seconds.")
    parser.add_argument("--report-only", action="store_true", help="Generate an HTML report and exit (no server).")
    parser.add_argument("--report-path", type=Path, default=None, help="Output path for --report-only.")
    parser.add_argument("--version", action="version", version=f"Commit Guard GUI {_version()}")
    return parser


def _report_only(args: argparse.Namespace) -> int:
    try:
        repo = actions.find_repo_root(args.repo)
        result = actions.run_scan(repo, {"mode": "all"}, engine=args.engine, timeout=args.timeout)
        export = actions.export_report(repo, result["report"], "html", save=False)
    except actions.ActionError as exc:
        print(f"[commit-guard-gui] ERROR: {exc}", file=sys.stderr)
        return 2
    output = Path(args.report_path).expanduser() if args.report_path else repo / "commit_guard_reports" / "report.html"
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(export["content"], encoding="utf-8")
    except OSError as exc:
        print(f"[commit-guard-gui] ERROR: could not write {output}: {exc}", file=sys.stderr)
        return 2
    print(f"[commit-guard-gui] HTML report: {output.resolve()}")
    if not args.no_open:
        try:
            webbrowser.open(output.resolve().as_uri())
        except Exception:  # noqa: BLE001,S110  # pragma: no cover - headless
            pass
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.report_only:
        return _report_only(args)

    host = args.host.strip()
    is_loopback = host in LOOPBACK_HOSTS
    if not is_loopback and not args.allow_remote:
        print(
            "[commit-guard-gui] ERROR: refusing to bind to a non-loopback address "
            "without --allow-remote.",
            file=sys.stderr,
        )
        return 2
    if args.timeout < 1:
        print("[commit-guard-gui] ERROR: --timeout must be a positive number.", file=sys.stderr)
        return 2

    initial = Path(args.repo).expanduser().resolve()
    try:
        server, token, state = create_server(
            host,
            args.port,
            engine=args.engine,
            timeout=args.timeout,
        )
    except OSError as exc:
        print(f"[commit-guard-gui] ERROR: could not start the server: {exc}", file=sys.stderr)
        return 2

    state.repo = str(initial)
    actual_port = server.server_address[1]
    display_host = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    url = f"http://{display_host}:{actual_port}/?t={token}"

    print("=" * 66)
    print("  COMMIT GUARD — Local Control Center")
    print("=" * 66)
    print(f"  URL      : {url}")
    print(f"  Repo     : {initial}")
    print(f"  Engine   : {args.engine or '(auto)'}")
    print(f"  Timeout  : {args.timeout}s")
    print("  Security : loopback only, per-run token, secrets redacted")
    print("  Stop     : Ctrl+C")
    print("=" * 66)

    if not args.no_open:
        def _open() -> None:
            try:
                webbrowser.open(url)
            except Exception:  # noqa: BLE001,S110  # pragma: no cover - headless
                pass

        threading.Timer(0.6, _open).start()

    try:
        server.serve_forever(poll_interval=0.3)
    except KeyboardInterrupt:
        print("\n[commit-guard-gui] shutting down.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
