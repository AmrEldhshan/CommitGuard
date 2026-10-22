"""
core/config.py
---------------
Loads `.commit_guard.toml` from the repository root (or an explicit path)
and merges it with CLI overrides.

The config file is intentionally optional and human-editable.  A complete
example lives in `docs/CONFIGURATION.md`; every key has a sane default so
an empty repository needs no configuration at all.

Supported schema:

    [scan]
    threshold = "high"          # critical | high | medium | low | info
    format = "markdown"         # markdown | json | sarif | both | junit | gitlab | checkstyle
    report_dir = "commit_guard_reports"
    redact = true               # mask secrets in reports/terminal output
    ignore_inline = true        # honor `commit-guard-ignore` comments
    max_findings = 0            # 0 = unlimited (report a count when capped)
    github_annotations = false  # emit ::error/::warning lines (auto in Actions)
    soft_fail = false           # report findings but exit 0 (operational errors still exit 2)
    fail_on = "all"             # all | new (with a baseline)
    filter_placeholders = true  # ignore obvious example/dummy secret values

    [paths]
    exclude = ["**/fixtures/**"]
    report_allowlist = ["docs/**"]

    [allowlist]
    rules = ["gitleaks-generic-api-key"]
    paths = ["tests/**"]

    [severity]
    "semgrep-generic-hardcoded-password" = "low"
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path

from core.paths import DEFAULT_EXCLUDES

CONFIG_FILENAME = ".commit_guard.toml"
VALID_THRESHOLDS = ("critical", "high", "medium", "low", "info")
VALID_FORMATS = (
    "markdown",
    "json",
    "sarif",
    "both",
    "junit",
    "gitlab",
    "checkstyle",
    "html",
)
VALID_FAIL_ON = ("all", "new")
VALID_PROFILES = ("strict", "balanced", "audit")
VALID_DEP_GRAPH_FORMATS = ("mermaid", "json", "dot", "all")


class ConfigError(RuntimeError):
    """Raised when a config file is malformed or contains invalid values."""


@dataclass(frozen=True)
class Config:
    threshold: str = "high"
    format: str = "markdown"
    report_dir: str = "commit_guard_reports"
    report_path: Path | None = None
    redact: bool = True
    ignore_inline: bool = True
    max_findings: int = 0
    github_annotations: bool = False
    soft_fail: bool = False
    fail_on: str = "all"
    filter_placeholders: bool = True
    dep_graph: bool = False
    dep_graph_format: str = "mermaid"
    dep_graph_max_nodes: int = 250
    sca: bool = False
    sca_online: bool = False
    sca_snapshot: Path | None = None
    sca_timeout: int = 20
    fix: bool = False
    fix_dry_run: bool = False
    exclude: tuple[str, ...] = DEFAULT_EXCLUDES
    report_allowlist: tuple[str, ...] = ()
    allowlist_rules: tuple[str, ...] = ()
    allowlist_paths: tuple[str, ...] = ()
    severity_overrides: dict[str, str] = field(default_factory=dict)
    rules_dir: Path | None = None
    warn_skipped_rules: bool = True

    def with_overrides(self, **overrides: object) -> Config:
        """Returns a copy with only the provided (non-None) values replaced."""
        clean = {key: value for key, value in overrides.items() if value is not None}
        if not clean:
            return self
        return replace(self, **clean)


def _as_str_tuple(value: object, key: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple)) and all(isinstance(v, str) for v in value):
        return tuple(value)
    raise ConfigError(f"'{key}' must be a string or a list of strings.")


def _validate(config: Config) -> Config:
    if config.threshold not in VALID_THRESHOLDS:
        raise ConfigError(
            f"Invalid threshold '{config.threshold}'. "
            f"Choose one of: {', '.join(VALID_THRESHOLDS)}."
        )
    if config.format not in VALID_FORMATS:
        raise ConfigError(
            f"Invalid format '{config.format}'. "
            f"Choose one of: {', '.join(VALID_FORMATS)}."
        )
    if config.max_findings < 0:
        raise ConfigError("'scan.max_findings' must be zero or a positive integer.")
    if config.fail_on not in VALID_FAIL_ON:
        raise ConfigError(
            f"Invalid fail_on '{config.fail_on}'. "
            f"Choose one of: {', '.join(VALID_FAIL_ON)}."
        )
    if config.dep_graph_format not in VALID_DEP_GRAPH_FORMATS:
        raise ConfigError(
            f"Invalid dep_graph_format '{config.dep_graph_format}'. "
            f"Choose one of: {', '.join(VALID_DEP_GRAPH_FORMATS)}."
        )
    if config.dep_graph_max_nodes < 1:
        raise ConfigError("'scan.dep_graph_max_nodes' must be a positive integer.")
    if config.sca_timeout < 1:
        raise ConfigError("'scan.sca_timeout' must be a positive integer.")
    for rule_id, severity in config.severity_overrides.items():
        if severity not in VALID_THRESHOLDS:
            raise ConfigError(
                f"Invalid severity override '{severity}' for rule '{rule_id}'."
            )
    return config


def load_config(
    repo_root: Path,
    explicit_path: Path | None = None,
    use_config: bool = True,
) -> Config:
    """
    Reads the config file and returns a validated Config.

    If `use_config` is False, or the default file does not exist, all
    defaults are returned.  An explicit `--config` path must exist.
    """
    if not use_config and explicit_path is None:
        return Config()

    config_path = explicit_path or (repo_root / CONFIG_FILENAME)
    if not config_path.is_file():
        if explicit_path is not None:
            raise ConfigError(f"Config file not found: {config_path}")
        return Config()

    try:
        raw = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"Could not parse {config_path}: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"Could not read {config_path}: {exc}") from exc

    scan = raw.get("scan", {}) or {}
    paths = raw.get("paths", {}) or {}
    allowlist = raw.get("allowlist", {}) or {}
    severity = raw.get("severity", {}) or {}

    if not isinstance(scan, dict) or not isinstance(paths, dict) or not isinstance(
        allowlist, dict
    ) or not isinstance(severity, dict):
        raise ConfigError("Sections 'scan', 'paths', 'allowlist', and 'severity' must be tables.")

    try:
        config = Config(
            threshold=scan.get("threshold", "high"),
            format=scan.get("format", "markdown"),
            report_dir=scan.get("report_dir", "commit_guard_reports"),
            report_path=Path(scan["report_path"]).expanduser() if scan.get("report_path") else None,
            redact=bool(scan.get("redact", True)),
            ignore_inline=bool(scan.get("ignore_inline", True)),
            max_findings=int(scan.get("max_findings", 0)),
            github_annotations=bool(scan.get("github_annotations", False)),
            soft_fail=bool(scan.get("soft_fail", False)),
            fail_on=str(scan.get("fail_on", "all")).lower(),
            filter_placeholders=bool(scan.get("filter_placeholders", True)),
            dep_graph=bool(scan.get("dep_graph", False)),
            dep_graph_format=str(scan.get("dep_graph_format", "mermaid")).lower(),
            dep_graph_max_nodes=int(scan.get("dep_graph_max_nodes", 250)),
            sca=bool(scan.get("sca", False)),
            sca_online=bool(scan.get("sca_online", False)),
            sca_snapshot=Path(scan["sca_snapshot"]).expanduser() if scan.get("sca_snapshot") else None,
            sca_timeout=int(scan.get("sca_timeout", 20)),
            fix=bool(scan.get("fix", False)),
            fix_dry_run=bool(scan.get("fix_dry_run", False)),
            exclude=DEFAULT_EXCLUDES + _as_str_tuple(paths.get("exclude"), "paths.exclude"),
            report_allowlist=_as_str_tuple(paths.get("report_allowlist"), "paths.report_allowlist"),
            allowlist_rules=_as_str_tuple(allowlist.get("rules"), "allowlist.rules"),
            allowlist_paths=_as_str_tuple(allowlist.get("paths"), "allowlist.paths"),
            severity_overrides={str(k): str(v).lower() for k, v in severity.items()},
            rules_dir=Path(scan["rules_dir"]) if scan.get("rules_dir") else None,
            warn_skipped_rules=bool(scan.get("warn_skipped_rules", True)),
        )
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"Invalid value in {config_path}: {exc}") from exc
    return _validate(config)


def default_config_text() -> str:
    """Returns the contents used by `commit-guard init`."""
    return """# Commit Guard configuration (.commit_guard.toml)
# Every key is optional; delete anything you don't need.

[scan]
threshold = "high"       # block commits on high+ severity (default)
format = "markdown"      # markdown | json | sarif | both | junit | gitlab | checkstyle | html
report_dir = "commit_guard_reports"
redact = true            # never print raw secrets in reports
ignore_inline = true     # honor `# commit-guard-ignore` comments
filter_placeholders = true  # ignore obvious example/dummy secret values
# soft_fail = false      # report findings but exit 0
# fail_on = "new"        # block only findings not in .commit_guard_ignore
# max_findings = 500
# github_annotations = true
# dep_graph = true          # write an architecture + blast-radius graph
# dep_graph_format = "mermaid"  # mermaid | json | dot | all
# dep_graph_max_nodes = 250
# sca = false              # check pinned dependencies against OSV data
# sca_online = false       # OSV.dev network query (offline snapshot otherwise)
# sca_snapshot = ".commit_guard_osv.json"
# sca_timeout = 20
# fix = false              # apply rules with fix_pattern/fix_replacement
# fix_dry_run = false      # preview fixes without writing or staging

[paths]
# Extra globs to skip (defaults already exclude lockfiles, vendor/, node_modules/).
exclude = [
    # "**/fixtures/**",
    # "**/testdata/**",
]

# Findings in these paths are recorded in the report but never block a commit.
report_allowlist = [
    # "docs/**",
]

[allowlist]
# Rule IDs disabled everywhere (prefer inline comments or paths when possible).
rules = [
    # "gitleaks-generic-api-key",
]
# Path globs where no rule can block a commit.
paths = [
    # "tests/fixtures/**",
]

[severity]
# Raise or lower individual rules.
# "semgrep-generic-hardcoded-password" = "low"
"""


def profile_defaults(profile: str) -> dict[str, object]:
    """Returns config overrides for an installer profile."""
    if profile not in VALID_PROFILES:
        raise ConfigError(
            f"Invalid profile '{profile}'. Choose one of: {', '.join(VALID_PROFILES)}."
        )
    if profile == "strict":
        return {"threshold": "medium", "soft_fail": False, "max_findings": 0}
    if profile == "audit":
        return {"threshold": "high", "soft_fail": True, "fail_on": "all"}
    return {"threshold": "high", "soft_fail": False, "fail_on": "all"}
