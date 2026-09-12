"""
core/rule_loader.py
--------------------
Loads and normalizes rules from the local `rules/` directory into a single
in-memory list of Rule objects that core/scanner.py can apply against
staged diff lines.

Supported sources:
    - rules/gitleaks.toml          (gitleaks-style [[rules]] TOML)
    - rules/semgrep_rules/*.yaml   (semgrep-style `rules:` YAML)
    - rules/nuclei_generic_key.yaml (nuclei-style YAML with a `matchers`/regex list)
    - rules/owasp_sqli.conf        (ModSecurity/OWASP CRD-style, one regex per
                                     directive line, best-effort parsing)

No external network calls are made — everything is read from disk with the
standard library plus PyYAML (the only third-party dependency, required
because semgrep/nuclei rules are YAML).
"""

from __future__ import annotations

import re
import tomllib
import warnings
from dataclasses import dataclass, field
from pathlib import Path

# Suppress regex FutureWarning (e.g. nested sets in complex regex patterns)
warnings.filterwarnings("ignore", category=FutureWarning)

try:
    import yaml  # PyYAML — required for semgrep/nuclei rule files.
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "PyYAML is required to parse semgrep/nuclei rule files. "
        "Install it with: pip install pyyaml"
    ) from exc


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass(frozen=True)
class Rule:
    """A normalized, source-agnostic security rule."""
    rule_id: str
    description: str
    severity: str            # one of SEVERITY_ORDER keys (lowercased)
    pattern: re.Pattern      # compiled regex applied against a single line
    source: str              # e.g. "gitleaks", "semgrep:python", "nuclei", "owasp_sqli"
    languages: tuple[str, ...] = field(default_factory=tuple)  # file extensions, empty = any


class RuleLoadError(RuntimeError):
    """Raised when a rule file is missing, malformed, or has no usable rules."""


# Semgrep uses its own severity vocabulary (ERROR/WARNING/INFO) rather
# than critical/high/medium/low — map those onto our common scale.
_SEMGREP_SEVERITY_MAP = {
    "error": "high",
    "warning": "medium",
    "info": "info",
}


def _normalize_severity(raw: str | None) -> str:
    if not raw:
        return "medium"
    raw = raw.strip().lower()
    if raw in SEVERITY_ORDER:
        return raw
    if raw in _SEMGREP_SEVERITY_MAP:
        return _SEMGREP_SEVERITY_MAP[raw]
    return "medium"


def _safe_compile(pattern: str, rule_id: str) -> re.Pattern | None:
    """Compiles a regex defensively; a single bad rule must never crash the scan or spam terminal."""
    try:
        return re.compile(pattern)
    except re.error:
        # Silently skip unsupported regex constructs (e.g. Go regex specific features)
        return None


# --------------------------------------------------------------------------
# gitleaks.toml
# --------------------------------------------------------------------------

def _load_gitleaks_toml(path: Path) -> list[Rule]:
    if not path.is_file():
        return []

    with path.open("rb") as f:
        data = tomllib.load(f)

    rules: list[Rule] = []
    for entry in data.get("rules", []):
        rule_id = entry.get("id", "gitleaks-unknown")
        regex_str = entry.get("regex")
        if not regex_str:
            continue
        compiled = _safe_compile(regex_str, rule_id)
        if compiled is None:
            continue
        rules.append(
            Rule(
                rule_id=rule_id,
                description=entry.get("description", "Potential hardcoded secret."),
                severity=_normalize_severity(entry.get("severity", "high")),
                pattern=compiled,
                source="gitleaks",
                languages=(),
            )
        )
    return rules


# --------------------------------------------------------------------------
# semgrep_rules/*.yaml
# --------------------------------------------------------------------------

# Maps semgrep's `languages:` identifiers to file extensions we can match
# against staged file paths.
_SEMGREP_LANG_TO_EXT = {
    "python": (".py",),
    "javascript": (".js", ".jsx", ".mjs"),
    "typescript": (".ts", ".tsx"),
    "go": (".go",),
    "java": (".java",),
    "c": (".c", ".h"),
    "csharp": (".cs",),
    "ruby": (".rb",),
    "php": (".php",),
    "rust": (".rs",),
    "kotlin": (".kt",),
    "scala": (".scala",),
    "swift": (".swift",),
    "solidity": (".sol",),
    "terraform": (".tf",),
    "dockerfile": ("dockerfile",),  # matched by filename, handled specially
    "yaml": (".yaml", ".yml"),
    "json": (".json",),
    "bash": (".sh",),
    "elixir": (".ex", ".exs"),
    "generic": (),  # applies to any file
}


def _extract_semgrep_regex(pattern_block: dict) -> str | None:
    """
    Semgrep rules are primarily AST-pattern based, not regex based, which
    Commit Guard cannot execute without the semgrep engine itself. To stay
    dependency-free we only pull rules that expose an explicit
    `pattern-regex` (semgrep's own regex-mode field) — these are common in
    the security-audit and secrets rule packs.
    """
    return pattern_block.get("pattern-regex")


def _load_semgrep_yaml_file(path: Path) -> list[Rule]:
    if not path.is_file():
        return []

    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    rules: list[Rule] = []
    for entry in data.get("rules", []):
        regex_str = _extract_semgrep_regex(entry)
        if not regex_str:
            # Skip AST-pattern-only rules; we can't evaluate those without
            # the semgrep engine, and Commit Guard is regex-only by design.
            continue

        rule_id = entry.get("id", f"semgrep-{path.stem}-unknown")
        compiled = _safe_compile(regex_str, rule_id)
        if compiled is None:
            continue

        raw_languages = entry.get("languages", [])
        exts: list[str] = []
        for lang in raw_languages:
            exts.extend(_SEMGREP_LANG_TO_EXT.get(lang.lower(), ()))

        metadata = entry.get("metadata", {}) or {}
        rules.append(
            Rule(
                rule_id=rule_id,
                description=entry.get("message", "Semgrep pattern match."),
                severity=_normalize_severity(
                    entry.get("severity", metadata.get("severity", "medium"))
                ),
                pattern=compiled,
                source=f"semgrep:{path.stem}",
                languages=tuple(exts),
            )
        )
    return rules


def _load_semgrep_rules(semgrep_dir: Path) -> list[Rule]:
    if not semgrep_dir.is_dir():
        return []
    rules: list[Rule] = []
    for yaml_path in sorted(semgrep_dir.glob("*.yaml")) + sorted(semgrep_dir.glob("*.yml")):
        rules.extend(_load_semgrep_yaml_file(yaml_path))
    return rules


# --------------------------------------------------------------------------
# nuclei_generic_key.yaml
# --------------------------------------------------------------------------

def _load_nuclei_yaml(path: Path) -> list[Rule]:
    if not path.is_file():
        return []

    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    rule_id = data.get("id", "nuclei-generic-key")
    info = data.get("info", {}) or {}
    severity = _normalize_severity(info.get("severity", "high"))
    description = info.get("description", info.get("name", "Generic exposed key/token."))

    rules: list[Rule] = []
    # Nuclei "file" templates typically nest regexes under
    # file: - extractors: - regex: [...] and/or matchers: - regex: [...]
    for file_block in data.get("file", []):
        for section_name in ("extractors", "matchers"):
            for block in file_block.get(section_name, []) or []:
                if block.get("type") != "regex":
                    continue
                for i, regex_str in enumerate(block.get("regex", [])):
                    compiled = _safe_compile(regex_str, f"{rule_id}-{i}")
                    if compiled is None:
                        continue
                    rules.append(
                        Rule(
                            rule_id=f"{rule_id}-{i}",
                            description=description,
                            severity=severity,
                            pattern=compiled,
                            source="nuclei",
                            languages=(),
                        )
                    )
    return rules


# --------------------------------------------------------------------------
# owasp_sqli.conf (ModSecurity CRS-style)
# --------------------------------------------------------------------------

# Matches lines like:
#   SecRule ARGS "@rx (?i:union\s+select)" "id:942100,phase:2,severity:'CRITICAL'"
_MODSEC_RULE_RE = re.compile(
    r'SecRule\s+\S+\s+"@rx\s+(?P<pattern>.+?)"\s+"(?P<meta>.+)"',
    re.IGNORECASE,
)
_MODSEC_ID_RE = re.compile(r"id:(\d+)")
_MODSEC_SEVERITY_RE = re.compile(r"severity:'?(\w+)'?", re.IGNORECASE)

_MODSEC_SEVERITY_MAP = {
    "critical": "critical",
    "2": "critical",
    "error": "high",
    "3": "high",
    "warning": "medium",
    "4": "medium",
    "notice": "low",
    "5": "low",
}


def _load_owasp_conf(path: Path) -> list[Rule]:
    if not path.is_file():
        return []

    rules: list[Rule] = []
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line_no, line in enumerate(f, start=1):
            match = _MODSEC_RULE_RE.search(line)
            if not match:
                continue

            pattern_str = match.group("pattern")
            meta = match.group("meta")

            id_match = _MODSEC_ID_RE.search(meta)
            rule_id = f"owasp-sqli-{id_match.group(1)}" if id_match else f"owasp-sqli-L{line_no}"

            sev_match = _MODSEC_SEVERITY_RE.search(meta)
            severity = _MODSEC_SEVERITY_MAP.get(
                sev_match.group(1).lower() if sev_match else "", "high"
            )

            compiled = _safe_compile(pattern_str, rule_id)
            if compiled is None:
                continue

            rules.append(
                Rule(
                    rule_id=rule_id,
                    description="Potential SQL injection pattern (OWASP CRS).",
                    severity=severity,
                    pattern=compiled,
                    source="owasp_sqli",
                    languages=(),
                )
            )
    return rules


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def load_all_rules(rules_dir: Path) -> list[Rule]:
    """
    Loads and merges rules from every supported source under `rules_dir`.

    Raises:
        RuleLoadError: if the resulting rule set is completely empty,
        since scanning with zero rules would silently give a false sense
        of security.
    """
    rules_dir = Path(rules_dir)

    all_rules: list[Rule] = []
    all_rules.extend(_load_gitleaks_toml(rules_dir / "gitleaks.toml"))
    all_rules.extend(_load_semgrep_rules(rules_dir / "semgrep_rules"))
    all_rules.extend(_load_nuclei_yaml(rules_dir / "nuclei_generic_key.yaml"))
    all_rules.extend(_load_owasp_conf(rules_dir / "owasp_sqli.conf"))

    if not all_rules:
        raise RuleLoadError(
            f"No usable rules were loaded from '{rules_dir}'. "
            "Check that gitleaks.toml, semgrep_rules/*.yaml, "
            "nuclei_generic_key.yaml, and owasp_sqli.conf exist and are well-formed."
        )

    return all_rules


def rules_for_file(rules: list[Rule], file_path: str) -> list[Rule]:
    """
    Filters a rule list down to those applicable to a given file path:
    rules with no `languages` restriction apply everywhere; rules with a
    languages tuple only apply when the file's extension matches.
    """
    ext = Path(file_path).suffix.lower()
    name = Path(file_path).name.lower()

    applicable = []
    for rule in rules:
        if not rule.languages:
            applicable.append(rule)
        elif ext in rule.languages:
            applicable.append(rule)
        elif "dockerfile" in rule.languages and name == "dockerfile":
            applicable.append(rule)
    return applicable
