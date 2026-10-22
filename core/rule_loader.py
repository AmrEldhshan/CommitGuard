"""
core/rule_loader.py
--------------------
Loads and normalizes rules from the local `rules/` directory into Rule
objects that core/scanner.py can apply against staged diff lines.

Supported sources
-----------------
    rules/gitleaks.toml            gitleaks `[[rules]]` TOML — including
                                   path filters, entropy, secretGroup,
                                   keywords, tags, and nested allowlists.
    rules/semgrep_rules/*.yaml     semgrep YAML; only regex-backed rules
                                   (`pattern-regex`, or a `pattern-either`
                                   made entirely of regexes) can run
                                   without the semgrep engine.
    rules/custom_rules.yaml        Commit Guard's simple native format
    rules/custom/*.yaml|*.yml      (see docs/RULES.md) for hand-written,
                                   high-signal rules.
    rules/nuclei_generic_key.yaml  nuclei file-template regex matchers.

The upstream OWASP CRS SQL-injection pack under `rules/experimental/` is
intentionally **not** loaded by default: it targets HTTP request values and
produces heavy false positives on source lines. `_load_owasp_conf` remains
available for opt-in experiments.

No network calls. The only third-party dependency is PyYAML, needed
because semgrep/nuclei rules are YAML.

Performance
-----------
Parsing ~100k lines of upstream YAML takes multiple seconds, which is
unacceptable inside a pre-commit hook. Parsed rules are therefore cached
as JSON under the user cache directory, keyed by a signature of every
rule file (path + size + mtime). A cache hit costs a few milliseconds; an
edit or upgrade invalidates it automatically. The cache is a pure
optimization — corrupt/unwritable caches fall back to a normal parse.

Diagnostics
-----------
Rules that cannot be represented as a single Python regex (most semgrep
AST rules) are counted rather than silently ignored. `load_ruleset`
prints a one-line summary; pass `verbose=True` (CLI: `--verbose-rules`)
for a per-rule explanation.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import re
import sys
import tempfile
import tomllib
import warnings
from dataclasses import dataclass, field
from pathlib import Path

# Complex upstream regexes sometimes trigger noisy FutureWarnings about
# nested sets; they still compile correctly.
warnings.filterwarnings("ignore", category=FutureWarning)

try:
    import yaml  # PyYAML — required for semgrep/nuclei/custom rule files.
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "PyYAML is required to parse semgrep/nuclei rule files. "
        "Install it with: pip install pyyaml"
    ) from exc

from core.paths import glob_to_regex

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

_RULE_FILE_SUFFIXES = (".toml", ".yaml", ".yml", ".conf")
_CACHE_VERSION = 8
_CACHE_ENV = "COMMIT_GUARD_CACHE_DIR"


@dataclass(frozen=True)
class Rule:
    """A normalized, source-agnostic security rule."""
    rule_id: str
    description: str
    severity: str
    pattern: re.Pattern[str]
    source: str
    languages: tuple[str, ...] = field(default_factory=tuple)
    path_regexes: tuple[re.Pattern[str], ...] = field(default_factory=tuple)
    secret_group: int = 0
    entropy: float | None = None
    keywords: tuple[str, ...] = field(default_factory=tuple)
    allowlist_regexes: tuple[re.Pattern[str], ...] = field(default_factory=tuple)
    allowlist_path_regexes: tuple[re.Pattern[str], ...] = field(default_factory=tuple)
    tags: tuple[str, ...] = field(default_factory=tuple)
    cwe: str | None = None
    is_secret: bool = False
    context_regexes: tuple[re.Pattern[str], ...] = field(default_factory=tuple)
    context_before: int = 0
    context_after: int = 0
    fix_pattern: re.Pattern[str] | None = None
    fix_replacement: str | None = None


@dataclass(frozen=True)
class SkippedRule:
    """A rule entry that failed to load, kept for diagnostics."""
    rule_id: str
    source: str
    reason: str


@dataclass(frozen=True)
class RuleSet:
    """All rules plus repo-wide allowlists declared by the rule packs."""
    rules: tuple[Rule, ...]
    skipped: tuple[SkippedRule, ...] = ()
    path_allowlist: tuple[re.Pattern[str], ...] = ()
    line_allowlist: tuple[re.Pattern[str], ...] = ()


class RuleLoadError(RuntimeError):
    """Raised when a rule file is missing, malformed, or has no usable rules."""


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

_SEMGREP_SEVERITY_MAP = {
    "error": "high",
    "warning": "medium",
    "info": "info",
}

_SEMGREP_LANG_TO_EXT = {
    "python": (".py",),
    "javascript": (".js", ".jsx", ".mjs", ".cjs"),
    "js": (".js", ".jsx", ".mjs", ".cjs"),
    "typescript": (".ts", ".tsx", ".mts", ".cts"),
    "ts": (".ts", ".tsx"),
    "go": (".go",),
    "java": (".java",),
    "c": (".c", ".h"),
    "cpp": (".cpp", ".cc", ".cxx", ".hpp", ".hxx"),
    "c++": (".cpp", ".cc", ".cxx", ".hpp", ".hxx"),
    "csharp": (".cs",),
    "cs": (".cs",),
    "ruby": (".rb",),
    "php": (".php", ".phtml"),
    "rust": (".rs",),
    "kotlin": (".kt", ".kts"),
    "scala": (".scala",),
    "swift": (".swift",),
    "solidity": (".sol",),
    "terraform": (".tf", ".tfvars"),
    "dockerfile": ("dockerfile",),
    "docker": ("dockerfile",),
    "yaml": (".yaml", ".yml"),
    "json": (".json",),
    "bash": (".sh", ".bash", ".zsh"),
    "shell": (".sh", ".bash", ".zsh"),
    "sh": (".sh",),
    "elixir": (".ex", ".exs"),
    "html": (".html", ".htm"),
    "vue": (".vue",),
    "generic": (),
}


def _normalize_severity(raw: object) -> str:
    if raw is None:
        return "medium"
    text = str(raw).strip().lower()
    if text in SEVERITY_ORDER:
        return text
    if text in _SEMGREP_SEVERITY_MAP:
        return _SEMGREP_SEVERITY_MAP[text]
    return "medium"


_GLOBAL_FLAG_RE = re.compile(r"\(\?([imsx]+)\)")


def _normalize_inline_flags(pattern: str) -> str:
    """
    Python requires global flags at the very start of a pattern, while
    gitleaks/semgrep packs frequently write `foo(?i)bar`.  Hoist those flags
    to the front so the rule compiles instead of being silently dropped.
    Scoped groups such as `(?i:...)` are left untouched.
    """
    flags: set[str] = set()

    def _collect(match: re.Match[str]) -> str:
        flags.update(match.group(1))
        return ""

    cleaned = _GLOBAL_FLAG_RE.sub(_collect, pattern)
    if not flags:
        return pattern
    prefix = "(?" + "".join(sorted(flags)) + ")"
    if cleaned.startswith(prefix):
        return cleaned
    return prefix + cleaned


def _safe_compile(
    pattern: str,
    rule_id: str,
    source: str,
    skipped: list[SkippedRule],
    *,
    label: str = "regex",
) -> re.Pattern[str] | None:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FutureWarning)
            return re.compile(_normalize_inline_flags(pattern))
    except re.error as exc:
        skipped.append(
            SkippedRule(
                rule_id=rule_id,
                source=source,
                reason=f"unsupported/invalid {label} ({exc})",
            )
        )
        return None


def _recompile(pattern: str) -> re.Pattern[str]:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", FutureWarning)
        return re.compile(pattern)


def _compile_many(
    patterns: object,
    rule_id: str,
    source: str,
    skipped: list[SkippedRule],
    *,
    label: str = "regex",
) -> tuple[re.Pattern[str], ...]:
    if patterns is None:
        return ()
    if isinstance(patterns, str):
        patterns = [patterns]
    if not isinstance(patterns, (list, tuple)):
        return ()
    compiled: list[re.Pattern[str]] = []
    for pattern in patterns:
        if not isinstance(pattern, str):
            continue
        item = _safe_compile(pattern, rule_id, source, skipped, label=label)
        if item is not None:
            compiled.append(item)
    return tuple(compiled)


def _first_string(value: object) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        for item in value:
            if isinstance(item, str):
                return item
    return None


# --------------------------------------------------------------------------
# gitleaks.toml
# --------------------------------------------------------------------------

def _allowlist_entries(container: object) -> list[dict]:
    if container is None:
        return []
    if isinstance(container, dict):
        return [container]
    if isinstance(container, list):
        return [entry for entry in container if isinstance(entry, dict)]
    return []


def _parse_allowlists(
    container: object,
    rule_id: str,
    source: str,
    skipped: list[SkippedRule],
) -> tuple[tuple[re.Pattern[str], ...], tuple[re.Pattern[str], ...]]:
    """Returns (path_regexes, match_regexes) for gitleaks-style allowlists."""
    paths: list[re.Pattern[str]] = []
    regexes: list[re.Pattern[str]] = []
    for entry in _allowlist_entries(container):
        paths.extend(
            _compile_many(entry.get("paths"), rule_id, source, skipped, label="allowlist path")
        )
        regexes.extend(
            _compile_many(entry.get("regexes"), rule_id, source, skipped, label="allowlist regex")
        )
    return tuple(paths), tuple(regexes)


def _load_gitleaks_toml(
    path: Path,
    skipped: list[SkippedRule],
) -> tuple[list[Rule], tuple[re.Pattern[str], ...], tuple[re.Pattern[str], ...]]:
    if not path.is_file():
        return [], (), ()

    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except (tomllib.TOMLDecodeError, OSError) as exc:
        skipped.append(SkippedRule(path.stem, "gitleaks", f"could not parse TOML ({exc})"))
        return [], (), ()

    global_paths: tuple[re.Pattern[str], ...] = ()
    global_regexes: tuple[re.Pattern[str], ...] = ()
    for block in _allowlist_entries(data.get("allowlist")) + _allowlist_entries(data.get("allowlists")):
        p, r = _parse_allowlists(block, "gitleaks-global-allowlist", "gitleaks", skipped)
        global_paths += p
        global_regexes += r

    rules: list[Rule] = []
    for entry in data.get("rules", []):
        if not isinstance(entry, dict):
            continue
        rule_id = str(entry.get("id", "gitleaks-unknown"))
        regex_str = entry.get("regex")
        if not isinstance(regex_str, str) or not regex_str:
            skipped.append(SkippedRule(rule_id, "gitleaks", "no 'regex' field present"))
            continue
        compiled = _safe_compile(regex_str, rule_id, "gitleaks", skipped)
        if compiled is None:
            continue

        path_regexes: tuple[re.Pattern[str], ...] = ()
        rule_path = entry.get("path")
        if isinstance(rule_path, str) and rule_path:
            built = _safe_compile(rule_path, rule_id, "gitleaks", skipped, label="path regex")
            path_regexes = (built,) if built else ()

        allow_paths, rule_allowlist_regexes = _parse_allowlists(
            entry.get("allowlist", entry.get("allowlists")),
            rule_id,
            "gitleaks",
            skipped,
        )

        keywords_raw = entry.get("keywords", [])
        keywords = tuple(
            str(k).lower() for k in keywords_raw if isinstance(k, (str, int, float))
        ) if isinstance(keywords_raw, list) else ()

        tags_raw = entry.get("tags", [])
        tags = tuple(str(t) for t in tags_raw) if isinstance(tags_raw, list) else ()

        secret_group = entry.get("secretGroup", 0)
        if not isinstance(secret_group, int) or secret_group < 0:
            secret_group = 0

        entropy = entry.get("entropy")
        if not isinstance(entropy, (int, float)):
            entropy = None

        rules.append(
            Rule(
                rule_id=rule_id,
                description=str(entry.get("description", "Potential hardcoded secret.")),
                severity=_normalize_severity(entry.get("severity", "high")),
                pattern=compiled,
                source="gitleaks",
                path_regexes=path_regexes,
                secret_group=secret_group,
                entropy=float(entropy) if entropy is not None else None,
                keywords=keywords,
                allowlist_regexes=rule_allowlist_regexes,
                allowlist_path_regexes=allow_paths,
                tags=tags,
                cwe=_first_string(entry.get("cwe")),
                is_secret=True,
            )
        )
    return rules, global_paths, global_regexes


# --------------------------------------------------------------------------
# semgrep_rules/*.yaml
# --------------------------------------------------------------------------

def _extract_semgrep_regex(entry: dict) -> str | None:
    """
    Returns a Python-runnable regex for a semgrep rule, or None.

    Only regex-backed semgrep rules are usable without the semgrep engine.
    `pattern-either` is supported when *every* branch is a regex (OR is
    straightforward); mixed AST/regex branches are skipped rather than
    approximated, because a silently-wrong matcher is worse than none.
    """
    direct = entry.get("pattern-regex")
    if isinstance(direct, str) and direct:
        return direct

    either = entry.get("pattern-either")
    if isinstance(either, list):
        parts: list[str] = []
        for branch in either:
            if not isinstance(branch, dict):
                return None
            part = _extract_semgrep_regex(branch)
            if not part:
                return None
            parts.append(f"(?:{part})")
        if parts:
            return "|".join(parts)
    return None


def _semgrep_reason(entry: dict) -> str:
    if entry.get("patterns") or entry.get("pattern-either") or entry.get("pattern"):
        return "AST/composite pattern (no top-level 'pattern-regex') — needs the semgrep engine"
    return "no usable regex pattern"


def _load_semgrep_yaml_file(path: Path, skipped: list[SkippedRule]) -> list[Rule]:
    if not path.is_file():
        return []

    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
    except (yaml.YAMLError, OSError) as exc:
        skipped.append(SkippedRule(path.stem, f"semgrep:{path.stem}", f"could not parse YAML ({exc})"))
        return []

    rules: list[Rule] = []
    source = f"semgrep:{path.stem}"
    for entry in data.get("rules", []) if isinstance(data, dict) else []:
        if not isinstance(entry, dict):
            continue
        rule_id = str(entry.get("id", f"semgrep-{path.stem}-unknown"))
        regex_str = _extract_semgrep_regex(entry)
        if not regex_str:
            skipped.append(SkippedRule(rule_id, source, _semgrep_reason(entry)))
            continue

        compiled = _safe_compile(regex_str, rule_id, source, skipped)
        if compiled is None:
            continue

        raw_languages = entry.get("languages", [])
        exts: list[str] = []
        if isinstance(raw_languages, list):
            for lang in raw_languages:
                exts.extend(_SEMGREP_LANG_TO_EXT.get(str(lang).lower(), ()))

        metadata = entry.get("metadata", {}) or {}
        if not isinstance(metadata, dict):
            metadata = {}
        tags = tuple(str(t) for t in metadata.get("technology", []) if isinstance(t, str))
        rules.append(
            Rule(
                rule_id=rule_id,
                description=str(entry.get("message", "Semgrep pattern match.")),
                severity=_normalize_severity(
                    entry.get("severity", metadata.get("severity", "medium"))
                ),
                pattern=compiled,
                source=source,
                languages=tuple(exts),
                tags=tags,
                cwe=_first_string(metadata.get("cwe")),
            )
        )
    return rules


def _load_semgrep_rules(semgrep_dir: Path, skipped: list[SkippedRule]) -> list[Rule]:
    if not semgrep_dir.is_dir():
        return []
    rules: list[Rule] = []
    for yaml_path in sorted(semgrep_dir.glob("*.yaml")) + sorted(semgrep_dir.glob("*.yml")):
        rules.extend(_load_semgrep_yaml_file(yaml_path, skipped))
    return rules


# --------------------------------------------------------------------------
# custom_rules.yaml / custom/*.yaml
# --------------------------------------------------------------------------

def _load_custom_yaml_file(path: Path, skipped: list[SkippedRule]) -> list[Rule]:
    if not path.is_file():
        return []

    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
    except (yaml.YAMLError, OSError) as exc:
        skipped.append(SkippedRule(path.stem, "custom", f"could not parse YAML ({exc})"))
        return []

    rules: list[Rule] = []
    entries = data.get("rules", []) if isinstance(data, dict) else []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        rule_id = str(entry.get("id", f"custom-{path.stem}-unknown"))
        regex_str = entry.get("regex", entry.get("pattern"))
        if not isinstance(regex_str, str) or not regex_str:
            skipped.append(SkippedRule(rule_id, "custom", "no 'regex'/'pattern' field present"))
            continue

        compiled = _safe_compile(regex_str, rule_id, "custom", skipped)
        if compiled is None:
            continue

        raw_languages = entry.get("languages", [])
        exts: list[str] = []
        if isinstance(raw_languages, list):
            for lang in raw_languages:
                exts.extend(_SEMGREP_LANG_TO_EXT.get(str(lang).lower(), ()))
        elif isinstance(raw_languages, str):
            exts.extend(_SEMGREP_LANG_TO_EXT.get(raw_languages.lower(), ()))

        path_regexes: list[re.Pattern[str]] = []
        raw_paths = entry.get("paths", entry.get("path", []))
        if isinstance(raw_paths, str):
            raw_paths = [raw_paths]
        if isinstance(raw_paths, list):
            for glob in raw_paths:
                if isinstance(glob, str) and glob.strip():
                    path_regexes.append(glob_to_regex(glob))

        context = entry.get("context", {})
        if not isinstance(context, dict):
            context = {}
        raw_context_regex = entry.get("context_regex", context.get("regex"))
        context_regexes = _compile_many(
            raw_context_regex,
            rule_id,
            "custom",
            skipped,
            label="context regex",
        )
        context_before = entry.get("context_before", context.get("before", 2))
        context_after = entry.get("context_after", context.get("after", 0))
        if not isinstance(context_before, int) or context_before < 0:
            context_before = 0
        if not isinstance(context_after, int) or context_after < 0:
            context_after = 0
        context_before = min(context_before, 50)
        context_after = min(context_after, 50)

        raw_fix_pattern = entry.get("fix_pattern")
        fix_pattern = (
            _safe_compile(
                raw_fix_pattern,
                rule_id,
                "custom",
                skipped,
                label="fix pattern",
            )
            if isinstance(raw_fix_pattern, str) and raw_fix_pattern
            else None
        )
        raw_fix_replacement = entry.get("fix_replacement")
        fix_replacement = (
            raw_fix_replacement if isinstance(raw_fix_replacement, str) else None
        )

        keywords_raw = entry.get("keywords", [])
        keywords = (
            tuple(str(k).lower() for k in keywords_raw)
            if isinstance(keywords_raw, list)
            else ()
        )
        tags_raw = entry.get("tags", [])
        tags = tuple(str(t) for t in tags_raw) if isinstance(tags_raw, list) else ()

        raw_severity = entry.get("severity", "medium")
        severity = str(raw_severity).strip().lower()
        if severity not in SEVERITY_ORDER:
            skipped.append(
                SkippedRule(
                    rule_id,
                    "custom",
                    f"invalid severity '{raw_severity}' "
                    f"(expected one of: {', '.join(SEVERITY_ORDER)})",
                )
            )
            continue

        entropy = entry.get("entropy")
        if not isinstance(entropy, (int, float)):
            entropy = None
        secret_group = entry.get("secret_group", entry.get("secretGroup", 0))
        if not isinstance(secret_group, int) or secret_group < 0:
            secret_group = 0

        rules.append(
            Rule(
                rule_id=rule_id,
                description=str(entry.get("description", entry.get("message", "Commit Guard rule match."))),
                severity=severity,
                pattern=compiled,
                source="custom",
                languages=tuple(exts),
                path_regexes=tuple(path_regexes),
                secret_group=secret_group,
                entropy=float(entropy) if entropy is not None else None,
                keywords=keywords,
                allowlist_regexes=_compile_many(
                    entry.get("allowlist_regexes", entry.get("allowlist")),
                    rule_id,
                    "custom",
                    skipped,
                    label="allowlist regex",
                ),
                tags=tags,
                cwe=_first_string(entry.get("cwe")),
                is_secret=bool(entry.get("secret", "secret" in tags)),
                context_regexes=context_regexes,
                context_before=context_before,
                context_after=context_after,
                fix_pattern=fix_pattern,
                fix_replacement=fix_replacement,
            )
        )
    return rules


def _load_custom_rules(rules_dir: Path, skipped: list[SkippedRule]) -> list[Rule]:
    rules: list[Rule] = []
    rules.extend(_load_custom_yaml_file(rules_dir / "custom_rules.yaml", skipped))
    for dirname in ("custom", "ai_security", "iac"):
        pack_dir = rules_dir / dirname
        if not pack_dir.is_dir():
            continue
        paths = sorted(pack_dir.rglob("*.yaml")) + sorted(pack_dir.rglob("*.yml"))
        for path in paths:
            rules.extend(_load_custom_yaml_file(path, skipped))
    return rules


# --------------------------------------------------------------------------
# nuclei_generic_key.yaml
# --------------------------------------------------------------------------

def _load_nuclei_yaml(path: Path, skipped: list[SkippedRule]) -> list[Rule]:
    if not path.is_file():
        return []

    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
    except (yaml.YAMLError, OSError) as exc:
        skipped.append(SkippedRule(path.stem, "nuclei", f"could not parse YAML ({exc})"))
        return []

    if not isinstance(data, dict):
        skipped.append(SkippedRule(path.stem, "nuclei", "template is not a mapping"))
        return []

    rule_id = str(data.get("id", "nuclei-generic-key"))
    info = data.get("info", {}) or {}
    if not isinstance(info, dict):
        info = {}
    severity = _normalize_severity(info.get("severity", "high"))
    description = str(info.get("description", info.get("name", "Generic exposed key/token.")))

    rules: list[Rule] = []
    file_blocks = data.get("file", [])
    if isinstance(file_blocks, dict):
        file_blocks = [file_blocks]
    for file_block in file_blocks if isinstance(file_blocks, list) else []:
        if not isinstance(file_block, dict):
            continue
        for section_name in ("extractors", "matchers"):
            for block in file_block.get(section_name, []) or []:
                if not isinstance(block, dict) or block.get("type") != "regex":
                    continue
                for index, regex_str in enumerate(block.get("regex", []) or []):
                    if not isinstance(regex_str, str):
                        continue
                    sub_id = f"{rule_id}-{index}"
                    compiled = _safe_compile(regex_str, sub_id, "nuclei", skipped)
                    if compiled is None:
                        continue
                    rules.append(
                        Rule(
                            rule_id=sub_id,
                            description=description,
                            severity=severity,
                            pattern=compiled,
                            source="nuclei",
                            secret_group=1,
                            is_secret=True,
                        )
                    )

    if not rules:
        skipped.append(
            SkippedRule(rule_id, "nuclei", "no regex file matchers/extractors found")
        )
    return rules


# --------------------------------------------------------------------------
# owasp_sqli.conf (ModSecurity CRS-style)
# --------------------------------------------------------------------------

_MODSEC_SEVERITY_MAP = {
    "critical": "medium",
    "2": "medium",
    "error": "medium",
    "3": "medium",
    "warning": "low",
    "4": "low",
    "notice": "low",
    "5": "low",
}


def _join_modsec_lines(text: str) -> list[str]:
    """Joins backslash-continued SecRule directives into single lines."""
    logical: list[str] = []
    buffer = ""
    for line in text.splitlines():
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            buffer += stripped[:-1].rstrip() + " "
            continue
        if buffer:
            buffer += stripped
            logical.append(buffer)
            buffer = ""
        else:
            logical.append(stripped)
    if buffer:
        logical.append(buffer)
    return logical


_MODSEC_ID_RE = re.compile(r"\bid:(\d+)")
_MODSEC_SEVERITY_RE = re.compile(r"severity:'?([\w]+)'?", re.IGNORECASE)


def _extract_modsec_rx(line: str) -> str | None:
    marker = '"@rx '
    start = line.find(marker)
    if start == -1:
        return None
    index = start + len(marker)
    pattern_chars: list[str] = []
    while index < len(line):
        char = line[index]
        if char == "\\" and index + 1 < len(line):
            pattern_chars.append(char)
            pattern_chars.append(line[index + 1])
            index += 2
            continue
        if char == '"':
            break
        pattern_chars.append(char)
        index += 1
    pattern = "".join(pattern_chars).strip()
    return pattern or None


def _load_owasp_conf(path: Path, skipped: list[SkippedRule]) -> list[Rule]:
    if not path.is_file():
        return []

    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        skipped.append(SkippedRule(path.stem, "owasp_sqli", f"could not read file ({exc})"))
        return []

    rules: list[Rule] = []
    for line_no, line in enumerate(_join_modsec_lines(text), start=1):
        if not line.lstrip().startswith("SecRule"):
            continue
        pattern_str = _extract_modsec_rx(line)
        if not pattern_str:
            continue

        id_match = _MODSEC_ID_RE.search(line)
        rule_id = f"owasp-sqli-{id_match.group(1)}" if id_match else f"owasp-sqli-L{line_no}"

        severity = "low"  # HTTP request signatures are advisory when applied to source.
        sev_match = _MODSEC_SEVERITY_RE.search(line)
        if sev_match:
            severity = _MODSEC_SEVERITY_MAP.get(sev_match.group(1).lower(), "low")

        compiled = _safe_compile(pattern_str, rule_id, "owasp_sqli", skipped)
        if compiled is None:
            continue

        rules.append(
            Rule(
                rule_id=rule_id,
                description="SQL-injection signature from the OWASP Core Rule Set (advisory).",
                severity=severity,
                pattern=compiled,
                source="owasp_sqli",
                tags=("sqli", "owasp-crs"),
                cwe="CWE-89",
            )
        )
    return rules


# --------------------------------------------------------------------------
# Cache
# --------------------------------------------------------------------------

def _cache_directory() -> Path:
    override = os.environ.get(_CACHE_ENV)
    if override:
        return Path(override).expanduser()
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("TEMP") or "."
    else:
        base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "commit-guard"


def _rule_signature(rules_dir: Path) -> str:
    digest = hashlib.sha256(str(rules_dir.resolve()).encode("utf-8"))
    files = [
        path
        for path in sorted(rules_dir.rglob("*"))
        if path.is_file() and path.suffix.lower() in _RULE_FILE_SUFFIXES
    ]
    for path in files:
        try:
            stat = path.stat()
        except OSError:
            continue
        relative = path.relative_to(rules_dir).as_posix()
        digest.update(f"{relative}:{stat.st_size}:{stat.st_mtime_ns}".encode())
    digest.update(f"v{_CACHE_VERSION}".encode("ascii"))
    return digest.hexdigest()


def _serialize_ruleset(ruleset: RuleSet) -> dict:
    return {
        "version": _CACHE_VERSION,
        "rules": [
            {
                "rule_id": rule.rule_id,
                "description": rule.description,
                "severity": rule.severity,
                "pattern": rule.pattern.pattern,
                "source": rule.source,
                "languages": list(rule.languages),
                "path_regexes": [p.pattern for p in rule.path_regexes],
                "secret_group": rule.secret_group,
                "entropy": rule.entropy,
                "keywords": list(rule.keywords),
                "allowlist_regexes": [p.pattern for p in rule.allowlist_regexes],
                "allowlist_path_regexes": [p.pattern for p in rule.allowlist_path_regexes],
                "tags": list(rule.tags),
                "cwe": rule.cwe,
                "is_secret": rule.is_secret,
                "context_regexes": [p.pattern for p in rule.context_regexes],
                "context_before": rule.context_before,
                "context_after": rule.context_after,
                "fix_pattern": rule.fix_pattern.pattern if rule.fix_pattern else None,
                "fix_replacement": rule.fix_replacement,
            }
            for rule in ruleset.rules
        ],
        "skipped": [
            {"rule_id": s.rule_id, "source": s.source, "reason": s.reason}
            for s in ruleset.skipped
        ],
        "path_allowlist": [p.pattern for p in ruleset.path_allowlist],
        "line_allowlist": [p.pattern for p in ruleset.line_allowlist],
    }


def _deserialize_ruleset(payload: dict) -> RuleSet:
    if payload.get("version") != _CACHE_VERSION:
        raise ValueError("cache version mismatch")
    rules = tuple(
        Rule(
            rule_id=entry["rule_id"],
            description=entry["description"],
            severity=entry["severity"],
            pattern=_recompile(entry["pattern"]),
            source=entry["source"],
            languages=tuple(entry.get("languages", [])),
            path_regexes=tuple(_recompile(p) for p in entry.get("path_regexes", [])),
            secret_group=int(entry.get("secret_group", 0)),
            entropy=entry.get("entropy"),
            keywords=tuple(entry.get("keywords", [])),
            allowlist_regexes=tuple(_recompile(p) for p in entry.get("allowlist_regexes", [])),
            allowlist_path_regexes=tuple(
                _recompile(p) for p in entry.get("allowlist_path_regexes", [])
            ),
            tags=tuple(entry.get("tags", [])),
            cwe=entry.get("cwe"),
            is_secret=bool(entry.get("is_secret", False)),
            context_regexes=tuple(
                _recompile(p) for p in entry.get("context_regexes", [])
            ),
            context_before=int(entry.get("context_before", 0)),
            context_after=int(entry.get("context_after", 0)),
            fix_pattern=(
                _recompile(entry["fix_pattern"]) if entry.get("fix_pattern") else None
            ),
            fix_replacement=entry.get("fix_replacement"),
        )
        for entry in payload["rules"]
    )
    skipped = tuple(
        SkippedRule(item["rule_id"], item["source"], item["reason"])
        for item in payload.get("skipped", [])
    )
    return RuleSet(
        rules=rules,
        skipped=skipped,
        path_allowlist=tuple(_recompile(p) for p in payload.get("path_allowlist", [])),
        line_allowlist=tuple(_recompile(p) for p in payload.get("line_allowlist", [])),
    )


def _read_cache(cache_path: Path) -> RuleSet | None:
    try:
        payload = json.loads(cache_path.read_text(encoding="utf-8"))
        return _deserialize_ruleset(payload)
    except (OSError, ValueError, KeyError, TypeError, re.error):
        return None


def _write_cache(cache_path: Path, ruleset: RuleSet) -> None:
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(dir=str(cache_path.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(_serialize_ruleset(ruleset), handle)
            os.replace(temp_name, cache_path)
        except BaseException:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
            raise
    except OSError:
        pass  # A read-only home directory must not break scanning.


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def _build_ruleset(rules_dir: Path) -> RuleSet:
    skipped: list[SkippedRule] = []

    gitleaks_rules, global_paths, global_regexes = _load_gitleaks_toml(
        rules_dir / "gitleaks.toml", skipped
    )
    all_rules: list[Rule] = list(gitleaks_rules)
    all_rules.extend(_load_semgrep_rules(rules_dir / "semgrep_rules", skipped))
    all_rules.extend(_load_custom_rules(rules_dir, skipped))
    all_rules.extend(_load_nuclei_yaml(rules_dir / "nuclei_generic_key.yaml", skipped))
    # The upstream OWASP CRS is designed for HTTP request values, not source
    # code; running it on every line produces severe false positives. It can
    # be enabled explicitly by adding an `owasp_sqli` source in a custom rule
    # pack. Curated SQLi source patterns ship in custom_rules.yaml instead.

    if not all_rules:
        raise RuleLoadError(
            f"No usable rules were loaded from '{rules_dir}'. "
            "Check that gitleaks.toml, semgrep_rules/*.yaml, custom_rules.yaml, "
            "nuclei_generic_key.yaml, and custom_rules.yaml exist and are well-formed."
        )

    return RuleSet(
        rules=tuple(all_rules),
        skipped=tuple(skipped),
        path_allowlist=tuple(global_paths),
        line_allowlist=tuple(global_regexes),
    )


def load_ruleset(
    rules_dir: Path,
    *,
    warn: bool = True,
    verbose: bool = False,
    use_cache: bool = True,
) -> RuleSet:
    """Loads every rule source, using a disk cache when possible."""
    rules_dir = Path(rules_dir)
    if not rules_dir.is_dir():
        raise RuleLoadError(f"Rules directory not found: '{rules_dir}'")

    cache_path: Path | None = None
    if use_cache:
        try:
            signature = _rule_signature(rules_dir)
            cache_path = _cache_directory() / f"{signature}.json"
            cached = _read_cache(cache_path)
            if cached is not None:
                _report_skipped(cached, warn=warn, verbose=verbose)
                return cached
        except OSError:
            cache_path = None

    ruleset = _build_ruleset(rules_dir)

    if cache_path is not None:
        _write_cache(cache_path, ruleset)

    _report_skipped(ruleset, warn=warn, verbose=verbose)
    return ruleset


def _is_expected_skip(entry: SkippedRule) -> bool:
    """
    AST-only/multi-pattern semgrep rules cannot run without the semgrep
    engine. A malformed rule file or an invalid regex, however, is a real
    coverage bug and should be surfaced.
    """
    if entry.source.startswith("semgrep"):
        return not (
            "unsupported/invalid regex" in entry.reason
            or "could not parse" in entry.reason
        )
    return "AST" in entry.reason or "no top-level 'pattern-regex'" in entry.reason


def _report_skipped(ruleset: RuleSet, *, warn: bool, verbose: bool) -> None:
    if not ruleset.skipped or not warn:
        return
    if verbose:
        print(
            f"[commit-guard] WARNING: {len(ruleset.skipped)} rule entries could "
            "not be loaded and will NOT be scanned for:",
            file=sys.stderr,
        )
        for entry in ruleset.skipped:
            print(f"    - [{entry.source}] {entry.rule_id}: {entry.reason}", file=sys.stderr)
        return

    unexpected = [entry for entry in ruleset.skipped if not _is_expected_skip(entry)]
    if not unexpected:
        return  # AST-only semgrep rules are a documented design limitation.

    skipped_sources = {entry.source for entry in unexpected}
    active_sources = {rule.source for rule in ruleset.rules}
    broken_sources = skipped_sources - active_sources
    # A couple of upstream edge cases are not worth nagging about on every
    # commit; a whole pack failing to load is.
    if len(unexpected) < 10 and not broken_sources:
        return

    counts: dict[str, int] = {}
    for entry in unexpected:
        counts[entry.source] = counts.get(entry.source, 0) + 1
    preview = ", ".join(
        f"{source}={count}"
        for source, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:5]
    )
    print(
        f"[commit-guard] WARNING: {len(unexpected)} rule entr"
        f"{'y' if len(unexpected) == 1 else 'ies'} could not be loaded "
        f"({preview}). Active rules: {len(ruleset.rules)}. "
        "Use --verbose-rules for details.",
        file=sys.stderr,
    )


def load_all_rules_verbose(rules_dir: Path) -> tuple[list[Rule], list[SkippedRule]]:
    """Backward-compatible helper returning (rules, skipped)."""
    ruleset = load_ruleset(rules_dir, warn=False)
    return list(ruleset.rules), list(ruleset.skipped)


def load_all_rules(rules_dir: Path, warn: bool = True) -> list[Rule]:
    """Backward-compatible helper returning the active rule list."""
    return list(load_ruleset(rules_dir, warn=warn).rules)


def rules_for_file(rules: list[Rule] | tuple[Rule, ...], file_path: str) -> list[Rule]:
    """Filters rules down to those applicable to a given file path."""
    suffix = Path(file_path).suffix.lower()
    name = Path(file_path).name.lower()

    is_dockerfile = (
        name == "dockerfile"
        or name.startswith("dockerfile.")
        or name.endswith(".dockerfile")
    )
    applicable: list[Rule] = []
    for rule in rules:
        if (
            not rule.languages
            or suffix in rule.languages
            or ("dockerfile" in rule.languages and is_dockerfile)
        ):
            applicable.append(rule)
    return applicable


def apply_severity_overrides(
    ruleset: RuleSet, overrides: dict[str, str]
) -> RuleSet:
    """Returns a RuleSet with per-rule severity overrides applied."""
    if not overrides:
        return ruleset

    updated = []
    for rule in ruleset.rules:
        replacement = overrides.get(rule.rule_id)
        if replacement:
            updated.append(dataclasses.replace(rule, severity=replacement))
        else:
            updated.append(rule)
    return RuleSet(
        rules=tuple(updated),
        skipped=ruleset.skipped,
        path_allowlist=ruleset.path_allowlist,
        line_allowlist=ruleset.line_allowlist,
    )
