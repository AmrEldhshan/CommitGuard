"""Rule validation, corpus checks, and `explain` rendering."""

from __future__ import annotations

from pathlib import Path

import yaml

from core.ast_taint import TAINT_RULES
from core.git_diff import DiffLine
from core.rule_loader import SEVERITY_ORDER, Rule, RuleLoadError, RuleSet, load_ruleset
from core.scanner import scan_diff


def _schema_issues(ruleset: RuleSet) -> tuple[list[str], list[str]]:
    issues: list[str] = []
    warnings: list[str] = []
    seen: dict[str, Rule] = {}
    for rule in ruleset.rules:
        previous = seen.get(rule.rule_id)
        if previous is not None:
            message = (
                f"duplicate rule id: {rule.rule_id} "
                f"({previous.source} and {rule.source})"
            )
            if previous.source == rule.source == "custom":
                issues.append(message)
            else:
                warnings.append(message)
        else:
            seen[rule.rule_id] = rule
        if not rule.description.strip():
            issues.append(f"{rule.rule_id}: empty description")
        if rule.severity not in SEVERITY_ORDER:
            issues.append(f"{rule.rule_id}: invalid severity '{rule.severity}'")
        if not rule.source.strip():
            issues.append(f"{rule.rule_id}: missing source")
        if rule.context_regexes and rule.context_before + rule.context_after == 0:
            issues.append(f"{rule.rule_id}: context regex has a zero-width window")
        if (rule.fix_pattern is None) != (rule.fix_replacement is None):
            issues.append(
                f"{rule.rule_id}: fix_pattern and fix_replacement must be provided together"
            )
    return issues, warnings


def _load_corpus(path: Path) -> list[dict]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise RuleLoadError(f"Could not read rule corpus '{path}': {exc}") from exc
    samples = data.get("samples", []) if isinstance(data, dict) else []
    if not isinstance(samples, list):
        raise RuleLoadError(f"'{path}' must contain a 'samples' list.")
    return [sample for sample in samples if isinstance(sample, dict)]


def _sample_match(rule: Rule, code: str, path: str, context: list[str]) -> bool:
    line_number = len(context) + 1
    diff_line = DiffLine(path, line_number, code)
    file_lines = {path: [*context, code]} if context else None
    findings = scan_diff(
        [diff_line],
        [rule],
        filter_placeholders=False,
        file_lines=file_lines,
    )
    return bool(findings)


def check_rules(
    rules_dir: Path,
    corpus_path: Path | None = None,
    *,
    use_cache: bool = True,
) -> int:
    """Runs schema checks plus positive/negative samples. Returns exit code."""
    try:
        ruleset = load_ruleset(rules_dir, warn=False, use_cache=use_cache)
    except RuleLoadError as exc:
        print(f"[commit-guard] ERROR: {exc}")
        return 2

    issues, warnings = _schema_issues(ruleset)
    for skipped in ruleset.skipped:
        if skipped.source == "custom":
            issues.append(
                f"custom rule '{skipped.rule_id}' could not be loaded: {skipped.reason}"
            )
    corpus = corpus_path or (rules_dir / "corpus.yaml")
    samples: list[dict] = []
    if corpus.is_file():
        try:
            samples = _load_corpus(corpus)
        except RuleLoadError as exc:
            print(f"[commit-guard] ERROR: {exc}")
            return 2
    else:
        print(f"[commit-guard] WARNING: no corpus at {corpus}; schema checks only.")

    by_id = {rule.rule_id: rule for rule in ruleset.rules}
    checked = 0
    for sample in samples:
        rule_id = str(sample.get("rule_id", ""))
        rule = by_id.get(rule_id)
        if rule is None:
            issues.append(f"corpus: unknown rule id '{rule_id}'")
            continue
        path = str(sample.get("path", "sample.py"))
        context = sample.get("context", [])
        if not isinstance(context, list):
            context = []
        context = [str(item) for item in context]
        negative_context = sample.get("negative_context", [])
        if not isinstance(negative_context, list):
            negative_context = []
        negative_context = [str(item) for item in negative_context]
        positive = sample.get("positive")
        negative = sample.get("negative")
        checked += 1
        if isinstance(positive, str) and not _sample_match(rule, positive, path, context):
            issues.append(f"{rule_id}: positive sample did not match: {positive!r}")
        if isinstance(negative, str) and _sample_match(
            rule, negative, path, negative_context
        ):
            issues.append(f"{rule_id}: negative sample matched: {negative!r}")

    print(
        f"[commit-guard] Rules: {len(ruleset.rules) + len(TAINT_RULES)} active, "
        f"{len(ruleset.skipped)} skipped; corpus samples: {checked}; "
        f"schema/corpus issues: {len(issues)}"
    )
    for warning in warnings:
        print(f"  warning: {warning}")
    for issue in issues:
        print(f"  - {issue}")
    return 1 if issues else 0


def render_rule(rule: Rule) -> str:
    lines = [
        f"Rule:        {rule.rule_id}",
        f"Description: {rule.description}",
        f"Severity:    {rule.severity}",
        f"Source:      {rule.source}",
        f"Regex:       {rule.pattern.pattern}",
    ]
    if rule.languages:
        lines.append(f"Languages:   {', '.join(rule.languages)}")
    if rule.path_regexes:
        lines.append("Paths:       " + ", ".join(p.pattern for p in rule.path_regexes))
    if rule.keywords:
        lines.append(f"Keywords:    {', '.join(rule.keywords)}")
    if rule.entropy is not None:
        lines.append(f"Entropy:     >= {rule.entropy}")
    if rule.context_regexes:
        lines.append(
            "Context:     "
            f"{rule.context_before} before / {rule.context_after} after, matching "
            + ", ".join(p.pattern for p in rule.context_regexes)
        )
    if rule.allowlist_regexes:
        lines.append(
            "Allowlist:   " + ", ".join(p.pattern for p in rule.allowlist_regexes)
        )
    if rule.fix_pattern is not None:
        lines.append(f"Auto-fix:    {rule.fix_pattern.pattern} -> {rule.fix_replacement!r}")
    if rule.tags:
        lines.append(f"Tags:        {', '.join(rule.tags)}")
    if rule.cwe:
        lines.append(f"CWE:         {rule.cwe}")
    return "\n".join(lines)


def explain_rule(rule_id: str, rules_dir: Path, *, use_cache: bool = True) -> int:
    try:
        ruleset = load_ruleset(rules_dir, warn=False, use_cache=use_cache)
    except RuleLoadError as exc:
        print(f"[commit-guard] ERROR: {exc}")
        return 2
    matches = [rule for rule in ruleset.rules if rule.rule_id == rule_id]
    if not matches:
        taint_rule = TAINT_RULES.get(rule_id)
        if taint_rule:
            print(f"Rule:        {rule_id}")
            print("Source:      python_ast")
            print(f"Severity:    {taint_rule['severity']}")
            print(f"Description: {taint_rule['description']}")
            print(f"Tags:        {', '.join(taint_rule['tags'])}")
            print(f"CWE:         {taint_rule['cwe']}")
            print("Analysis:    intraprocedural Python AST taint tracking")
            return 0
        print(f"[commit-guard] No active rule with id '{rule_id}'.")
        return 1
    for index, rule in enumerate(matches):
        if index:
            print()
        print(render_rule(rule))
    return 0
