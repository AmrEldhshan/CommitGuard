# Experimental rules (not loaded by default)

`owasp_sqli.conf` is the upstream OWASP Core Rule Set SQL-injection pack.
Those signatures are designed to inspect **HTTP request values at runtime**,
not source code. Applied line-by-line to a repository, they flag ordinary SQL
strings and even unrelated assignments, which makes them unsuitable for a
blocking pre-commit hook.

They are kept here for reference and experimentation. If you want to load
them, add an explicit loader call in your own rule pack or copy the specific
`@rx` patterns you trust into `../custom_rules.yaml` with a conservative
severity.

The default high-signal SQL-injection checks live in `../custom_rules.yaml`
(`cg-python-sql-fstring`, `cg-python-sql-percent`).

`bandit_exec_rule.py` is the upstream Bandit B102 plugin, kept as reference.
Commit Guard does not execute Python AST plugins; the equivalent regex rules
`cg-python-exec` / `cg-python-eval` live in `../custom_rules.yaml` and run
without a Bandit dependency.
