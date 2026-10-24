# Aegis Plan

**Status:** Draft 2.0 — strategy, architecture, and execution plan
**Working name:** Aegis (CLI: `aegis`)
**Provisional distribution name:** `aegis-sast` (the PyPI names `aegis`, `aegis-cli`, and `aegis-scan` are already taken; verify `aegis-sast` and all trademarks before release)
**Supersedes:** the earlier Aegis draft and the informal CommitGuard roadmap
**Baseline measured:** CommitGuard 2.1.0 working tree at commit `78d2c64`, including uncommitted GUI work, 2026-10-24
**Planning horizon:** 12 months, reviewed every four weeks
**Owner:** project maintainer
**Document rule:** every number in this plan is either (a) measured and labelled as such, or (b) a target with an owner, a test, and a date. If it is neither, it is not a commitment.

---

## Contents

- [0. How this plan is organized](#0-how-this-plan-is-organized)
- [1. Corrections to the previous draft](#1-corrections-to-the-previous-draft)
- [2. Executive summary](#2-executive-summary)
- [3. Naming, licensing, and identity](#3-naming-licensing-and-identity-phase-0-blocking)
- [4. Current baseline](#4-current-baseline-measured-not-estimated)
- [5. Users, jobs, and positioning](#5-users-jobs-and-positioning)
- [6. Strategy and differentiation](#6-strategy-and-differentiation)
- [7. Goals, metrics, and guardrails](#7-goals-metrics-and-guardrails)
- [8. Architecture](#8-architecture)
- [9. Detection strategy](#9-detection-strategy)
- [10. Interoperability and aggregation](#10-interoperability-and-aggregation)
- [11. Policy, triage, and audit](#11-policy-triage-and-audit)
- [12. Developer experience](#12-developer-experience)
- [13. Supply chain, compliance, and trust](#13-supply-chain-compliance-and-trust)
- [14. AI assistant](#14-bring-your-own-ai-assistant-opt-in-non-authoritative)
- [15. Execution plan](#15-execution-plan)
- [16. Release and versioning](#16-release-and-versioning)
- [17. Testing and benchmarks](#17-testing-quality-and-benchmark-protocol)
- [18. Threat model](#18-threat-model-for-aegis-itself)
- [19. Distribution, adoption, and community](#19-distribution-adoption-and-community)
- [20. Risks and mitigations](#20-risks-and-mitigations)
- [21. Decisions and open questions](#21-decisions-and-open-questions)
- [22. First twenty commits](#22-first-twenty-commits)
- [Appendices](#appendix-a--cli-surface-target)

---

## 0. How this plan is organized

This document is written to be executed, not admired. Read it in four layers:

1. **Decisions** — sections 1, 2, 3, 5, 6, and 21. These define what Aegis is, what it refuses to be, and the choices that must be made before code is written.
2. **Evidence** — sections 4 and 17. These establish the current baseline and the measurement system that will keep claims honest.
3. **Architecture and workstreams** — sections 8 through 14. These define the system, the detection strategy, the developer experience, and the trust model.
4. **Execution** — sections 15 through 22 and the appendices. These define sequencing, release criteria, risk controls, adoption, and the next concrete commits.

A plan that cannot be cut is not a plan. Every phase below has a **cut line**: the work that is removed first when time runs out. The cut lines protect the things that make Aegis trustworthy — tests, benchmarks, licensing, and release hygiene — and sacrifice features instead.

---

## 1. Corrections to the previous draft

The previous draft had the right instincts and several expensive mistakes. This version keeps the strategy, fixes the errors, and removes claims that cannot survive scrutiny.

| Previous draft | Problem | Correction in this plan |
|---|---|---|
| Name: Aegis | The repository and user-facing name are now Aegis; keeping two names creates migration debt and brand confusion. | Aegis everywhere. Aegis appears only as a historical note. |
| No license file | A public security tool with no declared license cannot be adopted legally, packaged, or contributed to. This is the highest-priority fix. | Add Apache-2.0, `NOTICE`, SPDX headers, and third-party notices before any public release (Phase 0). |
| “One signed binary” | The current implementation is Python and packaging is not yet decided. Promising a single binary before proving the toolchain is a credibility risk. | A distribution ladder: pip/pipx first, zipapp second, standalone binary third, with signing and checksums at every step. |
| “No server” while also proposing a browser UI | The new local GUI is a server process. The original wording contradicted the product. | Distinguish **hosted/multi-tenant services** (a non-goal) from an **ephemeral loopback developer console** (allowed). |
| PyPI name assumed available | `aegis`, `aegis-cli`, `aegis-scan`, `aegis-security`, and `aegis-sec` are already registered on PyPI. | Use `aegis-sast` provisionally; complete a naming and trademark gate before release. Keep fallbacks. |
| “5–7 months solo for M1–M6” | The estimate assumed no maintenance, no documentation, no legal work, and no benchmark debugging. | Three tiers with explicit capacity assumptions. A credible solo v1.0 is roughly 9–12 months; the full vision is 18–24 months. |
| Rule count as a headline goal | “2,000 active rules” measures inventory, not detection quality. | Replace with measured precision/recall per CWE and language, corpus coverage, and regression gates. |
| Semgrep treated as free infrastructure | The engine and the rule corpus have different licenses and different redistribution constraints. | Make Semgrep/Opengrep optional, never bundled, and gated by a written licensing review. Do not redistribute third-party rules until cleared. |
| “Parity with SonarQube” | No dataset, version, configuration, or metric was named. | Define the benchmark card: dataset, version, labels, command, metric, confidence interval, raw artifact. Claims without a card are prohibited. |
| AI assistant section | It ignored prompt injection, secret leakage, provider terms, non-determinism, and the difference between explanation and detection. | AI is opt-in, local-first, context-minimized, never authoritative, and evaluated like any other feature. |
| No threat model for Aegis itself | A security tool that parses hostile repositories, rules, SARIF, and lockfiles is an attack surface. | Add a full threat model, hostile fixtures, fuzzing, resource limits, and a disclosure process. |
| GUI omitted | The project now has a working local control center, a real differentiator for developer experience. | Make it part of the MVP and the DX story, with a strict local-only security model. |
| No migration plan | Renaming a CLI, config file, hook, action, and install directory without compatibility will break existing users. | A two-release compatibility window, aliases, `aegis migrate`, and a documented deprecation schedule. |
| “Signed reproducible builds” stated as a fact | Reproducibility is an engineering claim that must be demonstrated per artifact. | Stage the claim: checksums, Sigstore signatures, SBOM, then “reproducible” only after independent verification. |

The rest of this document is the corrected plan.

---

## 2. Executive summary

### 2.1 The thesis

The market does not need another rule pack. It needs a **local security control plane**: one policy, one baseline, one triage model, one report, one exit code, and one fast developer loop across every analyzer a team already uses — with no code leaving the machine by default.

Aegis wins by combining four things that are usually sold separately:

1. **A fast, offline-first scanner** for secrets, SAST, dependencies, IaC, containers, and supply chain.
2. **An aggregator** that normalizes SARIF and native output from Semgrep, CodeQL, Trivy, Checkov, gitleaks, Bandit, ruff, ESLint, golangci-lint, and coverage tools.
3. **Policy-as-code** with new-code gating, budgets, ratchets, baselines, triage, ownership, and expiry — all version-controlled.
4. **A fix-first developer experience**: IDE diagnostics, inline PR suggestions, safe autofixes, and a local console, without a hosted service, account, or telemetry.

### 2.2 What Aegis is

- A local, deterministic security gate for changed code.
- A normalizer and policy layer over multiple analyzers.
- A policy-as-code engine for new-code gates, baselines, triage, and audit.
- A developer tool: fast, interruptible, explainable, and fix-oriented.
- A trust artifact: signed releases, checksums, SBOMs, published benchmarks, and honest limitations.

### 2.3 What Aegis is not

- Not a hosted platform, multi-tenant dashboard, or code-quality suite.
- Not a from-scratch reimplementation of Semgrep, CodeQL, or a compiler front end.
- Not a guarantee of complete vulnerability coverage.
- Not a telemetry product.
- Not an AI product that guesses at vulnerabilities without reproducible evidence.
- Not a replacement for human review or a compliance certification.

### 2.4 The five bets

| Bet | Why it wins | How we prove it |
|---|---|---|
| **Local control plane** | Regulated, air-gapped, and privacy-sensitive teams cannot send code to SaaS. | Network-off demo; zero egress by default; air-gap test in CI. |
| **Diff-time speed** | A gate that runs after the PR is a tax; a gate that runs before the commit is a habit. | p50/p95 diff scan budgets on small, medium, and monorepo fixtures. |
| **Fix-first** | Developers adopt tools that remove work, not tools that create tickets. | Fix acceptance rate, time-to-fix, and inline suggestion tests. |
| **Policy-as-code** | One reviewable gate across five tools beats five dashboards. | One policy evaluates five normalized tools with reproducible results. |
| **Trust** | Security buyers punish exaggeration. | Signed releases, SBOMs, benchmark cards, documented limitations. |

### 2.5 The MVP

Aegis 0.9 is done when a developer can install it and run one scan in a fresh repository, getting a correct, actionable result in under two minutes — with no account, no network, and no configuration:

```bash
pipx install aegis-sast
aegis init
aegis scan --staged
```

The MVP includes the engine protocol, the Finding schema, the policy stage, SARIF ingestion, the local GUI, the pre-commit hook, the GitHub Action, and a benchmark harness. It does **not** require Semgrep, a database, an IDE extension, or an AI provider. A demo-grade preview can be ready in about 12 weeks; the full MVP exit criteria below take 4–6 months solo.

### 2.6 Timeline at a glance

| Tier | Duration (one experienced maintainer) | Outcome |
|---|---|---|
| **Phase 0 — Hygiene** | 2 weeks | License, rename, CI matrix, baseline, benchmark skeleton, security policy. |
| **Phase 1 — MVP** | 4–6 months | v0.9: engine protocol, policy, SARIF, GUI, pre-commit, Action, benchmark. |
| **Phase 2 — Credible 1.0** | 9–12 months total | Semgrep optional, taint expansion, LSP, PR fixes, SCA depth, SBOM, signed beta. |
| **Phase 3 — Category tool** | 12–18 months total | IaC/containers, compliance packs, plugins, multi-repo, dashboards, v1.x. |
| **Phase 4 — Ecosystem** | 18–24 months | Interprocedural taint, reachability SCA, AI assistant, signed packs, v2.0. |

With two engineers, compress Phase 2 and Phase 3 by roughly 30–40% (v1.0 in 5–7 months). With three, run detection, platform, and release work in parallel (v1.0 in 3–5 months). Do not compress Phase 0.

### 2.7 What “best” means

Aegis will not be the tool with the most rules. It will be the tool that a developer trusts at 2 a.m. before a release, that an AppSec engineer can audit without a vendor portal, and that a regulated organization can run with the network cable unplugged. That is the standard this plan optimizes for.

---

## 3. Naming, licensing, and identity (Phase 0, blocking)

### 3.1 Naming gate

Aegis is a strong working name: short, pronounceable, and associated with protection. It is also a crowded name in security, with existing products and trademarks using it. Do not publish under it until the gate is complete.

| Check | Result on 2026-10-24 | Action |
|---|---|---|
| PyPI `aegis` | Taken (1.1.1) | Do not use as distribution name. |
| PyPI `aegis-cli` | Taken (2.0.0) | Do not use. |
| PyPI `aegis-scan` | Taken (0.4.1) | Do not use. |
| PyPI `aegis-security` | Taken (1.0.0) | Do not use. |
| PyPI `aegis-sec` | Taken (0.1.3) | Do not use. |
| PyPI `aegis-sast` | Appears available | Provisional distribution name; re-check immediately before publish. |
| npm `aegis`, `aegis-cli`, `aegis-scan` | Taken | Irrelevant for the Python package; relevant for future JS integrations and brand. |
| Trademarks | Not yet searched | Search USPTO, EUIPO, UKIPO, and relevant national registries; obtain counsel before release. |
| Domains / social handles | Not yet checked | Reserve only after trademark clearance; do not spend on branding early. |

**Decision:** product and CLI name **Aegis**; distribution name **`aegis-sast`** provisionally. Keep a ranked fallback list: **Bastion**, **Redoubt**, **Cordon**, **Portcullis**, **Lintel**. Revisit only if the legal check fails.

**Rule:** the CLI command is `aegis`. The Python distribution is `aegis-sast`. The repository may remain `CommitGuard` until the rename gate passes; GitHub redirects handle the eventual repository rename.

### 3.2 License

The repository currently has **no license file and no license metadata**. That blocks adoption, packaging, contributions, and enterprise review. This is the first commit of Phase 0.

**Recommendation:** Apache-2.0 for the core.

Why Apache-2.0:

- Permissive enough for enterprises and commercial CI use.
- Includes an explicit patent grant, which matters for security tooling.
- Compatible with the existing dependency set (PyYAML is MIT).
- Easier to adopt than AGPL for a pre-commit tool that companies embed in their pipelines.
- Does not prevent a paid support or curated-pack business.

Required work:

- Add `LICENSE` (Apache-2.0) and `NOTICE`.
- Add `license = {text = "Apache-2.0"}` or SPDX metadata to `pyproject.toml`.
- Add SPDX headers to new source files; do not churn every existing file in one commit.
- Add `THIRD_PARTY_NOTICES.md` covering PyYAML, bundled rule sources, and any future engine.
- Use DCO sign-off (`Signed-off-by`) rather than a CLA. Keep contribution friction low.
- Add a `CONTRIBUTING.md` section explaining provenance and license requirements for contributed rules.
- Audit every bundled rule pack. The Semgrep rule corpus, gitleaks rules, nuclei templates, and any copied corpus have their own licenses. Do not redistribute a pack until its license is recorded and compatible.

**Hard rule:** no third-party rule pack ships in a release without a `rules/PROVENANCE.yaml` entry containing source URL, commit, license, retrieval date, and a checksum.

### 3.3 Rename mechanics

Renaming a developer tool is a migration project, not a find-and-replace.

| Surface | New | Compatibility |
|---|---|---|
| CLI | `aegis` | Keep `commit-guard` as a deprecated alias until v2.0. |
| Python distribution | `aegis-sast` | Keep publishing `commit-guard` as a meta-package for one release if feasible. |
| Install directory | `.aegis/` | Detect `.commit_guard/`; migrate on first run; keep reading old hooks. |
| Config | `.aegis.toml` | Read `.commit_guard.toml` with a warning; write new only after `aegis migrate`. |
| Baseline | `.aegis_baseline` | Read `.commit_guard_ignore`; preserve fingerprints exactly. |
| Env vars | `AEGIS_*` | Accept `COMMIT_GUARD_*` aliases for two minor releases. |
| Inline markers | `aegis-ignore` | Support `commit-guard-ignore` for two minor releases; document the mapping. |
| GitHub Action | `AmrEldhshan/aegis@v1` | Keep the old action name working until v2.0. |
| pre-commit hook ID | `aegis` | Keep `commit-guard` alias in `.pre-commit-hooks.yaml`. |
| Reports | `aegis_report.*` | Accept old names; do not silently overwrite. |

`aegis migrate` must be idempotent, dry-runnable, and must never delete the old state without a backup. Tests must cover a repository installed with CommitGuard 2.1.

### 3.4 Security policy and disclosure

Before the first public release:

- `SECURITY.md` with a private reporting channel and a 90-day disclosure target.
- A documented threat model (section 18) and a supported-versions table.
- A CVE request process and a release procedure for security fixes.
- A `security.txt` in the documentation site and repository.
- A policy for handling secrets accidentally committed to issues, logs, or test fixtures.
- A rule-pack revocation process: how a bad rule is disabled, versioned, and announced.

---

## 4. Current baseline (measured, not estimated)

Measured from the current checkout on 2026-10-24. These numbers are the starting line, not the goal. The 194 tests and the 9-tab GUI include uncommitted work; commit and tag the baseline before citing it publicly.

| Metric | Current value | Implication |
|---|---|---|
| Active rules | 340 | Useful, but far too small to claim broad SAST parity. |
| Skipped rule entries | 2,059 | Most of the bundled corpus is not executed. |
| Skipped because AST/composite Semgrep pattern | 1,764 | The largest coverage gap; needs an optional Semgrep/Opengrep engine. |
| Skipped because no usable regex | 293 | Regex extraction cannot represent these rules. |
| Skipped because malformed/unsupported | 2 | Must be fixed or explicitly quarantined. |
| Rules with auto-fix support | 6 | Fix-first is mostly aspirational today. |
| Secret rules | 239 | The strongest current category. |
| Corpus samples | 25 | Too small to measure precision or recall. |
| Test suite | 194 tests, passing | Good discipline; coverage is concentrated in the current feature set. |
| Languages with executable regex rules | Mostly language-agnostic plus Python, JavaScript, Dockerfile, Terraform, shell, YAML | Broad language claims are not yet supported by the executable corpus. |
| Report formats | Markdown, JSON, SARIF, JUnit, GitLab Code Quality, Checkstyle, HTML | Strong reporting base. |
| SCA | Offline OSV snapshot or opt-in OSV.dev; exact-pinned versions | No transitive or range resolution yet. |
| Dependency graph | File-level imports | Useful for blast radius; not symbol-level reachability. |
| Taint analysis | Python only; intraprocedural; 2 rules | Narrow; no interprocedural or cross-file flow. |
| Local GUI | 9-tab loopback control center | Real differentiator; needs hardening and docs. |
| Telemetry | None | Keep it that way. |
| License | None declared | Release blocker. |
| Distribution | Source checkout, installed engine, PyPI metadata present | No signed binary, no Homebrew/Scoop, no Docker image yet. |

### 4.1 What is genuinely strong today

- Offline-first execution with no account and no telemetry.
- Diff-first scanning and pre-commit ergonomics.
- Seven report formats, including SARIF and HTML.
- Baselines, fingerprints, suppressions, owner/expiry metadata, and audits.
- Rule caching and deterministic behavior.
- A working local GUI and a tested installer.
- A zero-dependency core apart from PyYAML.

### 4.2 What is missing for the stated ambition

- Measured accuracy and a benchmark harness.
- An engine abstraction that lets more than one analyzer contribute.
- Policy-as-code beyond a single threshold and baseline.
- SARIF ingestion and cross-tool normalization.
- Transitive dependency resolution and reachability.
- IaC and container coverage.
- A language server, watch mode, and editor integration.
- Signed releases, SBOMs, and a public security process.
- A license and a naming gate.

### 4.3 The honest conclusion

Today Aegis is a **good local secret and regex scanner with strong reporting and a promising GUI**. It is not yet a SAST platform. This plan closes that gap in stages, and it refuses to pretend the gap does not exist.

---

## 5. Users, jobs, and positioning

### 5.1 Ideal customer profile

**Primary**

- Regulated, air-gapped, or privacy-sensitive organizations that cannot send source code to a SaaS or operate a SonarQube stack.
- Small and mid-sized teams that will not run a JVM, PostgreSQL, and a reverse proxy for a linter.
- Monorepos and high-velocity teams where a full-platform scan is too slow for the inner loop.
- Teams already running Semgrep, Trivy, Checkov, gitleaks, or CodeQL that want one local gate and one normalized report.

**Secondary**

- Platform teams that want a fast pre-commit layer in front of an enterprise scanner.
- Open-source maintainers who need a free, no-account gate in CI.
- Security consultants who need an offline evidence pack for clients.

**Anti-personas**

- Organizations that require a multi-tenant SaaS dashboard, SSO, and portfolio governance on day one.
- Teams looking for a full code-quality, duplication, or coverage platform.
- Teams that will not run a CLI or configure a policy file.
- Buyers who equate “more rules” with “better security.”

### 5.2 Personas and jobs to be done

| Persona | Job | Aegis answer |
|---|---|---|
| **Maya, application developer** | “Stop me before I commit a secret or an injection.” | Fast pre-commit scan, precise line-level finding, safe fix, inline suggestion. |
| **Sam, AppSec engineer** | “Give me one gate and one report across our tools.” | Ingest SARIF/native output, normalize, dedupe, policy, audit trail. |
| **Priya, platform engineer** | “Make it work in CI without a new service.” | Single binary/pip install, Docker, GitHub Action, GitLab component, deterministic exit codes. |
| **Omar, regulated/air-gapped owner** | “Prove no code leaves the network.” | Offline by default, no telemetry, signed artifacts, SBOM, documented egress. |
| **Lena, open-source maintainer** | “Give me a free gate that does not spam me.” | Conservative defaults, baselines, easy suppression, no account. |
| **Ravi, engineering manager** | “Show me whether we are getting safer.” | Static dashboard from CI artifacts, trends, ownership, debt ratchet. |

### 5.3 Core workflows

1. **Before commit:** staged diff scan under two seconds; fix or suppress; hook blocks only new high-severity issues.
2. **Before push:** audit the commits being pushed, including secrets in history.
3. **Pull request:** scan the diff, upload SARIF, post a summary and inline suggestions, fail only the policy gate.
4. **Scheduled audit:** full-tree and history scan with an SBOM and license report.
5. **Aggregation:** ingest other tools’ output, dedupe, apply one policy, publish one report.
6. **Triage:** accept, false-positive, wont-fix, or fix with owner, expiry, ticket, and reason.
7. **Incident response:** search history for a leaked secret; produce an audit artifact.
8. **Onboarding:** one command, zero config, first finding in under two minutes.

### 5.4 Positioning statement

> **Aegis is the offline security control plane for developers: one fast gate over every analyzer you already run, one reviewable policy, one fix-first workflow, and no code leaving your machine. Run it before the commit, not after the incident.**

### 5.5 Competitive matrix

| Dimension | SonarQube | Snyk / SaaS | CodeQL | Semgrep | Trivy / gitleaks | Aegis target |
|---|---|---|---|---|---|---|
| Deployment | Server + DB | Cloud | CI/cloud | CLI/CI | CLI/CI | CLI, package, Docker, ephemeral local GUI |
| Offline / air-gap | Heavy | No | Limited | Yes | Yes | Native, tested with network off |
| Data privacy | Self-hosted | Vendor | Vendor | Local | Local | No egress by default |
| Speed on a diff | Slow | Moderate | Slow | Fast | Fast | Under 2s p50 on medium repos |
| SAST depth | Deep, broad | Good | Deep | Deep with rules | Narrow | Optional Semgrep/Opengrep + own taint |
| Secrets | Weak | Good | Weak | Partial | Strong | Strong, with validators and history |
| SCA | Add-on | Strong | Limited | Partial | Strong | Offline snapshot, transitive later |
| IaC / containers | Partial | Good | Limited | Partial | Strong | Ingest first, native later |
| Code quality | Native | Limited | No | No | No | Ingested, not rebuilt |
| Policy / gates | Strong | Strong | Weak | Basic | Basic | Policy-as-code, local, auditable |
| Triage / ownership | Server UI | Cloud UI | Code scanning UI | Limited | Limited | Committed triage + CODEOWNERS |
| Reporting / trends | Web UI | Web UI | Code scanning UI | JSON/SARIF | JSON/SARIF | Static HTML + artifacts |
| Supply chain | Basic | Good | Basic | Limited | Strong | SBOM, license policy, VEX later |
| Extensibility | Plugin marketplace | Limited | Queries | Rules | Plugins | Signed packs + out-of-process plugins |
| Cost | License + infra | Subscription | License | Free/paid | Free | Open core, paid support/packs |

The matrix is not a claim of superiority. It is a map of where Aegis must be credible and where it deliberately chooses not to compete.

### 5.6 Why now

- Supply-chain incidents have made “where does our code go?” a board-level question.
- Semgrep, OSV, SARIF, Sigstore, and CycloneDX have standardized the building blocks.
- Developers now expect fast local feedback and fix suggestions, not weekly PDFs.
- AI coding assistants increase the volume and speed of code changes; a fast local gate becomes more valuable, not less.
- Regulated buyers are tired of hosting scanners and are open to well-supported local tools.

---

## 6. Strategy and differentiation

### 6.1 The six pillars

1. **Local control plane.** One gate and one normalized report over every analyzer. This is the moat that incumbents cannot cheaply copy without abandoning their hosted business model.
2. **Diff-time speed.** Pre-commit, watch, and IDE loops measured in milliseconds to seconds. Speed is a security feature: a slow gate gets disabled.
3. **Fix-first.** Structured fixes, safe autofixes, inline PR suggestions, and explanations. Every finding should answer “what do I do next?”
4. **Policy-as-code.** New-code gating, budgets, ratchets, triage, ownership, expiry, and audit as versioned files.
5. **Trust.** Signed releases, checksums, SBOMs, benchmark cards, no telemetry, documented limitations, and a real disclosure process.
6. **Extensibility without supply-chain risk.** Stable interfaces for engines, ingesters, reporters, and rule packs, with signatures, capabilities, and explicit trust.

### 6.2 The moat

The moat is not the regex corpus. It is the combination of:

- **Workflow lock-in that is friendly:** one policy file, one triage file, one baseline, one report format.
- **Integration breadth:** every analyzer’s output becomes first-class.
- **Trust artifacts:** reproducible evidence and a public benchmark.
- **Developer habit:** the gate runs before the commit, not after the PR.
- **Community rule supply chain:** contributed, tested, provenance-tracked rules.

A competitor can copy a rule. Copying the workflow, the integrations, the benchmark, and the trust story takes years.

### 6.3 Business model (compatible with the constraints)

- **Open core:** Apache-2.0 CLI, engine, policy, ingesters, reporters, and baseline rules.
- **Paid support and training:** for regulated teams that need an SLA, architecture review, or air-gapped installation help.
- **Curated packs:** industry-specific, license-cleared rule packs and compliance mappings, sold as signed artifacts. Never remove core safety features to sell them.
- **Sponsorship and grants:** OpenSSF, security foundations, and corporate sponsors.
- **No hosted service, no telemetry, no per-seat gate on local scanning.** This is a promise, not a temporary tactic.

The business must not create an incentive to degrade the free tool. Publish the boundary explicitly.

### 6.4 Hard constraints

- **No hosted service.** Everything runs as a CLI, CI step, local subprocess, or stdio language server.
- **Offline by default.** No telemetry. No network unless the user explicitly opts in to a documented command.
- **Optional network only to public APIs** (OSV.dev, provider verification) or user-configured endpoints, with the user's credentials.
- **Python 3.11+ core, dependency-light.** Optional engines are external processes.
- **Backward compatible.** Existing CommitGuard installs, configs, baselines, and fingerprints keep working through the migration window.
- **Deterministic output.** Stable ordering, stable fingerprints, reproducible reports.
- **No arbitrary code execution from repository content.** Rules, plugins, SARIF, and config are untrusted input.

### 6.5 Non-goals

- No web application, daemon, or database service.
- No multi-tenant SSO, portfolio management, or organization-wide governance.
- No from-scratch code-quality, duplication, or coverage engine.
- No reimplementation of Semgrep or CodeQL analysis engines.
- No telemetry or mandatory cloud connectivity.
- No claim of complete vulnerability coverage.
- No attempt to beat every incumbent on every dimension.
- No AI-generated blocking finding without a reproducible rule or human review.
- No auto-fix that writes to a file without a preview and a reversible patch.

### 6.6 Adoption wedge

1. Migrate existing CommitGuard users with a zero-surprise rename.
2. Win pre-commit and GitHub Actions users with a two-minute install.
3. Win air-gapped teams with a network-off demo and signed artifacts.
4. Win teams already running Semgrep/Trivy with ingestion and one policy.
5. Expand into triage, SBOM, and compliance reporting once the gate is trusted.

---
## 7. Goals, metrics, and guardrails

### 7.1 North Star

**A developer can install Aegis, run it before a commit, understand the result, and fix or consciously accept it without leaving the terminal or opening a ticket.**

Everything else is instrumentation for that sentence.

### 7.2 Product metrics

| Metric | Target for v1.0 | How measured |
|---|---|---|
| Install to first finding | Under 2 minutes, no account | Timed usability test on a clean machine; 10 participants. |
| Median staged diff scan | Under 800 ms p50, under 2 s p95 | Benchmark fixture suite in CI. |
| Full incremental monorepo scan | Under 60 s p95 on the reference fixture | CI performance job. |
| Crash-free scans | Above 99.5% | Fuzz/integration corpus plus issue telemetry (manual triage). |
| First-run success | Above 95% without editing config | Installer integration tests and usability sessions. |
| Fix preview correctness | Zero destructive fixes in the regression corpus | `tests/fixes` golden corpus; every fix applied and diff-reviewed. |
| Report determinism | Byte-identical for identical inputs and versions | Golden tests across two runs and two platforms. |
| Network egress by default | Zero | Network-namespace test; DNS and socket instrumentation. |

### 7.3 Accuracy metrics

Accuracy claims are only valid with a benchmark card (Appendix G). The plan uses four layers:

1. **Rule-level corpus:** every rule has at least one positive and one negative sample; positive samples assert the expected location, severity, and fixability.
2. **Language/CWE benchmarks:** OWASP Benchmark (Java) first, then Juliet subsets, then framework-specific fixtures.
3. **Real-world regression corpus:** vulnerable-commit/fix-commit pairs, with a zero-findings-on-fixed-commit requirement.
4. **Cross-tool comparison:** same dataset, same commit ranges, same severity mapping, published configuration.

Targets for v1.0:

- Precision above 85% on the curated high-confidence corpus.
- False-positive rate below 5% on non-vulnerable files in the benchmark suite.
- Recall above 70% on the supported CWE subset for Python and JavaScript/TypeScript.
- Zero findings on the fixed-commit set for rules marked stable.
- Confidence labels calibrated: high-confidence findings should have a materially higher precision than medium/low.
- Per-rule corpus coverage above 90% before a rule can be marked stable.

These are initial targets, not universal guarantees. Publish results by language, CWE, and rule; never publish a single blended “accuracy” number.

### 7.4 Trust metrics

- Every release has a checksum file and a Sigstore signature.
- Every release has an SBOM and a `THIRD_PARTY_NOTICES` entry for new dependencies.
- Every public accuracy claim links to a benchmark card and raw artifact.
- Security reports are acknowledged within 3 business days.
- No release ships with a known critical vulnerability in its own dependencies.
- Reproducibility is either verified and stated, or explicitly marked “not yet verified.”

### 7.5 Developer and community metrics

- Time to first response on issues: under 5 business days.
- Time to triage a security report: under 3 business days.
- Percentage of merged rules with corpus tests: 100%.
- Percentage of releases with migration notes: 100%.
- Survey-based NPS after 30 days, with qualitative reasons (no telemetry).
- Download and Action usage are context, not proof of adoption.

### 7.6 Anti-metrics

Do not optimize for, report as success, or use in marketing:

- Number of rules (inventory is not coverage).
- Lines of code scanned.
- Number of integrations shipped.
- “AI-powered” claims without measured lift.
- GitHub stars as a proxy for security value.
- Blended precision/recall that hides weak languages.

### 7.7 Guardrails

- **No silent network.** Any feature that can make a request must be visible in config, documented, and off by default unless it is the explicit purpose of the command.
- **No auto-execution of repository content.** Rules, plugins, hooks, and config from a repository are untrusted input.
- **No destructive fix without a preview.** Fixes require a dry run, a diff, and an explicit apply.
- **No policy bypass by default.** A finding cannot be downgraded by an ingested tool’s severity without an explicit mapping.
- **No benchmark overfitting.** Rules tuned to a public dataset must be marked and evaluated on a held-out set.

---

## 8. Architecture

### 8.1 Principles

1. **One process by default.** No daemon, database service, or required network dependency.
2. **Policy applied once.** Inline suppression, triage, baseline, allowlists, severity overrides, and gate evaluation happen after all engines merge. Engines never implement policy.
3. **Optional engines degrade gracefully.** A missing engine is a warning; the scan still completes with the remaining engines.
4. **Deterministic output.** Stable ordering, stable fingerprints, stable report bytes.
5. **Untrusted input is the norm.** Repositories, diffs, rule packs, SARIF, lockfiles, and plugin manifests are hostile until validated.
6. **Bounded resources.** Every parser and engine has time, memory, and size limits.
7. **Interfaces before implementations.** Engines, ingesters, reporters, and rule sources share stable contracts.

### 8.2 Pipeline

```text
                   git diff / staged / range / history / all
                                   |
                                   v
                       +-----------+-----------+
                       |   change selection    |
                       | file list + hunks     |
                       +-----------+-----------+
                                   |
                                   v
                       +-----------+-----------+
                       |    engine planner     |
                       | capabilities + cost   |
                       +-----------+-----------+
                                   |
        +--------------+-----------+-----------+--------------+
        |              |                       |              |
   +----v----+    +----v----+             +----v----+    +----v----+
   | regex   |    | AST     |             | Semgrep |    | SCA     |
   | engine  |    | taint   |             | optional|    | OSV     |
   +----+----+    +----+----+             +----+----+    +----+----+
        |              |                       |              |
        +--------------+-----------+-----------+--------------+
                                   |
                       +-----------v-----------+
                       | external ingest       |  SARIF / native JSON
                       +-----------+-----------+
                                   |
                       +-----------v-----------+
                       | normalize + dedupe    |
                       | stable finding model  |
                       +-----------+-----------+
                                   |
                       +-----------v-----------+
                       | policy stage          |  inline, triage, baseline,
                       |                       |  allowlist, overrides, gate
                       +-----------+-----------+
                                   |
             +---------------------+---------------------+
             |                     |                     |
        +----v----+           +----v----+           +----v----+
        | reports |           | history |           |  CI     |
        | SARIF   |           | JSON    |           | exit    |
        | HTML    |           | optional|           | codes   |
        +---------+           +---------+           +---------+
```

### 8.3 Module map

| Path | Responsibility | Status |
|---|---|---|
| `core/engines/base.py` | Engine protocol, capability descriptor, result model | New |
| `core/engines/regex_engine.py` | Wrap `core/scanner.scan_diff` | New |
| `core/engines/taint_engine.py` | Wrap `core/ast_taint` | New |
| `core/engines/semgrep_engine.py` | Optional Semgrep/Opengrep subprocess adapter | New |
| `core/engines/sca_engine.py` | Wrap `core/sca` | New |
| `core/engines/runner.py` | Plan, execute, merge, dedupe, isolate failures | New |
| `core/ingest/` | SARIF and native normalizers | New |
| `core/policy.py` | Gates, budgets, ratchet, profiles, evaluation | New |
| `core/triage.py` | Committed triage state, ownership, expiry, audit | New |
| `core/owners.py` | CODEOWNERS mapping and team grouping | New |
| `core/history.py` | Optional local JSONL/SQLite trend store | New |
| `core/dashboard.py` | Static self-contained dashboard | Extend `core/trends.py` |
| `core/sbom.py` | CycloneDX and SPDX generation | New |
| `core/license.py` | Dependency license policy | New |
| `core/vex.py` | OpenVEX import/export | Later |
| `core/plugins.py` | Manifest validation and out-of-process loading | New |
| `core/lsp.py` | Stdio language server | New |
| `core/pr_creator.py` | Existing PR and inline suggestion support | Extend |
| `gui_server.py` / `gui_actions.py` / `gui_page.py` | Existing local control center | Extend and harden |
| `main.py` | CLI entry point and subcommands | Extend |
| `install_hook.py` | Installer and migration | Extend |
| `action.yml` | GitHub Action | Extend |
| `bench/` | Datasets, scorer, regression gate | New |
| `rules/taint/` | Taint packs by language | New |
| `rules/compliance/` | CWE/OWASP/ASVS/PCI mappings | New |
| `rules/PROVENANCE.yaml` | Rule source, license, checksum | New |

### 8.4 Engine protocol

```python
# core/engines/base.py (sketch)
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, Sequence

@dataclass(frozen=True)
class EngineCapability:
    name: str
    languages: frozenset[str]
    categories: frozenset[str]
    supports_fixes: bool = False
    supports_flows: bool = False
    requires_network: bool = False
    requires_binary: bool = False
    version: str = "unknown"

@dataclass(frozen=True)
class EngineResult:
    findings: tuple[Finding, ...]
    warnings: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    duration_ms: int = 0
    engine: str = "unknown"

class Engine(Protocol):
    name: str
    def capability(self) -> EngineCapability: ...
    def available(self) -> tuple[bool, str]: ...
    def run(self, context: ScanContext) -> EngineResult: ...
```

Rules for engines:

- `run` must be pure with respect to policy. It returns raw findings, warnings, errors, and timing.
- An engine failure is isolated. The runner records it as a warning and continues unless the engine is explicitly required.
- A missing binary is detected before execution and reported once, not per file.
- Engines receive an explicit file list and may not scan outside it.
- Engines must respect the global deadline and cancellation token.
- Output is normalized by the engine adapter; the runner does not parse engine-specific JSON.

### 8.5 Finding model (schema v3)

Extend the current model additively. Existing fields remain, so old reports and baselines continue to work.

| Field | Type | Required | Notes |
|---|---|---|---|
| `schema_version` | int | Yes | `3` for this model. |
| `id` | string | Yes | Stable per finding instance; see fingerprint rules. |
| `fingerprint` | string | Yes | `sha256(rule_id + path + normalized_code)[:16]`; line-independent. |
| `rule_id` | string | Yes | Namespaced, e.g. `aegis/python/sql-injection`. |
| `engine` | string | Yes | `regex`, `ast`, `semgrep`, `sca`, `ingest:<tool>`. |
| `category` | string | Yes | `secret`, `sast`, `dependency`, `iac`, `container`, `license`, `quality`. |
| `severity` | string | Yes | `critical`, `high`, `medium`, `low`, `info`. |
| `confidence` | string | Yes | `high`, `medium`, `low`; calibrated, not decorative. |
| `file` | string | Yes | Repository-relative, normalized, no `..`. |
| `line` | int | Yes | 1-based. |
| `column` | int | No | 1-based when known. |
| `end_line` | int | No | For multi-line findings. |
| `end_column` | int | No | For multi-line findings. |
| `description` | string | Yes | Actionable, no secret content. |
| `flagged_code` | string | Yes | Redacted by default. |
| `redacted_code` | string | No | Safe display; never contains a secret unless explicitly requested. |
| `fix` | object | No | `{description, safety, edits[]}`; edits have file, range, replacement. |
| `references` | array | No | Advisory, CWE, documentation. |
| `code_flows` | array | No | Ordered source-to-sink path for SARIF. |
| `cwe` | string | No | Primary CWE. |
| `tags` | array | No | Stable vocabulary. |
| `baseline_state` | string | Yes | `new`, `unchanged`, `updated`, `absent`. |
| `also_reported_by` | array | No | Engines/tools that reported the same finding. |
| `rule_version` | string | No | Rule pack version. |
| `pack_version` | string | No | Pack identifier and version. |
| `provenance` | object | No | Tool version, command, input digest. |

Compatibility rules:

- Add fields only; never rename or repurpose an existing field in a minor release.
- `schema_version` increments only for breaking changes; readers must reject unknown major versions and tolerate unknown fields.
- Fingerprints must not include line numbers, so code movement does not create “new” debt.
- Secret findings must never include the unredacted value in JSON, HTML, SARIF, logs, or the GUI unless the user explicitly requests it.
- Finding ordering: severity descending, then file path, then line, then rule ID, then fingerprint. This ordering is part of the report contract.

### 8.6 Normalization and deduplication

Deduplication is where aggregation becomes useful instead of noisy.

- **Exact match:** same normalized path, same line range, same rule mapping → one finding, `also_reported_by` records all sources.
- **Cross-tool match:** same category, same CWE, overlapping range, and a compatible rule mapping → merge when confidence is high; otherwise keep both and mark `related`.
- **Engine preference:** when a regex and an AST/Semgrep finding overlap, prefer the engine with the richer evidence (flows, fix, column) while preserving the other as `also_reported_by`.
- **Rule mapping:** a versioned `rules/tool-map.yaml` maps third-party rule IDs to Aegis categories, CWE, and policy class. Unmapped rules are `category: unknown` and never silently dropped.
- **Stable identity:** cross-tool dedupe must not merge findings of different categories (a secret and a SAST finding on the same line are different).
- **No loss:** every merged finding retains source locations and tool metadata for audit.

### 8.7 Policy stage and precedence

Policy is applied once, in this order. Later stages may suppress or downgrade a finding but cannot resurrect a finding suppressed by an earlier stage.

1. **Inline suppression:** `aegis-ignore` comments in source (legacy `commit-guard-ignore` remains supported through the migration window).
2. **Triage:** committed state (`accepted`, `false_positive`, `wont_fix`, `fixed`) with owner and expiry.
3. **Baseline:** fingerprint-based new-code comparison.
4. **Allowlists:** repo, path, rule, and line allowlists.
5. **Severity overrides:** config and mapped tool severity.
6. **Gate:** threshold, budgets, ratchet, new-code rules, profiles.
7. **Reporting:** only surviving findings appear; suppressed findings can be included in an audit view.

Every persistent suppression (baseline, triage, config, or allowlist) must have a reason category and an owner. Inline comments may use rule IDs, but they are counted and audited. Expired triage and stale baseline entries are findings of their own (at `info` or configurable severity).

### 8.8 Performance architecture

- **Change selection first.** Never walk the whole repository when a diff is available.
- **Content-addressed cache.** Cache engine results by `(engine version, rule pack signature, file content hash, config hash)`. Cache location: `.aegis/cache/` (gitignored).
- **Parallel engines, sequential policy.** Engines may run concurrently; normalization and policy are deterministic and ordered.
- **Bounded workers.** Default to `min(4, cpu_count)`; allow `--workers`.
- **Deadlines.** Global scan deadline and per-engine timeout. A timed-out engine yields a warning, not a hang.
- **Memory limits.** Reject files above a configurable size; stream large inputs; cap findings per file and per scan.
- **Early exit for pre-commit.** Stop after the blocking threshold is proven only when `--fail-fast` is explicit; otherwise complete for reporting.
- **Binary and generated files.** Skip by default with an audit trail; never silently treat as clean.

### 8.9 Local GUI boundary

The GUI is a **local developer console**, not a service.

- Bind to `127.0.0.1` (or `::1`) only; `--allow-remote` requires an explicit flag and a warning.
- Per-run bearer token; no persistent credentials.
- Validate `Host` to prevent DNS rebinding; set a strict Content Security Policy.
- No CDN assets, no external fonts, no telemetry.
- Secrets remain redacted; showing them requires an explicit per-session toggle.
- GitHub tokens live in page memory or an environment variable, never in a config file or log.
- The GUI uses the same actions layer as the CLI, so behavior cannot drift.
- CI uses the static HTML report, not the server.

### 8.10 Plugin model

Plugins are powerful and dangerous. Treat them as untrusted code.

- Out-of-process execution with a JSON protocol over stdio.
- A manifest declares name, version, capabilities, permissions, supported categories, and signature.
- Plugins are loaded only from an explicit user directory or an installed package; **never** auto-loaded from a scanned repository.
- Network and filesystem access are denied by default; grant only declared capabilities.
- Resource limits: timeout, memory, output size.
- Signature verification for distributed plugins; unsigned local plugins require an explicit `--allow-unsigned-plugin`.
- A plugin crash cannot crash the scan.
- Python in-process plugins are a later, explicitly trusted mode; they are not the default.

### 8.11 Cross-platform and determinism notes

- Normalize paths to POSIX form inside reports; preserve the native path for display only when necessary.
- Define case-sensitivity behavior explicitly; never assume a case-insensitive filesystem.
- Handle CRLF and mixed line endings without shifting columns or fingerprints.
- Read and write UTF-8 by default; handle invalid byte sequences without crashing.
- Use argument lists, never a shell; avoid platform-specific command construction.
- Respect long-path limits on Windows and test them in CI.
- Do not hold file locks longer than necessary; retry transient Windows sharing violations.
- Sort with a locale-independent key; never rely on filesystem enumeration order.
- Golden tests run on Linux, macOS, and Windows and must produce identical report bytes.

### 8.12 Monorepos

- Discover per-package configs and policies, with a documented root-to-leaf precedence.
- Scope scans to the changed packages plus their dependents when the graph is available.
- Support per-path budgets and per-team ownership without splitting the repository.
- Cache by package and file content; invalidate only what changed.
- Merge package results into one deterministic report with package labels.
- Keep the root policy authoritative for global gates; package policies may only tighten.
- Test a synthetic monorepo fixture with multiple languages and nested configs.

---

## 9. Detection strategy

Detection is table stakes, but it must be built in the right order: make the existing engine measurable, then add depth, then add breadth.

### 9.1 Language support policy

A language is “supported” only when it has executable rules, positive and negative tests, benchmark coverage, and documentation. Everything else is “best effort” or “via ingestion,” and the difference is visible in `aegis status` and the docs.

| Tier | Languages | Commitment |
|---|---|---|
| **1 — supported** | Python, JavaScript, TypeScript, Java, Go, Ruby, PHP, C#, Terraform, Dockerfile, Kubernetes YAML, shell | Rules, tests, benchmark coverage, docs, and regression gates. |
| **2 — best effort** | Rust, Kotlin, Swift, C/C++, Scala, Elixir, Solidity | Rules and tests where a maintained pack exists; no parity claim. |
| **3 — ingest only** | Any tool that emits SARIF/JSON | Normalized into the policy and report, with provenance. |

Do not market a language as supported because a rule file exists. The tier is earned by evidence.

### 9.2 Secrets

Current state: 239 secret rules, redaction by default, entropy support, placeholder filtering, inline suppression, and baseline support. This is the strongest category and should stay the best.

Roadmap:

- **Validators:** deterministic format validators for AWS, GitHub, GitLab, Slack, Stripe, Twilio, SendGrid, npm, PyPI, Google, Azure, and common private-key formats.
- **Optional verification:** `--verify-secrets` calls the provider’s documented verification endpoint only when explicitly enabled. It must never print or persist the secret, must respect rate limits, and must be documented as an egress event.
- **History scanning:** first-class `--history` secret scan with commit, author, and date metadata; never modify history automatically.
- **Entropy tuning:** per-rule entropy thresholds and allowlists to reduce random-string false positives.
- **Secret-specific triage:** a secret cannot be “accepted” without a reason, owner, and expiry. Revocation guidance is part of the finding.
- **Redaction tests:** every report format gets a test that asserts the raw secret does not appear.

Acceptance:

- Every secret rule has a positive and negative fixture.
- Redaction tests pass for JSON, SARIF, HTML, Markdown, JUnit, GitLab, Checkstyle, logs, and GUI.
- History scan identifies a secret introduced and later removed, with the introducing commit.

### 9.3 Regex and native SAST

Current state: 340 active rules, bounded multi-line context in the custom pack, path restrictions, language filters, allowlists, and severity overrides.

Roadmap:

- **Function scope:** map changed lines to the enclosing function or class and scan the whole unit without reporting old debt.
- **Multi-line patterns:** official support for bounded context windows, with a hard cap and deterministic matching.
- **Rule namespacing:** `aegis/<language>/<category>/<slug>`; aliases preserve existing IDs.
- **Confidence labels:** regex-only matches default to medium or low unless context raises confidence.
- **Rule-level tests:** mandatory positive and negative samples before a rule is marked stable.
- **Deprecation:** rules can be deprecated with a replacement, a removal release, and a changelog entry.

Acceptance:

- No stable rule without corpus coverage.
- Function-scope scan does not report findings outside the changed function.
- Existing reports remain reproducible for the existing rule set.

### 9.4 Optional Semgrep/Opengrep backend

This is the fastest path to the 1,764 skipped AST/composite rules, but it is optional and legally gated.

- Detect `semgrep` or `opengrep` from `PATH`, config, or `AEGIS_SEMGREP`.
- Run with `--json --metrics=off --disable-version-check`, an explicit config, and the exact file list.
- Set environment variables that disable metrics and version checks.
- Map severity, CWE, references, confidence, fix, columns, end lines, and code flows.
- Prefer AST/Semgrep findings over overlapping regex duplicates, preserving both in `also_reported_by`.
- Warn once if the binary is absent; continue with the built-in engines.
- Never bundle the binary.
- **Licensing gate:** record the license of every rule pack and the engine; do not redistribute third-party rules until reviewed. Support Opengrep as an alternative engine, but do not assume its rule licensing is identical.
- **Contract tests:** recorded JSON fixtures so CI runs without Semgrep installed; one optional integration job runs the real binary.

Acceptance:

- The 1,764 currently skipped Semgrep-compatible entries have a documented path to execution, a license status, and a test.
- A repository without Semgrep produces the same results as today plus a clear warning.
- A repository with Semgrep produces merged, deduplicated findings with flows and fixes.

### 9.5 Taint analysis

Taint is the difference between “this looks dangerous” and “this request parameter reaches this SQL query.” Start with Python, then add languages in order of user demand.

| Phase | Languages | Scope | Required capabilities |
|---|---|---|---|
| 1 | Python | Intraprocedural, cross-file summaries | Sources, sinks, sanitizers, attribute chains, aliases, code flows. |
| 2 | JavaScript/TypeScript | Intraprocedural plus imported helpers | Express/Koa/Fastify sources; SQL, shell, SSRF, path, template sinks. |
| 3 | Java | Method-level plus Spring/Servlet | Request sources; JDBC, process, template, XML sinks. |
| 4 | Go | Function-level plus `net/http` | Request sources; SQL, exec, path, template sinks. |
| 5 | PHP, Ruby, C# | Framework-specific packs | Demand-driven; benchmark before claiming support. |

Python hardening priorities:

- Fix qualified sources such as `flask.request.args`, `request.json`, `request.form`, `request.values`, `request.headers`.
- Resolve imports and aliases (`from flask import request as req`).
- Add sources: framework request objects, `sys.argv`, `os.environ`, sockets, file reads, message-queue payloads.
- Add sinks: `eval`, `exec`, `pickle.loads`, `yaml.load`, `open`, `os.path.join`, `requests`, `urllib`, template rendering, XML parsing.
- Add sanitizers: numeric casts, `shlex.quote`, `html.escape`, allowlist checks, parameterized-query patterns.
- Add interprocedural summaries with a depth cap and conservative recursion handling.
- Emit source-to-sink code flows in the finding and SARIF `codeFlows`.
- Make unknown calls conservative: either treat as sanitizer (fewer false positives) or propagator (more recall), and document the choice per language.

Acceptance:

- Cross-file Python fixtures pass.
- Every taint finding includes a readable source-to-sink path.
- No increase in false positives on the benchmark suite.
- Performance stays within the diff-scan budget.

### 9.6 Software composition analysis

Current state: offline OSV snapshot or opt-in OSV.dev; exact-pinned versions; no transitive resolution.

Roadmap:

- **Lockfile matrix:** pip/poetry/uv, npm/pnpm/yarn, Go modules, Maven/Gradle, Cargo, Composer, Bundler, NuGet, and container image manifests.
- **Transitive dependencies:** resolve the actual dependency graph where a lockfile provides it; otherwise mark the result “direct only.”
- **Version ranges:** compare against OSV ranges, not just exact pins. Use ecosystem-specific version comparison, with fixtures.
- **Snapshot provenance:** the offline OSV snapshot is downloaded with a checksum, signed metadata, timestamp, and a visible staleness warning.
- **Reachability (later):** determine whether a vulnerable function is actually called. This is a differentiator, but only after the graph and benchmarks are trustworthy.
- **VEX (later):** import/export OpenVEX so “not affected” decisions travel with the SBOM.
- **Container images:** ingest Trivy/Grype results first; native image scanning later.

Acceptance:

- At least six lockfile ecosystems parse with fixtures.
- A vulnerable transitive package is reported with the dependency path.
- A patched lockfile produces zero findings on the fixed-commit corpus.
- Offline mode never touches the network, verified by test.

### 9.7 IaC and containers

Do not rebuild Trivy and Checkov. Ingest first, then add native checks only for gaps.

- **Ingest:** Trivy JSON/SARIF, Checkov JSON/SARIF, and Kubernetes/Terraform findings.
- **Normalize:** map to `category: iac` or `container`, with resource, path, and remediation.
- **Native rules:** only for high-signal checks that are missing upstream and can be maintained with tests.
- **Policy:** container and IaC findings participate in the same gate, budgets, and triage.
- **Secrets in images:** detect obvious secret files and environment variables; do not claim deep image forensics.

Acceptance:

- Trivy and Checkov outputs normalize into the same report and gate.
- A Terraform misconfiguration fixture blocks under the strict profile.
- No container daemon is required for ingestion.

### 9.8 AI-assisted detection (optional, non-authoritative)

AI may suggest candidates, explain findings, and propose fixes. It must not be the sole basis for a blocking finding.

- When enabled, use a local model by default (Ollama, LM Studio, vLLM, or any OpenAI-compatible endpoint).
- External providers only with an explicit key and an explicit opt-in.
- Candidate findings are marked `confidence: low`, `source: ai`, and `blocking: false` until reviewed.
- Every AI finding must include the exact code location and a reproducible rule or reasoning trace.
- AI output is never auto-applied.
- Evaluate AI candidates against the same benchmark; publish lift, not anecdotes.

### 9.9 Rule supply chain

Rules are code. Treat them like dependencies.

- `rules/PROVENANCE.yaml` for every pack: source, commit, license, checksum, retrieval date, maintainer.
- Signed pack manifests; signature verification before load.
- Pinning and lockfiles for rule packs.
- A rule change is a code review with tests, changelog, and a benchmark delta.
- Deprecation policy: announce, provide replacement, keep for at least one minor release.
- No rule may execute code, spawn processes, or read arbitrary files.
- Rule parser limits: file size, nesting depth, regex length, and compile timeout.

---

## 10. Interoperability and aggregation

Aggregation is the strategic moat. It must be more than “we can read SARIF.”

### 10.1 SARIF 2.1.0

Aegis must both **ingest** and **emit** high-quality SARIF.

Emit:

- `$schema`, `version: 2.1.0`, `runs[].tool.driver` with name, version, and rules.
- Rule metadata: ID, name, short description, full description, help URI, default severity, CWE tags.
- Results: rule ID, level, message, locations with physical and logical locations, `partialFingerprints`, `baselineState`, `fixes`, and `codeFlows`.
- Suppressions: `suppressions[]` with kind and justification for triaged findings.
- Invocations: command line, start/end time, exit code, tool execution notifications.
- No secrets in messages, snippets, or artifacts.

Ingest:

- Validate against the schema; reject oversized or malformed documents with a clear error.
- Tolerate unknown properties and version-compatible extensions.
- Preserve original rule IDs, tool names, and properties in `provenance`.
- Map `level` to severity with an explicit, documented table.
- Import `fixes`, `codeFlows`, `baselineState`, and `suppressions` when present.
- Never execute a URI, command, or artifact referenced by SARIF.

Acceptance:

- GitHub code scanning accepts Aegis SARIF without warnings.
- A SARIF file from Semgrep, CodeQL, Trivy, and Checkov normalizes into one report.
- Round-trip tests preserve locations, fingerprints, and fixes.

### 10.2 Adapters

| Tool | Input formats | Priority | Notes |
|---|---|---|---|
| Semgrep | JSON, SARIF | P1 | Native adapter; optional engine. |
| CodeQL | SARIF | P1 | Ingest only; no CodeQL execution. |
| Trivy | JSON, SARIF | P1 | Container, IaC, dependencies. |
| Checkov | JSON, SARIF | P1 | IaC. |
| gitleaks | JSON, SARIF | P1 | Secrets. |
| Bandit | JSON | P2 | Python SAST. |
| ruff | JSON | P2 | Quality/security lint. |
| ESLint | JSON | P2 | JavaScript/TypeScript. |
| golangci-lint | JSON | P2 | Go. |
| coverage.py / Istanbul | JSON, XML, LCOV | P3 | Quality gate input; not a security finding by itself. |
| OWASP Dependency-Check | JSON, SARIF | P3 | SCA comparison. |
| Snyk | JSON/SARIF where licensed | P3 | Only with a documented license path. |

Each adapter requires:

- A recorded fixture from a pinned tool version.
- A golden normalized output.
- A schema/version check with a clear error on unsupported versions.
- A maintainer and a review date.
- A license note for redistributed fixtures.

### 10.3 Normalization contract

- Every ingested finding gets `engine: ingest:<tool>`, `category`, `confidence`, and `provenance`.
- Unknown fields are preserved, not discarded.
- Unknown rule IDs are not dropped; they are mapped to `category: unknown` and included in an “unmapped” report.
- Paths are canonicalized relative to the repository root; absolute paths outside the repository are rejected.
- Severity mapping is versioned and documented.
- Deduplication follows section 8.6.

### 10.4 Report merge

`aegis report merge` combines reports from multiple jobs, repositories, or tools:

- Inputs: Aegis JSON, SARIF, or a manifest of report paths.
- Output: one JSON, SARIF, HTML, or Markdown report with repository/job labels.
- Conflicts are resolved by fingerprint and source, never by last-write-wins.
- The merged report records the input digests and tool versions.
- The gate can evaluate the merged report with the same policy.

---

## 11. Policy, triage, and audit

### 11.1 Policy model

Policy is a versioned file, reviewable in a pull request, with deterministic evaluation.

Core concepts:

- **New-code gate:** findings whose fingerprint is absent from the baseline are “new.”
- **Threshold:** minimum severity that blocks.
- **Budgets:** maximum new findings by severity, category, path, or owner.
- **Ratchet:** the baseline may only improve; a regression fails the gate.
- **Profiles:** `strict`, `balanced`, `audit`, plus regulated profiles (`pci`, `asvs`).
- **Exceptions:** scoped, owned, expiring, and audited.
- **Explain:** every gate result states which rule fired, which finding matched, and why.

Example policy semantics:

```toml
[gate]
profile = "balanced"
fail_on = "new"
threshold = "high"
max_new = { critical = 0, high = 0, medium = 25, low = 100 }
ratchet = true
allow_expired_triage = false

[gate.budgets.python]
medium = 10

[gate.budgets."src/payments/**"]
high = 0
```

Rules:

- A gate result is a data structure, not a formatted string.
- `aegis policy validate` catches schema errors before CI.
- `aegis policy explain <finding>` shows the full precedence chain.
- A policy cannot silently ignore a category; ignoring requires an explicit allowlist entry with a reason.
- Tool severity is mapped, never trusted blindly.

### 11.2 Gate outcomes and exit codes

Keep the existing contract stable:

| Code | Meaning |
|---|---|
| `0` | Success; no blocking findings. |
| `1` | Gate failed; blocking findings or a policy violation. |
| `2` | Operational error: bad config, unreadable repository, missing required engine, invalid policy. |

Additional detail is emitted in machine-readable output (`--format json` or `--gate-json`), not by inventing new exit codes. This keeps CI scripts simple and backward compatible.

### 11.3 Triage state

Triage is committed to the repository (`.aegis_triage.yaml`) unless a team explicitly uses CI artifacts.

Each entry:

```yaml
version: 1
entries:
  - fingerprint: "9f2c..."
    rule_id: "aegis/python/sql-injection"
    path: "src/app/db.py"
    state: accepted        # accepted | false_positive | wont_fix | fixed
    owner: "@team-payments"
    reason: "Parameterized query added in #1234; awaiting removal of legacy helper."
    ticket: "SEC-456"
    expires: "2027-01-31"
    created: "2026-10-24"
    evidence: "https://example.invalid/evidence/1234"
```

Rules:

- `fixed` entries are removed automatically on the next scan when the finding disappears; the audit log records it.
- Expired entries become findings at the configured severity and fail the gate under `strict`.
- Merge conflicts are resolved deterministically by fingerprint; conflicting states are an error, not a silent choice.
- Triage is code-reviewed like any other change.
- A secret can never be `accepted` without an owner, expiry, and revocation note.

### 11.4 Ownership and audit

- Map findings to `CODEOWNERS`; group reports by team.
- Emit a JSONL audit log for every suppression, triage change, baseline update, and gate result.
- The audit log is append-only per run and suitable as a CI artifact.
- Provide `aegis triage list|prune|audit` and `aegis baseline update|audit`.
- No server, no database, no account.

### 11.5 Data retention

- Audit logs and history are local artifacts with a configurable retention window.
- Default retention: 90 days for scan history, indefinite for committed triage (because it is code).
- `aegis history prune` and `aegis audit prune` are explicit, dry-runnable, and log what they remove.
- Reports may contain sensitive metadata; document that they should be stored with the same care as source.
- The cache never stores secret values; it stores hashes and normalized locations only.

### 11.6 Compliance mapping

- Ship mapping packs for OWASP Top 10, CWE Top 25, ASVS 5.0, PCI-DSS 4.0, and SOC 2 where a defensible mapping exists.
- Every mapping entry cites the control and the rule, and carries a confidence note.
- Reports state clearly: **mapping is not certification.**
- Do not claim coverage of controls that are organizational rather than technical.

---

## 12. Developer experience

### 12.1 CLI principles

- **Zero-config first.** `aegis scan` works in a fresh repository.
- **One obvious command per job.** `scan`, `gate`, `ingest`, `triage`, `sbom`, `explain`.
- **Actionable errors.** Every error says what failed, why, and the next command.
- **Stable JSON.** `--format json` is a contract, versioned by `schema_version`.
- **No surprise network.** Print a clear line when a command can use the network and whether it did.
- **No surprise writes.** Fixes, baselines, triage, and config changes are explicit.
- **Fast help.** `aegis --help` and `aegis <command> --help` are complete and current.

### 12.2 Fix-first workflow

Every fix has a safety level:

| Level | Meaning | Default action |
|---|---|---|
| `safe` | Deterministic, semantics-preserving, tested | Offer with one click; still preview. |
| `review` | Likely correct but context-dependent | Preview and require confirmation. |
| `manual` | Guidance only | Link to documentation; never auto-apply. |

Rules:

- Never auto-fix secrets.
- Never auto-fix across files without a preview.
- Apply fixes to a working tree, then stage only the touched files.
- Run the project’s tests after applying fixes when configured; otherwise warn.
- Record the applied fix fingerprint in the report.
- Provide a reversible patch file for every applied fix.

### 12.3 IDE and editor

- `aegis lsp`: stdio language server with diagnostics, code actions, and quick fixes.
- VS Code extension first; Neovim and JetBrains via LSP.
- Diagnostics are debounced and scoped to the open file and changed region.
- Code actions map to safe fixes and “explain” actions.
- The LSP must work when the CLI is installed but the project is not initialized.
- No telemetry, no background upload, no silent full-repo scan.

### 12.4 Watch mode

- `aegis watch`: incremental re-scan on file save.
- Debounce, cancel in-flight scans, and show a compact status line.
- Watch mode never blocks the editor; a slow scan is cancelled, not queued forever.
- Default to staged/diff scope; full-tree watch is explicit.

### 12.5 Pull request experience

- One summary comment with counts, gate status, and the top actions.
- Inline suggestions for `safe` fixes; `review` fixes link to a patch.
- SARIF upload for code scanning.
- A check run with a stable conclusion and a link to the artifact.
- Idempotent comments: update the existing comment instead of spamming.
- Respect token scopes; degrade to summary-only without write access.
- Never print the token.

### 12.6 Local GUI

The local console is a first-class developer surface:

- Scan, fixes, PR actions, baseline, rules, reports, maintenance, and config.
- Every action maps to a documented CLI equivalent.
- Clear offline/online indicators.
- Accessible keyboard navigation and readable contrast.
- The GUI is optional; the CLI remains the source of truth.
- The server exits when the window closes or after an idle timeout.

### 12.7 Performance budgets

| Scenario | p50 | p95 |
|---|---|---|
| Staged diff, small repo (<1k files) | 300 ms | 800 ms |
| Staged diff, medium repo (10k files) | 800 ms | 2 s |
| Full incremental scan, medium repo | 10 s | 30 s |
| Full incremental scan, monorepo fixture (100k files) | 30 s | 60 s |
| Ingest 10 SARIF files | 1 s | 3 s |
| HTML report generation | 500 ms | 1.5 s |

Budgets are enforced with a CI performance job and published in the benchmark card. A regression above 20% blocks the release unless explicitly accepted.

---

## 13. Supply chain, compliance, and trust

### 13.1 SBOM and licenses

- Generate CycloneDX 1.6 and SPDX 2.3 from supported lockfiles.
- Include component name, version, ecosystem, purl, hashes, licenses, and dependency relationships.
- License policy: allowlist, denylist, and review list for direct and transitive dependencies.
- Distinguish “unknown license” from “disallowed license.”
- Produce a license report separate from the security gate; do not mix categories silently.
- SBOM for Aegis itself on every release.

### 13.2 VEX and advisory context

- Import OpenVEX to suppress “not affected” dependency findings with an owner, reason, and expiry.
- Export VEX alongside the SBOM.
- Never let a VEX statement hide a finding without an audit trail.
- Link findings to advisories and fixed versions.

### 13.3 Release trust

Stage the claims:

1. **Checksums** for every artifact.
2. **Sigstore/cosign signatures** for release artifacts and container images.
3. **SBOM + provenance** attached to the release.
4. **SLSA provenance** where the build platform supports it.
5. **Reproducibility** only after an independent build verifies bit-identical artifacts; otherwise say “not yet verified.”

Artifacts:

- PyPI sdist and wheel.
- Zipapp for Python users.
- Standalone binary for users without Python (PyInstaller or similar; document the trade-offs).
- Docker image (digest-pinned).
- Homebrew and Scoop formulae.
- GitHub Action and reusable workflow.

### 13.4 Self-protection

- Scan Aegis with Aegis in CI (dogfooding) using the strict profile.
- Run the dependency and license gate on every PR.
- Generate an SBOM for each release.
- Verify signatures in the release workflow and in the installer where practical.
- Publish a supported-versions table and an end-of-life policy.

### 13.5 Honest limitations

Publish and maintain:

- Supported languages, frameworks, and versions.
- Known false-positive classes.
- Known false-negative classes.
- What is not scanned (generated code, minified bundles, binary blobs, secrets in images).
- Benchmark scope, dataset licenses, and dates.
- The exact meaning of every confidence label.

A limitations page is a trust feature, not an admission of weakness.

---
## 14. Bring-your-own-AI assistant (opt-in, non-authoritative)

The goal is not to put a chatbot in a security tool. The goal is to reduce the time between “what is this finding?” and “what should I do?” without sending source code anywhere by default.

### 14.1 Provider model

| Mode | Provider | Default | Requirements |
|---|---|---|---|
| Disabled | none | Yes | No network, no model, no context extraction. |
| Local | Ollama, LM Studio, vLLM, OpenAI-compatible | No | User runs the model; endpoint is loopback. |
| External | Anthropic, OpenAI, custom | No | Explicit opt-in, user-supplied key, documented egress. |

- Keys come from an environment variable or the OS keychain; never from the repository, a report, or a log.
- The GUI never stores a key on disk.
- `aegis ask --offline` fails closed if a provider is not local.
- A network-egress notice is printed before any external request.

### 14.2 Context minimization

- Build a context pack from the finding, its code window, the rule description, the triage state, and relevant commit metadata.
- Default window: the finding plus a small number of surrounding lines; never the full repository.
- Redact secrets and high-entropy strings before packaging.
- Hash or omit file paths that match configured sensitive patterns.
- Show the exact context that would be sent and require confirmation the first time.
- Token budget and truncation are explicit; no silent dropping of critical context.

### 14.3 Safety and prompt-injection controls

- Treat repository content as untrusted text, not instructions.
- Delimit untrusted code in the prompt and instruct the model to ignore embedded instructions.
- No tool execution from model output by default. Any tool call must be from an allowlisted set and require user confirmation.
- Validate model output against a schema before display.
- Never auto-apply a model-suggested fix; route it through the normal fix preview.
- Log the request metadata (provider, model, token count, duration), not the code.
- Rate-limit and time out; a slow provider must not block a scan.
- Refuse to send secrets, even if the user asks, unless an explicit unsafe override is documented and logged.

### 14.4 Evaluation

- A golden set of finding explanations with expected citations.
- Hallucination checks: every claim about the code must cite a file and line.
- Fix-suggestion tests: the suggested patch must apply and pass the relevant tests, or be labeled unsafe.
- Latency and cost budgets per request.
- A published evaluation card for any model claim.

### 14.5 Non-goals

- No AI-only blocking findings.
- No automatic exploit generation.
- No hidden model routing.
- No training on user code.
- No “AI detected a vulnerability” marketing without a reproducible finding.

---

## 15. Execution plan

### 15.1 Capacity assumptions

The estimates below assume one experienced maintainer working roughly 30 focused hours per week, with community contributions for rules and docs. At that pace, a credible v1.0 is a 9–12 month project and the full vision is 18–24 months. With two engineers, parallelize detection and platform work and target v1.0 in 5–7 months; with three, add release/trust and community and target 3–5 months. Long procurement or legal delays are excluded.

The plan is deliberately front-loaded with the work that is hardest to retrofit: licensing, schema, benchmark, and policy.

### 15.2 Phase 0 — Hygiene and baseline (weeks 0–2)

**Goal:** make the project legally and operationally safe to build on.

Deliverables:

- Apache-2.0 `LICENSE`, `NOTICE`, third-party notices, SPDX headers for new files.
- `SECURITY.md`, `CODE_OF_CONDUCT.md`, DCO policy, issue and PR templates.
- Naming gate documented; `aegis` CLI and `aegis-sast` distribution chosen provisionally.
- Rename plan and compatibility aliases; `aegis migrate` design.
- CI matrix: Linux, macOS, Windows; Python 3.11–3.13; lint, type check, tests, package build.
- Baseline report: freeze current counts and test results in `docs/BASELINE.md`; commit and tag the measured tree.
- `bench/` skeleton with a scorer interface and one small labeled fixture.
- Release checklist and versioning policy.

Exit criteria:

- A new contributor can clone, install, test, and build in under 10 minutes.
- CI is green on all supported platforms.
- The license and security files are present.
- The baseline report is reproducible by a script.

Cut line: none. Phase 0 is not optional.

### 15.3 Phase 1 — MVP, v0.9 (months 0–6)

**Goal:** one fast gate that is measurably better than the current scanner and safe to try.

Deliverables:

- `Finding` schema v3 with engine, category, confidence, spans, fixes, references, and flows.
- Engine protocol and registry; regex and AST engines wrapped; runner with timeouts, parallelism, merge, and dedupe.
- Policy v1: threshold, new-code, budgets, ratchet, profiles, `policy validate`, `policy explain`.
- SARIF 2.1.0 emit and ingest with fixtures.
- CLI commands: `scan`, `gate`, `ingest`, `report merge`, `policy`, `triage`, `baseline`, `rules`, `doctor`, `status`.
- Local GUI updated to the new actions and schema; loopback security tests.
- GitHub Action and pre-commit hook updated; install-to-first-finding demo.
- Benchmark harness: rule corpus, small labeled fixture, regression threshold in CI.
- Determinism and redaction tests across all report formats.
- Migration from CommitGuard with compatibility aliases.

Exit criteria:

- `pipx install aegis-sast && aegis init && aegis scan --staged` works on a clean machine with no network.
- Five tools’ SARIF/native output normalize into one report and one exit code.
- A policy with a ratchet blocks a synthetic regression and allows existing debt.
- Median staged diff scan is under 2 seconds on the reference medium fixture.
- All existing tests pass; new tests cover every new module.

Cut line: defer IDE, watch mode, IaC/container adapters, SBOM, and AI. Do not defer schema, policy, benchmark, or security tests.

### 15.4 Phase 2 — Credible 1.0 (months 6–12)

**Goal:** a release that a security team can evaluate without excuses.

Deliverables:

- Optional Semgrep/Opengrep adapter with license review and contract tests.
- Python taint expansion: sources, sinks, sanitizers, aliases, code flows, cross-file summaries.
- Additional taint packs for JavaScript/TypeScript.
- LSP diagnostics and quick fixes; VS Code extension skeleton.
- `aegis watch`.
- PR summary and inline suggestions for GitHub and GitLab; Bitbucket and Azure next.
- SCA: transitive dependencies, version ranges, six ecosystem fixtures, signed OSV snapshot.
- SBOM (CycloneDX and SPDX) and license policy.
- Static dashboard with trends and ownership grouping.
- Signed releases, checksums, SBOM for Aegis, Docker image, zipapp.
- Published benchmark card and limitations page.
- Migration guide and compatibility tests.
- Dogfooding: Aegis scans itself with the strict profile.

Exit criteria:

- v1.0 release candidate passes the benchmark gate on the supported CWE subset.
- Zero findings on the fixed-commit corpus for stable rules.
- A user can install, scan, triage, and produce an SBOM without a network.
- A security reviewer can verify signatures, checksums, and the SBOM offline.
- An IDE user sees diagnostics and a safe fix in VS Code.
- The migration path from CommitGuard is tested end to end.

Cut line: defer multi-repo merge, compliance packs, plugins, AI, and additional languages. Do not defer signing, SBOM, benchmark, or migration.

### 15.5 Phase 3 — Category tool, v1.x (months 12–18)

**Goal:** become the default local control plane for the target niche.

Deliverables:

- IaC and container ingestion (Trivy, Checkov, Grype) and native high-signal checks.
- Compliance mapping packs (OWASP, CWE, ASVS, PCI-DSS) with caveats.
- Multi-repo and multi-job report merge.
- Triage ownership, expiry, and audit UI/CLI polish.
- Plugin API v1 with out-of-process execution, manifests, signatures, and capability limits.
- Dashboard exports for CI artifacts and “bring your own storage.”
- More language packs based on benchmark demand.
- Package manager distribution: Homebrew, Scoop, Docker tags.
- Support playbook and commercial support option.

Exit criteria:

- Five tools plus Aegis normalize into one gate in a reference monorepo.
- A plugin can be installed, verified, and removed without affecting core behavior.
- A team can run a quarterly audit entirely from local artifacts.
- The benchmark shows no regression on supported languages.

Cut line: defer reachability, VEX, AI, and additional compliance frameworks.

### 15.6 Phase 4 — Ecosystem, v2.0 (months 18–24)

**Goal:** durable differentiation that is hard to copy.

Deliverables:

- Interprocedural taint for JavaScript/TypeScript, Java, and Go.
- SCA reachability and VEX import/export.
- Signed third-party rule packs and a community pack registry (git-based, no hosted service).
- AI assistant with local-first context packaging and published evaluation.
- Native binaries for users without Python, if the cost is justified by adoption.
- Public benchmark leaderboard with reproducible artifacts.
- Governance: maintainer council, release managers, security response team.

Exit criteria:

- A security team can replace a hosted scanner for the supported use cases and document why.
- Accuracy claims are reproducible by an independent party.
- At least one external contributor maintains a rule pack.
- The release process survives a maintainer absence.

Cut line: this phase is explicitly allowed to slip. Phases 1–3 must not.

### 15.7 Weekly operating cadence

- **Monday:** choose the week’s one primary outcome and one measurable check.
- **Daily:** small commits, tests first for parsers and policy, no broken main.
- **Wednesday:** benchmark run; compare against the last four weeks.
- **Friday:** demo, changelog draft, risk review, and next-week cut decision.
- **Every four weeks:** release or release candidate; update the plan; retire a risk or add one.

### 15.8 Definition of done

A change is done only when:

- The behavior is specified and tested (positive and negative).
- The report/JSON/SARIF contract is updated if affected.
- The docs and changelog are updated.
- The benchmark impact is measured if detection changed.
- Security implications are reviewed if input parsing, plugins, network, or subprocesses changed.
- Cross-platform CI passes.
- The change can be reverted without data loss.

### 15.9 Work breakdown and dependency map

| Workstream | Key deliverables | Depends on | Phase | Effort (weeks at 30 focused hours/week) |
|---|---|---|---|---|
| Legal and identity | License, notices, naming, security policy, migration | None | 0 | 2 |
| Schema and engines | Finding v3, engine protocol, regex/AST wrappers | Legal | 1 | 3 |
| Runner | Parallelism, deadlines, merge, dedupe, failure isolation | Schema | 1 | 2 |
| Policy | Gate, budgets, ratchet, profiles, explain | Schema, runner | 1 | 3 |
| Interop | SARIF emit/ingest, adapters, merge | Schema, runner | 1 | 4 |
| Developer console | GUI schema update, security hardening, docs | Runner, policy | 1 | 2 |
| Benchmark | Datasets, scorer, CI gate, cards | Schema | 1 | 4 |
| Semgrep adapter | Contract tests, mapping, license gate | Runner, interop | 2 | 2 |
| Native taint | Python depth, JS/TS pack, code flows | Schema, benchmark | 2 | 5 |
| SCA depth | Transitive graph, ranges, fixtures, snapshot | Runner, benchmark | 2 | 4 |
| IDE | LSP, VS Code, watch | Policy, scan API | 2 | 3 |
| VCS review | PR summary, inline suggestions, checks | Policy, fixes | 2 | 2 |
| Supply chain | SBOM, license policy, VEX later | SCA | 2–3 | 2 |
| Release trust | Signing, SBOM, Docker, zipapp, checksums | All | 2 | 3 |
| Dashboards | Static HTML, trends, ownership | History, policy | 3 | 2 |
| IaC/containers | Ingest adapters, native gaps | Interop | 3 | 3 |
| Compliance | Mapping packs, report sections | Policy | 3 | 2 |
| Plugins | Protocol, manifests, signatures, sandbox | Runner | 3 | 4 |
| AI assistant | Provider layer, context, evaluation | Policy, triage | 4 | 4 |
| Docs and community | Guides, demo, migration, contribution | Ongoing | 0–4 | ongoing |

The critical path is **legal → schema → runner → policy → interop → benchmark → release**. Taint depth and Semgrep run in parallel after the runner exists. The table covers the core product; Phase 4 research, native binaries, and community work add roughly 4–8 months.

### 15.10 Cost and resource assumptions

| Item | Assumption | Mitigation if unfunded |
|---|---|---|
| CI runners | GitHub-hosted Linux plus periodic macOS/Windows | Run Linux on every PR; macOS/Windows nightly. |
| Signing | Sigstore/cosign is free; key management is time | Start with checksums and Sigstore keyless. |
| Benchmark compute | Local + CI; no GPU required | Keep datasets sampled and cached. |
| Domain and trademarks | Domain under $50/year; trademark search/registration can reach four figures | Use a provisional name and defer registration until adoption. |
| Packaging | PyPI and GitHub Releases are free | Delay Homebrew/Scoop until demand is proven. |
| Maintainer time | 30 focused hours/week | Cut Phase 3–4 scope before cutting quality. |
| Legal review | Needed for Semgrep rules, third-party fixtures, and the name | Do not ship ambiguous assets; keep them optional. |

---

## 16. Release and versioning

### 16.1 Versioning

- **Product line:** Aegis is a new distribution (`aegis-sast`) starting at `1.0.0`; CommitGuard `2.x` remains a maintenance line with security fixes for at least six months. Do not publish the rename as `2.2.0` and then switch to `1.0.0`, because users will see a version downgrade. If the project instead renames in place under the same package, publish `3.0.0` with a migration guide; do not silently reuse `2.x`.
- **CLI:** SemVer (`MAJOR.MINOR.PATCH`).
- **Config:** integer `config_version`; migration required for breaking changes.
- **Finding schema:** integer `schema_version`; additive changes do not bump it.
- **Rule packs:** independent semantic versions plus a content digest.
- **Policy:** integer `policy_version`.
- **Triage:** integer `version`.

### 16.2 Compatibility policy

- Two minor releases of deprecation notice for CLI flags, config keys, and env vars.
- Old config and baseline files are read with a warning; a migration writes new files and keeps a backup.
- Removed commands return a clear error with the replacement, never a stack trace.
- Report schema changes are additive for at least one major cycle.
- A `aegis migrate --dry-run` shows every change before writing.

### 16.3 Release gates

A release is blocked if any of the following is true:

- Tests, lint, type check, or packaging fails on any supported platform.
- The benchmark regression threshold is exceeded without an accepted waiver.
- A stable rule lacks corpus tests.
- The SBOM or third-party notices are missing.
- A known critical vulnerability affects a release dependency.
- The migration path is untested.
- The security policy or limitations page is stale.

### 16.4 Release cadence

- Patch releases as needed for security and correctness.
- Minor releases every 4–6 weeks during active development.
- A release candidate at least one week before a minor release.
- An LTS line after v1.0 for regulated users, with security fixes for 12 months.

### 16.5 Channels

PyPI (`aegis-sast`), pipx, zipapp, Docker, GitHub Action, pre-commit, Homebrew, Scoop, and a standalone binary when justified. Every channel has the same version, checksums, and SBOM.

---

## 17. Testing, quality, and benchmark protocol

### 17.1 Test layers

| Layer | Purpose | Gate |
|---|---|---|
| Unit | Pure functions, parsers, policy, fingerprints | Every commit |
| Golden | Byte-identical reports and SARIF | Every commit |
| Contract | Recorded tool fixtures; no external binary needed | Every commit |
| Integration | Fixture repositories, hooks, installer, GUI, Action | Every PR |
| Benchmark | Precision/recall/FPR/runtime | Weekly and release |
| Fuzz | SARIF, YAML/TOML, lockfiles, rules, diffs | Nightly |
| Performance | p50/p95 budgets on reference fixtures | Weekly and release |
| Cross-platform | Linux, macOS, Windows; Python 3.11–3.13 | Every PR |
| Dogfood | Aegis scans Aegis with the strict profile | Every PR |

### 17.2 Benchmark protocol

Every claim uses a benchmark card with:

- Dataset name, version, source URL, license, and checksum.
- Labels and how they were produced.
- Tool versions and exact commands.
- Configuration and policy profile.
- Metrics: TPR, FPR, precision, F1, runtime, and fixed-commit false positives.
- Confidence intervals or sample sizes.
- Raw artifact location and date.
- Known limitations and excluded cases.

Rules:

- No blended “accuracy” headline without the per-language and per-CWE breakdown.
- No tuning on the held-out set; keep a private or rotated holdout.
- No comparing against another tool without running it on the same data and configuration.
- No claim from a single repository or a cherry-picked rule.
- Negative results are published, not hidden.

### 17.3 Datasets

| Dataset | Use | License/notes |
|---|---|---|
| OWASP Benchmark (Java) | TPR/FPR baseline, Java taint | Verify license and version; record commit. |
| Juliet Test Suite subsets | CWE-specific recall | Large; select subsets with a documented script. |
| Semgrep rule test annotations | Rule portability | Rule and test licenses vary; verify before redistribution. |
| gitleaks / trufflehog fixtures | Secret detection | Verify licenses; do not vendor without permission. |
| Public CVE fix pairs | Regression corpus | Fetch metadata on demand; do not vendor repositories. |
| Synthetic framework fixtures | Framework sources/sinks | Authored by the project; safe to redistribute. |
| Internal hostile fixtures | Parser and resource limits | Authored by the project; never run untrusted code. |

### 17.4 Regression thresholds

- Any new false positive on the non-vulnerable corpus blocks a release unless explicitly accepted.
- A stable rule must keep its positive corpus passing at 100%.
- A detection change may not reduce recall on the benchmark by more than 2 percentage points without a written waiver.
- A performance regression above 20% blocks a release unless the benchmark card is updated with a rationale.
- A new parser must have fuzz coverage and a size limit.

### 17.5 Rule quality bar

A rule is stable only when it has:

- A precise positive sample.
- At least two negative samples, including a lookalike.
- A documented CWE, category, confidence, and remediation.
- A false-positive analysis.
- A severity justification.
- A test that runs in CI.
- A provenance entry.
- A deprecation path.

---

## 18. Threat model for Aegis itself

### 18.1 Assets

- Source code and diffs.
- Secrets accidentally present in code or history.
- GitHub/GitLab tokens and AI provider keys.
- Rule packs and plugin binaries.
- Reports, SBOMs, and audit logs.
- Release artifacts and signing keys.
- User trust and the integrity of the gate.

### 18.2 Adversaries and trust boundaries

| Adversary | Capability | Trust boundary |
|---|---|---|
| Malicious repository author | Controls files, paths, symlinks, diffs, lockfiles, config, comments | Repository content is untrusted. |
| Malicious rule-pack author | Controls YAML/TOML, regexes, metadata | Rule packs are untrusted until verified. |
| Compromised third-party tool | Emits hostile SARIF/JSON | Ingested reports are untrusted. |
| Network attacker | Intercepts optional online lookups | Network is untrusted; TLS and checksums required. |
| Malicious plugin | Arbitrary code if loaded in-process | Plugins are untrusted; out-of-process by default. |
| Compromised dependency | Supply-chain attack | Dependencies are pinned, scanned, and SBOM-tracked. |
| Insider or compromised CI | Can alter policy or baseline | Changes are reviewed and audited; tokens are scoped. |
| LLM prompt injection | Instructions embedded in code/comments | Model output is untrusted; no automatic actions. |

### 18.3 Controls

- Canonicalize and validate every path; reject absolute paths, `..`, and paths outside the repository.
- Define symlink behavior explicitly; never follow a symlink outside the repository.
- Enforce file size, diff size, line length, nesting depth, and finding-count limits.
- Invoke subprocesses with argument lists, never a shell; scrub the environment of tokens where possible.
- Apply timeouts to every parser and engine; kill process groups on cancellation.
- Validate SARIF and rule schemas before use; never execute URLs or commands from them.
- Escape terminal output to prevent escape-sequence injection; escape HTML in reports.
- Redact secrets by default in every output path, including errors and logs.
- Store no secrets in config, reports, cache, history, or GUI state.
- Verify signatures and checksums for downloaded engines, rule packs, snapshots, and plugins.
- Treat plugin output as untrusted; validate and cap it.
- Never auto-load plugins or rules from a scanned repository.
- Use a strict CSP and loopback binding for the GUI.
- Run a network-disabled test in CI to prove offline behavior.
- Publish a threat model and a disclosure process.

### 18.4 Abuse cases to test

- A repository with a 1 GB file, a deeply nested YAML rule, or a catastrophic regex.
- A symlink that points outside the repository.
- A file named with terminal control characters.
- A SARIF file with a million results or a cyclic structure.
- A rule pack that tries to read `/etc/passwd` or spawn a process.
- A plugin that hangs, allocates memory, or writes to stdout indefinitely.
- A prompt-injection comment that asks the AI to exfiltrate a file.
- A malicious lockfile that triggers pathological version parsing.
- A diff that deletes or renames thousands of files.
- A report with a secret in the message, snippet, or stack trace.

---

## 19. Distribution, adoption, and community

### 19.1 Documentation

Information architecture:

- **Start:** install, first scan, fix a finding, understand exit codes.
- **Concepts:** engines, policy, baseline, triage, fingerprints, confidence.
- **How-to:** pre-commit, GitHub Actions, GitLab, Jenkins, Azure, Docker, air-gap.
- **Rules:** authoring, testing, provenance, suppression, deprecation.
- **Integrations:** each tool and each VCS.
- **Benchmarks:** cards, datasets, methodology, limitations.
- **Security:** threat model, disclosure, supported versions.
- **Contributing:** DCO, style, tests, rule review, release process.
- **Migration:** CommitGuard to Aegis, config and baseline changes.

### 19.2 Launch assets

- A demo repository that fails a commit in 30 seconds and auto-fixes it.
- A two-minute quickstart video.
- A network-off air-gap demo.
- Comparison pages that are factual and link to benchmark cards: “Aegis and SonarQube,” “Aegis as a pre-commit gate,” “Aegis for air-gapped teams.”
- A migration guide with before/after commands.
- A “how we measure” page.
- A public roadmap with cut lines.

### 19.3 Community

- Issue templates for bug, false positive, false negative, rule request, and integration.
- A false-positive label and a fast triage path; false-positive reports are product feedback, not noise.
- Good-first-issue backlog for docs, adapters, and rule tests.
- Rule contribution guide with the quality bar and provenance requirements.
- Monthly office hours and a public changelog.
- A code of conduct and a moderation policy.
- A maintainer ladder: contributor → reviewer → maintainer, with explicit responsibilities.
- A release manager rotation after v1.0.

### 19.4 Partnerships

- Semgrep/Opengrep: optional engine, no bundling without licensing clarity.
- OSV: snapshot format and advisory metadata.
- Sigstore/OpenSSF: signing, provenance, and best practices.
- Package ecosystems: lockfile fixtures and version semantics.
- CI providers: first-class templates and reusable workflows.

### 19.5 Adoption sequence

1. Existing CommitGuard users: migration, compatibility, no surprise breakage.
2. Pre-commit and GitHub Actions users: two-minute install and a useful first finding.
3. Air-gapped and regulated teams: network-off proof, signed artifacts, SBOM, support.
4. Teams with existing scanners: ingestion, dedupe, one policy, one report.
5. Platform teams: plugin interface, multi-repo merges, dashboards, compliance mappings.

---

## 20. Risks and mitigations

| Risk | Early warning | Mitigation | Trigger / stop rule |
|---|---|---|---|
| Scope creep into a platform | “Just add SSO/dashboards/users” requests | Enforce non-goals; require every feature to work offline in one process | If a request needs a persistent service, reject it and point to integrations. |
| Semgrep licensing | Legal review finds redistribution restrictions | Optional binary; no bundled rules; Opengrep alternative; provenance | If licensing is unresolved, ship without Semgrep and keep regex/AST. |
| Becoming a thin Semgrep wrapper | Most value comes from one optional engine; built-in detection stagnates | Invest in native taint, policy, aggregation, fixes, and trust; benchmark both paths | If built-in detection cannot stand alone, reposition as an aggregator, not a scanner. |
| False-positive fatigue | Rising false-positive issues; users disable the hook | Conservative defaults, confidence labels, triage, benchmark gate | If FPR exceeds 5% on the corpus, block release and tune. |
| Rule maintenance burden | Stale rules; broken upstream packs | Provenance, pinning, generated tests, deprecation policy | If a pack cannot be tested, remove it from the default set. |
| Performance on monorepos | p95 exceeds budget; watch mode lag | Incremental cache, change-aware scope, parallel engines, limits | If p95 exceeds 2× budget, cut breadth before shipping. |
| Cross-platform drift | Windows path or encoding failures | CI matrix, fixtures, no shell assumptions | If Windows is broken for a release, fix or mark unsupported explicitly. |
| Trust deficit | “Another scanner” skepticism | Signed releases, benchmark cards, limitations page, transparent incidents | If a claim cannot be reproduced, retract it publicly. |
| Name/trademark conflict | Legal objection or package confusion | Naming gate, fallbacks, clear distribution name | If blocked, rename before public launch, not after. |
| Maintainer burnout | Missed releases; issue backlog | Cut lines, community roles, sustainable scope, sponsorship | If cadence slips two cycles, reduce scope and publish the change. |
| AI leakage or hallucination | Prompt-injection test failure; incorrect explanation | Local-first, redaction, schema validation, no auto-actions, evaluation | If a leak or unsafe auto-action occurs, disable external AI by default. |
| Plugin supply chain | Malicious plugin report | Out-of-process, signatures, capabilities, no auto-load | If sandboxing is unproven, keep plugins experimental. |
| Benchmark overfitting | Scores rise without real-world improvement | Held-out sets, private corpus, regression corpus, external review | If a rule only works on the benchmark, remove it. |
| Data loss from fixes | User reports a bad applied fix | Preview, safe levels, patch file, tests, no auto-fix for secrets | If a destructive fix ships, revert, add a test, and publish an advisory. |
| Funding | Maintainer time unavailable | Sponsorship, support contracts, grants, scoped milestones | If unfunded, ship Phases 0–2 and stop; do not fake the rest. |
| GitHub dependency | Action/API changes or outages | CLI-first, generic CI, GitLab/Azure support | If GitHub changes break the Action, the CLI still works. |

---

## 21. Decisions and open questions

| Decision | Recommendation | Reversible? | Deadline |
|---|---|---|---|
| Product name | Aegis, subject to trademark clearance | No after launch | Phase 0 |
| Distribution name | `aegis-sast` | Yes | Phase 0 |
| License | Apache-2.0 | No after contributions | Phase 0 |
| Default engine set | Built-in regex + AST; Semgrep optional | Yes | Phase 1 |
| Semgrep vs Opengrep | Support both; default to whichever is installed; legal review first | Yes | Phase 2 |
| Triage storage | Committed YAML by default; CI artifacts optional | Yes | Phase 1 |
| History storage | JSONL by default; SQLite optional | Yes | Phase 3 |
| Plugin model | Out-of-process, signed manifests, no auto-load | Yes | Phase 3 |
| AI default | Disabled; local-first when enabled | Yes | Phase 4 |
| Minimum Python | 3.11 through 3.13 for v1.0 | No for a major | Phase 1 |
| Binary packaging | Zipapp first; standalone only if adoption justifies it | Yes | Phase 2 |
| Commercial model | Support, training, curated packs; core stays Apache-2.0 | Yes | Phase 3 |
| Benchmark holdout | Private rotating set plus public datasets | Yes | Phase 1 |
| GUI scope | Local console only; static HTML for CI | Yes | Phase 1 |
| Rename timing | Before v1.0 public launch | No after | Phase 2 |
| Version line | Aegis starts at `1.0.0` in `aegis-sast`; CommitGuard `2.x` gets six months of security fixes | Yes | Phase 1 |

Open questions that must be answered with evidence, not opinion:

- Which two languages get the first credible taint claim? Recommendation: Python and JavaScript/TypeScript.
- Is Semgrep’s rule corpus legally redistributable in the target jurisdictions? Recommendation: assume no until reviewed.
- Does the target buyer value SBOM/license policy as much as SAST? Recommendation: validate with 10 interviews before Phase 3.
- Will users accept a committed triage file, or do they expect a UI? Recommendation: committed file first, GUI as a viewer/editor.
- Is a standalone binary worth the maintenance cost? Recommendation: only after 1,000+ Python installs and repeated requests.
- What is the minimum viable compliance mapping that is defensible? Recommendation: OWASP Top 10 + CWE Top 25 first.

---

## 22. First twenty commits

Each commit is small, tested, and independently reviewable.

1. Add `LICENSE` (Apache-2.0), `NOTICE`, `THIRD_PARTY_NOTICES.md`, license metadata, and SPDX headers for new files.
2. Add CI matrix (Linux/macOS/Windows, Python 3.11–3.13), lint, type check, package build, and a baseline test artifact.
3. Add `SECURITY.md`, `CODE_OF_CONDUCT.md`, DCO policy, issue templates, and PR template.
4. Add the naming/licensing decision record and the `aegis`/`aegis-sast` compatibility aliases.
5. Add `aegis migrate --dry-run` and migration tests from a CommitGuard-installed fixture.
6. Freeze the baseline in `docs/BASELINE.md` and add a script that reproduces every measured number.
7. Add `bench/` with a dataset manifest, scorer interface, and one labeled fixture.
8. Extend `Finding` to schema v3 (engine, category, confidence, spans, fix, references, flows) with golden tests.
9. Add `core/engines/base.py` (protocol, capability, result, registry) and tests.
10. Wrap the regex engine behind the protocol; prove report-byte compatibility.
11. Wrap the AST taint engine behind the protocol; preserve existing findings.
12. Add `core/engines/runner.py` with parallelism, deadlines, failure isolation, merge, and dedupe.
13. Add policy v1: `[gate]` config, new-code, budgets, ratchet, profiles, validate, explain.
14. Add SARIF 2.1.0 emit/ingest with schema validation and P1 adapter fixtures (Semgrep, CodeQL, Trivy, Checkov, gitleaks).
15. Add `ingest`, `report merge`, and `gate` commands with stable JSON and exit codes.
16. Add the Semgrep adapter contract test (skip if absent) and the license review checklist.
17. Expand Python taint: sources, sinks, sanitizers, aliases, code flows, cross-file fixtures.
18. Add SCA transitive resolution and six lockfile fixtures, with a signed-snapshot design.
19. Add P1 native adapters (Trivy, Checkov, gitleaks, Bandit, ruff) with recorded fixtures and golden outputs.
20. Cut v0.9: docs, migration guide, demo repository, checksums, SBOM, and the release workflow.

After these twenty commits, Aegis has a credible MVP plus early v1.0 foundations. The remaining phases are about depth, trust, and adoption — not about discovering what the product is.

---

## Appendix A — CLI surface (target)

```text
aegis install                 # optional compatibility/install helper
aegis init                    # write a commented config
aegis scan                    # staged / diff / all / history / pre-push
aegis gate                    # evaluate policy on a report
aegis ingest                  # normalize SARIF/native output
aegis policy validate|explain
aegis triage list|accept|false-positive|wont-fix|fixed|prune|audit
aegis baseline update|audit
aegis rules list|check|explain|test
aegis report merge
aegis sbom                    # CycloneDX / SPDX
aegis license                 # dependency license policy
aegis dashboard               # static HTML from local artifacts
aegis watch                   # incremental local loop
aegis lsp                     # stdio language server
aegis ask                     # opt-in AI assistant
aegis migrate                 # CommitGuard/Aegis -> Aegis
aegis doctor                  # environment and install diagnostics
aegis status                  # version, engines, rules, policy
aegis version
```

Compatibility: `commit-guard <command>` remains an alias until v2.0.

## Appendix B — Configuration v2 (target shape)

```toml
config_version = 2

[scan]
mode = "staged"              # staged | diff | all | history | pre-push
scope = "function"           # line | function | file
confidence_floor = "low"
workers = 4
cache = true
offline = true

[engines]
enabled = ["regex", "ast", "sca"]

[engines.semgrep]
enabled = false
command = "semgrep"
timeout = 120
rules = ".aegis/semgrep"
license_ack = false

[gate]
profile = "balanced"         # strict | balanced | audit | pci | asvs
fail_on = "new"              # all | new
threshold = "high"
ratchet = true
max_new = { critical = 0, high = 0, medium = 25, low = 100 }

[triage]
file = ".aegis_triage.yaml"

[ingest]
sarif_paths = []
tools = ["semgrep", "codeql", "trivy", "checkov", "gitleaks"]

[supply_chain]
sbom = "cyclonedx"
license_policy = "allowlist"

[reports]
directory = "aegis_reports"
formats = ["markdown", "json", "sarif", "html"]

[integrations.github]
enabled = false
comment = true
suggest_fixes = true

[ai]
enabled = false
provider = "local"           # local | external | disabled
endpoint = "http://127.0.0.1:11434/v1"
model = ""
```

## Appendix C — Exit codes and gate JSON

Exit codes: `0` pass, `1` gate failure, `2` operational/config error. Gate JSON includes:

```json
{
  "schema_version": 1,
  "passed": false,
  "profile": "balanced",
  "new_findings": 3,
  "blocking": 2,
  "reasons": [
    {"rule_id": "aegis/python/sql-injection", "path": "app/db.py", "line": 42, "reason": "new high finding"}
  ],
  "budgets": {"critical": 0, "high": 0},
  "suppressed": {"baseline": 12, "triage": 4, "inline": 1},
  "tool_versions": {"aegis": "1.0.0", "semgrep": "1.x"}
}
```

## Appendix D — Benchmark card template

```markdown
# Benchmark card: <dataset> / <version>

- Dataset: <name, version, commit, license, checksum>
- Labels: <how produced, by whom, date>
- Tool versions: <aegis, engines, comparison tools>
- Command: <exact command and config>
- Metrics: TPR, FPR, precision, F1, runtime, fixed-commit false positives
- Breakdown: per CWE, per language, per severity
- Sample sizes / confidence intervals:
- Raw artifact: <path, digest>
- Limitations:
- Reviewer/date:
```

## Appendix E — Evidence and claim checklist

Before publishing any claim:

- [ ] Is the dataset named and licensed?
- [ ] Is the version/commit recorded?
- [ ] Is the command recorded and reproducible?
- [ ] Is the comparison run on the same data and configuration?
- [ ] Is the metric defined?
- [ ] Are sample sizes or confidence intervals stated?
- [ ] Is the raw artifact available?
- [ ] Are the limitations stated?
- [ ] Would an independent reviewer reach the same conclusion?

If any answer is no, the claim is not ready.

## Appendix F — Naming and release checklist

- [ ] Trademark search in relevant jurisdictions.
- [ ] PyPI/npm/crates/GitHub availability.
- [ ] Domain and social handles reserved only after clearance.
- [ ] Distribution name and CLI name documented.
- [ ] Migration aliases tested.
- [ ] Action/package names updated with redirects.
- [ ] License and notices audited for every bundled rule pack.
- [ ] Security policy and disclosure channel live.
- [ ] Signed artifacts and SBOM generated.
- [ ] Limitations page published.

## Appendix G — Migration from CommitGuard

1. Run `aegis migrate --dry-run` and review every change.
2. Back up `.commit_guard/`, `.commit_guard.toml`, and `.commit_guard_ignore`.
3. Create `.aegis/` and `.aegis.toml`; keep old files until the next minor release.
4. Keep fingerprints unchanged so the baseline remains valid.
5. Update hooks, CI, pre-commit, and Action references.
6. Run `aegis scan --all` and compare the report to the last CommitGuard report.
7. Remove the old install only after two successful releases.

## Appendix H — 30/60/90-day plan

**Days 1–30:** license, CI matrix, naming gate, baseline, benchmark skeleton, schema v3, engine protocol, regex wrapper, runner.

**Days 31–60:** policy v1, SARIF ingest/emit, ingest/merge/gate commands, tests, GUI schema update, migration, first benchmark threshold.

**Days 61–90:** AST wrapper, Semgrep adapter (gated), Python taint expansion, LSP skeleton, demo repository, v0.9 release candidate.

The 90-day goal is not a finished product. It is a trustworthy MVP with a measurement system and a migration path.

---

## Closing statement

Aegis should be judged by a simple test: **does it make the secure path the fast path for a developer, without asking them to trust a black box?**

Every section of this plan serves that test. The scanner must be fast. The policy must be reviewable. The fixes must be safe. The reports must be honest. The releases must be verifiable. The tool must work with the network off. And the project must be brave enough to publish what it does not detect.

That is how a local scanner becomes a security control plane — and how Aegis becomes the tool developers keep installed.
