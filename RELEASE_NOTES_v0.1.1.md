# Sentinel-Code: What's New in Version v0.1.1 (vs. v0.1.0)

> **Release Version:** v0.1.1  
> **Previous Version:** v0.1.0 (v1.0 baseline)  
> **Release Date:** October 14, 2026  
> **Status:** Production-Ready CLI & CI/CD Gatekeeper  
> **Detailed Benchmark Report:** [docs/assets/gold_standard_benchmark_results.md](docs/assets/gold_standard_benchmark_results.md)

---

## Executive Summary

Sentinel-Code **v0.1.1** transforms Sentinel from an early experimental prototype into an **enterprise-grade, production-ready AI security gatekeeper and pre-commit auditor**. 

While **v0.1.0** was a minimal proof-of-concept (free-form prompt evaluation, a single hardcoded 6,000-character truncation limit, unmasked secrets sent over the wire, 5 basic rules, and an un-gated CLI), **v0.1.1** introduces **Pydantic structured schema validation**, an on-device **Zero-Token Privacy Shield (secret redaction)**, **smart multi-file chunking with risk scoring**, **SARIF v2.1.0 reporting**, **CI/CD exit-code gating**, **native pre-commit hooks**, **global cross-platform CLI launchers**, **28 comprehensive security rules**, and an automated **precision/recall evaluation suite** tested against Gemini 2.5 Flash and compared with Semgrep and Gitleaks.

---

## Quick Comparison: v0.1.0 vs. v0.1.1

| Capability / Feature | v0.1.0 (Baseline) | v0.1.1 (Current Release) | Impact / Advantage |
| :--- | :--- | :--- | :--- |
| **Output Type** | Free-form markdown string | Typed Pydantic Schema (`AuditResult`, `Finding`) | Machine-readable, deterministic parsing, zero prompt hallucination |
| **Privacy & Secret Redaction** | ❌ None (raw secrets transmitted to LLM API) | ✅ Local regex engine masks secrets before network calls | Zero-token privacy protection; catches credentials locally |
| **Reporting Formats** | Terminal string only | Markdown, JSON, and standard SARIF v2.1.0 | Compatible with GitHub Code Scanning, GitLab SAST, & CI dashboards |
| **Diff Budget & Chunking** | Single hardcoded cap (6,000 chars) | Smart multi-file chunking (≤30k tokens/chunk, max 5 chunks) | Audits massive diffs (up to ~600,000 chars) systematically |
| **Risk-Based Scheduling** | First-come, first-served | Heuristic risk scoring (`_file_risk_score`) | High-risk files (auth, tokens, configs, routes) audited first |
| **Partial Audit Protection** | ❌ False "Audit Passed" risk if diff truncated | ✅ Explicit truncation warnings; refuses false pass | Strict audit integrity; guarantees developers know what was skipped |
| **CI/CD & Exit-Code Gating** | ❌ Exited 0 unconditionally | ✅ `--fail-on [high\|medium\|low\|any\|none]`, `--fail-on-incomplete` | Blocks malicious PRs and broken commits in pipelines |
| **Pre-Commit Integration** | ❌ Manual CLI execution only | ✅ Native Git hook (`pre-commit-hook.sh`) + `.pre-commit-config.yaml` | Zero-friction automated gatekeeper before code is committed |
| **Cross-Platform Global CLI** | ❌ Project-local script execution only | ✅ Native `sentinel.bat` (Windows) and `sentinel` (macOS/Linux) | Run `sentinel` in any Git repository on your system |
| **Security Guidelines** | 5 generic baseline rules | 28 comprehensive enterprise security rules (+23 new) | Covers OWASP Top 10, CWEs, XSS, SSRF, crypto, and auth flaws |
| **Prompt Injection Defense** | Basic ``` escape | `<code_diff>` data fencing, closing tag sanitization, backtick escaping | Blocks malicious injection attempts embedded inside code diffs |
| **Concurrency** | Synchronous sequential execution | Asynchronous batching (`asyncio.gather` with Semaphore=3) | Faster multi-file processing without hitting API rate limits |
| **Validation Suite** | 0 privacy tests; basic filter tests | 33 unit tests (100% pass) + Gold-Standard benchmark suite | Evaluated across Meta CyberSecEval, SecurityEval, CredData, and CVEFixes |

---

## Detailed Breakdown of What Was Achieved

### 1. Local Privacy Shield & Secret Redaction (`core/redact.py`)
In v0.1.0, diffs containing API keys or database passwords were sent directly to Google Gemini unmasked. v0.1.1 introduces an on-device privacy engine:
- **Zero-Token Local Masking:** Evaluates staged diffs locally on your machine before any network transmission.
- **Recognized Credential Patterns:** Google API Keys (`AIza...`), AWS Access Keys (`AKIA...`), GitHub Tokens (`ghp_...`), Slack Tokens (`xoxb-...`), Stripe Keys (`sk_live_...`), Standard API Keys (`sk-...`), JWTs (`eyJ...`), PEM Private Keys, Database connection URLs with passwords, quoted assignments (`api_key = "..."`), and unquoted `.env` assignments.
- **Safe LLM Prompting:** Replaces secrets with `[REDACTED:<type>]` tokens so the LLM flags Rule #1 violations without ever receiving raw secret material.
- **Local Scanner for Documentation:** Scans `.md`, `.txt`, and non-code files for leaked credentials using `find_secret_matches()` with **0 LLM tokens**.

### 2. Pydantic Structured Output & Deterministic Schemas (`core/auditor_agent.py`)
In v0.1.0, the LLM returned arbitrary markdown strings which could break or hallucinate formatting.
- Defined strict Pydantic schemas:
  - `Finding`: `risk_level` (HIGH / MEDIUM / LOW), `file_path`, `rule`, `line`, and `fix`.
  - `ChunkAuditResult`: strongly-typed list of findings.
  - `AuditExecutionReport`: structured result containing report text, findings, local secret flags, and completeness status.
- Replaced raw text completions with LangChain's `.with_structured_output(ChunkAuditResult)` for Gemini 2.5 Flash.

### 3. Smart Multi-Diff Chunking & Heuristic Risk Prioritization
v0.1.0 truncated any diff larger than 6,000 characters with a blunt split. v0.1.1 implements a robust chunking architecture:
- **Multi-File Batching:** Combines diffs up to 30,000 tokens (~120,000 characters) per request.
- **Request Safety Budget:** Caps audits at 5 requests per run to strictly limit API usage.
- **Heuristic Risk Scoring (`_file_risk_score`):** Prioritizes files so high-risk security files (`auth`, `login`, `token`, `secret`, `jwt`, `crypto`, `routes`, `.env`) are audited in the earliest chunks before hitting budget caps.
- **Async Concurrency:** Executes chunks concurrently using `asyncio.gather` bounded by `asyncio.Semaphore(3)` to prevent rate limiting.

### 4. Partial-Audit Protection & Integrity
v0.1.0 suffered from a dangerous flaw: if a diff was truncated, the model could report "Audit Passed" on the un-truncated portion.
- **Integrity Enforcement:** Sentinel-Code v0.1.1 tracks whether any files were skipped or truncated.
- If incomplete, Sentinel-Code explicitly outputs a `[Partial Audit]` or `[Diff Truncated]` notice, lists every file that could not be analyzed, and **strictly refuses to issue a false "Audit Passed" status**.

### 5. Standard SARIF v2.1.0 & JSON Reporting
To support integration into enterprise DevSecOps pipelines:
- **SARIF v2.1.0:** Sentinel-Code generates standard OASIS SARIF output (`--format sarif`), enabling direct upload to **GitHub Code Scanning Alerts**, GitLab SAST dashboards, SonarQube, or VS Code SARIF viewers.
- **JSON Output:** Machine-readable JSON output (`--format json`) for custom CI/CD scripting.

### 6. CI/CD Gatekeeper & CLI Policy Controls (`interfaces/cli.py`)
In v0.1.0, the CLI simply printed text and always returned exit code 0. v0.1.1 functions as a strict gatekeeper:
- **Exit Code Protocol:** Returns `0` on clean diffs; returns `1` when security violations exceed policy thresholds or git commands fail.
- **Configurable CLI Flags:**
  - `--fail-on [high|medium|low|any|none]` (default: `high`): Configures the failure threshold.
  - `--fail-on-incomplete`: Exits with code `1` if changes were truncated or files were skipped due to budget caps.
  - `--format [markdown|json|sarif]`: Switches output formatting.
  - `--model`: Overrides the Gemini model on demand.

### 7. Native Git Hook & Pre-Commit Integration
- **Zero-Dependency Git Hook (`scripts/pre-commit-hook.sh`):** A shell script that developers can copy directly into `.git/hooks/pre-commit`.
- **Pre-Commit Framework Support (`.pre-commit-config.yaml`):** Supports Python `pre-commit` framework with clean stage filtering and exit-code enforcement.

### 8. Global Cross-Platform Launchers (`scripts/`)
- **Windows (`scripts/sentinel.bat`):** Native batch launcher that locates the virtual environment and bypasses Windows Store Python redirect shims.
- **macOS / Linux (`scripts/sentinel`):** Native shell script with executable permissions.
- Developers can add the `scripts/` directory to their system `PATH` and run `sentinel` against **any** local Git repository.

### 9. Expanded Security Rule Engine (`rules/security_rules.md`)
The rule set expanded from 5 baseline guidelines to **28 comprehensive enterprise security rules** (+23 new rules) covering Command Injection, XSS, Path Traversal, Insecure Deserialization, Weak Crypto, Insecure Randomness, Disabled TLS, Sensitive Logging, SSRF, Permissive CORS, IDOR, Insecure JWT, File Uploads, Input Validation, NoSQL/LDAP Injection, ReDoS, Open Redirects, and XXE.

---

## Benchmark & Quality Assurance Metrics

See the dedicated [Gold-Standard Benchmark Report](docs/assets/gold_standard_benchmark_results.md) for full empirical scores across Meta CyberSecEval, SecurityEval, CredData, and CVEFixes.

- **Empirical Accuracy:** ~71.4%–82.0% Precision and ~88.9%–94.1% Recall on industry-standard suites (realistically reflecting false-positive resistance against test mocks and allowlisted queries).
- **Unit Test Suite:** 33 automated tests passing in 0.17 seconds (26 pre-filter tests, 7 secret redaction tests).
- **Token Efficiency:** Benchmarked over commit histories demonstrating up to 48% token reduction and 55% skipped non-functional commits at < 1ms median latency.
