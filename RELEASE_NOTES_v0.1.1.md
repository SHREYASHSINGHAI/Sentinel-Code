# Sentinel-Code: What's New in Version v0.1.1 (vs. v0.1.0)

> **Release Version:** v0.1.1  
> **Previous Version:** v0.1.0 (v1.0 baseline)  
> **Release Date:** October 2026  
> **Status:** Production-Ready CLI & CI/CD Gatekeeper  
> **Detailed Benchmark Report:** [docs/assets/gold_standard_benchmark_results.md](docs/assets/gold_standard_benchmark_results.md)  
> **Unit Test Report:** [docs/assets/unit_test_result.md](docs/assets/unit_test_result.md)

---

## Executive Summary

Sentinel-Code **v0.1.1** transforms Sentinel from an early experimental prototype into an **enterprise-grade, production-ready AI security gatekeeper and pre-commit auditor**. 

While **v0.1.0** was a minimal proof-of-concept (free-form prompt evaluation, a single hardcoded 6,000-character truncation limit, unmasked secrets sent over the wire, 5 basic rules, and an un-gated CLI), **v0.1.1** introduces **Pydantic structured schema validation**, an on-device **Zero-Token Privacy Shield with diff-aware secret scanning**, **hunk-aware diff chunking and content-based risk scoring**, **SARIF v2.1.0 reporting**, **CI/CD exit-code gating with default-fail protection**, **native pre-commit hooks**, **global cross-platform CLI launchers**, **28 comprehensive security rules**, and an automated **82-test unit validation suite** along with gold-standard security benchmarks evaluated across Meta CyberSecEval, SecurityEval, CredData, and CVEFixes.

---

## Quick Comparison: v0.1.0 vs. v0.1.1

| Capability / Feature | v0.1.0 (Baseline) | v0.1.1 (Current Release) | Impact / Advantage |
| :--- | :--- | :--- | :--- |
| **Output Type** | Free-form markdown string | Typed Pydantic Schema (`AuditResult`, `Finding`) | Machine-readable, deterministic parsing, zero prompt hallucination |
| **Privacy & Secret Redaction** | ❌ None (raw secrets transmitted to LLM API) | ✅ Local regex engine masks secrets before network calls | Zero-token privacy protection; catches credentials locally |
| **Diff-Aware Secret Scanning** | ❌ None (secret in removed lines flagged as violation) | ✅ Differentiates added vs. removed vs. context lines | Deleting a secret or unchanged context line never triggers false alarms or blocks commits |
| **Mask Preview Privacy** | ❌ None | ✅ Shows prefix + asterisks (`AKIA********`), capped at 25% | Conceals full plaintext secret and exact character length in all reports |
| **Reporting Formats** | Terminal string only | Markdown, JSON, and standard SARIF v2.1.0 | Compatible with GitHub Code Scanning, GitLab SAST, & CI dashboards |
| **Diff Budget & Chunking** | Single hardcoded cap (6,000 chars) | Hunk-aware chunking (≤30k tokens/chunk, max 5 chunks) | Splits cleanly on git hunk boundaries; giant hunks split safely without losing context |
| **Risk-Based Scheduling** | First-come, first-served | Content-risk heuristic scoring (`core/risk.py`) | Added risky code (SQL injection, `eval`, secrets) audited first; decoy files cannot starve budget |
| **Partial Audit Protection** | ❌ False "Audit Passed" risk if diff truncated | ✅ Default-fail gatekeeper + explicit skipped file warnings | Incomplete audits fail by default; developers always know what was skipped |
| **CI/CD & Exit-Code Gating** | ❌ Exited 0 unconditionally | ✅ `--fail-on [high\|medium\|low\|any\|none]`, `--fail-on-incomplete` / `--no-fail-on-incomplete` | Blocks malicious PRs and broken commits in automated pipelines |
| **Pre-Commit Integration** | ❌ Manual CLI execution only | ✅ Native Git hook (`pre-commit-hook.sh`) + `.pre-commit-config.yaml` | Zero-friction automated gatekeeper before code is committed |
| **Cross-Platform Global CLI** | ❌ Project-local script execution only | ✅ Native `sentinel.bat` (Windows) and `sentinel` (macOS/Linux) | Run `sentinel` in any Git repository on your system |
| **Security Guidelines** | 5 generic baseline rules | 28 comprehensive enterprise security rules (+23 new) | Covers OWASP Top 10, CWEs, XSS, SSRF, crypto, and auth flaws |
| **Prompt Injection Defense** | Basic ``` escape | `<code_diff>` data fencing, closing tag sanitization, backtick escaping | Blocks malicious injection attempts embedded inside code diffs |
| **Concurrency** | Synchronous sequential execution | Asynchronous batching (`asyncio.gather` with Semaphore=3) | Faster multi-file processing without hitting API rate limits |
| **Validation Suite** | 0 privacy tests; basic filter tests | 82 unit tests (100% pass) + Gold-Standard benchmark suite | Evaluated across Meta CyberSecEval, SecurityEval, CredData, and CVEFixes |

---

## Detailed Breakdown of What Was Achieved

### 1. Local Privacy Shield & Diff-Aware Secret Scanning (`core/redact.py`, `core/diff_lines.py`)
In v0.1.0, diffs containing API keys or database passwords were sent directly to Google Gemini unmasked. v0.1.1 introduces an on-device privacy engine with diff-line awareness:
- **Zero-Token Local Masking:** Evaluates staged diffs locally on your machine before any network transmission.
- **Diff-Aware Classification:** Classifies lines into added (`+`), removed (`-`), and unchanged context (` `).
- **Zero False Alarms on Secret Removal:** When a developer removes a hardcoded credential or revokes a key, Sentinel-Code does **not** flag it as a violation or block the commit. Removed secrets are harmlessly sanitized as `[REMOVED_SECRET:<type>]`.
- **Safe Mask Previews:** Exposes only the first few identifying characters followed by asterisks (e.g. `AKIA********`, `AIza********`), reveals at most 25% of the secret, and conceals the true secret length to prevent brute-force inference.
- **Recognized Credential Patterns:** Google API Keys (`AIza...`), AWS Access Keys (`AKIA...`), GitHub Tokens (`ghp_...`), Slack Tokens (`xoxb-...`), Stripe Keys (`sk_live_...`, `rk_live_...`), Standard API Keys (`sk-...`), JWTs (`eyJ...`), PEM Private Keys, Database connection URLs with passwords, quoted assignments (`api_key = "..."`), and unquoted `.env` assignments.
- **Local Scanner for Documentation:** Scans `.md`, `.txt`, and non-code files for leaked credentials using `find_secret_matches()` with **0 LLM tokens**.

### 2. Pydantic Structured Output & Deterministic Schemas (`core/auditor_agent.py`)
In v0.1.0, the LLM returned arbitrary markdown strings which could break or hallucinate formatting.
- Defined strict Pydantic schemas:
  - `Finding`: `risk_level` (HIGH / MEDIUM / LOW), `file_path`, `rule`, `line`, and `fix`.
  - `ChunkAuditResult`: strongly-typed list of findings.
  - `AuditExecutionReport`: structured result containing report text, findings, local secret flags, and completeness status.
- Replaced raw text completions with LangChain's `.with_structured_output(ChunkAuditResult)` for Gemini 2.5 Flash.

### 3. Hunk-Aware Diff Chunking & First-Fit Bin-Packing (`core/chunker.py`)
v0.1.0 truncated any diff larger than 6,000 characters with a blunt cut. v0.1.1 implements a robust chunking architecture:
- **Hunk-Boundary Splitting:** Diffs are parsed and split along native git hunk boundaries (`@@ -l,s +l,s @@`) rather than arbitrary line cuts, preserving full context around changes.
- **Giant Hunk Splitting:** When a single hunk exceeds the piece budget, Sentinel-Code splits it into syntactically valid sub-hunks with mathematically accurate line numbering headers.
- **Oversized Line Slicing:** Single lines that exceed the size cap are sliced cleanly rather than dropped.
- **First-Fit Bin Packing:** Diff pieces are packed into chunks up to 30,000 tokens (~120,000 characters) per request, filling gaps in earlier chunks efficiently while preserving within-file ordering.
- **Request Safety Budget:** Audits are capped at 5 requests per run to strictly govern API usage and prevent runaway costs.

### 4. Content-Based Risk Scoring & Prioritization (`core/risk.py`)
Instead of auditing files on a simple first-come-first-served basis:
- **Analyzes Added Lines Only:** Evaluates added code lines (`+`) for dangerous indicators:
  - Raw SQL query string concatenation and formatting
  - Dangerous dynamic execution (`eval()`, `exec()`, `os.system()`, `subprocess.Popen(..., shell=True)`)
  - Hardcoded credential assignments, API keys, and PEM blocks
  - Authentication bypasses, weak crypto (`md5`, `des`), and disabled TLS verification (`verify=False`)
- **Content Outranks File Names:** High-risk code added to innocuous files (e.g., `utils.py`) scores higher priority than benign documentation in a file named `auth_docs.md`.
- **Decoy Resistance:** Removing risky code earns zero priority score, preventing malicious decoy files from exhausting the token budget before real vulnerabilities are reviewed.

### 5. Partial-Audit Protection & Default-Fail CI Gate (`interfaces/cli.py`)
v0.1.0 suffered from a dangerous flaw: if a diff was truncated, the model could report "Audit Passed" on the un-truncated portion.
- **Integrity Enforcement:** Sentinel-Code v0.1.1 tracks whether any files were skipped or truncated.
- **Default-Fail Policy:** Incomplete audits fail the gate by default (`exit code 1`), ensuring skipped files are never silently ignored.
- **Override Support:** Developers can explicitly allow partial audits using `--no-fail-on-incomplete` or report-only mode (`--fail-on none`).
- **Audit Detail:** Explicitly lists every file and hunk that could not be audited due to budget exhaustion.

### 6. Standard SARIF v2.1.0 & JSON Reporting
To support integration into enterprise DevSecOps pipelines:
- **SARIF v2.1.0:** Sentinel-Code generates standard OASIS SARIF output (`--format sarif`), enabling direct upload to **GitHub Code Scanning Alerts**, GitLab SAST dashboards, SonarQube, or VS Code SARIF viewers.
- **JSON Output:** Machine-readable JSON output (`--format json`) for custom CI/CD scripting.

### 7. CI/CD Gatekeeper & CLI Policy Controls (`interfaces/cli.py`)
In v0.1.0, the CLI simply printed text and always returned exit code 0. v0.1.1 functions as a strict gatekeeper:
- **Exit Code Protocol:** Returns `0` on clean diffs; returns `1` when security violations exceed policy thresholds or git commands fail.
- **Configurable CLI Flags:**
  - `--fail-on [high|medium|low|any|none]` (default: `high`): Configures the failure threshold.
  - `--fail-on-incomplete` / `--no-fail-on-incomplete`: Controls failure when diffs are partially audited (default: on).
  - `--format [markdown|json|sarif]`: Switches output formatting.
  - `--model`: Overrides the Gemini model on demand.

### 8. Native Git Hook & Pre-Commit Integration
- **Zero-Dependency Git Hook (`scripts/pre-commit-hook.sh`):** A shell script that developers can copy directly into `.git/hooks/pre-commit`.
- **Pre-Commit Framework Support (`.pre-commit-config.yaml`):** Supports Python `pre-commit` framework with clean stage filtering and exit-code enforcement.

### 9. Global Cross-Platform Launchers (`scripts/`)
- **Windows (`scripts/sentinel.bat`):** Native batch launcher that locates the virtual environment and bypasses Windows Store Python redirect shims.
- **macOS / Linux (`scripts/sentinel`):** Native shell script with executable permissions.
- Developers can add the `scripts/` directory to their system `PATH` and run `sentinel` against **any** local Git repository.

### 10. Expanded Security Rule Engine (`rules/security_rules.md`)
The rule set expanded from 5 baseline guidelines to **28 comprehensive enterprise security rules** (+23 new rules) covering Command Injection, XSS, Path Traversal, Insecure Deserialization, Weak Crypto, Insecure Randomness, Disabled TLS, Sensitive Logging, SSRF, Permissive CORS, IDOR, Insecure JWT, File Uploads, Input Validation, NoSQL/LDAP Injection, ReDoS, Open Redirects, and XXE.

---

## Benchmark & Quality Assurance Metrics

### 1. Comprehensive Unit Test Suite (82 Tests, 100% Pass)
*Full breakdown available in [docs/assets/unit_test_result.md](docs/assets/unit_test_result.md).*

| Test Suite | Module Under Test | Tests | Passed | Failed | Status |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **`tests/test_chunker.py`** | Diff Chunking, Hunk Splitting & Smart Budgeting | 12 | 12 | 0 | ✅ PASS |
| **`tests/test_diff_lines_and_risk.py`** | Line Classification & Content-Based Risk Scoring | 10 | 10 | 0 | ✅ PASS |
| **`tests/test_filter.py`** | AST & Extension Pre-Filter Engine | 26 | 26 | 0 | ✅ PASS |
| **`tests/test_gate_and_pipeline.py`** | Security Gate, Pipeline & Bypass Protection | 12 | 12 | 0 | ✅ PASS |
| **`tests/test_redact.py`** | Secret Masking & Credential Redaction Engine | 7 | 7 | 0 | ✅ PASS |
| **`tests/test_secret_scanning.py`** | Diff-Aware Secret Scanning & Mask Preview | 15 | 15 | 0 | ✅ PASS |
| **Total** | | **82** | **82** | **0** | **✅ 100% PASS** |

### 2. Pre-Filter Commit Replay Benchmark
*Full breakdown available in [docs/assets/filter_test_result.md](docs/assets/filter_test_result.md).*

- **Sentinel-Code Repository (50 Commits Replayed):**
  - **Skipped Commits (0 Tokens):** 21 (42%)
  - **Estimated Token Reduction:** 34% (baseline 49,113 tokens reduced to 32,172 tokens)
  - **Filter Latency:** Median 0.18 ms, max 7.31 ms
- **pallets/click Repository (50 Commits Replayed):**
  - **Skipped Commits (0 Tokens):** 6 (12%)
  - **Estimated Token Reduction:** 15%
  - **Filter Latency:** < 1 ms

### 3. Gold-Standard Security Benchmark
*Full breakdown available in [docs/assets/gold_standard_benchmark_results.md](docs/assets/gold_standard_benchmark_results.md).*

- **Standards Evaluated:** Meta CyberSecEval, SecurityEval, CredData, and CVEFixes across 33 test cases.
- **Empirical Accuracy:** ~71.4%–82.0% Precision and ~88.9%–94.1% Recall on industry-standard suites (realistically reflecting false-positive resistance against test mocks and allowlisted queries).

