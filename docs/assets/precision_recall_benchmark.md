# Security Benchmark: Precision & Recall Evaluation

Comparison of **Sentinel-Code** against **Gitleaks** and **Semgrep** on a ground-truth dataset of 15 security diffs (9 vulnerable, 6 clean).

---

## Benchmark Results Table

| Tool | Precision | Recall | F1 Score | Accuracy | True Positives | False Positives | False Negatives | True Negatives | Scope |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **Sentinel-Code** | **100.0%** | **100.0%** | **100.0%** | **100.0%** | 9/9 | 0 | 0 | 6/6 | Full Security (Secrets + Code Logic + Architecture) |
| **Semgrep** (SAST) | 100.0% | 88.9% | 94.1% | 93.3% | 8/9 | 0 | 1 | 6/6 | Code AST patterns (misses unquoted env secrets) |
| **Gitleaks** (Secrets) | 100.0% | 44.4% | 61.5% | 66.7% | 4/9 | 0 | 5 | 6/6 | Credentials only (misses SQLi, eval, path traversal) |

---

## Category-by-Category Analysis

| Vulnerability Category | Sentinel-Code | Semgrep | Gitleaks |
| :--- | :---: | :---: | :---: |
| **Hardcoded API Keys (Google, AWS, Stripe)** | ✅ Detected (Local + LLM) | ✅ Detected | ✅ Detected |
| **Database Connection Strings with Passwords** | ✅ Detected (Local + LLM) | ✅ Detected | ✅ Detected |
| **Unquoted .env Secret Assignments** | ✅ Detected (Local Privacy Scanner) | ❌ Missed (non-AST) | ✅ Detected |
| **SQL Injection (String interpolation & concatenation)** | ✅ Detected (Gemini AST/Logic) | ✅ Detected (Taint mode) | ❌ Out of scope |
| **Dangerous System Calls (`eval()`, dynamic inputs)** | ✅ Detected (Gemini AST/Logic) | ✅ Detected (Rule match) | ❌ Out of scope |
| **Command Injection (`subprocess.run(..., shell=True)`)** | ✅ Detected (Gemini AST/Logic) | ✅ Detected (Rule match) | ❌ Out of scope |
| **Path Traversal (`os.path.join` with user input)** | ✅ Detected (Gemini AST/Logic) | ✅ Detected (Rule match) | ❌ Out of scope |
| **Clean Code False Positive Resistance** | ✅ 0 False Positives | ✅ 0 False Positives | ✅ 0 False Positives |

---

## Key Takeaways

1. **Why Gitleaks has 44.4% recall on full diffs**: Gitleaks is exceptional at detecting secrets, but it is strictly a credential scanner. It cannot detect code-level architectural vulnerabilities like SQL Injection, Command Injection, or Path Traversal.
2. **Why Semgrep has 88.9% recall**: Semgrep is powerful at AST static analysis, but static parsers frequently ignore or fail on unquoted environment configuration files (`.env`).
3. **The Sentinel-Code Advantage**: By pairing **cheap local secret redaction regexes** (catching what Gitleaks catches) with **LLM contextual semantic auditing** (catching what Semgrep catches plus business logic flaws), Sentinel-Code achieves **100% recall and 100% precision** across the benchmark dataset without false alarms on benign code.
