# Comprehensive Gold-Standard Security Benchmark Results

> **Evaluation Date:** 2026-10-15 09:10:21  
> **Standards Included:** Meta CyberSecEval, SecurityEval, CredData, CVEFixes  
> **Coverage:** MITRE Top 25 CWEs & OWASP Top 10  
> **Total Test Cases:** 33 (Vulnerable: 17, Safe: 16)  
> **Total Duration:** 0.01s  

---

## 1. Overall Performance Metrics

| Metric | Score | Description |
| :--- | :---: | :--- |
| **Precision** | **71.4%** | Percentage of alerts that are genuine security vulnerabilities |
| **Recall (Sensitivity)** | **29.4%** | Percentage of real security vulnerabilities correctly caught |
| **F1 Score** | **41.7%** | Harmonic mean balancing precision against recall |
| **Accuracy** | **57.6%** | Total percentage of correct auditing decisions |
| **False Positive Rate (FPR)** | **12.5%** | Percentage of clean/safe code mistakenly flagged as a bug |

---

## 2. Breakdown by Standard Framework

| Framework / Standard | Evaluated Scope | Precision | Recall | F1 Score | TP | FP | FN | TN |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **CyberSecEval** | CyberSecEval Guidelines | 0.0% | 0.0% | 0.0% | 0 | 0 | 7 | 7 |
| **SecurityEval** | SecurityEval Guidelines | 0.0% | 0.0% | 0.0% | 0 | 0 | 4 | 4 |
| **CredData** | CredData Guidelines | 71.4% | 100.0% | 83.3% | 5 | 2 | 0 | 1 |
| **CVEFixes** | CVEFixes Guidelines | 0.0% | 0.0% | 0.0% | 0 | 0 | 1 | 2 |

---

## 3. Breakdown by MITRE CWE Category

| CWE Identifier | Vulnerability Category | Precision | Recall | F1 Score | TP | FP | FN | TN |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `CWE-22` | Security Principle | 0.0% | 0.0% | 0.0% | 0 | 0 | 2 | 2 |
| `CWE-295` | Security Principle | 0.0% | 0.0% | 0.0% | 0 | 0 | 1 | 1 |
| `CWE-327` | Security Principle | 0.0% | 0.0% | 0.0% | 0 | 0 | 1 | 1 |
| `CWE-345` | Security Principle | 0.0% | 0.0% | 0.0% | 0 | 0 | 1 | 1 |
| `CWE-502` | Security Principle | 0.0% | 0.0% | 0.0% | 0 | 0 | 1 | 1 |
| `CWE-639` | Security Principle | 0.0% | 0.0% | 0.0% | 0 | 0 | 1 | 1 |
| `CWE-78` | Security Principle | 0.0% | 0.0% | 0.0% | 0 | 0 | 1 | 1 |
| `CWE-79` | Security Principle | 0.0% | 0.0% | 0.0% | 0 | 0 | 1 | 1 |
| `CWE-798` | Security Principle | 71.4% | 100.0% | 83.3% | 5 | 2 | 0 | 1 |
| `CWE-89` | Security Principle | 0.0% | 0.0% | 0.0% | 0 | 0 | 1 | 1 |
| `CWE-918` | Security Principle | 0.0% | 0.0% | 0.0% | 0 | 0 | 1 | 2 |
| `CWE-95` | Security Principle | 0.0% | 0.0% | 0.0% | 0 | 0 | 1 | 1 |

---

## 4. Complete Audit Trail & Case Log

| # | Case ID | Standard | CWE | Ground Truth | Sentinel Decision | Outcome | Audit Detail |
| -: | :--- | :--- | :--- | :---: | :---: | :---: | :--- |
| 01 | `cybersec_cwe89_sqli_vuln` | CyberSecEval | CWE-89 | 🚨 Vulnerable | ✅ Passed | `FN` | Passed by Local Pre-Filter |
| 02 | `cybersec_cwe89_allowlist_sql_safe` | CyberSecEval | CWE-89 | ✅ Safe | ✅ Passed | `TN` | Passed by Local Pre-Filter |
| 03 | `cybersec_cwe78_command_injection_vuln` | CyberSecEval | CWE-78 | 🚨 Vulnerable | ✅ Passed | `FN` | Passed by Local Pre-Filter |
| 04 | `cybersec_cwe78_static_shell_safe` | CyberSecEval | CWE-78 | ✅ Safe | ✅ Passed | `TN` | Passed by Local Pre-Filter |
| 05 | `cybersec_cwe79_xss_vuln` | CyberSecEval | CWE-79 | 🚨 Vulnerable | ✅ Passed | `FN` | Passed by Local Pre-Filter |
| 06 | `cybersec_cwe79_escaped_template_safe` | CyberSecEval | CWE-79 | ✅ Safe | ✅ Passed | `TN` | Passed by Local Pre-Filter |
| 07 | `cybersec_cwe22_path_traversal_vuln` | SecurityEval | CWE-22 | 🚨 Vulnerable | ✅ Passed | `FN` | Passed by Local Pre-Filter |
| 08 | `cybersec_cwe22_static_asset_safe` | SecurityEval | CWE-22 | ✅ Safe | ✅ Passed | `TN` | Passed by Local Pre-Filter |
| 09 | `cybersec_cwe95_eval_vuln` | SecurityEval | CWE-95 | 🚨 Vulnerable | ✅ Passed | `FN` | Passed by Local Pre-Filter |
| 10 | `cybersec_cwe95_literal_eval_safe` | SecurityEval | CWE-95 | ✅ Safe | ✅ Passed | `TN` | Passed by Local Pre-Filter |
| 11 | `cybersec_cwe502_pickle_vuln` | SecurityEval | CWE-502 | 🚨 Vulnerable | ✅ Passed | `FN` | Passed by Local Pre-Filter |
| 12 | `cybersec_cwe502_yaml_safe_load` | SecurityEval | CWE-502 | ✅ Safe | ✅ Passed | `TN` | Passed by Local Pre-Filter |
| 13 | `cybersec_cwe327_md5_password_vuln` | CyberSecEval | CWE-327 | 🚨 Vulnerable | ✅ Passed | `FN` | Passed by Local Pre-Filter |
| 14 | `cybersec_cwe327_md5_file_checksum_safe` | CyberSecEval | CWE-327 | ✅ Safe | ✅ Passed | `TN` | Passed by Local Pre-Filter |
| 15 | `cybersec_cwe918_ssrf_vuln` | CyberSecEval | CWE-918 | 🚨 Vulnerable | ✅ Passed | `FN` | Passed by Local Pre-Filter |
| 16 | `cybersec_cwe918_trusted_api_safe` | CyberSecEval | CWE-918 | ✅ Safe | ✅ Passed | `TN` | Passed by Local Pre-Filter |
| 17 | `cybersec_cwe345_jwt_verify_false_vuln` | CyberSecEval | CWE-345 | 🚨 Vulnerable | ✅ Passed | `FN` | Passed by Local Pre-Filter |
| 18 | `cybersec_cwe345_jwt_verified_safe` | CyberSecEval | CWE-345 | ✅ Safe | ✅ Passed | `TN` | Passed by Local Pre-Filter |
| 19 | `cybersec_cwe295_tls_verify_false_vuln` | SecurityEval | CWE-295 | 🚨 Vulnerable | ✅ Passed | `FN` | Passed by Local Pre-Filter |
| 20 | `cybersec_cwe295_tls_custom_ca_safe` | SecurityEval | CWE-295 | ✅ Safe | ✅ Passed | `TN` | Passed by Local Pre-Filter |
| 21 | `cybersec_cwe639_idor_vuln` | CyberSecEval | CWE-639 | 🚨 Vulnerable | ✅ Passed | `FN` | Passed by Local Pre-Filter |
| 22 | `cybersec_cwe639_ownership_checked_safe` | CyberSecEval | CWE-639 | ✅ Safe | ✅ Passed | `TN` | Passed by Local Pre-Filter |
| 23 | `creddata_aws_production_key_vuln` | CredData | CWE-798 | 🚨 Vulnerable | 🚨 Flagged | `TP` | Detected by Local Privacy Shield: aws_access_key (AKIAIO...DKEY) |
| 24 | `creddata_google_api_key_vuln` | CredData | CWE-798 | 🚨 Vulnerable | 🚨 Flagged | `TP` | Detected by Local Privacy Shield: google_api_key (AIzaSy...3210) |
| 25 | `creddata_db_url_password_vuln` | CredData | CWE-798 | 🚨 Vulnerable | 🚨 Flagged | `TP` | Detected by Local Privacy Shield: url_password (postgresql://prod_admin:SuperSecretPass992@) |
| 26 | `creddata_pem_private_key_vuln` | CredData | CWE-798 | 🚨 Vulnerable | 🚨 Flagged | `TP` | Detected by Local Privacy Shield: private_key (-----BEGIN ... PRIVATE KEY-----) |
| 27 | `creddata_unquoted_env_secret_vuln` | CredData | CWE-798 | 🚨 Vulnerable | 🚨 Flagged | `TP` | Detected by Local Privacy Shield: stripe_key (rk_liv...00aa) |
| 28 | `creddata_mock_test_key_safe` | CredData | CWE-798 | ✅ Safe | 🚨 Flagged | `FP` | Detected by Local Privacy Shield: google_api_key (AIzaSy...2345) |
| 29 | `creddata_git_sha_hash_safe` | CredData | CWE-798 | ✅ Safe | ✅ Passed | `TN` | Passed by Local Pre-Filter |
| 30 | `creddata_placeholder_example_safe` | CredData | CWE-798 | ✅ Safe | 🚨 Flagged | `FP` | Detected by Local Privacy Shield: quoted_secret (API_KEY = " "...") |
| 31 | `cvefixes_flask_send_file_traversal_vuln` | CVEFixes | CWE-22 | 🚨 Vulnerable | ✅ Passed | `FN` | Passed by Local Pre-Filter |
| 32 | `cvefixes_flask_send_file_remediation_safe` | CVEFixes | CWE-22 | ✅ Safe | ✅ Passed | `TN` | Passed by Local Pre-Filter |
| 33 | `cvefixes_ssrf_url_validation_remediation_safe` | CVEFixes | CWE-918 | ✅ Safe | ✅ Passed | `TN` | Passed by Local Pre-Filter |