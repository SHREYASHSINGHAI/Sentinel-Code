# Sentinel-Code Unit Test Results

**Date:** 2026-10-14  
**Python Version:** Python 3.14.3  
**Framework:** Pytest 9.1.1  
**Status:** All 31 tests passing (100%)  
**Execution Time:** 0.13s  

---

## Summary

| Test Suite | Tests | Passed | Failed | Skipped | Status |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **`tests/test_filter.py`** (Pre-Filter Engine) | 25 | 25 | 0 | 0 | ✅ PASS |
| **`tests/test_redact.py`** (Secret Redaction Engine) | 6 | 6 | 0 | 0 | ✅ PASS |
| **Total** | **31** | **31** | **0** | **0** | **✅ 100% PASS** |

---

## Detailed Test Case Results

### 1. Pre-Filter Engine (`tests/test_filter.py`)

| Test Name | Description | Result |
| :--- | :--- | :---: |
| `test_empty` | Empty diffs are discarded immediately | ✅ Passed |
| `test_readme_skipped` | Documentation changes (.md, .txt) are skipped | ✅ Passed |
| `test_lockfile_skipped` | Lockfiles (package-lock.json, poetry.lock, etc.) skipped | ✅ Passed |
| `test_image_skipped` | Binary and image assets (.png, .jpg, .svg) skipped | ✅ Passed |
| `test_comment_only_python` | Pure comment changes in Python are skipped | ✅ Passed |
| `test_code_change_kept` | Real logic edits are preserved for audit | ✅ Passed |
| `test_secret_in_comment_kept` | Comments containing secret keywords are retained | ✅ Passed |
| `test_whitespace_only_reindent` | Re-indentation and formatting-only edits skipped | ✅ Passed |
| `test_spacing_reformat` | Spaces/tab adjustment edits skipped | ✅ Passed |
| `test_real_change_with_same_line_count` | Modifying code line-for-line is retained | ✅ Passed |
| `test_reorder_is_kept` | Line order rearrangements are retained | ✅ Passed |
| `test_c_pointer_not_comment` | C/C++ pointer dereference (`*p`) not confused with comment | ✅ Passed |
| `test_c_block_comment_ignored` | C-style block comments (`/* ... */`) properly ignored | ✅ Passed |
| `test_hash_in_c_is_code` | Preprocessor directives (`#include`) in C treated as code | ✅ Passed |
| `test_yaml_config_kept` | Configuration files (.yaml, .yml) retained for security check | ✅ Passed |
| `test_env_file_kept` | Environment files (.env) retained for secret check | ✅ Passed |
| `test_unknown_extension_kept` | Unknown extensions default to being audited for safety | ✅ Passed |
| `test_deleted_file` | File deletions handled correctly without crashing | ✅ Passed |
| `test_new_file` | Completely new files flagged and extracted | ✅ Passed |
| `test_pure_rename_not_meaningful` | Renaming files without code edits is skipped | ✅ Passed |
| `test_multi_file_only_code_kept` | Mixed diff with docs + code retains only code files | ✅ Passed |
| `test_plain_unified_diff_without_git_header` | Unified diffs without Git headers handled correctly | ✅ Passed |
| `test_plain_unified_two_files` | Multi-file standard unified diff parsing | ✅ Passed |
| `test_removed_line_starting_with_dashes_is_content` | Lines starting with `--` recognized as SQL/Lua comments | ✅ Passed |
| `test_commit_message_prefix_ignored` | Prefixed commit logs within diff ignored | ✅ Passed |

---

### 2. Secret Redaction Engine (`tests/test_redact.py`)

| Test Name | Description | Result |
| :--- | :--- | :---: |
| `test_redact_google_api_key` | Masks Google API key (`AIza...`) with `[REDACTED:google_api_key]` | ✅ Passed |
| `test_redact_aws_key` | Masks AWS Access Keys (`AKIA...`) with `[REDACTED:aws_access_key]` | ✅ Passed |
| `test_redact_url_password` | Masks passwords in database URLs (`postgres://user:pass@host`) with `[REDACTED:password]` | ✅ Passed |
| `test_redact_quoted_fallback` | Masks quoted variable assignments (`api_key = "..."`) with `[REDACTED:secret]` | ✅ Passed |
| `test_redact_clean_code_unchanged` | Leaves ordinary non-secret code untouched | ✅ Passed |
| `test_redact_env_unquoted_assignment` | Masks unquoted `.env` assignments (`SECRET=...`, `TOKEN=...`, `PASSWORD=...`) | ✅ Passed |
