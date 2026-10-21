# Sentinel-Code Unit Test Results

**Date:** 2026-10-21  
**Python Version:** Python 3.14.3  
**Framework:** Pytest 9.1.1  
**Status:** All 82 tests passing (100%)  
**Execution Time:** 7.65s  

---

## Summary

| Test Suite | Module Under Test | Tests | Passed | Failed | Skipped | Status |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **`tests/test_chunker.py`** | Diff Chunking & Smart Budgeting | 12 | 12 | 0 | 0 | ✅ PASS |
| **`tests/test_diff_lines_and_risk.py`** | Line Classification & Risk Scoring | 10 | 10 | 0 | 0 | ✅ PASS |
| **`tests/test_filter.py`** | Pre-Filter Engine & Extension Filtering | 26 | 26 | 0 | 0 | ✅ PASS |
| **`tests/test_gate_and_pipeline.py`** | Security Gate, Pipeline & Bypass Protection | 12 | 12 | 0 | 0 | ✅ PASS |
| **`tests/test_redact.py`** | Secret Masking & Redaction Engine | 7 | 7 | 0 | 0 | ✅ PASS |
| **`tests/test_secret_scanning.py`** | Diff-Aware Secret Scanning & Mask Preview | 15 | 15 | 0 | 0 | ✅ PASS |
| **Total** | | **82** | **82** | **0** | **0** | **✅ 100% PASS** |

---

## Detailed Test Case Results

### 1. Diff Chunking & Smart Budgeting (`tests/test_chunker.py`)

| Test Name | Description | Result |
| :--- | :--- | :---: |
| `test_small_diff_is_a_single_untouched_piece` | Small diffs within budget remain an intact single piece | ✅ Passed |
| `test_large_file_splits_on_hunk_boundaries_and_loses_nothing` | Large files split cleanly on hunk boundaries without losing content | ✅ Passed |
| `test_single_giant_hunk_is_split_with_correct_line_numbers` | Giant individual hunks split with preserved line numbers | ✅ Passed |
| `test_one_enormous_line_is_sliced_not_dropped` | Enormous single lines sliced rather than dropped | ✅ Passed |
| `test_diff_without_hunks_falls_back_to_line_split` | Diffs without git hunk headers fall back to line splitting | ✅ Passed |
| `test_make_pieces_labels_parts` | Multiple pieces are correctly labeled as parts (e.g. part 1/2) | ✅ Passed |
| `test_plan_within_budget_is_complete` | Diff pieces within total budget produce complete plan | ✅ Passed |
| `test_plan_over_cap_reports_skipped_never_drops_silently` | Plan exceeding chunk cap reports skipped sections explicitly | ✅ Passed |
| `test_plan_prioritises_by_score_so_risky_content_is_audited_first` | Content-based scoring prioritizes risky code ahead of decoys | ✅ Passed |
| `test_first_fit_fills_gaps_in_earlier_chunks` | First-fit algorithm fills gaps in earlier chunks efficiently | ✅ Passed |
| `test_chunk_text_keeps_original_order_within_a_chunk` | Original ordering preserved within chunks | ✅ Passed |
| `test_describe_pieces` | Description helper produces accurate summary strings | ✅ Passed |

---

### 2. Line Classification & Risk Scoring (`tests/test_diff_lines_and_risk.py`)

| Test Name | Description | Result |
| :--- | :--- | :---: |
| `test_classify_kinds` | Line classification into ADDED, REMOVED, and CONTEXT | ✅ Passed |
| `test_removed_line_that_looks_like_file_marker_is_removed_content` | Removed line resembling `---` or `+++` treated as content | ✅ Passed |
| `test_added_lines_strip_prefix_and_ignore_headers` | Added lines correctly stripped of `+` and header lines excluded | ✅ Passed |
| `test_no_hunk_markers_falls_back_to_prefixes` | Diff without hunk markers falls back to line prefixes | ✅ Passed |
| `test_parse_file_diff_and_hunk_helpers` | File diff and hunk parsing helper correctness | ✅ Passed |
| `test_content_outranks_file_name` | Risky file content scores higher priority than file name heuristic alone | ✅ Passed |
| `test_removed_risky_code_earns_nothing` | Removing risky code does not inflate risk priority score | ✅ Passed |
| `test_added_secret_placeholder_is_top_priority_but_not_added_is_not` | Added secret placeholder receives top priority score | ✅ Passed |
| `test_signals_count_once_and_size_bonus_is_capped` | Duplicate signal matches count once and size bonus is capped | ✅ Passed |
| `test_sql_string_building_detected_but_parameterized_not` | String concatenation SQL detected while parameterized queries not flagged | ✅ Passed |

---

### 3. Pre-Filter Engine (`tests/test_filter.py`)

| Test Name | Description | Result |
| :--- | :--- | :---: |
| `test_empty` | Empty diffs are discarded immediately | ✅ Passed |
| `test_readme_skipped` | Documentation changes (.md, .txt) are skipped | ✅ Passed |
| `test_lockfile_skipped` | Lockfiles (package-lock.json, poetry.lock, etc.) skipped | ✅ Passed |
| `test_image_skipped` | Binary and image assets (.png, .jpg, .svg) skipped | ✅ Passed |
| `test_comment_only_python` | Pure comment changes in Python are skipped | ✅ Passed |
| `test_code_change_kept` | Real logic edits are preserved for audit | ✅ Passed |
| `test_secret_in_comment_kept` | Comments containing secret keywords are retained | ✅ Passed |
| `test_whitespace_only_reindent_c_like` | Re-indentation in brace-delimited languages (.js, .c) skipped | ✅ Passed |
| `test_spacing_reformat_c_like` | Space/tab reformatting in brace-delimited languages skipped | ✅ Passed |
| `test_whitespace_preserved_for_indentation_sensitive` | Whitespace/indentation changes in .py, .yaml, .yml, and Makefile are strictly audited | ✅ Passed |
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

### 4. Security Gate, Pipeline & Bypass Protection (`tests/test_gate_and_pipeline.py`)

| Test Name | Description | Result |
| :--- | :--- | :---: |
| `test_incomplete_fails_by_default` | Incomplete audits fail security gate by default under standard threshold | ✅ Passed |
| `test_incomplete_flag_overrides` | `--no-fail-on-incomplete` and report-only thresholds override gate behavior | ✅ Passed |
| `test_existing_should_fail_behaviour_unchanged` | Standard findings risk levels correctly trigger or pass gate | ✅ Passed |
| `test_decoy_files_can_no_longer_hide_a_vulnerability` | Decoy files cannot starve audit budget away from real vulnerability | ✅ Passed |
| `test_oversized_file_is_split_not_truncated` | Oversized diff files split into chunks instead of being truncated | ✅ Passed |
| `test_budget_exhaustion_is_incomplete_names_what_was_skipped_and_fails_gate` | Budget exhaustion marks audit incomplete, logs skipped files, and fails gate | ✅ Passed |
| `test_json_output_is_still_a_plain_findings_list` | JSON output format maintains valid findings array | ✅ Passed |
| `test_commit_that_removes_a_secret_is_not_blocked` | Removing a hardcoded secret passes gate without blocking commit | ✅ Passed |
| `test_commit_that_adds_a_secret_is_still_blocked_and_report_is_masked` | Adding a secret is blocked and secrets in reports are masked | ✅ Passed |
| `test_secret_added_in_a_doc_file_is_still_caught_locally` | Secrets added in Markdown or text files detected locally without LLM calls | ✅ Passed |
| `test_secret_removed_from_a_doc_file_is_not_flagged` | Removing secret from doc files passes cleanly | ✅ Passed |
| `test_run_audit_wrapper_returns_same_report_string` | Wrapper `run_audit()` returns identical report string as detailed result | ✅ Passed |

---

### 5. Secret Redaction Engine (`tests/test_redact.py`)

| Test Name | Description | Result |
| :--- | :--- | :---: |
| `test_redact_google_api_key` | Masks Google API key (`AIza...`) with `[REDACTED:google_api_key]` | ✅ Passed |
| `test_redact_aws_key` | Masks AWS Access Keys (`AKIA...`) with `[REDACTED:aws_access_key]` | ✅ Passed |
| `test_redact_url_password` | Masks passwords in database URLs (`postgres://user:pass@host`) with `[REDACTED:password]` | ✅ Passed |
| `test_redact_quoted_fallback` | Masks quoted variable assignments (`api_key = "..."`) with `[REDACTED:secret]` | ✅ Passed |
| `test_redact_clean_code_unchanged` | Leaves ordinary non-secret code untouched | ✅ Passed |
| `test_redact_env_unquoted_assignment` | Masks unquoted `.env` assignments (`SECRET=...`, `TOKEN=...`, `PASSWORD=...`) | ✅ Passed |
| `test_find_secret_matches_in_markdown_and_docs` | Scans non-code documents (.md, .txt) for secrets with zero LLM calls | ✅ Passed |

---

### 6. Diff-Aware Secret Scanning & Mask Preview (`tests/test_secret_scanning.py`)

| Test Name | Description | Result |
| :--- | :--- | :---: |
| `test_mask_preview_shows_few_leading_chars_then_stars` | Mask preview exposes only initial characters followed by asterisks | ✅ Passed |
| `test_mask_preview_never_reveals_more_than_a_quarter_and_hides_length` | Masking reveals at most 25% of secret and conceals true length | ✅ Passed |
| `test_previews_never_contain_the_full_secret` | Secret previews guaranteed never to reveal full plaintext secret | ✅ Passed |
| `test_preview_shapes` | Preview patterns adhere to fixed formatting expectations | ✅ Passed |
| `test_removing_a_secret_is_not_a_finding` | Deleted secret line does not generate security violation finding | ✅ Passed |
| `test_removing_a_whole_env_file_secret_or_pem_is_not_a_finding` | Removing PEM blocks or entire `.env` secrets is not a finding | ✅ Passed |
| `test_unchanged_context_line_with_secret_is_not_a_finding` | Existing secret in unchanged diff context line is not flagged | ✅ Passed |
| `test_adding_a_secret_is_still_a_finding` | Introducing new secrets in added lines is strictly flagged | ✅ Passed |
| `test_new_file_with_secret_is_a_finding` | Creating a new file containing secrets is strictly flagged | ✅ Passed |
| `test_plain_find_secret_matches_behaviour_is_unchanged_for_non_diff_text` | Plain text scanning behavior remains backward compatible | ✅ Passed |
| `test_redact_diff_labels_added_vs_not_added_and_leaks_nothing` | Redacted diff differentiates added vs removed secrets without leakage | ✅ Passed |
| `test_redact_diff_removed_secret_never_gets_the_violation_placeholder` | Removed secrets tagged with harmless placeholder rather than violation | ✅ Passed |
| `test_redact_diff_removed_pem_block_is_fully_masked` | Removed PEM private key blocks completely masked | ✅ Passed |
| `test_redact_diff_clean_diff_roundtrips_exactly` | Diff without secrets is unaffected by redaction pass | ✅ Passed |
| `test_redact_secrets_original_function_is_untouched` | Legacy `redact_secrets()` function maintains original contract | ✅ Passed |
