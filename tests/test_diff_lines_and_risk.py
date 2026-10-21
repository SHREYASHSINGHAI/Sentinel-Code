from core.diff_lines import (
    ADDED, CONTEXT, HEADER, REMOVED,
    added_lines, classify_lines, parse_file_diff, parse_hunk_header, hunk_line_counts,
)
from core.risk import BASE_SCORE, matched_risk_signals, score_diff_risk


def d(path, body):
    return f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1,3 +1,3 @@\n{body}\n"


# ----------------------------- diff_lines ----------------------------------- #

def test_classify_kinds():
    diff = d("a.py", " keep\n-old\n+new")
    kinds = [k for k, _ in classify_lines(diff)]
    assert kinds[:4] == [HEADER, HEADER, HEADER, HEADER]      # diff/---/+++/@@
    assert kinds[4:7] == [CONTEXT, REMOVED, ADDED]


def test_removed_line_that_looks_like_file_marker_is_removed_content():
    # a removed SQL "-- note" line appears as "--- note" in a diff
    diff = d("q.sql", "--- note\n+SELECT 1;")
    assert (REMOVED, "--- note") in classify_lines(diff)
    assert added_lines(diff) == ["SELECT 1;"]


def test_added_lines_strip_prefix_and_ignore_headers():
    diff = d("a.py", "+x = 1\n-y = 2\n z = 3")
    assert added_lines(diff) == ["x = 1"]


def test_no_hunk_markers_falls_back_to_prefixes():
    diff = "--- a/x.py\n+++ b/x.py\n-old\n+new\n"
    assert added_lines(diff) == ["new"]


def test_parse_file_diff_and_hunk_helpers():
    diff = d("a.py", "+a\n-b") + "@@ -20,2 +20,2 @@ def f():\n+c\n d\n"
    header, hunks = parse_file_diff(diff)
    assert header[0].startswith("diff --git") and len(hunks) == 2
    assert parse_hunk_header(hunks[1].header) == (20, 20, " def f():")
    assert hunk_line_counts(hunks[1].lines) == (1, 2)
    assert parse_hunk_header("not a header") == (1, 1, "")


# -------------------------------- risk -------------------------------------- #

def test_content_outranks_file_name():
    decoy = d("auth_login_token.py", "+x = 1\n+y = 2")                 # scary name, harmless content
    real = d("helpers.py", "+import os\n+os.system(user_cmd)")          # bland name, dangerous content
    assert score_diff_risk(real) > score_diff_risk(decoy)
    assert "code_execution" in matched_risk_signals(real)
    assert score_diff_risk(decoy) == BASE_SCORE


def test_removed_risky_code_earns_nothing():
    removal = d("a.py", "-eval(user_input)\n-os.system(cmd)")
    assert score_diff_risk(removal) == BASE_SCORE


def test_added_secret_placeholder_is_top_priority_but_not_added_is_not():
    added = d("a.py", '+key = "[REDACTED:google_api_key]"')
    gone = d("a.py", '-key = "[REDACTED-NOT-ADDED:google_api_key]"')
    assert "hardcoded_secret" in matched_risk_signals(added)
    assert score_diff_risk(added) > score_diff_risk(gone) == BASE_SCORE


def test_signals_count_once_and_size_bonus_is_capped():
    many = d("a.py", "\n".join("+eval(x)" for _ in range(5000)))
    one = d("a.py", "+eval(x)")
    assert score_diff_risk(many) - score_diff_risk(one) <= 5        # padding cannot inflate priority


def test_sql_string_building_detected_but_parameterized_not():
    bad = d("r.py", "+cur.execute(f\"SELECT * FROM t WHERE id = '{uid}'\")")
    good = d("r.py", "+cur.execute(\"SELECT * FROM t WHERE id = %s\", (uid,))")
    assert "sql_string_building" in matched_risk_signals(bad)
    assert "sql_string_building" not in matched_risk_signals(good)
