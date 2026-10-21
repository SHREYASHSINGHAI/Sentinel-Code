from core.chunker import (
    DiffPiece, describe_pieces, make_pieces, plan_chunks, split_diff_text,
)
from core.diff_lines import ADDED, classify_lines, parse_file_diff


def file_diff(path, hunks):
    """hunks: list of (start_line, [added lines])"""
    out = f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n"
    for start, lines in hunks:
        out += f"@@ -{start},0 +{start},{len(lines)} @@ def f():\n" + "\n".join("+" + l for l in lines) + "\n"
    return out


def added(text):
    return [l for k, l in classify_lines(text) if k == ADDED]


# ------------------------------ splitting ----------------------------------- #

def test_small_diff_is_a_single_untouched_piece():
    diff = file_diff("a.py", [(1, ["x = 1"])])
    assert split_diff_text(diff, 10_000) == [diff]


def test_large_file_splits_on_hunk_boundaries_and_loses_nothing():
    hunks = [(i * 100, [f"line_{i}_{j} = {j}" for j in range(40)]) for i in range(30)]
    diff = file_diff("big.py", hunks)
    max_chars = 6_000
    pieces = split_diff_text(diff, max_chars)

    assert len(pieces) > 1
    assert all(len(p) <= max_chars for p in pieces)
    assert all(p.startswith("diff --git a/big.py b/big.py") for p in pieces)   # header repeated
    # every added line appears exactly once across the pieces
    assert sorted(l for p in pieces for l in added(p)) == sorted(added(diff))
    # pieces split between hunks: each piece's hunk headers are the original ones
    for p in pieces:
        _, hs = parse_file_diff(p)
        assert all(h.header.startswith("@@ -") and h.header.endswith("@@ def f():") for h in hs)


def test_single_giant_hunk_is_split_with_correct_line_numbers():
    lines = [f"v{i} = {i}" for i in range(3000)]
    diff = file_diff("gen.py", [(1, lines)])
    pieces = split_diff_text(diff, 8_000)

    assert len(pieces) > 1 and all(len(p) <= 8_000 for p in pieces)
    assert [l for p in pieces for l in added(p)] == added(diff)           # order + content preserved

    expected_new_start = 1
    for idx, p in enumerate(pieces):
        _, (hunk,) = parse_file_diff(p)
        assert f"+{expected_new_start}," in hunk.header                   # numbering continues
        assert ("[continued]" in hunk.header) == (idx > 0)
        expected_new_start += len(hunk.lines)


def test_one_enormous_line_is_sliced_not_dropped():
    blob = "A" * 50_000
    diff = file_diff("min.js", [(1, [blob])])
    pieces = split_diff_text(diff, 10_000)
    assert len(pieces) > 1 and all(len(p) <= 10_000 for p in pieces)
    assert "".join(l[1:] for p in pieces for l in added(p)) == blob


def test_diff_without_hunks_falls_back_to_line_split():
    text = "\n".join(f"+line {i}" for i in range(2000))
    pieces = split_diff_text(text, 5_000)
    assert len(pieces) > 1 and all(len(p) <= 5_000 for p in pieces)
    assert "\n".join(pieces) == text


def test_make_pieces_labels_parts():
    diff = file_diff("big.py", [(i * 10, [f"x{j} = 1" for j in range(60)]) for i in range(20)])
    pieces = make_pieces("big.py", diff, 5_000)
    assert [p.part for p in pieces] == list(range(1, len(pieces) + 1))
    assert all(p.total_parts == len(pieces) for p in pieces)


# ------------------------------- planning ----------------------------------- #

def piece(path, size, tag="x"):
    return DiffPiece(path=path, text=tag * size)


def test_plan_within_budget_is_complete():
    plan = plan_chunks([piece("a", 40), piece("b", 40), piece("c", 40)], max_chars=100, max_requests=5)
    assert plan.is_complete and plan.audited_pieces == 3 and plan.skipped == []


def test_plan_over_cap_reports_skipped_never_drops_silently():
    pieces = [piece(f"f{i}", 90) for i in range(7)]
    plan = plan_chunks(pieces, max_chars=100, max_requests=5)
    assert len(plan.chunks) == 5
    assert [p.path for p in plan.skipped] == ["f5", "f6"]
    assert not plan.is_complete
    assert plan.audited_pieces + len(plan.skipped) == plan.total_pieces == 7


def test_plan_prioritises_by_score_so_risky_content_is_audited_first():
    pieces = [DiffPiece("low1", "a" * 90), DiffPiece("low2", "a" * 90), DiffPiece("hot", "EVIL" * 20)]
    plan = plan_chunks(pieces, max_chars=100, max_requests=2,
                       score_fn=lambda text: 100 if text.startswith("EVIL") else 1)
    audited = {p.path for c in plan.chunks for p in c.pieces}
    assert "hot" in audited
    assert [p.path for p in plan.skipped] == ["low2"]


def test_first_fit_fills_gaps_in_earlier_chunks():
    pieces = [piece("big1", 60), piece("big2", 60), piece("small", 30)]
    plan = plan_chunks(pieces, max_chars=100, max_requests=2)
    assert plan.is_complete
    assert sorted(p.path for p in plan.chunks[0].pieces) == ["big1", "small"]


def test_chunk_text_keeps_original_order_within_a_chunk():
    plan = plan_chunks([piece("a", 10, "A"), piece("b", 10, "B")], max_chars=100, max_requests=1,
                       score_fn=lambda t: 1 if t.startswith("A") else 9)     # B ranked first
    assert plan.chunks[0].text == "A" * 10 + "\n" + "B" * 10


def test_describe_pieces():
    ps = [DiffPiece("a.py", "x"), DiffPiece("big.py", "x", 3, 5), DiffPiece("big.py", "x", 4, 5)]
    assert describe_pieces(ps) == ["a.py", "big.py (part 3, 4 of 5)"]
