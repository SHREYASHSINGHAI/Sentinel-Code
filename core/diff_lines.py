"""
Line-level helpers for a single file's unified diff.

Everything here is pure (no I/O, no LLM) and is shared by:
  * core/redact.py   - only ADDED lines count as findings; removed/context lines
                       are masked for privacy but never block a commit.
  * core/risk.py     - risk is scored from the lines a change adds.
  * core/chunker.py  - oversized files are split on hunk boundaries.

Contract: the input is ONE file's diff (as produced by core.filter's block
splitter). Multi-file text is tolerated for classification, but is not split.
"""
import re
from dataclasses import dataclass, field
from typing import List, Tuple

HEADER = "header"      # file headers, hunk headers, "\ No newline at end of file"
ADDED = "added"        # line starting with "+" inside a hunk
REMOVED = "removed"    # line starting with "-" inside a hunk
CONTEXT = "context"    # unchanged line inside a hunk

_HUNK_HEADER = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@(.*)$")


def classify_lines(diff_text: str) -> List[Tuple[str, str]]:
    """
    Returns [(kind, line), ...] in original order; `line` keeps its diff prefix.

    Inside a hunk, the first character decides the kind, so a removed SQL
    comment such as "--- note" is correctly REMOVED, not a file header.
    A diff with no "@@" markers at all (hand-written / sloppy) falls back to
    prefix matching, skipping the "+++ " / "--- " file markers.
    """
    lines = diff_text.split("\n")
    has_hunks = any(line.startswith("@@") for line in lines)
    out: List[Tuple[str, str]] = []
    in_hunk = False

    for line in lines:
        if line.startswith("diff --git "):
            in_hunk = False
            out.append((HEADER, line))
        elif has_hunks:
            if line.startswith("@@"):
                in_hunk = True
                out.append((HEADER, line))
            elif not in_hunk:
                out.append((HEADER, line))
            elif line.startswith("+"):
                out.append((ADDED, line))
            elif line.startswith("-"):
                out.append((REMOVED, line))
            elif line.startswith("\\"):
                out.append((HEADER, line))
            else:
                out.append((CONTEXT, line))
        else:
            if line.startswith("+") and not line.startswith("+++"):
                out.append((ADDED, line))
            elif line.startswith("-") and not line.startswith("---"):
                out.append((REMOVED, line))
            else:
                out.append((HEADER, line))
    return out


def group_runs(diff_text: str) -> List[Tuple[str, List[str]]]:
    """Groups consecutive lines of the same kind: [(kind, [lines...]), ...]."""
    runs: List[Tuple[str, List[str]]] = []
    for kind, line in classify_lines(diff_text):
        if runs and runs[-1][0] == kind:
            runs[-1][1].append(line)
        else:
            runs.append((kind, [line]))
    return runs


def added_lines(diff_text: str) -> List[str]:
    """Content of every added line, with the leading '+' removed."""
    return [line[1:] for kind, line in classify_lines(diff_text) if kind == ADDED]


def added_text(diff_text: str) -> str:
    return "\n".join(added_lines(diff_text))


# --------------------------------------------------------------------------- #
# Hunk structure (used for splitting oversized files)
# --------------------------------------------------------------------------- #

@dataclass
class Hunk:
    header: str
    lines: List[str] = field(default_factory=list)


def parse_file_diff(diff_text: str) -> Tuple[List[str], List[Hunk]]:
    """Splits one file's diff into (header_lines, hunks)."""
    header: List[str] = []
    hunks: List[Hunk] = []
    current = None
    for line in diff_text.split("\n"):
        if line.startswith("@@"):
            current = Hunk(header=line)
            hunks.append(current)
        elif current is None:
            header.append(line)
        else:
            current.lines.append(line)
    if hunks:
        while hunks[-1].lines and hunks[-1].lines[-1] == "":
            hunks[-1].lines.pop()          # trailing-newline artifact
    return header, hunks


def parse_hunk_header(header: str) -> Tuple[int, int, str]:
    """Returns (old_start, new_start, trailing_section_text); (1, 1, '') if malformed."""
    m = _HUNK_HEADER.match(header)
    if not m:
        return 1, 1, ""
    return int(m.group(1)), int(m.group(2)), m.group(3)


def hunk_line_counts(lines: List[str]) -> Tuple[int, int]:
    """Returns (old_line_count, new_line_count) for the given hunk body lines."""
    old = new = 0
    for line in lines:
        if line.startswith("+"):
            new += 1
        elif line.startswith("-"):
            old += 1
        elif line.startswith("\\"):
            continue
        else:
            old += 1
            new += 1
    return old, new
