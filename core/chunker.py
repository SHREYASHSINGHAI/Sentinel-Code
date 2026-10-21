"""
Splits per-file diffs into audit-sized pieces and packs them into LLM requests.

Replaces the old "truncate anything over the budget" behaviour: a file that is
too large is now split on HUNK boundaries (and, for a single giant hunk, on line
boundaries with corrected `@@` line numbers) so that every part of it can be
audited. Each piece repeats the file's header so the model always knows which
file it is looking at.

Pure functions only - no LLM, no I/O - so the whole planner is unit-testable.

Public API:
    make_pieces(path, diff_text, max_chars)          -> List[DiffPiece]
    plan_chunks(pieces, max_chars, max_requests, score_fn) -> ChunkPlan
    describe_pieces(pieces)                           -> List[str]
"""
from dataclasses import dataclass, field, replace
from typing import Callable, Dict, List, Optional

from core.diff_lines import (
    Hunk,
    hunk_line_counts,
    parse_file_diff,
    parse_hunk_header,
)

MAX_CHARS_PER_CHUNK = 120_000   # ~30,000 tokens
MAX_REQUESTS = 5

_MIN_LINE_BUDGET = 2_000        # below this, header repetition is not worth it
_CONT_HEADER_RESERVE = 120      # room for a rebuilt "@@ ... [continued]" line


@dataclass(frozen=True)
class DiffPiece:
    """One auditable section: a whole file's diff, or a slice of a large one."""
    path: str
    text: str
    part: int = 1
    total_parts: int = 1
    order: int = 0


@dataclass
class Chunk:
    """The pieces sent together in a single LLM request."""
    pieces: List[DiffPiece] = field(default_factory=list)
    size: int = 0

    def fits(self, piece: DiffPiece, max_chars: int) -> bool:
        extra = len(piece.text) + (1 if self.pieces else 0)
        return self.size + extra <= max_chars

    def add(self, piece: DiffPiece) -> None:
        self.size += len(piece.text) + (1 if self.pieces else 0)
        self.pieces.append(piece)

    @property
    def paths(self) -> List[str]:
        seen: List[str] = []
        for p in self.pieces:
            if p.path not in seen:
                seen.append(p.path)
        return seen

    @property
    def text(self) -> str:
        return "\n".join(p.text for p in sorted(self.pieces, key=lambda p: p.order))


@dataclass
class ChunkPlan:
    chunks: List[Chunk]
    skipped: List[DiffPiece]
    total_pieces: int

    @property
    def audited_pieces(self) -> int:
        return self.total_pieces - len(self.skipped)

    @property
    def is_complete(self) -> bool:
        return not self.skipped


# --------------------------------------------------------------------------- #
# Splitting one file
# --------------------------------------------------------------------------- #

def _bounded_lines(lines: List[str], limit: int) -> List[str]:
    """Slices any line longer than `limit` so every returned line fits; keeps the diff prefix."""
    out: List[str] = []
    for line in lines:
        if len(line) <= limit:
            out.append(line)
            continue
        prefix = line[0] if line and line[0] in "+- " else " "
        body = line[1:] if line and line[0] in "+- " else line
        size = max(limit - 2, 1)
        for i in range(0, len(body), size):
            out.append(prefix + body[i:i + size])
    return out


def _split_plain(lines: List[str], max_chars: int) -> List[str]:
    """Fallback for diffs with no usable hunk structure: split on lines only."""
    pieces: List[str] = []
    cur: List[str] = []
    cur_len = 0
    for line in _bounded_lines(lines, max_chars):
        add = len(line) + (1 if cur else 0)
        if cur and cur_len + add > max_chars:
            pieces.append("\n".join(cur))
            cur, cur_len, add = [], 0, len(line)
        cur.append(line)
        cur_len += add
    if cur:
        pieces.append("\n".join(cur))
    return pieces


def _split_hunk(hunk: Hunk, line_budget: int) -> List[str]:
    """Splits one oversized hunk, rebuilding each piece's `@@` header with correct line numbers."""
    old_pos, new_pos, section = parse_hunk_header(hunk.header)
    pieces: List[str] = []
    cur: List[str] = []
    cur_len = 0

    def emit(first: bool) -> None:
        nonlocal cur, cur_len, old_pos, new_pos
        if not cur:
            return
        old_n, new_n = hunk_line_counts(cur)
        tail = section if first else f"{section} [continued]"
        header = f"@@ -{old_pos},{old_n} +{new_pos},{new_n} @@{tail}"
        pieces.append(header + "\n" + "\n".join(cur))
        old_pos += old_n
        new_pos += new_n
        cur, cur_len = [], 0

    for line in _bounded_lines(hunk.lines, line_budget):
        add = len(line) + 1
        if cur and cur_len + add > line_budget:
            emit(first=not pieces)
        cur.append(line)
        cur_len += add
    emit(first=not pieces)
    return pieces


def split_diff_text(diff_text: str, max_chars: int = MAX_CHARS_PER_CHUNK) -> List[str]:
    """
    Returns pieces of `diff_text`, each <= max_chars, that together contain every line.
    A diff already within budget is returned unchanged as a single piece.
    """
    if len(diff_text) <= max_chars:
        return [diff_text]

    header, hunks = parse_file_diff(diff_text)
    header_text = "\n".join(header)
    budget = max_chars - len(header_text) - 1 - _CONT_HEADER_RESERVE
    if not hunks or budget < _MIN_LINE_BUDGET:
        return _split_plain(diff_text.split("\n"), max_chars)

    pieces: List[str] = []
    group: List[str] = []
    group_len = 0

    def flush() -> None:
        nonlocal group, group_len
        if group:
            pieces.append(header_text + "\n" + "\n".join(group))
        group, group_len = [], 0

    for hunk in hunks:
        hunk_text = "\n".join([hunk.header] + hunk.lines)
        if len(hunk_text) > budget:
            flush()
            for sub in _split_hunk(hunk, budget):
                pieces.append(header_text + "\n" + sub)
            continue
        if group and group_len + 1 + len(hunk_text) > budget:
            flush()
        group_len += len(hunk_text) + (1 if group else 0)
        group.append(hunk_text)
    flush()
    return pieces


def make_pieces(path: str, diff_text: str, max_chars: int = MAX_CHARS_PER_CHUNK) -> List[DiffPiece]:
    texts = split_diff_text(diff_text, max_chars)
    return [DiffPiece(path=path, text=t, part=i + 1, total_parts=len(texts)) for i, t in enumerate(texts)]


# --------------------------------------------------------------------------- #
# Packing pieces into requests
# --------------------------------------------------------------------------- #

def plan_chunks(
    pieces: List[DiffPiece],
    max_chars: int = MAX_CHARS_PER_CHUNK,
    max_requests: int = MAX_REQUESTS,
    score_fn: Optional[Callable[[str], int]] = None,
) -> ChunkPlan:
    """
    Packs pieces into at most `max_requests` chunks of at most `max_chars` each.

    Pieces are placed in priority order (highest `score_fn(piece.text)` first;
    ties keep their original order) using first-fit, so a higher-priority piece
    is never displaced by a lower one, and gaps in earlier chunks get filled.
    Whatever still does not fit is returned in `skipped` - never silently dropped.
    """
    indexed = [replace(p, order=i) for i, p in enumerate(pieces)]
    ranked = sorted(indexed, key=lambda p: -score_fn(p.text)) if score_fn else list(indexed)

    chunks: List[Chunk] = []
    skipped: List[DiffPiece] = []
    for piece in ranked:
        target = next((c for c in chunks if c.fits(piece, max_chars)), None)
        if target is None and len(chunks) < max_requests:
            target = Chunk()
            chunks.append(target)
        if target is None:
            skipped.append(piece)
        else:
            target.add(piece)

    skipped.sort(key=lambda p: p.order)
    return ChunkPlan(chunks=chunks, skipped=skipped, total_pieces=len(indexed))


def describe_pieces(pieces: List[DiffPiece]) -> List[str]:
    """Human-readable labels, e.g. ['a.py', 'big.py (part 3, 4 of 5)']."""
    by_path: Dict[str, List[DiffPiece]] = {}
    for p in pieces:
        by_path.setdefault(p.path, []).append(p)

    labels: List[str] = []
    for path, group in by_path.items():
        if all(p.total_parts == 1 for p in group):
            labels.append(path)
        else:
            parts = ", ".join(str(p.part) for p in group)
            labels.append(f"{path} (part {parts} of {group[0].total_parts})")
    return labels
