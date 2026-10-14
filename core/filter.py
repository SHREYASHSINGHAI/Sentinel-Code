"""
Smart pre-filter for Sentinel-Code.

Decides, locally and for free, whether a Git diff contains changes worth sending
to the LLM. Works per file:

  1. Skips non-code files by path (docs, images, lockfiles).
  2. Ignores blank lines and comment-only lines (language-aware), BUT keeps
     comment lines that look like they contain a secret.
  3. Ignores formatting-only edits (re-indentation, spacing) by comparing
     removed vs added lines with whitespace stripped.

Config files (.yaml, .json, .toml, .env) are intentionally NOT skipped, because
secrets leak there often.

Public API:
    parse_diff_metadata(diff_text)     -> (meaningful_file_paths, is_meaningful)
    extract_meaningful_diff(diff_text) -> str  (diff containing only meaningful files)
"""
import os
import re
from dataclasses import dataclass
from typing import List, Tuple


SKIP_EXTENSIONS = {

    ".md", ".markdown", ".rst", ".txt", ".adoc",

    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".pdf",

    ".lock",
}

SKIP_FILENAMES = {
    "license", "licence", "notice", "copying", "changelog", "changes",
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "pipfile.lock", "uv.lock", "cargo.lock", "go.sum", "composer.lock",
}


_HASH = ("#",)
_C_LIKE = ("//", "/*", "*/")
_HTML = ("<!--", "-->")

COMMENT_STYLES = {

    ".py": _HASH, ".sh": _HASH, ".bash": _HASH, ".zsh": _HASH, ".rb": _HASH,
    ".pl": _HASH, ".r": _HASH, ".yaml": _HASH, ".yml": _HASH, ".toml": _HASH,
    ".cfg": _HASH, ".conf": _HASH, ".tf": _HASH, ".env": _HASH,
    "dockerfile": _HASH, "makefile": _HASH,
    
    ".js": _C_LIKE, ".jsx": _C_LIKE, ".ts": _C_LIKE, ".tsx": _C_LIKE,
    ".java": _C_LIKE, ".c": _C_LIKE, ".h": _C_LIKE, ".cpp": _C_LIKE,
    ".hpp": _C_LIKE, ".cc": _C_LIKE, ".cs": _C_LIKE, ".go": _C_LIKE,
    ".rs": _C_LIKE, ".swift": _C_LIKE, ".kt": _C_LIKE, ".scala": _C_LIKE,
    ".php": _C_LIKE + _HASH, ".css": ("/*", "*/"), ".scss": _C_LIKE,

    ".sql": ("--", "/*", "*/"), ".lua": ("--",),
    ".html": _HTML, ".htm": _HTML, ".xml": _HTML, ".vue": _HTML,
}


SECRET_HINT = re.compile(
    r"(api[_-]?key|secret|passw(or)?d|token|private[_-]?key|credential"
    r"|BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{20,})",
    re.IGNORECASE,
)


@dataclass
class FileDiff:
    path: str
    raw_lines: List[str]
    meaningful: bool



def _skip_by_path(path: str) -> bool:
    base = os.path.basename(path).lower()
    ext = os.path.splitext(base)[1]
    return ext in SKIP_EXTENSIONS or base in SKIP_FILENAMES


def _comment_style(path: str) -> Tuple[str, ...]:
    base = os.path.basename(path).lower()
    ext = os.path.splitext(base)[1]
    if base.startswith(".env"):
        return _HASH
  
    return COMMENT_STYLES.get(ext) or COMMENT_STYLES.get(base) or ()


def _is_ignorable_comment(content: str, style: Tuple[str, ...]) -> bool:
    if not style:
        return False
    is_comment = content.startswith(style)

    if not is_comment and "/*" in style:
        is_comment = content == "*" or content.startswith("* ")

    return is_comment and not SECRET_HINT.search(content)


def _split_blocks(diff_text: str) -> List[List[str]]:
    """Split a diff into per-file blocks. Handles `git diff` and plain unified diffs."""
    lines = diff_text.splitlines()
    blocks: List[List[str]] = []
    cur: List[str] = []

    for i, line in enumerate(lines):
        nxt = lines[i + 1] if i + 1 < len(lines) else ""
        starts_new = line.startswith("diff --git ")
        if (
            not starts_new
            and (line.startswith("--- a/") or line.startswith("--- /dev/null"))
            and (nxt.startswith("+++ b/") or nxt.startswith("+++ /dev/null"))
            and any(l.startswith("+++ ") for l in cur)
        ):
            starts_new = True  

        if starts_new and cur:
            blocks.append(cur)
            cur = []
        cur.append(line)

    if cur:
        blocks.append(cur)
    return blocks


def _analyze_block(block: List[str]) -> FileDiff:
    path = old_path = git_path = None
    in_hunk = False
    added: List[str] = []
    removed: List[str] = []

    for line in block:
        if line.startswith("@@"):
            in_hunk = True
            continue
        if not in_hunk:  
            if line.startswith("+++ "):
                p = line[4:].strip()
                if p != "/dev/null":
                    path = p[2:] if p.startswith("b/") else p
            elif line.startswith("--- "):
                p = line[4:].strip()
                if p != "/dev/null":
                    old_path = p[2:] if p.startswith("a/") else p
            elif line.startswith("diff --git "):
                m = re.match(r"diff --git a/(.+?) b/(.+)$", line)
                if m:
                    git_path = m.group(2).strip()
            continue
  
        if line.startswith("+"):
            added.append(line[1:])
        elif line.startswith("-"):
            removed.append(line[1:])

    final_path = path or old_path or git_path or "" 
    meaningful = bool(final_path) and _is_meaningful(final_path, added, removed)
    return FileDiff(path=final_path, raw_lines=block, meaningful=meaningful)


def _is_meaningful(path: str, added: List[str], removed: List[str]) -> bool:
    if _skip_by_path(path):
        return False

    style = _comment_style(path)

    def keep(lines: List[str]) -> List[str]:
        out = []
        for raw in lines:
            c = raw.strip()
            if c and not _is_ignorable_comment(c, style):
                out.append(c)
        return out

    a, r = keep(added), keep(removed)
    if not a and not r:
        return False  

    def squash(xs: List[str]) -> List[str]:
        return [re.sub(r"\s+", "", x) for x in xs]

    if squash(a) == squash(r):
        return False

    return True


def _analyze(diff_text: str) -> List[FileDiff]:
    if not diff_text or not diff_text.strip():
        return []
    return [_analyze_block(b) for b in _split_blocks(diff_text)]



def parse_diff_metadata(diff_text: str) -> Tuple[List[str], bool]:
    """
    Returns:
        file_paths: paths of files that contain meaningful (auditable) changes.
        is_meaningful: True if at least one file needs an LLM audit.
    """
    files = [f for f in _analyze(diff_text) if f.meaningful]
    return [f.path for f in files], len(files) > 0


def extract_meaningful_diff(diff_text: str) -> str:
    """Return a diff containing only the files that need auditing."""
    files = [f for f in _analyze(diff_text) if f.meaningful]
    return "\n".join("\n".join(f.raw_lines) for f in files)


def extract_meaningful_file_diffs(diff_text: str) -> List[Tuple[str, str]]:
    """Return a list of (path, diff_content) for files that need auditing."""
    return [(f.path, "\n".join(f.raw_lines)) for f in _analyze(diff_text) if f.meaningful]