"""
Local, best-effort masking of secrets before a diff is sent to the LLM.

Runs on your machine. It replaces values that look like secrets with a placeholder
such as [REDACTED:google_api_key], so the model can still see that a hardcoded secret
exists but never receives the secret itself.

What it catches:
  - well-known token formats (Google, AWS, GitHub, Slack, Stripe, sk-... keys, JWTs)
  - PEM private key blocks
  - passwords inside URLs (scheme://user:password@host)
  - quoted values assigned to names like api_key, secret, token, password

  - unquoted KEY=value assignments (.env files, shell exports)

What it does NOT catch (use a scanner such as gitleaks for these):
  - secrets with no recognizable format or name
This is a safety net, not a guarantee.

Diff awareness:
  Only ADDED lines (+) are findings. A removed (-) or unchanged context line that
  contains a secret is still masked before anything leaves the machine, but it is
  labelled [REDACTED-NOT-ADDED:...] and never reported or blocked - deleting a
  leaked credential is the fix, not the problem.

Previews:
  Anything shown to the user (local-detection reports, CI logs) reveals at most the
  first few characters of a secret followed by asterisks - never the full value.
"""
import re
from typing import List, Tuple

from core.diff_lines import CONTEXT, REMOVED, added_text, group_runs

PREVIEW_VISIBLE_CHARS = 4      # at most this many leading characters are shown...
PREVIEW_MAX_VISIBLE_RATIO = 4  # ...and never more than 1/4 of the value
PREVIEW_MASK = "********"      # fixed length, so the secret's length is not revealed
NOT_ADDED_PLACEHOLDER = "[REDACTED-NOT-ADDED:"

_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL
)
_PRIVATE_KEY_MARKER = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")

# (label, pattern) for well-known token formats
_TOKEN_PATTERNS: List[Tuple[str, "re.Pattern[str]"]] = [
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z_\-]{20,}")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b")),
    ("github_token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}")),
    ("stripe_key", re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("api_key", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
]

# scheme://user:PASSWORD@host  ->  mask only the password
_URL_CREDENTIALS = re.compile(r"(\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@\"']+:)([^\s@/\"']+)(@)")

# name = "value"  /  "name": "value"  (quoted values only, to avoid breaking real code)
_QUOTED_ASSIGNMENT = re.compile(
    r"(?i)((?:api[_-]?key|apikey|secret(?:[_-]?key)?|client[_-]?secret|access[_-]?token"
    r"|auth[_-]?token|token|passw(?:or)?d|pwd|private[_-]?key)[\"']?\s*[:=]\s*[\"'])"
    r"(?!\[REDACTED)([^\"'\s]{6,})([\"'])"
)

# KEY=value / NAME_WITH_KEY/SECRET/TOKEN/PASSWORD=value (e.g., .env or bash unquoted variables)
_ENV_ASSIGNMENT = re.compile(
    r"(?im)^([ \t]*[+-]?[ \t]*(?:export[ \t]+)?[A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|PWD)[A-Z0-9_]*[ \t]*=[ \t]*)"
    r"(?!\[REDACTED)(['\"]?)(?!\s*\[REDACTED)(?![A-Za-z_][\w]*[.(\[])(?!/)(?![A-Za-z][A-Za-z0-9+.\-]*://)([^#\r\n\s'\"]{6,})\2([ \t]*(?:#.*)?)$"
)




def redact_secrets(text: str) -> Tuple[str, int]:
    """Return (masked_text, number_of_values_masked)."""
    if not text:
        return text, 0

    total = 0

    text, n = _PRIVATE_KEY_BLOCK.subn("[REDACTED:private_key]", text)
    total += n
    text, n = _PRIVATE_KEY_MARKER.subn("[REDACTED:private_key]", text)
    total += n

    for label, pattern in _TOKEN_PATTERNS:
        text, n = pattern.subn(f"[REDACTED:{label}]", text)
        total += n

    text, n = _URL_CREDENTIALS.subn(r"\1[REDACTED:password]\3", text)
    total += n

    text, n = _QUOTED_ASSIGNMENT.subn(r"\1[REDACTED:secret]\3", text)
    total += n

    text, n = _ENV_ASSIGNMENT.subn(r"\1[REDACTED:secret]\4", text)
    total += n

    return text, total


def mask_preview(value: str) -> str:
    """
    Safe-to-display form of a secret: the first few characters, then asterisks.

    Shows at most PREVIEW_VISIBLE_CHARS characters and never more than a quarter
    of the value (so short secrets stay mostly hidden); the asterisk run has a
    fixed length so the secret's length is not revealed either.
        AIzaSyD1234567890SecretKeyHere -> AIza********
        pw12                            -> ********
    """
    visible = min(PREVIEW_VISIBLE_CHARS, len(value) // PREVIEW_MAX_VISIBLE_RATIO)
    return value[:visible] + PREVIEW_MASK


def find_secret_matches(text: str) -> List[Tuple[str, str]]:
    """
    Finds and returns a list of (secret_label, masked_preview) found in the text.
    Scans EVERY line it is given; for diffs, use find_added_secret_matches() so that
    removed/context lines are ignored.
    Used for local detection on all files (including skipped .md, .txt) with no LLM calls.
    """
    if not text:
        return []

    findings: List[Tuple[str, str]] = []

    # Check for private keys
    if _PRIVATE_KEY_MARKER.search(text):
        findings.append(("private_key", "-----BEGIN ... PRIVATE KEY-----"))

    # Check specific token formats
    for label, pattern in _TOKEN_PATTERNS:
        for m in pattern.finditer(text):
            findings.append((label, mask_preview(m.group(0))))

    # Check credentials in URLs: keep scheme://user:, mask the password
    for m in _URL_CREDENTIALS.finditer(text):
        findings.append(("url_password", m.group(1) + mask_preview(m.group(2)) + m.group(3)))

    # Check quoted assignments: api_key = "Supe********"
    for m in _QUOTED_ASSIGNMENT.finditer(text):
        findings.append(("quoted_secret", m.group(1).strip() + mask_preview(m.group(2)) + m.group(3)))

    # Check unquoted env assignments: API_KEY=Supe********
    for m in _ENV_ASSIGNMENT.finditer(text):
        name = m.group(1).lstrip("+- \t")
        findings.append(("env_secret", name + m.group(2) + mask_preview(m.group(3)) + m.group(2)))

    return findings


def find_added_secret_matches(diff_text: str) -> List[Tuple[str, str]]:
    """
    Diff-aware local detection: only lines the change ADDS are scanned.
    Removing or leaving untouched a line that holds a secret is never a finding.
    """
    return find_secret_matches(added_text(diff_text))


def redact_diff_secrets(diff_text: str) -> Tuple[str, int]:
    """
    Diff-aware masking for text that is about to be sent to the LLM.

    Every secret is masked, whatever kind of line it is on (nothing leaves the
    machine unmasked). Secrets on ADDED lines get the usual [REDACTED:<type>]
    placeholder; secrets on removed or unchanged lines get
    [REDACTED-NOT-ADDED:<type>] so the model can tell a credential being
    introduced from one being deleted. Returns (masked_text, number_masked).

    Consecutive lines of the same kind are masked together, which keeps
    multi-line secrets (PEM blocks) intact.
    """
    if not diff_text:
        return diff_text, 0

    total = 0
    parts: List[str] = []
    for kind, lines in group_runs(diff_text):
        masked, n = redact_secrets("\n".join(lines))
        total += n
        if n and kind in (REMOVED, CONTEXT):
            masked = masked.replace("[REDACTED:", NOT_ADDED_PLACEHOLDER)
        parts.append(masked)
    return "\n".join(parts), total

