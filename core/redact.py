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

What it does NOT catch (use a scanner such as gitleaks for these):
  - unquoted values, e.g. KEY=value lines in .env files
  - secrets with no recognizable format or name
This is a safety net, not a guarantee.
"""
import re
from typing import List, Tuple

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

    return text, total
