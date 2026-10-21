"""
Content-based risk scoring for diff sections.

Decides which parts of a large diff are audited FIRST when the request budget
cannot cover everything. It looks only at the lines a change ADDS - never at
the file name - so naming a file `auth_x.py` earns nothing, and deleting risky
code earns nothing.

Each signal counts once per section (distinct categories, not raw occurrences),
and size contributes only a small capped bonus, so padding a section with
thousands of lines cannot inflate its priority.

This is prioritisation only. Completeness is enforced separately: any section
that does not fit the budget is reported as skipped and fails the gate by
default (see interfaces/cli.py).

Public API:
    score_diff_risk(diff_text)         -> int   (higher = audit earlier)
    matched_risk_signals(diff_text)    -> List[str]
"""
import re
from dataclasses import dataclass
from typing import List, Pattern

from core.diff_lines import added_lines

BASE_SCORE = 10
SIZE_BONUS_CAP = 5
LINES_PER_SIZE_POINT = 50
MAX_LINE_CHARS = 2000      # bounds regex cost on minified / generated lines


@dataclass(frozen=True)
class RiskSignal:
    name: str
    weight: int
    pattern: Pattern[str]


def _sig(name: str, weight: int, pattern: str, flags: int = 0) -> RiskSignal:
    return RiskSignal(name, weight, re.compile(pattern, flags))


_SQL_KEYWORDS = r"\b(?:select\s.+\sfrom|insert\s+into|update\s+\S+\s+set|delete\s+from)\b"
_STRING_BUILDING = r"(?:\{[^}]+\}|[\"']\s*\+|\+\s*\w|\.format\(|[\"']\s*%\s*[\w(])"

RISK_SIGNALS: List[RiskSignal] = [
    # A masked credential on an added line (see core/redact.py)
    _sig("hardcoded_secret", 60, r"\[REDACTED:"),
    _sig("code_execution", 40,
         r"\b(?:eval|exec)\s*\(|\bos\.(?:system|popen)\s*\(|\bshell\s*=\s*True|child_process"
         r"|\bRuntime\.getRuntime\(\)\.exec|\bnew\s+Function\s*\(|\b__import__\s*\("),
    _sig("unsafe_deserialization", 40,
         r"\b(?:pickle|cPickle|marshal|dill)\.loads?\s*\(|\byaml\.load\s*\((?![^)]*Safe)"
         r"|\bObjectInputStream\b|\bunserialize\s*\(|\bjsonpickle\.decode"),
    _sig("sql_string_building", 35,
         rf"{_SQL_KEYWORDS}.*{_STRING_BUILDING}|\.execute\w*\(\s*(?:f[\"']|[^)]*(?:\+|\.format\())",
         re.IGNORECASE),
    _sig("xss_sink", 30,
         r"\b(?:innerHTML|outerHTML)\b|dangerouslySetInnerHTML|document\.write\s*\(|\|\s*safe\b"
         r"|\{!!|\bv-html\b|insertAdjacentHTML"),
    _sig("tls_or_weak_crypto", 30,
         r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify|CERT_NONE"
         r"|check_hostname\s*=\s*False|\b(?:md5|sha1|DES|RC4|ECB)\b", re.IGNORECASE),
    _sig("jwt_cors_cookie", 30,
         r"verify_signature['\"]?\s*:\s*False|algorithms?\s*[=:]\s*\[?\s*['\"]none"
         r"|Access-Control-Allow-Origin|allow_origins|allow_credentials|\bset_cookie\b"
         r"|\bhttponly\b|\bsamesite\b|\bjwt\.(?:decode|verify)\b", re.IGNORECASE),
    _sig("credential_assignment", 25,
         r"(?:api[_-]?key|secret|private[_-]?key)\s*[:=]", re.IGNORECASE),
    _sig("external_io", 20,
         r"\brequests\.(?:get|post|put|delete|request)\s*\(|\burllib\.|\bhttpx\.|\bfetch\s*\("
         r"|\bsend_file\b|\bsend_from_directory\b|\bredirect\s*\("
         r"|\bopen\s*\([^)]*(?:\+|f[\"']|format|request|input)|\bos\.path\.join\s*\("
         r"|\bshutil\.|\bos\.(?:remove|unlink|rmdir)\b"),
    _sig("debug_enabled", 20,
         r"\bdebug\s*[:=]\s*(?:True|true|1)\b", re.IGNORECASE),
    _sig("auth_logic", 15,
         r"\b(?:password|passwd|credential|secret|token|session|login|logout|authenticat\w*"
         r"|authoriz\w*|permission|oauth|is_admin|role)\b", re.IGNORECASE),
    _sig("user_input_source", 15,
         r"\brequest\.(?:args|form|json|values|GET|POST|data|files|headers|cookies)\b"
         r"|\breq\.(?:body|query|params|headers|cookies)\b|\bsys\.argv\b|\binput\s*\("
         r"|\bgetParameter\s*\("),
    _sig("weak_randomness", 15, r"\brandom\.(?:random|randint|choice|randrange)\s*\(|\bMath\.random\s*\("),
    _sig("risky_infrastructure", 15,
         r"\bprivileged\b|\bchmod\s+(?:-R\s+)?777\b|\b0\.0\.0\.0\b|curl[^|\n]*\|\s*(?:ba)?sh"
         r"|\bADD\s+https?://|--no-check-certificate|\bsudo\b", re.IGNORECASE),
    _sig("xml_parsing", 10,
         r"\bxml\.(?:etree|dom|sax)\b|\bXMLParser\b|\bDocumentBuilderFactory\b|\blxml\.etree\b"),
]


def _match(lines: List[str]) -> List[str]:
    remaining = list(RISK_SIGNALS)
    matched: List[str] = []
    for line in lines:
        if not remaining:
            break
        probe = line[:MAX_LINE_CHARS]
        for signal in remaining[:]:
            if signal.pattern.search(probe):
                matched.append(signal.name)
                remaining.remove(signal)
    return matched


def matched_risk_signals(diff_text: str) -> List[str]:
    """Names of the risk signals present on the lines this diff adds."""
    return _match(added_lines(diff_text))


def score_diff_risk(diff_text: str) -> int:
    """Higher score = more security-relevant added content = audit earlier."""
    lines = added_lines(diff_text)
    matched = set(_match(lines))
    score = BASE_SCORE + sum(s.weight for s in RISK_SIGNALS if s.name in matched)
    score += min(len(lines) // LINES_PER_SIZE_POINT, SIZE_BONUS_CAP)
    return score
