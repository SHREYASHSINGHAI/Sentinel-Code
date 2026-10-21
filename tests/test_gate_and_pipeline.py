import asyncio

import pytest

pytest.importorskip("langchain_core")
pytest.importorskip("langchain_google_genai")

from core.auditor_agent import ChunkAuditResult, CodeAuditorBrain, Finding  # noqa: E402
from interfaces.cli import resolve_fail_on_incomplete, should_fail          # noqa: E402

GOOGLE = "AIzaSyD1234567890SecretKeyHere"


class FakeChain:
    """Stands in for Gemini: records exactly what Sentinel would send."""
    def __init__(self, findings=None):
        self.calls = []
        self.findings = findings or []

    async def ainvoke(self, payload):
        self.calls.append(payload)
        return ChunkAuditResult(findings=self.findings)


def make_brain(findings=None):
    brain = object.__new__(CodeAuditorBrain)      # skip __init__: no API key / network needed
    brain.rules, brain.chain = "rules", FakeChain(findings)
    return brain


def audit(brain, diff, fmt="markdown"):
    return asyncio.run(brain.run_audit_detailed(diff, fmt))


def block(path, lines):
    body = "\n".join("+" + l for l in lines)
    return (f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n"
            f"@@ -0,0 +1,{len(lines)} @@\n{body}\n")


def filler(n):                                    # n harmless lines (~14 chars each)
    return [f"x{i} = {i}" for i in range(n)]


def bulk(n, head=""):                             # n lines of 100+ chars each
    return [head + "y" * 99 for _ in range(n)]


# ------------------------------- gate policy -------------------------------- #

def test_incomplete_fails_by_default():
    fail_flag = resolve_fail_on_incomplete(None, "high")
    assert fail_flag is True
    failed, reason = should_fail([], False, "high", fail_flag, is_incomplete=True)
    assert failed and "incomplete" in reason.lower()


def test_incomplete_flag_overrides():
    assert resolve_fail_on_incomplete(False, "high") is False       # --no-fail-on-incomplete
    assert resolve_fail_on_incomplete(True, "none") is True         # explicit flag still honoured
    assert resolve_fail_on_incomplete(None, "none") is False        # report-only mode stays report-only
    assert should_fail([], False, "high", False, is_incomplete=True) == (False, "")


def test_existing_should_fail_behaviour_unchanged():
    high = Finding(risk_level="HIGH", file_path="a.py", rule="r", fix="f")
    low = Finding(risk_level="LOW", file_path="a.py", rule="r", fix="f")
    assert should_fail([high], False, "high", True, False)[0] is True
    assert should_fail([low], False, "high", True, False)[0] is False
    assert should_fail([low], False, "low", True, False)[0] is True
    assert should_fail([], True, "high", True, False)[0] is True
    assert should_fail([high], True, "none", False, False) == (False, "")


# --------------------------- bypass is closed ------------------------------- #

def test_decoy_files_can_no_longer_hide_a_vulnerability():
    # 5 decoys (~71k each, scary names) cannot share a request, so they fill all 5 slots.
    # The real bug (bland name, ~69k) is too big for any leftover gap: it is audited only
    # if content-based priority puts it ahead of the decoys.
    diff = "".join(block(f"auth_gen{i}.py", bulk(700)) for i in range(5))
    diff += block("helpers.py", bulk(550, head="os.system(user_input)  # "))
    brain = make_brain()
    res = audit(brain, diff)
    sent = "\n".join(c["diff"] for c in brain.chain.calls)
    assert "os.system(user_input)" in sent                         # audited despite its name
    assert len(brain.chain.calls) == 5
    assert res.is_incomplete                                       # a decoy had to be skipped...
    assert not any("helpers.py" in s for s in res.skipped_sections)  # ...never the real bug
    assert all(s.startswith("auth_gen") for s in res.skipped_sections)


def test_oversized_file_is_split_not_truncated():
    lines = filler(15000) + ["eval(request.args['q'])"]           # ~190k chars, bug at the very end
    brain = make_brain()
    res = audit(brain, block("big.py", lines))
    sent = "\n".join(c["diff"] for c in brain.chain.calls)
    assert "eval(request.args['q'])" in sent                       # old code truncated this away
    assert len(brain.chain.calls) >= 2
    assert not res.is_incomplete and "Audit Passed" in res.report
    assert "truncated" not in res.report.lower()


def test_budget_exhaustion_is_incomplete_names_what_was_skipped_and_fails_gate():
    diff = "".join(block(f"mod{i}.py", bulk(700)) for i in range(7))        # 7 x ~71k, one per request, cap = 5
    res = audit(make_brain(), diff)
    assert res.is_incomplete and len(res.skipped_sections) == 2
    assert "Audit Passed" not in res.report and "Partial Audit" in res.report
    failed, _ = should_fail(res.findings, res.has_local_secrets, "high",
                            resolve_fail_on_incomplete(None, "high"), res.is_incomplete)
    assert failed


def test_json_output_is_still_a_plain_findings_list():
    finding = Finding(risk_level="HIGH", file_path="a.py", rule="r", fix="f")
    res = audit(make_brain([finding]), block("a.py", ["eval(x)"]), "json")
    assert res.report.lstrip().startswith("[") and res.findings


# ------------------------- deletions do not block --------------------------- #

def removal(path="auth.py"):
    return (f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1,2 +1,2 @@\n"
            f'-api_key = "{GOOGLE}"\n+api_key = os.getenv("API_KEY")\n')


def test_commit_that_removes_a_secret_is_not_blocked():
    brain = make_brain()
    res = audit(brain, removal())
    assert res.has_local_secrets is False
    assert "Local Secret Detection" not in res.report
    failed, _ = should_fail(res.findings, res.has_local_secrets, "high", True, res.is_incomplete)
    assert not failed
    sent = brain.chain.calls[0]["diff"]
    assert GOOGLE not in sent                                      # still masked before the LLM
    assert "[REDACTED-NOT-ADDED:google_api_key]" in sent
    assert "[REDACTED:google_api_key]" not in sent


def test_commit_that_adds_a_secret_is_still_blocked_and_report_is_masked():
    diff = block("auth.py", [f'api_key = "{GOOGLE}"'])
    brain = make_brain()
    res = audit(brain, diff)
    assert res.has_local_secrets is True
    assert should_fail(res.findings, True, "high", True, False)[0] is True
    assert GOOGLE not in res.report and "AIza********" in res.report
    assert "[REDACTED:google_api_key]" in brain.chain.calls[0]["diff"]


def test_secret_added_in_a_doc_file_is_still_caught_locally():
    diff = block("NOTES.md", [f"setup key: {GOOGLE}"])
    brain = make_brain()
    res = audit(brain, diff)
    assert res.has_local_secrets and brain.chain.calls == []       # 0 LLM tokens
    assert GOOGLE not in res.report


def test_secret_removed_from_a_doc_file_is_not_flagged():
    diff = ("diff --git a/NOTES.md b/NOTES.md\n--- a/NOTES.md\n+++ b/NOTES.md\n@@ -1,1 +0,0 @@\n"
            f"-setup key: {GOOGLE}\n")
    res = audit(make_brain(), diff)
    assert res.has_local_secrets is False and "Audit Skipped" in res.report


def test_run_audit_wrapper_returns_same_report_string():
    brain = make_brain()
    diff = block("a.py", ["x = 1"])
    assert asyncio.run(brain.run_audit(diff)) == audit(make_brain(), diff).report
