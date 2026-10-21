import argparse
import asyncio
import os
import subprocess
import sys
from dotenv import load_dotenv
from core.auditor_agent import CodeAuditorBrain, Finding

load_dotenv()

def get_staged_git_diff() -> tuple[str, bool]:
    """
    Executes 'git diff --staged' to get staged local code changes.
    Returns (diff_text, success_boolean).
    """
    try:
        result = subprocess.run(
            ["git", "diff", "--staged"],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip(), True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error getting git diff: {e.stderr or e}", file=sys.stderr)
        return "", False
    except FileNotFoundError:
        print("❌ Git is not installed or not found in PATH.", file=sys.stderr)
        return "", False


def resolve_fail_on_incomplete(flag: bool | None, fail_on: str) -> bool:
    """
    Incomplete audits FAIL by default: files that were skipped were never checked,
    so a partial audit must not pass the gate silently.

    flag is the tri-state CLI value: True (--fail-on-incomplete), False
    (--no-fail-on-incomplete) or None (not given). When not given, it follows the
    policy: on, except in report-only mode (--fail-on none).
    """
    if flag is not None:
        return flag
    return fail_on != "none"


def should_fail(
    findings: list[Finding],
    has_local_secrets: bool,
    fail_on: str,
    fail_on_incomplete: bool,
    is_incomplete: bool
) -> tuple[bool, str]:
    """Determines whether the CLI should exit with a non-zero code based on policy."""
    if has_local_secrets and fail_on != "none":
        return True, "Hardcoded secrets detected by local privacy scanner."

    if fail_on_incomplete and is_incomplete:
        return True, "Audit was incomplete (part of the diff was not checked: request limit hit)."

    if fail_on == "none":
        return False, ""

    thresholds = {
        "high": {"HIGH"},
        "medium": {"HIGH", "MEDIUM"},
        "low": {"HIGH", "MEDIUM", "LOW"},
        "any": {"HIGH", "MEDIUM", "LOW"},
    }
    target_risks = thresholds.get(fail_on.lower(), set())

    violations = [f for f in findings if f.risk_level in target_risks]
    if violations:
        return True, f"Found {len(violations)} security violation(s) matching threshold '{fail_on}'."

    return False, ""


async def main():
    parser = argparse.ArgumentParser(description="Sentinel-Code Local Git Diff Auditor & Gatekeeper")
    parser.add_argument(
        "--format",
        choices=["markdown", "json", "sarif"],
        default="markdown",
        help="Output format: markdown (default), json, or sarif"
    )
    parser.add_argument(
        "--fail-on",
        choices=["high", "medium", "low", "any", "none"],
        default="high",
        help="Fail (exit 1) if findings at or above this risk level are found (default: high)"
    )
    parser.add_argument(
        "--fail-on-incomplete",
        action=argparse.BooleanOptionalAction,
        default=None,
        help=(
            "Fail (exit 1) if parts of the diff were not audited because of the request limit. "
            "ON by default (except with --fail-on none); use --no-fail-on-incomplete to allow partial audits"
        )
    )
    parser.add_argument(
        "--model",
        default=os.getenv("MODEL", "gemini-2.5-flash"),
        help="LLM model to use (defaults to MODEL in .env or gemini-2.5-flash)"
    )
    args = parser.parse_args()

    diff_text, success = get_staged_git_diff()
    if not success:
        sys.exit(1)

    if not diff_text:
        if args.format == "markdown":
            print("ℹ️ No staged changes found. Use 'git add <file>' before running audit.")
        sys.exit(0)

    if args.format == "markdown":
        print("🔍 Fetching staged changes from Git...")
        print(f"🤖 Running Sentinel-Code Local Audit (Model: {args.model})...\n")

    brain = CodeAuditorBrain(model_name=args.model)
    result = await brain.run_audit_detailed(diff_text, output_format=args.format)

    if args.format == "markdown":
        print("=" * 60)
        print(result.report)
        print("=" * 60)
    else:
        print(result.report)

    failed, reason = should_fail(
        findings=result.findings,
        has_local_secrets=result.has_local_secrets,
        fail_on=args.fail_on,
        fail_on_incomplete=resolve_fail_on_incomplete(args.fail_on_incomplete, args.fail_on),
        is_incomplete=result.is_incomplete
    )

    if failed:
        # stderr, for every format: json/sarif stdout stays machine-readable but CI still sees why
        print(f"\n❌ [Audit Failed]: Gatekeeper policy triggered: {reason}", file=sys.stderr)
        sys.exit(1)

    if args.format == "markdown":
        print("\n✅ Gate check passed.")
    sys.exit(0)


if __name__ == "__main__":
    asyncio.run(main())