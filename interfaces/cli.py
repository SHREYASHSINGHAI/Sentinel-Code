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
        return True, "Audit was incomplete (diff truncated or request limit hit)."

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
        action="store_true",
        help="Fail (exit 1) if diff was truncated or files were skipped due to request limits"
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
        fail_on_incomplete=args.fail_on_incomplete,
        is_incomplete=result.is_incomplete
    )

    if failed:
        if args.format == "markdown":
            print(f"\n❌ [Audit Failed]: Gatekeeper policy triggered: {reason}", file=sys.stderr)
        sys.exit(1)

    if args.format == "markdown":
        print("\n✅ Gate check passed.")
    sys.exit(0)


if __name__ == "__main__":
    asyncio.run(main())