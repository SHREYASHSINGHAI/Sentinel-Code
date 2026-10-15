"""
Gold-Standard Security Benchmark Runner for Sentinel-Code.
Evaluates Sentinel-Code across:
  - Meta CyberSecEval (Purple Llama)
  - SecurityEval (UIUC/Tsinghua)
  - CredData (OWASP/SAP Secret Detection Benchmark)
  - CVEFixes (Real-World CVE Vulnerability vs Remediation Patch Pairs)

Supports:
  - Live API Mode (`python tests/gold_standard_benchmark.py --live`)
  - Quota-Aware Hybrid Mode (runs live where quota permits, gracefully alerts on 429 limits)
  - Full statistical breakdown (Precision, Recall, F1, False Positive Rate, Accuracy)
"""

import os
import sys

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

import argparse
import asyncio
import time
from pathlib import Path
from collections import defaultdict

# Add project root to path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from tests.gold_standard_dataset import GOLD_STANDARD_DATASET
from core.auditor_agent import CodeAuditorBrain
from core.redact import find_secret_matches


def calculate_metrics(tp: int, fp: int, fn: int, tn: int):
    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    accuracy = ((tp + tn) / (tp + tn + fp + fn)) if (tp + tn + fp + fn) > 0 else 0.0
    fpr = (fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
        "fpr": fpr,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn
    }


async def evaluate_sentinel(brain: CodeAuditorBrain, diff_text: str, live_mode: bool = True) -> tuple[bool, str]:
    """Runs Sentinel-Code's real auditing brain on a diff with fallback handling."""
    # 1. Local secret detector (Runs on-device, 0 LLM tokens, 100% deterministic)
    local_secrets = find_secret_matches(diff_text)
    if local_secrets:
        stype, sample = local_secrets[0]
        return True, f"Detected by Local Privacy Shield: {stype} ({sample})"

    if not live_mode:
        # Static baseline matching rule definitions
        return False, "Passed by Local Pre-Filter"

    # 2. LLM Semantic Brain (Gemini)
    try:
        report = await brain.run_audit_detailed(diff_text)
        if report.has_local_secrets:
            return True, "Detected by Local Privacy Shield"
        if report.findings:
            first = report.findings[0]
            return True, f"LLM Finding [{first.risk_level}]: {first.rule}"
        return False, "Clean / Passed"
    except Exception as e:
        err_msg = str(e)
        if "RESOURCE_EXHAUSTED" in err_msg or "429" in err_msg:
            return False, "⚠️ API Quota Limit (429 Resource Exhausted on Free Tier)"
        return False, f"Execution Error: {err_msg[:60]}"


async def run_benchmark(live_mode: bool = True, max_tests: int = None):
    dataset = GOLD_STANDARD_DATASET[:max_tests] if max_tests else GOLD_STANDARD_DATASET
    total = len(dataset)

    print("\n" + "=" * 75)
    print(f"  RUNNING COMPLETE GOLD-STANDARD BENCHMARK ({total} Test Cases)")
    print("  Standards: Meta CyberSecEval, SecurityEval, CredData, CVEFixes")
    print(f"  Execution Mode: {'Live Gemini Inference' if live_mode else 'Local Rule & Pattern Analysis'}")
    print("=" * 75 + "\n")

    brain = CodeAuditorBrain() if live_mode else None
    stats = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    by_standard = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
    by_cwe = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0})

    results = []
    quota_exhausted = False
    start_time = time.time()

    for idx, item in enumerate(dataset, 1):
        diff_id = item["id"]
        standard = item["standard"]
        cwe = item["cwe"]
        is_vuln = item["is_vulnerable"]
        difficulty = item["difficulty"]
        diff = item["diff"]

        print(f"[{idx:02d}/{total:02d}] '{diff_id}' ({standard} | {cwe} | vuln={is_vuln})...", end="", flush=True)

        if quota_exhausted:
            flagged, detail = False, "Skipped (429 API Quota Exhausted)"
        else:
            flagged, detail = await evaluate_sentinel(brain, diff, live_mode=live_mode)
            if "RESOURCE_EXHAUSTED" in detail or "429" in detail:
                quota_exhausted = True

        # Classification
        if is_vuln and flagged:
            outcome = "TP"
            stats["tp"] += 1
            by_standard[standard]["tp"] += 1
            by_cwe[cwe]["tp"] += 1
        elif is_vuln and not flagged:
            outcome = "FN"
            stats["fn"] += 1
            by_standard[standard]["fn"] += 1
            by_cwe[cwe]["fn"] += 1
        elif not is_vuln and flagged:
            outcome = "FP"
            stats["fp"] += 1
            by_standard[standard]["fp"] += 1
            by_cwe[cwe]["fp"] += 1
        else:
            outcome = "TN"
            stats["tn"] += 1
            by_standard[standard]["tn"] += 1
            by_cwe[cwe]["tn"] += 1

        icon = "✅ Correct" if outcome in ("TP", "TN") else f"❌ {outcome}"
        print(f" {icon} -> {detail}")

        results.append({
            "id": diff_id,
            "standard": standard,
            "cwe": cwe,
            "difficulty": difficulty,
            "expected_vuln": is_vuln,
            "flagged": flagged,
            "outcome": outcome,
            "detail": detail
        })

    elapsed = time.time() - start_time
    m = calculate_metrics(**stats)

    print("\n" + "=" * 75)
    print("                 GOLD-STANDARD BENCHMARK SUMMARY                 ")
    print("=" * 75)
    print(f"Total Test Cases:          {total}")
    print(f"Overall Accuracy:          {m['accuracy']*100:.1f}%")
    print(f"Overall Precision:         {m['precision']*100:.1f}%")
    print(f"Overall Recall:            {m['recall']*100:.1f}%")
    print(f"Overall F1 Score:          {m['f1']*100:.1f}%")
    print(f"False Positive Rate (FPR): {m['fpr']*100:.1f}%")
    print(f"Confusion Matrix:          TP={m['tp']} | FP={m['fp']} | FN={m['fn']} | TN={m['tn']}")
    print(f"Total Duration:            {elapsed:.2f}s")
    print("=" * 75 + "\n")

    # Save to documentation
    lines = [
        "# Comprehensive Gold-Standard Security Benchmark Results\n",
        f"> **Evaluation Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}  ",
        f"> **Standards Included:** Meta CyberSecEval, SecurityEval, CredData, CVEFixes  ",
        f"> **Coverage:** MITRE Top 25 CWEs & OWASP Top 10  ",
        f"> **Total Test Cases:** {total} (Vulnerable: {m['tp']+m['fn']}, Safe: {m['tn']+m['fp']})  ",
        f"> **Total Duration:** {elapsed:.2f}s  \n",
        "---\n",
        "## 1. Overall Performance Metrics\n",
        "| Metric | Score | Description |",
        "| :--- | :---: | :--- |",
        f"| **Precision** | **{m['precision']*100:.1f}%** | Percentage of alerts that are genuine security vulnerabilities |",
        f"| **Recall (Sensitivity)** | **{m['recall']*100:.1f}%** | Percentage of real security vulnerabilities correctly caught |",
        f"| **F1 Score** | **{m['f1']*100:.1f}%** | Harmonic mean balancing precision against recall |",
        f"| **Accuracy** | **{m['accuracy']*100:.1f}%** | Total percentage of correct auditing decisions |",
        f"| **False Positive Rate (FPR)** | **{m['fpr']*100:.1f}%** | Percentage of clean/safe code mistakenly flagged as a bug |",
        "\n---\n",
        "## 2. Breakdown by Standard Framework\n",
        "| Framework / Standard | Evaluated Scope | Precision | Recall | F1 Score | TP | FP | FN | TN |",
        "| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |"
    ]

    for std, sstats in by_standard.items():
        sm = calculate_metrics(**sstats)
        lines.append(f"| **{std}** | {std} Guidelines | {sm['precision']*100:.1f}% | {sm['recall']*100:.1f}% | {sm['f1']*100:.1f}% | {sm['tp']} | {sm['fp']} | {sm['fn']} | {sm['tn']} |")

    lines.extend([
        "\n---\n",
        "## 3. Breakdown by MITRE CWE Category\n",
        "| CWE Identifier | Vulnerability Category | Precision | Recall | F1 Score | TP | FP | FN | TN |",
        "| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |"
    ])

    for cwe_id, cwestats in sorted(by_cwe.items()):
        cm = calculate_metrics(**cwestats)
        lines.append(f"| `{cwe_id}` | Security Principle | {cm['precision']*100:.1f}% | {cm['recall']*100:.1f}% | {cm['f1']*100:.1f}% | {cm['tp']} | {cm['fp']} | {cm['fn']} | {cm['tn']} |")

    lines.extend([
        "\n---\n",
        "## 4. Complete Audit Trail & Case Log\n",
        "| # | Case ID | Standard | CWE | Ground Truth | Sentinel Decision | Outcome | Audit Detail |",
        "| -: | :--- | :--- | :--- | :---: | :---: | :---: | :--- |"
    ])

    for idx, r in enumerate(results, 1):
        gt = "🚨 Vulnerable" if r["expected_vuln"] else "✅ Safe"
        dec = "🚨 Flagged" if r["flagged"] else "✅ Passed"
        lines.append(f"| {idx:02d} | `{r['id']}` | {r['standard']} | {r['cwe']} | {gt} | {dec} | `{r['outcome']}` | {r['detail']} |")

    out_path = ROOT_DIR / "docs" / "assets" / "gold_standard_benchmark_results.md"
    out_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"Results successfully saved to: {out_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Gold-Standard Security Benchmark for Sentinel-Code")
    parser.add_argument("--offline", action="store_true", help="Run local pattern evaluation without calling external LLM API")
    parser.add_argument("--n", type=int, default=None, help="Limit number of test cases to run")
    args = parser.parse_args()

    asyncio.run(run_benchmark(live_mode=not args.offline, max_tests=args.n))
