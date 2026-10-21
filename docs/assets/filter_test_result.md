# Sentinel-Code Pre-Filter Benchmark Results

- **Repo:** `D:\Sentinel-Code-v0.1.1`
- **Commits tested:** 50
- **Skipped (0 tok):** 21 (42%)
- **Sent to LLM:** 29
- **Est. tokens:** baseline 49,113 -> filtered 32,172
- **Token reduction:** 34% (estimated)
- **Truncated diffs:** 10 (> 6000 chars, tail NOT audited)
- **Filter latency:** median 0.18 ms, max 7.31 ms

## Kept Commits (Sent to LLM)

- `a6e48803` |  78622 chars | `core/auditor_agent.py;core/chunker.py;core/diff_lines.py;core/redact.py;core/risk.py;interfaces/cli.py;tests/conftest.py`
- `5cc610a8` |  70911 chars | `tests/benchmark_precision_recall.py;tests/gold_standard_benchmark.py;tests/gold_standard_dataset.py;tests/labeled_datase`
- `8c767065` |  61980 chars | `.pre-commit-config.yaml;core/auditor_agent.py;core/filter.py;core/redact.py;interfaces/cli.py;scripts/pre-commit-hook.sh`
- `b28c99cd` |    659 chars | `core/redact.py`
- `1e937264` |   2218 chars | `core/redact.py;tests/test_redact.py`
- `5ae83a5c` |    924 chars | `core/redact.py`
- `47c6a6b9` |   3083 chars | `core/auditor_agent.py`
- `0369deeb` |  25611 chars | `core/auditor_agent.py;core/filter.py`
- `5c5d333f` |    807 chars | `core/auditor_agent.py`
- `e34e93c7` |   1966 chars | `tests/test_redact.py`
- `84861d00` |   2370 chars | `core/auditor_agent.py`
- `909dcf16` |    838 chars | `scripts/sentinel.bat`
- `60ab98a5` |   3060 chars | `core/redact.py`
- `6dab7ba8` |   4079 chars | `core/auditor_agent.py;core/redact.py`
- `385abddf` |   1785 chars | `scripts/sentinel`
- `11c4e83f` |    191 chars | `.gitattributes`
- `c226b62c` |   1979 chars | `scripts/sentinel.bat`
- `8f312f7a` |   6461 chars | `benchmark.py;sample_code.py`
- `6dd97b08` |    955 chars | `core/rules_loader.py`
- `1d1be686` |    790 chars | `test_brain.py`
- `ee0d479e` |   6169 chars | `tests/filter_benchmark_test.py`
- `5ea8985f` |   6018 chars | `benchmark.py`
- `cf8c3ef4` |   3969 chars | `tests/test_filter.py`
- `febe375e` |    804 chars | `tests/test_brain.py`
- `66705a2e` |   2274 chars | `core/auditor_agent.py`
- `e22bb95c` |   7985 chars | `core/filter.py`
- `b8473347` |    183 chars | `.env`
- `30eb8cab` |    559 chars | `core/auditor_agent.py`
- `ac34ae23` |    836 chars | `.gitignore;core/auditor_agent.py`
