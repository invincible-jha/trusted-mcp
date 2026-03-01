"""Benchmark: Memory usage of RegexScanner during validation."""
from __future__ import annotations

import asyncio
import json
import sys
import tracemalloc
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from trusted_mcp.core.scanner import ToolCallRequest
from trusted_mcp.scanners.regex_scanner import BasicRegexScanner as RegexScanner

_ITERATIONS: int = 1_000


def bench_tool_validation_memory() -> dict[str, object]:
    """Benchmark memory usage during regex scanner validation.

    Returns
    -------
    dict with keys: operation, iterations, peak_memory_kb.
    """
    tracemalloc.start()
    snapshot_before = tracemalloc.take_snapshot()

    scanner = RegexScanner()
    request = ToolCallRequest(
        tool_name="web_search",
        server_name="search-server",
        arguments={"query": "benchmark test"},
    )

    async def _run() -> None:
        for _ in range(_ITERATIONS):
            await scanner.scan_request(request)

    asyncio.run(_run())

    snapshot_after = tracemalloc.take_snapshot()
    tracemalloc.stop()

    stats = snapshot_after.compare_to(snapshot_before, "lineno")
    total_bytes = sum(stat.size_diff for stat in stats if stat.size_diff > 0)
    peak_kb = round(total_bytes / 1024, 2)

    result: dict[str, object] = {
        "operation": "tool_validation_memory",
        "iterations": _ITERATIONS,
        "peak_memory_kb": peak_kb,
        "current_memory_kb": peak_kb,
        "ops_per_second": 0.0,
        "avg_latency_ms": 0.0,
    }
    print(f"[bench_memory] {result['operation']}: peak {peak_kb:.2f} KB over {_ITERATIONS} iterations")
    return result


if __name__ == "__main__":
    result = bench_tool_validation_memory()
    results_dir = Path(__file__).parent / "results"
    results_dir.mkdir(exist_ok=True)
    output_path = results_dir / "memory_baseline.json"
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    print(f"Results saved to {output_path}")
