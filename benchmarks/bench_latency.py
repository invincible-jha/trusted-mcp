"""Benchmark: MCP tool validation latency (p50/p95/mean)."""
from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from trusted_mcp.core.scanner import ToolCallRequest
from trusted_mcp.scanners.regex_scanner import BasicRegexScanner as RegexScanner

_WARMUP: int = 100
_ITERATIONS: int = 3_000


def bench_tool_validation_latency() -> dict[str, object]:
    """Benchmark tool validation latency via RegexScanner.

    Returns
    -------
    dict with keys: operation, iterations, total_seconds, ops_per_second,
    avg_latency_ms, p50_ms, p95_ms.
    """
    scanner = RegexScanner()
    request = ToolCallRequest(
        tool_name="web_search",
        server_name="search-server",
        arguments={"query": "hello world"},
    )
    latencies_ms: list[float] = []

    async def _run() -> None:
        for _ in range(_WARMUP):
            await scanner.scan_request(request)
        for _ in range(_ITERATIONS):
            t0 = time.perf_counter()
            await scanner.scan_request(request)
            latencies_ms.append((time.perf_counter() - t0) * 1000)

    asyncio.run(_run())

    sorted_lats = sorted(latencies_ms)
    n = len(sorted_lats)
    total = sum(latencies_ms) / 1000

    result: dict[str, object] = {
        "operation": "tool_validation_latency",
        "iterations": _ITERATIONS,
        "total_seconds": round(total, 4),
        "ops_per_second": round(_ITERATIONS / total, 1),
        "avg_latency_ms": round(sum(latencies_ms) / n, 4),
        "p50_ms": round(sorted_lats[int(n * 0.50)], 4),
        "p95_ms": round(sorted_lats[min(int(n * 0.95), n - 1)], 4),
    }
    print(
        f"[bench_latency] {result['operation']}: "
        f"p50={result['p50_ms']:.4f}ms  p95={result['p95_ms']:.4f}ms  "
        f"mean={result['avg_latency_ms']:.4f}ms"
    )
    return result


if __name__ == "__main__":
    result = bench_tool_validation_latency()
    results_dir = Path(__file__).parent / "results"
    results_dir.mkdir(exist_ok=True)
    output_path = results_dir / "latency_baseline.json"
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    print(f"Results saved to {output_path}")
