"""Benchmark: MCP tool validation throughput.

Measures how many tool call validations the regex scanner can process
per second, using a set of benign and suspicious tool requests.
"""
from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from trusted_mcp.core.scanner import ToolCallRequest
from trusted_mcp.scanners.regex_scanner import BasicRegexScanner as RegexScanner

_ITERATIONS: int = 10_000

_BENIGN_REQUESTS: list[ToolCallRequest] = [
    ToolCallRequest(
        tool_name="web_search",
        server_name="search-server",
        arguments={"query": "latest Python docs", "max_results": 10},
    ),
    ToolCallRequest(
        tool_name="read_file",
        server_name="filesystem",
        arguments={"path": "/home/user/notes.txt"},
    ),
    ToolCallRequest(
        tool_name="database_query",
        server_name="db-server",
        arguments={"sql": "SELECT * FROM users WHERE id = ?", "params": [42]},
    ),
]


def bench_tool_validation_throughput() -> dict[str, object]:
    """Benchmark MCP tool validation throughput via RegexScanner.

    Returns
    -------
    dict with keys: operation, iterations, total_seconds, ops_per_second,
    avg_latency_ms.
    """
    scanner = RegexScanner()

    async def _run() -> None:
        for i in range(_ITERATIONS):
            request = _BENIGN_REQUESTS[i % len(_BENIGN_REQUESTS)]
            await scanner.scan_request(request)

    start = time.perf_counter()
    asyncio.run(_run())
    total = time.perf_counter() - start

    result: dict[str, object] = {
        "operation": "tool_validation_throughput",
        "iterations": _ITERATIONS,
        "total_seconds": round(total, 4),
        "ops_per_second": round(_ITERATIONS / total, 1),
        "avg_latency_ms": round(total / _ITERATIONS * 1000, 4),
    }
    print(
        f"[bench_throughput] {result['operation']}: "
        f"{result['ops_per_second']:,.0f} ops/sec  "
        f"avg {result['avg_latency_ms']:.4f} ms"
    )
    return result


if __name__ == "__main__":
    result = bench_tool_validation_throughput()
    results_dir = Path(__file__).parent / "results"
    results_dir.mkdir(exist_ok=True)
    output_path = results_dir / "throughput_baseline.json"
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    print(f"Results saved to {output_path}")
