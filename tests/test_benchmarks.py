"""Structural tests for trusted-mcp benchmark module."""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).parent.parent / "benchmarks"))


def test_bench_throughput_importable() -> None:
    """Verify bench_throughput module can be imported."""
    mod = importlib.import_module("bench_throughput")
    assert hasattr(mod, "bench_tool_validation_throughput")


def test_bench_latency_importable() -> None:
    """Verify bench_latency module can be imported."""
    mod = importlib.import_module("bench_latency")
    assert hasattr(mod, "bench_tool_validation_latency")


def test_bench_memory_importable() -> None:
    """Verify bench_memory module can be imported."""
    mod = importlib.import_module("bench_memory")
    assert hasattr(mod, "bench_tool_validation_memory")


def test_throughput_returns_expected_keys() -> None:
    """Verify bench_tool_validation_throughput returns expected result keys."""
    from bench_throughput import bench_tool_validation_throughput

    result = bench_tool_validation_throughput()
    assert "operation" in result
    assert "iterations" in result
    assert "ops_per_second" in result
    assert "avg_latency_ms" in result
    assert float(result["ops_per_second"]) > 0  # type: ignore[arg-type]


def test_latency_returns_expected_keys() -> None:
    """Verify bench_tool_validation_latency returns expected result keys."""
    from bench_latency import bench_tool_validation_latency

    result = bench_tool_validation_latency()
    assert "operation" in result
    assert "ops_per_second" in result
    assert "avg_latency_ms" in result
    assert "p50_ms" in result
    assert "p95_ms" in result
