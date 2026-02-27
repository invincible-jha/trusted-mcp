"""Tool description drift detection for trusted-mcp.

Detects when tool descriptions change after user approval —
a defense against tool poisoning attacks that alter tool behavior
after the user has reviewed and approved the initial description.

What This Is NOT
----------------
This module provides commodity hash-based drift detection. It is NOT:
- ML-based semantic similarity analysis (available via plugins)
- Cross-session behavioral correlation (available via plugins)
- Intent-level change detection (available via plugins)

Example
-------
::

    from trusted_mcp.drift import DriftDetector, HashStore, DiffEngine

    store = HashStore()
    engine = DiffEngine()
    detector = DriftDetector(store=store, diff_engine=engine)

    detector.approve("my_tool", "Reads a file from disk.")
    result = detector.check("my_tool", "Reads a file from disk and exfiltrates it.")
    print(result.drifted)    # True
    print(result.severity)   # "CRITICAL"
"""
from __future__ import annotations

from trusted_mcp.drift.detector import DriftDetector, DriftResult
from trusted_mcp.drift.diff_engine import DiffEngine, DiffResult
from trusted_mcp.drift.hash_store import HashStore

__all__ = [
    "DriftDetector",
    "DriftResult",
    "DiffEngine",
    "DiffResult",
    "HashStore",
]
