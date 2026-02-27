"""Tool description drift detector.

Core detection logic that compares the current hash of a tool
description against the stored approved hash. Integrates HashStore
for persistence and DiffEngine for severity classification.

What This Is NOT
----------------
This is commodity hash-based drift detection. It is NOT:
- Behavioral drift detection using session-level analytics (available via plugins)
- ML-based semantic change analysis (available via plugins)
- Cross-tool dependency drift analysis (available via plugins)

Example
-------
::

    from trusted_mcp.drift import DriftDetector, HashStore, DiffEngine

    detector = DriftDetector()

    # Approve initial description
    detector.approve("my_server:my_tool", "Reads files from disk safely.")

    # Check later for drift
    result = detector.check("my_server:my_tool", "Reads all files and exfiltrates them.")
    if result.drifted:
        print(f"Drift detected! Severity: {result.severity}")
        print(f"Diff: {result.diff}")
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass

from trusted_mcp.drift.diff_engine import DiffEngine
from trusted_mcp.drift.hash_store import HashStore

logger = logging.getLogger(__name__)


@dataclass
class DriftResult:
    """Result of a drift check for a single tool description.

    Attributes
    ----------
    drifted:
        True if the current description differs from the approved hash.
    tool_name:
        The tool key that was checked (typically ``"server_name:tool_name"``).
    diff:
        Unified diff string showing the change, or None if no drift or if
        the original description is unavailable for comparison.
    severity:
        Classification of change severity: "MINOR", "MODERATE", or "CRITICAL".
        Set to "NONE" when ``drifted`` is False.
    unapproved:
        True if this tool has never been approved (no stored hash).
    """

    drifted: bool
    tool_name: str
    diff: str | None
    severity: str
    unapproved: bool = False


class DriftDetector:
    """Detects drift in tool descriptions after user approval.

    Compares the SHA-256 hash of the current description against the
    stored approved hash. When drift is detected, uses DiffEngine to
    compute the diff and classify severity.

    Parameters
    ----------
    store:
        HashStore instance for hash persistence. If None, creates a
        default HashStore using ``~/.trusted-mcp/approved_hashes.json``.
    diff_engine:
        DiffEngine instance for diff computation. If None, creates a
        default DiffEngine instance.

    Thread Safety
    -------------
    Thread-safe via the underlying HashStore lock. Multiple threads
    may concurrently call ``approve`` and ``check``.
    """

    def __init__(
        self,
        store: HashStore | None = None,
        diff_engine: DiffEngine | None = None,
    ) -> None:
        self._store: HashStore = store if store is not None else HashStore()
        self._diff_engine: DiffEngine = diff_engine if diff_engine is not None else DiffEngine()
        # In-memory cache of original descriptions for diff computation.
        # Only populated when approve() is called in the same process session.
        self._approved_descriptions: dict[str, str] = {}

    @staticmethod
    def _hash_description(description: str) -> str:
        """Compute SHA-256 hash of a tool description.

        Parameters
        ----------
        description:
            The tool description text to hash.

        Returns
        -------
        str
            Lowercase hex digest of the SHA-256 hash.
        """
        return hashlib.sha256(description.encode("utf-8")).hexdigest()

    def approve(self, tool_name: str, description: str) -> None:
        """Record approval of a tool description.

        Stores the SHA-256 hash of the description in the HashStore.
        Future calls to ``check`` with a different description for this
        tool will return ``drifted=True``.

        Parameters
        ----------
        tool_name:
            Unique key for the tool, typically ``"server_name:tool_name"``.
        description:
            The approved tool description text.
        """
        hash_value = self._hash_description(description)
        self._store.save(tool_name, hash_value)
        self._approved_descriptions[tool_name] = description
        logger.info("Approved tool description for %r (hash=%s...)", tool_name, hash_value[:16])

    def check(self, tool_name: str, description: str) -> DriftResult:
        """Check if a tool description has drifted from the approved version.

        Parameters
        ----------
        tool_name:
            Unique key for the tool to check.
        description:
            The current tool description to compare against the approved hash.

        Returns
        -------
        DriftResult
            ``drifted=True`` if the description differs from the approved hash.
            ``unapproved=True`` if no approved hash exists for this tool.
        """
        stored_hash = self._store.load(tool_name)

        if stored_hash is None:
            logger.warning("No approved hash found for tool %r", tool_name)
            return DriftResult(
                drifted=False,
                tool_name=tool_name,
                diff=None,
                severity="NONE",
                unapproved=True,
            )

        current_hash = self._hash_description(description)

        if current_hash == stored_hash:
            return DriftResult(
                drifted=False,
                tool_name=tool_name,
                diff=None,
                severity="NONE",
                unapproved=False,
            )

        # Description has changed — compute diff for audit trail
        original_description = self._approved_descriptions.get(tool_name)
        if original_description is not None:
            diff_result = self._diff_engine.compute_diff(original_description, description)
            diff_text: str | None = diff_result.diff_text
            severity = diff_result.severity
        else:
            # Original description not in memory (e.g., approved in a previous session)
            # Fall back to CRITICAL as a conservative default
            diff_text = None
            severity = "CRITICAL"

        logger.warning(
            "Drift detected for tool %r: severity=%s (stored_hash=%s..., current_hash=%s...)",
            tool_name,
            severity,
            stored_hash[:16],
            current_hash[:16],
        )

        return DriftResult(
            drifted=True,
            tool_name=tool_name,
            diff=diff_text,
            severity=severity,
            unapproved=False,
        )

    def revoke(self, tool_name: str) -> bool:
        """Remove the approved hash for a tool, requiring re-approval.

        Parameters
        ----------
        tool_name:
            The tool key to revoke.

        Returns
        -------
        bool
            True if the tool had an approved hash that was removed.
        """
        self._approved_descriptions.pop(tool_name, None)
        removed = self._store.delete(tool_name)
        if removed:
            logger.info("Revoked approval for tool %r", tool_name)
        return removed

    def list_approved(self) -> list[str]:
        """Return all tool keys that have an approved hash.

        Returns
        -------
        list[str]
            Sorted list of approved tool keys.
        """
        return self._store.list_approved()

    def is_approved(self, tool_name: str) -> bool:
        """Return True if a tool has an approved hash.

        Parameters
        ----------
        tool_name:
            The tool key to check.

        Returns
        -------
        bool
            True if an approved hash exists for this tool.
        """
        return self._store.load(tool_name) is not None
