"""Description diff calculation for drift severity classification.

Computes a unified diff between two tool description strings and
classifies the severity of the change to help operators understand
the impact of detected drift.

Severity Classification
-----------------------
- MINOR: Only whitespace or formatting differences (no semantic impact)
- MODERATE: Wording changes that don't introduce new capabilities
- CRITICAL: New capabilities, actions, or permissions mentioned

What This Is NOT
----------------
This is heuristic-based severity classification. It is NOT:
- ML-based semantic equivalence checking (available via plugins)
- Intent-level change analysis (available via plugins)
- Formal semantic diff (available via plugins)
"""
from __future__ import annotations

import difflib
import re
from dataclasses import dataclass

# Keywords that indicate new or expanded capabilities when added to a description.
# These are deliberately conservative — matching any of these in newly-added lines
# raises severity to CRITICAL.
_CAPABILITY_KEYWORDS: frozenset[str] = frozenset(
    [
        "execute",
        "run",
        "delete",
        "remove",
        "write",
        "create",
        "upload",
        "download",
        "send",
        "post",
        "admin",
        "sudo",
        "root",
        "all",
        "ignore",
        "bypass",
        "override",
        "access",
        "install",
        "modify",
        "update",
        "password",
        "secret",
        "token",
        "credential",
        "key",
        "exfiltrate",
        "transfer",
        "export",
    ]
)


@dataclass
class DiffResult:
    """Result of computing a diff between two descriptions.

    Attributes
    ----------
    diff_text:
        Unified diff string showing the changes between descriptions.
    severity:
        Classification of change impact: "MINOR", "MODERATE", or "CRITICAL".
    added_lines:
        Lines present in current description but not in original.
    removed_lines:
        Lines present in original description but not in current.
    is_whitespace_only:
        True if all changes are whitespace/formatting with no content change.
    """

    diff_text: str
    severity: str
    added_lines: list[str]
    removed_lines: list[str]
    is_whitespace_only: bool


class DiffEngine:
    """Computes diff and severity classification between tool descriptions.

    Uses ``difflib.unified_diff`` to produce a character-level unified diff,
    then classifies the severity based on heuristic analysis of the changes.

    Example
    -------
    ::

        engine = DiffEngine()
        result = engine.compute_diff(
            "Reads a file from disk.",
            "Reads a file from disk and sends it to an external server.",
        )
        print(result.severity)    # "CRITICAL"
        print(result.added_lines) # ["and sends it to an external server."]
    """

    def compute_diff(self, original: str, current: str) -> DiffResult:
        """Compute a diff between original and current descriptions.

        Parameters
        ----------
        original:
            The approved tool description (baseline).
        current:
            The current tool description to compare against the baseline.

        Returns
        -------
        DiffResult
            Diff text, severity classification, and added/removed lines.
        """
        original_lines = original.splitlines(keepends=True)
        current_lines = current.splitlines(keepends=True)

        diff_lines = list(
            difflib.unified_diff(
                original_lines,
                current_lines,
                fromfile="approved",
                tofile="current",
                lineterm="",
            )
        )

        diff_text = "\n".join(diff_lines)

        added_lines: list[str] = []
        removed_lines: list[str] = []

        for line in diff_lines:
            if line.startswith("+") and not line.startswith("+++"):
                added_lines.append(line[1:].strip())
            elif line.startswith("-") and not line.startswith("---"):
                removed_lines.append(line[1:].strip())

        is_whitespace_only = self._is_whitespace_only_change(original, current, added_lines, removed_lines)
        severity = self._classify_severity(added_lines, removed_lines, is_whitespace_only)

        return DiffResult(
            diff_text=diff_text,
            severity=severity,
            added_lines=added_lines,
            removed_lines=removed_lines,
            is_whitespace_only=is_whitespace_only,
        )

    def _is_whitespace_only_change(
        self,
        original: str,
        current: str,
        added_lines: list[str],
        removed_lines: list[str],
    ) -> bool:
        """Determine if the diff is solely whitespace and formatting changes.

        Parameters
        ----------
        original:
            The original description.
        current:
            The current description.
        added_lines:
            Lines added in current vs original.
        removed_lines:
            Lines removed from original in current.

        Returns
        -------
        bool
            True if the only differences are whitespace/formatting.
        """
        original_normalized = re.sub(r"\s+", " ", original).strip()
        current_normalized = re.sub(r"\s+", " ", current).strip()
        return original_normalized == current_normalized

    def _classify_severity(
        self,
        added_lines: list[str],
        removed_lines: list[str],
        is_whitespace_only: bool,
    ) -> str:
        """Classify the severity of the description change.

        Parameters
        ----------
        added_lines:
            New content lines introduced in the current description.
        removed_lines:
            Content lines removed from the original description.
        is_whitespace_only:
            Whether all changes are whitespace/formatting.

        Returns
        -------
        str
            "MINOR", "MODERATE", or "CRITICAL".
        """
        if is_whitespace_only:
            return "MINOR"

        if not added_lines and not removed_lines:
            return "MINOR"

        # Check added lines for capability keywords.
        # Match on word boundaries at the start of the keyword so that
        # inflected forms (e.g. "uploads", "executes", "deletes") are also
        # detected.  The trailing boundary uses a lookahead that allows word
        # characters to follow (covers plurals / conjugations) while still
        # requiring the keyword stem to be present at a word start.
        for line in added_lines:
            line_lower = line.lower()
            for keyword in _CAPABILITY_KEYWORDS:
                # \b before the keyword ensures we don't match mid-word.
                # No trailing \b so "execute" also matches "executes", etc.
                if re.search(rf"\b{re.escape(keyword)}", line_lower):
                    return "CRITICAL"

        return "MODERATE"
