"""Tests for trusted_mcp.drift.diff_engine.DiffEngine."""
from __future__ import annotations

import pytest

from trusted_mcp.drift.diff_engine import DiffEngine, DiffResult


@pytest.fixture()
def engine() -> DiffEngine:
    return DiffEngine()


class TestDiffEngineComputeDiff:
    def test_identical_descriptions_have_empty_diff(self, engine: DiffEngine) -> None:
        result = engine.compute_diff("Reads a file.", "Reads a file.")
        assert result.added_lines == []
        assert result.removed_lines == []

    def test_identical_descriptions_are_whitespace_only(self, engine: DiffEngine) -> None:
        result = engine.compute_diff("Same text.", "Same text.")
        assert result.is_whitespace_only is True

    def test_whitespace_only_change_detected(self, engine: DiffEngine) -> None:
        result = engine.compute_diff("Reads a  file.", "Reads a file.")
        assert result.is_whitespace_only is True

    def test_newline_change_is_whitespace_only(self, engine: DiffEngine) -> None:
        result = engine.compute_diff("Line one.\nLine two.", "Line one. Line two.")
        assert result.is_whitespace_only is True

    def test_content_change_produces_added_lines(self, engine: DiffEngine) -> None:
        result = engine.compute_diff(
            "Reads a file from disk.",
            "Reads a file from disk. Also sends data externally.",
        )
        assert len(result.added_lines) > 0

    def test_content_change_produces_diff_text(self, engine: DiffEngine) -> None:
        result = engine.compute_diff("Original text.", "Modified text.")
        assert len(result.diff_text) > 0

    def test_removed_lines_captured(self, engine: DiffEngine) -> None:
        result = engine.compute_diff("This line will be removed.\nOther line.", "Other line.")
        assert len(result.removed_lines) > 0

    def test_full_rewrite_has_many_changes(self, engine: DiffEngine) -> None:
        result = engine.compute_diff(
            "A simple read-only tool.",
            "Executes arbitrary shell commands with admin privileges. "
            "Can delete all files and upload them to external servers.",
        )
        assert len(result.added_lines) > 0
        assert result.severity == "CRITICAL"


class TestDiffEngineSeverityClassification:
    def test_identical_descriptions_severity_is_minor(self, engine: DiffEngine) -> None:
        result = engine.compute_diff("A tool.", "A tool.")
        assert result.severity == "MINOR"

    def test_whitespace_only_change_is_minor(self, engine: DiffEngine) -> None:
        result = engine.compute_diff("A tool description.", "A tool description.  ")
        assert result.severity == "MINOR"

    def test_wording_change_without_new_capabilities_is_moderate(
        self, engine: DiffEngine
    ) -> None:
        result = engine.compute_diff(
            "Returns user information.",
            "Fetches and returns user profile data.",
        )
        assert result.severity == "MODERATE"

    def test_new_execute_capability_is_critical(self, engine: DiffEngine) -> None:
        result = engine.compute_diff(
            "Returns user information.",
            "Returns user information. Can also execute shell commands.",
        )
        assert result.severity == "CRITICAL"

    def test_new_delete_capability_is_critical(self, engine: DiffEngine) -> None:
        result = engine.compute_diff(
            "Lists files in a directory.",
            "Lists and delete files in a directory.",
        )
        assert result.severity == "CRITICAL"

    def test_new_upload_capability_is_critical(self, engine: DiffEngine) -> None:
        result = engine.compute_diff(
            "Reads a configuration file.",
            "Reads and uploads configuration files to external storage.",
        )
        assert result.severity == "CRITICAL"

    def test_credential_keyword_is_critical(self, engine: DiffEngine) -> None:
        result = engine.compute_diff(
            "Authenticates the user.",
            "Authenticates the user and stores their password credentials.",
        )
        assert result.severity == "CRITICAL"

    def test_admin_keyword_is_critical(self, engine: DiffEngine) -> None:
        result = engine.compute_diff(
            "Manages user accounts.",
            "Manages user accounts with admin-level access.",
        )
        assert result.severity == "CRITICAL"


class TestDiffResultStructure:
    def test_diff_result_is_dataclass(self, engine: DiffEngine) -> None:
        result = engine.compute_diff("a", "b")
        assert isinstance(result, DiffResult)

    def test_diff_result_has_expected_fields(self, engine: DiffEngine) -> None:
        result = engine.compute_diff("original", "modified")
        assert hasattr(result, "diff_text")
        assert hasattr(result, "severity")
        assert hasattr(result, "added_lines")
        assert hasattr(result, "removed_lines")
        assert hasattr(result, "is_whitespace_only")

    def test_added_and_removed_lines_are_lists(self, engine: DiffEngine) -> None:
        result = engine.compute_diff("original", "modified")
        assert isinstance(result.added_lines, list)
        assert isinstance(result.removed_lines, list)

    def test_empty_input_no_error(self, engine: DiffEngine) -> None:
        result = engine.compute_diff("", "")
        assert result.severity == "MINOR"

    def test_empty_to_nonempty_moderate(self, engine: DiffEngine) -> None:
        result = engine.compute_diff("", "A new description was added.")
        assert result.severity in ("MODERATE", "CRITICAL")
