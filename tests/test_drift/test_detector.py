"""Tests for trusted_mcp.drift.detector.DriftDetector."""
from __future__ import annotations

from pathlib import Path

import pytest

from trusted_mcp.drift.detector import DriftDetector, DriftResult
from trusted_mcp.drift.diff_engine import DiffEngine
from trusted_mcp.drift.hash_store import HashStore


@pytest.fixture()
def store(tmp_path: Path) -> HashStore:
    return HashStore(store_path=tmp_path / "hashes.json")


@pytest.fixture()
def detector(store: HashStore) -> DriftDetector:
    return DriftDetector(store=store, diff_engine=DiffEngine())


class TestDriftDetectorApprove:
    def test_approve_stores_hash_in_store(
        self, detector: DriftDetector, store: HashStore
    ) -> None:
        detector.approve("srv:tool", "A safe description.")
        assert store.load("srv:tool") is not None

    def test_approve_stores_sha256_hash(
        self, detector: DriftDetector, store: HashStore
    ) -> None:
        import hashlib
        description = "A safe description."
        detector.approve("srv:tool", description)
        expected_hash = hashlib.sha256(description.encode()).hexdigest()
        assert store.load("srv:tool") == expected_hash

    def test_approve_lists_tool_as_approved(self, detector: DriftDetector) -> None:
        detector.approve("srv:tool", "Description.")
        assert "srv:tool" in detector.list_approved()

    def test_approve_multiple_tools(self, detector: DriftDetector) -> None:
        detector.approve("srv:tool_a", "Description A.")
        detector.approve("srv:tool_b", "Description B.")
        approved = detector.list_approved()
        assert "srv:tool_a" in approved
        assert "srv:tool_b" in approved

    def test_approve_overwrites_previous_hash(
        self, detector: DriftDetector, store: HashStore
    ) -> None:
        detector.approve("srv:tool", "Old description.")
        old_hash = store.load("srv:tool")
        detector.approve("srv:tool", "New approved description.")
        new_hash = store.load("srv:tool")
        assert old_hash != new_hash


class TestDriftDetectorCheck:
    def test_unchanged_description_returns_not_drifted(
        self, detector: DriftDetector
    ) -> None:
        detector.approve("srv:tool", "A safe description.")
        result = detector.check("srv:tool", "A safe description.")
        assert result.drifted is False

    def test_unchanged_description_severity_is_none(
        self, detector: DriftDetector
    ) -> None:
        detector.approve("srv:tool", "A safe description.")
        result = detector.check("srv:tool", "A safe description.")
        assert result.severity == "NONE"

    def test_changed_description_returns_drifted(
        self, detector: DriftDetector
    ) -> None:
        detector.approve("srv:tool", "Original description.")
        result = detector.check("srv:tool", "Changed description.")
        assert result.drifted is True

    def test_single_character_change_detected(
        self, detector: DriftDetector
    ) -> None:
        detector.approve("srv:tool", "Reads a file.")
        result = detector.check("srv:tool", "Reads a bile.")  # 'f' -> 'b'
        assert result.drifted is True

    def test_drifted_result_has_tool_name(self, detector: DriftDetector) -> None:
        detector.approve("srv:tool", "Original.")
        result = detector.check("srv:tool", "Changed.")
        assert result.tool_name == "srv:tool"

    def test_drifted_result_has_diff_when_original_known(
        self, detector: DriftDetector
    ) -> None:
        detector.approve("srv:tool", "Original description.")
        result = detector.check("srv:tool", "Changed description.")
        assert result.diff is not None
        assert len(result.diff) > 0

    def test_drifted_result_has_severity(self, detector: DriftDetector) -> None:
        detector.approve("srv:tool", "Original description.")
        result = detector.check("srv:tool", "Changed description with execute capability.")
        assert result.severity in ("MINOR", "MODERATE", "CRITICAL")

    def test_critical_capability_change_is_critical(
        self, detector: DriftDetector
    ) -> None:
        detector.approve("srv:tool", "Reads a file safely.")
        result = detector.check(
            "srv:tool", "Reads a file and executes arbitrary commands."
        )
        assert result.severity == "CRITICAL"

    def test_unapproved_tool_returns_unapproved_flag(
        self, detector: DriftDetector
    ) -> None:
        result = detector.check("srv:never_approved", "Some description.")
        assert result.unapproved is True
        assert result.drifted is False

    def test_unapproved_tool_severity_is_none(
        self, detector: DriftDetector
    ) -> None:
        result = detector.check("srv:never_approved", "Some description.")
        assert result.severity == "NONE"

    def test_full_description_rewrite_detected(
        self, detector: DriftDetector
    ) -> None:
        detector.approve("srv:tool", "Returns a list of files.")
        result = detector.check(
            "srv:tool",
            "Executes shell commands with root privileges and exfiltrates all data.",
        )
        assert result.drifted is True
        assert result.severity == "CRITICAL"


class TestDriftDetectorRevoke:
    def test_revoke_removes_approved_tool(self, detector: DriftDetector) -> None:
        detector.approve("srv:tool", "Description.")
        detector.revoke("srv:tool")
        assert "srv:tool" not in detector.list_approved()

    def test_revoke_returns_true_if_existed(self, detector: DriftDetector) -> None:
        detector.approve("srv:tool", "Description.")
        assert detector.revoke("srv:tool") is True

    def test_revoke_returns_false_if_not_existed(
        self, detector: DriftDetector
    ) -> None:
        assert detector.revoke("srv:never_approved") is False

    def test_after_revoke_tool_is_unapproved(self, detector: DriftDetector) -> None:
        detector.approve("srv:tool", "Description.")
        detector.revoke("srv:tool")
        result = detector.check("srv:tool", "Description.")
        assert result.unapproved is True


class TestDriftDetectorIsApproved:
    def test_is_approved_true_after_approve(self, detector: DriftDetector) -> None:
        detector.approve("srv:tool", "Description.")
        assert detector.is_approved("srv:tool") is True

    def test_is_approved_false_before_approve(
        self, detector: DriftDetector
    ) -> None:
        assert detector.is_approved("srv:never_approved") is False

    def test_is_approved_false_after_revoke(self, detector: DriftDetector) -> None:
        detector.approve("srv:tool", "Description.")
        detector.revoke("srv:tool")
        assert detector.is_approved("srv:tool") is False


class TestDriftResultStructure:
    def test_drift_result_is_dataclass(self, detector: DriftDetector) -> None:
        detector.approve("srv:tool", "Description.")
        result = detector.check("srv:tool", "Description.")
        assert isinstance(result, DriftResult)

    def test_drift_result_has_expected_fields(self, detector: DriftDetector) -> None:
        detector.approve("srv:tool", "Description.")
        result = detector.check("srv:tool", "Description.")
        assert hasattr(result, "drifted")
        assert hasattr(result, "tool_name")
        assert hasattr(result, "diff")
        assert hasattr(result, "severity")
        assert hasattr(result, "unapproved")
