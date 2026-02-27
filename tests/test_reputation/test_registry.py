"""Tests for trusted_mcp.reputation.registry."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from trusted_mcp.reputation.registry import (
    ReputationRegistry,
    ReputationReport,
    ReportType,
    ServerReputation,
)


def _make_violation_report(server_id: str = "srv://test", severity: int = 5) -> ReputationReport:
    return ReputationReport(
        server_id=server_id,
        report_type=ReportType.VIOLATION,
        severity=severity,
        description="Test violation",
    )


def _make_endorsement_report(server_id: str = "srv://test") -> ReputationReport:
    return ReputationReport(
        server_id=server_id,
        report_type=ReportType.ENDORSEMENT,
        severity=0,
        description="Positive endorsement",
    )


class TestReputationReport:
    def test_valid_report_creation(self) -> None:
        report = _make_violation_report()
        assert report.server_id == "srv://test"
        assert report.report_type == ReportType.VIOLATION
        assert report.severity == 5

    def test_invalid_severity_raises(self) -> None:
        with pytest.raises(ValueError, match="severity"):
            ReputationReport(
                server_id="srv",
                report_type=ReportType.VIOLATION,
                severity=11,
                description="bad",
            )

    def test_report_id_auto_generated(self) -> None:
        r1 = _make_violation_report()
        r2 = _make_violation_report()
        assert r1.report_id != r2.report_id

    def test_created_at_set(self) -> None:
        report = _make_violation_report()
        assert report.created_at != ""


class TestServerReputation:
    def test_default_score_is_70(self) -> None:
        rep = ServerReputation(server_id="srv")
        assert rep.trust_score == 70

    def test_apply_report_increments_count(self) -> None:
        rep = ServerReputation(server_id="srv")
        report = _make_violation_report()
        rep.apply_report(report, new_score=60)
        assert rep.report_count == 1

    def test_apply_violation_increments_violation_count(self) -> None:
        rep = ServerReputation(server_id="srv")
        rep.apply_report(_make_violation_report(), new_score=60)
        assert rep.violation_count == 1

    def test_apply_endorsement_increments_endorsement_count(self) -> None:
        rep = ServerReputation(server_id="srv")
        rep.apply_report(_make_endorsement_report(), new_score=73)
        assert rep.endorsement_count == 1

    def test_apply_report_updates_score(self) -> None:
        rep = ServerReputation(server_id="srv")
        rep.apply_report(_make_violation_report(), new_score=55)
        assert rep.trust_score == 55

    def test_score_clamped_to_min(self) -> None:
        rep = ServerReputation(server_id="srv")
        rep.apply_report(_make_violation_report(), new_score=-5)
        assert rep.trust_score == 0

    def test_score_clamped_to_max(self) -> None:
        rep = ServerReputation(server_id="srv")
        rep.apply_report(_make_endorsement_report(), new_score=105)
        assert rep.trust_score == 100


class TestReputationRegistry:
    def test_get_score_default_for_new_server(self) -> None:
        registry = ReputationRegistry()
        score = registry.get_score("new://server")
        assert score == 70

    def test_add_violation_reduces_score(self) -> None:
        registry = ReputationRegistry()
        initial = registry.get_score("srv://test")
        registry.add_report(_make_violation_report("srv://test", severity=8))
        assert registry.get_score("srv://test") < initial

    def test_add_endorsement_increases_score(self) -> None:
        registry = ReputationRegistry()
        initial = registry.get_score("srv://test")
        registry.add_report(_make_endorsement_report("srv://test"))
        assert registry.get_score("srv://test") >= initial

    def test_multiple_violations_compound(self) -> None:
        registry = ReputationRegistry()
        for _ in range(5):
            registry.add_report(_make_violation_report("srv://test", severity=5))
        assert registry.get_score("srv://test") < 50

    def test_get_reputation_creates_if_absent(self) -> None:
        registry = ReputationRegistry()
        rep = registry.get_reputation("new://server")
        assert isinstance(rep, ServerReputation)
        assert rep.server_id == "new://server"

    def test_all_servers_lists_known_servers(self) -> None:
        registry = ReputationRegistry()
        registry.add_report(_make_violation_report("srv://a"))
        registry.add_report(_make_violation_report("srv://b"))
        servers = registry.all_servers()
        assert "srv://a" in servers
        assert "srv://b" in servers

    def test_servers_below_threshold(self) -> None:
        registry = ReputationRegistry()
        for _ in range(8):
            registry.add_report(_make_violation_report("srv://bad", severity=10))
        registry.add_report(_make_endorsement_report("srv://good"))
        below = registry.servers_below_threshold(50)
        ids = [r.server_id for r in below]
        assert "srv://bad" in ids
        assert "srv://good" not in ids

    def test_reset_restores_initial_score(self) -> None:
        registry = ReputationRegistry()
        for _ in range(5):
            registry.add_report(_make_violation_report("srv://test", severity=10))
        registry.reset("srv://test")
        assert registry.get_score("srv://test") == 70

    def test_reports_stored_in_reputation(self) -> None:
        registry = ReputationRegistry()
        registry.add_report(_make_violation_report("srv://test"))
        rep = registry.get_reputation("srv://test")
        assert len(rep.reports) == 1

    def test_json_persistence_save_and_load(self) -> None:
        with tempfile.NamedTemporaryFile(
            suffix=".json", delete=False
        ) as tmp:
            tmp_path = Path(tmp.name)

        try:
            reg1 = ReputationRegistry(cache_path=tmp_path)
            reg1.add_report(_make_violation_report("srv://test", severity=7))
            saved_score = reg1.get_score("srv://test")

            reg2 = ReputationRegistry(cache_path=tmp_path)
            loaded_score = reg2.get_score("srv://test")
            assert saved_score == loaded_score
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_nonexistent_cache_starts_fresh(self) -> None:
        registry = ReputationRegistry(
            cache_path=Path("/nonexistent/reputation.json")
        )
        # Should not raise; just start fresh (file doesn't exist)
        assert registry.all_servers() == []
