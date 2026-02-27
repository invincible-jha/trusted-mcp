"""Tests for trusted_mcp.reputation.trust_scorer."""
from __future__ import annotations

import pytest

from trusted_mcp.reputation.registry import (
    ReportType,
    ReputationReport,
    ServerReputation,
)
from trusted_mcp.reputation.trust_scorer import (
    TrustScorer,
    TrustScorerConfig,
    compute_trust_score,
)


def _make_reputation(server_id: str = "srv://test") -> ServerReputation:
    return ServerReputation(server_id=server_id)


def _make_report(
    report_type: ReportType = ReportType.VIOLATION,
    severity: int = 5,
    server_id: str = "srv://test",
) -> ReputationReport:
    return ReputationReport(
        server_id=server_id,
        report_type=report_type,
        severity=severity,
        description="Test report",
    )


class TestTrustScorerConfig:
    def test_frozen_dataclass(self) -> None:
        cfg = TrustScorerConfig()
        with pytest.raises((AttributeError, TypeError)):
            cfg.initial_score = 50  # type: ignore[misc]

    def test_default_initial_score(self) -> None:
        cfg = TrustScorerConfig()
        assert cfg.initial_score == 70


class TestTrustScorerCompute:
    def test_violation_decreases_score(self) -> None:
        scorer = TrustScorer()
        rep = _make_reputation()
        initial = rep.trust_score
        new_score = scorer.compute(rep, _make_report(ReportType.VIOLATION, 5))
        assert new_score < initial

    def test_endorsement_increases_score(self) -> None:
        scorer = TrustScorer()
        rep = _make_reputation()
        initial = rep.trust_score
        new_score = scorer.compute(rep, _make_report(ReportType.ENDORSEMENT, 0))
        assert new_score >= initial

    def test_high_severity_violation_larger_penalty(self) -> None:
        scorer = TrustScorer()
        rep_low = _make_reputation()
        rep_high = _make_reputation()
        score_low = scorer.compute(rep_low, _make_report(ReportType.VIOLATION, 1))
        score_high = scorer.compute(rep_high, _make_report(ReportType.VIOLATION, 10))
        assert score_low > score_high

    def test_anomaly_decreases_score(self) -> None:
        scorer = TrustScorer()
        rep = _make_reputation()
        initial = rep.trust_score
        new_score = scorer.compute(rep, _make_report(ReportType.ANOMALY, 5))
        assert new_score < initial

    def test_timeout_decreases_score(self) -> None:
        scorer = TrustScorer()
        rep = _make_reputation()
        initial = rep.trust_score
        new_score = scorer.compute(rep, _make_report(ReportType.TIMEOUT, 0))
        assert new_score < initial

    def test_schema_mismatch_decreases_score(self) -> None:
        scorer = TrustScorer()
        rep = _make_reputation()
        initial = rep.trust_score
        new_score = scorer.compute(rep, _make_report(ReportType.SCHEMA_MISMATCH, 0))
        assert new_score < initial

    def test_score_clamped_to_zero(self) -> None:
        scorer = TrustScorer()
        rep = ServerReputation(server_id="srv", trust_score=0)
        new_score = scorer.compute(rep, _make_report(ReportType.VIOLATION, 10))
        assert new_score == 0

    def test_score_clamped_to_100(self) -> None:
        scorer = TrustScorer()
        rep = ServerReputation(server_id="srv", trust_score=100)
        new_score = scorer.compute(rep, _make_report(ReportType.ENDORSEMENT, 0))
        assert new_score == 100

    def test_custom_config_applied(self) -> None:
        cfg = TrustScorerConfig(per_violation_penalty=20.0)
        scorer = TrustScorer(config=cfg)
        rep = _make_reputation()
        initial = rep.trust_score
        new_score = scorer.compute(rep, _make_report(ReportType.VIOLATION, 5))
        # Should be penalized more heavily than with default config
        default_scorer = TrustScorer()
        default_score = default_scorer.compute(_make_reputation(), _make_report(ReportType.VIOLATION, 5))
        assert new_score < default_score


class TestComputeTrustScoreConvenience:
    def test_returns_int(self) -> None:
        rep = _make_reputation()
        score = compute_trust_score(rep)
        assert isinstance(score, int)

    def test_with_report_changes_score(self) -> None:
        rep = _make_reputation()
        report = _make_report(ReportType.VIOLATION, 8)
        initial = rep.trust_score
        new_score = compute_trust_score(rep, report)
        assert new_score < initial

    def test_without_report_reflects_history(self) -> None:
        rep = _make_reputation()
        report = _make_report(ReportType.VIOLATION, 5)
        rep.apply_report(report, new_score=60)
        score = compute_trust_score(rep)
        assert isinstance(score, int)
        assert 0 <= score <= 100


class TestTrustScorerScoreFromReputation:
    def test_fresh_server_returns_near_initial(self) -> None:
        scorer = TrustScorer()
        rep = _make_reputation()
        score = scorer.score_from_reputation(rep)
        # Fresh server with no reports, small age bonus possible
        assert 70 <= score <= 80

    def test_server_with_violations_lower(self) -> None:
        scorer = TrustScorer()
        rep = _make_reputation()
        for _ in range(3):
            report = _make_report(ReportType.VIOLATION, 8)
            rep.apply_report(report, new_score=rep.trust_score)  # keep score stale
            rep.reports.append(report)
        score = scorer.score_from_reputation(rep)
        assert score < 70
