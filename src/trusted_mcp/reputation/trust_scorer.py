"""Trust score computation for MCP server reputation.

Computes a weighted trust score based on:
- Server age (older = more established = higher base score)
- Total report count (more reports = more data = less uncertainty)
- Violation count (violations decrease trust)
- Endorsement count (endorsements increase trust)
- Most recent report type and severity

Formula
-------
The scoring uses a decay-based approach rooted in commodity actuarial math:

  base = initial_score
  age_bonus = min(age_days / age_cap_days, 1.0) * age_weight
  violation_penalty = violation_count * per_violation_penalty * severity_multiplier
  endorsement_bonus = endorsement_count * per_endorsement_bonus
  score = base + age_bonus - violation_penalty + endorsement_bonus

All parameters are configurable via TrustScorerConfig.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from trusted_mcp.reputation.registry import (
    ReportType,
    ReputationReport,
    ServerReputation,
)

logger = logging.getLogger(__name__)

_INITIAL_SCORE: int = 70
_MIN_SCORE: int = 0
_MAX_SCORE: int = 100


@dataclass(frozen=True)
class TrustScorerConfig:
    """Configuration parameters for TrustScorer.

    Attributes
    ----------
    initial_score:
        Starting score for all new servers (0-100).
    age_weight:
        Maximum bonus points awarded purely for server age.
    age_cap_days:
        Number of days after which the age bonus is fully accrued.
    per_violation_penalty:
        Points deducted per violation report (before severity scaling).
    severity_multiplier_weight:
        Fraction of the per-violation penalty that scales with severity.
        severity 10 = full multiplier; severity 0 = base penalty.
    per_endorsement_bonus:
        Points added per endorsement report.
    anomaly_penalty:
        Points deducted per anomaly report.
    timeout_penalty:
        Points deducted per timeout report.
    schema_penalty:
        Points deducted per schema-mismatch report.
    """

    initial_score: int = _INITIAL_SCORE
    age_weight: float = 10.0
    age_cap_days: float = 90.0
    per_violation_penalty: float = 8.0
    severity_multiplier_weight: float = 0.5
    per_endorsement_bonus: float = 3.0
    anomaly_penalty: float = 4.0
    timeout_penalty: float = 2.0
    schema_penalty: float = 3.0


def _parse_timestamp(ts: str) -> datetime | None:
    """Parse an ISO-8601 timestamp string to a datetime.

    Parameters
    ----------
    ts:
        ISO-8601 timestamp string.

    Returns
    -------
    datetime | None
        Parsed datetime in UTC, or None if parsing fails.
    """
    try:
        return datetime.fromisoformat(ts).astimezone(timezone.utc)
    except (ValueError, OSError):
        return None


def compute_trust_score(
    reputation: ServerReputation,
    new_report: ReputationReport | None = None,
    config: TrustScorerConfig | None = None,
) -> int:
    """Compute the trust score for a server from its reputation record.

    This is a module-level convenience wrapper around TrustScorer.

    Parameters
    ----------
    reputation:
        The server's reputation record.
    new_report:
        An optional incoming report to factor in.
    config:
        Optional scorer configuration; defaults are used if not provided.

    Returns
    -------
    int
        Trust score clamped to [0, 100].
    """
    scorer = TrustScorer(config=config)
    if new_report is None:
        return scorer.score_from_reputation(reputation)
    return scorer.compute(reputation, new_report)


class TrustScorer:
    """Computes trust scores for MCP servers using a weighted formula.

    Usage
    -----
    ::

        scorer = TrustScorer()
        new_score = scorer.compute(reputation, report)
    """

    def __init__(self, config: TrustScorerConfig | None = None) -> None:
        """Initialise the scorer.

        Parameters
        ----------
        config:
            Optional scorer configuration; defaults are used if not provided.
        """
        self.config = config or TrustScorerConfig()

    def score_from_reputation(self, reputation: ServerReputation) -> int:
        """Compute a score from the current reputation state (no new report).

        Parameters
        ----------
        reputation:
            The server's reputation record.

        Returns
        -------
        int
            Computed trust score clamped to [0, 100].
        """
        cfg = self.config

        # 1. Age bonus
        age_bonus = self._compute_age_bonus(reputation.first_seen)

        # 2. Violation penalties (use average severity from existing reports)
        violation_reports = [
            r for r in reputation.reports
            if r.report_type == ReportType.VIOLATION
        ]
        violation_penalty = self._compute_violation_penalty(violation_reports)

        # 3. Endorsement bonus
        endorsement_bonus = reputation.endorsement_count * cfg.per_endorsement_bonus

        # 4. Other report penalties
        other_penalty = self._compute_other_penalties(reputation.reports)

        raw = (
            cfg.initial_score
            + age_bonus
            - violation_penalty
            + endorsement_bonus
            - other_penalty
        )
        return max(_MIN_SCORE, min(_MAX_SCORE, round(raw)))

    def compute(
        self,
        reputation: ServerReputation,
        report: ReputationReport,
    ) -> int:
        """Compute the new score after applying an incoming report.

        Parameters
        ----------
        reputation:
            Current reputation record (before applying *report*).
        report:
            Incoming report to factor into the score.

        Returns
        -------
        int
            New trust score clamped to [0, 100].
        """
        cfg = self.config
        current_score = reputation.trust_score

        if report.report_type == ReportType.VIOLATION:
            severity_factor = 1.0 + (
                cfg.severity_multiplier_weight * report.severity / 10.0
            )
            penalty = cfg.per_violation_penalty * severity_factor
            new_score = current_score - penalty

        elif report.report_type == ReportType.ENDORSEMENT:
            new_score = current_score + cfg.per_endorsement_bonus

        elif report.report_type == ReportType.ANOMALY:
            severity_factor = 0.5 + (0.5 * report.severity / 10.0)
            new_score = current_score - (cfg.anomaly_penalty * severity_factor)

        elif report.report_type == ReportType.TIMEOUT:
            new_score = current_score - cfg.timeout_penalty

        elif report.report_type == ReportType.SCHEMA_MISMATCH:
            new_score = current_score - cfg.schema_penalty

        else:
            new_score = float(current_score)

        logger.debug(
            "Trust score for %r: %d -> %.1f (report=%s severity=%d)",
            report.server_id,
            current_score,
            new_score,
            report.report_type.value,
            report.severity,
        )

        return max(_MIN_SCORE, min(_MAX_SCORE, round(new_score)))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _compute_age_bonus(self, first_seen: str) -> float:
        cfg = self.config
        first_seen_dt = _parse_timestamp(first_seen)
        if first_seen_dt is None:
            return 0.0

        now = datetime.now(timezone.utc)
        age_days = max(0.0, (now - first_seen_dt).total_seconds() / 86400.0)
        age_fraction = min(age_days / cfg.age_cap_days, 1.0)
        return age_fraction * cfg.age_weight

    def _compute_violation_penalty(
        self, violation_reports: list[ReputationReport]
    ) -> float:
        cfg = self.config
        if not violation_reports:
            return 0.0

        total = 0.0
        for report in violation_reports:
            severity_factor = 1.0 + (
                cfg.severity_multiplier_weight * report.severity / 10.0
            )
            total += cfg.per_violation_penalty * severity_factor
        return total

    def _compute_other_penalties(
        self, all_reports: list[ReputationReport]
    ) -> float:
        cfg = self.config
        total = 0.0
        for report in all_reports:
            if report.report_type == ReportType.ANOMALY:
                severity_factor = 0.5 + (0.5 * report.severity / 10.0)
                total += cfg.anomaly_penalty * severity_factor
            elif report.report_type == ReportType.TIMEOUT:
                total += cfg.timeout_penalty
            elif report.report_type == ReportType.SCHEMA_MISMATCH:
                total += cfg.schema_penalty
        return total
