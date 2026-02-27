"""Server reputation registry with local JSON persistence.

The ReputationRegistry maintains a per-server reputation record that
aggregates reports from trust audits and security scans. Scores are
stored as a local JSON cache on disk (or in-memory only when no path
is configured).

Score range: 0 (completely untrusted) to 100 (fully trusted).
New servers start at 70 (neutral-positive assumption).
"""
from __future__ import annotations

import json
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from trusted_mcp.reputation.trust_scorer import TrustScorer

logger = logging.getLogger(__name__)

_DEFAULT_INITIAL_SCORE: int = 70
_MIN_SCORE: int = 0
_MAX_SCORE: int = 100


class ReportType(str, Enum):
    """Category of reputation report submitted by a caller."""

    VIOLATION = "violation"          # Security policy violation
    ANOMALY = "anomaly"              # Behavioral anomaly detected
    ENDORSEMENT = "endorsement"      # Positive endorsement from trusted operator
    TIMEOUT = "timeout"              # Tool call timeout
    SCHEMA_MISMATCH = "schema_mismatch"  # Tool description mismatch


@dataclass
class ReputationReport:
    """A single incident report affecting a server's reputation.

    Attributes
    ----------
    server_id:
        The MCP server identifier this report pertains to.
    report_type:
        Category of the report.
    severity:
        0-10 score indicating report severity (10 = most severe).
    description:
        Human-readable description of the incident.
    report_id:
        Auto-generated unique identifier for this report.
    created_at:
        UTC timestamp when this report was created.
    reporter:
        Optional identifier of the reporting system or operator.
    """

    server_id: str
    report_type: ReportType
    severity: int
    description: str
    report_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    reporter: str = ""

    def __post_init__(self) -> None:
        if not 0 <= self.severity <= 10:
            raise ValueError(
                f"Report severity must be between 0 and 10, got {self.severity}."
            )


@dataclass
class ServerReputation:
    """Aggregated reputation record for a single MCP server.

    Attributes
    ----------
    server_id:
        Unique identifier for the MCP server.
    trust_score:
        Current trust score (0-100). Higher is more trusted.
    report_count:
        Total number of reports submitted for this server.
    violation_count:
        Number of violation-category reports.
    endorsement_count:
        Number of endorsement-category reports.
    last_updated:
        ISO-8601 UTC timestamp of the most recent update.
    first_seen:
        ISO-8601 UTC timestamp when the server was first registered.
    reports:
        List of all reports submitted for this server.
    """

    server_id: str
    trust_score: int = _DEFAULT_INITIAL_SCORE
    report_count: int = 0
    violation_count: int = 0
    endorsement_count: int = 0
    last_updated: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    first_seen: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    reports: list[ReputationReport] = field(default_factory=list)

    def apply_report(self, report: ReputationReport, new_score: int) -> None:
        """Update the reputation record with a new report.

        Parameters
        ----------
        report:
            The incoming report to record.
        new_score:
            Recalculated trust score after this report.
        """
        self.reports.append(report)
        self.report_count += 1
        if report.report_type == ReportType.VIOLATION:
            self.violation_count += 1
        elif report.report_type == ReportType.ENDORSEMENT:
            self.endorsement_count += 1
        self.trust_score = max(_MIN_SCORE, min(_MAX_SCORE, new_score))
        self.last_updated = datetime.now(timezone.utc).isoformat()


def _reputation_to_dict(reputation: ServerReputation) -> dict[str, object]:
    """Serialize a ServerReputation to a JSON-safe dict."""
    data = asdict(reputation)
    return data


def _reputation_from_dict(data: dict[str, object]) -> ServerReputation:
    """Deserialize a ServerReputation from a dict loaded from JSON."""
    reports_raw = data.pop("reports", [])
    reputation = ServerReputation(**data)
    reputation.reports = [
        ReputationReport(
            server_id=r["server_id"],
            report_type=ReportType(r["report_type"]),
            severity=r["severity"],
            description=r["description"],
            report_id=r.get("report_id", str(uuid.uuid4())),
            created_at=r.get("created_at", ""),
            reporter=r.get("reporter", ""),
        )
        for r in reports_raw
    ]
    return reputation


class ReputationRegistry:
    """Local reputation registry for MCP servers.

    Usage
    -----
    ::

        registry = ReputationRegistry(cache_path=Path("reputation.json"))
        registry.add_report(ReputationReport(
            server_id="mcp://tools.example.com",
            report_type=ReportType.VIOLATION,
            severity=7,
            description="Tool returned unexpected schema",
        ))
        score = registry.get_score("mcp://tools.example.com")
        print(score)   # 0-100

    Persistence
    -----------
    When ``cache_path`` is provided, the registry is persisted to JSON
    after every write operation (add_report, reset). When no path is
    provided, the registry operates in-memory only.
    """

    def __init__(
        self,
        cache_path: Path | None = None,
        initial_score: int = _DEFAULT_INITIAL_SCORE,
    ) -> None:
        """Initialise the registry.

        Parameters
        ----------
        cache_path:
            Optional path to the JSON persistence file. If the file
            exists on construction, it is loaded automatically.
        initial_score:
            Default trust score for newly registered servers.
        """
        self._reputations: dict[str, ServerReputation] = {}
        self._cache_path = cache_path
        self._initial_score = initial_score

        if cache_path and cache_path.exists():
            self._load_cache()

    # ------------------------------------------------------------------
    # Registry operations
    # ------------------------------------------------------------------

    def get_reputation(self, server_id: str) -> ServerReputation:
        """Return the reputation record for *server_id*, creating it if absent.

        Parameters
        ----------
        server_id:
            The MCP server identifier.

        Returns
        -------
        ServerReputation
        """
        if server_id not in self._reputations:
            self._reputations[server_id] = ServerReputation(
                server_id=server_id,
                trust_score=self._initial_score,
            )
        return self._reputations[server_id]

    def get_score(self, server_id: str) -> int:
        """Return the current trust score for *server_id*.

        Parameters
        ----------
        server_id:
            The MCP server identifier.

        Returns
        -------
        int
            Trust score 0-100. Returns the initial score if the server
            has never been reported.
        """
        return self.get_reputation(server_id).trust_score

    def add_report(
        self,
        report: ReputationReport,
        scorer: TrustScorer | None = None,
    ) -> ServerReputation:
        """Submit a reputation report and update the server's score.

        Parameters
        ----------
        report:
            The report to add.
        scorer:
            Optional TrustScorer instance. If not provided, a default
            scorer is used to compute the new score.

        Returns
        -------
        ServerReputation
            Updated reputation record.
        """
        from trusted_mcp.reputation.trust_scorer import TrustScorer

        if scorer is None:
            scorer = TrustScorer()

        reputation = self.get_reputation(report.server_id)
        new_score = scorer.compute(reputation, report)
        reputation.apply_report(report, new_score)

        logger.info(
            "Report added: server=%r type=%s severity=%d new_score=%d",
            report.server_id,
            report.report_type.value,
            report.severity,
            new_score,
        )

        if self._cache_path:
            self._save_cache()

        return reputation

    def reset(self, server_id: str) -> None:
        """Reset a server's reputation to the initial score.

        Parameters
        ----------
        server_id:
            The MCP server to reset.
        """
        self._reputations[server_id] = ServerReputation(
            server_id=server_id,
            trust_score=self._initial_score,
        )
        if self._cache_path:
            self._save_cache()

    def all_servers(self) -> list[str]:
        """Return all server IDs currently in the registry.

        Returns
        -------
        list[str]
        """
        return list(self._reputations.keys())

    def servers_below_threshold(self, threshold: int) -> list[ServerReputation]:
        """Return all servers with a trust score below *threshold*.

        Parameters
        ----------
        threshold:
            Score boundary (exclusive lower bound).

        Returns
        -------
        list[ServerReputation]
        """
        return [
            rep for rep in self._reputations.values()
            if rep.trust_score < threshold
        ]

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _save_cache(self) -> None:
        assert self._cache_path is not None
        data = {
            server_id: _reputation_to_dict(rep)
            for server_id, rep in self._reputations.items()
        }
        try:
            self._cache_path.write_text(
                json.dumps(data, indent=2), encoding="utf-8"
            )
            logger.debug("Reputation cache saved to %s", self._cache_path)
        except OSError as exc:
            logger.error("Failed to save reputation cache: %s", exc)

    def _load_cache(self) -> None:
        assert self._cache_path is not None
        try:
            raw = json.loads(self._cache_path.read_text(encoding="utf-8"))
            for server_id, rep_data in raw.items():
                self._reputations[server_id] = _reputation_from_dict(rep_data)
            logger.debug(
                "Loaded %d reputation records from cache", len(self._reputations)
            )
        except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
            logger.warning("Failed to load reputation cache: %s", exc)
            self._reputations = {}
