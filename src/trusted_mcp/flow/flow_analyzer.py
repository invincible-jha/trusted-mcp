"""Cross-server data flow analysis and leakage detection.

The FlowAnalyzer examines a sequence of DataTag lineage records and
identifies patterns that suggest potential information leakage:

1. Trust downgrade — data moving from HIGH to LOW/UNTRUSTED zones.
2. Excessive hop count — data traversing more servers than expected.
3. Cyclic flow — data returning to a server it has already visited.
4. Untrusted sink — data originating in a trusted zone ending in UNTRUSTED.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum

from trusted_mcp.flow.data_tagger import DataTag, DataTagger, TrustLevel

logger = logging.getLogger(__name__)

_TRUST_ORDER: dict[TrustLevel, int] = {
    TrustLevel.HIGH: 3,
    TrustLevel.MEDIUM: 2,
    TrustLevel.LOW: 1,
    TrustLevel.UNTRUSTED: 0,
}


class FlowRiskLevel(str, Enum):
    """Severity level for a detected information-flow risk."""

    INFO = "info"
    WARN = "warn"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class FlowRisk:
    """A single detected flow risk tied to a specific DataTag.

    Attributes
    ----------
    tag_id:
        The tag identifier of the implicated data.
    risk_level:
        Severity of the risk.
    description:
        Human-readable explanation of the risk.
    origin_server:
        The origin server of the data.
    involved_servers:
        All servers that have seen this data.
    """

    tag_id: str
    risk_level: FlowRiskLevel
    description: str
    origin_server: str
    involved_servers: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class FlowEvent:
    """A single step in a data-flow trace, for audit purposes.

    Attributes
    ----------
    tag_id:
        The tag this event relates to.
    from_server:
        The server that sent the data.
    to_server:
        The server that received the data.
    tool_name:
        The receiving tool.
    trust_delta:
        Positive if trust increased, negative if it decreased, 0 if same.
    """

    tag_id: str
    from_server: str
    to_server: str
    tool_name: str
    trust_delta: int = 0


class FlowAnalyzer:
    """Analyzes cross-server data flows for information leakage risks.

    Usage
    -----
    ::

        tagger = DataTagger()
        tagger.set_trust_level("internal_db", TrustLevel.HIGH)
        tagger.set_trust_level("external_api", TrustLevel.UNTRUSTED)

        tagged = tagger.tag(db_result, "internal_db", "query")
        forwarded = tagger.forward(tagged, "external_api", "post_data")

        analyzer = FlowAnalyzer(tagger)
        risks = analyzer.analyze()
        # -> [FlowRisk(risk_level=CRITICAL, ...)]
    """

    DEFAULT_MAX_HOPS: int = 5

    def __init__(
        self,
        tagger: DataTagger,
        max_hops: int = DEFAULT_MAX_HOPS,
    ) -> None:
        """Initialise the analyzer.

        Parameters
        ----------
        tagger:
            The DataTagger session to analyze.
        max_hops:
            Maximum allowed hop count before flagging as WARN.
        """
        self._tagger = tagger
        self.max_hops = max_hops

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self) -> list[FlowRisk]:
        """Analyze all tagged data and return detected risks.

        Returns
        -------
        list[FlowRisk]
            All risks detected across the current tagger session,
            sorted by severity (CRITICAL first).
        """
        risks: list[FlowRisk] = []
        for tag in self._tagger.all_tags():
            risks.extend(self._analyze_tag(tag))

        return sorted(
            risks,
            key=lambda r: _TRUST_ORDER.get(
                TrustLevel(r.risk_level.value)
                if r.risk_level.value in _TRUST_ORDER
                else TrustLevel.MEDIUM,
                0,
            ),
            reverse=True,
        )

    def analyze_tag(self, tag: DataTag) -> list[FlowRisk]:
        """Analyze a single DataTag for risks.

        Parameters
        ----------
        tag:
            The tag to analyze.

        Returns
        -------
        list[FlowRisk]
        """
        return self._analyze_tag(tag)

    def build_flow_events(self, tag: DataTag) -> list[FlowEvent]:
        """Build an ordered list of FlowEvents for a tag's lineage.

        Parameters
        ----------
        tag:
            The tag whose lineage to trace.

        Returns
        -------
        list[FlowEvent]
            One event per hop in the lineage (may be empty for unforwarded data).
        """
        events: list[FlowEvent] = []
        if not tag.lineage:
            return events

        origin_trust = _TRUST_ORDER.get(tag.trust_level, 2)
        prev_server = tag.origin_server
        prev_trust = origin_trust

        for hop_server, hop_tool in tag.lineage:
            hop_trust_level = self._tagger.trust_level_for(hop_server)
            hop_trust = _TRUST_ORDER.get(hop_trust_level, 2)
            delta = hop_trust - prev_trust

            events.append(
                FlowEvent(
                    tag_id=tag.tag_id,
                    from_server=prev_server,
                    to_server=hop_server,
                    tool_name=hop_tool,
                    trust_delta=delta,
                )
            )
            prev_server = hop_server
            prev_trust = hop_trust

        return events

    def flag_leakage(
        self,
        tag: DataTag,
        *,
        severity: FlowRiskLevel = FlowRiskLevel.HIGH,
        reason: str = "",
    ) -> FlowRisk:
        """Manually flag a tag as a leakage risk.

        Useful for callers that detect leakage through domain-specific logic.

        Parameters
        ----------
        tag:
            The tag to flag.
        severity:
            The risk level to assign.
        reason:
            Human-readable reason for the flag.

        Returns
        -------
        FlowRisk
        """
        return FlowRisk(
            tag_id=tag.tag_id,
            risk_level=severity,
            description=reason or f"Manually flagged leakage for tag {tag.tag_id}",
            origin_server=tag.origin_server,
            involved_servers=frozenset(tag.servers_in_lineage()),
        )

    # ------------------------------------------------------------------
    # Internal analysis
    # ------------------------------------------------------------------

    def _analyze_tag(self, tag: DataTag) -> list[FlowRisk]:
        risks: list[FlowRisk] = []

        if not tag.has_crossed_boundary:
            return risks

        all_servers = tag.servers_in_lineage()

        # 1. Trust downgrade detection
        trust_risk = self._check_trust_downgrade(tag)
        if trust_risk:
            risks.append(trust_risk)

        # 2. Excessive hop count
        if tag.hop_count > self.max_hops:
            risks.append(
                FlowRisk(
                    tag_id=tag.tag_id,
                    risk_level=FlowRiskLevel.WARN,
                    description=(
                        f"Data from '{tag.origin_server}' has traversed "
                        f"{tag.hop_count} servers (max={self.max_hops}). "
                        "Excessive hops may indicate unintended data circulation."
                    ),
                    origin_server=tag.origin_server,
                    involved_servers=frozenset(all_servers),
                )
            )

        # 3. Cyclic flow detection
        cycle_risk = self._check_cycles(tag)
        if cycle_risk:
            risks.append(cycle_risk)

        return risks

    def _check_trust_downgrade(self, tag: DataTag) -> FlowRisk | None:
        origin_trust_score = _TRUST_ORDER.get(tag.trust_level, 2)

        for hop_server, _ in tag.lineage:
            hop_trust_level = self._tagger.trust_level_for(hop_server)
            hop_trust_score = _TRUST_ORDER.get(hop_trust_level, 2)

            if hop_trust_score < origin_trust_score:
                delta = origin_trust_score - hop_trust_score
                risk_level = FlowRiskLevel.CRITICAL if delta >= 3 else FlowRiskLevel.HIGH

                return FlowRisk(
                    tag_id=tag.tag_id,
                    risk_level=risk_level,
                    description=(
                        f"Data from trusted server '{tag.origin_server}' "
                        f"({tag.trust_level.value}) has flowed to less-trusted "
                        f"server '{hop_server}' ({hop_trust_level.value}). "
                        "Potential information leakage across trust boundary."
                    ),
                    origin_server=tag.origin_server,
                    involved_servers=frozenset(tag.servers_in_lineage()),
                )

        return None

    def _check_cycles(self, tag: DataTag) -> FlowRisk | None:
        visited: set[str] = {tag.origin_server}

        for hop_server, _ in tag.lineage:
            if hop_server in visited:
                return FlowRisk(
                    tag_id=tag.tag_id,
                    risk_level=FlowRiskLevel.WARN,
                    description=(
                        f"Data from '{tag.origin_server}' has returned to "
                        f"server '{hop_server}' which it already visited. "
                        "Cyclic data flows may indicate a redirect or exfiltration loop."
                    ),
                    origin_server=tag.origin_server,
                    involved_servers=frozenset(tag.servers_in_lineage()),
                )
            visited.add(hop_server)

        return None
