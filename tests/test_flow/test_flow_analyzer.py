"""Tests for trusted_mcp.flow.flow_analyzer."""
from __future__ import annotations

import pytest

from trusted_mcp.flow.data_tagger import DataTag, DataTagger, TrustLevel
from trusted_mcp.flow.flow_analyzer import (
    FlowAnalyzer,
    FlowEvent,
    FlowRisk,
    FlowRiskLevel,
)


def _make_tagger_with_servers(
    trust_map: dict[str, TrustLevel],
) -> DataTagger:
    tagger = DataTagger()
    for server, trust in trust_map.items():
        tagger.set_trust_level(server, trust)
    return tagger


class TestFlowAnalyzerNoCrossBoundary:
    def test_no_risks_when_data_stays_on_origin_server(self) -> None:
        tagger = DataTagger()
        td = tagger.tag("data", "srv_a", "tool_a")
        # Forward to same server
        tagger.forward(td, "srv_a", "other_tool")
        analyzer = FlowAnalyzer(tagger)
        risks = analyzer.analyze()
        assert risks == []

    def test_no_risks_for_unforwarded_data(self) -> None:
        tagger = DataTagger()
        tagger.tag("data", "srv_a", "tool_a")
        analyzer = FlowAnalyzer(tagger)
        risks = analyzer.analyze()
        assert risks == []


class TestFlowAnalyzerTrustDowngrade:
    def test_high_to_untrusted_is_critical(self) -> None:
        tagger = _make_tagger_with_servers(
            {"internal": TrustLevel.HIGH, "external": TrustLevel.UNTRUSTED}
        )
        td = tagger.tag("secret", "internal", "query")
        tagger.forward(td, "external", "post")
        analyzer = FlowAnalyzer(tagger)
        risks = analyzer.analyze()
        assert len(risks) >= 1
        critical = [r for r in risks if r.risk_level == FlowRiskLevel.CRITICAL]
        assert len(critical) >= 1

    def test_high_to_low_is_high_risk(self) -> None:
        tagger = _make_tagger_with_servers(
            {"internal": TrustLevel.HIGH, "dmz": TrustLevel.LOW}
        )
        td = tagger.tag("data", "internal", "tool")
        tagger.forward(td, "dmz", "relay")
        analyzer = FlowAnalyzer(tagger)
        risks = analyzer.analyze()
        high = [r for r in risks if r.risk_level == FlowRiskLevel.HIGH]
        assert len(high) >= 1

    def test_same_trust_level_no_downgrade_risk(self) -> None:
        tagger = _make_tagger_with_servers(
            {"srv_a": TrustLevel.MEDIUM, "srv_b": TrustLevel.MEDIUM}
        )
        td = tagger.tag("data", "srv_a", "tool")
        tagger.forward(td, "srv_b", "process")
        analyzer = FlowAnalyzer(tagger)
        risks = analyzer.analyze()
        downgrade_risks = [
            r for r in risks
            if "trust boundary" in r.description.lower()
        ]
        assert len(downgrade_risks) == 0

    def test_risk_contains_server_names(self) -> None:
        tagger = _make_tagger_with_servers(
            {"trusted_db": TrustLevel.HIGH, "public_api": TrustLevel.UNTRUSTED}
        )
        td = tagger.tag("sensitive", "trusted_db", "query")
        tagger.forward(td, "public_api", "send")
        analyzer = FlowAnalyzer(tagger)
        risks = analyzer.analyze()
        assert any("trusted_db" in r.description for r in risks)


class TestFlowAnalyzerExcessiveHops:
    def test_exceeds_max_hops_flagged(self) -> None:
        tagger = DataTagger()
        td = tagger.tag("data", "s0", "t")
        for i in range(1, 8):
            td = tagger.forward(td, f"s{i}", "t")
        analyzer = FlowAnalyzer(tagger, max_hops=5)
        risks = analyzer.analyze()
        warn = [r for r in risks if r.risk_level == FlowRiskLevel.WARN]
        assert len(warn) >= 1

    def test_within_max_hops_no_hop_warning(self) -> None:
        tagger = DataTagger()
        td = tagger.tag("data", "s0", "t")
        for i in range(1, 4):
            td = tagger.forward(td, f"s{i}", "t")
        analyzer = FlowAnalyzer(tagger, max_hops=5)
        risks = analyzer.analyze()
        hop_warns = [r for r in risks if "hop" in r.description.lower()]
        assert hop_warns == []


class TestFlowAnalyzerCyclicFlow:
    def test_cyclic_flow_detected(self) -> None:
        tagger = DataTagger()
        td = tagger.tag("data", "s_a", "t")
        td = tagger.forward(td, "s_b", "t")
        tagger.forward(td, "s_a", "t")  # back to origin
        analyzer = FlowAnalyzer(tagger)
        risks = analyzer.analyze()
        cyclic = [r for r in risks if "cyclic" in r.description.lower()]
        assert len(cyclic) >= 1

    def test_linear_flow_not_cyclic(self) -> None:
        tagger = DataTagger()
        td = tagger.tag("data", "s_a", "t")
        td = tagger.forward(td, "s_b", "t")
        tagger.forward(td, "s_c", "t")
        analyzer = FlowAnalyzer(tagger)
        risks = analyzer.analyze()
        cyclic = [r for r in risks if "cyclic" in r.description.lower()]
        assert cyclic == []


class TestFlowAnalyzerBuildFlowEvents:
    def test_no_hops_returns_empty(self) -> None:
        tagger = DataTagger()
        td = tagger.tag("data", "srv", "tool")
        analyzer = FlowAnalyzer(tagger)
        events = analyzer.build_flow_events(td.tag)
        assert events == []

    def test_single_hop_produces_one_event(self) -> None:
        tagger = _make_tagger_with_servers(
            {"srv_a": TrustLevel.HIGH, "srv_b": TrustLevel.MEDIUM}
        )
        td = tagger.tag("data", "srv_a", "tool_a")
        forwarded = tagger.forward(td, "srv_b", "tool_b")
        analyzer = FlowAnalyzer(tagger)
        events = analyzer.build_flow_events(forwarded.tag)
        assert len(events) == 1
        assert events[0].from_server == "srv_a"
        assert events[0].to_server == "srv_b"

    def test_trust_delta_negative_on_downgrade(self) -> None:
        tagger = _make_tagger_with_servers(
            {"high_srv": TrustLevel.HIGH, "low_srv": TrustLevel.LOW}
        )
        td = tagger.tag("data", "high_srv", "tool")
        forwarded = tagger.forward(td, "low_srv", "relay")
        analyzer = FlowAnalyzer(tagger)
        events = analyzer.build_flow_events(forwarded.tag)
        assert events[0].trust_delta < 0


class TestFlowAnalyzerFlagLeakage:
    def test_flag_leakage_returns_risk(self) -> None:
        tagger = DataTagger()
        td = tagger.tag("data", "srv", "tool")
        analyzer = FlowAnalyzer(tagger)
        risk = analyzer.flag_leakage(
            td.tag, severity=FlowRiskLevel.CRITICAL, reason="Manual flag"
        )
        assert isinstance(risk, FlowRisk)
        assert risk.risk_level == FlowRiskLevel.CRITICAL
        assert risk.description == "Manual flag"
