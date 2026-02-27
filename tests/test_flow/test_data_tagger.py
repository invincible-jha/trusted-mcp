"""Tests for trusted_mcp.flow.data_tagger."""
from __future__ import annotations

import pytest

from trusted_mcp.flow.data_tagger import (
    DataTag,
    DataTagger,
    TaggedData,
    TrustLevel,
)


class TestDataTag:
    def test_frozen_immutability(self) -> None:
        tag = DataTag(origin_server="srv", origin_tool="tool")
        with pytest.raises((AttributeError, TypeError)):
            tag.origin_server = "other"  # type: ignore[misc]

    def test_with_hop_returns_new_tag(self) -> None:
        tag = DataTag(origin_server="srv_a", origin_tool="tool_a")
        hopped = tag.with_hop("srv_b", "tool_b")
        assert hopped is not tag
        assert hopped.tag_id == tag.tag_id
        assert len(hopped.lineage) == 1
        assert hopped.lineage[0] == ("srv_b", "tool_b")

    def test_with_hop_preserves_origin(self) -> None:
        tag = DataTag(origin_server="srv_a", origin_tool="tool_a")
        hopped = tag.with_hop("srv_b", "tool_b")
        assert hopped.origin_server == "srv_a"

    def test_hop_count_initial_zero(self) -> None:
        tag = DataTag(origin_server="srv", origin_tool="tool")
        assert tag.hop_count == 0

    def test_hop_count_increments(self) -> None:
        tag = DataTag(origin_server="srv_a", origin_tool="t")
        t1 = tag.with_hop("srv_b", "t")
        t2 = t1.with_hop("srv_c", "t")
        assert t2.hop_count == 2

    def test_has_crossed_boundary_false_on_same_server(self) -> None:
        tag = DataTag(origin_server="srv_a", origin_tool="t")
        hopped = tag.with_hop("srv_a", "other_tool")
        assert hopped.has_crossed_boundary is False

    def test_has_crossed_boundary_true_on_different_server(self) -> None:
        tag = DataTag(origin_server="srv_a", origin_tool="t")
        hopped = tag.with_hop("srv_b", "t")
        assert hopped.has_crossed_boundary is True

    def test_servers_in_lineage_includes_origin(self) -> None:
        tag = DataTag(origin_server="srv_a", origin_tool="t")
        assert "srv_a" in tag.servers_in_lineage()

    def test_servers_in_lineage_includes_all_hops(self) -> None:
        tag = DataTag(origin_server="srv_a", origin_tool="t")
        hopped = tag.with_hop("srv_b", "t").with_hop("srv_c", "t")
        servers = hopped.servers_in_lineage()
        assert "srv_a" in servers
        assert "srv_b" in servers
        assert "srv_c" in servers


class TestTaggedDataCreate:
    def test_create_sets_origin(self) -> None:
        td = TaggedData.create("hello", "server_a", "tool_x")
        assert td.tag.origin_server == "server_a"
        assert td.tag.origin_tool == "tool_x"

    def test_create_default_trust_medium(self) -> None:
        td = TaggedData.create("hello", "server_a", "tool_x")
        assert td.tag.trust_level == TrustLevel.MEDIUM

    def test_create_custom_trust(self) -> None:
        td = TaggedData.create(
            "secret", "db", "query", trust_level=TrustLevel.HIGH
        )
        assert td.tag.trust_level == TrustLevel.HIGH

    def test_content_hash_set(self) -> None:
        td = TaggedData.create("content", "srv", "tool")
        assert len(td.tag.content_hash) > 0

    def test_forwarded_to_extends_lineage(self) -> None:
        td = TaggedData.create("data", "srv_a", "tool_a")
        forwarded = td.forwarded_to("srv_b", "tool_b")
        assert forwarded.tag.lineage == (("srv_b", "tool_b"),)
        assert forwarded.tag.origin_server == "srv_a"


class TestDataTagger:
    def test_tag_registers_data(self) -> None:
        tagger = DataTagger()
        td = tagger.tag("hello", "srv", "tool")
        retrieved = tagger.get(td.tag.tag_id)
        assert retrieved is not None
        assert retrieved.tag.tag_id == td.tag.tag_id

    def test_tag_uses_configured_trust_level(self) -> None:
        tagger = DataTagger(server_trust_map={"db": TrustLevel.HIGH})
        td = tagger.tag("data", "db", "query")
        assert td.tag.trust_level == TrustLevel.HIGH

    def test_set_trust_level(self) -> None:
        tagger = DataTagger()
        tagger.set_trust_level("external", TrustLevel.UNTRUSTED)
        assert tagger.trust_level_for("external") == TrustLevel.UNTRUSTED

    def test_trust_level_for_unknown_defaults_medium(self) -> None:
        tagger = DataTagger()
        assert tagger.trust_level_for("unknown_server") == TrustLevel.MEDIUM

    def test_forward_extends_lineage(self) -> None:
        tagger = DataTagger()
        td = tagger.tag("data", "srv_a", "tool_a")
        forwarded = tagger.forward(td, "srv_b", "tool_b")
        assert forwarded.tag.has_crossed_boundary is True
        assert ("srv_b", "tool_b") in forwarded.tag.lineage

    def test_all_tags_returns_all(self) -> None:
        tagger = DataTagger()
        tagger.tag("d1", "s1", "t1")
        tagger.tag("d2", "s2", "t2")
        assert len(tagger.all_tags()) >= 2

    def test_tags_from_server_filters(self) -> None:
        tagger = DataTagger()
        tagger.tag("d1", "s1", "t1")
        tagger.tag("d2", "s2", "t2")
        tagger.tag("d3", "s1", "t3")
        tags = tagger.tags_from_server("s1")
        assert all(t.origin_server == "s1" for t in tags)
        assert len(tags) == 2

    def test_cross_boundary_tags_filtered(self) -> None:
        tagger = DataTagger()
        local = tagger.tag("local", "srv_a", "tool_a")
        crossed = tagger.tag("crossing", "srv_a", "tool_a")
        tagger.forward(crossed, "srv_b", "tool_b")
        cross_tags = tagger.cross_boundary_tags()
        # Only the forwarded data crosses the boundary
        assert any(t.tag_id == crossed.tag.tag_id for t in cross_tags)

    def test_get_nonexistent_returns_none(self) -> None:
        tagger = DataTagger()
        assert tagger.get("nonexistent-uuid") is None
