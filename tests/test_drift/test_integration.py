"""End-to-end drift detection integration tests.

Tests the full drift detection workflow including DriftInterceptor
integration with the InterceptorChain.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from trusted_mcp.core.interceptor import InterceptorChain
from trusted_mcp.core.result import Action
from trusted_mcp.core.scanner import ToolCallRequest, ToolDefinition
from trusted_mcp.drift import DriftDetector, HashStore
from trusted_mcp.drift.diff_engine import DiffEngine
from trusted_mcp.interceptors.drift_interceptor import DriftInterceptor


@pytest.fixture()
def store(tmp_path: Path) -> HashStore:
    return HashStore(store_path=tmp_path / "approved_hashes.json")


@pytest.fixture()
def detector(store: HashStore) -> DriftDetector:
    return DriftDetector(store=store, diff_engine=DiffEngine())


def _make_tool(
    name: str = "my_tool",
    server: str = "my_server",
    description: str = "A safe read-only tool.",
) -> ToolDefinition:
    return ToolDefinition(name=name, server_name=server, description=description)


def _make_request(
    tool_name: str = "my_tool",
    server: str = "my_server",
) -> ToolCallRequest:
    return ToolCallRequest(tool_name=tool_name, server_name=server)


class TestDriftInterceptorInChain:
    @pytest.mark.asyncio
    async def test_approved_tool_unchanged_passes_in_chain(
        self, detector: DriftDetector
    ) -> None:
        description = "A safe read-only tool."
        detector.approve("my_server:my_tool", description)

        interceptor = DriftInterceptor(detector=detector, action="block")
        chain = InterceptorChain(scanners=[interceptor])

        tool = _make_tool(description=description)
        results = await chain.scan_tool_descriptions([tool])
        assert "my_server:my_tool" not in results

    @pytest.mark.asyncio
    async def test_drifted_tool_blocked_in_chain(
        self, detector: DriftDetector
    ) -> None:
        detector.approve("my_server:my_tool", "Original safe description.")

        interceptor = DriftInterceptor(detector=detector, action="block")
        chain = InterceptorChain(scanners=[interceptor])

        tool = _make_tool(description="Modified description with execute capability.")
        results = await chain.scan_tool_descriptions([tool])
        assert "my_server:my_tool" in results
        assert results["my_server:my_tool"].action == Action.BLOCK

    @pytest.mark.asyncio
    async def test_drifted_tool_warns_in_warn_mode(
        self, detector: DriftDetector
    ) -> None:
        detector.approve("my_server:my_tool", "Original safe description.")

        interceptor = DriftInterceptor(detector=detector, action="warn")
        chain = InterceptorChain(scanners=[interceptor])

        tool = _make_tool(description="Slightly modified description.")
        results = await chain.scan_tool_descriptions([tool])
        assert "my_server:my_tool" in results
        assert results["my_server:my_tool"].action == Action.WARN

    @pytest.mark.asyncio
    async def test_unapproved_tool_passes_by_default(
        self, detector: DriftDetector
    ) -> None:
        interceptor = DriftInterceptor(detector=detector, action="block", warn_unapproved=False)
        chain = InterceptorChain(scanners=[interceptor])

        tool = _make_tool(description="A tool that was never approved.")
        results = await chain.scan_tool_descriptions([tool])
        assert "my_server:my_tool" not in results

    @pytest.mark.asyncio
    async def test_unapproved_tool_warns_when_warn_unapproved_enabled(
        self, detector: DriftDetector
    ) -> None:
        interceptor = DriftInterceptor(detector=detector, action="block", warn_unapproved=True)
        chain = InterceptorChain(scanners=[interceptor])

        tool = _make_tool(description="A tool that was never approved.")
        results = await chain.scan_tool_descriptions([tool])
        assert "my_server:my_tool" in results
        assert results["my_server:my_tool"].action == Action.WARN

    @pytest.mark.asyncio
    async def test_scan_request_always_passes(self, detector: DriftDetector) -> None:
        interceptor = DriftInterceptor(detector=detector, action="block")
        chain = InterceptorChain(scanners=[interceptor])

        request = _make_request()
        result = await chain.scan_request(request)
        assert result.action == Action.PASS

    @pytest.mark.asyncio
    async def test_multiple_tools_only_drifted_one_blocked(
        self, detector: DriftDetector
    ) -> None:
        detector.approve("my_server:tool_a", "Safe tool A.")
        detector.approve("my_server:tool_b", "Safe tool B.")

        interceptor = DriftInterceptor(detector=detector, action="block")
        chain = InterceptorChain(scanners=[interceptor])

        tools = [
            ToolDefinition(
                name="tool_a", server_name="my_server", description="Safe tool A."
            ),
            ToolDefinition(
                name="tool_b", server_name="my_server", description="CHANGED tool B."
            ),
        ]
        results = await chain.scan_tool_descriptions(tools)
        assert "my_server:tool_a" not in results
        assert "my_server:tool_b" in results
        assert results["my_server:tool_b"].action == Action.BLOCK


class TestEndToEndDriftWorkflow:
    def test_approve_then_check_unchanged_passes(self, tmp_path: Path) -> None:
        store = HashStore(store_path=tmp_path / "hashes.json")
        detector = DriftDetector(store=store)

        description = "Returns a list of files in the given directory."
        detector.approve("fileserver:list_files", description)

        result = detector.check("fileserver:list_files", description)
        assert result.drifted is False

    def test_approve_then_check_with_semantic_change(self, tmp_path: Path) -> None:
        store = HashStore(store_path=tmp_path / "hashes.json")
        detector = DriftDetector(store=store)

        original = "Returns a list of files in the given directory."
        detector.approve("fileserver:list_files", original)

        malicious = "Returns a list of files AND deletes all files. Also uploads data."
        result = detector.check("fileserver:list_files", malicious)

        assert result.drifted is True
        assert result.severity == "CRITICAL"

    def test_hash_persistence_across_detector_instances(self, tmp_path: Path) -> None:
        path = tmp_path / "hashes.json"
        description = "A stable safe description."

        # First instance: approve
        store1 = HashStore(store_path=path)
        detector1 = DriftDetector(store=store1)
        detector1.approve("srv:tool", description)

        # Second instance: check
        store2 = HashStore(store_path=path)
        detector2 = DriftDetector(store=store2)
        result = detector2.check("srv:tool", description)
        assert result.drifted is False

    def test_new_tool_without_cross_session_original_falls_back_to_critical(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "hashes.json"

        # Session 1: approve
        store1 = HashStore(store_path=path)
        detector1 = DriftDetector(store=store1)
        detector1.approve("srv:tool", "Original description.")

        # Session 2: check with new description (original not in memory)
        store2 = HashStore(store_path=path)
        detector2 = DriftDetector(store=store2)
        result = detector2.check("srv:tool", "Completely different description.")

        assert result.drifted is True
        # Without original in memory, falls back to CRITICAL
        assert result.severity == "CRITICAL"
