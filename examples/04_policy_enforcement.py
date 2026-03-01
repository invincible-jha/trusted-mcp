#!/usr/bin/env python3
"""Example: Policy Enforcement

Demonstrates how to use reputation and trust scoring to enforce
policies on MCP server connections.

Usage:
    python examples/04_policy_enforcement.py

Requirements:
    pip install trusted-mcp
"""
from __future__ import annotations

import trusted_mcp
from trusted_mcp import (
    ReputationRegistry,
    ReputationReport,
    ReportType,
    TrustScorer,
    TrustScorerConfig,
    compute_trust_score,
)


def main() -> None:
    print(f"trusted-mcp version: {trusted_mcp.__version__}")

    # Step 1: Initialise a reputation registry
    registry = ReputationRegistry()
    server_id = "data-pipeline-mcp"

    # Step 2: Submit reputation reports for a server
    positive_report = ReputationReport(
        server_id=server_id,
        report_type=ReportType.POSITIVE,
        reporter_id="agent-alpha",
        details="Server responded correctly and within SLA.",
    )
    registry.submit(positive_report)

    negative_report = ReputationReport(
        server_id=server_id,
        report_type=ReportType.NEGATIVE,
        reporter_id="agent-beta",
        details="Server returned unexpected schema twice.",
    )
    registry.submit(negative_report)

    # Step 3: Retrieve server reputation
    reputation = registry.get(server_id)
    print(f"\nReputation for '{server_id}':")
    print(f"  Total reports: {reputation.total_reports}")
    print(f"  Positive: {reputation.positive_count}  Negative: {reputation.negative_count}")

    # Step 4: Compute trust score
    config = TrustScorerConfig(
        positive_weight=0.6,
        negative_weight=0.4,
        min_trust_threshold=0.5,
    )
    scorer = TrustScorer(config=config)
    trust_score = scorer.score(reputation)
    print(f"\nTrust score: {trust_score.value:.2f}")
    print(f"  Trust level: {trust_score.level.name}")

    # Step 5: Enforce policy based on trust
    policy_threshold = 0.4
    allowed = trust_score.value >= policy_threshold
    print(f"\nPolicy enforcement (threshold={policy_threshold}):")
    print(f"  Connection allowed: {allowed}")
    if not allowed:
        print(f"  Reason: Trust score {trust_score.value:.2f} below threshold")

    # Quick convenience check
    quick_score = compute_trust_score(server_id=server_id, registry=registry, config=config)
    print(f"\nQuick trust check: {quick_score.value:.2f} (level={quick_score.level.name})")


if __name__ == "__main__":
    main()
