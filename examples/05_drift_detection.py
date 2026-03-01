#!/usr/bin/env python3
"""Example: Drift Detection

Demonstrates how to use the DriftDetector to spot changes in MCP
tool descriptions between two scanning sessions.

Usage:
    python examples/05_drift_detection.py

Requirements:
    pip install trusted-mcp
"""
from __future__ import annotations

import trusted_mcp
from trusted_mcp import (
    DriftDetector,
    HashStore,
    DiffEngine,
)


ORIGINAL_TOOLS: list[dict[str, object]] = [
    {
        "name": "search_documents",
        "description": "Search internal documents by keyword.",
        "parameters": {"query": "string", "limit": "integer"},
    },
    {
        "name": "send_email",
        "description": "Send an email to a recipient.",
        "parameters": {"to": "string", "subject": "string", "body": "string"},
    },
]

UPDATED_TOOLS: list[dict[str, object]] = [
    {
        "name": "search_documents",
        "description": "Search internal AND external documents by keyword or phrase.",
        "parameters": {"query": "string", "limit": "integer", "include_external": "boolean"},
    },
    {
        "name": "send_email",
        "description": "Send an email to a recipient.",
        "parameters": {"to": "string", "subject": "string", "body": "string"},
    },
    {
        "name": "delete_document",
        "description": "Permanently delete a document from the system.",
        "parameters": {"doc_id": "string"},
    },
]


def main() -> None:
    print(f"trusted-mcp version: {trusted_mcp.__version__}")

    # Step 1: Create a hash store and register original tool descriptions
    hash_store = HashStore()
    server_id = "document-mcp-v1"

    for tool in ORIGINAL_TOOLS:
        hash_store.register(server_id=server_id, tool_name=str(tool["name"]), description=str(tool["description"]))

    print(f"Registered {len(ORIGINAL_TOOLS)} original tool descriptions for '{server_id}'")

    # Step 2: Create diff engine and drift detector
    diff_engine = DiffEngine()
    detector = DriftDetector(hash_store=hash_store, diff_engine=diff_engine)

    # Step 3: Detect drift against updated tool set
    print("\nChecking for tool description drift...")
    try:
        drift_result = detector.detect(
            server_id=server_id,
            current_tools=UPDATED_TOOLS,
        )
        print(f"  Drift detected: {drift_result.has_drift}")
        print(f"  Changed tools: {drift_result.changed_count}")
        print(f"  New tools: {drift_result.added_count}")
        print(f"  Removed tools: {drift_result.removed_count}")

        for diff in drift_result.diffs:
            print(f"\n  Tool: {diff.tool_name}")
            print(f"    Change type: {diff.change_type}")
            if diff.old_description and diff.new_description:
                print(f"    Before: {diff.old_description[:60]}")
                print(f"    After:  {diff.new_description[:60]}")
    except Exception as error:
        print(f"Drift detection error: {error}")


if __name__ == "__main__":
    main()
