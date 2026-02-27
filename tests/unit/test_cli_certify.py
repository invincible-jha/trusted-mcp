"""Tests for the `certify` subcommand in trusted_mcp.cli.main."""
from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path

from click.testing import CliRunner

from trusted_mcp.cli.main import cli


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape codes from text to make assertions portable."""
    ansi_escape = re.compile(r"\x1b\[[0-9;]*[mGKH]")
    return ansi_escape.sub("", text)


def _invoke_certify(*args: str) -> "click.testing.Result":  # type: ignore[name-defined]
    # color=False ensures Rich does not emit ANSI codes into the captured buffer.
    runner = CliRunner()
    return runner.invoke(cli, ["certify", *args], color=False)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestCertifyCommand:
    def test_certify_with_server_produces_output(self) -> None:
        result = _invoke_certify("--server", "my-test-server")
        assert result.exit_code == 0
        assert result.output  # non-empty output

    def test_certify_shows_server_name_in_output(self) -> None:
        result = _invoke_certify("--server", "acme-server")
        assert result.exit_code == 0
        assert "acme-server" in result.output

    def test_certify_json_format_produces_valid_json(self) -> None:
        result = _invoke_certify("--server", "json-server", "--format", "json")
        assert result.exit_code == 0
        # Strip any ANSI codes and find the JSON object in the output.
        clean_output = _strip_ansi(result.output).strip()
        # Find the outermost JSON object.
        start = clean_output.index("{")
        # Collect the full JSON blob (everything from first '{' onwards).
        json_str = clean_output[start:]
        parsed = json.loads(json_str)
        assert "level" in parsed
        assert "server" in parsed
        assert parsed["server"] == "json-server"

    def test_certify_json_format_contains_attestation(self) -> None:
        result = _invoke_certify("--server", "json-server", "--format", "json")
        assert result.exit_code == 0
        clean_output = _strip_ansi(result.output).strip()
        start = clean_output.index("{")
        parsed = json.loads(clean_output[start:])
        assert "attestation" in parsed
        assert "sha256_hash" in parsed["attestation"]

    def test_certify_badge_saves_svg_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            badge_path = os.path.join(tmpdir, "badge.svg")
            result = _invoke_certify("--server", "badge-server", "--badge", badge_path)
            assert result.exit_code == 0
            assert Path(badge_path).exists()
            content = Path(badge_path).read_text(encoding="utf-8")
            assert content.startswith("<svg")

    def test_certify_attestation_saves_json_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            attestation_path = os.path.join(tmpdir, "attestation.json")
            result = _invoke_certify(
                "--server", "attest-server", "--attestation", attestation_path
            )
            assert result.exit_code == 0
            assert Path(attestation_path).exists()
            parsed = json.loads(Path(attestation_path).read_text(encoding="utf-8"))
            assert "sha256_hash" in parsed
            assert parsed["server_name"] == "attest-server"

    def test_certify_shows_level_in_table_output(self) -> None:
        result = _invoke_certify("--server", "level-check-server")
        assert result.exit_code == 0
        # The table output includes the level in uppercase.
        output = result.output.upper()
        # Should contain at least one known level name.
        assert any(level in output for level in ("NONE", "BRONZE", "SILVER", "GOLD"))

    def test_certify_shows_requirement_table(self) -> None:
        result = _invoke_certify("--server", "table-server")
        assert result.exit_code == 0
        # Table output includes "Requirement" header.
        assert "Requirement" in result.output

    def test_certify_missing_server_fails(self) -> None:
        result = _invoke_certify()
        # Missing required --server option → non-zero exit code.
        assert result.exit_code != 0
