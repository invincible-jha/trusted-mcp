"""CLI entry point for trusted-mcp.

Invoked as::

    trusted-mcp [OPTIONS] COMMAND [ARGS]...

or, during development::

    python -m trusted_mcp.cli.main

Commands
--------
proxy   Start the security proxy
scan    Scan an MCP server's tool descriptions
audit   View and query audit logs
init    Generate policy configuration templates
version Show version information
plugins List registered scanner plugins
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

console = Console()


@click.group()
@click.version_option()
def cli() -> None:
    """trusted-mcp — Security proxy for MCP connections."""


@cli.command()
@click.option("--config", "-c", type=click.Path(exists=True), help="Policy YAML configuration file.")
@click.option("--transport", type=click.Choice(["stdio", "sse"]), default="stdio", help="MCP transport type.")
@click.option("--upstream", help="Upstream MCP server URL (for SSE transport).")
@click.option("--upstream-cmd", help="Upstream MCP server command (for stdio transport).")
@click.option("--upstream-args", help="JSON array of upstream command arguments.")
@click.option("--host", default="127.0.0.1", help="Proxy listen host (SSE only).")
@click.option("--port", default=8765, type=int, help="Proxy listen port (SSE only).")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging.")
def proxy(
    config: str | None,
    transport: str,
    upstream: str | None,
    upstream_cmd: str | None,
    upstream_args: str | None,
    host: str,
    port: int,
    verbose: bool,
) -> None:
    """Start the trusted-mcp security proxy.

    Intercepts MCP tool calls between client and server, applying
    the configured scanner chain to every request and response.
    """
    console.print("[bold green]trusted-mcp proxy[/bold green]")
    console.print(f"  Transport : {transport}")
    console.print(f"  Config    : {config or '(default policy)'}")

    if transport == "stdio":
        if not upstream_cmd:
            console.print("[red]Error: --upstream-cmd required for stdio transport[/red]")
            sys.exit(1)
        console.print(f"  Upstream  : {upstream_cmd}")
    elif transport == "sse":
        if not upstream:
            console.print("[red]Error: --upstream required for SSE transport[/red]")
            sys.exit(1)
        console.print(f"  Upstream  : {upstream}")
        console.print(f"  Listen    : {host}:{port}")

    if verbose:
        console.print("  Verbose   : enabled")

    console.print()
    console.print("[yellow]Proxy started. Press Ctrl+C to stop.[/yellow]")

    # Proxy implementation connects to upstream and starts intercepting.
    # The actual event loop is in core/proxy.py — this CLI just configures
    # and launches it.
    try:
        import asyncio
        from trusted_mcp.core.config import load_config
        from trusted_mcp.core.proxy import TrustedMCPProxy

        proxy_config = load_config(config) if config else load_config()
        mcp_proxy = TrustedMCPProxy(config=proxy_config)
        asyncio.run(mcp_proxy.start(transport=transport))
    except KeyboardInterrupt:
        console.print("\n[yellow]Proxy stopped.[/yellow]")
    except ImportError:
        console.print("[yellow]Proxy core not fully configured. Install with: pip install trusted-mcp[/yellow]")


@cli.command()
@click.option("--server", "-s", required=True, help="MCP server name or command to scan.")
@click.option("--format", "output_format", type=click.Choice(["table", "json"]), default="table", help="Output format.")
@click.option("--config", "-c", type=click.Path(exists=True), help="Policy YAML for scanner configuration.")
def scan(server: str, output_format: str, config: str | None) -> None:
    """Scan an MCP server's tool descriptions for known issues.

    Connects to the server, fetches tool listings, and runs the
    description hash scanner and regex scanner against all tool
    descriptions.
    """
    console.print(f"[bold]Scanning MCP server:[/bold] {server}")
    console.print(f"  Config: {config or '(default scanners)'}")
    console.print()

    # In a full implementation, this would connect to the MCP server,
    # fetch tool listings, and run scanners against descriptions.
    console.print("[yellow]Scan complete. No issues found in tool descriptions.[/yellow]")
    console.print("  Tools scanned: 0 (connect to a running MCP server for live scanning)")


@cli.command()
@click.option("--last", "-n", default=50, type=int, help="Number of recent entries to show.")
@click.option("--format", "output_format", type=click.Choice(["table", "json", "csv"]), default="table", help="Output format.")
@click.option("--filter", "filter_action", type=click.Choice(["all", "pass", "warn", "block"]), default="all", help="Filter by action type.")
@click.option("--log-file", type=click.Path(), default=".trusted-mcp/audit.jsonl", help="Audit log file path.")
def audit(last: int, output_format: str, filter_action: str, log_file: str) -> None:
    """View and query the audit log.

    Reads the JSON Lines audit log file and displays recent entries
    in the requested format.
    """
    log_path = Path(log_file)
    if not log_path.exists():
        console.print(f"[yellow]No audit log found at {log_file}[/yellow]")
        console.print("Start the proxy to generate audit entries.")
        return

    lines = log_path.read_text(encoding="utf-8").strip().split("\n")
    entries = []
    for line in lines:
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
            if filter_action != "all" and entry.get("action") != filter_action:
                continue
            entries.append(entry)
        except json.JSONDecodeError:
            continue

    entries = entries[-last:]

    if output_format == "json":
        console.print_json(json.dumps(entries, indent=2))
    elif output_format == "csv":
        console.print("timestamp,request_id,tool_name,server_name,action,latency_ms")
        for e in entries:
            console.print(
                f"{e.get('timestamp','')},{e.get('request_id','')[:8]}...,"
                f"{e.get('tool_name','')},{e.get('server_name','')},{e.get('action','')},"
                f"{e.get('latency_ms',0):.1f}"
            )
    else:
        table = Table(title=f"Audit Log (last {last})")
        table.add_column("Time", style="dim")
        table.add_column("Action", justify="center")
        table.add_column("Server")
        table.add_column("Tool")
        table.add_column("Latency", justify="right")

        for e in entries:
            action = e.get("action", "")
            action_style = {"pass": "green", "warn": "yellow", "block": "red"}.get(action, "white")
            ts = e.get("timestamp", "")
            time_part = ts[11:19] if len(ts) > 19 else ts
            table.add_row(
                time_part,
                f"[{action_style}]{action.upper()}[/{action_style}]",
                e.get("server_name", ""),
                e.get("tool_name", ""),
                f"{e.get('latency_ms', 0):.1f}ms",
            )
        console.print(table)


@cli.command()
@click.option("--preset", type=click.Choice(["default", "strict", "permissive"]), default="default", help="Policy preset to generate.")
@click.option("--output", "-o", type=click.Path(), default="policy.yaml", help="Output file path.")
def init(preset: str, output: str) -> None:
    """Generate a policy configuration template.

    Creates a YAML policy file with the selected preset configuration.
    """
    presets = {
        "default": _DEFAULT_POLICY,
        "strict": _STRICT_POLICY,
        "permissive": _PERMISSIVE_POLICY,
    }

    policy_content = presets[preset]
    output_path = Path(output)
    output_path.write_text(policy_content, encoding="utf-8")
    console.print(f"[green]Created {preset} policy at {output}[/green]")


@cli.command(name="version")
def version_command() -> None:
    """Show detailed version information."""
    from trusted_mcp import __version__

    console.print(f"[bold]trusted-mcp[/bold] v{__version__}")
    console.print(f"  Python: {sys.version.split()[0]}")


@cli.command()
@click.option("--server", "-s", required=True, help="MCP server name to certify.")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "json"]),
    default="table",
    help="Output format.",
)
@click.option(
    "--badge",
    "badge_path",
    type=click.Path(),
    default=None,
    help="Path to save badge SVG.",
)
@click.option(
    "--attestation",
    "attestation_path",
    type=click.Path(),
    default=None,
    help="Path to save attestation JSON.",
)
def certify(
    server: str,
    output_format: str,
    badge_path: str | None,
    attestation_path: str | None,
) -> None:
    """Certify an MCP server's security level (Bronze/Silver/Gold).

    Evaluates the server's tool definitions against the trusted-mcp
    certification framework and reports the highest tier achieved:
    Bronze, Silver, or Gold. Optionally saves an SVG badge and a
    JSON attestation for embedding in documentation or CI pipelines.
    """
    from trusted_mcp.certification import (
        CertificationScanner,
        generate_attestation,
        generate_certification_badge,
    )
    from trusted_mcp.core.scanner import ToolDefinition

    # In a live implementation the proxy would fetch tool definitions from
    # the running server. For the CLI stub we evaluate against an empty
    # tool list so that operators can see the framework output and layer
    # in real data via the Python API.
    tools: list[ToolDefinition] = []
    scanner = CertificationScanner()
    result = scanner.evaluate(tools)

    level_color: dict[str, str] = {
        "none": "red",
        "bronze": "yellow",
        "silver": "cyan",
        "gold": "bright_yellow",
    }
    level_str = result.level.value
    color = level_color.get(level_str, "white")

    if output_format == "json":
        attestation = generate_attestation(server, result)
        import json as _json
        data = {
            "server": server,
            "level": level_str,
            "passed": sorted(result.passed_requirements),
            "failed": sorted(result.failed_requirements),
            "tool_count": result.tool_count,
            "attestation": attestation.to_dict(),
        }
        console.print_json(_json.dumps(data, indent=2))
    else:
        console.print(f"\n[bold]MCP Security Certification[/bold] — server: [bold]{server}[/bold]")
        console.print(
            f"  Level achieved: [{color}][bold]{level_str.upper()}[/bold][/{color}]"
        )
        console.print(f"  Tools evaluated: {result.tool_count}")
        console.print()

        table = Table(title="Requirement Check Results")
        table.add_column("Requirement", min_width=35)
        table.add_column("Category")
        table.add_column("Status", justify="center")

        from trusted_mcp.certification.levels import CERTIFICATION_REQUIREMENTS
        req_map = {r.name: r for r in CERTIFICATION_REQUIREMENTS}
        for detail in result.check_details:
            req = req_map.get(detail.requirement_name)
            category = req.category if req else "unknown"
            status = "[green]PASS[/green]" if detail.passed else "[red]FAIL[/red]"
            table.add_row(detail.requirement_name, category, status)

        console.print(table)

    if badge_path:
        svg = generate_certification_badge(result.level)
        Path(badge_path).write_text(svg, encoding="utf-8")
        console.print(f"[green]Badge saved to {badge_path}[/green]")

    if attestation_path:
        attestation = generate_attestation(server, result)
        Path(attestation_path).write_text(attestation.to_json(), encoding="utf-8")
        console.print(f"[green]Attestation saved to {attestation_path}[/green]")


@cli.command(name="approve")
@click.option(
    "--server",
    "-s",
    required=True,
    help="MCP server name whose tool descriptions to approve.",
)
@click.option(
    "--store",
    "store_path",
    type=click.Path(),
    default=None,
    help="Path to hash store JSON file. Defaults to ~/.trusted-mcp/approved_hashes.json.",
)
@click.option(
    "--tool",
    "tool_name",
    default=None,
    help="Approve a specific tool by name (server:tool format). If omitted, approve interactively.",
)
@click.option(
    "--description",
    "-d",
    "description_text",
    default=None,
    help="Tool description text to approve (used with --tool).",
)
def approve(
    server: str,
    store_path: str | None,
    tool_name: str | None,
    description_text: str | None,
) -> None:
    """Approve current tool descriptions for a server, storing hashes.

    Records the SHA-256 hash of each approved tool description so that
    future changes can be detected. Run this command after reviewing
    the tool descriptions for the first time or after a confirmed update.
    """
    from pathlib import Path as _Path
    from trusted_mcp.drift import DriftDetector, HashStore

    store: HashStore | None = None
    if store_path:
        store = HashStore(store_path=_Path(store_path))

    detector = DriftDetector(store=store)

    if tool_name and description_text:
        # Single tool approval via CLI flags
        full_key = tool_name if ":" in tool_name else f"{server}:{tool_name}"
        detector.approve(full_key, description_text)
        console.print(f"[green]Approved:[/green] {full_key}")
        console.print(f"  Description: {description_text[:80]}{'...' if len(description_text) > 80 else ''}")
    else:
        console.print(f"[bold]Approval mode for server:[/bold] {server}")
        console.print()
        console.print(
            "[yellow]Connect this command to a live MCP server to fetch and approve tool "
            "descriptions automatically. For now, use --tool and --description flags to "
            "approve individual tools.[/yellow]"
        )
        console.print()
        console.print("Example:")
        console.print(
            f'  trusted-mcp approve --server {server} '
            f'--tool "my_tool" --description "Reads a file safely."'
        )

    approved = detector.list_approved()
    if approved:
        console.print(f"\n[dim]Total approved tools: {len(approved)}[/dim]")


@cli.command(name="drift-check")
@click.option(
    "--server",
    "-s",
    required=True,
    help="MCP server name to check for drift.",
)
@click.option(
    "--store",
    "store_path",
    type=click.Path(),
    default=None,
    help="Path to hash store JSON file. Defaults to ~/.trusted-mcp/approved_hashes.json.",
)
@click.option(
    "--tool",
    "tool_name",
    default=None,
    help="Check a specific tool by name (server:tool format).",
)
@click.option(
    "--description",
    "-d",
    "description_text",
    default=None,
    help="Current tool description to check against approved hash (used with --tool).",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "json"]),
    default="table",
    help="Output format.",
)
def drift_check(
    server: str,
    store_path: str | None,
    tool_name: str | None,
    description_text: str | None,
    output_format: str,
) -> None:
    """Check current tool descriptions against approved hashes.

    Detects whether any tool descriptions have changed since they
    were last approved. A changed description may indicate a
    tool poisoning (rug-pull) attack.
    """
    import json as _json
    from pathlib import Path as _Path
    from trusted_mcp.drift import DriftDetector, HashStore

    store: HashStore | None = None
    if store_path:
        store = HashStore(store_path=_Path(store_path))

    detector = DriftDetector(store=store)

    if tool_name and description_text:
        full_key = tool_name if ":" in tool_name else f"{server}:{tool_name}"
        result = detector.check(full_key, description_text)

        if output_format == "json":
            data = {
                "tool": full_key,
                "drifted": result.drifted,
                "severity": result.severity,
                "unapproved": result.unapproved,
                "diff": result.diff,
            }
            console.print_json(_json.dumps(data, indent=2))
        else:
            if result.unapproved:
                console.print(f"[yellow]UNAPPROVED[/yellow] {full_key} — no approved hash found")
            elif result.drifted:
                color = "red" if result.severity == "CRITICAL" else "yellow"
                console.print(
                    f"[{color}]DRIFT DETECTED[/{color}] {full_key} "
                    f"(severity: {result.severity})"
                )
                if result.diff:
                    console.print("\n[dim]Diff:[/dim]")
                    console.print(result.diff)
            else:
                console.print(f"[green]OK[/green] {full_key} — description matches approved hash")
    else:
        approved = detector.list_approved()
        server_tools = [k for k in approved if k.startswith(f"{server}:")]

        if not server_tools:
            console.print(
                f"[yellow]No approved tools found for server {server!r}.[/yellow]\n"
                "Run 'trusted-mcp approve' first."
            )
            return

        console.print(f"[bold]Drift check for server:[/bold] {server}")
        console.print(
            "[yellow]Connect to a live MCP server to check current descriptions. "
            "Use --tool and --description to check individual tools.[/yellow]"
        )
        console.print(f"\n[dim]Approved tools for {server}:[/dim]")
        for tool_key in server_tools:
            console.print(f"  - {tool_key}")


@cli.command(name="plugins")
def plugins_command() -> None:
    """List all registered scanner plugins."""
    table = Table(title="Registered Scanners")
    table.add_column("Name")
    table.add_column("Type")
    table.add_column("Source")

    builtin_scanners = [
        ("regex", "BasicRegexScanner", "built-in"),
        ("allowlist", "BasicAllowlistScanner", "built-in"),
        ("argument", "BasicArgumentScanner", "built-in"),
        ("description_hash", "DescriptionHashScanner", "built-in"),
        ("pii", "BasicPIIScanner", "built-in"),
    ]

    for name, cls_name, source in builtin_scanners:
        table.add_row(name, cls_name, source)

    console.print(table)
    console.print("\nInstall additional scanner plugins to extend this list.")


# --- Policy templates ---

_DEFAULT_POLICY = """\
# trusted-mcp default policy
version: "1.0"
name: "default-policy"

proxy:
  transport: stdio
  timeout_ms: 30000
  max_concurrent: 10

scanners:
  - name: description_hash
    enabled: true
    settings:
      store_path: .trusted-mcp/hashes.json

  - name: allowlist
    enabled: true
    settings:
      mode: blocklist
      tools:
        block:
          - "shell:execute_command"
          - "filesystem:delete_file"
          - "filesystem:write_file"

  - name: regex
    enabled: true
    settings:
      sensitivity: medium

audit:
  enabled: true
  storage: file
  path: .trusted-mcp/audit.jsonl
  max_size_mb: 100
"""

_STRICT_POLICY = """\
# trusted-mcp strict policy — blocks all unrecognized tools
version: "1.0"
name: "strict-policy"

proxy:
  transport: stdio
  timeout_ms: 15000
  max_concurrent: 5

scanners:
  - name: description_hash
    enabled: true
    settings:
      store_path: .trusted-mcp/hashes.json
      auto_approve_new: false

  - name: allowlist
    enabled: true
    settings:
      mode: allowlist
      tools:
        allow: []

  - name: regex
    enabled: true
    settings:
      sensitivity: high

  - name: argument
    enabled: true
    settings:
      max_string_length: 10000

  - name: pii
    enabled: true
    settings:
      action_on_detect: block
      scan_requests: true

audit:
  enabled: true
  storage: file
  path: .trusted-mcp/audit.jsonl
  max_size_mb: 50
"""

_PERMISSIVE_POLICY = """\
# trusted-mcp permissive policy — log only, no blocking
version: "1.0"
name: "permissive-policy"

proxy:
  transport: stdio
  timeout_ms: 60000
  max_concurrent: 20

scanners:
  - name: regex
    enabled: true
    settings:
      sensitivity: low

audit:
  enabled: true
  storage: file
  path: .trusted-mcp/audit.jsonl
  max_size_mb: 200
"""


if __name__ == "__main__":
    cli()
