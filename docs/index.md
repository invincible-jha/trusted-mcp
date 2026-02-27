# trusted-mcp

**MCP Security Proxy** — intercept, scan, and enforce policies on MCP tool calls.

[![CI](https://github.com/invincible-jha/trusted-mcp/actions/workflows/ci.yaml/badge.svg)](https://github.com/invincible-jha/trusted-mcp/actions/workflows/ci.yaml)
[![PyPI version](https://img.shields.io/pypi/v/aumos-trusted-mcp.svg)](https://pypi.org/project/aumos-trusted-mcp/)
[![Python versions](https://img.shields.io/pypi/pyversions/aumos-trusted-mcp.svg)](https://pypi.org/project/aumos-trusted-mcp/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/invincible-jha/trusted-mcp/blob/main/LICENSE)

trusted-mcp is a security proxy for [Model Context Protocol](https://modelcontextprotocol.io/) connections. It sits between AI clients and MCP servers, scanning every tool call request, response, and tool definition through a configurable chain of scanners — blocking, warning, or logging based on your YAML policy.

## Installation

```bash
pip install aumos-trusted-mcp
```

Verify the installation:

```bash
trusted-mcp version
```

## Quick Start

```python
import trusted_mcp
from trusted_mcp.proxy import InterceptorChain
from trusted_mcp.scanners import RegexScanner, PiiScanner, AllowlistScanner

# Build an interceptor chain
chain = InterceptorChain(scanners=[
    AllowlistScanner(allowed_tools=["search", "read_file", "write_file"]),
    PiiScanner(action="block"),
    RegexScanner(patterns=["rm -rf", "DROP TABLE"], action="block"),
])

# Scan a tool call before it executes
result = chain.scan_request(
    tool_name="shell",
    arguments={"command": "rm -rf /"},
    server_name="my-mcp-server",
)

print(result.decision)   # BLOCK
print(result.reason)     # "Tool 'shell' not in allowlist"
```

You can also use a declarative YAML policy:

```yaml
# shield.yaml
scanners:
  allowlist:
    allowed_tools: [search, read_file, write_file]
  pii:
    action: block
  regex:
    patterns: ["rm -rf", "DROP TABLE"]
    action: block

audit:
  path: /var/log/trusted-mcp-audit.jsonl
```

```bash
trusted-mcp proxy --config shield.yaml
```

## Key Features

- **InterceptorChain pipeline** — ordered scanners applied to every request, response, and tool definition; short-circuits on the first BLOCK result
- **Built-in scanners** — `RegexScanner`, `AllowlistScanner`, `PiiScanner`, `ArgumentScanner`, and `DescriptionHashScanner` out of the box
- **Tool-poisoning detection** — hash verification catches MCP servers that change tool descriptions between sessions
- **Declarative YAML policy** — security profile is version-controlled alongside your code
- **JSON audit log** — append-only record of every PASS/WARN/BLOCK decision with scanner name, reason, tool name, and server name
- **Native client adapters** — transparent injection into Claude Desktop, Cursor, and VS Code MCP configurations
- **Extensible scanner registry** — third-party scanners install via Python entry-points without touching the proxy codebase

## Links

- [GitHub Repository](https://github.com/invincible-jha/trusted-mcp)
- [PyPI Package](https://pypi.org/project/aumos-trusted-mcp/)
- [Architecture](architecture.md)
- [Contributing](https://github.com/invincible-jha/trusted-mcp/blob/main/CONTRIBUTING.md)
- [Changelog](https://github.com/invincible-jha/trusted-mcp/blob/main/CHANGELOG.md)

---

Part of the [AumOS](https://github.com/aumos-ai) open-source agent infrastructure portfolio.
