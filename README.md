# trusted-mcp

Security proxy for MCP (Model Context Protocol) connections

[![CI](https://github.com/aumos-ai/trusted-mcp/actions/workflows/ci.yaml/badge.svg)](https://github.com/aumos-ai/trusted-mcp/actions/workflows/ci.yaml)
[![PyPI version](https://img.shields.io/pypi/v/trusted-mcp.svg)](https://pypi.org/project/trusted-mcp/)
[![Python versions](https://img.shields.io/pypi/pyversions/trusted-mcp.svg)](https://pypi.org/project/trusted-mcp/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Part of the [AumOS](https://github.com/aumos-ai) open-source agent infrastructure portfolio.

---

## Features

- `InterceptorChain` pipeline that applies an ordered sequence of scanners to every tool call request, response, and tool definition — short-circuits on the first BLOCK result
- `Scanner` ABC for building custom scanners; ships with `RegexScanner`, `AllowlistScanner`, `PiiScanner`, `ArgumentScanner`, and `DescriptionHashScanner` out of the box
- Tool description hash verification detects MCP tool-poisoning attacks where a server's tool descriptions change between sessions
- YAML policy config maps scanner slugs to settings, making the security profile fully declarative and version-controlled
- JSON audit logger writes an append-only record of every PASS/WARN/BLOCK decision with scanner name, reason, tool name, and server name
- Native adapters for Claude Desktop, Cursor, and VS Code that inject the proxy transparently into each client's MCP configuration
- Extensible scanner registry via Python entry-points — third-party scanners install and register without modifying the proxy codebase

## Current Limitations

> **Transparency note**: We list known limitations to help you evaluate fit.

- **Detection**: Regex heuristics only — no ML-based threat detection.
- **Streaming**: No real-time streaming protocol support.
- **Scope**: MCP protocol only — no generic API gateway capabilities.

## Quick Start

Install from PyPI:

```bash
pip install trusted-mcp
```

Verify the installation:

```bash
trusted-mcp version
```

Basic usage:

```python
import trusted_mcp

# See examples/01_quickstart.py for a working example
```

## Documentation

- [Architecture](docs/architecture.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)
- [Examples](examples/README.md)

## Enterprise Upgrade

For production deployments requiring SLA-backed support and advanced
integrations, contact the maintainers or see the commercial extensions documentation.

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md)
before opening a pull request.

## License

Apache 2.0 — see [LICENSE](LICENSE) for full terms.

---

Part of [AumOS](https://github.com/aumos-ai) — open-source agent infrastructure.
