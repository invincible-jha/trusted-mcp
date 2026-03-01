# Examples

| # | Example | Description |
|---|---------|-------------|
| 01 | [Quickstart](01_quickstart.py) | Minimal working example with TrustedProxy |
| 02 | [Tool Validation](02_tool_validation.py) | Validate MCP tool calls with audit logging |
| 03 | [Cert Verification](03_cert_verification.py) | MCP server certification scanning and badges |
| 04 | [Policy Enforcement](04_policy_enforcement.py) | Trust scoring and policy-based connection control |
| 05 | [Drift Detection](05_drift_detection.py) | Detect changes in tool descriptions across sessions |
| 06 | [LangChain MCP](06_langchain_mcp.py) | Wrap LangChain tools with trusted-mcp audit layer |
| 07 | [Rate Limiting](07_rate_limiting.py) | Per-server rate limiting with trusted-mcp audit |

## Running the examples

```bash
pip install trusted-mcp
python examples/01_quickstart.py
```

For framework integrations:

```bash
pip install langchain   # for example 06
```
