# @aumos/trusted-mcp

TypeScript client for the [AumOS TrustedMCP](https://github.com/invincible-jha/trusted-mcp)
security proxy. Manage policies, inspect audit logs, control tool allowlists, and build
YAML scan policies programmatically.

## Requirements

- Node.js 18+ (uses native Fetch API)
- TypeScript 5.3+ (strict mode)

## Installation

```bash
npm install @aumos/trusted-mcp
```

## Usage

### HTTP client

```ts
import { createTrustedMCPClient } from "@aumos/trusted-mcp";

const client = createTrustedMCPClient({
  baseUrl: "http://localhost:8092",
  timeoutMs: 10_000,
});

// Check proxy health
const status = await client.getProxyStatus();
if (status.ok) {
  console.log("Healthy:", status.data.healthy);
  console.log("Blocked today:", status.data.blocked_calls_today);
}

// Retrieve current proxy configuration
const config = await client.getProxyConfig();

// Retrieve audit log with filtering
const log = await client.getAuditLog({
  agentId: "my-agent",
  outcome: "blocked",
  limit: 50,
});
if (log.ok) {
  for (const entry of log.data.entries) {
    console.log(`[${entry.timestamp}] ${entry.tool_name} → ${entry.outcome}`);
  }
  // Paginate if there are more results
  if (log.data.next_cursor !== null) {
    const nextPage = await client.getAuditLog({ cursor: log.data.next_cursor });
  }
}

// Update the active scan policy
const updatedPolicy = await client.updatePolicy({
  name: "strict-prod",
  prompt_injection_enabled: true,
  pii_detection_enabled: true,
  malicious_payload_enabled: true,
  block_threshold: "high",
  scan_tool_inputs: true,
  scan_tool_outputs: false,
  custom_patterns: [],
});

// Manage tool allowlist
const allowlist = await client.getToolAllowlist({ enabledOnly: true });

const newRule = await client.addAllowlistRule({
  tool_pattern: "web_search",
  action: "allow",
  agent_id: "*",
  enabled: true,
  description: "Allow web search for all agents",
  priority: 10,
});

await client.deleteAllowlistRule("rule-id-to-remove");
```

### Policy builder

```ts
import { createPolicyBuilder } from "@aumos/trusted-mcp";

// Build a policy object for the update API
const policy = createPolicyBuilder("strict-prod")
  .withPromptInjectionScanning(true)
  .withPiiDetection(true)
  .withMaliciousPayloadScanning(true)
  .withBlockThreshold("high")
  .withToolInputScanning(true)
  .withToolOutputScanning(false)
  .addCustomPattern("(?i)internal_api_key")
  .build();

await client.updatePolicy(policy);

// Serialise to YAML for GitOps / policy-as-code workflows
const lenient = createPolicyBuilder("dev-lenient")
  .withBlockThreshold("critical")
  .withPiiDetection(false)
  .toYaml();

console.log(lenient);
// # TrustedMCP Scan Policy
// ---
// name: dev-lenient
// prompt_injection_enabled: true
// pii_detection_enabled: false
// ...

// Clone and branch a policy
const stricterPolicy = createPolicyBuilder("base")
  .withBlockThreshold("medium")
  .clone()
  .withToolOutputScanning(true)
  .addCustomPattern("CONFIDENTIAL")
  .build();
```

## API reference

### `createTrustedMCPClient(config)`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `baseUrl` | `string` | required | TrustedMCP proxy URL |
| `timeoutMs` | `number` | `10000` | Request timeout (ms) |
| `headers` | `Record<string, string>` | `{}` | Extra HTTP headers |

#### Methods

| Method | Description |
|--------|-------------|
| `getProxyStatus()` | Live health and call-count metrics |
| `getProxyConfig()` | Active runtime configuration |
| `getAuditLog(options?)` | Paginated, filtered audit log |
| `updatePolicy(policy)` | Replace the active scan policy |
| `getToolAllowlist(options?)` | Retrieve all allowlist rules |
| `addAllowlistRule(rule)` | Add a new allowlist rule |
| `deleteAllowlistRule(ruleId)` | Remove an allowlist rule |
| `getToolCallResult(entryId)` | Retrieve the result of a specific proxied call |

### `createPolicyBuilder(name)`

| Method | Description |
|--------|-------------|
| `withPromptInjectionScanning(enabled)` | Toggle prompt-injection scanning |
| `withPiiDetection(enabled)` | Toggle PII detection |
| `withMaliciousPayloadScanning(enabled)` | Toggle malicious-payload scanning |
| `withBlockThreshold(threshold)` | Set minimum severity for block action |
| `withToolInputScanning(enabled)` | Toggle scanning of tool-call inputs |
| `withToolOutputScanning(enabled)` | Toggle scanning of tool-call outputs |
| `addCustomPattern(pattern)` | Add a custom regex pattern |
| `clearCustomPatterns()` | Remove all custom patterns |
| `build()` | Return a `ScanPolicy` object (without server-assigned fields) |
| `toYaml()` | Serialise to YAML string for policy-as-code |
| `clone()` | Deep-copy the builder for branched derivation |

### Allowlist actions

| Action | Description |
|--------|-------------|
| `allow` | Permit the tool call unconditionally |
| `deny` | Block the tool call unconditionally |
| `require_approval` | Gate the tool call on human approval |

## License

Apache-2.0. See [LICENSE](../../LICENSE) for details.
