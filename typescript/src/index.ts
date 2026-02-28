/**
 * @aumos/trusted-mcp
 *
 * TypeScript client for the AumOS TrustedMCP security proxy.
 * Provides HTTP client, fluent policy builder, and proxy type definitions.
 */

// Client and configuration
export type { TrustedMCPClient, TrustedMCPClientConfig } from "./client.js";
export { createTrustedMCPClient } from "./client.js";

// Core types
export type {
  ProxyConfig,
  ProxyStatus,
  ScanPolicy,
  PolicySeverity,
  AllowlistRule,
  AllowlistAction,
  AuditEntry,
  AuditLogResponse,
  AuditOutcome,
  ToolCallResult,
  ApiError,
  ApiResult,
} from "./types.js";

// Policy builder
export type { PolicyBuilder } from "./policy.js";
export { createPolicyBuilder } from "./policy.js";
