/**
 * TypeScript interfaces for the TrustedMCP security proxy.
 *
 * Mirrors the Pydantic models defined in:
 *   trusted_mcp.schemas.proxy
 *   trusted_mcp.schemas.policy
 *   trusted_mcp.schemas.audit
 *
 * All interfaces use readonly fields to match Python's frozen Pydantic models.
 */

// ---------------------------------------------------------------------------
// Proxy configuration
// ---------------------------------------------------------------------------

/** Runtime configuration of the TrustedMCP proxy. */
export interface ProxyConfig {
  /** Unique proxy instance identifier. */
  readonly proxy_id: string;
  /** Upstream MCP server URL being proxied. */
  readonly upstream_url: string;
  /** Whether the proxy is currently active. */
  readonly active: boolean;
  /** Maximum number of concurrent tool calls permitted. */
  readonly max_concurrency: number;
  /** Per-call timeout in milliseconds. */
  readonly call_timeout_ms: number;
  /** Whether audit logging is enabled. */
  readonly audit_enabled: boolean;
  /** ISO-8601 UTC timestamp of last configuration update. */
  readonly updated_at: string;
}

// ---------------------------------------------------------------------------
// Allowlist rules
// ---------------------------------------------------------------------------

/**
 * Action to take when a rule matches a tool call.
 * Maps to AllowlistAction enum in Python.
 */
export type AllowlistAction = "allow" | "deny" | "require_approval";

/** A single rule in the tool-call allowlist. */
export interface AllowlistRule {
  /** Unique rule identifier. */
  readonly rule_id: string;
  /**
   * Glob pattern matched against the tool name
   * (e.g. "file_*", "web_search", "*").
   */
  readonly tool_pattern: string;
  /** Action applied when this rule matches. */
  readonly action: AllowlistAction;
  /** Optional agent identifier this rule applies to ("*" for all agents). */
  readonly agent_id: string;
  /** Whether this rule is currently active. */
  readonly enabled: boolean;
  /** ISO-8601 UTC timestamp when the rule was created. */
  readonly created_at: string;
  /** Human-readable note explaining the rule's purpose. */
  readonly description: string;
  /** Rule evaluation priority — lower numbers are evaluated first. */
  readonly priority: number;
}

// ---------------------------------------------------------------------------
// Scan policy
// ---------------------------------------------------------------------------

/** Severity levels used in policy thresholds. */
export type PolicySeverity = "critical" | "high" | "medium" | "low" | "none";

/** A scan policy controlling which defense checks the proxy applies. */
export interface ScanPolicy {
  /** Unique policy identifier. */
  readonly policy_id: string;
  /** Human-readable policy name. */
  readonly name: string;
  /** Whether prompt-injection scanning is enabled. */
  readonly prompt_injection_enabled: boolean;
  /** Whether PII detection is enabled. */
  readonly pii_detection_enabled: boolean;
  /** Whether malicious-payload scanning is enabled. */
  readonly malicious_payload_enabled: boolean;
  /** Minimum severity level that triggers a block action. */
  readonly block_threshold: PolicySeverity;
  /** Whether to scan tool-call input arguments. */
  readonly scan_tool_inputs: boolean;
  /** Whether to scan tool-call output results. */
  readonly scan_tool_outputs: boolean;
  /** Custom regex patterns added by the operator. */
  readonly custom_patterns: readonly string[];
  /** ISO-8601 UTC timestamp when the policy was last updated. */
  readonly updated_at: string;
}

// ---------------------------------------------------------------------------
// Audit log entries
// ---------------------------------------------------------------------------

/**
 * The outcome recorded for a single proxied tool call.
 * Maps to AuditOutcome enum in Python.
 */
export type AuditOutcome = "allowed" | "blocked" | "approved" | "error";

/** A single entry in the TrustedMCP audit log. */
export interface AuditEntry {
  /** Unique audit entry identifier. */
  readonly entry_id: string;
  /** ISO-8601 UTC timestamp of the event. */
  readonly timestamp: string;
  /** Agent that initiated the tool call. */
  readonly agent_id: string;
  /** Session in which the call occurred. */
  readonly session_id: string;
  /** Name of the tool called. */
  readonly tool_name: string;
  /** Outcome of the proxy decision. */
  readonly outcome: AuditOutcome;
  /** Rule that determined the outcome, or null if no rule matched. */
  readonly matched_rule_id: string | null;
  /** Reason for the outcome (human-readable). */
  readonly reason: string;
  /** End-to-end proxy latency in milliseconds. */
  readonly latency_ms: number;
  /** Whether scan findings contributed to the decision. */
  readonly scan_triggered: boolean;
}

/** Paginated audit log response. */
export interface AuditLogResponse {
  readonly entries: readonly AuditEntry[];
  readonly total: number;
  /** Cursor token for fetching the next page (null on last page). */
  readonly next_cursor: string | null;
}

// ---------------------------------------------------------------------------
// Tool-call result
// ---------------------------------------------------------------------------

/** Result returned to the caller after the proxy processes a tool call. */
export interface ToolCallResult {
  /** Whether the tool call was executed (false if blocked). */
  readonly executed: boolean;
  /** Outcome decision made by the proxy. */
  readonly outcome: AuditOutcome;
  /** Audit entry ID for this call. */
  readonly audit_entry_id: string;
  /** Raw tool output (null when blocked or errored). */
  readonly tool_output: unknown;
  /** Reason the call was not executed, or null if executed. */
  readonly block_reason: string | null;
  /** Total proxy overhead in milliseconds. */
  readonly proxy_latency_ms: number;
}

// ---------------------------------------------------------------------------
// Proxy status
// ---------------------------------------------------------------------------

/** Live status of the TrustedMCP proxy instance. */
export interface ProxyStatus {
  readonly proxy_id: string;
  readonly healthy: boolean;
  readonly upstream_reachable: boolean;
  readonly active_calls: number;
  readonly total_calls_today: number;
  readonly blocked_calls_today: number;
  readonly policy_id: string;
  readonly version: string;
}

// ---------------------------------------------------------------------------
// API result wrapper (shared pattern)
// ---------------------------------------------------------------------------

/** Standard error payload returned by the TrustedMCP API. */
export interface ApiError {
  readonly error: string;
  readonly detail: string;
}

/** Result type for all client operations. */
export type ApiResult<T> =
  | { readonly ok: true; readonly data: T }
  | { readonly ok: false; readonly error: ApiError; readonly status: number };
