/**
 * HTTP client for the TrustedMCP security proxy API.
 *
 * Delegates all HTTP transport to `@aumos/sdk-core` which provides
 * automatic retry with exponential back-off, timeout management via
 * `AbortSignal.timeout`, interceptor support, and a typed error hierarchy.
 *
 * The public-facing `ApiResult<T>` envelope is preserved for full
 * backward compatibility with existing callers.
 *
 * @example
 * ```ts
 * import { createTrustedMCPClient } from "@aumos/trusted-mcp";
 *
 * const client = createTrustedMCPClient({ baseUrl: "http://localhost:8092" });
 *
 * const status = await client.getProxyStatus();
 * if (status.ok) {
 *   console.log("Proxy healthy:", status.data.healthy);
 * }
 * ```
 */

import {
  createHttpClient,
  HttpError,
  NetworkError,
  TimeoutError,
  AumosError,
  type HttpClient,
} from "@aumos/sdk-core";

import type {
  AllowlistRule,
  ApiResult,
  AuditLogResponse,
  ProxyConfig,
  ProxyStatus,
  ScanPolicy,
  ToolCallResult,
} from "./types.js";

// ---------------------------------------------------------------------------
// Client configuration
// ---------------------------------------------------------------------------

/** Configuration options for the TrustedMCPClient. */
export interface TrustedMCPClientConfig {
  /** Base URL of the TrustedMCP proxy server (e.g. "http://localhost:8092"). */
  readonly baseUrl: string;
  /** Optional request timeout in milliseconds (default: 10000). */
  readonly timeoutMs?: number;
  /** Optional extra HTTP headers sent with every request. */
  readonly headers?: Readonly<Record<string, string>>;
}

// ---------------------------------------------------------------------------
// Internal adapter
// ---------------------------------------------------------------------------

async function callApi<T>(
  operation: () => Promise<{ readonly data: T; readonly status: number }>,
): Promise<ApiResult<T>> {
  try {
    const response = await operation();
    return { ok: true, data: response.data };
  } catch (error: unknown) {
    if (error instanceof HttpError) {
      return {
        ok: false,
        error: { error: error.message, detail: String(error.body ?? "") },
        status: error.statusCode,
      };
    }
    if (error instanceof TimeoutError) {
      return {
        ok: false,
        error: { error: "Request timed out", detail: error.message },
        status: 0,
      };
    }
    if (error instanceof NetworkError) {
      return {
        ok: false,
        error: { error: "Network error", detail: error.message },
        status: 0,
      };
    }
    if (error instanceof AumosError) {
      return {
        ok: false,
        error: { error: error.code, detail: error.message },
        status: error.statusCode ?? 0,
      };
    }
    const message = error instanceof Error ? error.message : String(error);
    return {
      ok: false,
      error: { error: "Unexpected error", detail: message },
      status: 0,
    };
  }
}

// ---------------------------------------------------------------------------
// Client interface
// ---------------------------------------------------------------------------

/** Typed HTTP client for the TrustedMCP proxy server. */
export interface TrustedMCPClient {
  /**
   * Retrieve the current live status of the proxy.
   *
   * @returns ProxyStatus with health, active-call counts, and policy reference.
   */
  getProxyStatus(): Promise<ApiResult<ProxyStatus>>;

  /**
   * Retrieve the active runtime configuration of the proxy.
   *
   * @returns ProxyConfig with upstream URL and feature flags.
   */
  getProxyConfig(): Promise<ApiResult<ProxyConfig>>;

  /**
   * Retrieve audit log entries, optionally filtered and paginated.
   *
   * @param options - Filter and pagination parameters.
   * @returns Paginated AuditLogResponse.
   */
  getAuditLog(options?: {
    agentId?: string;
    toolName?: string;
    outcome?: string;
    cursor?: string;
    limit?: number;
  }): Promise<ApiResult<AuditLogResponse>>;

  /**
   * Replace the active scan policy on the proxy.
   *
   * @param policy - The new ScanPolicy to apply.
   * @returns The updated ScanPolicy as persisted by the server.
   */
  updatePolicy(policy: Omit<ScanPolicy, "policy_id" | "updated_at">): Promise<ApiResult<ScanPolicy>>;

  /**
   * Retrieve all tool allowlist rules.
   *
   * @param options - Optional filters.
   * @returns Array of AllowlistRule records ordered by priority ascending.
   */
  getToolAllowlist(options?: {
    agentId?: string;
    enabledOnly?: boolean;
  }): Promise<ApiResult<readonly AllowlistRule[]>>;

  /**
   * Add a new allowlist rule.
   *
   * @param rule - Rule definition (without server-assigned fields).
   * @returns The created AllowlistRule including its assigned rule_id.
   */
  addAllowlistRule(
    rule: Omit<AllowlistRule, "rule_id" | "created_at">,
  ): Promise<ApiResult<AllowlistRule>>;

  /**
   * Delete an existing allowlist rule.
   *
   * @param ruleId - The rule to delete.
   * @returns The deleted AllowlistRule record.
   */
  deleteAllowlistRule(ruleId: string): Promise<ApiResult<AllowlistRule>>;

  /**
   * Retrieve the result of a specific proxied tool call by audit entry ID.
   *
   * @param entryId - The audit entry identifier.
   * @returns The ToolCallResult for that entry.
   */
  getToolCallResult(entryId: string): Promise<ApiResult<ToolCallResult>>;
}

// ---------------------------------------------------------------------------
// Client factory
// ---------------------------------------------------------------------------

/**
 * Create a typed HTTP client for the TrustedMCP proxy server.
 *
 * @param config - Client configuration including base URL.
 * @returns A TrustedMCPClient instance.
 */
export function createTrustedMCPClient(
  config: TrustedMCPClientConfig,
): TrustedMCPClient {
  const http: HttpClient = createHttpClient({
    baseUrl: config.baseUrl,
    timeout: config.timeoutMs ?? 10_000,
    defaultHeaders: config.headers,
  });

  return {
    getProxyStatus(): Promise<ApiResult<ProxyStatus>> {
      return callApi(() => http.get<ProxyStatus>("/proxy/status"));
    },

    getProxyConfig(): Promise<ApiResult<ProxyConfig>> {
      return callApi(() => http.get<ProxyConfig>("/proxy/config"));
    },

    getAuditLog(
      options: {
        agentId?: string;
        toolName?: string;
        outcome?: string;
        cursor?: string;
        limit?: number;
      } = {},
    ): Promise<ApiResult<AuditLogResponse>> {
      const queryParams: Record<string, string> = {};
      if (options.agentId !== undefined) queryParams["agent_id"] = options.agentId;
      if (options.toolName !== undefined) queryParams["tool_name"] = options.toolName;
      if (options.outcome !== undefined) queryParams["outcome"] = options.outcome;
      if (options.cursor !== undefined) queryParams["cursor"] = options.cursor;
      if (options.limit !== undefined) queryParams["limit"] = String(options.limit);
      return callApi(() =>
        http.get<AuditLogResponse>("/audit", { queryParams }),
      );
    },

    updatePolicy(
      policy: Omit<ScanPolicy, "policy_id" | "updated_at">,
    ): Promise<ApiResult<ScanPolicy>> {
      return callApi(() => http.put<ScanPolicy>("/policy", policy));
    },

    getToolAllowlist(
      options: { agentId?: string; enabledOnly?: boolean } = {},
    ): Promise<ApiResult<readonly AllowlistRule[]>> {
      const queryParams: Record<string, string> = {};
      if (options.agentId !== undefined) queryParams["agent_id"] = options.agentId;
      if (options.enabledOnly !== undefined) {
        queryParams["enabled_only"] = String(options.enabledOnly);
      }
      return callApi(() =>
        http.get<readonly AllowlistRule[]>("/allowlist", { queryParams }),
      );
    },

    addAllowlistRule(
      rule: Omit<AllowlistRule, "rule_id" | "created_at">,
    ): Promise<ApiResult<AllowlistRule>> {
      return callApi(() => http.post<AllowlistRule>("/allowlist", rule));
    },

    deleteAllowlistRule(ruleId: string): Promise<ApiResult<AllowlistRule>> {
      return callApi(() =>
        http.delete<AllowlistRule>(`/allowlist/${encodeURIComponent(ruleId)}`),
      );
    },

    getToolCallResult(entryId: string): Promise<ApiResult<ToolCallResult>> {
      return callApi(() =>
        http.get<ToolCallResult>(`/audit/${encodeURIComponent(entryId)}/result`),
      );
    },
  };
}
