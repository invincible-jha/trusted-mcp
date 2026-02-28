/**
 * HTTP client for the TrustedMCP security proxy API.
 *
 * Uses the Fetch API (available natively in Node 18+, browsers, and Deno).
 * No external dependencies required.
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

import type {
  AllowlistRule,
  ApiError,
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
// Internal helpers
// ---------------------------------------------------------------------------

async function fetchJson<T>(
  url: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<ApiResult<T>> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, { ...init, signal: controller.signal });
    clearTimeout(timeoutId);

    const body = await response.json() as unknown;

    if (!response.ok) {
      const errorBody = body as Partial<ApiError>;
      return {
        ok: false,
        error: {
          error: errorBody.error ?? "Unknown error",
          detail: errorBody.detail ?? "",
        },
        status: response.status,
      };
    }

    return { ok: true, data: body as T };
  } catch (err: unknown) {
    clearTimeout(timeoutId);
    const message = err instanceof Error ? err.message : String(err);
    return {
      ok: false,
      error: { error: "Network error", detail: message },
      status: 0,
    };
  }
}

function buildHeaders(
  extraHeaders: Readonly<Record<string, string>> | undefined,
): Record<string, string> {
  return {
    "Content-Type": "application/json",
    Accept: "application/json",
    ...extraHeaders,
  };
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
  const { baseUrl, timeoutMs = 10_000, headers: extraHeaders } = config;
  const baseHeaders = buildHeaders(extraHeaders);

  return {
    async getProxyStatus(): Promise<ApiResult<ProxyStatus>> {
      return fetchJson<ProxyStatus>(
        `${baseUrl}/proxy/status`,
        { method: "GET", headers: baseHeaders },
        timeoutMs,
      );
    },

    async getProxyConfig(): Promise<ApiResult<ProxyConfig>> {
      return fetchJson<ProxyConfig>(
        `${baseUrl}/proxy/config`,
        { method: "GET", headers: baseHeaders },
        timeoutMs,
      );
    },

    async getAuditLog(
      options: {
        agentId?: string;
        toolName?: string;
        outcome?: string;
        cursor?: string;
        limit?: number;
      } = {},
    ): Promise<ApiResult<AuditLogResponse>> {
      const params = new URLSearchParams();
      if (options.agentId !== undefined) params.set("agent_id", options.agentId);
      if (options.toolName !== undefined) params.set("tool_name", options.toolName);
      if (options.outcome !== undefined) params.set("outcome", options.outcome);
      if (options.cursor !== undefined) params.set("cursor", options.cursor);
      if (options.limit !== undefined) params.set("limit", String(options.limit));

      const queryString = params.toString();
      const url = queryString
        ? `${baseUrl}/audit?${queryString}`
        : `${baseUrl}/audit`;

      return fetchJson<AuditLogResponse>(
        url,
        { method: "GET", headers: baseHeaders },
        timeoutMs,
      );
    },

    async updatePolicy(
      policy: Omit<ScanPolicy, "policy_id" | "updated_at">,
    ): Promise<ApiResult<ScanPolicy>> {
      return fetchJson<ScanPolicy>(
        `${baseUrl}/policy`,
        {
          method: "PUT",
          headers: baseHeaders,
          body: JSON.stringify(policy),
        },
        timeoutMs,
      );
    },

    async getToolAllowlist(
      options: { agentId?: string; enabledOnly?: boolean } = {},
    ): Promise<ApiResult<readonly AllowlistRule[]>> {
      const params = new URLSearchParams();
      if (options.agentId !== undefined) params.set("agent_id", options.agentId);
      if (options.enabledOnly !== undefined) {
        params.set("enabled_only", String(options.enabledOnly));
      }

      const queryString = params.toString();
      const url = queryString
        ? `${baseUrl}/allowlist?${queryString}`
        : `${baseUrl}/allowlist`;

      return fetchJson<readonly AllowlistRule[]>(
        url,
        { method: "GET", headers: baseHeaders },
        timeoutMs,
      );
    },

    async addAllowlistRule(
      rule: Omit<AllowlistRule, "rule_id" | "created_at">,
    ): Promise<ApiResult<AllowlistRule>> {
      return fetchJson<AllowlistRule>(
        `${baseUrl}/allowlist`,
        {
          method: "POST",
          headers: baseHeaders,
          body: JSON.stringify(rule),
        },
        timeoutMs,
      );
    },

    async deleteAllowlistRule(ruleId: string): Promise<ApiResult<AllowlistRule>> {
      return fetchJson<AllowlistRule>(
        `${baseUrl}/allowlist/${encodeURIComponent(ruleId)}`,
        { method: "DELETE", headers: baseHeaders },
        timeoutMs,
      );
    },

    async getToolCallResult(entryId: string): Promise<ApiResult<ToolCallResult>> {
      return fetchJson<ToolCallResult>(
        `${baseUrl}/audit/${encodeURIComponent(entryId)}/result`,
        { method: "GET", headers: baseHeaders },
        timeoutMs,
      );
    },
  };
}

