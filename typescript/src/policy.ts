/**
 * PolicyBuilder — fluent API for constructing TrustedMCP scan policies
 * programmatically and serialising them to YAML or plain objects.
 *
 * No external dependencies are required. The YAML serialiser is a minimal
 * hand-rolled implementation sufficient for the flat policy structure.
 *
 * @example
 * ```ts
 * import { createPolicyBuilder } from "@aumos/trusted-mcp";
 *
 * const policy = createPolicyBuilder("strict-prod")
 *   .withPromptInjectionScanning(true)
 *   .withPiiDetection(true)
 *   .withMaliciousPayloadScanning(true)
 *   .withBlockThreshold("high")
 *   .withToolInputScanning(true)
 *   .withToolOutputScanning(false)
 *   .addCustomPattern("(?i)internal_secret")
 *   .build();
 *
 * const yaml = createPolicyBuilder("strict-prod")
 *   .withPromptInjectionScanning(true)
 *   .withBlockThreshold("high")
 *   .toYaml();
 * ```
 */

import type { PolicySeverity, ScanPolicy } from "./types.js";

// ---------------------------------------------------------------------------
// Mutable draft type (all fields optional during construction)
// ---------------------------------------------------------------------------

interface PolicyDraft {
  name: string;
  prompt_injection_enabled: boolean;
  pii_detection_enabled: boolean;
  malicious_payload_enabled: boolean;
  block_threshold: PolicySeverity;
  scan_tool_inputs: boolean;
  scan_tool_outputs: boolean;
  custom_patterns: string[];
}

// ---------------------------------------------------------------------------
// PolicyBuilder interface
// ---------------------------------------------------------------------------

/** Fluent builder for constructing TrustedMCP ScanPolicy objects. */
export interface PolicyBuilder {
  /**
   * Enable or disable prompt-injection scanning.
   *
   * @param enabled - Whether to enable this defense check.
   * @returns The builder instance (for chaining).
   */
  withPromptInjectionScanning(enabled: boolean): PolicyBuilder;

  /**
   * Enable or disable PII detection.
   *
   * @param enabled - Whether to enable this defense check.
   * @returns The builder instance (for chaining).
   */
  withPiiDetection(enabled: boolean): PolicyBuilder;

  /**
   * Enable or disable malicious-payload scanning.
   *
   * @param enabled - Whether to enable this defense check.
   * @returns The builder instance (for chaining).
   */
  withMaliciousPayloadScanning(enabled: boolean): PolicyBuilder;

  /**
   * Set the minimum severity level that triggers a block action.
   *
   * @param threshold - Minimum PolicySeverity to act on.
   * @returns The builder instance (for chaining).
   */
  withBlockThreshold(threshold: PolicySeverity): PolicyBuilder;

  /**
   * Enable or disable scanning of tool-call input arguments.
   *
   * @param enabled - Whether to scan tool inputs.
   * @returns The builder instance (for chaining).
   */
  withToolInputScanning(enabled: boolean): PolicyBuilder;

  /**
   * Enable or disable scanning of tool-call output results.
   *
   * @param enabled - Whether to scan tool outputs.
   * @returns The builder instance (for chaining).
   */
  withToolOutputScanning(enabled: boolean): PolicyBuilder;

  /**
   * Append a custom regex pattern to the policy.
   *
   * Patterns are matched against scanned content in addition to built-in rules.
   *
   * @param pattern - A valid ECMAScript regex pattern string.
   * @returns The builder instance (for chaining).
   */
  addCustomPattern(pattern: string): PolicyBuilder;

  /**
   * Remove all previously added custom patterns.
   *
   * @returns The builder instance (for chaining).
   */
  clearCustomPatterns(): PolicyBuilder;

  /**
   * Build a ScanPolicy object from the current builder state.
   *
   * The returned object omits server-assigned fields (`policy_id`,
   * `updated_at`) so it can be passed directly to `TrustedMCPClient.updatePolicy`.
   *
   * @returns A ScanPolicy sans server-assigned fields.
   */
  build(): Omit<ScanPolicy, "policy_id" | "updated_at">;

  /**
   * Serialise the current builder state to a YAML string.
   *
   * The produced YAML is suitable for committing to a policy repository
   * and later applying via the TrustedMCP admin CLI.
   *
   * @returns YAML representation of the policy.
   */
  toYaml(): string;

  /**
   * Create a deep copy of this builder, allowing branched policy derivation.
   *
   * @returns A new PolicyBuilder with identical current state.
   */
  clone(): PolicyBuilder;
}

// ---------------------------------------------------------------------------
// Minimal YAML serialiser
// ---------------------------------------------------------------------------

function toYamlValue(value: unknown): string {
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return String(value);
  if (typeof value === "string") {
    // Quote strings that contain special YAML characters.
    if (/[:#\[\]{},|>&*!%@`'"\\]/.test(value) || value.trim() !== value) {
      return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
    }
    return value;
  }
  return String(value);
}

function draftToYaml(draft: Readonly<PolicyDraft>): string {
  const lines: string[] = ["# TrustedMCP Scan Policy", "---"];

  lines.push(`name: ${toYamlValue(draft.name)}`);
  lines.push(`prompt_injection_enabled: ${toYamlValue(draft.prompt_injection_enabled)}`);
  lines.push(`pii_detection_enabled: ${toYamlValue(draft.pii_detection_enabled)}`);
  lines.push(`malicious_payload_enabled: ${toYamlValue(draft.malicious_payload_enabled)}`);
  lines.push(`block_threshold: ${toYamlValue(draft.block_threshold)}`);
  lines.push(`scan_tool_inputs: ${toYamlValue(draft.scan_tool_inputs)}`);
  lines.push(`scan_tool_outputs: ${toYamlValue(draft.scan_tool_outputs)}`);

  if (draft.custom_patterns.length === 0) {
    lines.push("custom_patterns: []");
  } else {
    lines.push("custom_patterns:");
    for (const pattern of draft.custom_patterns) {
      lines.push(`  - ${toYamlValue(pattern)}`);
    }
  }

  return lines.join("\n") + "\n";
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create a PolicyBuilder initialised with safe defaults.
 *
 * Defaults:
 * - All scanning checks enabled
 * - block_threshold: "high"
 * - scan_tool_inputs: true
 * - scan_tool_outputs: false
 * - custom_patterns: []
 *
 * @param name - Human-readable name for the policy being constructed.
 * @returns A PolicyBuilder instance.
 */
export function createPolicyBuilder(name: string): PolicyBuilder {
  const draft: PolicyDraft = {
    name,
    prompt_injection_enabled: true,
    pii_detection_enabled: true,
    malicious_payload_enabled: true,
    block_threshold: "high",
    scan_tool_inputs: true,
    scan_tool_outputs: false,
    custom_patterns: [],
  };

  const builder: PolicyBuilder = {
    withPromptInjectionScanning(enabled: boolean): PolicyBuilder {
      draft.prompt_injection_enabled = enabled;
      return builder;
    },

    withPiiDetection(enabled: boolean): PolicyBuilder {
      draft.pii_detection_enabled = enabled;
      return builder;
    },

    withMaliciousPayloadScanning(enabled: boolean): PolicyBuilder {
      draft.malicious_payload_enabled = enabled;
      return builder;
    },

    withBlockThreshold(threshold: PolicySeverity): PolicyBuilder {
      draft.block_threshold = threshold;
      return builder;
    },

    withToolInputScanning(enabled: boolean): PolicyBuilder {
      draft.scan_tool_inputs = enabled;
      return builder;
    },

    withToolOutputScanning(enabled: boolean): PolicyBuilder {
      draft.scan_tool_outputs = enabled;
      return builder;
    },

    addCustomPattern(pattern: string): PolicyBuilder {
      draft.custom_patterns.push(pattern);
      return builder;
    },

    clearCustomPatterns(): PolicyBuilder {
      draft.custom_patterns = [];
      return builder;
    },

    build(): Omit<ScanPolicy, "policy_id" | "updated_at"> {
      return {
        name: draft.name,
        prompt_injection_enabled: draft.prompt_injection_enabled,
        pii_detection_enabled: draft.pii_detection_enabled,
        malicious_payload_enabled: draft.malicious_payload_enabled,
        block_threshold: draft.block_threshold,
        scan_tool_inputs: draft.scan_tool_inputs,
        scan_tool_outputs: draft.scan_tool_outputs,
        custom_patterns: [...draft.custom_patterns],
      };
    },

    toYaml(): string {
      return draftToYaml(draft);
    },

    clone(): PolicyBuilder {
      const cloned = createPolicyBuilder(draft.name);
      cloned
        .withPromptInjectionScanning(draft.prompt_injection_enabled)
        .withPiiDetection(draft.pii_detection_enabled)
        .withMaliciousPayloadScanning(draft.malicious_payload_enabled)
        .withBlockThreshold(draft.block_threshold)
        .withToolInputScanning(draft.scan_tool_inputs)
        .withToolOutputScanning(draft.scan_tool_outputs);
      for (const pattern of draft.custom_patterns) {
        cloned.addCustomPattern(pattern);
      }
      return cloned;
    },
  };

  return builder;
}
