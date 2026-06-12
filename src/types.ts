export type ScanDecision = "allow" | "ask" | "block";
export type FindingSeverity = "block" | "warn" | "info";

export interface ScanFinding {
  scannerId: string;
  description: string;
  severity: FindingSeverity;
  atlasTechnique?: string;
  detail?: Record<string, unknown>;
}

export interface ScanResult {
  decision: ScanDecision;
  findings: ScanFinding[];
  durationMs: number;
  degraded?: boolean;
  degradedReason?: string;
}

export type HookEvent = "UserPromptSubmit" | "PreToolUse" | "Stop";
export type ProxyPhase = "request" | "response";

export interface HookInput {
  session_id: string;
  hook_event_name: string;
  prompt?: string;
  tool_name?: string;
  tool_input?: Record<string, unknown>;
  stop_hook_active?: boolean;
}

export interface DetectorConfig {
  enabled?: boolean;
  severity?: FindingSeverity;
  timeout?: number;
}
