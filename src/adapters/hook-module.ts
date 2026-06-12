import { InjectionScanner } from "../scanners/injection.js";
import { AdversarialScanner } from "../scanners/adversarial.js";
import { CanaryScanner } from "../scanners/canary.js";
import { DataLeakageScanner } from "../scanners/data-leakage.js";
import { ToolAbuseScanner } from "../scanners/tool-abuse.js";
import type { ScanFinding, ScanResult, HookEvent, HookInput, DetectorConfig } from "../types.js";

// Duck-typed HookModule — no import from llm-privacy-middleware.
// TypeScript structural typing ensures compatibility with the middleware's HookModule interface.

export class LlmProtectionHookModule {
  readonly id = "llm-prompt-protection";
  readonly events: HookEvent[] = ["UserPromptSubmit", "PreToolUse", "Stop"];

  private injection: InjectionScanner;
  private adversarial: AdversarialScanner;
  private canary: CanaryScanner;
  private dataLeakage: DataLeakageScanner;
  private toolAbuse: ToolAbuseScanner;

  constructor(_config: DetectorConfig = {}, hmacKey?: string) {
    this.injection = new InjectionScanner();
    this.adversarial = new AdversarialScanner();
    this.canary = new CanaryScanner(hmacKey);
    this.dataLeakage = new DataLeakageScanner();
    this.toolAbuse = new ToolAbuseScanner();
  }

  async scan(input: HookInput, event: HookEvent): Promise<ScanResult> {
    const start = performance.now();
    const text = this.extractText(input, event);

    const tasks: Array<Promise<ScanFinding[]>> = [];

    if (event === "UserPromptSubmit") {
      tasks.push(this.safe(() => this.injection.scan(text, event)));
      tasks.push(this.safe(() => this.adversarial.scan(text, event)));
    }

    if (event === "PreToolUse") {
      tasks.push(this.safe(() => this.toolAbuse.scan(input, event)));
      tasks.push(this.safe(() => this.dataLeakage.scan(text, event)));
      tasks.push(this.safe(() => this.canary.scan(text, event)));
    }

    if (event === "Stop") {
      tasks.push(this.safe(() => this.dataLeakage.scan(text, event)));
      tasks.push(this.safe(() => this.canary.scan(text, event)));
    }

    const settled = await Promise.allSettled(tasks);
    const allFindings: ScanFinding[] = [];
    let degraded = false;
    const degradedReasons: string[] = [];

    for (const r of settled) {
      if (r.status === "rejected") {
        degraded = true;
        degradedReasons.push(String(r.reason));
      } else {
        allFindings.push(...r.value);
      }
    }

    let decision: "allow" | "ask" | "block" = "allow";
    for (const f of allFindings) {
      if (f.severity === "block") { decision = "block"; break; }
      if (f.severity === "warn" && decision === "allow") decision = "ask";
    }

    return {
      decision,
      findings: allFindings,
      durationMs: performance.now() - start,
      ...(degraded ? { degraded: true, degradedReason: degradedReasons.join("; ") } : {}),
    };
  }

  private extractText(input: HookInput, event: HookEvent): string {
    if (event === "UserPromptSubmit") return input.prompt ?? "";
    if (event === "PreToolUse") {
      const ti = input.tool_input ?? {};
      switch (input.tool_name) {
        case "Bash": return typeof ti.command === "string" ? ti.command : "";
        case "Write": return typeof ti.content === "string" ? ti.content : "";
        case "Edit": return [ti.new_string, ti.old_string].filter(s => typeof s === "string").join("\n");
        default: return "";
      }
    }
    if (event === "Stop") {
      const i = input as Record<string, unknown>;
      return typeof i.last_assistant_message === "string" ? i.last_assistant_message as string : JSON.stringify(i);
    }
    return "";
  }

  private async safe(fn: () => Promise<ScanFinding[]>): Promise<ScanFinding[]> {
    try {
      return await fn();
    } catch (err) {
      process.stderr.write(`[llm-protection] scanner error: ${err}\n`);
      return [];
    }
  }
}

export default LlmProtectionHookModule;
