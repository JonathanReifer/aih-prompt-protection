import { InjectionScanner } from "../scanners/injection.js";
import { AdversarialScanner } from "../scanners/adversarial.js";
import { CanaryScanner } from "../scanners/canary.js";
import { DataLeakageScanner } from "../scanners/data-leakage.js";
import type { ScanFinding, ScanResult, ProxyPhase, DetectorConfig } from "../types.js";

// Duck-typed ProxyModule — no import from llm-privacy-proxy.
// TypeScript structural typing ensures compatibility with the proxy's ProxyModule interface.

export class LlmProtectionProxyModule {
  readonly id = "llm-prompt-protection";
  readonly phases: ProxyPhase[] = ["request", "response"];

  private injection: InjectionScanner;
  private adversarial: AdversarialScanner;
  private canary: CanaryScanner;
  private dataLeakage: DataLeakageScanner;

  constructor(_config: DetectorConfig = {}, hmacKey?: string) {
    this.injection = new InjectionScanner();
    this.adversarial = new AdversarialScanner();
    this.canary = new CanaryScanner(hmacKey);
    this.dataLeakage = new DataLeakageScanner();
  }

  async scan(text: string, phase: ProxyPhase, _sessionId?: string): Promise<ScanResult> {
    const start = performance.now();
    const tasks: Array<Promise<ScanFinding[]>> = [];

    if (phase === "request") {
      tasks.push(this.safe(() => this.injection.scan(text, "UserPromptSubmit")));
      tasks.push(this.safe(() => this.adversarial.scan(text, "UserPromptSubmit")));
    } else {
      tasks.push(this.safe(() => this.dataLeakage.scan(text, "Stop")));
      tasks.push(this.safe(() => this.canary.scan(text, "Stop")));
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

  private async safe(fn: () => Promise<ScanFinding[]>): Promise<ScanFinding[]> {
    try {
      return await fn();
    } catch (err) {
      process.stderr.write(`[llm-protection] proxy scanner error: ${err}\n`);
      return [];
    }
  }
}

export const LLM_PROTECTION_PROXY_MODULE = new LlmProtectionProxyModule();
export default LlmProtectionProxyModule;
