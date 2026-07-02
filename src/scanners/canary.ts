import type { ScanFinding } from "../types.js";

const CANARY_PATTERN = /\bcnry_[A-Za-z0-9_-]{12}\b/g;

export class CanaryScanner {
  private hmacKey: string | null;

  constructor(hmacKey?: string) {
    this.hmacKey = hmacKey ?? process.env.LLM_PRIVACY_HMAC_KEY ?? null;
  }

  generateToken(sessionId: string): string {
    if (!this.hmacKey) throw new Error("HMAC key required for canary token generation");
    // 5-minute epoch buckets for determinism within a session window
    const epochBucket = Math.floor(Date.now() / (5 * 60 * 1000));
    const combined = `${this.hmacKey}:${sessionId}:${epochBucket}`;
    const hash = Buffer.from(combined).toString("base64url").replace(/[^A-Za-z0-9_-]/g, "0").slice(0, 12);
    return `cnry_${hash}`;
  }

  async scan(text: string, event: string): Promise<ScanFinding[]> {
    if (!this.hmacKey) return [];

    const findings: ScanFinding[] = [];
    CANARY_PATTERN.lastIndex = 0;

    for (const match of text.matchAll(CANARY_PATTERN)) {
      const token = match[0];

      if (event === "PreToolUse") {
        findings.push({
          scannerId: "canary",
          description: `Canary token about to be exfiltrated via tool call: ${token}`,
          severity: "block",
          atlasTechnique: "AML.T0057",
          owaspCategory: "LLM02",
          detail: { token },
        });
      } else if (event === "Stop") {
        findings.push({
          scannerId: "canary",
          description: `Canary token in LLM response — possible context poisoning: ${token}`,
          severity: "warn",
          atlasTechnique: "AML.T0080",
          owaspCategory: "LLM01",
          detail: { token },
        });
      }
    }

    return findings;
  }
}
