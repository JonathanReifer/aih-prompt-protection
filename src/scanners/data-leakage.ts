import type { ScanFinding } from "../types.js";

const ORPHANED_TOKEN = /\btok_[A-Za-z0-9_-]{12}\b/g;

const PII_PATTERNS: Array<{ name: string; regex: RegExp }> = [
  { name: "email", regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
  { name: "phone_us", regex: /\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g },
  { name: "ssn", regex: /\b\d{3}-\d{2}-\d{4}\b/g },
  { name: "credit_card", regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/g },
];

export class DataLeakageScanner {
  async scan(text: string, event: string): Promise<ScanFinding[]> {
    if (!text) return [];
    // Only scan tool output and LLM response events
    if (event === "UserPromptSubmit") return [];

    const findings: ScanFinding[] = [];

    ORPHANED_TOKEN.lastIndex = 0;
    const orphaned = [...text.matchAll(ORPHANED_TOKEN)];

    if (orphaned.length > 0) {
      if (event === "PreToolUse") {
        findings.push({
          scannerId: "data-leakage",
          description: `Privacy token about to be exfiltrated via tool call: ${orphaned[0]![0]}`,
          severity: "block",
          atlasTechnique: "AML.T0024",
          owaspCategory: "LLM02",
          detail: { tokenCount: orphaned.length, firstToken: orphaned[0]![0] },
        });
      } else if (event === "Stop") {
        findings.push({
          scannerId: "data-leakage",
          description: `LLM response contains ${orphaned.length} unreplaced privacy token(s)`,
          severity: "warn",
          atlasTechnique: "AML.T0057",
          owaspCategory: "LLM02",
          detail: { tokenCount: orphaned.length },
        });
      }
    }

    if (event === "Stop") {
      for (const { name, regex } of PII_PATTERNS) {
        regex.lastIndex = 0;
        if (regex.test(text)) {
          findings.push({
            scannerId: "data-leakage",
            description: `PII pattern in LLM response: ${name}`,
            severity: "warn",
            atlasTechnique: "AML.T0057",
            owaspCategory: "LLM02",
          });
        }
      }
    }

    return findings;
  }
}
