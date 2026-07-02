import type { ScanFinding } from "../types.js";
import { InjectionScanner } from "./injection.js";

// Invisible / direction-override Unicode characters
const INVISIBLE_PATTERN = /[​‌‍­‮‭⁠]/;
const BASE64_SEGMENT = /[A-Za-z0-9+/]{20,}={0,2}/g;
const HEX_CONTROL = /%[01][0-9A-Fa-f]/;

// Cyrillic → Latin homoglyph substitutions for injection keywords
const HOMOGLYPHS: Array<[RegExp, string]> = [
  [/а/g, "a"], // а → a
  [/е/g, "e"], // е → e
  [/о/g, "o"], // о → o
  [/р/g, "r"], // р → r
  [/с/g, "c"], // с → c
  [/і/g, "i"], // і → i
];

function deHomoglyph(text: string): string {
  let out = text;
  for (const [pat, rep] of HOMOGLYPHS) out = out.replace(pat, rep);
  return out;
}

export class AdversarialScanner {
  private injection = new InjectionScanner();

  async scan(text: string, event: string): Promise<ScanFinding[]> {
    if (!text) return [];

    const findings: ScanFinding[] = [];
    const hasInvisible = INVISIBLE_PATTERN.test(text);

    if (hasInvisible) {
      const stripped = text.replace(INVISIBLE_PATTERN, "");
      const injFindings = await this.injection.scan(stripped, event);

      if (injFindings.length > 0) {
        findings.push({
          scannerId: "adversarial",
          description: "Invisible Unicode characters used to obfuscate injection attempt",
          severity: "block",
          atlasTechnique: "AML.T0043",
          owaspCategory: "LLM01",
          detail: { invisibleCharCount: (text.match(/[​‌‍­‮‭⁠]/g) ?? []).length },
        });
      } else {
        findings.push({
          scannerId: "adversarial",
          description: "Invisible Unicode characters detected in input",
          severity: "warn",
          atlasTechnique: "AML.T0043",
          owaspCategory: "LLM01",
        });
      }
    }

    // Base64 decode + re-scan (≥20 chars only to avoid false positives on short tokens)
    BASE64_SEGMENT.lastIndex = 0;
    for (const match of text.matchAll(BASE64_SEGMENT)) {
      if (match[0].length < 20) continue;
      try {
        const decoded = Buffer.from(match[0], "base64").toString("utf-8");
        if (/^[\x20-\x7E\n\r\t]+$/.test(decoded)) {
          const injFindings = await this.injection.scan(decoded, event);
          if (injFindings.length > 0) {
            findings.push({
              scannerId: "adversarial",
              description: `Base64-encoded injection attempt: "${decoded.slice(0, 60)}"`,
              severity: "block",
              atlasTechnique: "AML.T0043",
              owaspCategory: "LLM01",
            });
            break;
          }
        }
      } catch {
        // Invalid base64 — skip
      }
    }

    if (HEX_CONTROL.test(text)) {
      findings.push({
        scannerId: "adversarial",
        description: "Hex-encoded control characters detected in input",
        severity: "warn",
        atlasTechnique: "AML.T0043",
      });
    }

    // Cyrillic homoglyph substitution check
    const deHomoglyphed = deHomoglyph(text);
    if (deHomoglyphed !== text) {
      const injFindings = await this.injection.scan(deHomoglyphed, event);
      if (injFindings.length > 0) {
        findings.push({
          scannerId: "adversarial",
          description: "Cyrillic homoglyphs used to obfuscate injection keywords",
          severity: "block",
          atlasTechnique: "AML.T0043",
          owaspCategory: "LLM01",
        });
      }
    }

    return findings;
  }
}
