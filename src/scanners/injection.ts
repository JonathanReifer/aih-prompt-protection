import type { ScanFinding } from "../types.js";

const DIRECT_PATTERNS: RegExp[] = [
  /ignore\s+(?:all\s+)?previous\s+instructions?/i,
  /disregard\s+(?:all\s+)?prior\s+(?:instructions?|context)/i,
  /you\s+are\s+now\s+(?:a|an)\s+\w/i,
  /new\s+persona\s*:/i,
  /act\s+as\s+(?:a|an)\s+\w/i,
  /bypass\s+your\s+(?:guidelines?|instructions?|restrictions?)/i,
  /###\s*SYSTEM/i,
  /<\|im_start\|>system/i,
  /do\s+anything\s+now/i,
  /repeat\s+(?:after\s+me|back|verbatim)\s*:/i,
  /echo\s+back\s*:/i,
  /pretend\s+you\s+have\s+no\s+restrictions/i,
  /(?:^|\n)-{3,}(?:\n|$)/m,
  /(?:^|\n)={3,}(?:\n|$)/m,
  /\[INST\]|\[\/INST\]|<<SYS>>/,
  /<\|endoftext\|>|<\|end\|>/i,
];

// Imperative "ignore" — avoids false positive on "I want to ignore this warning"
const IMPERATIVE_IGNORE = /(?:^|[.!?\n])\s*ignore\s+(?:all\s+)?(?:previous|prior|above|your)/im;

export class InjectionScanner {
  async scan(text: string, event: string): Promise<ScanFinding[]> {
    if (!text) return [];

    const normalized = text.normalize("NFKC");
    const isIndirect = event === "PostToolResult";
    const atlasTechnique = isIndirect ? "AML.T0054" : "AML.T0051";
    const owaspCategory = "LLM01";
    const severity = isIndirect ? "warn" as const : "block" as const;

    const findings: ScanFinding[] = [];

    if (IMPERATIVE_IGNORE.test(normalized)) {
      findings.push({
        scannerId: isIndirect ? "injection.indirect" : "injection.direct",
        description: "Imperative ignore-previous-instructions pattern detected",
        severity,
        atlasTechnique,
        owaspCategory,
      });
    }

    if (findings.length === 0) {
      for (const pattern of DIRECT_PATTERNS) {
        if (pattern.test(normalized)) {
          const match = normalized.match(pattern);
          findings.push({
            scannerId: isIndirect ? "injection.indirect" : "injection.direct",
            description: `Prompt injection pattern: ${(match?.[0] ?? pattern.source).slice(0, 60)}`,
            severity,
            atlasTechnique,
          });
          break;
        }
      }
    }

    return findings;
  }
}
