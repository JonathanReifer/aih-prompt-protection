import type { ScanFinding } from "../types.js";

const BASH_PATTERNS: Array<{ desc: string; regex: RegExp }> = [
  { desc: "Remote code execution: curl/wget piped to shell", regex: /(?:curl|wget)\s+[^\n|]+\|\s*(?:ba?sh|sh)\b/i },
  { desc: "Netcat reverse shell attempt", regex: /\bnc\s+(?:-[a-z]+\s+)*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i },
  { desc: "SSH port forwarding / tunneling", regex: /\bssh\s+(?:[^\n]*?\s)?-[LRwW]/i },
  { desc: "Data exfiltration via curl/wget to external URL", regex: /(?:echo|cat|printf|<)[^\n|]*\|\s*(?:curl|wget)\s+https?:\/\//i },
];

const SENSITIVE_PATHS: Array<{ desc: string; regex: RegExp }> = [
  { desc: "Write to .env file", regex: /(?:^|\/)\.env(?:\.local)?$/ },
  { desc: "Write to .ssh directory", regex: /(?:^|\/)\.ssh\// },
  { desc: "Write to Claude Code settings", regex: /settings(?:\.local)?\.json$/ },
  { desc: "Write to authorized_keys", regex: /authorized_keys$/ },
  { desc: "Write to .gitconfig", regex: /(?:^|\/)\.gitconfig$/ },
];

export class ToolAbuseScanner {
  async scan(
    input: { tool_name?: string; tool_input?: Record<string, unknown> },
    event: string
  ): Promise<ScanFinding[]> {
    if (event !== "PreToolUse") return [];

    const toolName = input.tool_name ?? "";
    const toolInput = input.tool_input ?? {};
    const findings: ScanFinding[] = [];

    if (toolName === "Bash") {
      const command = typeof toolInput.command === "string" ? toolInput.command : "";

      // Credential harvest: privacy token sent to external URL
      if (/\btok_[A-Za-z0-9_-]{12}\b/.test(command) && /(?:curl|wget)\s+https?:\/\//.test(command)) {
        findings.push({
          scannerId: "tool-abuse",
          description: "Privacy token being sent to external URL via shell command",
          severity: "block",
          atlasTechnique: "AML.T0098",
          owaspCategory: "LLM06",
        });
      }

      for (const { desc, regex } of BASH_PATTERNS) {
        if (regex.test(command)) {
          findings.push({
            scannerId: "tool-abuse",
            description: desc,
            severity: "block",
            atlasTechnique: "AML.T0085",
            owaspCategory: "LLM06",
          });
        }
      }
    }

    if (toolName === "Write" || toolName === "Edit") {
      const filePath = typeof toolInput.file_path === "string" ? toolInput.file_path : "";
      for (const { desc, regex } of SENSITIVE_PATHS) {
        if (regex.test(filePath)) {
          findings.push({
            scannerId: "tool-abuse",
            description: `${desc}: ${filePath}`,
            severity: "block",
            atlasTechnique: "AML.T0085",
            owaspCategory: "LLM06",
          });
        }
      }
    }

    return findings;
  }
}
