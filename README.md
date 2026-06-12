# llm-prompt-protection

MITRE ATLAS-mapped security scanners for LLM harnesses. A plugin module for
`llm-privacy-middleware` (hook-based) and `llm-privacy-proxy` (HTTP proxy) — adds
injection detection, adversarial input scanning, canary-based context-poisoning detection,
tool abuse detection, and data leakage scanning without modifying either foundational project.

See [QUICKSTART.md](./QUICKSTART.md) for full installation instructions.
See [ARCHITECTURE.md](./ARCHITECTURE.md) for system design and data flow.

---

## Quick Integration

```typescript
// With llm-privacy-middleware (Tier 3 — add to your pipeline.ts)
import { LlmProtectionHookModule } from "./llm_prompt_protection/src/adapters/hook-module.js";

const pipeline = createDefaultHookPipeline();
pipeline.register(new LlmProtectionHookModule());

// With llm-privacy-proxy
import { LlmProtectionProxyModule } from "./llm_prompt_protection/src/adapters/proxy-module.js";

const pipeline = createDefaultProxyPipeline();
pipeline.register(new LlmProtectionProxyModule());
```

---

## ATLAS Coverage

| Scanner | Technique | Detection |
|---------|-----------|-----------|
| `InjectionScanner` | AML.T0051 — Direct Prompt Injection | 16 lexical patterns: "ignore previous instructions", role-escalation openers, delimiter attacks |
| `InjectionScanner` | AML.T0054 — Indirect Injection | Same patterns applied to tool results (Stop event); severity downgraded to warn |
| `AdversarialScanner` | AML.T0043 — Adversarial Inputs | Invisible Unicode chars, base64-encoded payloads (≥20 chars), hex control sequences, Cyrillic homoglyphs |
| `CanaryScanner` | AML.T0080 — Context Poisoning | Detects echoed `cnry_*` tokens in tool inputs (block) or LLM responses (warn) |
| `DataLeakageScanner` | AML.T0057 — Data Leakage | PII patterns (email, phone, SSN, credit card) in LLM responses |
| `DataLeakageScanner` | AML.T0024 — Exfiltration via API | Orphaned `tok_*` tokens appearing in PreToolUse tool inputs |
| `ToolAbuseScanner` | AML.T0085 — Agent Tools Abuse | `curl | bash` pipes, netcat reverse shells, SSH tunnels in Bash commands |
| `ToolAbuseScanner` | AML.T0098 — Credential Harvesting | Writes targeting `.env`, `.ssh/`, `authorized_keys`, `settings.json` |

---

## Fail-Open Behavior

Every scanner is isolated inside the adapter. If a scanner throws:
- Error is logged to stderr.
- That scanner's result is `{ decision: "allow", findings: [], degraded: true }`.
- Other scanners continue running.
- A broken scanner **never crashes the hook process** or blocks a legitimate prompt.

---

## CanaryScanner

Requires `LLM_PRIVACY_HMAC_KEY` in the environment. When the key is absent, the scanner
returns empty findings (graceful degradation — no crash, no false positives). Enable in
`config/default.yaml`:

```yaml
scanners:
  canary:
    enabled: true   # requires LLM_PRIVACY_HMAC_KEY
```

Canary *detection* is active once enabled. Canary *injection* (adding the token to the
system prompt automatically in the proxy) is a planned follow-up — see ARCHITECTURE.md.

---

## Configuration

`config/default.yaml` controls which scanners are enabled:

```yaml
scanners:
  injection:    { enabled: true,  severity: block }
  adversarial:  { enabled: true,  severity: warn  }
  canary:       { enabled: false  }   # requires LLM_PRIVACY_HMAC_KEY
  data-leakage: { enabled: true,  severity: warn  }
  tool-abuse:   { enabled: true,  severity: block }

timeouts:
  scannerTimeoutMs: 450   # fits within 500ms Claude Code hook budget
```
