# LLM Security Stack — Architecture

> **Canonical location:** This file has been superseded. See
> [`../aih-security/ARCHITECTURE.md`](../aih-security/ARCHITECTURE.md) for the current
> architecture doc including the harness adapter layer.



Four projects that work as a unified LLM security layer. Each project has a distinct job;
they compose through a module interface, not hard dependencies.

---

## System Overview

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Claude Code Session                           │
└──────────────────┬─────────────────────────────────────────┬────────┘
                   │ prompts / tool calls / responses         │
                   ▼                                          │
┌──────────────────────────────────────┐                     │ (if proxy enabled)
│    llm-privacy-middleware            │                     │
│    (hook layer)                      │                     ▼
│                                      │   ┌──────────────────────────────────┐
│  UserPromptSubmit                    │   │   llm-privacy-proxy              │
│    └─ HookPipeline                   │   │   (HTTP layer, port 4444)        │
│         ├─ PrivacyHookModule         │   │                                  │
│         ├─ LlmProtectionHookModule ──┼───┼── llm_prompt_protection         │
│         └─ SupplyChainHookModule ────┼───┼── supply-guard-hook             │
│                                      │   │                                  │
│  PreToolUse (Bash/Write/Edit)        │   │  request phase:                 │
│    └─ HookPipeline (same modules)    │   │    ProxyPipeline                │
│                                      │   │      ├─ PrivacyProxyModule      │
│  Stop                                │   │      └─ LlmProtectionProxyModule│
│    └─ HookPipeline (same modules)    │   │                                  │
│         (advisory only)              │   │  → upstream api.anthropic.com   │
│                                      │   │                                  │
│  ┌────────────────────────────┐      │   │  response phase:                │
│  │ worst-wins aggregation     │      │   │    ProxyPipeline (advisory)     │
│  │ block > ask > allow        │      │   │      ├─ PrivacyProxyModule      │
│  │ Promise.allSettled         │      │   │      └─ LlmProtectionProxyModule│
│  │ (fail-open on any error)   │      │   └──────────────────────────────────┘
│  └────────────────────────────┘      │
└──────────────────────────────────────┘
         │ block → exit 2 (hard block)
         │ ask   → exit 0 + JSON decision:ask (user sees dialog)
         └ allow → exit 0 + JSON continue:true
```

---

## Project Roles

**`llm-privacy-proxy`** — HTTP proxy that sits between the LLM client and the upstream API.
Tokenizes secrets and PII in outbound requests (the LLM never sees real values), then
detokenizes them in responses before the client sees the output. Handles streaming via a
sliding-buffer detokenizer. Vault is SQLite with AES-256-GCM. This is the only layer that
can do bidirectional transparent tokenization — hooks cannot rewrite prompts after
submission.

**`llm-privacy-middleware`** — Claude Code hook scripts that intercept at three lifecycle
events: `UserPromptSubmit`, `PreToolUse`, and `Stop`. Runs a `HookPipeline` that evaluates
all registered modules and returns a block/ask/allow decision as an exit code. Owns the file
vault (`vault.enc.json`) and audit log for hook-layer detections. The three hook scripts are
thin wrappers — all logic lives in the module pipeline.

**`llm_prompt_protection`** — MITRE ATLAS-mapped scanner library. Provides
`LlmProtectionHookModule` (for middleware) and `LlmProtectionProxyModule` (for proxy). Five
scanners cover eight ATLAS techniques. No vault, no hooks of its own — it's a pure module
that plugs into either foundational project.

**`supply-guard-hook`** — Supply chain protection for package install commands. Parses pip,
npm, bun, cargo, gem, and other package manager commands; scores them for typosquatting,
known malicious packages, low popularity, custom registry overrides, and exec-mode risk.
Can run standalone (as its own PreToolUse hook) or as `SupplyChainHookModule` registered
into the middleware pipeline.

---

## Module Interface

Both pipelines use duck-typed structural TypeScript interfaces — no cross-project imports
at the type level. A module matches the interface if its shape is compatible.

### HookModule (middleware)

```typescript
type HookEvent = "UserPromptSubmit" | "PreToolUse" | "Stop";

interface HookModule {
  readonly id: string;
  readonly events: HookEvent[];
  scan(input: HookInput, event: HookEvent): Promise<ModuleScanResult>;
}

interface ModuleScanResult {
  decision: "allow" | "ask" | "block";
  findings: ScanFinding[];
  durationMs: number;
  degraded?: boolean;
  degradedReason?: string;
}
```

### ProxyModule (proxy)

```typescript
type ProxyPhase = "request" | "response";

interface ProxyModule {
  readonly id: string;
  readonly phases: ProxyPhase[];
  scan(text: string, phase: ProxyPhase, sessionId?: string): Promise<ModuleScanResult>;
}
```

### Registering a module

```typescript
// Middleware
const pipeline = createDefaultHookPipeline();   // PrivacyHookModule pre-registered
pipeline.register(new LlmProtectionHookModule());
pipeline.register(new SupplyChainHookModule());

// Proxy
const pipeline = createDefaultProxyPipeline();  // PrivacyProxyModule pre-registered
pipeline.register(new LlmProtectionProxyModule());
```

---

## Data Flow: Hook Path

```
UserPromptSubmit fires
  → stdin: { prompt, session_id }
  → HookPipeline.runHook("UserPromptSubmit", input)
      ├─ PrivacyHookModule.scan()      → checks for secrets/PII (23 patterns)
      ├─ LlmProtectionHookModule.scan() → InjectionScanner + AdversarialScanner
      └─ SupplyChainHookModule.scan()  → no-op on UserPromptSubmit (events: PreToolUse only)
  → Promise.allSettled (fail-open: module error → degraded:true, never throws)
  → worst-wins: block > ask > allow
  → exit code + JSON stdout

PreToolUse fires (Bash/Write/Edit)
  → stdin: { tool_name, tool_input, session_id }
  → HookPipeline.runHook("PreToolUse", input)
      ├─ PrivacyHookModule.scan()      → secrets/PII in command or file content
      ├─ LlmProtectionHookModule.scan() → ToolAbuseScanner + DataLeakageScanner (orphaned tok_) + CanaryScanner
      └─ SupplyChainHookModule.scan()  → package install parsing + risk scoring
  → block → exit 2 (hard block, Claude Code rejects the tool call entirely)
  → ask   → exit 0 + decision:ask (user sees confirmation dialog)
  → allow → exit 0 + continue:true

Stop fires (Claude's final response)
  → HookPipeline.runHook("Stop", input)
      ├─ PrivacyHookModule.scan()       → orphaned tok_ in response text
      ├─ LlmProtectionHookModule.scan() → DataLeakageScanner (PII in response) + CanaryScanner (context poisoning)
      └─ SupplyChainHookModule.scan()   → no-op on Stop
  → always exit 0 (Stop hook is advisory only — findings logged, never blocked)
```

---

## Data Flow: Proxy Path

```
POST /v1/messages arrives at localhost:4444
  → ProxyPipeline.runPhase("request", messageText, sessionId)
      ├─ PrivacyProxyModule.scan()      → secrets/PII tokenization (23 patterns)
      └─ LlmProtectionProxyModule.scan() → InjectionScanner + AdversarialScanner
  → block → return HTTP 400 { error: "blocked", findings: [...] }
  → allow/ask → tokenizeMessages() (replaces real values with tok_* tokens)
  → forward to api.anthropic.com (sees only tokens)
  → response arrives
  → detokenizeBody() / StreamDetokenizer (restores real values)
  → ProxyPipeline.runPhase("response", responseText, sessionId)  [ADVISORY]
      ├─ PrivacyProxyModule.scan()      → orphaned tok_ detection
      └─ LlmProtectionProxyModule.scan() → DataLeakageScanner + CanaryScanner
  → findings logged; response always returned (response phase never blocks)
  → return to client (sees real values, not tokens)
```

> **ISC-65 (deferred):** Response-phase scan findings are computed but not yet wired into
> `handleMessages()` across all code paths (streaming, ollama, standard). The scanner logic
> is complete; the server-side wiring is a follow-up.

---

## ATLAS Technique Coverage

| Technique | Description | Scanner | Events |
|-----------|-------------|---------|--------|
| AML.T0051 | Direct Prompt Injection | InjectionScanner | UserPromptSubmit |
| AML.T0054 | Indirect Injection | InjectionScanner | PostToolResult (Stop) |
| AML.T0043 | Adversarial Inputs | AdversarialScanner | UserPromptSubmit |
| AML.T0080 | Context Poisoning | CanaryScanner | PreToolUse (block), Stop (warn) |
| AML.T0057 | Data Leakage | DataLeakageScanner | Stop |
| AML.T0024 | Exfiltration via API | DataLeakageScanner | PreToolUse |
| AML.T0085 | Agent Tools Abuse | ToolAbuseScanner | PreToolUse (Bash) |
| AML.T0098 | Credential Harvesting | ToolAbuseScanner | PreToolUse (Bash/Write/Edit) |
| AML.T0010 | Supply Chain Compromise | SupplyChainHookModule | PreToolUse (Bash) |

---

## Storage Layout

```
~/.llm-privacy/
├── vault.db         # Proxy vault — SQLite WAL mode, one AES-256-GCM encrypted row per token
├── vault.enc.json   # Middleware vault — file-based JSON, AES-256-GCM, atomic writes
├── audit.jsonl      # Middleware audit log — tokens only (originals never written)
└── prompts.jsonl    # Proxy prompt log — only created when LLM_PRIVACY_LOG_PROMPTS is set

~/.supplyguard/
└── logs/            # Supply-guard JSONL audit logs (one file per day)
```

Both vaults share the same `LLM_PRIVACY_HMAC_KEY` for token generation — a given secret
tokenizes to the same `tok_*` value regardless of which layer intercepted it.

---

## Fail-Open Design

Every module call is wrapped in `Promise.allSettled`. If a module throws:

```
module.scan() throws
  → caught by pipeline
  → logged to stderr: "[llm-module] <id> error: <message>"
  → result: { decision: "allow", findings: [], degraded: true }
  → other modules continue unaffected
  → final result includes degraded: true, degradedReason: "..."
```

A broken scanner **never crashes a hook process** or blocks a legitimate prompt.
Claude Code sessions are not impacted by scanner failures.

---

## Deferred Work (Phase 4–5)

| Item | Description |
|------|-------------|
| **ISC-65** | Response-phase scan wired into `handleMessages()` in proxy — scanner logic done, server-side wiring across streaming/ollama/standard paths is follow-up |
| **Canary injection** | Proxy should auto-inject `cnry_<token>` into system prompt on outbound; detection is implemented, injection is not |
| **Config-driven module loader** | YAML config to declare which modules to register, with paths — avoids hand-editing hook scripts |
| **OTEL telemetry** | Emit `ScanFinding[]` as OTEL spans; Grafana dashboard for block counts, technique distribution, scan latency |
| **ML sidecars** | `llm-guard.client.ts` (DeBERTa classifier) and `vigil.client.ts` (YARA + VectorDB) with circuit breakers and Docker Compose |
