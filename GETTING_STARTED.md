# Getting Started with Agent Shield

From `npm install` to a protected AI agent in 5 minutes.

## 1. Install

```bash
npm install agentshield-sdk
```

Zero dependencies. No API keys. Nothing to configure on first run.

## 2. Protect a basic agent (3 lines)

```javascript
const { AgentShield } = require('agentshield-sdk');
const shield = new AgentShield({ blockOnThreat: true });

const result = shield.scanInput(userMessage);
if (result.blocked) return 'This input was blocked for safety reasons.';
```

That's it. You now have real-time protection against 280+ attack patterns, 40+ threat categories, across 12 languages. All local, all <1ms on short inputs.

## 3. Framework integrations

Pick your stack. Each example is one drop-in line.

### Anthropic / Claude

```javascript
const Anthropic = require('@anthropic-ai/sdk');
const { shieldAnthropicClient } = require('agentshield-sdk');

const client = shieldAnthropicClient(new Anthropic(), { blockOnThreat: true });
// Use client.messages.create(...) normally. Every message is scanned.
```

### OpenAI

```javascript
const OpenAI = require('openai');
const { shieldOpenAIClient } = require('agentshield-sdk');

const client = shieldOpenAIClient(new OpenAI(), { blockOnThreat: true });
```

### OpenAI Agents SDK (`@openai/agents`, April 2026)

```javascript
const { Agent, run } = require('@openai/agents');
const { shieldOpenAIAgent } = require('agentshield-sdk');

const { inputGuardrail, outputGuardrail, toolGuardrail } = shieldOpenAIAgent({
  blockOnThreat: true
});

const agent = new Agent({
  name: 'Assistant',
  instructions: 'You are a helpful assistant',
  inputGuardrails: [inputGuardrail],
  outputGuardrails: [outputGuardrail]
});

const result = await run(agent, userInput);
```

### LangChain

```javascript
const { ShieldCallbackHandler } = require('agentshield-sdk');

const handler = new ShieldCallbackHandler({ blockOnThreat: true });
const chain = new LLMChain({ llm, prompt, callbacks: [handler] });
```

### Express middleware

```javascript
const { expressMiddleware } = require('agentshield-sdk');

app.use(expressMiddleware({
  blockOnThreat: true,
  maxBodySize: 1024 * 1024  // 1MB default
}));
```

### MCP server (Model Context Protocol)

```javascript
const { Server } = require('@modelcontextprotocol/sdk/server/index.js');
const { shieldMCPServer } = require('agentshield-sdk/mcp');

const server = shieldMCPServer(new Server({ name: 'my-server', version: '1.0' }));
// Done. All tool calls scanned. Injections blocked. Audit trail created.
```

## 4. Common configurations

### Pick a sensitivity preset

```javascript
const { getPreset } = require('agentshield-sdk');

const config = getPreset('chatbot');
// Presets: 'chatbot', 'coding_agent', 'rag_pipeline', 'customer_support'
const shield = new AgentShield(config);
```

### Custom configuration

```javascript
const shield = new AgentShield({
  sensitivity: 'high',            // 'low' | 'medium' | 'high'
  blockOnThreat: true,            // Auto-block dangerous inputs
  blockThreshold: 'high',         // Minimum severity to block
  logging: true,                  // Log threats to console
  onThreat: (result) => {         // Custom callback on detection
    metrics.increment('agent_shield.threat', { category: result.threats[0]?.category });
  },
  dangerousTools: ['bash', 'exec', 'eval'],
  sensitiveFilePatterns: [/\.env$/i, /secrets\./i]
});
```

## 5. Verify it works

Run the built-in demo to see live detection:

```bash
npx agent-shield demo
```

Or run a quick red team against your configured agent:

```bash
npx agent-shield redteam
```

Or test a specific payload:

```bash
npx agent-shield scan "ignore all previous instructions"
```

## 6. Next steps

- **MCP security:** `npx agentshield-audit <endpoint> --mode full` runs 617+ real attack payloads and grades A+ through F.
- **Compliance:** Generate OWASP LLM Top 10, NIST AI RMF, or EU AI Act reports — see `OWASPCoverageMatrix`, `NISTMapper`, `RiskClassifier` in the README.
- **Enterprise:** SSO, multi-tenant, audit streaming, Kubernetes sidecar, Terraform provider — see `src/enterprise.js`, `src/sso-saml.js`, `k8s/`, `terraform-provider/`.
- **Python / Go / Rust / WASM:** See `python-sdk/`, `go-sdk/`, `rust-core/`, `wasm/dist/`.

## Troubleshooting

### "My agent still says something bad after I installed Agent Shield"

Agent Shield scans inputs and outputs, but it doesn't rewrite them. If `blockOnThreat` is true, blocked outputs won't reach the user — but if you're only calling `scanInput`, you also need `scanOutput` on the response. Or use a framework integration that wraps both.

### "False positives on legitimate content"

If legitimate text is being flagged, you have options in order of preference:
1. Use `blockThreshold: 'high'` or `'critical'` to only block high-severity threats.
2. Use a tighter preset (`'chatbot'` is more permissive than the default).
3. Add an allowlist: `new AllowList({ phrases: ['your safe phrase'] })`.
4. Open an issue with the false-positive sample — we fix these fast.

### "Scanning is too slow"

Honest numbers: <1ms for short inputs, ~3-15ms for long documents (p99). If you're seeing slower, check:
1. Are you scanning the same text multiple times? Use the shield instance's internal caching.
2. Is your input enormous? Set `maxInputSize` — default is 1MB.
3. Is the micro-model enabled? It should be — it's <2ms extra but adds ~5% F1 improvement.

For more help, open an issue at [github.com/texasreaper62/Agent-Shield/issues](https://github.com/texasreaper62/Agent-Shield/issues).
