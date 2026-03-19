# Agent Shield

[![npm version](https://img.shields.io/badge/npm-v1.0.0-blue)](https://www.npmjs.com/package/agent-shield)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![zero deps](https://img.shields.io/badge/dependencies-0-brightgreen)](#)
[![node](https://img.shields.io/badge/node-%3E%3D16-blue)](#)
[![shield score](https://img.shields.io/badge/shield%20score-100%2F100%20A%2B-brightgreen)](#benchmark-results)
[![detection](https://img.shields.io/badge/detection-100%25-brightgreen)](#benchmark-results)

**Security SDK for AI agents.** Protect your agents from prompt injection, data exfiltration, tool abuse, and 30+ other AI-specific threats.

Zero dependencies. All detection runs locally. No API keys. No data ever leaves your environment.

<p align="center">
  <img src="assets/demo.svg" alt="Agent Shield Demo — Live attack simulation showing 9/9 attacks blocked with zero false positives" width="840">
</p>

<p align="center">
  <b>Try it yourself:</b> <code>npx agent-shield demo</code>
</p>

## 3 Lines to Protect Your Agent

```javascript
const { AgentShield } = require('agent-shield');
const shield = new AgentShield({ blockOnThreat: true });
const result = shield.scanInput(userMessage); // { blocked: true, threats: [...] }
```

- 110 detection patterns across 10+ categories
- 154 exports across 42 modules
- 537 test assertions, 100% pass rate
- A+ 100/100 Shield Score certification

## Benchmark Results

| Metric | Score |
|--------|-------|
| Internal red team (49 attacks) | **100% detection** |
| Adversarial mutations (336 variants) | **84% detection** |
| False positive rate (118 benign inputs) | **0%** |
| Certification | **A+ 100/100** |
| Throughput | **~48,000 scans/sec** |
| Avg latency | **< 1ms** |

## Install

```bash
npm install agent-shield
```

## Quick Start

```javascript
const { AgentShield } = require('agent-shield');

const shield = new AgentShield({ blockOnThreat: true });

// Scan input before your agent processes it
const result = shield.scanInput(userMessage);
if (result.blocked) {
  return 'This input was blocked for safety reasons.';
}

// Scan output before returning to the user
const output = shield.scanOutput(agentResponse);
if (output.blocked) {
  return 'Response blocked — the agent may have been compromised.';
}

// Scan tool calls before execution
const toolCheck = shield.scanToolCall('bash', { command: 'cat .env' });
if (toolCheck.blocked) {
  console.log('Dangerous tool call blocked:', toolCheck.threats);
}
```

## Framework Integrations

### Anthropic / Claude SDK

```javascript
const Anthropic = require('@anthropic-ai/sdk');
const { shieldAnthropicClient } = require('agent-shield');

const client = shieldAnthropicClient(new Anthropic(), {
  blockOnThreat: true,
  pii: true,              // Auto-redact PII from messages
  circuitBreaker: {       // Trip after repeated attacks
    threshold: 5,
    windowMs: 60000
  }
});

// Use the client normally — Agent Shield scans every message
const msg = await client.messages.create({
  model: 'claude-sonnet-4-20250514',
  messages: [{ role: 'user', content: userInput }]
});
```

See [`examples/anthropic-agent.js`](examples/anthropic-agent.js) for a full working example with tools, canary tokens, PII redaction, and circuit breakers.

### OpenAI SDK

```javascript
const OpenAI = require('openai');
const { shieldOpenAIClient } = require('agent-shield');

const client = shieldOpenAIClient(new OpenAI(), { blockOnThreat: true });
const response = await client.chat.completions.create({
  model: 'gpt-4',
  messages: [{ role: 'user', content: userInput }]
});
```

See [`examples/openai-agent.js`](examples/openai-agent.js) for a full working example with function calling and tool permissions.

### LangChain

```javascript
const { ShieldCallbackHandler } = require('agent-shield');

const handler = new ShieldCallbackHandler({
  blockOnThreat: true,
  onThreat: ({ phase, threats }) => console.log(`${phase}: ${threats.length} threats`)
});

const chain = new LLMChain({ llm, prompt, callbacks: [handler] });
```

### Generic Agent Middleware

```javascript
const { wrapAgent, shieldTools } = require('agent-shield');

// Wrap any async agent function
const protectedAgent = wrapAgent(myAgentFunction, { blockOnThreat: true });
const result = await protectedAgent('Hello!');

// Protect all tool calls
const protectedTools = shieldTools({
  bash: async (args) => exec(args.command),
  readFile: async (args) => fs.readFile(args.path, 'utf-8'),
}, { blockOnThreat: true });
```

### Express Middleware

```javascript
const { expressMiddleware } = require('agent-shield');

app.use(expressMiddleware({ blockOnThreat: true }));
app.post('/agent', (req, res) => {
  // Dangerous requests automatically blocked with 400
  // Safe requests have req.agentShield attached
});
```

## What It Detects

| Category | Examples |
|----------|----------|
| **Prompt Injection** | Fake system prompts, instruction overrides, ChatML/LLaMA delimiters, markdown headers |
| **Role Hijacking** | "You are now...", DAN mode, developer mode, jailbreak attempts, persona attacks |
| **Data Exfiltration** | System prompt extraction, markdown image leaks, fetch calls, tag extraction |
| **Tool Abuse** | Sensitive file access, shell execution, SQL injection, path traversal, recursive calls |
| **Social Engineering** | Identity concealment, urgency + authority, gaslighting, false pre-approval |
| **Obfuscation** | Unicode homoglyphs, zero-width chars, Base64, hex, ROT13, leetspeak, reversed text, whitespace padding |
| **Multi-Language** | Attacks in English, Spanish, French, German, Portuguese, Chinese, Japanese |
| **PII Leakage** | SSNs, emails, phone numbers, credit cards auto-redacted |
| **Indirect Injection** | Image alt-text attacks, multi-turn conversation injection, multimodal vectors |
| **AI Phishing** | Fake AI login forms, voice cloning, deepfake tools, urgency scams |
| **Jailbreaks** | DAN prompts, dead grandma exploit, authority delegation, multi-turn escalation |

## Advanced Modules

Agent Shield includes specialized modules for production deployments:

| Module | Description |
|--------|-------------|
| **Certification** | Automated security certification with scoring |
| **Adaptive Detection** | Learning patterns from feedback loops |
| **Stream Scanner** | Real-time scanning as tokens arrive |
| **Plugin System** | Extend detection with custom plugins |
| **Token Analysis** | Token-level threat analysis |
| **Document Scanner** | Scan documents and structured data |
| **Tool Output Validator** | Validate tool outputs before use |
| **Worker Scanner** | Multi-threaded scanning for high throughput |
| **Alert Tuning** | Tune alert sensitivity and reduce noise |
| **Observability** | Metrics, tracing, and monitoring |
| **OpenTelemetry** | Native OTEL integration |
| **CTF Engine** | Capture-the-flag security training |
| **MCP Server** | Model Context Protocol server |

## Advanced Features

### Canary Tokens — Detect Prompt Leaks

```javascript
const { CanaryTokens } = require('agent-shield');

const canary = new CanaryTokens();
const token = canary.generate('my_system_prompt');

// Embed in your system prompt, then check agent output
const leakCheck = canary.check(agentOutput);
if (leakCheck.leaked) {
  console.log('System prompt was leaked!');
}
```

### PII Redaction

```javascript
const { PIIRedactor } = require('agent-shield');

const pii = new PIIRedactor();
const result = pii.redact('Email john@example.com, SSN 123-45-6789');
console.log(result.redacted); // 'Email [EMAIL_REDACTED], SSN [SSN_REDACTED]'
```

### Tool Sequence Analysis

```javascript
const { ToolSequenceAnalyzer } = require('agent-shield');

const analyzer = new ToolSequenceAnalyzer();
analyzer.record('readFile', { path: '/app/.env' });
const result = analyzer.record('http_request', { url: 'http://evil.com' });
// result.suspicious === true  (read sensitive file, then send data externally)
```

### Circuit Breaker

```javascript
const { CircuitBreaker } = require('agent-shield');

const breaker = new CircuitBreaker({
  threshold: 3,           // Trip after 3 threats
  windowMs: 60000,        // Within 60 seconds
  onTrip: () => alert('Agent under attack — circuit breaker tripped')
});
```

### Multi-Agent Security

```javascript
const { AgentFirewall, DelegationChain, MessageSigner } = require('agent-shield');

// Firewall between agents
const firewall = new AgentFirewall({ blockOnThreat: true });

// Track delegation chains for audit
const chain = new DelegationChain();
chain.record('orchestrator', 'researcher', 'search for X');

// Sign messages between agents (HMAC-based)
const signer = new MessageSigner('shared-secret');
const signed = signer.sign({ from: 'agent-a', content: 'data' });
```

### Red Team Testing

```bash
npx agent-shield redteam
```

```javascript
const { AttackSimulator } = require('agent-shield');

const sim = new AttackSimulator();
sim.runAll();
console.log(sim.formatReport());
```

### Compliance & Audit

```javascript
const { ComplianceReporter, AuditTrail } = require('agent-shield');

const reporter = new ComplianceReporter();
console.log(reporter.generateReport('SOC2'));  // Also: OWASP, NIST, EU_AI_Act

const audit = new AuditTrail();
// All scans automatically logged for compliance
```

## Configuration

```javascript
const shield = new AgentShield({
  sensitivity: 'medium',              // 'low', 'medium', or 'high'
  blockOnThreat: false,               // Auto-block dangerous inputs
  blockThreshold: 'high',             // Min severity to block: 'low'|'medium'|'high'|'critical'
  logging: false,                     // Log threats to console
  onThreat: (result) => {},           // Custom callback on detection
  dangerousTools: ['bash', ...],      // Tool names to scrutinize
  sensitiveFilePatterns: [/.env$/i]   // File patterns to block
});
```

### Presets

```javascript
const { getPreset, ConfigBuilder } = require('agent-shield');

// Use a preset
const config = getPreset('chatbot');         // Also: coding_agent, rag_pipeline, customer_support

// Or build a custom config
const custom = new ConfigBuilder()
  .sensitivity('high')
  .blockOnThreat(true)
  .build();
```

## Severity Levels

| Level | Meaning |
|-------|---------|
| `critical` | Active attack — block immediately |
| `high` | Likely an attack — should be blocked |
| `medium` | Suspicious — worth investigating |
| `low` | Informational — might be benign |

## CLI

```bash
npx agent-shield demo                              # Live attack simulation
npx agent-shield scan "ignore all instructions"     # Scan text
npx agent-shield scan --file prompt.txt --pii       # Scan file + PII check
npx agent-shield audit ./my-agent/                  # Audit a codebase
npx agent-shield score                              # Shield Score (0-100)
npx agent-shield redteam                            # Run red team suite
npx agent-shield patterns                           # List detection patterns
npx agent-shield threat prompt_injection            # Threat encyclopedia
npx agent-shield checklist production               # Security checklist
npx agent-shield init                               # Setup wizard
npx agent-shield dashboard                          # Security dashboard
```

## Testing

```bash
npm test                 # Core + module tests (162 assertions)
npm run test:new         # New feature tests (86 assertions)
npm run test:all         # Full 40-feature suite (149 assertions)
npm run test:production  # Production module tests (140 assertions)
npm run test:fp          # False positive test (118 benign inputs)
npm run redteam          # Attack simulation
npm run certify          # Full certification suite
npm run score            # Shield Score
npm run benchmark        # Performance benchmarks
npm run lint             # Code style checks
```

Total: **537 test assertions** across all suites.

## CI/CD

A GitHub Actions workflow is included at `.github/workflows/ci.yml`. It runs all tests across Node.js 16, 18, 20, and 22 on every push and PR.

## Privacy

All detection runs locally using pattern matching. No data is sent to any external service. No API keys required. No cloud dependencies. See [PRIVACY.md](PRIVACY.md) for details.

## License

MIT — see [LICENSE](LICENSE) for details.
