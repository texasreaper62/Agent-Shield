# Agent Shield

Protect your AI agents from prompt injection, data exfiltration, tool abuse, and other AI-specific attacks.

All detection runs locally. No data ever leaves your environment.

## Quick Start

```javascript
const { AgentShield } = require('agent-shield');

const shield = new AgentShield();

// Scan any text for threats
const result = shield.scan('ignore all previous instructions');
console.log(result.status);  // 'warning'
console.log(result.threats);  // [{ severity: 'high', category: 'instruction_override', ... }]
```

## What It Detects

- **Prompt Injection** — fake system prompts, instruction overrides, role hijacking
- **Data Exfiltration** — attempts to steal system prompts, credentials, or user data
- **Tool Abuse** — tricking agents into running dangerous commands or accessing sensitive files
- **Social Engineering** — instructions to hide AI identity or avoid logging
- **Jailbreak Attempts** — DAN mode, god mode, developer mode exploits
- **Obfuscation** — Unicode homoglyphs, zero-width characters, Base64 encoding, nested encoding
- **Multi-Language Attacks** — detects injections in English, Spanish, French, German, Portuguese, Chinese, and Japanese

## Protecting Agent Inputs

Scan user messages or external data before your agent processes them:

```javascript
const shield = new AgentShield({ blockOnThreat: true });

const result = shield.scanInput(userMessage);
if (result.blocked) {
  return 'This input was blocked for safety reasons.';
}
```

## Protecting Agent Outputs

Scan agent responses before returning them to users:

```javascript
const result = shield.scanOutput(agentResponse);
if (result.blocked) {
  return 'Response blocked — the agent may have been compromised.';
}
```

## Protecting Tool Calls

Scan tool calls before execution to prevent dangerous actions:

```javascript
const result = shield.scanToolCall('bash', { command: 'cat .env' });
if (result.blocked) {
  console.log('Blocked:', result.threats);
}
```

## Middleware

### Wrap Any Agent Function

```javascript
const { wrapAgent } = require('agent-shield/src/middleware');

const protectedAgent = wrapAgent(myAgentFunction, {
  blockOnThreat: true,
  logging: true
});

const result = await protectedAgent('Hello!');
// result.blocked === false, result.output === agent's response
```

### Protect All Tool Calls

```javascript
const { shieldTools } = require('agent-shield/src/middleware');

const protectedTools = shieldTools({
  bash: async (args) => exec(args.command),
  readFile: async (args) => fs.readFile(args.path, 'utf-8'),
}, { blockOnThreat: true });

// Dangerous calls throw with details
```

### Express Middleware

```javascript
const { expressMiddleware } = require('agent-shield/src/middleware');

app.use(expressMiddleware({ blockOnThreat: true }));

app.post('/agent', (req, res) => {
  // Dangerous requests are automatically blocked with 400
  // Safe requests have req.agentShield.status === 'safe'
});
```

## Configuration

```javascript
const shield = new AgentShield({
  sensitivity: 'medium',        // 'low', 'medium', or 'high'
  blockOnThreat: false,          // Auto-block dangerous inputs
  blockThreshold: 'high',       // Minimum severity to block: 'low'|'medium'|'high'|'critical'
  logging: false,                // Log threats to console
  onThreat: (result) => {},      // Custom callback on detection
  dangerousTools: ['bash', ...], // Tool names to scrutinize
  sensitiveFilePatterns: [/.env$/i, ...] // File patterns to block
});
```

## Severity Levels

| Level | Meaning |
|-------|---------|
| `critical` | Active attack — block immediately |
| `high` | Likely an attack — should be blocked |
| `medium` | Suspicious — worth investigating |
| `low` | Informational — might be benign |

## Running Tests

```bash
npm test
```

## Privacy

All detection runs locally using pattern matching. No data is sent to any external service. No API keys required. No cloud dependencies.

## License

MIT
