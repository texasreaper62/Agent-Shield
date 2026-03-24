# Framework Integration Guide

Agent Shield provides first-class integrations for the most popular AI agent frameworks. Each integration wraps your existing client so you can keep your code unchanged — Agent Shield scans every message transparently.

## Table of Contents

- [Anthropic / Claude SDK](#anthropic--claude-sdk)
- [OpenAI SDK](#openai-sdk)
- [LangChain](#langchain)
- [Vercel AI SDK](#vercel-ai-sdk)
- [Express Middleware](#express-middleware)
- [Generic Agent Wrapper](#generic-agent-wrapper)
- [Generic Tool Wrapper](#generic-tool-wrapper)

---

## Anthropic / Claude SDK

Wrap your Anthropic client to scan all messages automatically:

```javascript
const Anthropic = require('@anthropic-ai/sdk');
const { shieldAnthropicClient } = require('agent-shield');

const client = shieldAnthropicClient(new Anthropic(), {
  blockOnThreat: true,
  sensitivity: 'medium',
  pii: true,                  // Auto-redact PII before sending to Claude
  circuitBreaker: {
    threshold: 5,             // Trip after 5 threats in window
    windowMs: 60000,          // 60-second window
  },
  onThreat: (result) => {
    console.log('Threat detected:', result.threats);
  }
});

// Use the client exactly as you normally would
const msg = await client.messages.create({
  model: 'claude-sonnet-4-20250514',
  max_tokens: 1024,
  messages: [{ role: 'user', content: userInput }],
});
```

### What Gets Scanned

- **Input messages** — all user messages are scanned before being sent to Claude
- **Output messages** — Claude's responses are scanned before being returned to you
- **Tool calls** — if Claude requests tool use, the tool name and arguments are scanned
- **PII** — if `pii: true`, PII in messages is redacted before sending

### Handling Blocked Requests

When a message is blocked, the wrapped client throws a `ShieldBlockedError`:

```javascript
try {
  const msg = await client.messages.create({ ... });
} catch (err) {
  if (err.name === 'ShieldBlockedError') {
    console.log('Blocked:', err.threats);
    return 'Your message was blocked for safety reasons.';
  }
  throw err;
}
```

### Full Example

See [`examples/anthropic-agent.js`](../examples/anthropic-agent.js) for a complete working example with tool use, canary tokens, PII redaction, and circuit breakers.

---

## OpenAI SDK

```javascript
const OpenAI = require('openai');
const { shieldOpenAIClient } = require('agent-shield');

const client = shieldOpenAIClient(new OpenAI(), {
  blockOnThreat: true,
  sensitivity: 'medium',
});

// Use normally — all chat completions are scanned
const response = await client.chat.completions.create({
  model: 'gpt-4',
  messages: [{ role: 'user', content: userInput }],
});
```

### Function Calling Protection

When using OpenAI function calling, Agent Shield scans tool arguments:

```javascript
const response = await client.chat.completions.create({
  model: 'gpt-4',
  messages: [{ role: 'user', content: userInput }],
  tools: [
    {
      type: 'function',
      function: {
        name: 'read_file',
        parameters: { type: 'object', properties: { path: { type: 'string' } } }
      }
    }
  ],
});
// Tool calls like read_file({ path: '/etc/passwd' }) are automatically flagged
```

See [`examples/openai-agent.js`](../examples/openai-agent.js) for a full working example.

---

## LangChain

Agent Shield integrates with LangChain via a callback handler:

```javascript
const { ShieldCallbackHandler } = require('agent-shield');

const handler = new ShieldCallbackHandler({
  blockOnThreat: true,
  sensitivity: 'medium',
  onThreat: ({ phase, threats }) => {
    console.log(`[${phase}] ${threats.length} threat(s) detected`);
  }
});

// Add to any LangChain chain or agent
const chain = new LLMChain({
  llm: model,
  prompt: template,
  callbacks: [handler],
});

const result = await chain.call({ input: userInput });
```

### What Gets Scanned

- **LLM inputs** — scanned in `handleLLMStart`
- **LLM outputs** — scanned in `handleLLMEnd`
- **Tool inputs** — scanned in `handleToolStart`
- **Chain inputs** — scanned in `handleChainStart`

See [`examples/langchain-agent.js`](../examples/langchain-agent.js).

---

## Vercel AI SDK

```javascript
const { shieldVercelAI } = require('agent-shield');

const shielded = shieldVercelAI(model, {
  blockOnThreat: true,
  sensitivity: 'medium',
});

// Works with generateText, streamText, etc.
const result = await generateText({
  model: shielded,
  prompt: userInput,
});
```

---

## Express Middleware

Protect your API endpoints with Express middleware:

```javascript
const express = require('express');
const { expressMiddleware } = require('agent-shield');

const app = express();
app.use(express.json());

// Add Agent Shield middleware
app.use(expressMiddleware({
  blockOnThreat: true,
  blockThreshold: 'high',
  sensitivity: 'medium',
}));

app.post('/chat', (req, res) => {
  // If we get here, the request passed security checks
  // req.agentShield contains scan results
  console.log('Scan result:', req.agentShield);

  // Process the request normally
  res.json({ response: 'Hello!' });
});
```

### What Gets Scanned

The middleware scans `req.body` (the JSON body of POST requests). If a threat is detected and blocking is enabled, it returns a `400` response automatically:

```json
{
  "error": "Request blocked by Agent Shield",
  "threats": [{ "type": "prompt_injection", "severity": "critical" }]
}
```

See [`examples/express-server.js`](../examples/express-server.js).

---

## Generic Agent Wrapper

Wrap any async function that acts as an agent:

```javascript
const { wrapAgent } = require('agent-shield');

async function myAgent(input) {
  // Your agent logic — call LLM, use tools, etc.
  return 'Agent response';
}

const protectedAgent = wrapAgent(myAgent, {
  blockOnThreat: true,
  sensitivity: 'medium',
});

// Input is scanned before myAgent runs
// Output is scanned before being returned
const result = await protectedAgent('Hello!');
```

---

## Generic Tool Wrapper

Protect all tool calls with a single wrapper:

```javascript
const { shieldTools } = require('agent-shield');

const tools = {
  bash: async (args) => exec(args.command),
  readFile: async (args) => fs.readFile(args.path, 'utf-8'),
  httpRequest: async (args) => fetch(args.url),
};

const protectedTools = shieldTools(tools, {
  blockOnThreat: true,
  dangerousTools: ['bash'],           // Extra scrutiny on these
  sensitiveFilePatterns: [/\.env$/i], // Block access to these files
});

// Tool calls are scanned before execution
const result = await protectedTools.readFile({ path: '/app/data.json' }); // OK
const blocked = await protectedTools.readFile({ path: '/app/.env' });     // Blocked
```

---

## Combining Integrations

You can use multiple integrations together:

```javascript
const shield = new AgentShield({ blockOnThreat: true });
const client = shieldAnthropicClient(new Anthropic(), { blockOnThreat: true });
const protectedTools = shieldTools(myTools, { blockOnThreat: true });

// The Anthropic wrapper scans LLM I/O
// The tool wrapper scans tool calls
// Use the shield instance for any additional manual scans
```
