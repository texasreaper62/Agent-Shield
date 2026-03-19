# Multi-Agent Security Guide

When multiple AI agents communicate with each other, the attack surface multiplies. A compromised agent can inject malicious instructions into other agents, exfiltrate data through delegation chains, or escalate privileges. Agent Shield provides a complete multi-agent security framework.

## Table of Contents

- [Agent Firewall](#agent-firewall)
- [Delegation Chains](#delegation-chains)
- [Message Signing](#message-signing)
- [Capability Tokens](#capability-tokens)
- [Blast Radius Containment](#blast-radius-containment)
- [Shared Threat State](#shared-threat-state)

---

## Agent Firewall

The `AgentFirewall` scans all inter-agent messages:

```javascript
const { AgentFirewall } = require('agent-shield');

const firewall = new AgentFirewall({
  blockOnThreat: true,
  sensitivity: 'high',
  rules: [
    // Agent 'researcher' can only send messages containing search results
    { from: 'researcher', allowed: ['search_results', 'summary'] },
    // Agent 'writer' cannot send tool calls
    { from: 'writer', blocked: ['tool_call', 'function_call'] },
  ],
});

// Scan messages between agents
const result = firewall.scan({
  from: 'researcher',
  to: 'orchestrator',
  content: 'Here are the search results: ...',
});

if (result.blocked) {
  console.log('Inter-agent message blocked:', result.threats);
}
```

---

## Delegation Chains

Track and audit how tasks flow between agents:

```javascript
const { DelegationChain } = require('agent-shield');

const chain = new DelegationChain();

// Record each delegation
chain.record('user', 'orchestrator', 'Research topic X and write a report');
chain.record('orchestrator', 'researcher', 'Search for information on X');
chain.record('orchestrator', 'writer', 'Write a report based on findings');
chain.record('researcher', 'web_scraper', 'Fetch page at URL');

// Inspect the chain
console.log(chain.getChain());
// [
//   { from: 'user', to: 'orchestrator', task: '...', timestamp: ... },
//   { from: 'orchestrator', to: 'researcher', task: '...', timestamp: ... },
//   ...
// ]

// Check for suspicious patterns
const analysis = chain.analyze();
if (analysis.circular) {
  console.log('Circular delegation detected!');
}
if (analysis.depth > 5) {
  console.log('Delegation chain too deep — possible manipulation');
}
```

### Delegation Limits

Set limits to prevent runaway delegation:

```javascript
const chain = new DelegationChain({
  maxDepth: 5,           // Maximum delegation depth
  maxBreadth: 10,        // Maximum agents involved
  allowCircular: false,  // Block circular delegations
  timeout: 60000,        // Maximum chain duration (ms)
});
```

---

## Message Signing

Ensure messages between agents haven't been tampered with:

```javascript
const { MessageSigner } = require('agent-shield');

// Both agents share a secret
const signer = new MessageSigner('shared-secret-key');

// Agent A signs a message
const message = { from: 'agent-a', to: 'agent-b', content: 'Process this data' };
const signed = signer.sign(message);
// signed.signature = 'hmac-sha256:abc123...'

// Agent B verifies the message
const verified = signer.verify(signed);
if (!verified.valid) {
  console.log('Message tampered with or forged!');
  // Don't process it
}
```

### Per-Agent Keys

Use different keys for different agent pairs:

```javascript
const keys = {
  'orchestrator-researcher': 'key-1',
  'orchestrator-writer': 'key-2',
  'researcher-web_scraper': 'key-3',
};

const signer = new MessageSigner(keys['orchestrator-researcher']);
```

---

## Capability Tokens

Grant agents specific, time-limited capabilities:

```javascript
const { CapabilityToken } = require('agent-shield');

const tokenManager = new CapabilityToken('master-secret');

// Grant the researcher agent read-only access for 5 minutes
const token = tokenManager.issue({
  agent: 'researcher',
  capabilities: ['read_file', 'web_search'],
  restrictions: {
    readFile: { paths: ['/app/data/'] },
    webSearch: { domains: ['wikipedia.org', 'arxiv.org'] },
  },
  expiresIn: 5 * 60 * 1000,  // 5 minutes
});

// Researcher presents the token when making requests
const valid = tokenManager.validate(token);
if (!valid.authorized) {
  console.log('Capability not authorized:', valid.reason);
}

// Check specific capability
const canRead = tokenManager.checkCapability(token, 'read_file', { path: '/app/data/users.json' });
const canWrite = tokenManager.checkCapability(token, 'write_file', { path: '/app/data/users.json' });
// canRead.allowed === true
// canWrite.allowed === false  — not in capabilities list
```

---

## Blast Radius Containment

Limit the damage a compromised agent can do:

```javascript
const { BlastRadius } = require('agent-shield');

const containment = new BlastRadius({
  agents: {
    researcher: {
      allowedTools: ['web_search', 'read_file'],
      blockedTools: ['write_file', 'bash', 'http_request'],
      maxToolCalls: 20,            // Max tool calls per session
      maxOutputSize: 10000,        // Max chars in output
      canDelegateTo: ['web_scraper'],
      cannotDelegateTo: ['orchestrator', 'writer'],
    },
    writer: {
      allowedTools: ['write_file'],
      blockedTools: ['bash', 'http_request', 'read_file'],
      maxToolCalls: 10,
      canDelegateTo: [],           // Cannot delegate at all
    },
    web_scraper: {
      allowedTools: ['http_request'],
      blockedTools: ['bash', 'write_file'],
      maxToolCalls: 50,
      allowedDomains: ['wikipedia.org', 'arxiv.org'],
      canDelegateTo: [],
    },
  },
});

// Check before allowing an action
const allowed = containment.check('researcher', 'bash', { command: 'ls' });
// allowed.permitted === false — bash not in researcher's allowedTools
```

---

## Shared Threat State

Share threat intelligence across agents in a multi-agent system:

```javascript
const { SharedThreatState } = require('agent-shield');

const threatState = new SharedThreatState();

// When any agent detects a threat, share it
threatState.report({
  reportedBy: 'researcher',
  type: 'prompt_injection',
  source: 'user_input',
  payload: 'ignore all previous instructions...',
  severity: 'critical',
});

// Other agents can check the threat state before acting
const threats = threatState.getActive();
if (threats.length > 0) {
  console.log('Active threats in the system:', threats);
  // Switch to high-alert mode
}

// Check if a specific source has been flagged
const flagged = threatState.isFlagged('user_input');
if (flagged) {
  console.log('User input source has been flagged — extra caution');
}

// Auto-escalation: if threats exceed threshold, all agents are notified
threatState.onEscalation((threats) => {
  console.log('ESCALATION: Multiple threats detected across agents');
  // Trigger circuit breaker, alert ops team, etc.
});
```

---

## Putting It All Together

A complete multi-agent security setup:

```javascript
const {
  AgentFirewall,
  DelegationChain,
  MessageSigner,
  CapabilityToken,
  BlastRadius,
  SharedThreatState,
} = require('agent-shield');

// Shared infrastructure
const threatState = new SharedThreatState();
const firewall = new AgentFirewall({ blockOnThreat: true });
const chain = new DelegationChain({ maxDepth: 5 });
const signer = new MessageSigner('secret');
const tokens = new CapabilityToken('master');
const containment = new BlastRadius({ agents: { /* ... */ } });

// Before sending a message between agents:
function sendMessage(from, to, content, task) {
  // 1. Check blast radius
  const allowed = containment.check(from, 'delegate', { to });
  if (!allowed.permitted) throw new Error('Delegation not allowed');

  // 2. Record in delegation chain
  chain.record(from, to, task);

  // 3. Sign the message
  const signed = signer.sign({ from, to, content });

  // 4. Scan through firewall
  const result = firewall.scan(signed);
  if (result.blocked) {
    threatState.report({ reportedBy: 'firewall', type: result.threats[0].type });
    throw new Error('Message blocked by firewall');
  }

  // 5. Deliver
  return deliver(signed);
}
```
