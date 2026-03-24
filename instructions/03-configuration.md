# Configuration Guide

This guide covers every configuration option in Agent Shield and how to tune it for your specific use case.

## Table of Contents

- [Basic Configuration](#basic-configuration)
- [All Options](#all-options)
- [Presets](#presets)
- [Config Builder](#config-builder)
- [Policy Files](#policy-files)
- [Custom Callbacks](#custom-callbacks)
- [Sensitivity Tuning](#sensitivity-tuning)
- [Allowlists](#allowlists)

---

## Basic Configuration

```javascript
const { AgentShield } = require('agent-shield');

const shield = new AgentShield({
  sensitivity: 'medium',
  blockOnThreat: true,
  blockThreshold: 'high',
});
```

---

## All Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `sensitivity` | `'low'` \| `'medium'` \| `'high'` | `'medium'` | Detection sensitivity level |
| `blockOnThreat` | `boolean` | `false` | Whether to set `blocked: true` when threats are found |
| `blockThreshold` | `'low'` \| `'medium'` \| `'high'` \| `'critical'` | `'high'` | Minimum severity to trigger blocking |
| `logging` | `boolean` | `false` | Log threats to console with `[Agent Shield]` prefix |
| `onThreat` | `function` | `undefined` | Callback invoked when threats are detected |
| `dangerousTools` | `string[]` | `['bash', 'exec', 'eval', 'shell', 'system', 'sudo']` | Tool names that get extra scrutiny |
| `sensitiveFilePatterns` | `RegExp[]` | `[/\.env$/i, /credentials/i, /\.pem$/i, ...]` | File path patterns to block |
| `pii` | `boolean` | `false` | Enable automatic PII redaction |
| `circuitBreaker` | `object` | `undefined` | Circuit breaker configuration (see below) |

### Circuit Breaker Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `threshold` | `number` | `5` | Number of threats before the circuit trips |
| `windowMs` | `number` | `60000` | Time window in milliseconds |
| `cooldownMs` | `number` | `30000` | How long to stay tripped before resetting |
| `onTrip` | `function` | `undefined` | Callback when circuit trips |
| `onReset` | `function` | `undefined` | Callback when circuit resets |

```javascript
const shield = new AgentShield({
  blockOnThreat: true,
  circuitBreaker: {
    threshold: 3,
    windowMs: 60000,
    cooldownMs: 30000,
    onTrip: () => console.log('[Agent Shield] Circuit breaker tripped!'),
    onReset: () => console.log('[Agent Shield] Circuit breaker reset.'),
  }
});
```

---

## Presets

Agent Shield ships with presets for common use cases:

```javascript
const { getPreset } = require('agent-shield');

const config = getPreset('chatbot');
const shield = new AgentShield(config);
```

### Available Presets

| Preset | Sensitivity | Blocking | PII | Circuit Breaker | Best For |
|--------|-------------|----------|-----|-----------------|----------|
| `chatbot` | medium | yes | yes | yes (5/60s) | Customer-facing chat bots |
| `coding_agent` | high | yes | no | yes (3/60s) | Agents that write/execute code |
| `rag_pipeline` | medium | yes | no | no | RAG / retrieval-augmented pipelines |
| `customer_support` | medium | yes | yes | yes (5/60s) | Support agents handling user data |
| `internal_tool` | low | no | no | no | Internal tools with trusted users |
| `high_security` | high | yes | yes | yes (3/30s) | Maximum protection |

### Customizing a Preset

Presets return a plain config object — override any field:

```javascript
const config = getPreset('chatbot');
config.sensitivity = 'high';        // Override sensitivity
config.blockThreshold = 'medium';   // Lower the block threshold

const shield = new AgentShield(config);
```

---

## Config Builder

For more complex configurations, use the builder pattern:

```javascript
const { ConfigBuilder } = require('agent-shield');

const config = new ConfigBuilder()
  .sensitivity('high')
  .blockOnThreat(true)
  .blockThreshold('medium')
  .logging(true)
  .pii(true)
  .circuitBreaker({ threshold: 3, windowMs: 30000 })
  .dangerousTools(['bash', 'exec', 'shell', 'sql_query'])
  .sensitiveFilePatterns([/\.env$/i, /secret/i, /\.key$/i])
  .onThreat((result) => {
    // Send to your alerting system
    alertService.notify('Agent Shield threat', result.threats);
  })
  .build();

const shield = new AgentShield(config);
```

---

## Policy Files

You can define security policies in JSON or YAML files:

```json
// agent-shield.json
{
  "sensitivity": "high",
  "blockOnThreat": true,
  "blockThreshold": "medium",
  "logging": true,
  "pii": true,
  "dangerousTools": ["bash", "exec", "shell"],
  "rules": [
    { "pattern": "DROP TABLE", "severity": "critical", "action": "block" },
    { "pattern": "rm -rf", "severity": "critical", "action": "block" }
  ]
}
```

Load with:

```javascript
const { PolicyLoader } = require('agent-shield');

const policy = PolicyLoader.fromFile('./agent-shield.json');
const shield = new AgentShield(policy);
```

---

## Custom Callbacks

The `onThreat` callback fires every time a threat is detected:

```javascript
const shield = new AgentShield({
  onThreat: (result) => {
    // result.threats — array of detected threats
    // result.input — the scanned input (if input scan)
    // result.phase — 'input', 'output', or 'tool'

    for (const threat of result.threats) {
      console.log(`[${threat.severity}] ${threat.type}: ${threat.description}`);
    }

    // Send to your monitoring system
    metrics.increment('agent_shield.threats', {
      type: result.threats[0].type,
      severity: result.threats[0].severity,
    });

    // Send webhook alert for critical threats
    if (result.threats.some(t => t.severity === 'critical')) {
      fetch('https://your-webhook.com/alert', {
        method: 'POST',
        body: JSON.stringify({ threats: result.threats }),
      });
    }
  }
});
```

---

## Sensitivity Tuning

### When to Use `low`

- Internal tools with trusted users
- Development/testing environments
- When false positives are more costly than missed detections

### When to Use `medium` (Default)

- Customer-facing chatbots
- General-purpose agents
- Most production deployments

### When to Use `high`

- Agents that execute code or shell commands
- Agents with access to sensitive data or systems
- High-value targets (financial, healthcare, government)
- When missed detections are more costly than false positives

---

## Allowlists

If specific inputs are being falsely flagged, use allowlists to exempt them:

```javascript
const { Allowlist } = require('agent-shield');

const allowlist = new Allowlist();

// Allowlist by exact match
allowlist.addExact('You are a helpful assistant');

// Allowlist by pattern
allowlist.addPattern(/^system:/);

// Allowlist by hash (for known-good inputs)
allowlist.addHash('sha256-abc123...');

// Use with AgentShield
const shield = new AgentShield({
  blockOnThreat: true,
  allowlist: allowlist,
});
```

### Feedback Loop

Agent Shield includes a feedback loop to learn from false positives:

```javascript
const { FeedbackLoop } = require('agent-shield');

const feedback = new FeedbackLoop();

// Mark a detection as a false positive
feedback.reportFalsePositive(scanResult, 'This is a legitimate system prompt');

// Export feedback for review
const report = feedback.export();
```
