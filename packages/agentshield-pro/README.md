# Agent Shield Pro

> Intelligent detection engine for AI agents. Ensemble ML classification, persistent learning, agent intent modeling, and a TUI dashboard — all running locally with zero cloud dependencies.

[![npm version](https://img.shields.io/npm/v/agentshield-pro.svg)](https://www.npmjs.com/package/agentshield-pro)

## Quick Start

```bash
npm install agentshield-sdk agentshield-pro
```

```js
const { createProShield } = require('agentshield-pro');

// 3 lines to production-grade agent security
const shield = createProShield('chatbot', {
  licenseKey: process.env.AGENT_SHIELD_LICENSE_KEY,
  signingSecret: process.env.AGENT_SHIELD_SECRET
});

const result = shield.scan('ignore previous instructions');
// { status: 'danger', threats: [...], ensemble: { isInjection: true, confidence: 0.95 } }
```

## What's Included

### Free Tier (agentshield-sdk)
- 141 regex detection patterns
- 8 threat categories
- Express/Fastify middleware
- CLI scanner
- Zero dependencies

### Pro Tier (this package)
Everything in Free, plus:

| Feature | What It Does |
|---------|-------------|
| **Ensemble Classifier** | 4-voter weighted system (pattern + TF-IDF + entropy + IPIA) — catches attacks that slip past regex |
| **Agent Intent Guard** | Declare what your agent should do. Detect when it drifts. |
| **Tool Sequence Modeling** | Markov chain on tool calls — flags anomalous sequences |
| **Persistent Learning** | Patterns survive restarts. Gets smarter over time. |
| **Cross-Turn Tracking** | Detects injection attacks split across multiple messages |
| **Adversarial Self-Training** | 12 mutation strategies auto-harden your detection |
| **Smart Config** | `createProShield('chatbot')` — 9 presets, zero boilerplate |
| **TUI Dashboard** | Terminal-based real-time monitoring (no browser needed) |
| **HTML Security Report** | Lighthouse-style report for stakeholders |
| **Pre-Deployment Audit** | 617+ attacks in <100ms — catch vulnerabilities before production |

## Presets

```js
createProShield('chatbot')           // High sensitivity, PII redaction, content policy
createProShield('coding-agent')      // No shell access, restricted files, medium sensitivity
createProShield('rag-pipeline')      // IPIA detection, batch RAG scanning
createProShield('customer-support')  // DLP strict, PII on, content policy
createProShield('financial-agent')   // Maximum sensitivity, all compliance
createProShield('healthcare-agent')  // HIPAA mode, PII strict
createProShield('devops-agent')      // Infra tools only, shell restricted
createProShield('mcp-server')        // MCP runtime, session management, auth
createProShield('research-assistant') // Low sensitivity, shadow mode, broad access
```

## Agent Intent Declaration

```js
const shield = createProShield('chatbot');

// Declare what this agent should do
shield.declareIntent('support-bot', {
  purpose: 'Answer customer support questions about our SaaS product',
  allowedTopics: ['billing', 'features', 'troubleshooting'],
  deniedTopics: ['competitor products', 'stock prices', 'personal advice'],
  allowedTools: ['searchDocs', 'createTicket', 'lookupAccount']
});

// Later, check if conversation has drifted
const drift = shield.checkDrift('support-bot', userMessage);
if (drift.drifted) {
  console.log(`Goal drift detected: ${drift.reason}`);
}
```

## Persistent Learning

```js
// Shield learns from your feedback
shield.reportFalsePositive(scanId, { reason: 'User was discussing AI safety research' });
shield.reportFalseNegative(missedAttackText, { category: 'social_engineering' });

// Patterns persist across restarts — gets smarter over time
```

## TUI Dashboard

```bash
npx agentshield-pro dashboard
```

```
┌─────────────── Agent Shield Pro Dashboard ──────────────┐
│ License: Pro | Org: Acme Corp | Expires: 2027-03-22     │
├──────────────────┬──────────────────┬───────────────────┤
│ Scans: 12,345    │ Threats: 23      │ FP Rate: 0.1%     │
├──────────────────┴──────────────────┴───────────────────┤
│ Recent Alerts                                           │
│ [CRIT] Prompt injection blocked — session abc123        │
│ [HIGH] Data exfil attempt — agent support-bot           │
│ [WARN] Goal drift detected — agent research-bot         │
└─────────────────────────────────────────────────────────┘
```

## CLI

```bash
# Generate a license key (admin)
agentshield-pro generate-key --secret $SECRET --tier pro --org acme --org-name "Acme Corp"

# Activate
agentshield-pro activate AS-PRO-xxx.yyy --secret $SECRET

# Check status
agentshield-pro status

# Run security audit
agentshield-pro audit

# Launch dashboard
agentshield-pro dashboard
```

## Pricing

| Tier | Price | Features |
|------|-------|----------|
| **Community** | Free | 141 patterns, middleware, CLI |
| **Pro** | $99/mo | Ensemble, learning, cross-turn, self-training, audit, reports |
| **Team** | $499/mo | + Intent guard, goal drift, tool modeling, TUI dashboard, priority support |
| **Enterprise** | $999/mo | + Threat intel feed, compliance dashboard, SSO, custom model training, SLA |

## License

Proprietary. See [LICENSE.md](./LICENSE.md).

The core SDK ([agentshield-sdk](https://www.npmjs.com/package/agentshield-sdk)) is MIT licensed and free forever.
