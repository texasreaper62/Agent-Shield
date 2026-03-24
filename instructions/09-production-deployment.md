# Production Deployment Guide

This guide covers everything you need to deploy Agent Shield in production — monitoring, compliance, enterprise features, performance tuning, and operational best practices.

## Table of Contents

- [Production Checklist](#production-checklist)
- [Recommended Configuration](#recommended-configuration)
- [Monitoring & Alerting](#monitoring--alerting)
- [Compliance Reporting](#compliance-reporting)
- [Audit Trail](#audit-trail)
- [Enterprise Features](#enterprise-features)
- [Performance Tuning](#performance-tuning)
- [Shadow Mode](#shadow-mode)
- [Graceful Degradation](#graceful-degradation)

---

## Production Checklist

Before going live, verify:

- [ ] `blockOnThreat: true` — threats are blocked, not just logged
- [ ] `sensitivity` is set appropriately for your use case
- [ ] `onThreat` callback is configured to send alerts
- [ ] False positive testing complete — legitimate inputs are not blocked
- [ ] Red team simulation passing — `npm run redteam`
- [ ] Shield score at acceptable level — `npm run score`
- [ ] Circuit breaker configured to prevent sustained attacks
- [ ] PII redaction enabled if handling personal data
- [ ] Tool permissions configured if agent uses tools
- [ ] Audit trail enabled for compliance
- [ ] Monitoring dashboards set up

---

## Recommended Configuration

```javascript
const { AgentShield } = require('agent-shield');

const shield = new AgentShield({
  // Detection
  sensitivity: 'medium',
  blockOnThreat: true,
  blockThreshold: 'high',

  // Logging
  logging: true,

  // PII protection
  pii: true,

  // Circuit breaker
  circuitBreaker: {
    threshold: 5,
    windowMs: 60000,
    cooldownMs: 30000,
    onTrip: () => {
      alertOps('Circuit breaker tripped — possible attack in progress');
    },
  },

  // Alerting
  onThreat: (result) => {
    metrics.increment('agent_shield.threats_detected');
    metrics.tag('severity', result.threats[0].severity);

    if (result.threats.some(t => t.severity === 'critical')) {
      alertOps('Critical threat detected', result);
    }
  },
});
```

---

## Monitoring & Alerting

### Structured Logging

```javascript
const { StructuredLogger } = require('agent-shield');

const logger = new StructuredLogger({
  format: 'json',          // 'json' | 'text'
  destination: 'stdout',   // 'stdout' | 'file' | custom function
  includeInput: false,     // Don't log raw inputs (privacy)
  includeTimestamp: true,
});

const shield = new AgentShield({
  logger: logger,
  logging: true,
});

// Output:
// {"timestamp":"2026-03-19T12:00:00Z","level":"warn","type":"prompt_injection","severity":"critical","blocked":true}
```

### Webhook Alerts

```javascript
const { WebhookNotifier } = require('agent-shield');

const webhook = new WebhookNotifier({
  url: 'https://hooks.slack.com/services/...',  // Or any webhook URL
  minSeverity: 'high',  // Only alert on 'high' and 'critical'
  rateLimit: {
    max: 10,             // Max 10 alerts
    windowMs: 60000,     // Per minute
  },
});

const shield = new AgentShield({
  onThreat: (result) => webhook.notify(result),
});
```

### Metrics

Extract metrics from Agent Shield for your monitoring stack:

```javascript
const shield = new AgentShield({ blockOnThreat: true });

// After processing requests, get stats
const stats = shield.getStats();
console.log(stats);
// {
//   totalScans: 15420,
//   threatsDetected: 23,
//   threatsBlocked: 23,
//   falsePositives: 0,
//   avgScanTimeMs: 0.02,
//   circuitBreakerTrips: 1,
//   topThreatTypes: { prompt_injection: 15, data_exfiltration: 5, tool_abuse: 3 },
// }

// Feed into Prometheus, Datadog, CloudWatch, etc.
```

---

## Compliance Reporting

Generate compliance reports for security audits:

```javascript
const { ComplianceReporter } = require('agent-shield');

const reporter = new ComplianceReporter();

// Generate framework-specific reports
const soc2 = reporter.generateReport('SOC2');
const owasp = reporter.generateReport('OWASP');
const nist = reporter.generateReport('NIST');
const euAiAct = reporter.generateReport('EU_AI_Act');
const hipaa = reporter.generateReport('HIPAA');
const gdpr = reporter.generateReport('GDPR');

console.log(soc2);
// {
//   framework: 'SOC2',
//   controls: [
//     { id: 'CC6.1', name: 'Logical Access Security', status: 'compliant', evidence: '...' },
//     ...
//   ],
//   overallStatus: 'compliant',
//   generatedAt: '2026-03-19T12:00:00Z',
// }
```

---

## Audit Trail

Maintain a complete audit trail of all scans:

```javascript
const { AuditTrail } = require('agent-shield');

const audit = new AuditTrail({
  retention: '90d',        // Keep logs for 90 days
  storage: 'memory',       // 'memory' | 'file' | custom adapter
  hashInputs: true,        // Store hashed inputs instead of raw (privacy)
});

const shield = new AgentShield({
  audit: audit,
  blockOnThreat: true,
});

// Query the audit trail
const recentThreats = audit.query({
  from: new Date('2026-03-01'),
  to: new Date(),
  severity: ['critical', 'high'],
});

// Export for compliance
const export_ = audit.export('csv');
```

---

## Enterprise Features

### Multi-Tenant Isolation

Run separate shield instances per tenant:

```javascript
const { MultiTenantShield } = require('agent-shield');

const multiTenant = new MultiTenantShield({
  tenants: {
    'tenant-a': { sensitivity: 'high', blockOnThreat: true },
    'tenant-b': { sensitivity: 'medium', blockOnThreat: true },
    'tenant-c': { sensitivity: 'low', blockOnThreat: false },
  },
});

// Scans are isolated per tenant
const result = multiTenant.scanInput('tenant-a', userInput);
```

### Role-Based Access Control (RBAC)

```javascript
const { RBAC } = require('agent-shield');

const rbac = new RBAC({
  roles: {
    admin: { canModifyConfig: true, canViewAudit: true, canBypassBlock: true },
    operator: { canModifyConfig: false, canViewAudit: true, canBypassBlock: false },
    viewer: { canModifyConfig: false, canViewAudit: true, canBypassBlock: false },
  },
});

// Check permissions
const allowed = rbac.check('operator', 'canModifyConfig');
// false
```

### Debug Mode

For troubleshooting in staging/development:

```javascript
const { DebugMode } = require('agent-shield');

const debug = new DebugMode({
  enabled: process.env.NODE_ENV !== 'production',
  verbose: true,          // Log every pattern check
  explainDecisions: true, // Explain why each decision was made
});

const shield = new AgentShield({
  debug: debug,
});

// Debug output:
// [Agent Shield DEBUG] Scanning input (42 chars)
// [Agent Shield DEBUG] Pattern 'ignore_instructions' → NO MATCH
// [Agent Shield DEBUG] Pattern 'fake_system_prompt' → MATCH (severity: critical)
// [Agent Shield DEBUG] Decision: BLOCK (1 threat, max severity: critical)
```

---

## Performance Tuning

Agent Shield is already fast (~48,000 scans/sec), but for extreme throughput:

### Sampling Mode

Scan a percentage of requests instead of all:

```javascript
const { SamplingScanner } = require('agent-shield');

const scanner = new SamplingScanner({
  sampleRate: 0.1,         // Scan 10% of requests
  alwaysScanFirst: 100,    // Always scan the first 100 requests (warmup)
  escalateOnThreat: true,  // If a threat is found, switch to 100% for 5 minutes
});
```

### Scan Caching

Cache results for repeated inputs:

```javascript
const { ScanCache } = require('agent-shield');

const cache = new ScanCache({
  maxSize: 10000,          // Cache up to 10,000 results
  ttl: 300000,             // Cache for 5 minutes
});

const shield = new AgentShield({
  cache: cache,
});
```

---

## Shadow Mode

Run Agent Shield in shadow mode to evaluate without blocking:

```javascript
const { ShadowMode } = require('agent-shield');

const shadow = new ShadowMode({
  // Run two configurations side by side
  primary: { sensitivity: 'medium', blockOnThreat: true },
  shadow: { sensitivity: 'high', blockOnThreat: true },
  // Compare results
  onDifference: (primary, shadow, input) => {
    console.log('Configs disagree:', {
      primaryBlocked: primary.blocked,
      shadowBlocked: shadow.blocked,
    });
  },
});
```

This lets you test a new configuration against production traffic without affecting users.

---

## Graceful Degradation

Handle errors in Agent Shield without breaking your agent:

```javascript
const { GracefulScanner } = require('agent-shield');

const scanner = new GracefulScanner({
  fallbackOnError: 'allow',  // 'allow' | 'block' — what to do if scanning fails
  timeout: 100,              // Max scan time in ms before fallback
  onError: (err) => {
    console.error('[Agent Shield] Scanner error:', err.message);
    metrics.increment('agent_shield.errors');
  },
});

// Even if Agent Shield encounters an error, your agent keeps running
const result = scanner.scan(input);
// result.fallback === true if an error occurred
```
