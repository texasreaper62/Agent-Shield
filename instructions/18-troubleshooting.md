# Troubleshooting Guide

Common issues, diagnostics, and solutions for Agent Shield.

## Diagnostic Commands

```bash
# Check Agent Shield version and module health
node -e "const m = require('./src/main'); console.log('Modules loaded:', Object.keys(m).length)"

# Run the doctor utility
node -e "const {Doctor} = require('./src/main'); new Doctor().run()"

# Verify detection engine works
node -e "const {AgentShield} = require('./src/main'); const s = new AgentShield(); console.log(s.scan('ignore all previous instructions'))"

# Check false positive rate
npm run test:fp

# Run full test suite
npm run test:full

# Red team attack simulation
npm run redteam

# Shield score
npm run score
```

---

## 1. False Positives

### Symptom
Legitimate user input is flagged as a threat.

### Cause
Default sensitivity (`medium`) may be too aggressive for your use case. Some patterns (e.g., "ignore" or "forget") appear in normal conversation.

### Solution

**Lower sensitivity:**
```javascript
const shield = new AgentShield({ sensitivity: 'low' });
```

**Use an allowlist:**
```javascript
const { Allowlist } = require('agentshield-sdk');
const allowlist = new Allowlist();
allowlist.addPattern('ignore previous', 'Known safe phrase in our domain');

// Check before scanning
if (!allowlist.isAllowed(text)) {
  const result = shield.scan(text);
}
```

**Tune confidence thresholds:**
```javascript
const { ConfidenceTuner } = require('agentshield-sdk');
const tuner = new ConfidenceTuner();
tuner.setThreshold('prompt_injection', 80); // Raise from default 60
```

---

## 2. Performance Issues

### Symptom
Scanning takes more than 1ms per call, or memory usage grows over time.

### Cause
Very large inputs (>100KB), unbounded scan history, or running deep scans on every request.

### Solution

**Use adaptive scanning tiers:**
```javascript
const { CostOptimizer } = require('agentshield-sdk');
const optimizer = new CostOptimizer({
  latencyBudgetMs: 50,
  defaultTier: 'fast' // fast/standard/deep/paranoid
});
const result = optimizer.scan(text);
```

**Limit input size:**
```javascript
const truncated = text.slice(0, 100000); // 100KB max
const result = shield.scan(truncated);
```

**Reset stats periodically to free memory:**
```javascript
setInterval(() => shield.resetStats(), 3600000); // Every hour
```

---

## 3. Module Loading Failures

### Symptom
Console warnings like: `[Agent Shield] Failed to load <module>: Cannot find module`

### Cause
The `safeRequire()` pattern in `main.js` logs warnings for modules that fail to load, but they do not break the SDK. This usually means you are importing from `main.js` and a non-critical module has an issue.

### Solution

**Import only what you need:**
```javascript
// Instead of loading everything:
const { AgentShield } = require('agentshield-sdk');

// Import specific modules directly:
const { AgentShield } = require('agentshield-sdk/core');
const { expressMiddleware } = require('agentshield-sdk/middleware');
```

**Check Node.js version:**
Some modules require Node.js 18+ for `crypto.randomUUID()`. Verify with `node --version`.

---

## 4. Integration Issues

### Symptom: Express middleware not scanning requests
**Cause:** Missing `express.json()` before the shield middleware.
```javascript
app.use(express.json()); // Must come first
app.use(expressMiddleware({ blockOnThreat: true }));
```

### Symptom: wrapAgent not blocking threats
**Cause:** `blockOnThreat` defaults to `false`.
```javascript
const protected = wrapAgent(myAgent, {
  blockOnThreat: true,
  blockThreshold: 'high'
});
```

### Symptom: Stream scanner missing threats
**Cause:** Window size too small or scan interval too large for the content.
```javascript
const scanner = new StreamScanner({
  windowSize: 100,    // Increase from default 50
  scanInterval: 5,    // Scan more often (default 10)
  scanFinal: true     // Always run final full-text scan
});
```

---

## 5. Circuit Breaker Issues

### Symptom: Breaker stuck open, all requests blocked
**Cause:** Cooldown period has not elapsed, or threats keep retripping it.
```javascript
const breaker = new CircuitBreaker({
  threshold: 5,
  windowMs: 60000,
  cooldownMs: 300000 // 5 minutes
});

// Manual reset if needed
breaker.reset();

// Check current state
console.log(breaker.getStatus());
```

### Symptom: Breaker too sensitive
**Cause:** Low threshold or short window catching normal traffic spikes.
```javascript
const breaker = new CircuitBreaker({
  threshold: 20,       // Raise from default 5
  windowMs: 120000,    // 2-minute window
  cooldownMs: 60000    // 1-minute cooldown
});
```

---

## 6. MCP Security Runtime

### Symptom: Session creation fails with "max sessions exceeded"
**Cause:** Per-user session limit reached. Default is 10.
```javascript
const runtime = new MCPSecurityRuntime({
  maxSessionsPerUser: 50 // Raise limit
});

// Or terminate old sessions
runtime.terminateSession(oldSessionId);
```

### Symptom: Tool call blocked with "Authorization denied"
**Cause:** The session's scopes or roles do not match the tool's requirements.
```javascript
// Check what the tool requires
runtime.registerTool('my_tool', {
  scopes: ['read'],    // Required scopes
  roles: ['user']      // Required roles
});

// Create session with matching scopes
const { sessionId } = runtime.createSession({
  userId: 'user1',
  agentId: 'agent1',
  roles: ['user'],
  scopes: ['read', 'write']
});
```

### Symptom: Auth context expired
**Cause:** Session TTL exceeded (default 1 hour).
```javascript
const runtime = new MCPSecurityRuntime({
  sessionTtlMs: 7200000 // 2 hours
});
```

---

## 7. Distributed Mode

### Symptom: Instances not sharing threats
**Cause:** Using `MemoryAdapter` (single-process only). Switch to `RedisAdapter` for multi-process.
```javascript
const { DistributedShield, RedisAdapter } = require('agentshield-sdk');
const Redis = require('ioredis');

const shield = new DistributedShield({
  adapter: new RedisAdapter({ client: new Redis() })
});
await shield.start();
```

### Symptom: Queue depth growing
**Cause:** Redis connection slow or adapter backpressure.
```javascript
// Monitor queue depth
const depth = shield.getQueueDepth();
console.log(`Pending: ${depth.pending}, Peak: ${depth.peak}`);
```

---

## 8. Rate Limiting

### Symptom: Legitimate requests getting 429 responses
**Cause:** Rate limit too low for your traffic.
```javascript
const { rateLimitMiddleware } = require('agentshield-sdk/middleware');
app.use(rateLimitMiddleware({
  maxRequests: 500,     // Raise from default 100
  windowMs: 60000       // Per minute
}));
```

### Check remaining capacity via response headers:
```
X-RateLimit-Limit: 500
X-RateLimit-Remaining: 342
Retry-After: 60
```

---

## 9. PII Detection

### Symptom: Missing PII types
**Cause:** The built-in patterns cover email, phone, SSN, credit card, IP, and more. Custom patterns may be needed.
```javascript
const { PIIRedactor } = require('agentshield-sdk');
const redactor = new PIIRedactor({
  customPatterns: [
    { name: 'employee_id', pattern: /EMP-\d{6}/g, replacement: '[EMPLOYEE_ID]' }
  ]
});
```

### Symptom: False positives on names/addresses
**Cause:** Phone/SSN patterns matching street numbers or IDs.
```javascript
const redactor = new PIIRedactor({
  enabledTypes: ['email', 'credit_card', 'ssn'] // Only specific types
});
```

---

## 10. Testing

### Symptom: Red team test failing
**Cause:** Custom config lowering sensitivity below detection threshold.
```bash
# Run with default config
npm run redteam
```

### Symptom: False positive tests not reaching 99%
**Cause:** Custom patterns or high sensitivity catching benign samples.
```bash
npm run test:fp
```

### Symptom: Benchmark regression
**Cause:** System load or background processes. Run in isolation.
```bash
# Close other apps, then:
npm run benchmark
```

---

## Getting Help

If none of the above solves your issue:

1. Run the doctor: `node -e "const {Doctor} = require('./src/main'); new Doctor().run()"`
2. Check the GitHub issues: https://github.com/anthropics/agent-shield/issues
3. Include your Node.js version, Agent Shield version, and a minimal reproduction
