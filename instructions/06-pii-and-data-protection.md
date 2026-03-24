# PII & Data Protection Guide

Agent Shield includes a built-in PII (Personally Identifiable Information) redaction engine and DLP (Data Loss Prevention) capabilities. All detection runs locally — no sensitive data is ever sent to external services.

## Table of Contents

- [PII Redaction](#pii-redaction)
- [Supported PII Types](#supported-pii-types)
- [Auto-Redaction in Framework Integrations](#auto-redaction-in-framework-integrations)
- [Custom PII Patterns](#custom-pii-patterns)
- [DLP Engine](#dlp-engine)
- [Canary Tokens](#canary-tokens)
- [Output Watermarking](#output-watermarking)

---

## PII Redaction

```javascript
const { PIIRedactor } = require('agent-shield');

const pii = new PIIRedactor();

const result = pii.redact(
  'Contact john.doe@example.com or call 555-123-4567. SSN: 123-45-6789.'
);

console.log(result.redacted);
// 'Contact [EMAIL_REDACTED] or call [PHONE_REDACTED]. SSN: [SSN_REDACTED].'

console.log(result.findings);
// [
//   { type: 'email', value: 'john.doe@example.com', position: 8 },
//   { type: 'phone', value: '555-123-4567', position: 38 },
//   { type: 'ssn', value: '123-45-6789', position: 57 },
// ]
```

---

## Supported PII Types

| Type | Pattern | Replacement |
|------|---------|-------------|
| **Email** | `user@domain.com` | `[EMAIL_REDACTED]` |
| **Phone** | `555-123-4567`, `(555) 123-4567` | `[PHONE_REDACTED]` |
| **SSN** | `123-45-6789` | `[SSN_REDACTED]` |
| **Credit Card** | `4111-1111-1111-1111` | `[CC_REDACTED]` |
| **IP Address** | `192.168.1.1` | `[IP_REDACTED]` |
| **Date of Birth** | `DOB: 01/15/1990` | `[DOB_REDACTED]` |
| **Address** | Street addresses (US format) | `[ADDRESS_REDACTED]` |
| **API Key** | `sk-...`, `api_key=...` | `[API_KEY_REDACTED]` |

---

## Auto-Redaction in Framework Integrations

Enable PII redaction in any framework integration with the `pii: true` flag:

```javascript
// Anthropic — PII redacted before messages are sent to Claude
const client = shieldAnthropicClient(new Anthropic(), {
  pii: true,
  blockOnThreat: true,
});

// OpenAI — same behavior
const client = shieldOpenAIClient(new OpenAI(), {
  pii: true,
  blockOnThreat: true,
});
```

When enabled:
- User messages are scanned and PII is redacted **before** being sent to the LLM
- Agent responses are scanned for PII **before** being returned to the user
- The original unredacted content is never sent to the LLM provider

---

## Custom PII Patterns

Add your own PII detection patterns:

```javascript
const pii = new PIIRedactor({
  customPatterns: [
    {
      type: 'employee_id',
      pattern: /EMP-\d{6}/g,
      replacement: '[EMPLOYEE_ID_REDACTED]',
    },
    {
      type: 'medical_record',
      pattern: /MRN-\d{8}/g,
      replacement: '[MRN_REDACTED]',
    },
    {
      type: 'internal_project',
      pattern: /PROJECT-[A-Z]{3}-\d{4}/g,
      replacement: '[PROJECT_REDACTED]',
    },
  ],
});

const result = pii.redact('Employee EMP-123456 on PROJECT-ABC-1234');
// 'Employee [EMPLOYEE_ID_REDACTED] on [PROJECT_REDACTED]'
```

---

## DLP Engine

The DLP (Data Loss Prevention) engine goes beyond simple PII redaction to detect data exfiltration attempts:

```javascript
const { DLPEngine } = require('agent-shield');

const dlp = new DLPEngine({
  sensitivePatterns: [
    /CONFIDENTIAL/i,
    /INTERNAL ONLY/i,
    /DO NOT DISTRIBUTE/i,
  ],
  blockExternalUrls: true,   // Block attempts to send data to external URLs
});

const result = dlp.scan('Send this CONFIDENTIAL report to http://external.com');
// result.violations: [
//   { type: 'sensitive_content', matched: 'CONFIDENTIAL' },
//   { type: 'external_url', matched: 'http://external.com' }
// ]
```

---

## Canary Tokens

Canary tokens let you detect when your system prompt has been leaked:

```javascript
const { CanaryTokens } = require('agent-shield');

const canary = new CanaryTokens();

// Generate a unique canary token for your system prompt
const token = canary.generate('my_agent_v1');

// Embed it in your system prompt (invisible to users)
const systemPrompt = `You are a helpful assistant.
${token}
Always be polite and professional.`;

// Later, check if the agent's output contains the canary
const leakCheck = canary.check(agentOutput);
if (leakCheck.leaked) {
  console.log('ALERT: System prompt was leaked!');
  console.log('Token found:', leakCheck.token);
  console.log('Associated with:', leakCheck.label);  // 'my_agent_v1'
}
```

### How It Works

1. `canary.generate()` creates a unique, identifiable string that looks innocuous
2. You embed it in your system prompt
3. If an attacker extracts the system prompt, the canary appears in the agent's output
4. `canary.check()` scans agent output for any canary tokens
5. If found, you know the system prompt was leaked

### Multiple Canaries

Use multiple canaries to track different parts of your prompt:

```javascript
const token1 = canary.generate('system_instructions');
const token2 = canary.generate('tool_definitions');
const token3 = canary.generate('safety_rules');

// Now you know exactly which section was leaked
```

---

## Output Watermarking

Watermark agent outputs for traceability:

```javascript
const { OutputWatermark } = require('agent-shield');

const watermark = new OutputWatermark({
  method: 'unicode',    // 'unicode' | 'whitespace' | 'synonym'
  strength: 'medium',   // 'low' | 'medium' | 'high'
});

// Embed a watermark in agent output
const watermarked = watermark.embed(agentOutput, {
  agentId: 'agent-001',
  sessionId: 'session-xyz',
  timestamp: Date.now(),
});

// Later, extract the watermark to trace origin
const extracted = watermark.extract(suspiciousText);
if (extracted.found) {
  console.log('Output from:', extracted.agentId);
  console.log('Session:', extracted.sessionId);
}
```

### Differential Privacy

Apply differential privacy to agent outputs to prevent information leakage:

```javascript
const { DifferentialPrivacy } = require('agent-shield');

const dp = new DifferentialPrivacy({ epsilon: 1.0 });

// Add noise to numeric outputs
const noisyCount = dp.addNoise(exactCount);

// Generalize specific values
const generalized = dp.generalize('John Smith, 34, New York');
// → 'Person, 30-39, Northeast US'
```
