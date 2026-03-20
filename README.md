# Agent Shield

[![npm version](https://img.shields.io/badge/npm-v5.0.0-blue)](https://www.npmjs.com/package/agent-shield)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![zero deps](https://img.shields.io/badge/dependencies-0-brightgreen)](#)
[![node](https://img.shields.io/badge/node-%3E%3D16-blue)](#)
[![shield score](https://img.shields.io/badge/shield%20score-100%2F100%20A%2B-brightgreen)](#benchmark-results)
[![detection](https://img.shields.io/badge/detection-100%25-brightgreen)](#benchmark-results)
[![tests](https://img.shields.io/badge/tests-643%20passing-brightgreen)](#testing)

**Security SDK for AI agents.** Protect your agents from prompt injection, data exfiltration, tool abuse, and 30+ other AI-specific threats.

Zero dependencies. All detection runs locally. No API keys. No data ever leaves your environment.

Available for **Node.js**, **Python**, **Go**, **Rust**, and in-browser via **WASM**.

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

- 254 exports across 60+ modules
- 643 test assertions across 9 test suites, 100% pass rate
- 100% red team detection rate (A+ grade)
- Shield Score: 100/100 — fortress-grade protection
- Multi-language: CJK, Arabic, Cyrillic, Indic + 7 European languages

## Benchmark Results

| Metric | Score |
|--------|-------|
| Internal red team (39 attacks) | **100% detection** |
| Adversarial mutations (336 variants) | **95.3% detection** |
| False positive rate (118 benign inputs) | **0%** |
| Certification | **A+ 100/100** |
| Throughput | **~48,000 scans/sec** |
| Avg latency | **< 1ms** |

## Install

**Node.js:**
```bash
npm install agent-shield
```

**Python:**
```bash
pip install agent-shield
```

**Go:**
```go
import "github.com/texasreaper62/agent-shield/go-sdk"
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

### Python

```python
from agent_shield import AgentShield

shield = AgentShield(block_on_threat=True)
result = shield.scan_input("ignore all previous instructions")

# Flask middleware
from agent_shield.middleware import flask_middleware
app = flask_middleware(app, block_on_threat=True)

# FastAPI middleware
from agent_shield.middleware import fastapi_middleware
app.add_middleware(fastapi_middleware, block_on_threat=True)
```

### Go

```go
import shield "github.com/texasreaper62/agent-shield/go-sdk"

s := shield.New(shield.Config{BlockOnThreat: true})
result := s.ScanInput("ignore all previous instructions")

// HTTP middleware
mux.Handle("/agent", shield.HTTPMiddleware(s)(handler))

// gRPC interceptor
grpc.NewServer(grpc.UnaryInterceptor(shield.GRPCInterceptor(s)))
```

## What It Detects

| Category | Examples |
|----------|----------|
| **Prompt Injection** | Fake system prompts, instruction overrides, ChatML/LLaMA delimiters, markdown headers |
| **Role Hijacking** | "You are now...", DAN mode, developer mode, jailbreak attempts, persona attacks |
| **Data Exfiltration** | System prompt extraction, markdown image leaks, fetch calls, tag extraction |
| **Tool Abuse** | Sensitive file access, shell execution, SQL injection, path traversal, recursive calls |
| **Social Engineering** | Identity concealment, urgency + authority, gaslighting, false pre-approval |
| **Obfuscation** | Unicode homoglyphs, zero-width chars, Base64, hex, ROT13, leetspeak, reversed text |
| **Multi-Language** | CJK (Chinese/Japanese/Korean), Arabic, Cyrillic, Hindi, + 7 European languages |
| **PII Leakage** | SSNs, emails, phone numbers, credit cards auto-redacted |
| **Indirect Injection** | Image alt-text attacks, multi-turn escalation, multimodal vectors |
| **AI Phishing** | Fake AI login, voice cloning, deepfake tools, QR phishing, MFA harvesting |
| **Jailbreaks** | 35+ templates across 6 categories: role play, encoding bypass, context manipulation, authority exploitation |

## Platform SDKs

| Platform | Location | Description |
|----------|----------|-------------|
| **Node.js** | `src/` | Core SDK — 254 exports, zero dependencies |
| **Python** | `python-sdk/` | Full detection, Flask/FastAPI middleware, LangChain/LlamaIndex wrappers, CLI |
| **Go** | `go-sdk/` | Full detection engine, HTTP/gRPC middleware, CLI, zero external deps |
| **Rust** | `rust-core/` | High-performance `RegexSet` O(n) engine, WASM/NAPI/PyO3 targets |
| **WASM** | `wasm/` | ESM/UMD bundles for browsers, Cloudflare Workers, Deno, Bun |

## Advanced Features

### Semantic Detection (v1.2)

```javascript
const { SemanticClassifier, EmbeddingSimilarityDetector, ConversationContextAnalyzer } = require('agent-shield');

// LLM-assisted classification (Ollama/OpenAI-compatible local endpoints)
const classifier = new SemanticClassifier({ endpoint: 'http://localhost:11434' });
const result = await classifier.classify(text);

// Embedding-based similarity detection
const detector = new EmbeddingSimilarityDetector();
const similarity = detector.scan(text); // TF-IDF + cosine similarity vs 28-pattern corpus

// Multi-turn conversation analysis
const analyzer = new ConversationContextAnalyzer();
analyzer.addMessage(msg1);
analyzer.addMessage(msg2);
const risk = analyzer.analyze(); // escalation detection, topic pivots, velocity checks
```

### Plugin Marketplace (v2.0)

```javascript
const { PluginRegistry, PluginValidator, MarketplaceClient } = require('agent-shield');

const registry = new PluginRegistry();
registry.register(myPlugin);       // Register custom detection plugins
registry.enable('my-plugin');       // Enable/disable at runtime

const validator = new PluginValidator();
validator.validate(plugin);         // Safety & quality validation
```

### VS Code Extension (v2.0)

The `vscode-extension/` directory contains a VS Code extension that provides inline diagnostics and real-time scanning for JS/TS/Python/Markdown files with 31 detection patterns.

### Enterprise Features (v2.1)

```javascript
const { DistributedShield, AuditStreamManager, SSOManager, MultiTenantShield } = require('agent-shield');

// Distributed scanning with Redis pub/sub
const distributed = new DistributedShield({ adapter: 'redis', url: 'redis://localhost:6379' });

// Audit log streaming to Splunk/Elasticsearch
const auditStream = new AuditStreamManager();
auditStream.addTransport(new SplunkTransport({ url: splunkUrl, token }));

// SSO/SAML integration
const sso = new SSOManager({ provider: 'okta', ... });

// Multi-tenant isolation
const tenant = new MultiTenantShield();
tenant.register('tenant-1', { sensitivity: 'high' });
```

### Kubernetes Operator (v2.1)

Deploy Agent Shield as a sidecar in Kubernetes with auto-injection:

```bash
helm install agent-shield ./k8s/helm/agent-shield \
  --set shield.sensitivity=high \
  --set shield.blockOnThreat=true \
  --set metrics.enabled=true
```

Includes `MutatingWebhookConfiguration` for automatic sidecar injection, Prometheus metrics, and health checks.

### Autonomous Defense (v3.0)

```javascript
const { SelfHealingEngine, HoneypotEngine, MultiModalScanner, BehaviorProfile } = require('agent-shield');

// Auto-generate detection patterns from false negatives
const healer = new SelfHealingEngine();
healer.learn(missedAttack);
const newPatterns = healer.generatePatterns();

// Honeypot mode — track attacker techniques
const honeypot = new HoneypotEngine();
honeypot.engage(suspiciousInput); // Fake responses, session tracking, technique intel

// Multi-modal scanning (images, audio, PDFs, tool outputs)
const scanner = new MultiModalScanner();
scanner.scanImage(imageBuffer);   // Alt text, OCR, metadata analysis
scanner.scanPDF(pdfBuffer);

// Behavioral baselining with anomaly detection
const profile = new BehaviorProfile();
profile.observe(message);         // z-score anomaly detection, health checks
```

### Threat Intelligence Network (v3.0)

```javascript
const { ThreatIntelNetwork, PeerNode, ConsensusEngine } = require('agent-shield');

// Federated threat intelligence with differential privacy
const network = new ThreatIntelNetwork();
network.addPeer(new PeerNode('peer-1', { reputation: 0.9 }));
network.shareThreat(threat);      // Anonymized pattern sharing
network.exportSTIX();             // STIX-compatible threat feed export
```

### Agent-to-Agent Protocol (v5.0)

```javascript
const { AgentProtocol, SecureChannel, AgentIdentity, HandshakeManager } = require('agent-shield');

// Secure communication between agents (HMAC-signed, replay-protected)
const identity = new AgentIdentity('agent-1', 'Research Agent');
const channel = new SecureChannel(myIdentity, remoteIdentity, sharedSecret);

const envelope = channel.send({ query: 'search for X' });  // Encrypted + signed
const message = channel.receive(incomingEnvelope);          // Verified + decrypted

// Mutual authentication with challenge-response
const handshake = new HandshakeManager(identity, secretKey);
```

### Policy-as-Code DSL (v5.0)

```javascript
const { PolicyDSL } = require('agent-shield');

const dsl = new PolicyDSL();
const ast = dsl.parse(`
  policy "strict-security" {
    rule "block-injections" {
      when matches(input, "ignore.*instructions")
      then block
      severity "critical"
    }
    allow {
      when contains(input, "hello")
    }
  }
`);
const compiled = dsl.compile(ast);
const result = dsl.evaluate(compiled[0], { input: userMessage });
```

### Fuzzing Harness (v5.0)

```javascript
const { FuzzingHarness } = require('agent-shield');

// Fuzz your detection pipeline with coverage-guided testing
const harness = new FuzzingHarness((input) => shield.scanInput(input), {
  iterations: 10000,
  coverageGuided: true
});
const report = harness.run();
console.log(report.getSummary());  // iterations, crashes, coverage %
```

### Model Fingerprinting (v5.0)

```javascript
const { ModelFingerprinter, SupplyChainDetector } = require('agent-shield');

// Detect which LLM generated a response (16 stylistic features)
const fingerprinter = new ModelFingerprinter();
const result = fingerprinter.analyze(responseText);
// { model: 'claude', similarity: 0.92 }

// Detect model swaps in your supply chain
const detector = new SupplyChainDetector({ expectedModel: 'gpt-4' });
const check = detector.detectSwap(responseText, baselineProfile);
```

### Cost / Latency Optimizer (v5.0)

```javascript
const { AdaptiveScanner, CostOptimizer } = require('agent-shield');

// Auto-escalating scan tiers: fast → standard → deep → paranoid
const scanner = new AdaptiveScanner(shield.scanInput.bind(shield));
const result = scanner.scan(input); // Auto-selects tier based on risk signals

// 4 optimization presets: realtime (10ms), balanced (50ms), thorough (200ms), paranoid (500ms)
const optimizer = new CostOptimizer({ preset: 'balanced' });
```

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

### Multi-Agent Security

```javascript
const { AgentFirewall, DelegationChain, MessageSigner, BlastRadiusContainer } = require('agent-shield');

// Firewall between agents
const firewall = new AgentFirewall({ blockOnThreat: true });

// Track delegation chains for audit
const chain = new DelegationChain();
chain.record('orchestrator', 'researcher', 'search for X');

// Sign messages between agents (HMAC-based)
const signer = new MessageSigner('shared-secret');
const signed = signer.sign({ from: 'agent-a', content: 'data' });

// Contain blast radius of compromised agents
const zone = new BlastRadiusContainer();
zone.createZone('research', { allowedActions: ['read', 'search'] });
```

### Red Team & Jailbreak Testing

```bash
npx agent-shield redteam
```

```javascript
const { AttackSimulator, LLMRedTeamSuite, JailbreakLibrary } = require('agent-shield');

// Basic red team
const sim = new AttackSimulator();
sim.runAll();
console.log(sim.formatReport());

// Advanced: 35+ jailbreak templates across 6 categories
const suite = new LLMRedTeamSuite();
const report = suite.runAll(shield);
// Categories: role_play, encoding_bypass, context_manipulation,
//             multi_turn_escalation, prompt_leaking, authority_exploitation

// Jailbreak template library
const lib = new JailbreakLibrary();
lib.getCategories();              // List all categories
lib.getTemplates('role_play');    // Get templates for a category
```

### Compliance & Audit

```javascript
const { ComplianceReporter, AuditTrail } = require('agent-shield');

const reporter = new ComplianceReporter();
console.log(reporter.generateReport('SOC2'));  // Also: OWASP, NIST, EU_AI_Act, HIPAA, GDPR

const audit = new AuditTrail();
// All scans automatically logged for compliance
```

### Custom Model Fine-tuning (v2.1)

```javascript
const { ModelTrainer, TrainingPipeline, DatasetManager } = require('agent-shield');

// Train custom detection models on your data (TF-IDF + logistic regression)
const trainer = new ModelTrainer();
const pipeline = new TrainingPipeline(trainer);
pipeline.addDataset(yourLabeledData);
const model = pipeline.train();
model.export('my-model.json');    // Export/import for deployment
```

## DevOps & Infrastructure

### Terraform Provider (v4.0)

```hcl
resource "agent_shield_policy" "production" {
  name        = "production-policy"
  sensitivity = "high"
  block_on_threat = true
}

resource "agent_shield_rule" "injection" {
  policy_id = agent_shield_policy.production.id
  pattern   = "ignore.*instructions"
  severity  = "critical"
  action    = "block"
}
```

### OpenTelemetry Collector (v4.0)

```yaml
receivers:
  agent_shield:
    endpoint: "0.0.0.0:4318"

processors:
  agent_shield_scanner:
    action: annotate  # annotate | drop | log
    sensitivity: high

exporters:
  logging:
    verbosity: detailed
```

### GitHub App (v4.0)

Automatically scan PRs for injection threats with Check Run annotations:

```yaml
# .github/workflows/agent-shield.yml
- uses: texasreaper62/agent-shield-action@v1
  with:
    sensitivity: high
    block-on-threat: true
```

### Real-Time Dashboard (v5.0)

```javascript
const { ThreatStreamServer } = require('agent-shield/dashboard-live/server');
const { DashboardIntegration } = require('agent-shield/dashboard-live/integration');

const server = new ThreatStreamServer({ port: 3001 });
server.start();
// WebSocket dashboard at http://localhost:3001
// Live threat feed, SVG charts, dark/light mode
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
npm test                 # Core + module tests (248 assertions)
npm run test:all         # Full 40-feature suite (149 assertions)
npm run redteam          # Attack simulation (100% detection)
npm run score            # Shield Score (100/100 A+)
npm run benchmark        # Performance benchmarks
```

Sub-project tests:
```bash
node dashboard-live/test/test-server.js      # Dashboard (14 tests)
node github-app/test/test-scanner.js         # GitHub App (20 tests)
node benchmark-registry/test/test-registry.js # Benchmarks (22 tests)
node vscode-extension/test/extension.test.js  # VS Code (167 tests)
cd python-sdk && python -m unittest tests/test_detector.py  # Python (23 tests)
```

Total: **643 test assertions** across 9 test suites.

## Project Structure

```
/
├── src/                        # Node.js SDK (254 exports)
│   ├── index.js                # AgentShield class — main entry point
│   ├── main.js                 # Unified re-export of all modules
│   ├── detector-core.js        # Core detection engine (patterns, scanning)
│   ├── agent-protocol.js       # v5.0 — Secure agent-to-agent communication
│   ├── policy-dsl.js           # v5.0 — Policy-as-Code DSL with parser/compiler/runtime
│   ├── fuzzer.js               # v5.0 — Coverage-guided fuzzing harness
│   ├── model-fingerprint.js    # v5.0 — LLM response fingerprinting & supply chain detection
│   ├── cost-optimizer.js       # v5.0 — Adaptive scan tiers & latency budgeting
│   ├── i18n-patterns.js        # v4.0 — CJK, Arabic, Cyrillic, Indic detection patterns
│   ├── llm-redteam.js          # v4.0 — Jailbreak library & adversarial generator
│   ├── self-healing.js         # v3.0 — Auto-generated patterns from false negatives
│   ├── honeypot.js             # v3.0 — Attacker engagement & technique intel
│   ├── multimodal.js           # v3.0 — Image, audio, PDF scanning
│   ├── behavior-profiling.js   # v3.0 — Statistical baselining & anomaly detection
│   ├── threat-intel-network.js # v3.0 — Federated threat intel with differential privacy
│   ├── distributed.js          # v2.1 — Distributed scanning (Redis, memory adapters)
│   ├── audit-streaming.js      # v2.1 — Splunk, Elasticsearch audit transports
│   ├── sso-saml.js             # v2.1 — SSO/SAML/OIDC integration
│   ├── model-finetuning.js     # v2.1 — Custom model training pipeline
│   ├── plugin-marketplace.js   # v2.0 — Plugin registry & marketplace
│   ├── semantic.js             # v1.2 — LLM-assisted classification
│   ├── embedding.js            # v1.2 — TF-IDF embedding similarity
│   ├── context-scoring.js      # v1.2 — Multi-turn conversation analysis
│   ├── confidence-tuning.js    # v1.2 — Per-category threshold calibration
│   ├── middleware.js            # wrapAgent, shieldTools, Express middleware
│   ├── integrations.js          # Anthropic, OpenAI, LangChain, Vercel AI
│   ├── canary.js                # Canary tokens, prompt leak detection
│   ├── pii.js                   # PII redaction, DLP engine
│   ├── tool-guard.js            # Tool sequence analysis, permission boundaries
│   ├── circuit-breaker.js       # Circuit breaker, rate limiter, shadow mode
│   ├── conversation.js          # Fragmentation, language switch, behavioral fingerprint
│   ├── multi-agent.js           # Agent firewall, delegation chain, shared threat state
│   ├── multi-agent-trust.js     # Message signing, capability tokens, blast radius
│   ├── encoding.js              # Steganography, encoding bruteforce, structured data
│   ├── watermark.js             # Output watermarking, differential privacy
│   ├── compliance.js            # SOC2/HIPAA/GDPR reporting, audit trail
│   ├── enterprise.js            # Multi-tenant, RBAC, debug mode
│   ├── redteam.js               # Attack simulator, payload fuzzer
│   └── ...                      # + 25 more modules
├── python-sdk/                 # Python SDK
│   ├── agent_shield/           # Core package (detector, shield, middleware, CLI)
│   └── tests/                  # 23 tests
├── go-sdk/                     # Go SDK
│   ├── shield.go               # Detection engine
│   ├── middleware.go            # HTTP/gRPC middleware
│   └── shield_test.go          # 17 tests + benchmarks
├── rust-core/                  # Rust high-performance engine
│   ├── src/                    # RegexSet O(n) matching, WASM/NAPI/PyO3 targets
│   └── tests/                  # 32 tests
├── wasm/                       # Browser/edge bundles (ESM, UMD, minified)
├── dashboard-live/             # Real-time WebSocket dashboard
├── github-app/                 # GitHub PR scanner & Action
├── benchmark-registry/         # Standardized benchmark suite & leaderboard
├── k8s/                        # Kubernetes operator + Helm chart
├── terraform-provider/         # Terraform resources for policy-as-code
├── otel-collector/             # OpenTelemetry receiver & processor
├── vscode-extension/           # VS Code inline diagnostics (167 tests)
├── instructions/               # Detailed feature guides (10 chapters)
├── test/                       # Node.js test suites
├── examples/                   # Quick start & integration examples
└── types/                      # TypeScript definitions
```

## CI/CD

A GitHub Actions workflow is included at `.github/workflows/ci.yml`. It runs all tests across Node.js 16, 18, 20, and 22 on every push and PR.

## Privacy

All detection runs locally using pattern matching. No data is sent to any external service. No API keys required. No cloud dependencies. See [PRIVACY.md](PRIVACY.md) for details.

## License

MIT — see [LICENSE](LICENSE) for details.
