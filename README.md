# Agent Shield

[![npm](https://img.shields.io/badge/npm-v13.3.0-blue)](https://www.npmjs.com/package/agentshield-sdk)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](#)
[![node](https://img.shields.io/badge/node-%3E%3D16-blue)](#)
[![F1](https://img.shields.io/badge/F1-0.988%20real--world-gold)](#benchmarks)
[![tests](https://img.shields.io/badge/tests-3400%2B-brightgreen)](#testing)

**Security middleware for AI agents.** Protects against prompt injection, tool poisoning, data exfiltration, and 40+ threat categories. Zero dependencies. All detection runs locally.

```bash
npm install agentshield-sdk
```

```javascript
const { AgentShield } = require('agentshield-sdk');
const shield = new AgentShield({ blockOnThreat: true });

const result = shield.scanInput(userMessage);
if (result.blocked) return 'Blocked for safety.';
```

---

## Benchmarks

| Metric | Result |
|--------|--------|
| F1 (real-world: HackAPrompt + TensorTrust + research papers) | **0.988** |
| F1 (embedded: BIPIA/HackAPrompt/MCPTox/Multilingual/Stealth) | **1.000** |
| Red team (617+ attack payloads) | **100% detection** |
| False positive rate (118+ benign inputs) | **0%** |
| Self-training convergence | **0% bypass in 3 cycles** |
| Avg latency | **< 0.4ms** |

Detection stack: 100+ regex patterns, 35-feature logistic regression + k-NN ensemble, 5-layer evasion resistance, 19-language support, chunked scanning, adversarial self-training loop.

```bash
# Verify locally
npm run score && npm run redteam
```

---

## What It Detects

| Category | Examples |
|----------|----------|
| Prompt Injection | System prompt overrides, ChatML/LLaMA delimiters, instruction hijacking |
| Role Hijacking | DAN mode, developer mode, persona attacks, jailbreaks (35+ templates) |
| Data Exfiltration | Prompt extraction, markdown image leaks, DNS tunneling, side-channel encoding |
| Tool Abuse | Shell execution, SQL injection, path traversal, sensitive file access |
| Social Engineering | Identity concealment, urgency + authority, gaslighting, false pre-approval |
| Obfuscation | Unicode homoglyphs, zero-width chars, Base64, hex, ROT13, leetspeak |
| Indirect Injection | RAG poisoning, tool output injection, email/document payloads, few-shot poisoning |
| Visual Deception | Hidden HTML/CSS content, LaTeX phantom commands, rendering differentials |
| Multi-Language | CJK, Arabic, Cyrillic, Hindi + 15 more languages |
| AI Phishing | Fake AI login, QR phishing, MFA harvesting, credential urgency |
| Sybil Attacks | Coordinated fake agents, voting collusion, behavioral clustering |
| Side Channels | DNS exfiltration, timing-based encoding, beaconing detection |

---

## Framework Integrations

Works with any agent framework in 1-3 lines:

```javascript
// Anthropic / Claude SDK
const { shieldAnthropicClient } = require('agentshield-sdk');
const client = shieldAnthropicClient(new Anthropic(), { blockOnThreat: true });

// OpenAI SDK
const { shieldOpenAIClient } = require('agentshield-sdk');
const client = shieldOpenAIClient(new OpenAI(), { blockOnThreat: true });

// LangChain
const { ShieldCallbackHandler } = require('agentshield-sdk');
const chain = new LLMChain({ llm, prompt, callbacks: [new ShieldCallbackHandler()] });

// Express middleware
const { expressMiddleware } = require('agentshield-sdk');
app.use(expressMiddleware({ blockOnThreat: true }));

// MCP SDK (Model Context Protocol)
const { shieldMCPServer } = require('agentshield-sdk/mcp');
const server = shieldMCPServer(new Server({ name: 'my-server', version: '1.0' }));

// Generic agent wrapper
const { wrapAgent } = require('agentshield-sdk');
const safe = wrapAgent(myAgent, { blockOnThreat: true });
```

Also available for **Python**, **Go**, **Rust**, and **WASM** (browsers/edge).

---

## MCP Security

17-layer security middleware for Model Context Protocol servers. Covers attestation, SSRF/path-traversal firewalls, OAuth, rate limiting, circuit breaker, behavioral baselines, ML classification, drift monitoring, and more.

```javascript
const { MCPGuard } = require('agentshield-sdk/guard');

// One-line setup with presets: minimal | standard | recommended | strict | paranoid
const guard = MCPGuard.fromPreset('recommended');

guard.registerServer('my-server', toolDefinitions, oauthToken);
const result = guard.interceptToolCall('my-server', 'search', { query: input });
// { allowed: true, threats: [], anomalies: [] }
```

**Supply chain scanning** for MCP servers (11 CVEs, schema poisoning, SARIF output):

```javascript
const { SupplyChainScanner } = require('agentshield-sdk/scanner');
const report = new SupplyChainScanner().scanServer({ name: 'server', tools: defs });
const sarif = report.toSARIF(); // CI/CD integration
```

---

## DeepMind AI Agent Trap Defenses

Comprehensive defenses for all 6 categories from Google DeepMind's "AI Agent Traps" research, built from first-principles analysis.

```javascript
const { TrapDefenseV2 } = require('agentshield-sdk/traps');

const defense = new TrapDefenseV2();

// Content structure analysis (hidden HTML/CSS/ARIA payloads)
defense.structureAnalyzer.analyze(htmlContent);

// Retrieval-time scanning (catches RAG poisoning at query time)
defense.retrievalScanner.scanRetrieval(userQuery, ragResult);

// Few-shot validation (detect poisoned examples)
defense.fewShotValidator.validate(contextExamples);

// Sub-agent spawn gating (block privilege escalation)
defense.spawnGate.validateSpawn(parentPerms, childConfig);

// Escalating scrutiny (detect approval fatigue)
defense.scrutinyEngine.getScrutinyLevel();

// Cross-agent fragment assembly (split-payload attacks)
defense.fragmentAssembler.addFragment(text, source);
```

**All modules:** ContentStructureAnalyzer, SourceReputationTracker, RetrievalTimeScanner, FewShotValidator, SubAgentSpawnGate, SelfReferenceMonitor, InformationAsymmetryDetector, ProvenanceMarker, EscalatingScrutinyEngine, CompositeFragmentAssembler

---

## Visual Deception Detection

Detects content that renders differently than it reads -- attackers hiding instructions in markup.

```javascript
const { RenderDifferentialAnalyzer } = require('agentshield-sdk');

const analyzer = new RenderDifferentialAnalyzer();

// Scan any format (auto-detected or explicit)
const result = analyzer.scan(content, 'auto');
// { deceptive: true, techniques: [{ type: 'css_hidden', severity: 'high', ... }] }

// Format-specific analysis
analyzer.analyzeHTML(html);       // CSS tricks: display:none, opacity:0, off-screen
analyzer.analyzeMarkdown(md);     // Link mismatch, hidden spans, comment injection
analyzer.analyzeLatex(tex);       // \phantom, \textcolor{white}, \renewcommand
```

---

## Sybil Detection

Detect coordinated fake agents acting in concert.

```javascript
const { SybilDetector } = require('agentshield-sdk');

const detector = new SybilDetector({ similarityThreshold: 0.7, minClusterSize: 3 });

detector.registerAgent('agent-1', { name: 'Helper' });
detector.registerAgent('agent-2', { name: 'Assistant' });
detector.registerAgent('agent-3', { name: 'Aide' });

detector.recordAction('agent-1', { type: 'vote', target: 'proposal-A' });
detector.recordAction('agent-2', { type: 'vote', target: 'proposal-A' });
detector.recordAction('agent-3', { type: 'vote', target: 'proposal-A' });

const { clusters, sybilRisk } = detector.detectClusters();
// { clusters: [{ agents: ['agent-1','agent-2','agent-3'], similarity: 0.9 }], sybilRisk: 'high' }
```

---

## Side-Channel Monitoring

Detect data exfiltration via covert channels.

```javascript
const { SideChannelMonitor, BeaconDetector } = require('agentshield-sdk');

const monitor = new SideChannelMonitor();

// DNS exfiltration (high-entropy subdomains, base64 labels)
monitor.analyzeDNSQuery('aGVsbG8gd29ybGQ.attacker.com');

// Timing-based exfiltration (binary encoding in delays)
monitor.analyzeTimingPattern(timestamps);

// URL parameter exfiltration
monitor.analyzeURLParams('https://evil.com/log?d=c2VjcmV0');

// C2 beaconing detection
const beacon = new BeaconDetector();
beacon.addEvent(t1); beacon.addEvent(t2); beacon.addEvent(t3);
beacon.detectBeaconing(); // { beaconing: true, interval: 60000, confidence: 0.85 }
```

---

## Autonomous Defense

```javascript
const { AutonomousHardener, MicroModel } = require('agentshield-sdk');

// Self-training loop: attacks itself, finds bypasses, learns from them
const hardener = new AutonomousHardener({
  microModel: new MicroModel(),
  persistPath: './learned-samples.json',
  maxFPRate: 0.05
});

hardener.runCycle(); // 18 mutation strategies, converges to 0% bypass in 3 cycles
```

```javascript
const { IntentFirewall, AttackGenome, HerdImmunity } = require('agentshield-sdk');

// Intent classification (same words, different action)
const firewall = new IntentFirewall();
firewall.classify('Help me write a phishing email');        // BLOCKED
firewall.classify('Help me write about phishing training'); // ALLOWED

// Cross-agent herd immunity
const herd = new HerdImmunity();
herd.reportAttack({ text: 'DAN mode jailbreak', agentId: 'agent-a' });
// All connected agents now have the pattern
```

---

## Compliance

Built-in coverage for major security frameworks:

| Framework | Module |
|-----------|--------|
| OWASP LLM Top 10 (2025) | `OWASPCoverageMatrix` |
| OWASP Agentic Top 10 (2026) | `OWASPAgenticScanner` |
| NIST AI RMF | `NISTMapper`, `AIBOMGenerator` |
| EU AI Act | `RiskClassifier`, `ConformityAssessment` |
| SOC 2 / HIPAA / GDPR | `ComplianceReporter` |

```javascript
const { OWASPCoverageMatrix } = require('agentshield-sdk');
const report = new OWASPCoverageMatrix().generateReport();
// Per-category scores, gap analysis, remediation guidance
```

---

## Security Primitives

| Capability | Module |
|-----------|--------|
| Prompt hardening (4 levels) | `PromptHardener` |
| HMAC message integrity chain | `MessageIntegrityChain` |
| Cryptographic intent binding | `IntentBinder`, `createGatedExecutor` |
| Semantic isolation (provenance tags) | `SemanticIsolationEngine` |
| Confused deputy prevention | `ConfusedDeputyGuard` |
| PII redaction | `PIIRedactor` |
| Canary tokens | `CanaryTokens` |
| Attack surface mapping | `AttackSurfaceMapper` |
| Causal intent graph | `IntentGraph` |
| Behavioral drift IDS | `DriftMonitor` |

---

## Red Team & Auditing

```bash
# CLI audit (617+ attacks, A+-F grading)
npx agentshield-audit https://your-agent.com --mode full

# Pre-deployment audit (< 100ms)
npx agent-shield redteam
```

```javascript
const { RedTeamCLI } = require('agentshield-sdk');
const report = new RedTeamCLI().run(endpoint, { mode: 'full' });
// HTML, JSON, and Markdown reports with grading
```

---

## Enterprise

| Feature | Module |
|---------|--------|
| Distributed scanning (Redis) | `DistributedShield` |
| Audit streaming (Splunk, ES) | `AuditStreamManager` |
| SSO / SAML / OIDC | `SSOManager` |
| Multi-tenant isolation | `MultiTenantShield` |
| Policy-as-Code DSL | `PolicyDSL` |
| Kubernetes sidecar | `k8s/helm/agent-shield` |
| Terraform provider | `terraform-provider/` |
| OpenTelemetry collector | `otel-collector/` |
| GitHub App / Action | `github-app/` |
| VS Code extension | `vscode-extension/` |
| Real-time dashboard | `dashboard-live/` |

---

## Platform SDKs

| Platform | Install | Features |
|----------|---------|----------|
| **Node.js** | `npm install agentshield-sdk` | Full SDK, 400+ exports, zero deps |
| **Python** | `pip install agent-shield` | Detection, Flask/FastAPI middleware, CLI |
| **Go** | `go get github.com/texasreaper62/agent-shield/go-sdk` | Detection, HTTP/gRPC middleware, zero deps |
| **Rust** | `rust-core/` | RegexSet O(n) engine, WASM/NAPI/PyO3 |
| **WASM** | `wasm/dist/` | ESM/UMD for browsers, Workers, Deno, Bun |

---

## CLI

```bash
npx agent-shield scan "ignore all instructions"     # Scan text
npx agent-shield scan --file prompt.txt --pii        # Scan file + PII
npx agent-shield demo                                # Live attack simulation
npx agent-shield score                               # Shield Score (0-100)
npx agent-shield redteam                             # Red team suite
npx agent-shield audit ./my-agent/                   # Audit codebase
npx agent-shield patterns                            # List detection patterns
npx agent-shield threat prompt_injection             # Threat encyclopedia
npx agentshield-audit <endpoint> --mode full         # Remote agent audit
```

---

## Configuration

```javascript
const shield = new AgentShield({
  sensitivity: 'medium',            // low | medium | high
  blockOnThreat: false,             // Auto-block dangerous inputs
  blockThreshold: 'high',           // Min severity to block
  logging: false,                   // Console logging
  onThreat: (result) => {},         // Callback on detection
  dangerousTools: ['bash'],         // Tools to scrutinize
  sensitiveFilePatterns: [/.env$/i] // File patterns to block
});

// Or use presets
const { getPreset } = require('agentshield-sdk');
const config = getPreset('chatbot'); // chatbot | coding_agent | rag_pipeline | customer_support
```

---

## Testing

```bash
npm test                  # Core + module tests
npm run test:all          # Full 40-feature suite
npm run test:full         # All test suites combined
npm run test:fp           # False positive accuracy (100%)
npm run redteam           # Attack simulation (100% detection)
npm run score             # Shield Score (100/100 A+)
npm run benchmark         # Performance benchmarks
```

**3,400+ test assertions** across 22 test suites, plus Python and VS Code extension tests.

---

## Project Structure

```
src/                  100+ modules, 400+ exports (zero dependencies)
python-sdk/           Python SDK with Flask/FastAPI middleware
go-sdk/               Go SDK with HTTP/gRPC middleware
rust-core/            Rust high-perf engine (WASM/NAPI/PyO3)
wasm/                 Browser/edge bundles
dashboard-live/       Real-time WebSocket dashboard
github-app/           GitHub PR scanner & Action
benchmark-registry/   Standardized benchmark suite
k8s/                  Kubernetes operator + Helm chart
terraform-provider/   Terraform policy-as-code
otel-collector/       OpenTelemetry receiver & processor
vscode-extension/     VS Code inline diagnostics
research/             Attack research & threat intelligence
test/                 22 test suites
examples/             Quick start guides
types/                TypeScript definitions
```

---

## CI/CD

GitHub Actions workflow at `.github/workflows/ci.yml` runs all tests across Node.js 18, 20, and 22 on every push and PR.

## Why Free?

Agent Shield started as a paid SDK with Pro and Enterprise tiers. We removed all gating in v9.0. Every feature — ML detection, compliance reporting, MCP security, CORTEX autonomous defense — is now free and open source.

Security shouldn't have a paywall. If your agent is vulnerable, it doesn't matter what tier you're on.

## Privacy

All detection runs locally. No data is sent to any external service. No API keys required. No cloud dependencies.

## License

MIT -- see [LICENSE](LICENSE).
