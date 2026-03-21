# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## Project Overview

Agent Shield is a security SDK for AI agents. It protects agents from prompt injection, data exfiltration, tool abuse, and 30+ other AI-specific threats. It runs as a sub-agent or middleware inside any agent pipeline — Claude SDK, OpenAI, LangChain, or custom agents.

**Design Philosophy:** Zero-dependency, local-only detection. Drop it into any Node.js agent and it works. No API keys, no cloud calls, no data leaves the user's environment.

**Privacy First:** All detection runs locally via pattern matching. No external calls ever.

**Multi-Platform:** Available as Node.js, Python, Go, Rust, and WASM SDKs.

## npm Package

Published as **`agentshield-sdk`** on npm (the name `agent-shield` was taken).

```bash
npm install agentshield-sdk
```

## Build & Development

```bash
# Install (no external dependencies)
npm install

# Run tests
npm test

# Run full test suite (40 features)
npm run test:all

# Adaptive defense tests
npm run test:adaptive

# False positive accuracy tests
npm run test:fp

# Red team attack simulation
npm run redteam

# Shield score / benchmarks
npm run score
npm run benchmark

# Sub-project tests
node dashboard-live/test/test-server.js
node github-app/test/test-scanner.js
node benchmark-registry/test/test-registry.js
node vscode-extension/test/extension.test.js
cd python-sdk && python -m unittest tests/test_detector.py
```

## Code Style

- Vanilla JavaScript (Node.js >=16) — no frameworks or build tools
- CommonJS modules (`require`/`module.exports`)
- JSDoc comments on all public functions
- Console logging prefixed with `[Agent Shield]` for easy filtering
- Use `const` and `let`, never `var`
- Strict mode (`'use strict'`) in all scripts
- Follow existing patterns in the codebase
- Keep functions focused and concise

## Project Structure

```
/
├── src/                           # Node.js SDK (390 exports, 93 modules)
│   ├── index.js                   # AgentShield class — main SDK entry point
│   ├── main.js                    # Unified re-export of all modules
│   ├── detector-core.js           # Core detection engine (patterns, scanning)
│   ├── middleware.js               # wrapAgent, shieldTools, Express middleware
│   ├── integrations.js             # Anthropic, OpenAI, LangChain, Vercel AI
│   ├── canary.js                   # Canary tokens, prompt leak detection
│   ├── pii.js                      # PII redaction, DLP engine
│   ├── tool-guard.js               # Tool sequence analysis, permission boundaries
│   ├── circuit-breaker.js          # Circuit breaker, rate limiter, shadow mode
│   ├── conversation.js             # Fragmentation, language switch, behavioral fingerprint
│   ├── multi-agent.js              # Agent firewall, delegation chain, shared threat state
│   ├── multi-agent-trust.js        # Message signing, capability tokens, blast radius
│   ├── encoding.js                 # Steganography, encoding bruteforce, structured data
│   ├── watermark.js                # Output watermarking, differential privacy
│   ├── policy.js                   # Policy loading, structured logging, webhooks
│   ├── policy-extended.js          # A/B testing, threat intel, pattern builder
│   ├── compliance.js               # SOC2/HIPAA/GDPR reporting, audit trail
│   ├── enterprise.js               # Multi-tenant, RBAC, debug mode
│   ├── scanners.js                 # RAG scanner, prompt linter, tool schema validator
│   ├── production.js               # Sampling, shadow comparison, graceful scanner
│   ├── testing.js                  # Test suite generator, agent contracts
│   ├── redteam.js                  # Attack simulator, payload fuzzer
│   ├── shield-score.js             # Shield score calculator, benchmarks
│   ├── threat-encyclopedia.js      # Threat reference database
│   ├── presets.js                  # Config presets, snippet generator
│   ├── badges.js                   # Badge generator, GitHub Action reporter
│   ├── allowlist.js                # Allowlists, feedback loop, scan cache
│   ├── errors.js                   # Structured error codes (AS-{CATEGORY}-{NUMBER})
│   ├── utils.js                    # Shared utilities
│   │
│   │  # v1.2 — Semantic Detection
│   ├── semantic.js                 # LLM-assisted classification (SemanticClassifier)
│   ├── embedding.js                # TF-IDF embedding similarity detector
│   ├── context-scoring.js          # Multi-turn conversation context analyzer
│   ├── confidence-tuning.js        # Per-category threshold calibration
│   │
│   │  # v2.0 — Platform & Ecosystem
│   ├── plugin-marketplace.js       # PluginRegistry, MarketplaceClient
│   ├── plugin-system.js            # Custom detector plugins (detect() interface)
│   │
│   │  # v2.1 — Enterprise & Scale
│   ├── distributed.js              # DistributedShield (Redis/memory adapters)
│   ├── audit-streaming.js          # AuditStreamManager (Splunk, ES transports)
│   ├── audit-immutable.js          # SHA-256 hash-chained tamper-evident audit log
│   ├── sso-saml.js                 # SSOManager, SAMLParser, OIDCHandler
│   ├── model-finetuning.js         # ModelTrainer, TrainingPipeline
│   │
│   │  # v3.0 — Autonomous Defense
│   ├── self-healing.js             # Auto-generated patterns from false negatives
│   ├── honeypot.js                 # HoneypotEngine — attacker engagement
│   ├── multimodal.js               # Image, audio, PDF scanning
│   ├── behavior-profiling.js       # Statistical baselining, z-score anomaly
│   ├── threat-intel-network.js     # Federated threat intel (differential privacy)
│   │
│   │  # v4.0 — Performance & Polyglot
│   ├── i18n-patterns.js            # CJK, Arabic, Cyrillic, Indic patterns (32+)
│   ├── llm-redteam.js              # JailbreakLibrary (35+ templates, 6 categories)
│   ├── worker-scanner.js           # Async non-blocking scanner with event loop yielding
│   │
│   │  # v5.0 — Advanced Capabilities
│   ├── agent-protocol.js           # SecureChannel (HMAC, replay protection)
│   ├── policy-dsl.js               # Policy DSL parser/compiler/runtime
│   ├── fuzzer.js                   # Coverage-guided fuzzing harness
│   ├── model-fingerprint.js        # LLM fingerprinting, supply chain detection
│   ├── cost-optimizer.js           # Adaptive scan tiers, latency budgeting
│   ├── stream-scanner.js           # Token-by-token sliding window scanner for LLM streaming
│   ├── token-analysis.js           # Shannon entropy & n-gram perplexity injection detection
│   ├── document-scanner.js         # Text extraction & threat scanning for uploaded documents
│   ├── response-handler.js         # Configurable threat response strategies (block/sanitize/redirect)
│   ├── benchmark-harness.js        # Standardized framework for detection engine evaluation
│   │
│   │  # v6.0 — Compliance & Standards
│   ├── owasp-2025.js               # OWASP LLM Top 10 v2025 coverage matrix
│   ├── mcp-bridge.js               # MCP tool security, session guards, middleware
│   ├── nist-mapping.js             # NIST AI RMF mapping, AI-BOM generator
│   ├── eu-ai-act.js                # EU AI Act risk classification, conformity
│   ├── prompt-leakage.js           # System prompt extraction detection (LLM07)
│   ├── rag-vulnerability.js        # RAG/vector vulnerability scanning (LLM08)
│   ├── confused-deputy.js          # Confused deputy prevention (Meta incident)
│   ├── certification.js            # Certification badge and audit for compliance attestation
│   ├── alert-tuning.js             # Alert fatigue scoring and auto-tuning
│   ├── observability.js            # Prometheus metrics, structured JSON logging
│   ├── otel.js                     # OpenTelemetry-compatible metrics and tracing
│   ├── tool-output-validator.js    # Tool return value scanning for injection/exfiltration
│   │
│   │  # v7.0 — MCP Security Runtime
│   ├── mcp-security-runtime.js     # Unified MCP security layer (auth+scan+behavior+audit)
│   ├── mcp-certification.js        # MCP certification, threat intel, cross-org trust
│   ├── mcp-sdk-integration.js      # Drop-in security wrapper for MCP SDK servers
│   ├── mcp-server.js               # MCP server exposing Shield over JSON-RPC 2.0
│   │
│   │  # v7.1 — Adaptive Defense
│   ├── adaptive-defense.js         # Learning loops, agent contracts, compliance attestation
│   ├── adaptive.js                 # Adaptive detection with semantic hooks, community patterns
│   ├── ctf.js                      # Capture-the-flag challenge system for security testing
│   ├── openclaw.js                 # OpenClaw skill integration and message hook
│   │
│   │  # v7.2 — IPIA Detection
│   └── ipia-detector.js            # Indirect prompt injection detector (joint-context pipeline)
│
│  # v7.3 - CORTEX Autonomous Defense
│   ├── attack-genome.js            # Attack genome sequencing (intent/technique/evasion/target)
│   ├── evolution-simulator.js      # Adversarial evolution with mutation engine
│   ├── intent-firewall.js          # Intent classification (same words, different action)
│   ├── herd-immunity.js            # Cross-agent pattern sharing, immune memory
│   ├── threat-intel-federation.js  # Federated threat intel with differential privacy
│   ├── behavioral-dna.js           # Per-agent behavioral baselines, anomaly detection
│   ├── audit.js                    # Pre-deployment security audit (617+ attacks)
│   ├── flight-recorder.js          # Forensic conversation replay, auto-fix patterns
│   ├── supply-chain.js             # Tool chain validation, response scanning
│   ├── report-generator.js         # Lighthouse-style HTML security report
│   ├── soc-dashboard.js            # Enterprise SOC with Slack/PagerDuty/Teams
│   ├── attack-replay.js            # Record, replay, compare defense improvements
│   ├── compliance-authority.js     # HMAC-signed compliance certificates
│   └── real-attack-datasets.js     # HackAPrompt/TensorTrust/research corpus
│
├── python-sdk/                    # Python SDK
│   ├── agent_shield/              # Core package
│   │   ├── __init__.py
│   │   ├── detector.py            # Detection engine (patterns, scanning)
│   │   ├── shield.py              # AgentShield class
│   │   ├── middleware.py          # Flask/FastAPI middleware
│   │   └── cli.py                 # CLI tool
│   └── tests/                     # 23 tests
│
├── go-sdk/                        # Go SDK
│   ├── shield.go                  # Detection engine
│   ├── middleware.go              # HTTP/gRPC middleware
│   ├── shield_test.go             # 17 tests
│   └── benchmark_test.go          # Performance benchmarks
│
├── rust-core/                     # Rust high-performance engine
│   ├── src/                       # RegexSet O(n) matching
│   ├── tests/                     # 32 tests
│   └── build.sh                   # WASM, NAPI, PyO3 build targets
│
├── wasm/                          # Browser/edge WASM bundles
│   └── dist/                      # ESM, UMD, minified builds
│
├── dashboard-live/                # Real-time WebSocket dashboard
│   ├── server.js                  # WebSocket server (RFC 6455)
│   ├── index.html                 # SVG charts, dark/light mode
│   ├── integration.js             # AgentShield integration wrapper
│   └── test/                      # 14 tests
│
├── github-app/                    # GitHub PR scanner
│   ├── app.js                     # GitHub App server
│   ├── scanner.js                 # PR diff scanner
│   ├── action.yml                 # GitHub Action definition
│   └── test/                      # 20 tests
│
├── benchmark-registry/            # Standardized benchmarks
│   ├── registry.js                # BenchmarkSuite (100+ test cases)
│   ├── metrics.js                 # F1, MCC, throughput, latency percentiles
│   ├── leaderboard.js             # Engine comparison rankings
│   └── test/                      # 22 tests
│
├── k8s/                           # Kubernetes operator
│   ├── server.js                  # Sidecar container
│   ├── webhook.js                 # MutatingWebhookConfiguration
│   ├── Dockerfile
│   └── helm/                      # Helm chart (Chart.yaml, values.yaml, templates/)
│
├── terraform-provider/            # Terraform provider
│   ├── provider.go                # Provider definition
│   ├── resource_policy.go         # agent_shield_policy resource
│   ├── resource_rule.go           # agent_shield_rule resource
│   └── resource_tenant.go         # agent_shield_tenant resource
│
├── otel-collector/                # OpenTelemetry Collector plugins
│   ├── receiver/                  # HTTP scan endpoint → log records
│   └── processor/                 # Scan logs/traces, annotate/drop/log
│
├── vscode-extension/              # VS Code extension
│   ├── extension.js               # 141 detection patterns, inline diagnostics
│   └── test/                      # 167 tests
│
├── instructions/                  # Detailed feature documentation (10+ guides)
├── test/                          # Node.js test suites
├── examples/                      # Quick start & integration examples
├── types/                         # TypeScript type definitions
├── bin/                           # CLI tool
├── dashboard/                     # Static security dashboard
├── ROADMAP.md                     # Version history & roadmap
├── package.json
├── LICENSE
├── README.md
└── CLAUDE.md
```

## Important Conventions

- Commit messages should be clear and descriptive
- All new features should include tests
- All detection must run locally — never transmit user data
- Severity levels: critical > high > medium > low
- Status levels: danger > warning > caution > safe
- Use `safeRequire()` pattern in main.js for graceful module loading
- New src/ modules must be added to main.js exports

## Testing

- `npm test` — core, module, and new feature tests (248 assertions)
- `npm run test:mcp` — MCP security runtime, certification & trust tests (112 assertions)
- `npm run test:deputy` — confused deputy prevention tests (85 assertions)
- `npm run test:v6` — v6.0 compliance & standards tests (122 assertions)
- `npm run test:adaptive` — adaptive defense system tests (85 assertions)
- `npm run test:ipia` — indirect prompt injection detector tests (117 assertions)
- `npm run test:all` — full 40-feature suite (149 assertions)
- `npm run test:fp` — false positive accuracy tests (118 samples, 99.2% accuracy)
- `npm run test:production` — production readiness tests (24 assertions)
- `npm run test:full` — runs all test suites together
- `npm run redteam` — attack simulation (100% detection, A+)
- `npm run score` — shield score (100/100)
- Sub-project tests: dashboard (14), github-app (20), benchmarks (22), python (32), vscode (607)
- Total: **2,220 test assertions** across 16 test suites + Python + VSCode

## Architecture Notes

- **detector-core.js** — standalone pattern matching engine, no DOM dependencies
- **index.js** — `AgentShield` class wrapping the detector with config, stats, blocking
- **main.js** — unified re-export of all 390 symbols via `safeRequire()` for graceful loading
- **integrations.js** — framework-specific wrappers (Anthropic, OpenAI, LangChain, Vercel)
- **middleware.js** — generic agent wrapping and Express middleware
- **agent-protocol.js** — HMAC-signed secure channels with replay protection
- **policy-dsl.js** — tokenizer → recursive descent parser → compiler → runtime
- **fuzzer.js** — coverage-guided fuzzing with xorshift32 PRNG for reproducibility
- **model-fingerprint.js** — 16-feature stylistic analysis with cosine similarity matching
- **cost-optimizer.js** — 4-tier adaptive scanning with latency budgets
- **adaptive-defense.js** — autonomous learning loops with compliance attestation framework
- **mcp-security-runtime.js** — unified MCP layer with AES-256-GCM encryption, adaptive defense integration
- **ipia-detector.js** — joint-context IPIA pipeline: context construction → TF-IDF features → decision tree classifier, pluggable embedding backends

## Version History

- **v1.0** — Core detection engine, framework integrations, middleware, CLI
- **v1.1** — Hardening: homoglyphs, worker threads, benchmarks, adversarial resilience
- **v1.2** — Semantic detection: LLM classifier, embeddings, conversation context, calibration
- **v2.0** — Platform: plugin marketplace, dashboard, Python SDK, WASM, VS Code extension
- **v2.1** — Enterprise: distributed scanning, audit streaming, K8s, SSO/SAML, model fine-tuning
- **v3.0** — Autonomous: self-healing, honeypot, multi-modal, behavior profiling, threat intel
- **v4.0** — Polyglot: Rust core, Go SDK, Terraform, OTel, GitHub App, benchmarks, i18n, red team
- **v5.0** — Advanced: agent protocol, live dashboard, policy DSL, fuzzer, fingerprinting, cost optimizer
- **v6.0** — Compliance: OWASP LLM Top 10 v2025, MCP Bridge, NIST AI RMF, EU AI Act, prompt leakage detector, RAG vulnerability scanner, confused deputy prevention
- **v7.0** — MCP Security: unified runtime (auth+scan+behavior+audit), AES-256-GCM encryption, HMAC signing, MCP certification framework, cross-org agent trust CA, threat intelligence engine
- **v7.1** — Adaptive Defense: learning loops, agent contracts, compliance attestation, CTF challenges, adaptive detection with community patterns, MCP SDK integration, OpenClaw hooks
- **v7.2** — IPIA Detection: joint-context embedding pipeline, TF-IDF + decision tree classifier, pluggable embedding backends, batch RAG scanning, Express middleware
- **v7.3** — CORTEX Autonomous Defense: attack genome sequencing, adversarial evolution simulator, intent firewall, herd immunity, federated threat intel, behavioral DNA, pre-deployment audit, flight recorder, supply chain verification, SOC dashboard, compliance certification authority
