# Changelog

All notable changes to Agent Shield will be documented in this file.

This project follows [Semantic Versioning](https://semver.org/).

## [5.0.0] — 2026-03-20

### Added

- **Agent-to-Agent Protocol** — `AgentProtocol` with `SecureChannel` (HMAC-signed, replay-protected), `HandshakeManager` (mutual auth, challenge-response), `MessageRouter` for multi-agent topologies (`src/agent-protocol.js`)
- **Real-time Streaming Dashboard** — WebSocket server (RFC 6455) with live threat feed, SVG line/donut/heatmap charts, dark/light mode, auto-reconnect (`dashboard-live/`)
- **Policy-as-Code DSL** — `PolicyDSL` with tokenizer, recursive descent parser, compiler, and runtime supporting `when/then/and/or` conditions, `allow` blocks, `rate_limit`, `scan_mode` (`src/policy-dsl.js`)
- **Fuzzing Harness** — `FuzzingHarness` with `InputGenerator` (8 strategies including grammar-based, mutation, encoding), `MutationEngine` (13 mutations), `CoverageTracker`, `CrashCollector`, 50+ seed corpus (`src/fuzzer.js`)
- **Model Fingerprinting** — `ModelFingerprinter` with `ResponseAnalyzer` (16 stylistic features), `StyleProfile` (cosine similarity), `FingerprintDatabase` (5 built-in profiles), `SupplyChainDetector` for model swap detection (`src/model-fingerprint.js`)
- **Cost/Latency Optimizer** — `CostOptimizer` with `AdaptiveScanner` (auto-escalating tiers: fast/standard/deep/paranoid), `LatencyBudget`, `PerformanceMonitor` (p50/p95/p99), 4 optimization presets (`src/cost-optimizer.js`)

## [4.0.0] — 2026-03-19

### Added

- **Rust Core Engine** — `RegexSet`-based O(n) multi-pattern matching with compilation targets for WASM (`wasm-bindgen`), Node.js NAPI (`napi-rs`), and Python (`PyO3`) (`rust-core/`)
- **Go SDK** — full detection engine, HTTP/gRPC middleware, CLI tool, benchmarks, zero external dependencies (`go-sdk/`)
- **Terraform Provider** — `agent_shield_policy`, `agent_shield_rule`, `agent_shield_tenant` resources for infrastructure-as-code (`terraform-provider/`)
- **OpenTelemetry Collector** — receiver (HTTP scan endpoint to log records) and processor (scan logs/traces, annotate/drop/log actions) (`otel-collector/`)
- **GitHub App** — PR scanning with Check Run annotations, GitHub Action (`action.yml`), webhook signature verification, diff parsing (`github-app/`)
- **Benchmark Registry** — `BenchmarkSuite` (100+ test cases), `MetricsCalculator` (F1, MCC, throughput, latency percentiles), `Leaderboard` with interactive web dashboard (`benchmark-registry/`)
- **Multi-language Patterns** — `I18nPatternManager` with 32+ patterns across CJK, Arabic, Cyrillic, and Indic scripts (`src/i18n-patterns.js`)
- **LLM Red Team Suite** — `JailbreakLibrary` (35+ templates across 6 categories), `AdversarialGenerator`, `EvasionTester`, `RedTeamReport` with weakness analysis (`src/llm-redteam.js`)

## [3.0.0] — 2026-03-19

### Added

- **Self-Healing Patterns** — `SelfHealingEngine` auto-generates detection patterns from false negatives with `PatternGenerator` (`src/self-healing.js`)
- **Honeypot Mode** — `HoneypotEngine` with session tracking, escalation analysis, technique intelligence, fake response generation (`src/honeypot.js`)
- **Multi-Modal Scanning** — `MultiModalScanner` for images (alt text, OCR, metadata), audio transcripts, PDFs, and tool outputs (`src/multimodal.js`)
- **Agent Behavior Profiling** — `BehaviorProfile` with statistical baselining, anomaly detection (z-score), health checks (`src/behavior-profiling.js`)
- **Threat Intelligence Network** — `ThreatIntelNetwork` with `PeerNode` reputation, `PatternAnonymizer` (differential privacy), `ConsensusEngine`, `ThreatFeed` with STIX-like export (`src/threat-intel-network.js`)

## [2.1.0] — 2026-03-19

### Added

- **Distributed Scanning** — `DistributedShield` with pluggable adapters (`MemoryAdapter`, `RedisAdapter`), pub/sub threat broadcasting (`src/distributed.js`)
- **Audit Log Streaming** — `AuditStreamManager` with `FileTransport`, `SplunkTransport`, `ElasticsearchTransport` adapters (`src/audit-streaming.js`)
- **Kubernetes Operator** — sidecar container with Helm chart, `MutatingWebhookConfiguration` for auto-injection, Prometheus metrics, health checks (`k8s/`)
- **SSO/SAML Integration** — `SSOManager`, `SAMLParser`, `OIDCHandler`, `IdentityMapper` with enterprise IdP mapping to RBAC roles (`src/sso-saml.js`)
- **Custom Model Fine-Tuning** — `ModelTrainer` with TF-IDF + logistic regression, `TrainingPipeline`, `DatasetManager`, `ModelEvaluator`, `FineTunedModel` export/import (`src/model-finetuning.js`)

## [2.0.0] — 2026-03-19

### Added

- **Plugin Marketplace** — `PluginRegistry`, `PluginValidator`, `MarketplaceClient` with quality scoring, safety validation, version management (`src/plugin-marketplace.js`)
- **Dashboard v2** — real-time web dashboard with threat visualization, donut charts, sparklines, dark/light mode, scan metrics (`dashboard-live/`)
- **Python SDK** — `agent_shield` Python package with core detection, `AgentShield` class, LangChain/LlamaIndex wrappers, Flask/FastAPI middleware, CLI tool (`python-sdk/`)
- **WASM Build** — ESM/UMD bundles for browsers, Cloudflare Workers, Deno, Bun with build script and platform-specific examples (`wasm/`)
- **VS Code Extension** — `agent-shield-vscode` with inline diagnostics, real-time scanning, severity mapping, string literal extraction for JS/TS/Python/Markdown (`vscode-extension/`)

## [1.2.0] — 2026-03-19

### Added

- **LLM-Assisted Classification** — `SemanticClassifier` with Ollama/OpenAI-compatible local endpoint support, two-pass `enhancedScan()` (`src/semantic.js`)
- **Embedding-Based Similarity** — `EmbeddingSimilarityDetector` using TF-IDF + cosine similarity against 28-pattern attack corpus (`src/embedding.js`)
- **Context-Aware Scoring** — `ConversationContextAnalyzer` with multi-turn escalation detection, topic pivot alerts, velocity/repetition checks (`src/context-scoring.js`)
- **Confidence Calibration** — `ConfidenceTuner` with per-category threshold learning, feedback recording, precision/recall metrics (`src/confidence-tuning.js`)

## [1.1.0] — 2026-03-19

### Added

- **Expanded Homoglyph Detection** — comprehensive Unicode mapping covering Cherokee, Georgian, IPA, Math Symbols, Enclosed/Circled, Small Caps, Superscript/Subscript characters
- **Worker Threads Support** — opt-in `ThreadedWorkerScanner` for real parallel CPU-bound scanning
- **Independent Benchmark Suite** — reproducible performance script (`npm run benchmark`) with throughput, latency, scaling, accuracy, and memory metrics
- **AI Phishing Patterns** — QR code phishing, MFA harvesting, credential urgency, subscription scams, AI access lures

### Changed

- **Adversarial Mutation Resilience** — synonym-aware keyword cluster detection, pre-normalization, hex-escape decoding (84% to 95.3% detection rate)

## [1.0.0] — 2026-03-19

### Initial Release

Agent Shield v1.0.0 — a zero-dependency security SDK for AI agents.

### Core Features

- **Prompt Injection Detection** — detects fake system prompts, instruction overrides, ChatML/LLaMA delimiters, markdown headers, and 30+ injection patterns
- **Role Hijacking Detection** — catches DAN mode, developer mode, jailbreak attempts, persona attacks
- **Data Exfiltration Prevention** — blocks system prompt extraction, markdown image leaks, fetch calls, tag extraction
- **Tool Abuse Detection** — flags sensitive file access, shell execution, SQL injection, path traversal, recursive tool calls
- **Social Engineering Detection** — identifies identity concealment, urgency + authority, gaslighting, false pre-approval
- **Obfuscation Detection** — decodes Unicode homoglyphs, zero-width chars, Base64, hex, ROT13, leetspeak, reversed text
- **Multi-Language Support** — detects attacks in English, Spanish, French, German, Portuguese, Chinese, Japanese

### Modules

- **AgentShield** — main SDK class with configurable sensitivity, blocking, and callbacks
- **Canary Tokens** — generate and detect prompt leak canaries
- **PII Redactor** — auto-redact SSNs, emails, phone numbers, credit cards (DLP engine)
- **Tool Guard** — tool sequence analysis and permission boundaries
- **Circuit Breaker** — rate limiting and automatic trip on repeated attacks
- **Conversation Analysis** — fragmentation detection, language switch detection, behavioral fingerprinting
- **Multi-Agent Security** — agent firewall, delegation chains, shared threat state
- **Multi-Agent Trust** — message signing (HMAC), capability tokens, blast radius containment
- **Encoding Detection** — steganography, encoding bruteforce, structured data scanning
- **Output Watermarking** — watermark agent outputs with differential privacy
- **Policy Engine** — YAML/JSON policy loading, structured logging, webhook alerts
- **Compliance Reporting** — SOC2, HIPAA, GDPR, OWASP, NIST, EU AI Act reports with audit trails
- **Enterprise Features** — multi-tenant isolation, RBAC, debug mode
- **RAG Scanner** — scan retrieved documents before they enter the context
- **Red Team Simulator** — 49 built-in attack payloads with automated testing
- **Shield Score** — quantitative security scoring and benchmarking

### Framework Integrations

- Anthropic / Claude SDK (`shieldAnthropicClient`)
- OpenAI SDK (`shieldOpenAIClient`)
- LangChain (`ShieldCallbackHandler`)
- Vercel AI SDK (`shieldVercelAI`)
- Express middleware (`expressMiddleware`)
- Generic agent wrapper (`wrapAgent`, `shieldTools`)

### CLI

- `npx agent-shield scan` — scan text for threats
- `npx agent-shield score` — calculate shield score
- `npx agent-shield redteam` — run attack simulation
- `npx agent-shield audit` — compliance audit
- `npx agent-shield patterns` — list all detection patterns

### Benchmarks

- 100% detection on internal red team (49 attacks)
- 99.1% detection on external benchmark (108 real-world attacks)
- 0% false positive rate (103 benign inputs)
- 100/100 A+ shield score
- ~48,000 scans/sec throughput
- < 0.03ms average latency
