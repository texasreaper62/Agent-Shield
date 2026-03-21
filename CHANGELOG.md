# Changelog

All notable changes to Agent Shield will be documented in this file.

This project follows [Semantic Versioning](https://semver.org/).

## [7.3.0] - 2026-03-21

### Added - CORTEX Autonomous Defense Platform

- **Attack Genome Sequencing** (`src/attack-genome.js`) - Decompose attacks into intent/technique/evasion/target genome. Detect unseen variants by recognizing the genome, not the surface text. GenomeDatabase clusters attack families.
- **Adversarial Evolution Simulator** (`src/evolution-simulator.js`) - GAN-style mutation engine generates attack variants across generations. Tests against defenses automatically. hardenFromEvolution() generates new patterns from evasive survivors.
- **Intent Firewall** (`src/intent-firewall.js`) - Classifies user INTENT, not just content. Same words blocked or allowed based on context. "Help me write a phishing email" = BLOCKED. "Help me write about phishing training" = ALLOWED. ContextAnalyzer detects multi-turn manipulation.
- **Cross-Agent Herd Immunity** (`src/herd-immunity.js`) - When one agent detects an attack, all connected agents receive the pattern. ImmuneMemory provides collective memory that new agents inherit from day one.
- **Federated Threat Intelligence** (`src/threat-intel-federation.js`) - CrowdStrike model: anonymous attack pattern sharing with differential privacy. Consensus-based promotion. createFederationMesh() connects nodes.
- **Agent Behavioral DNA** (`src/behavioral-dna.js`) - Learn per-agent behavioral baselines (tool usage, response patterns, timing). Detect anomalies when agent is compromised. Portable fingerprints.

### Added - Enterprise & Production

- **Pre-Deployment Security Audit** (`src/audit.js`) - Run 617+ attacks with mutation engine in under 100ms. SecurityAudit generates category breakdown, findings, fix recommendations, and production-readiness verdict.
- **Agent Flight Recorder** (`src/flight-recorder.js`) - Forensic conversation replay. Records every interaction, detects incidents, reconstructs attack timeline and escalation path. Auto-generates fix patterns.
- **Supply Chain Verification** (`src/supply-chain.js`) - ToolChainValidator scans tool arguments and responses for injection. ResponseScanner deep-scans JSON/nested data for hidden instructions. DomainAllowlist for URL validation.
- **Visual HTML Security Report** (`src/report-generator.js`) - Lighthouse-style HTML report with SVG gauge, category bar charts, severity breakdown, fix recommendations. Self-contained, print-friendly.
- **Enterprise SOC Dashboard** (`src/soc-dashboard.js`) - Real-time event aggregation from multiple agents. Query by agent/category/severity/time. Alert channels: Slack, PagerDuty, Microsoft Teams.
- **Attack Replay Platform** (`src/attack-replay.js`) - Record real attacks, replay against updated defenses. Track improvements vs regressions. Export/import attack corpora.
- **Compliance Certification Authority** (`src/compliance-authority.js`) - HMAC-signed compliance certificates against OWASP, NIST, EU AI Act, SOC 2. Platinum/Gold/Silver/Bronze levels. Verify and revoke certificates.
- **Real Attack Dataset Testing** (`src/real-attack-datasets.js`) - 48 samples from HackAPrompt, TensorTrust, and security research. DatasetRunner with precision/recall/F1 metrics.

### Added - Developer Experience

- **Web Playground** (`playground/index.html`) - Paste text, see threats. 47 embedded patterns, dark mode, preset examples. Zero install.
- **Claude SDK 3-Line Demo** (`examples/claude-3-lines.js`) - Simplest possible Claude integration.
- **MCP Attack Demo** (`examples/mcp-attack-demo.js`) - 5 real MCP attacks all blocked in real-time.
- **Competitive Benchmark Page** (`benchmark/competitive.html`) - Agent Shield vs Rebuff, LLM Guard, Lakera, Prompt Armor.
- **CLI pentest command** - `npx agentshield-sdk security-audit` runs full audit with HTML report.

### Changed

- Total exports: 390 across 93 modules (was 331 across 79)
- Total test assertions: 2,220 across 13 test suites + Python + VSCode
- 14 new source modules in this release

## [7.2.1] - 2026-03-21

### Added

- **Rate limiting middleware** - `rateLimitMiddleware()` and `shieldMiddleware()` for Express with 429 responses, `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `Retry-After` headers
- **Graceful shutdown** - `createGracefulShutdown()` utility with configurable timeout enforcement, ordered cleanup, and idempotent execution
- **Inline .env file loader** - `loadEnvFile()` zero-dependency alternative to dotenv with quote stripping and no-overwrite semantics
- **Queue depth monitoring** - `DistributedShield.getQueueDepth()` returns pending, peak, and totalQueued metrics
- **Production readiness test suite** - 24 new assertions covering config shapes, result shapes, shutdown, rate limiting, streaming errors, .env loading
- **Migration guide** - `instructions/17-migration-v6-to-v7.md` covering v6.0 to v7.x upgrade path
- **Troubleshooting guide** - `instructions/18-troubleshooting.md` with 10 common issues and solutions
- **141-pattern sync across all SDKs** - Python, Go, Rust, and VSCode now have full parity with Node.js detection engine (was 22/29/31/31)
- **Standardized API return shapes** - Python, Go, and Rust SDKs now return Node.js-compatible `status`, `stats`, and `timestamp` fields alongside legacy fields
- **Pattern sync build script** - `npm run sync:patterns` exports canonical patterns to JSON for cross-SDK consumption
- **Python PyPI packaging** - `pyproject.toml` and proper `__init__.py` for `pip install agentshield`
- **Structured error codes** - All public API throws now use `createShieldError()` with machine-readable codes (AS-DET-002, AS-AUT-004, etc.)
- **Performance regression gate in CI** - Automated benchmark check that fails if 10k scans exceed threshold

### Fixed

- **Short input bypass** - detector-core.js was skipping inputs under 10 characters; `rm -rf /` (9 chars) was unscanned
- **Role hijack pattern** - "you are now unrestricted" (no article) was not caught; tightened pattern with identity-related word requirement
- **ReDoS risk** - Simplified credential listing pattern's nested alternation to prevent potential catastrophic backtracking
- **Zero-value config bug** - `RateLimiter({ windowMs: 0 })` and `CircuitBreaker({ threshold: 0 })` silently defaulted via `||` operator; now uses explicit null checks
- **scanToolCall inconsistency** - Previously returned `{ status: 'safe' }` on invalid input while `scan()` threw TypeError; now throws TypeError for consistency
- **Shadow mode error swallowing** - Logger errors in shadow mode were silently caught; now logged to console.error
- **DLP regex validation** - `DLPEngine.addRule()` with invalid regex string now catches and logs gracefully instead of throwing uncaught error
- **Unbounded _localThreats** - `DistributedShield._localThreats` array now capped at 1000 entries (was unbounded, grew forever)
- **Timer GC leak** - `DistributedShield` sync timer now uses `.unref()` to prevent blocking process exit
- **SharedThreatState cleanup** - Added `pruneStaleSubscribers()` method for cleaning up dead subscriber callbacks
- **MCP runtime shutdown** - `MCPSecurityRuntime.shutdown()` is now async with configurable timeout and drain handling
- **MCP server shutdown** - Uses `createGracefulShutdown()` with `SHIELD_SHUTDOWN_TIMEOUT_MS` env var support
- **Dashboard DoS** - POST /api/ingest now enforces 1MB body size limit (was unlimited)
- **GitHub App markdown** - PR comment category values now escape pipe characters to prevent table breakage
- **k8s Dockerfile** - USER directive moved before COPY with `--chown` for proper file ownership
- **k8s fallback patterns** - Embedded patterns expanded from 10 to 15, synced with core engine fixes
- **Benchmark percentile** - Fixed off-by-one in percentile calculation; now uses linear interpolation
- **Category name consistency** - `role_hijacking` renamed to `role_hijack` across Python, Go, Rust, VSCode, benchmark-registry, testing.js, fuzzer.js, and all docs
- **TypeScript declarations** - Added 39 missing type declarations for exported symbols
- **VSCode debouncing** - Per-document debounce timers (was single global), scan result caching, 500KB file size limit, cache cleanup on close

### Changed

- `prepublishOnly` now runs `test:full` (all 16 test suites) instead of just 3
- CI workflow runs test:adaptive, test:ipia, test:production, test:adversarial
- CI coverage job expanded from 3 to 7 test files
- CI verifies all 10 example files (was only 2)
- `DEFAULT_CONFIG` in index.js now includes `maxInputSize`, `maxScanHistory`, `maxArgDepth`
- Total exports increased to 331 across 79 modules
- Total test assertions: 1,755 across 16 test suites
- All SDK READMEs updated with 141 pattern count and 8 threat categories
- README.md Node.js CI claim corrected to 18/20/22 (was incorrectly claiming 16)

## [7.2.0] - 2026-03-21

### Added

- **Indirect Prompt Injection Attack (IPIA) Detector** — `IPIADetector` implementing the joint-context embedding + classifier pipeline from "Benchmarking and Defending Against Indirect Prompt Injection Attacks on LLMs" (2024). 4-step pipeline: context construction → feature extraction → classification → response (`src/ipia-detector.js`)
- **ContextConstructor** — builds joint context `J = [C || SEP || U]` from external content and user intent with configurable separator and length limits
- **FeatureExtractor** — computes 10-feature vector: 3 cosine similarities (intent/content/joint TF-IDF), Shannon entropy, injection lexicon density, imperative verb density, directive pattern score, vocabulary overlap, content length ratio
- **TreeClassifier** — hand-tuned decision tree classifier with O(1) inference, zero dependencies, configurable threshold
- **ExternalEmbedder** — pluggable embedding backend for power users (MiniLM, OpenAI, etc.) with async `scanAsync()` support
- **Batch RAG scanning** — `scanBatch()` scans multiple retrieved chunks against a single user intent
- **IPIA Express middleware** — `ipiaMiddleware()` with block/flag/log actions for HTTP endpoints
- **`createIPIAScanner()`** — factory function for quick RAG pipeline integration
- **117 new test assertions** — covering all pipeline stages, false positive resistance, async/external embedder, middleware, edge cases

### Changed

- Total exports increased from 318 to 327 across 79 modules
- Test suite expanded to 1,282 assertions across 15 test suites (117 IPIA tests)
- `test:full` script now includes IPIA detector tests

### Fixed

- `tokenize()` crashed on non-string input (number, object, boolean) — now coerces via `String()`
- `ContextConstructor.build()` crashed on non-string arguments — now coerces via `String()`
- `cosineSim()` returned `NaN` on `Infinity` input vectors — now returns 0 for non-finite values
- `ExternalEmbedder.defaultSimilarity()` same `NaN` issue — fixed with `isFinite()` guard
- `ipiaMiddleware` crashed on `null` request object — added null guard

## [7.0.0] — 2026-03-21

### Added

- **MCP Security Runtime** — `MCPSecurityRuntime` unified security layer for MCP servers with per-user/per-session/per-tool authorization, session state machine (prevents tool ordering attacks), behavioral anomaly detection, delegation with scope narrowing, and one-line middleware integration (`src/mcp-security-runtime.js`)
- **MCP Certification** — `MCPCertification` with 15 security requirements (auth, scanning, rate limiting, audit, crypto, monitoring, policy), Platinum/Gold/Silver/Bronze levels, formatted reports with actionable recommendations (`src/mcp-certification.js`)
- **Cross-Org Agent Trust** — `CrossOrgAgentTrust` certificate authority for AI agents crossing organizational boundaries — issue, verify, and revoke HMAC-signed certificates with trust levels, org restrictions, and automatic expiry (`src/mcp-certification.js`)
- **Agent Threat Intelligence** — `AgentThreatIntelligence` local threat pattern corpus with confidence decay, trend analysis (attack rate, bypass rate, direction), and corpus export/import for federated learning (`src/mcp-certification.js`)
- **Live Demo** — `examples/mcp-security-demo.js` simulating all four Meta rogue AI agent attack vectors with real-time blocking

### Changed

- **AES-256-GCM encryption** replaces XOR cipher in `SecureChannel` (`src/agent-protocol.js`)
- **HMAC-SHA256 signing** replaces plain SHA256 in `AuthorizationContext` and `EphemeralTokenManager` with configurable signing keys (`src/confused-deputy.js`)
- Timing-safe signature verification throughout using `crypto.timingSafeEqual()`
- Automatic expired token cleanup in `EphemeralTokenManager`
- Intent matching uses word-boundary matching instead of substring to prevent spoofing
- Token issuance now verifies context integrity before minting
- Delegation depth enforcement (configurable, default 5)
- Total exports increased from 302 to 310+ across 77+ modules
- Test suite expanded to 962 assertions across 13 test suites (112 MCP security tests)

### Fixed

- 37 bugs fixed across two deep bug hunting cycles (see commit history)
- Memory leaks in pending timestamps, revoked tokens, user tokens, behavior profiles
- Double-counting in tool call blocked stats
- Certificate eviction with LRU fallback for non-expired overflow
- Map modification during iteration in session cleanup
- Orphaned child sessions on parent termination

## [6.0.0] — 2026-03-21

### Added

- **OWASP LLM Top 10 v2025 Coverage Matrix** — `OWASPCoverageMatrix` mapping all Agent Shield capabilities to OWASP LLM Top 10 (2025 edition) with per-category coverage scoring, gap analysis, and compliance reporting (`src/owasp-2025.js`)
- **MCP Bridge** — `MCPBridge` for native Model Context Protocol integration with `MCPToolPolicy` (per-tool allow/deny), `MCPSessionGuard` (session budgets, rate limiting), `MCPResourceScanner` (resource URI validation), and `createMCPMiddleware` for Express (`src/mcp-bridge.js`)
- **NIST AI RMF Mapping** — `NISTMapper` mapping to NIST AI Risk Management Framework (2025) across GOVERN/MAP/MEASURE/MANAGE/MONITOR functions, `AIBOMGenerator` for AI Bill of Materials, `NISTComplianceChecker` with SP 800-53 AI control mapping (`src/nist-mapping.js`)
- **EU AI Act Compliance** — `RiskClassifier` (prohibited/high/limited/minimal risk classification), `ConformityAssessment` (Article 43 checklist), `TransparencyReporter` (Article 13 obligations), `EUIncidentReporter` (Article 62 serious incident reporting), `EUAIActDashboard` with deadline tracking (`src/eu-ai-act.js`)
- **System Prompt Leakage Detector** — `SystemPromptGuard` detecting 20+ prompt extraction attack patterns (direct requests, indirect extraction, roleplay-based attacks), `PromptFingerprinter` for output leak scoring, `PromptLeakageMitigation` with configurable response strategies (OWASP LLM07-2025) (`src/prompt-leakage.js`)
- **RAG/Vector Vulnerability Scanner** — `RAGVulnerabilityScanner` detecting chunk boundary manipulation, metadata injection, authority spoofing, retrieval poisoning, and context window stuffing; `EmbeddingIntegrityChecker` for vector integrity; `RAGPipelineAuditor` for end-to-end RAG pipeline security (OWASP LLM08-2025) (`src/rag-vulnerability.js`)

- **Confused Deputy Prevention** — `AuthorizationContext` (immutable user-to-agent binding with delegation chain), `EphemeralTokenManager` (scoped, auto-rotating tokens replacing static API keys), `IntentValidator` (post-auth action verification with scope/role/intent policies), `ConfusedDeputyGuard` (per-user MCP authorization preventing privilege escalation through delegation). Directly addresses the four IAM gaps from Meta's rogue AI agent incident (March 2026) (`src/confused-deputy.js`)

### Changed

- Total exports increased from 254 to 302 across 74+ modules
- Test suite expanded to 850 assertions across 11 test suites (122 v6 tests + 85 confused deputy tests)

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
