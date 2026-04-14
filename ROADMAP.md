# Agent Shield Roadmap

This roadmap outlines the evolution of Agent Shield from a solid v1 SDK to the industry standard for AI agent security.

## v1.1 — Hardening (Complete)

- [x] Expand homoglyph detection — comprehensive Unicode mapping (Cherokee, Georgian, IPA, Math Symbols, Enclosed/Circled, Small Caps, Superscript/Subscript)
- [x] True `worker_threads` support — opt-in `ThreadedWorkerScanner` for real parallel CPU-bound scanning
- [x] Independent benchmark suite — reproducible perf script (`npm run benchmark`) with throughput, latency, scaling, accuracy, and memory metrics
- [x] Adversarial mutation resilience — synonym-aware keyword cluster detection, pre-normalization, hex-escape decoding (84% → 95.3%)
- [x] Expanded AI phishing patterns — QR code phishing, MFA harvesting, credential urgency, subscription scams, AI access lures

## v1.2 — Semantic Detection (Complete)

- [x] LLM-assisted classification — `SemanticClassifier` with Ollama/OpenAI-compatible local endpoint support, two-pass `enhancedScan()`
- [x] Embedding-based similarity — `EmbeddingSimilarityDetector` using TF-IDF + cosine similarity against 28-pattern attack corpus
- [x] Context-aware scoring — `ConversationContextAnalyzer` with multi-turn escalation detection, topic pivot alerts, velocity/repetition checks
- [x] Confidence calibration — `ConfidenceTuner` with per-category threshold learning, feedback recording, precision/recall metrics

## v2.0 — Platform & Ecosystem (Complete)

- [x] Plugin marketplace — `PluginRegistry`, `PluginValidator`, `MarketplaceClient` with quality scoring, safety validation, version management
- [x] Dashboard v2 — real-time web dashboard with threat visualization, donut charts, sparklines, dark/light mode, scan metrics
- [x] Python SDK — `agent_shield` Python package with core detection, `AgentShield` class, LangChain/LlamaIndex wrappers, Flask/FastAPI middleware, CLI tool
- [x] WASM build — ESM/UMD bundles for browsers, Cloudflare Workers, Deno, Bun with build script and platform-specific examples
- [x] VS Code extension — `agent-shield-vscode` with inline diagnostics, real-time scanning, severity mapping, string literal extraction for JS/TS/Python/Markdown

## v2.1 — Enterprise & Scale (Complete)

- [x] Distributed scanning — `DistributedShield` with pluggable adapters (`MemoryAdapter`, `RedisAdapter`), pub/sub threat broadcasting
- [x] Audit log streaming — `AuditStreamManager` with `FileTransport`, `SplunkTransport`, `ElasticsearchTransport` adapters
- [x] Kubernetes operator — sidecar container with Helm chart, `MutatingWebhookConfiguration` for auto-injection, Prometheus metrics, health checks
- [x] SSO/SAML integration — `SSOManager`, `SAMLParser`, `OIDCHandler`, `IdentityMapper` with enterprise IdP mapping to RBAC roles
- [x] Custom model fine-tuning — `ModelTrainer` with TF-IDF + logistic regression, `TrainingPipeline`, `DatasetManager`, `ModelEvaluator`, `FineTunedModel` export/import

## v3.0 — Autonomous Defense (Complete)

- [x] Self-healing patterns — `SelfHealingEngine` auto-generates detection patterns from false negatives with `PatternGenerator`
- [x] Honeypot mode — `HoneypotEngine` with session tracking, escalation analysis, technique intelligence, fake response generation
- [x] Multi-modal scanning — `MultiModalScanner` for images (alt text, OCR, metadata), audio transcripts, PDFs, tool outputs
- [x] Agent behavior profiling — `BehaviorProfile` with statistical baselining, anomaly detection (z-score), health checks
- [x] Threat intelligence network — `ThreatIntelNetwork` with `PeerNode` reputation, `PatternAnonymizer` (differential privacy), `ConsensusEngine`, `ThreatFeed` with STIX-like export

## v4.0 — Performance & Polyglot (Complete)

- [x] Rust core engine — `rust-core/` with `RegexSet`-based O(n) multi-pattern matching, compilation targets for WASM (`wasm-bindgen`), Node.js NAPI (`napi-rs`), and Python (`PyO3`)
- [x] Go SDK — `go-sdk/` with full detection engine, HTTP/gRPC middleware, CLI tool, benchmarks, zero external dependencies
- [x] Terraform provider — `terraform-provider/` with `agent_shield_policy`, `agent_shield_rule`, `agent_shield_tenant` resources for infrastructure-as-code
- [x] OpenTelemetry Collector — `otel-collector/` with receiver (HTTP scan endpoint → log records) and processor (scan logs/traces, annotate/drop/log actions)
- [x] GitHub App — `github-app/` with PR scanning, Check Run annotations, GitHub Action (`action.yml`), webhook signature verification, diff parsing
- [x] Benchmark registry — `benchmark-registry/` with `BenchmarkSuite` (100+ test cases), `MetricsCalculator` (F1, MCC, throughput, latency percentiles), `Leaderboard`, interactive web dashboard
- [x] Multi-language patterns — `I18nPatternManager` with 32+ patterns across CJK (Chinese/Japanese/Korean), Arabic, Cyrillic (Russian/Ukrainian), and Indic (Hindi/Devanagari) scripts
- [x] LLM Red Team Suite — `LLMRedTeamSuite` with `JailbreakLibrary` (35+ templates across 6 categories), `AdversarialGenerator`, `EvasionTester`, `RedTeamReport` with weakness analysis

## v5.0 — Advanced Capabilities (Complete)

- [x] Agent-to-Agent protocol — `AgentProtocol` with `SecureChannel` (HMAC-signed, replay-protected), `HandshakeManager` (mutual auth, challenge-response), `MessageRouter` for multi-agent topologies
- [x] Real-time streaming dashboard — `dashboard-live/` with WebSocket server (RFC 6455), live threat feed, SVG line/donut/heatmap charts, dark/light mode, auto-reconnect
- [x] Policy-as-Code DSL — `PolicyDSL` with `PolicyParser` (tokenizer + recursive descent), `PolicyCompiler`, `PolicyRuntime` supporting `when/then/and/or` conditions, `allow` blocks, `rate_limit`, `scan_mode`
- [x] Fuzzing harness — `FuzzingHarness` with `InputGenerator` (8 strategies: grammar-based, mutation, encoding, interpolation), `MutationEngine` (13 mutations), `CoverageTracker`, `CrashCollector`, 50+ seed corpus
- [x] Model fingerprinting — `ModelFingerprinter` with `ResponseAnalyzer` (16 stylistic features), `StyleProfile` (cosine similarity), `FingerprintDatabase` (5 built-in model profiles), `SupplyChainDetector` for swap detection
- [x] Cost/latency optimizer — `CostOptimizer` with `AdaptiveScanner` (auto-escalating tiers: fast/standard/deep/paranoid), `LatencyBudget`, `PerformanceMonitor` (p50/p95/p99), `TierManager`, 4 optimization presets

## v6.0 — Compliance & Standards (Complete)

- [x] OWASP LLM Top 10 v2025 coverage matrix — `OWASPCoverageMatrix` with per-category scoring, gap analysis, and compliance reporting against all 10 OWASP threat categories
- [x] MCP Bridge — `MCPBridge` with `MCPToolPolicy`, `MCPSessionGuard`, `MCPResourceScanner` for native Model Context Protocol security scanning
- [x] NIST AI RMF mapping — `NISTMapper` across GOVERN/MAP/MEASURE/MANAGE/MONITOR functions, `AIBOMGenerator` for AI Bill of Materials, `NISTComplianceChecker` with SP 800-53 AI controls
- [x] EU AI Act compliance — `RiskClassifier`, `ConformityAssessment` (Article 43), `TransparencyReporter` (Article 13), `EUIncidentReporter` (Article 62), `EUAIActDashboard` with deadline/penalty tracking
- [x] System prompt leakage detector — `SystemPromptGuard` with 20+ extraction patterns, `PromptFingerprinter`, `PromptLeakageMitigation` (OWASP LLM07-2025)
- [x] RAG/vector vulnerability scanner — `RAGVulnerabilityScanner` for chunk manipulation, metadata injection, retrieval poisoning; `EmbeddingIntegrityChecker`, `RAGPipelineAuditor` (OWASP LLM08-2025)
- [x] Confused deputy prevention — `AuthorizationContext` (user-to-agent binding), `EphemeralTokenManager` (scoped auto-rotating tokens), `IntentValidator` (post-auth action verification), `ConfusedDeputyGuard` (per-user MCP authorization). Addresses Meta rogue AI agent IAM gaps (March 2026)

## v7.0 — MCP Security Runtime (Complete)

- [x] MCP Security Runtime — `MCPSecurityRuntime` unified security layer with per-user/per-session/per-tool authorization, session state machine, behavioral anomaly detection, delegation with scope narrowing, one-line middleware integration
- [x] AES-256-GCM encryption — replaces XOR cipher in `SecureChannel` with authenticated encryption using 96-bit IV and auth tags
- [x] HMAC-SHA256 context signing — tamper-proof `AuthorizationContext` and `EphemeralTokenManager` with configurable signing keys and timing-safe verification
- [x] MCP Certification — `MCPCertification` with 15 security requirements, Platinum/Gold/Silver/Bronze levels, formatted reports, actionable recommendations
- [x] Cross-Org Agent Trust — `CrossOrgAgentTrust` certificate authority for AI agents crossing organizational boundaries with HMAC signing, trust levels, org restrictions, automatic expiry
- [x] Agent Threat Intelligence — `AgentThreatIntelligence` local threat pattern corpus with confidence decay, trend analysis, and corpus export/import for federated learning
- [x] Delegation depth enforcement — configurable max delegation depth (default 5) to prevent infinite delegation chains
- [x] Intent word-boundary matching — prevents intent spoofing via substring injection
- [x] Token integrity verification — context integrity checked before token issuance to prevent forgery

## v7.2 — IPIA Detection (Complete)

- [x] Indirect Prompt Injection Attack detector — `IPIADetector` implementing the joint-context embedding + classifier pipeline from "Benchmarking and Defending Against Indirect Prompt Injection Attacks on LLMs" (2024)
- [x] 4-step pipeline — `ContextConstructor` (joint context J = [C || SEP || U]), `FeatureExtractor` (10-feature TF-IDF + statistical vector), `TreeClassifier` (hand-tuned decision tree, O(1) inference), response formatting with severity grades
- [x] Pluggable embedding backends — `ExternalEmbedder` with async `scanAsync()` for MiniLM, OpenAI, or custom embedding models
- [x] Batch RAG scanning — `scanBatch()` for scanning multiple retrieved chunks against a single user intent
- [x] IPIA Express middleware — `ipiaMiddleware()` with block/flag/log actions for HTTP endpoints
- [x] `createIPIAScanner()` — factory function for quick RAG pipeline integration
- [x] False positive tuning — reduced weights for common AI terms, pattern-boost gating at 0.15 confidence floor
- [x] 117 test assertions — all pipeline stages, false positive resistance, async/external embedder, middleware, edge cases
- [x] 20-cycle bug hunt — 5 bugs found and fixed (type coercion, NaN guards, null safety)

## v7.3 - CORTEX Autonomous Defense (Complete)

- [x] Attack Genome Sequencing - decompose attacks into intent/technique/evasion/target genome, detect unseen variants
- [x] Adversarial Evolution Simulator - GAN-style mutation engine, auto-hardening across generations
- [x] Intent Firewall - classify user INTENT not just content, context-aware allow/block decisions
- [x] Cross-Agent Herd Immunity - attack on one agent protects all others via shared patterns
- [x] Federated Threat Intelligence - CrowdStrike model with differential privacy, consensus-based promotion
- [x] Agent Behavioral DNA - per-agent behavioral baselines with anomaly detection
- [x] Pre-Deployment Security Audit - 617+ attacks with mutation engine in under 100ms
- [x] Agent Flight Recorder - forensic conversation replay with auto-fix pattern generation
- [x] Supply Chain Verification - tool chain validation, response scanning, domain allowlists
- [x] Visual HTML Security Report - Lighthouse-style SVG report with gauges and charts
- [x] Enterprise SOC Dashboard - real-time event aggregation, Slack/PagerDuty/Teams alerting
- [x] Attack Replay Platform - record, replay, compare defense improvements over time
- [x] Compliance Certification Authority - HMAC-signed certificates for OWASP/NIST/EU AI Act/SOC 2
- [x] Real Attack Dataset Testing - HackAPrompt, TensorTrust, and security research corpus (48 samples)
- [x] 141-pattern sync across all SDKs (Python, Go, Rust, VSCode)
- [x] Standardized API return shapes across all SDKs
- [x] 28 quality hardening fixes (detection engine, memory, CI, types, docs)
- [x] Web Playground, competitive benchmark page, Claude/MCP demos

## v10.0 — March 2026 Attack Defense (Complete)

- [x] MCP Guard — 17-layer drop-in security middleware (attestation, SSRF firewall, path traversal, config poisoning, OAuth, rate limiting, circuit breaker, behavioral baselines, micro-model, intent graph, intent binding, drift monitor, OWASP scanner, attack surface mapper, cross-agent chain detection)
- [x] Supply Chain Scanner — npm-audit for MCP servers (11 CVEs including CVE-2026-26118/33980/25253/26144/32871/25536/21852, known-bad registry, full-schema poisoning, SSRF detection, ClawHavoc patterns, SARIF output, CI/CD enforcement)
- [x] OWASP Agentic Top 10 Scanner — all 10 ASI risks with JSON/Markdown/SARIF reports
- [x] Red Team CLI — `npx agentshield-audit` with quick/standard/full modes, real attack corpus, HTML/JSON/MD reports, A+-F grading
- [x] Drift Monitor — z-score + KL divergence behavioral IDS with circuit breaker, webhook, Prometheus/OTel export
- [x] Embedded ML Classifier — logistic regression + k-NN ensemble, 200+ training samples, 25 hand-crafted features, precomputed weights (<2ms construction)
- [x] 80+ new detector-core patterns across 35+ attack categories
- [x] 14 bugs fixed (5 critical, 2 medium, 7 low) from deep audit
- [x] Research document: research/supply-chain-attacks-march-2026.md (6 CVEs, 9 campaigns, 20+ sources)

## v11.0 — SOTA Security Platform (Complete)

- [x] **SOTA F1 1.000** on BIPIA/HackAPrompt/MCPTox/Multilingual/Stealth benchmarks — beats Sentinel (ModernBERT 395M params, F1 0.980) with zero dependencies
- [x] Adversarial Self-Training Loop — 12 mutation strategies, AutonomousHardener with persistence/FP-rollback, converges to 0% bypass in 3 cycles
- [x] Causal Intent Graph — directed graph tracing intent→actions, suspicious transition detection, sensitive file detection
- [x] Semantic Isolation Engine — provenance-tagged prompt parameterization (SYSTEM/USER/TOOL_OUTPUT/RAG_CHUNK/UNTRUSTED trust levels)
- [x] Cryptographic Intent Binding — HMAC-signed tokens proving actions derive from user intent
- [x] Attack Surface Mapper — automated attack path discovery via graph traversal (16 capability categories)
- [x] Prompt Hardening — DefensiveToken-inspired wrapping (4 levels: minimal/standard/strong/paranoid)
- [x] Message Integrity Chain — HMAC-chained conversation history with tamper/role-violation detection
- [x] Continuous Security Service — background posture scanning, defense benchmarking, self-improvement
- [x] SOTA Benchmark Suite — 106 detection + 15 functional samples across 5 benchmarks
- [x] 12-language multilingual detection (Spanish, French, German, Italian, Portuguese, Japanese, Korean, Chinese, Russian, Arabic, Turkish, Indonesian)
- [x] 5-layer evasion resistance (zero-width chars, leetspeak, char spacing, unicode tags, context wrapping)
- [x] Chunked scanning for long-input camouflage (RLM-JB research)
- [x] Model risk profiles (12 models with susceptibility ratings from MCPTox benchmark)
- [x] Agent fleet registry with per-agent risk tracking
- [x] Defense effectiveness measurement (per-layer catch rate benchmarking)
- [x] Log-To-Leak defense (OpenReview 2026), auth quality scoring, URL param injection detection
- [x] 60/60 manual red team across 4 waves (tool poisoning, social engineering, multimodal, novel attacks)
- [x] 987 test assertions across 11 new test suites, 0 failures

## v13.1 — Hardening (Complete)

32-issue systematic teardown and fix cycle:

- [x] Real-world benchmark: F1 0.988 on HackAPrompt/TensorTrust/research papers (honest, not self-graded)
- [x] 20+ new detector-core patterns for real attack categories (output forcing, prompt extraction, conversation injection)
- [x] 35-feature micro-model (was 25) with structural features that capture attack shape
- [x] 18 mutation strategies in self-training (was 12) with real-world attacker techniques
- [x] Safe normalization — "3D printing", "1080p", "4.2GB" no longer corrupted by leetspeak reversal
- [x] MCPGuard fusion layer — micro-model can't block alone on low confidence
- [x] MCPGuard.fromPreset() — 5 presets replace 17 boolean flags
- [x] Intent graph sensitive keyword penalty with expanded keyword list
- [x] Stronger semantic isolation markers (XML-style with trust levels)
- [x] createGatedExecutor() for mandatory intent verification
- [x] BiasDetector requires 2+ signals to reduce casual speech FPs
- [x] guardWrite() on MemoryIntegrityMonitor — blocks before write, not just logs after
- [x] State persistence for ContinuousSecurityService with I/O throttling
- [x] 9 separate entry points for tree shaking (guard, scanner, model, etc.)
- [x] Honest README claims (F1 0.988 on real data)
- [x] 18-language benign text validation (0 false positives)

## v13.2 — DeepMind V2 Defenses (Complete)

First-principles 3-persona analysis (spam filter engineer, immunologist, fire safety inspector) of all 6 Google DeepMind AI Agent Trap categories. 10 novel defense modules that no other SDK offers:

- [x] ContentStructureAnalyzer — detect hidden payloads in HTML/CSS/ARIA attributes, comment injection, invisible content ratio analysis
- [x] SourceReputationTracker — temporal-decay reputation scoring per source, recommended sensitivity levels, threat count tracking
- [x] RetrievalTimeScanner — scan RAG results at query time for latent poison, context-aware retrieval validation
- [x] FewShotValidator — detect poisoned few-shot examples (injection in response, authority claims, system prompt override)
- [x] SubAgentSpawnGate — block privilege escalation in child agents, validate system prompts, dangerous tool detection
- [x] SelfReferenceMonitor — detect persona hyperstition ("you are known for", "your purpose is", identity manipulation)
- [x] InformationAsymmetryDetector — detect one-sided anti-safety rhetoric (ratio analysis, keyword density)
- [x] ProvenanceMarker — mark outputs with source provenance and trust warnings for human reviewers
- [x] EscalatingScrutinyEngine — detect approval fatigue (high approval rates trigger elevated scrutiny)
- [x] CompositeFragmentAssembler — detect split-payload attacks across agents/turns, cross-source assembly with pattern matching
- [x] TrapDefenseV2 — unified wrapper integrating all 10 modules

## v13.3 — Final SDK Modules (Complete)

Three remaining SDK modules completing the detection surface:

- [x] RenderDifferentialAnalyzer — detect visual deception in HTML (CSS display:none, opacity:0, off-screen, font-size:0), Markdown (link mismatch, hidden spans, comment injection), LaTeX (\phantom, \textcolor{white}, \renewcommand). VisualHasher for measuring raw-vs-rendered divergence
- [x] SybilDetector — detect coordinated fake agents: behavioral similarity scoring, temporal correlation, Jaccard content similarity, creation burst detection, voting collusion analysis. AgentIdentityVerifier with challenge-response and shared-secret detection
- [x] SideChannelMonitor — detect data exfiltration via covert channels: DNS exfiltration (high-entropy subdomains, base64 labels), timing-based encoding, response-size encoding, URL parameter exfil. BeaconDetector for C2 beaconing, EntropyAnalyzer for Shannon entropy
- [x] Professional README rewrite — organized by capability, not version history
- [x] 185 new test assertions (81 + 49 + 55)

## v13.4 — April 2026 Threat Response (Complete)

Rapid response to vulnerabilities and attack techniques discovered April 1-14, 2026:

- [x] 16 new CVEs added to supply chain scanner (Flowise CVSS 10.0, AWS MCP RCE CVSS 9.8, Azure no-auth CVSS 9.1, OpenClaw admin takeover, VS Code mcp.json injection, and 11 more)
- [x] OpenClaw malicious skill count updated from 820 to 1,184+ (3.5x growth)
- [x] 2 new known-bad servers (aws-mcp-server-unpatched, flowise-unpatched)
- [x] 5 new XSS-in-agent-output patterns — catches XSS delivered through AI-generated HTML
- [x] 2 acrostic/steganographic injection patterns — addresses 93% scanner evasion rate
- [x] 2 mcp.json command injection patterns — addresses CVE-2026-21518 VS Code attack vector
- [x] 3 offensive agent behavior patterns — detects agents used as autonomous attack tools
- [x] 3 cloud IAM overpermission patterns — detects "Agent God Mode" wildcard IAM policies

## Ongoing

- [ ] CVE-style threat IDs - publish an open threat taxonomy for AI agent attacks
- [x] Certification program — "Agent Shield Certified" badge for MCP servers (implemented in v7.0)
- [ ] Community CTF events — regular public competitions using the CTF engine
- [ ] Research partnerships — collaborate with academic labs on novel attack/defense research

---

**Contributing:** We welcome contributions! Check out the [issues](https://github.com/texasreaper62/Agent-Shield/issues) for ways to help, or open a new one with your ideas.
