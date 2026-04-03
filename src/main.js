'use strict';

/**
 * Agent Shield — Unified Entry Point
 *
 * Import everything from a single module:
 *   const shield = require('agent-shield');
 *
 * Each module is loaded safely — if one fails, the rest still work.
 */

/**
 * Safely require a module. Returns its exports or an empty object on failure.
 * @param {string} path - Module path
 * @param {string} label - Label for error logging
 * @returns {object}
 */
function safeRequire(path, label) {
  try {
    return require(path);
  } catch (err) {
    console.warn(`[Agent Shield] Failed to load ${label}: ${err.message}`);
    return {};
  }
}

// Core (these are critical — if they fail, we still export what we can)
const { AgentShield } = safeRequire('./index', 'core');
const { scanText, getPatterns, SEVERITY_ORDER } = safeRequire('./detector-core', 'detector-core');
const { expressMiddleware, wrapAgent, shieldTools, extractTextFromBody, rateLimitMiddleware, shieldMiddleware } = safeRequire('./middleware', 'middleware');

// Protection
const { CircuitBreaker, shadowMode, RateLimiter, STATE } = safeRequire('./circuit-breaker', 'circuit-breaker');
const { CanaryTokens, PromptLeakDetector, API_KEY_PATTERNS } = safeRequire('./canary', 'canary');
const { PIIRedactor, DLPEngine, ContentPolicy, PII_PATTERNS, CONTENT_CATEGORIES } = safeRequire('./pii', 'pii');
const { ToolSequenceAnalyzer, PermissionBoundary, InputQuarantine, SUSPICIOUS_SEQUENCES } = safeRequire('./tool-guard', 'tool-guard');

// Conversation
const { FragmentationDetector, LanguageSwitchDetector, TokenBudgetAnalyzer, InstructionHierarchy, BehavioralFingerprint } = safeRequire('./conversation', 'conversation');

// Policy & Logging
const { loadPolicy, loadPolicyFile, StructuredLogger, WebhookAlert, LOG_LEVEL } = safeRequire('./policy', 'policy');

// Multi-Agent
const { AgentFirewall, DelegationChain, SharedThreatState } = safeRequire('./multi-agent', 'multi-agent');

// Advanced Detection
const { SteganographyDetector, EncodingBruteforceDetector, StructuredDataScanner, STEGO_PATTERNS } = safeRequire('./encoding', 'encoding');

// Watermarking & Privacy
const { OutputWatermark, DifferentialPrivacy } = safeRequire('./watermark', 'watermark');

// Utilities
const { getGrade, getGradeLabel, makeBar, truncate, formatHeader, generateId, createGracefulShutdown, loadEnvFile } = safeRequire('./utils', 'utils');

// Error codes & deprecation
const { ERROR_CODES, createShieldError, deprecationWarning } = safeRequire('./errors', 'errors');

// v7.0 — MCP Security Runtime
const { MCPSecurityRuntime, MCPSessionStateMachine, SESSION_STATES } = safeRequire('./mcp-security-runtime', 'mcp-security-runtime');

// v7.0 — Adaptive Defense
const { LearningLoop, AgentContract: BehaviorContract, ContractRegistry, ComplianceAttestor, ATTESTATION_FRAMEWORKS } = safeRequire('./adaptive-defense', 'adaptive-defense');

// v7.0 — MCP SDK Integration
const { shieldMCPServer, createMCPSecurityLayer } = safeRequire('./mcp-sdk-integration', 'mcp-sdk-integration');

// v7.0 — MCP Certification & Trust
const { AgentThreatIntelligence, MCPCertification, CrossOrgAgentTrust, THREAT_CATEGORIES: CERT_THREAT_CATEGORIES, CERTIFICATION_REQUIREMENTS, CERTIFICATION_LEVELS } = safeRequire('./mcp-certification', 'mcp-certification');

// v5.1 — Stream scanning
const { StreamScanner, createStreamWrapper, scanAsyncIterator, StreamBuffer } = safeRequire('./stream-scanner', 'stream-scanner');

// v5.1 — Immutable audit log
const { ImmutableAuditLog, AuditEntry, MemoryAuditStore, FileAuditStore, AuditProof, verifyAuditChain } = safeRequire('./audit-immutable', 'audit-immutable');

// v5.1 — Agent observability
const { PrometheusExporter, DatadogLogger, MetricsCollector: ObservabilityMetrics } = safeRequire('./observability', 'observability');

// v5.1 — Benchmark harness
const { BenchmarkHarness, DatasetLoader, BenchmarkMetrics, RegressionTracker, BenchmarkReportGenerator } = safeRequire('./benchmark-harness', 'benchmark-harness');

// Text Normalizer
const { TextNormalizer, normalize: normalizeText, HOMOGLYPH_MAP: NORMALIZER_HOMOGLYPH_MAP, LEET_MAP, DEFAULT_LAYERS } = safeRequire('./normalizer', 'normalizer');

// Integrations
const { ShieldCallbackHandler, shieldAnthropicClient, shieldOpenAIClient, shieldVercelAI, shieldFetch, ShieldBlockError } = safeRequire('./integrations', 'integrations');

// Red Team
const { AttackSimulator, PayloadFuzzer, getAttackCategories, getPayloads, ATTACK_PAYLOADS } = safeRequire('./redteam', 'redteam');

// Shield Score
const { ShieldScoreCalculator, SCORE_CATEGORIES } = safeRequire('./shield-score', 'shield-score');

// Benchmark Harness — imported above (line 69)

// Threat Encyclopedia
const { ThreatEncyclopedia, THREAT_ENCYCLOPEDIA, DAILY_PATTERNS } = safeRequire('./threat-encyclopedia', 'threat-encyclopedia');

// Compliance & Audit
const { ComplianceReporter, AuditTrail, IncidentPlaybook, SecurityChecklistGenerator, COMPLIANCE_FRAMEWORKS, INCIDENT_PLAYBOOKS } = safeRequire('./compliance', 'compliance');

// Enterprise
const { MultiTenantShield, RoleBasedPolicy, DebugShield, DEFAULT_ROLES } = safeRequire('./enterprise', 'enterprise');

// Badges
const { BadgeGenerator, GitHubActionReporter } = safeRequire('./badges', 'badges');

// Allowlist & Feedback
const { Allowlist, ConfidenceCalibrator, FeedbackLoop, ScanCache } = safeRequire('./allowlist', 'allowlist');

// Presets & Config Builder
const { PRESETS, ConfigBuilder, SnippetGenerator, getPresets, getPreset } = safeRequire('./presets', 'presets');

// v8.0 — Smart Config
const { ShieldBuilder, createShield, validateConfig, describeConfig, FEATURE_DEFAULTS, VALID_PRESETS } = safeRequire('./smart-config', 'smart-config');

// v8.0 — Ensemble Detection
const { EnsembleClassifier, PatternVoter, TFIDFVoter, EntropyVoter, IPIAVoter, VOTER_NAMES } = safeRequire('./ensemble', 'ensemble');

// v8.0 — Agent Intent & Goal Drift
const { AgentIntent, GoalDriftDetector, ToolSequenceModeler } = safeRequire('./agent-intent', 'agent-intent');

// v8.0 — Persistent Learning & Feedback
const { PersistentLearningLoop, FeedbackCollector } = safeRequire('./persistent-learning', 'persistent-learning');

// v8.0 — Cross-Turn & Adaptive Thresholds
const { CrossTurnTracker, AdaptiveThresholdCalibrator } = safeRequire('./cross-turn', 'cross-turn');

// v8.0 — Adversarial Self-Training
const { SelfTrainer, MutationEngine: SelfTrainingMutationEngine, SEED_ATTACKS, MUTATION_STRATEGIES } = safeRequire('./self-training', 'self-training');

// Advanced Scanners
const { RAGScanner, RAG_INJECTION_PATTERNS, PromptLinter, LINT_RULES, ToolSchemaValidator, DANGEROUS_TOOL_PATTERNS } = safeRequire('./scanners', 'scanners');

// Production
const { SamplingScanner, ShadowComparison, GracefulScanner, ThreatReplay, AttackAttributionChain, DiffReporter, PostureTracker } = safeRequire('./production', 'production');

// Testing & Contracts
const { TestSuiteGenerator, ATTACK_TEMPLATES, AgentContract, BreakglassProtocol } = safeRequire('./testing', 'testing');

// Multi-Agent Trust
const { MessageSigner, CapabilityToken, DelegationManager, BlastRadiusContainer } = safeRequire('./multi-agent-trust', 'multi-agent-trust');

// Extended Policy & Intelligence
const { ABTestRunner, ThreatIntelFeed, PatternBuilder, Doctor, GitHubActionGenerator, SOCIntegration, MigrationGuide, Playground } = safeRequire('./policy-extended', 'policy-extended');

// --- New Modules ---

// Streaming (legacy import — full import on line 60)
// StreamScanner, StreamBuffer, createStreamWrapper, scanAsyncIterator loaded above

// Plugin System
const { PluginManager, PluginTemplate, PluginSandbox } = safeRequire('./plugin-system', 'plugin-system');

// Token Analysis
const { EntropyAnalyzer, PerplexityEstimator, BurstDetector, TextStatistics } = safeRequire('./token-analysis', 'token-analysis');

// Document Scanner
const { DocumentScanner, TextExtractor, IndirectInjectionScanner } = safeRequire('./document-scanner', 'document-scanner');

// Tool Output Validator
const { ToolOutputValidator, OutputSanitizer } = safeRequire('./tool-output-validator', 'tool-output-validator');

// Response Handler
const { ResponseHandler, ResponseTemplates, ReviewQueue } = safeRequire('./response-handler', 'response-handler');

// Worker Scanner
const { WorkerScanner, ScanQueue, ThreadedWorkerScanner } = safeRequire('./worker-scanner', 'worker-scanner');

// Alert Tuning
const { AlertFatigueAnalyzer, AutoTuner, AlertCorrelator } = safeRequire('./alert-tuning', 'alert-tuning');

// OpenTelemetry
const { ShieldMetrics, ShieldTracer, MetricsDashboard } = safeRequire('./otel', 'otel');

// Certification
const { CertificationRunner, Certificate, CertificationHistory } = safeRequire('./certification', 'certification');

// MCP Server
const { MCPServer, MCPToolHandler } = safeRequire('./mcp-server', 'mcp-server');

// CTF
const { CTFEngine, CTFReporter, CHALLENGES } = safeRequire('./ctf', 'ctf');

// Observability — imported above (line 66)

// Adaptive Detection
const { AdaptiveDetector, SemanticAnalysisHook, CommunityPatterns } = safeRequire('./adaptive', 'adaptive');

// OpenClaw
const { OpenClawShieldSkill, shieldOpenClawMessages, generateOpenClawSkill } = safeRequire('./openclaw', 'openclaw');

// v8.0 — ML Detection (Pro/Enterprise)
const { MLShield, isMLTier, isValidTier, loadMLPackage, ML_ENABLED_TIERS, VALID_TIERS } = safeRequire('./ml-detector', 'ml-detector');

// v7.2 — IPIA Detector
const { IPIADetector, ContextConstructor, FeatureExtractor, TreeClassifier, ExternalEmbedder, createIPIAScanner, ipiaMiddleware, FEATURE_NAMES: IPIA_FEATURE_NAMES, INJECTION_LEXICON: IPIA_INJECTION_LEXICON } = safeRequire('./ipia-detector', 'ipia-detector');

// v7.2.1 — Pre-Deployment Audit
const { SecurityAudit, AuditReport, AUDIT_ATTACKS, generateMutations: auditMutations, runAuditCLI } = safeRequire('./audit', 'audit');

// v7.2.1 — Flight Recorder
const { FlightRecorder } = safeRequire('./flight-recorder', 'flight-recorder');

// v7.2.1 — HTML Report Generator
const { generateHTMLReport, generateReportFile } = safeRequire('./report-generator', 'report-generator');

// v7.3 — Supply Chain Verification
const { ToolChainValidator, ResponseScanner, DomainAllowlist, RESPONSE_INJECTION_PATTERNS, EXFILTRATION_URL_PATTERNS, CREDENTIAL_PATTERNS, CHAIN_SUSPICIOUS_PATTERNS } = safeRequire('./supply-chain', 'supply-chain');

// v7.4 — Herd Immunity
const { HerdImmunity, ImmuneMemory, createHerdNetwork } = safeRequire('./herd-immunity', 'herd-immunity');

// v7.4 — Adversarial Evolution Simulator
const { EvolutionSimulator, MutationEngine, hardenFromEvolution } = safeRequire('./evolution-simulator', 'evolution-simulator');

// v7.4 — Attack Replay Platform
const { AttackReplayEngine, compareDefenses } = safeRequire('./attack-replay', 'attack-replay');

// v7.4 — Enterprise SOC Dashboard
const { SOCDashboard, SlackAlertChannel, PagerDutyAlertChannel, TeamsAlertChannel } = safeRequire('./soc-dashboard', 'soc-dashboard');

// v7.4 — Attack Genome (loaded when available)
const { AttackGenome, GenomeDatabase, detectByGenome, INTENT_PATTERNS: GENOME_INTENT_PATTERNS, TECHNIQUE_PATTERNS: GENOME_TECHNIQUE_PATTERNS, EVASION_PATTERNS: GENOME_EVASION_PATTERNS, TARGET_PATTERNS: GENOME_TARGET_PATTERNS } = safeRequire('./attack-genome', 'attack-genome');

// v7.4 — Intent Firewall (loaded when available)
const { IntentFirewall, ContextAnalyzer: IntentContextAnalyzer, IntentRules, intentDemo, INTENT_CATEGORIES, INTENT_SIGNALS, CONTEXT_MODIFIERS } = safeRequire('./intent-firewall', 'intent-firewall');

// v7.4 — Real Attack Dataset Testing
const { DatasetRunner, HACKAPROMPT_SAMPLES, TENSORTRUST_SAMPLES, RESEARCH_SAMPLES, BENIGN_SAMPLES } = safeRequire('./real-attack-datasets', 'real-attack-datasets');

// v7.4 — Federated Threat Intelligence
const { ThreatIntelFederation, createFederationMesh } = safeRequire('./threat-intel-federation', 'threat-intel-federation');

// v7.4 — Behavioral DNA (loaded when available)
const { BehavioralDNA, AgentProfiler, extractFeatures: extractBehavioralFeatures, DEFAULT_NUMERIC_FEATURES, DEFAULT_CATEGORICAL_FEATURES } = safeRequire('./behavioral-dna', 'behavioral-dna');

// v7.4 — Compliance Certification Authority (loaded when available)
const { ComplianceCertificateAuthority, ComplianceReport: ComplianceCertReport, ComplianceScheduler, AUTHORITY_FRAMEWORKS, CAPABILITY_MAP: CA_CAPABILITY_MAP, CERTIFICATE_LEVELS: CA_CERTIFICATE_LEVELS } = safeRequire('./compliance-authority', 'compliance-authority');

// --- v1.2 Modules ---

// Semantic Detection
const { SemanticClassifier, httpPost } = safeRequire('./semantic', 'semantic');

// Embedding Similarity
const { EmbeddingSimilarityDetector, ATTACK_CORPUS, tokenize: tokenizeText, cosineSimilarity } = safeRequire('./embedding', 'embedding');

// Context-Aware Scoring
const { ConversationContextAnalyzer, ESCALATION_SIGNALS, TOPIC_PIVOT_SIGNALS } = safeRequire('./context-scoring', 'context-scoring');

// Confidence Tuning
const { ConfidenceTuner } = safeRequire('./confidence-tuning', 'confidence-tuning');

// --- v2.0 Modules ---

// Plugin Marketplace
const { PluginRegistry, PluginValidator, MarketplaceClient } = safeRequire('./plugin-marketplace', 'plugin-marketplace');

// --- v2.1 Modules ---

// Distributed Scanning
const { DistributedShield, DistributedAdapter, MemoryAdapter, RedisAdapter } = safeRequire('./distributed', 'distributed');

// Audit Log Streaming
const { AuditStreamManager, AuditTransport, FileTransport, SplunkTransport, ElasticsearchTransport } = safeRequire('./audit-streaming', 'audit-streaming');

// Immutable Audit Log — imported above (line 63)

// --- v3.0 Modules ---

// Self-Healing Patterns
const { SelfHealingEngine, PatternGenerator: SelfHealingPatternGenerator } = safeRequire('./self-healing', 'self-healing');

// Honeypot Mode
const { HoneypotEngine, HoneypotSession } = safeRequire('./honeypot', 'honeypot');

// Multi-Modal Scanning
const { MultiModalScanner, ModalityExtractor } = safeRequire('./multimodal', 'multimodal');

// Behavior Profiling
const { BehaviorProfile } = safeRequire('./behavior-profiling', 'behavior-profiling');

// --- Remaining Roadmap Modules ---

// SSO/SAML Integration
const { SSOManager, SAMLParser, OIDCHandler, IdentityMapper, SSOSession, DEFAULT_MAPPINGS: SSO_DEFAULT_MAPPINGS } = safeRequire('./sso-saml', 'sso-saml');

// Custom Model Fine-Tuning
const { ModelTrainer, TrainingPipeline, DatasetManager, ModelEvaluator, FineTunedModel } = safeRequire('./model-finetuning', 'model-finetuning');

// Threat Intelligence Network
const { ThreatIntelNetwork, PeerNode, PatternAnonymizer, ConsensusEngine, ThreatFeed, NETWORK_DEFAULTS } = safeRequire('./threat-intel-network', 'threat-intel-network');

// --- v4.0 Modules ---

// Multi-Language Patterns
const { I18nPatternManager, CJK_PATTERNS, ARABIC_PATTERNS, CYRILLIC_PATTERNS, INDIC_PATTERNS, MULTILINGUAL_PATTERNS, getI18nPatterns } = safeRequire('./i18n-patterns', 'i18n-patterns');

// LLM Red Team Suite
const { LLMRedTeamSuite, AdversarialGenerator, JailbreakLibrary, EvasionTester, RedTeamReport, JAILBREAK_TEMPLATES, MUTATION_TECHNIQUES } = safeRequire('./llm-redteam', 'llm-redteam');

// --- v5.0 Modules ---

// Agent-to-Agent Protocol
const { AgentProtocol, SecureChannel, HandshakeManager, AgentIdentity, ProtocolMessage, MessageRouter, PROTOCOL_VERSION } = safeRequire('./agent-protocol', 'agent-protocol');

// Policy-as-Code DSL
const { PolicyDSL, PolicyParser, PolicyCompiler, PolicyRuntime, PolicyValidator, BUILTIN_FUNCTIONS: DSL_BUILTINS, EXAMPLE_STRICT_POLICY, EXAMPLE_PERMISSIVE_POLICY, EXAMPLE_CUSTOM_RULES_POLICY } = safeRequire('./policy-dsl', 'policy-dsl');

// Fuzzing Harness
const { FuzzingHarness, InputGenerator, MutationEngine: FuzzMutationEngine, CoverageTracker, FuzzReport, CrashCollector, SEED_CORPUS } = safeRequire('./fuzzer', 'fuzzer');

// Model Fingerprinting
const { ModelFingerprinter, ResponseAnalyzer, StyleProfile, FingerprintDatabase, SupplyChainDetector, MODEL_SIGNATURES } = safeRequire('./model-fingerprint', 'model-fingerprint');

// Cost/Latency Optimizer
const { CostOptimizer, LatencyBudget, AdaptiveScanner, TierManager, PerformanceMonitor, ScanPlan, OPTIMIZATION_PRESETS } = safeRequire('./cost-optimizer', 'cost-optimizer');

// --- v6.0 — Compliance & Market Readiness ---

// OWASP LLM Top 10 v2025 Coverage Matrix
const { OWASP_LLM_2025, OWASPCoverageMatrix, SEVERITY_WEIGHTS: OWASP_SEVERITY_WEIGHTS, COVERAGE_MULTIPLIERS } = safeRequire('./owasp-2025', 'owasp-2025');

// MCP Bridge (Model Context Protocol integration)
const { MCPBridge, MCPToolPolicy, MCPSessionGuard, MCPResourceScanner, MCP_DANGEROUS_TOOLS, ARG_INJECTION_PATTERNS, createMCPMiddleware } = safeRequire('./mcp-bridge', 'mcp-bridge');

// NIST AI RMF Mapping & AI-BOM Generator
const { NIST_AI_RMF_2025, SP800_53_AI_CONTROLS, NISTMapper, AIBOMGenerator, ComplianceChecker: NISTComplianceChecker } = safeRequire('./nist-mapping', 'nist-mapping');

// EU AI Act Compliance
const { EU_AI_ACT_REQUIREMENTS, RiskClassifier, ConformityAssessment, TransparencyReporter, IncidentReporter: EUIncidentReporter, EUAIActDashboard } = safeRequire('./eu-ai-act', 'eu-ai-act');

// System Prompt Leakage Detector (OWASP LLM07-2025)
const { PROMPT_EXTRACTION_PATTERNS, SystemPromptGuard, PromptFingerprinter, PromptLeakageMitigation } = safeRequire('./prompt-leakage', 'prompt-leakage');

// RAG/Vector Vulnerability Scanner (OWASP LLM08-2025)
const { RAG_VULNERABILITY_PATTERNS, VECTOR_DB_SECURITY_CHECKLIST, RAGVulnerabilityScanner, EmbeddingIntegrityChecker, RAGPipelineAuditor } = safeRequire('./rag-vulnerability', 'rag-vulnerability');

// Confused Deputy Prevention (Meta Incident Response)
const { AuthorizationContext, EphemeralTokenManager, IntentValidator, ConfusedDeputyGuard } = safeRequire('./confused-deputy', 'confused-deputy');

// v10.0 — MCP Guard
const { MCPGuard, ServerAttestation, CrossServerIsolation, OAuthEnforcer, ToolBehaviorBaseline } = safeRequire('./mcp-guard', 'mcp-guard');

// v10.0 — MCP Supply Chain Scanner
const { SupplyChainScanner, KNOWN_BAD_SERVERS, CVE_REGISTRY: MCP_CVE_REGISTRY, DESCRIPTION_INJECTION_PATTERNS, BROAD_PERMISSION_PATTERNS } = safeRequire('./supply-chain-scanner', 'supply-chain-scanner');

// v10.0 — OWASP Agentic Top 10 2026
const { OWASPAgenticScanner, OWASP_AGENTIC_2026, SEVERITY_WEIGHTS: AGENTIC_SEVERITY_WEIGHTS } = safeRequire('./owasp-agentic', 'owasp-agentic');

// v10.0 — Red Team Audit CLI Engine
const { RedTeamCLI, REDTEAM_MODES, ATTACK_CORPUS: REDTEAM_ATTACK_CORPUS } = safeRequire('./redteam-cli', 'redteam-cli');

// v10.0 — Behavioral Drift Monitor
const { DriftMonitor, klDivergence: driftKLDivergence } = safeRequire('./drift-monitor', 'drift-monitor');

// v10.0 — Micro Detection Model (March 2026 attack corpus)
const { MicroModel, TRAINING_CORPUS: MICRO_MODEL_CORPUS } = safeRequire('./micro-model', 'micro-model');

// v10.0 L5 — Adversarial Self-Training
const { SelfTrainer: L5SelfTrainer, MutationEngine: L5MutationEngine, AutonomousHardener } = safeRequire('./self-training', 'self-training');

// v10.0 L5 — Causal Intent Graph
const { IntentGraph, extractTopics, jaccardSimilarity: intentJaccard, SUSPICIOUS_TRANSITIONS: INTENT_SUSPICIOUS_TRANSITIONS } = safeRequire('./intent-graph', 'intent-graph');

// v10.0 L5 — Semantic Isolation Engine
const { SemanticIsolationEngine, IsolationPolicy, TaggedContent, PROVENANCE: ISOLATION_PROVENANCE, TRUST_LEVELS } = safeRequire('./semantic-isolation', 'semantic-isolation');

// v10.0 L5 — Cryptographic Intent Binding
const { IntentBinder, IntentToken } = safeRequire('./intent-binding', 'intent-binding');

// v10.0 L5 — Attack Surface Mapper
const { AttackSurfaceMapper, CAPABILITY_RISK, CAPABILITY_PATTERNS } = safeRequire('./attack-surface', 'attack-surface');

// v10.0 SOTA — Prompt Hardening
const { PromptHardener, DEFENSIVE_TEMPLATES, SYSTEM_PROMPT_HARDENING } = safeRequire('./prompt-hardening', 'prompt-hardening');

// v10.0 SOTA — Message Integrity
const { MessageIntegrityChain } = safeRequire('./message-integrity', 'message-integrity');

// v10.0 SOTA — Continuous Security Service
const { ContinuousSecurityService } = safeRequire('./continuous-security', 'continuous-security');

// v10.0 SOTA — Benchmark Suite
const { SOTABenchmark, BIPIA_SAMPLES: SOTA_BIPIA_SAMPLES, HACKAPROMPT_SAMPLES: SOTA_HACKAPROMPT_SAMPLES, MCPTOX_SAMPLES: SOTA_MCPTOX_SAMPLES, MULTILINGUAL_SAMPLES: SOTA_MULTILINGUAL_SAMPLES, STEALTH_SAMPLES: SOTA_STEALTH_SAMPLES } = safeRequire('./sota-benchmark', 'sota-benchmark');

// v12.0 — Multi-Turn Attack Detection
const { ConversationTracker } = safeRequire('./cross-turn', 'cross-turn');

// v12.0 — Automated Incident Response
const { IncidentResponse, RESPONSE_STRATEGIES } = safeRequire('./incident-response', 'incident-response');

// v12.0 — Agent Behavioral Fingerprinting
const { AgentFingerprint, SIMILARITY_THRESHOLDS, DEFAULT_DEVIATION_THRESHOLD, MIN_OBSERVATIONS: FP_MIN_OBSERVATIONS } = safeRequire('./agent-intent', 'agent-intent');

// v12.0 — Advanced Text Normalizer
const { TextNormalizer, normalizeAll, stripZeroWidth, reverseLeetspeak, collapseCharSpacing, stripContextWrappers, decodeUnicodeEscapes, ZERO_WIDTH_RE, LEET_MAP, CONTEXT_WRAPPERS: NORMALIZER_CONTEXT_WRAPPERS, HTML_ENTITIES } = safeRequire('./normalizer', 'normalizer');

// v12.0 — Multi-Classifier Ensemble
const { DetectionEnsemble, DEFAULT_WEIGHTS: ENSEMBLE_DEFAULT_WEIGHTS, DEFAULT_THRESHOLD: ENSEMBLE_DEFAULT_THRESHOLD, MIN_QUORUM, CALIBRATION_PARAMS, plattScale, binnedCalibration } = safeRequire('./ensemble', 'ensemble');

// v12.0 — Smart Configuration / Policy Engine
const { SmartConfig, DEPLOYMENT_PRESETS, VALIDATION_RULES: CONFIG_VALIDATION_RULES } = safeRequire('./smart-config', 'smart-config');

// v12.0 — Multimodal Detector
const { MultimodalDetector } = safeRequire('./ml-detector', 'ml-detector');

// v12.0 — Federated Threat Intelligence
const { ThreatIntelNode } = safeRequire('./persistent-learning', 'persistent-learning');

// Build exports, filtering out undefined values from failed imports
const _exports = {
  // Core
  AgentShield,
  scanText,
  getPatterns,
  SEVERITY_ORDER,

  // Middleware
  expressMiddleware,
  wrapAgent,
  shieldTools,
  extractTextFromBody,
  rateLimitMiddleware,
  shieldMiddleware,

  // Protection
  CircuitBreaker,
  shadowMode,
  RateLimiter,
  STATE,
  CanaryTokens,
  PromptLeakDetector,
  API_KEY_PATTERNS,
  PIIRedactor,
  DLPEngine,
  ContentPolicy,
  PII_PATTERNS,
  CONTENT_CATEGORIES,
  ToolSequenceAnalyzer,
  PermissionBoundary,
  InputQuarantine,
  SUSPICIOUS_SEQUENCES,

  // Conversation
  FragmentationDetector,
  LanguageSwitchDetector,
  TokenBudgetAnalyzer,
  InstructionHierarchy,
  BehavioralFingerprint,

  // Policy & Logging
  loadPolicy,
  loadPolicyFile,
  StructuredLogger,
  WebhookAlert,
  LOG_LEVEL,

  // Multi-Agent
  AgentFirewall,
  DelegationChain,
  SharedThreatState,

  // Advanced Detection
  SteganographyDetector,
  EncodingBruteforceDetector,
  StructuredDataScanner,
  STEGO_PATTERNS,

  // Watermarking & Privacy
  OutputWatermark,
  DifferentialPrivacy,

  // Utilities
  getGrade,
  getGradeLabel,
  makeBar,
  truncate,
  formatHeader,
  generateId,
  createGracefulShutdown,
  loadEnvFile,

  // Integrations
  ShieldCallbackHandler,
  shieldAnthropicClient,
  shieldOpenAIClient,
  shieldVercelAI,
  shieldFetch,
  ShieldBlockError,

  // Red Team
  AttackSimulator,
  PayloadFuzzer,
  getAttackCategories,
  getPayloads,
  ATTACK_PAYLOADS,

  // Shield Score
  ShieldScoreCalculator,
  SCORE_CATEGORIES,

  // Benchmark Harness
  BenchmarkHarness,
  DatasetLoader,
  BenchmarkMetrics,
  RegressionTracker,
  BenchmarkReportGenerator,

  // Threat Encyclopedia
  ThreatEncyclopedia,
  THREAT_ENCYCLOPEDIA,
  DAILY_PATTERNS,

  // Compliance & Audit
  ComplianceReporter,
  AuditTrail,
  IncidentPlaybook,
  SecurityChecklistGenerator,
  COMPLIANCE_FRAMEWORKS,
  INCIDENT_PLAYBOOKS,

  // Enterprise
  MultiTenantShield,
  RoleBasedPolicy,
  DebugShield,
  DEFAULT_ROLES,

  // Badges
  BadgeGenerator,
  GitHubActionReporter,

  // Allowlist & Feedback
  Allowlist,
  ConfidenceCalibrator,
  FeedbackLoop,
  ScanCache,

  // Presets & Config Builder
  PRESETS,
  ConfigBuilder,
  SnippetGenerator,
  getPresets,
  getPreset,

  // Advanced Scanners
  RAGScanner,
  RAG_INJECTION_PATTERNS,
  PromptLinter,
  LINT_RULES,
  ToolSchemaValidator,
  DANGEROUS_TOOL_PATTERNS,

  // Production
  SamplingScanner,
  ShadowComparison,
  GracefulScanner,
  ThreatReplay,
  AttackAttributionChain,
  DiffReporter,
  PostureTracker,

  // Testing & Contracts
  TestSuiteGenerator,
  ATTACK_TEMPLATES,
  AgentContract,
  BreakglassProtocol,

  // Multi-Agent Trust
  MessageSigner,
  CapabilityToken,
  DelegationManager,
  BlastRadiusContainer,

  // Extended Policy & Intelligence
  ABTestRunner,
  ThreatIntelFeed,
  PatternBuilder,
  Doctor,
  GitHubActionGenerator,
  SOCIntegration,
  MigrationGuide,
  Playground,

  // Streaming
  StreamScanner,
  StreamBuffer,
  createStreamWrapper,
  scanAsyncIterator,

  // Plugin System
  PluginManager,
  PluginTemplate,
  PluginSandbox,

  // Token Analysis
  EntropyAnalyzer,
  PerplexityEstimator,
  BurstDetector,
  TextStatistics,

  // Document Scanner
  DocumentScanner,
  TextExtractor,
  IndirectInjectionScanner,

  // Tool Output Validator
  ToolOutputValidator,
  OutputSanitizer,

  // Response Handler
  ResponseHandler,
  ResponseTemplates,
  ReviewQueue,

  // Worker Scanner
  WorkerScanner,
  ScanQueue,
  ThreadedWorkerScanner,

  // Alert Tuning
  AlertFatigueAnalyzer,
  AutoTuner,
  AlertCorrelator,

  // OpenTelemetry
  ShieldMetrics,
  ShieldTracer,
  MetricsDashboard,

  // Certification
  CertificationRunner,
  Certificate,
  CertificationHistory,

  // MCP Server
  MCPServer,
  MCPToolHandler,

  // CTF
  CTFEngine,
  CTFReporter,
  CHALLENGES,

  // Observability
  PrometheusExporter,
  DatadogLogger,
  MetricsCollector: ObservabilityMetrics,

  // Adaptive Detection
  AdaptiveDetector,
  SemanticAnalysisHook,
  CommunityPatterns,

  // OpenClaw
  OpenClawShieldSkill,
  shieldOpenClawMessages,
  generateOpenClawSkill,

  // v1.2 — Semantic Detection
  SemanticClassifier,
  httpPost,
  EmbeddingSimilarityDetector,
  ATTACK_CORPUS,
  tokenizeText,
  cosineSimilarity,
  ConversationContextAnalyzer,
  ESCALATION_SIGNALS,
  TOPIC_PIVOT_SIGNALS,
  ConfidenceTuner,

  // v2.0 — Plugin Marketplace
  PluginRegistry,
  PluginValidator,
  MarketplaceClient,

  // v2.1 — Distributed Scanning
  DistributedShield,
  DistributedAdapter,
  MemoryAdapter,
  RedisAdapter,

  // v2.1 — Audit Log Streaming
  AuditStreamManager,
  AuditTransport,
  FileTransport,
  SplunkTransport,
  ElasticsearchTransport,

  // Immutable Audit Log — exported below in v5.1 section

  // v3.0 — Self-Healing Patterns
  SelfHealingEngine,
  SelfHealingPatternGenerator,

  // v3.0 — Honeypot Mode
  HoneypotEngine,
  HoneypotSession,

  // v3.0 — Multi-Modal Scanning
  MultiModalScanner,
  ModalityExtractor,

  // v3.0 — Behavior Profiling
  BehaviorProfile,

  // SSO/SAML Integration
  SSOManager,
  SAMLParser,
  OIDCHandler,
  IdentityMapper,
  SSOSession,
  SSO_DEFAULT_MAPPINGS,

  // Custom Model Fine-Tuning
  ModelTrainer,
  TrainingPipeline,
  DatasetManager,
  ModelEvaluator,
  FineTunedModel,

  // Threat Intelligence Network
  ThreatIntelNetwork,
  PeerNode,
  PatternAnonymizer,
  ConsensusEngine,
  ThreatFeed,
  NETWORK_DEFAULTS,

  // v4.0 — Multi-Language Patterns
  I18nPatternManager,
  CJK_PATTERNS,
  ARABIC_PATTERNS,
  CYRILLIC_PATTERNS,
  INDIC_PATTERNS,
  MULTILINGUAL_PATTERNS,
  getI18nPatterns,

  // v4.0 — LLM Red Team Suite
  LLMRedTeamSuite,
  AdversarialGenerator,
  JailbreakLibrary,
  EvasionTester,
  RedTeamReport,
  JAILBREAK_TEMPLATES,
  MUTATION_TECHNIQUES,

  // v5.0 — Agent-to-Agent Protocol
  AgentProtocol,
  SecureChannel,
  HandshakeManager,
  AgentIdentity,
  ProtocolMessage,
  MessageRouter,
  PROTOCOL_VERSION,

  // v5.0 — Policy-as-Code DSL
  PolicyDSL,
  PolicyParser,
  PolicyCompiler,
  PolicyRuntime,
  PolicyValidator,
  DSL_BUILTINS,
  EXAMPLE_STRICT_POLICY,
  EXAMPLE_PERMISSIVE_POLICY,
  EXAMPLE_CUSTOM_RULES_POLICY,

  // v5.0 — Fuzzing Harness
  FuzzingHarness,
  InputGenerator,
  FuzzMutationEngine,
  CoverageTracker,
  FuzzReport,
  CrashCollector,
  SEED_CORPUS,

  // v5.0 — Model Fingerprinting
  ModelFingerprinter,
  ResponseAnalyzer,
  StyleProfile,
  FingerprintDatabase,
  SupplyChainDetector,
  MODEL_SIGNATURES,

  // v5.0 — Cost/Latency Optimizer
  CostOptimizer,
  LatencyBudget,
  AdaptiveScanner,
  TierManager,
  PerformanceMonitor,
  ScanPlan,
  OPTIMIZATION_PRESETS,

  // Error codes & deprecation
  ERROR_CODES,
  createShieldError,
  deprecationWarning,

  // v5.1 — Immutable audit log
  ImmutableAuditLog,
  AuditEntry,
  MemoryAuditStore,
  FileAuditStore,
  AuditProof,
  verifyAuditChain,

  // v5.1 — Agent observability exported in Observability section above
  // v5.1 — Benchmark harness exported in Benchmark Harness section above

  // v6.0 — OWASP LLM Top 10 v2025
  OWASP_LLM_2025,
  OWASPCoverageMatrix,
  OWASP_SEVERITY_WEIGHTS,
  COVERAGE_MULTIPLIERS,

  // v6.0 — MCP Bridge
  MCPBridge,
  MCPToolPolicy,
  MCPSessionGuard,
  MCPResourceScanner,
  MCP_DANGEROUS_TOOLS,
  ARG_INJECTION_PATTERNS,
  createMCPMiddleware,

  // v6.0 — NIST AI RMF
  NIST_AI_RMF_2025,
  SP800_53_AI_CONTROLS,
  NISTMapper,
  AIBOMGenerator,
  NISTComplianceChecker,

  // v6.0 — EU AI Act
  EU_AI_ACT_REQUIREMENTS,
  RiskClassifier,
  ConformityAssessment,
  TransparencyReporter,
  EUIncidentReporter,
  EUAIActDashboard,

  // v6.0 — System Prompt Leakage (LLM07)
  PROMPT_EXTRACTION_PATTERNS,
  SystemPromptGuard,
  PromptFingerprinter,
  PromptLeakageMitigation,

  // v6.0 — RAG/Vector Vulnerability (LLM08)
  RAG_VULNERABILITY_PATTERNS,
  VECTOR_DB_SECURITY_CHECKLIST,
  RAGVulnerabilityScanner,
  EmbeddingIntegrityChecker,
  RAGPipelineAuditor,

  // Confused Deputy Prevention
  AuthorizationContext,
  EphemeralTokenManager,
  IntentValidator,
  ConfusedDeputyGuard,

  // v7.0 — Adaptive Defense
  LearningLoop,
  BehaviorContract,
  ContractRegistry,
  ComplianceAttestor,
  ATTESTATION_FRAMEWORKS,

  // v7.0 — MCP SDK Integration
  shieldMCPServer,
  createMCPSecurityLayer,

  // v7.0 — MCP Security Runtime
  MCPSecurityRuntime,
  MCPSessionStateMachine,
  SESSION_STATES,

  // v7.0 — MCP Certification & Trust
  AgentThreatIntelligence,
  MCPCertification,
  CrossOrgAgentTrust,
  MCP_THREAT_CATEGORIES: CERT_THREAT_CATEGORIES,
  CERTIFICATION_REQUIREMENTS,
  CERTIFICATION_LEVELS,

  // v8.0 — ML Detection (Pro/Enterprise)
  MLShield,
  isMLTier,
  isValidTier,
  loadMLPackage,
  ML_ENABLED_TIERS,
  VALID_TIERS,

  // v7.2 — IPIA Detector
  IPIADetector,
  ContextConstructor,
  FeatureExtractor,
  TreeClassifier,
  ExternalEmbedder,
  createIPIAScanner,
  ipiaMiddleware,
  IPIA_FEATURE_NAMES,
  IPIA_INJECTION_LEXICON,

  // v7.2.1 — Pre-Deployment Audit
  SecurityAudit,
  AuditReport,
  AUDIT_ATTACKS,
  auditMutations,
  runAuditCLI,

  // v7.2.1 — Flight Recorder
  FlightRecorder,

  // v7.2.1 — HTML Report Generator
  generateHTMLReport,
  generateReportFile,

  // v7.3 — Supply Chain Verification
  ToolChainValidator,
  ResponseScanner,
  DomainAllowlist,
  RESPONSE_INJECTION_PATTERNS,
  EXFILTRATION_URL_PATTERNS,
  CREDENTIAL_PATTERNS,
  CHAIN_SUSPICIOUS_PATTERNS,

  // v7.4 — Herd Immunity
  HerdImmunity,
  ImmuneMemory,
  createHerdNetwork,

  // v7.4 — Adversarial Evolution Simulator
  EvolutionSimulator,
  MutationEngine,
  hardenFromEvolution,

  // v7.4 — Attack Replay Platform
  AttackReplayEngine,
  compareDefenses,

  // v7.4 — Enterprise SOC Dashboard
  SOCDashboard,
  SlackAlertChannel,
  PagerDutyAlertChannel,
  TeamsAlertChannel,

  // v7.4 — Attack Genome
  AttackGenome,
  GenomeDatabase,
  detectByGenome,
  GENOME_INTENT_PATTERNS,
  GENOME_TECHNIQUE_PATTERNS,
  GENOME_EVASION_PATTERNS,
  GENOME_TARGET_PATTERNS,

  // v7.4 — Intent Firewall
  IntentFirewall,
  IntentContextAnalyzer,
  IntentRules,
  intentDemo,
  INTENT_CATEGORIES,
  INTENT_SIGNALS,
  CONTEXT_MODIFIERS,

  // v7.4 — Real Attack Datasets
  DatasetRunner,
  HACKAPROMPT_SAMPLES,
  TENSORTRUST_SAMPLES,
  RESEARCH_SAMPLES,
  BENIGN_SAMPLES,

  // v7.4 — Federated Threat Intelligence
  ThreatIntelFederation,
  createFederationMesh,

  // v7.4 — Behavioral DNA
  BehavioralDNA,
  AgentProfiler,
  extractBehavioralFeatures,
  DEFAULT_NUMERIC_FEATURES,
  DEFAULT_CATEGORICAL_FEATURES,

  // v10.0 — MCP Guard
  MCPGuard,
  ServerAttestation,
  CrossServerIsolation,
  OAuthEnforcer,
  ToolBehaviorBaseline,

  // v10.0 — MCP Supply Chain Scanner
  SupplyChainScanner,
  KNOWN_BAD_SERVERS,
  MCP_CVE_REGISTRY,
  DESCRIPTION_INJECTION_PATTERNS,
  BROAD_PERMISSION_PATTERNS,

  // v10.0 — OWASP Agentic Top 10 2026
  OWASPAgenticScanner,
  OWASP_AGENTIC_2026,
  AGENTIC_SEVERITY_WEIGHTS,

  // v10.0 — Red Team Audit CLI Engine
  RedTeamCLI,
  REDTEAM_MODES,
  REDTEAM_ATTACK_CORPUS,

  // v10.0 — Behavioral Drift Monitor
  DriftMonitor,
  driftKLDivergence,

  // v10.0 — Micro Detection Model
  MicroModel,
  MICRO_MODEL_CORPUS,

  // v10.0 L5 — Adversarial Self-Training
  L5SelfTrainer,
  L5MutationEngine,
  AutonomousHardener,

  // v10.0 L5 — Causal Intent Graph
  IntentGraph,
  extractTopics,
  intentJaccard,
  INTENT_SUSPICIOUS_TRANSITIONS,

  // v10.0 L5 — Semantic Isolation Engine
  SemanticIsolationEngine,
  IsolationPolicy,
  TaggedContent,
  ISOLATION_PROVENANCE,
  TRUST_LEVELS,

  // v10.0 L5 — Cryptographic Intent Binding
  IntentBinder,
  IntentToken,

  // v10.0 L5 — Attack Surface Mapper
  AttackSurfaceMapper,
  CAPABILITY_RISK,
  CAPABILITY_PATTERNS,

  // v10.0 SOTA — Prompt Hardening
  PromptHardener,
  DEFENSIVE_TEMPLATES,
  SYSTEM_PROMPT_HARDENING,

  // v10.0 SOTA — Message Integrity
  MessageIntegrityChain,

  // v10.0 SOTA — Continuous Security Service
  ContinuousSecurityService,

  // v10.0 SOTA — Benchmark Suite
  SOTABenchmark,
  SOTA_BIPIA_SAMPLES,
  SOTA_HACKAPROMPT_SAMPLES,
  SOTA_MCPTOX_SAMPLES,
  SOTA_MULTILINGUAL_SAMPLES,
  SOTA_STEALTH_SAMPLES,

  // v12.0 — Multi-Turn Attack Detection
  ConversationTracker,

  // v12.0 — Automated Incident Response
  IncidentResponse,
  RESPONSE_STRATEGIES,

  // v12.0 — Agent Behavioral Fingerprinting
  AgentFingerprint,
  SIMILARITY_THRESHOLDS,
  DEFAULT_DEVIATION_THRESHOLD,
  FP_MIN_OBSERVATIONS,

  // v12.0 — Advanced Text Normalizer
  TextNormalizer,
  normalizeAll,
  stripZeroWidth,
  reverseLeetspeak,
  collapseCharSpacing,
  stripContextWrappers,
  decodeUnicodeEscapes,
  ZERO_WIDTH_RE,
  LEET_MAP,
  NORMALIZER_CONTEXT_WRAPPERS,
  HTML_ENTITIES,

  // v12.0 — Multi-Classifier Ensemble
  DetectionEnsemble,
  ENSEMBLE_DEFAULT_WEIGHTS,
  ENSEMBLE_DEFAULT_THRESHOLD,
  MIN_QUORUM,
  CALIBRATION_PARAMS,
  plattScale,
  binnedCalibration,

  // v12.0 — Smart Configuration / Policy Engine
  SmartConfig,
  DEPLOYMENT_PRESETS,
  CONFIG_VALIDATION_RULES,

  // v12.0 — Multimodal Detector
  MultimodalDetector,

  // v12.0 — Federated Threat Intelligence
  ThreatIntelNode,

  // v7.5 — Compliance Certification Authority
  ComplianceCertificateAuthority,
  ComplianceCertReport,
  ComplianceScheduler,
  AUTHORITY_FRAMEWORKS,
  CA_CAPABILITY_MAP,
  CA_CERTIFICATE_LEVELS,

};

// Filter out undefined exports (from modules that failed to load)
for (const key of Object.keys(_exports)) {
  if (_exports[key] === undefined) {
    delete _exports[key];
  }
}

module.exports = _exports;
