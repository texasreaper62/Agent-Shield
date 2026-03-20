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
const { expressMiddleware, wrapAgent, shieldTools, extractTextFromBody } = safeRequire('./middleware', 'middleware');

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
const { getGrade, getGradeLabel, makeBar, truncate, formatHeader, generateId } = safeRequire('./utils', 'utils');

// Integrations
const { ShieldCallbackHandler, shieldAnthropicClient, shieldOpenAIClient, shieldVercelAI, shieldFetch, ShieldBlockError } = safeRequire('./integrations', 'integrations');

// Red Team
const { AttackSimulator, PayloadFuzzer, getAttackCategories, getPayloads, ATTACK_PAYLOADS } = safeRequire('./redteam', 'redteam');

// Shield Score
const { ShieldScoreCalculator, SCORE_CATEGORIES } = safeRequire('./shield-score', 'shield-score');

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

// Streaming
const { StreamScanner, TokenStreamScanner } = safeRequire('./stream-scanner', 'stream-scanner');

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

// Observability
const { PrometheusExporter, DatadogLogger, MetricsCollector } = safeRequire('./observability', 'observability');

// Adaptive Detection
const { AdaptiveDetector, SemanticAnalysisHook, CommunityPatterns } = safeRequire('./adaptive', 'adaptive');

// OpenClaw
const { OpenClawShieldSkill, shieldOpenClawMessages, generateOpenClawSkill } = safeRequire('./openclaw', 'openclaw');

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
  TokenStreamScanner,

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
  MetricsCollector,

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
  NETWORK_DEFAULTS
};

// Filter out undefined exports (from modules that failed to load)
for (const key of Object.keys(_exports)) {
  if (_exports[key] === undefined) {
    delete _exports[key];
  }
}

module.exports = _exports;
