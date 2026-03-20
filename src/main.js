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
  generateOpenClawSkill
};

// Filter out undefined exports (from modules that failed to load)
for (const key of Object.keys(_exports)) {
  if (_exports[key] === undefined) {
    delete _exports[key];
  }
}

module.exports = _exports;
