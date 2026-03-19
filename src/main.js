'use strict';

/**
 * Agent Shield — Unified Entry Point
 *
 * Import everything from a single module:
 *   const shield = require('agent-shield');
 */

// Core
const { AgentShield } = require('./index');
const { scanText, getPatterns, SEVERITY_ORDER } = require('./detector-core');
const { expressMiddleware, wrapAgent, shieldTools, extractTextFromBody } = require('./middleware');

// Protection
const { CircuitBreaker, shadowMode, RateLimiter, STATE } = require('./circuit-breaker');
const { CanaryTokens, PromptLeakDetector, API_KEY_PATTERNS } = require('./canary');
const { PIIRedactor, DLPEngine, ContentPolicy, PII_PATTERNS, CONTENT_CATEGORIES } = require('./pii');
const { ToolSequenceAnalyzer, PermissionBoundary, InputQuarantine, SUSPICIOUS_SEQUENCES } = require('./tool-guard');

// Conversation
const { FragmentationDetector, LanguageSwitchDetector, TokenBudgetAnalyzer, InstructionHierarchy, BehavioralFingerprint } = require('./conversation');

// Policy & Logging
const { loadPolicy, loadPolicyFile, StructuredLogger, WebhookAlert, LOG_LEVEL } = require('./policy');

// Multi-Agent
const { AgentFirewall, DelegationChain, SharedThreatState } = require('./multi-agent');

// Advanced Detection
const { SteganographyDetector, EncodingBruteforceDetector, StructuredDataScanner, STEGO_PATTERNS } = require('./encoding');

// Watermarking & Privacy
const { OutputWatermark, DifferentialPrivacy } = require('./watermark');

// Utilities
const { getGrade, getGradeLabel, makeBar, truncate, formatHeader, generateId } = require('./utils');

// Integrations
const { ShieldCallbackHandler, shieldAnthropicClient, shieldOpenAIClient, shieldVercelAI, shieldFetch, ShieldBlockError } = require('./integrations');

// Red Team
const { AttackSimulator, PayloadFuzzer, getAttackCategories, getPayloads, ATTACK_PAYLOADS } = require('./redteam');

// Shield Score & Benchmarks
const { ShieldScoreCalculator, BenchmarkSuite, SCORE_CATEGORIES } = require('./shield-score');

// Threat Encyclopedia
const { ThreatEncyclopedia, THREAT_ENCYCLOPEDIA, DAILY_PATTERNS } = require('./threat-encyclopedia');

// Compliance & Audit
const { ComplianceReporter, AuditTrail, IncidentPlaybook, SecurityChecklistGenerator, COMPLIANCE_FRAMEWORKS, INCIDENT_PLAYBOOKS } = require('./compliance');

// Enterprise
const { MultiTenantShield, RoleBasedPolicy, DebugShield, DEFAULT_ROLES } = require('./enterprise');

// Badges
const { BadgeGenerator, GitHubActionReporter } = require('./badges');

// Allowlist & Feedback
const { Allowlist, ConfidenceCalibrator, FeedbackLoop, ScanCache } = require('./allowlist');

// Presets & Config Builder
const { PRESETS, ConfigBuilder, SnippetGenerator, getPresets, getPreset } = require('./presets');

// Advanced Scanners
const { RAGScanner, RAG_INJECTION_PATTERNS, PromptLinter, LINT_RULES, ToolSchemaValidator, DANGEROUS_TOOL_PATTERNS } = require('./scanners');

// Production
const { SamplingScanner, ShadowComparison, GracefulScanner, ThreatReplay, AttackAttributionChain, DiffReporter, PostureTracker } = require('./production');

// Testing & Contracts
const { TestSuiteGenerator, ATTACK_TEMPLATES, AgentContract, BreakglassProtocol } = require('./testing');

// Multi-Agent Trust
const { MessageSigner, CapabilityToken, DelegationManager, BlastRadiusContainer } = require('./multi-agent-trust');

// Extended Policy & Intelligence
const { ABTestRunner, ThreatIntelFeed, PatternBuilder, Doctor, GitHubActionGenerator, SOCIntegration, MigrationGuide, Playground } = require('./policy-extended');

// --- New Modules ---

// Streaming
const { StreamScanner, TokenStreamScanner } = require('./stream-scanner');

// Plugin System
const { PluginManager, PluginTemplate, PluginSandbox } = require('./plugin-system');

// Token Analysis
const { EntropyAnalyzer, PerplexityEstimator, BurstDetector, TextStatistics } = require('./token-analysis');

// Document Scanner
const { DocumentScanner, TextExtractor, IndirectInjectionScanner } = require('./document-scanner');

// Tool Output Validator
const { ToolOutputValidator, OutputSanitizer } = require('./tool-output-validator');

// Response Handler
const { ResponseHandler, ResponseTemplates, ReviewQueue } = require('./response-handler');

// Worker Scanner
const { WorkerScanner, ScanQueue } = require('./worker-scanner');

// Alert Tuning
const { AlertFatigueAnalyzer, AutoTuner, AlertCorrelator } = require('./alert-tuning');

// OpenTelemetry
const { ShieldMetrics, ShieldTracer, MetricsDashboard } = require('./otel');

// Certification
const { CertificationRunner, Certificate, CertificationHistory } = require('./certification');

// MCP Server
const { MCPServer, MCPToolHandler } = require('./mcp-server');

// CTF
const { CTFEngine, CTFReporter, CHALLENGES } = require('./ctf');

module.exports = {
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

  // Shield Score & Benchmarks
  ShieldScoreCalculator,
  BenchmarkSuite,
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

  // Allowlist & Feedback (Features 21-23, 29)
  Allowlist,
  ConfidenceCalibrator,
  FeedbackLoop,
  ScanCache,

  // Presets & Config Builder (Features 1-4)
  PRESETS,
  ConfigBuilder,
  SnippetGenerator,
  getPresets,
  getPreset,

  // Advanced Scanners (Features 24-26)
  RAGScanner,
  RAG_INJECTION_PATTERNS,
  PromptLinter,
  LINT_RULES,
  ToolSchemaValidator,
  DANGEROUS_TOOL_PATTERNS,

  // Production (Features 27-28, 30-33, 40)
  SamplingScanner,
  ShadowComparison,
  GracefulScanner,
  ThreatReplay,
  AttackAttributionChain,
  DiffReporter,
  PostureTracker,

  // Testing & Contracts (Features 34-36)
  TestSuiteGenerator,
  ATTACK_TEMPLATES,
  AgentContract,
  BreakglassProtocol,

  // Multi-Agent Trust (Features 37-39)
  MessageSigner,
  CapabilityToken,
  DelegationManager,
  BlastRadiusContainer,

  // Extended Policy & Intelligence (Features 5-7, 9-10, 13-16, 17-20)
  ABTestRunner,
  ThreatIntelFeed,
  PatternBuilder,
  Doctor,
  GitHubActionGenerator,
  SOCIntegration,
  MigrationGuide,
  Playground,

  // --- New Modules ---

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
  CHALLENGES
};
