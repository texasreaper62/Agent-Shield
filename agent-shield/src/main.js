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
  GitHubActionReporter
};
