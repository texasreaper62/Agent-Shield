/**
 * Agent Shield — TypeScript Declarations
 */

// =========================================================================
// Core
// =========================================================================

export interface ScanResult {
  status: 'safe' | 'danger' | 'warning' | 'caution';
  threats: Threat[];
  blocked: boolean;
  stats: {
    totalThreats: number;
    scanTimeMs: number;
    patternsChecked?: number;
  };
}

export interface Threat {
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: string;
  description: string;
  detail?: string;
  confidence: number;
  confidenceLabel: string;
  matched?: string;
}

export interface ShieldOptions {
  sensitivity?: 'low' | 'medium' | 'high';
  blockOnThreat?: boolean;
  blockThreshold?: 'low' | 'medium' | 'high' | 'critical';
  logging?: boolean;
  customPatterns?: Pattern[];
}

export interface Pattern {
  pattern: RegExp;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: string;
  description: string;
}

export interface ShieldStats {
  totalScans: number;
  threatsDetected: number;
  blocked: number;
}

export declare class AgentShield {
  constructor(options?: ShieldOptions);
  scan(text: string, options?: { source?: string }): ScanResult;
  scanInput(text: string): ScanResult;
  scanOutput(text: string): ScanResult;
  getPatterns(): Pattern[];
  getStats(): ShieldStats;
}

export declare function scanText(text: string, sensitivity?: string): ScanResult;
export declare function getPatterns(): Pattern[];

// =========================================================================
// Middleware
// =========================================================================

export interface MiddlewareOptions extends ShieldOptions {
  configPath?: string;
}

export declare function expressMiddleware(options?: MiddlewareOptions): (req: any, res: any, next: any) => void;
export declare function wrapAgent(agentFn: Function, options?: ShieldOptions): Function;
export declare function shieldTools(tools: any[], options?: ShieldOptions): any[];

export interface RateLimitMiddlewareOptions {
  maxRequests?: number;
  windowMs?: number;
  maxThreatsPerWindow?: number;
  onLimit?: (info: { count: number; windowMs: number }) => void;
  onAnomaly?: (info: { threatCount: number; windowMs: number }) => void;
  includeBackpressureHeaders?: boolean;
}

export declare function rateLimitMiddleware(options?: RateLimitMiddlewareOptions): (req: any, res: any, next: any) => void;

export interface ShieldMiddlewareOptions extends MiddlewareOptions, RateLimitMiddlewareOptions {}

export declare function shieldMiddleware(options?: ShieldMiddlewareOptions): (req: any, res: any, next: any) => void;

// =========================================================================
// Circuit Breaker
// =========================================================================

export declare const STATE: {
  CLOSED: 'closed';
  OPEN: 'open';
  HALF_OPEN: 'half_open';
};

export interface CircuitBreakerOptions {
  threshold?: number;
  windowMs?: number;
  cooldownMs?: number;
  onTrip?: (info: { threatCount: number; state: string }) => void;
}

export declare class CircuitBreaker {
  constructor(options?: CircuitBreakerOptions);
  check(): { allowed: boolean; reason?: string };
  recordThreat(count?: number): void;
  reset(): void;
  getStatus(): { state: string; threatCount: number; lastTrip: string | null };
}

export interface RateLimiterOptions {
  maxRequests?: number;
  windowMs?: number;
  maxThreatsPerWindow?: number;
  onLimit?: () => void;
}

export declare class RateLimiter {
  constructor(options?: RateLimiterOptions);
  recordRequest(): { allowed: boolean; reason?: string };
  getStatus(): { requests: number; threats: number };
}

export declare function shadowMode(shield: AgentShield, options?: { onThreat?: (result: ScanResult) => void }): AgentShield;

// =========================================================================
// Canary
// =========================================================================

export interface CanaryToken {
  token: string;
  description: string;
  instruction: string;
  createdAt: string;
}

export interface CanaryCheckResult {
  leaked: boolean;
  leaks: Array<{ token: string; description: string }>;
}

export declare class CanaryTokens {
  constructor(options?: { onTriggered?: (leak: any) => void });
  generate(description: string): CanaryToken;
  check(text: string): CanaryCheckResult;
}

export interface LeakResult {
  leaked: boolean;
  leaks: Array<{ severity: string; description: string; pattern: string }>;
}

export declare class PromptLeakDetector {
  constructor(options?: { systemPrompt?: string; sensitiveStrings?: string[] });
  scan(text: string, source?: string): LeakResult;
}

// =========================================================================
// PII
// =========================================================================

export interface PIIResult {
  hasPII: boolean;
  findings: Array<{ type: string; description: string; count: number }>;
}

export interface RedactResult {
  redacted: string;
  count: number;
  findings: PIIResult['findings'];
}

export declare class PIIRedactor {
  constructor(options?: { categories?: string[]; logging?: boolean });
  detect(text: string): PIIResult;
  redact(text: string): RedactResult;
}

export interface DLPRule {
  name: string;
  pattern: string;
  action: 'block' | 'redact' | 'warn';
  severity?: string;
  replacement?: string;
}

export declare class DLPEngine {
  constructor(rules?: DLPRule[]);
  scan(text: string): { violations: Array<{ rule: string; action: string; severity: string }> };
  enforce(text: string): { text: string; blocked: boolean; violations: any[] };
}

export declare class ContentPolicy {
  constructor(options?: { blockedCategories?: string[] });
  check(text: string): { allowed: boolean; violations: string[] };
}

// =========================================================================
// Tool Guard
// =========================================================================

export interface ToolCheckResult {
  allowed: boolean;
  reason?: string;
}

export declare class PermissionBoundary {
  constructor(options: {
    allowedTools?: string[];
    blockedTools?: string[];
    tools?: Record<string, any>;
  });
  check(toolName: string, args: any): ToolCheckResult;
}

export interface SequenceResult {
  suspicious: boolean;
  matches: Array<{ name: string; description: string; severity: string }>;
}

export declare class ToolSequenceAnalyzer {
  constructor(options?: { onSuspicious?: (info: SequenceResult) => void });
  record(toolName: string, args?: any): SequenceResult;
  reset(): void;
}

export declare class InputQuarantine {
  constructor(options?: { maxQueueSize?: number });
  quarantine(input: string, metadata?: any): { id: string; input: string };
  release(id: string): any | null;
  reject(id: string): boolean;
  getPending(): any[];
}

// =========================================================================
// Conversation
// =========================================================================

export declare class FragmentationDetector {
  constructor(options?: { windowSize?: number; onDetection?: (info: any) => void });
  addMessage(text: string): { fragmented: boolean; matches?: any[] };
  getHistory(): any[];
  reset(): void;
}

export declare class LanguageSwitchDetector {
  constructor();
  analyze(text: string): { switched: boolean; scripts: string[]; details: any };
  reset(): void;
}

export declare class TokenBudgetAnalyzer {
  constructor(options?: { maxTokens?: number });
  analyze(text: string): { tokens: number; overBudget: boolean };
}

export declare class InstructionHierarchy {
  constructor(options?: { levels?: string[] });
  classify(text: string): { level: string; priority: number };
}

export declare class BehavioralFingerprint {
  constructor(options?: { learningPeriod?: number; stdDevThreshold?: number; onAnomaly?: (info: any) => void });
  record(event: { inputLength?: number; responseTimeMs?: number; toolName?: string; threatCount?: number }): { anomalies: any[]; isLearning: boolean };
  getProfile(): any;
  reset(): void;
}

// =========================================================================
// Multi-Agent
// =========================================================================

export declare class AgentFirewall {
  constructor(options?: ShieldOptions);
  validateMessage(from: string, to: string, message: string): ScanResult;
}

export declare class DelegationChain {
  constructor(options?: { maxDepth?: number });
  start(requestId: string, originAgent: string, originalInput?: string): any;
  delegate(requestId: string, fromAgent: string, toAgent: string, action: string, permissions?: string): { allowed: boolean; depth: number; chain: any; reason?: string };
  complete(requestId: string): void;
  getChain(requestId: string): any;
  getActiveChain(agentId: string): any;
  getAllChains(): any[];
  reset(): void;
}

export declare class SharedThreatState {
  constructor(options?: { ttlMs?: number; onBroadcast?: (threat: any) => void });
  subscribe(agentId: string, callback: (threat: any) => void): void;
  unsubscribe(agentId: string): void;
  broadcast(reportingAgent: string, threat: { signature: string; category: string; severity: string; description?: string }): void;
  isKnown(signature: string): any | null;
  getActiveThreats(): any[];
  reset(): void;
}

// =========================================================================
// Encoding
// =========================================================================

export declare class SteganographyDetector {
  constructor();
  scan(text: string): { detected: boolean; findings: any[] };
}

export declare class EncodingBruteforceDetector {
  constructor();
  check(text: string): { detected: boolean; decoded: string; encoding: string };
  reset(): void;
}

export declare class StructuredDataScanner {
  constructor();
  scanJSON(json: string, source?: string): { clean: boolean; threats: Threat[] };
}

// =========================================================================
// Watermark
// =========================================================================

export declare class OutputWatermark {
  constructor(options?: { key?: string });
  embed(text: string): string;
  extract(text: string): { watermarked: boolean; valid: boolean };
  strip(text: string): string;
}

export declare class DifferentialPrivacy {
  constructor(options?: { epsilon?: number });
  addNoise(value: number): number;
  anonymize(text: string): string;
}

// =========================================================================
// Policy
// =========================================================================

export interface PolicyConfig {
  sensitivity?: string;
  blockOnThreat?: boolean;
  blockThreshold?: string;
  logging?: boolean;
  circuitBreaker?: CircuitBreakerOptions;
  rateLimiter?: RateLimiterOptions;
  permissions?: any;
  pii?: any;
  dlp?: any;
  contentPolicy?: any;
}

export declare function loadPolicy(config: PolicyConfig): PolicyConfig;
export declare function loadPolicyFile(filePath: string): PolicyConfig;

export declare const LOG_LEVEL: {
  DEBUG: 'debug';
  INFO: 'info';
  WARN: 'warn';
  ERROR: 'error';
  CRITICAL: 'critical';
};

export declare class StructuredLogger {
  constructor(options?: { console?: boolean; file?: string; serviceName?: string });
  log(level: string, event: string, data?: any): void;
  logScan(result: ScanResult, metadata?: any): void;
  logBlock(reason: string, source: string, data?: any): void;
  getEntries(): any[];
}

export declare class WebhookAlert {
  constructor(options: { url: string; events?: string[] });
  send(event: string, data: any): Promise<void>;
}

// =========================================================================
// Integrations
// =========================================================================

export declare class ShieldCallbackHandler {
  constructor(options?: ShieldOptions & { pii?: boolean; onThreat?: (info: any) => void });
  handleLLMStart(llm: any, prompts: string[]): Promise<void>;
  handleLLMEnd(output: any): Promise<void>;
  handleChainStart(chain: any, inputs: any): Promise<void>;
  handleToolStart(tool: any, input: string): Promise<void>;
  getStats(): ShieldStats;
}

export declare function shieldAnthropicClient(client: any, options?: ShieldOptions & {
  pii?: boolean;
  circuitBreaker?: CircuitBreakerOptions;
  onThreat?: (info: any) => void;
}): any;

export declare function shieldOpenAIClient(client: any, options?: ShieldOptions & {
  pii?: boolean;
  circuitBreaker?: CircuitBreakerOptions;
  onThreat?: (info: any) => void;
}): any;

export declare function shieldVercelAI(options?: ShieldOptions & {
  onThreat?: (info: any) => void;
}): any;

export declare function shieldFetch(fetchFn: typeof fetch, options?: ShieldOptions): typeof fetch;

export declare class ShieldBlockError extends Error {
  threats: Threat[];
  code: string;
  constructor(message: string, threats?: Threat[]);
}

// =========================================================================
// Red Team
// =========================================================================

export interface AttackPayload {
  name: string;
  text: string;
  difficulty: 'easy' | 'medium' | 'hard';
}

export interface AttackResult {
  category: string;
  attack: string;
  difficulty: string;
  detected: boolean;
  threats: Threat[];
  scanTimeMs: number;
  text: string;
}

export interface RedTeamReport {
  summary: {
    total: number;
    detected: number;
    missed: number;
    detectionRate: string;
    avgScanTimeMs: number;
  };
  byDifficulty: Array<{ difficulty: string; total: number; detected: number; rate: string }>;
  byCategory: Array<{ category: string; total: number; detected: number; rate: string }>;
  missedAttacks: Array<{ category: string; attack: string; difficulty: string; text: string }>;
  grade: string;
}

export declare class AttackSimulator {
  constructor(options?: { sensitivity?: string; customPatterns?: any[] });
  runCategory(category: string): AttackResult[];
  runAll(): Record<string, AttackResult[]>;
  runMultiTurn(scanFn: (message: string, turnIndex: number) => ScanResult): any[];
  runCustom(payloads: AttackPayload[]): AttackResult[];
  generateReport(): RedTeamReport;
  formatReport(): string;
  reset(): void;
}

export declare class PayloadFuzzer {
  constructor(options?: { mutations?: number; sensitivity?: string });
  fuzz(basePayload: string): {
    totalMutations: number;
    detected: number;
    evaded: number;
    evasionRate: string;
    evasions: Array<{ mutation: string; text: string }>;
  };
}

export declare function getAttackCategories(): Array<{ key: string; name: string; description: string; payloadCount: number }>;
export declare function getPayloads(category: string): AttackPayload[] | null;

// =========================================================================
// Shield Score & Benchmarks
// =========================================================================

export interface ShieldScore {
  score: number;
  grade: string;
  label: string;
  emoji: string;
  categories: Array<{
    key: string;
    name: string;
    weight: number;
    description: string;
    score: number;
    detected: number;
    total: number;
  }>;
  recommendations: Array<{ category: string; priority: string; message: string; missedAttacks: string[] }>;
  benchmarkTimeMs: number;
  timestamp: string;
}

export declare class ShieldScoreCalculator {
  constructor(options?: { sensitivity?: string; scanFn?: (text: string) => ScanResult });
  calculate(): ShieldScore;
  formatReport(): string;
}

// =========================================================================
// Threat Encyclopedia
// =========================================================================

export interface ThreatEntry {
  id: string;
  name: string;
  category: string;
  severity: string;
  summary: string;
  description: string;
  aliases: string[];
  discoveredDate: string;
  mitreTactic: string;
  examples: Array<{ name: string; payload?: string; turns?: string[]; explanation: string }>;
  mitigations: string[];
  references: Array<{ title: string; url: string }>;
  relatedThreats: string[];
}

export interface DailyPattern {
  id: string;
  title: string;
  threat: string;
  description: string;
  realWorldExample: string;
  howToDefend: string;
  tags: string[];
}

export declare class ThreatEncyclopedia {
  constructor();
  getAll(): ThreatEntry[];
  get(idOrKey: string): ThreatEntry | null;
  search(query: string): ThreatEntry[];
  getByCategory(category: string): ThreatEntry[];
  getBySeverity(severity: string): ThreatEntry[];
  getPatternOfTheDay(): DailyPattern;
  getAllPatterns(): DailyPattern[];
  getRelated(idOrKey: string): ThreatEntry[];
  getCategories(): Array<{ name: string; count: number; severities: string[] }>;
  formatThreat(idOrKey: string): string;
}

// =========================================================================
// Compliance
// =========================================================================

export interface ComplianceReport {
  framework: string;
  version: string;
  date: string;
  summary: { total: number; compliant: number; available: number; manual: number; complianceRate: string };
  controls: Array<{ id: string; name: string; check: string; description: string; status: string; feature: string; module: string | null }>;
}

export declare class ComplianceReporter {
  constructor(options?: { enabledModules?: string[]; framework?: string });
  generateReport(frameworkId?: string): ComplianceReport;
  generateAllReports(): Record<string, ComplianceReport>;
  formatReport(report: ComplianceReport): string;
}

export declare class AuditTrail {
  constructor(options?: { maxEvents?: number; autoFlush?: boolean; flushPath?: string });
  record(event: any): any;
  recordScan(input: string, result: ScanResult, metadata?: any): any;
  recordBlock(reason: string, input: string, threats?: Threat[], metadata?: any): any;
  recordToolCall(tool: string, args: any, result: any, metadata?: any): any;
  exportJSON(): string;
  exportCSV(): string;
  flush(filePath?: string): void;
  query(filters?: { type?: string; blocked?: boolean; since?: string; until?: string; minThreats?: number }): any[];
  getSummary(): { total: number; scans: number; blocks: number; toolCalls: number; threats: number };
  clear(): void;
}

export declare class IncidentPlaybook {
  constructor();
  get(threatType: string): any | null;
  getAll(): any[];
  recommend(scanResult: ScanResult): any | null;
  format(playbook: any): string;
}

export interface ChecklistItem {
  item: string;
  priority: 'critical' | 'high' | 'medium' | 'low';
  checked: boolean;
}

export interface Checklist {
  environment: string;
  date: string;
  totalItems: number;
  categories: Array<{ name: string; items: ChecklistItem[] }>;
}

export declare class SecurityChecklistGenerator {
  constructor();
  generate(environment?: string): Checklist;
  format(checklist: Checklist): string;
}

// =========================================================================
// Enterprise
// =========================================================================

export declare class MultiTenantShield {
  constructor(options?: { defaultPolicy?: ShieldOptions; globalOverrides?: Partial<ShieldOptions>; onTenantCreated?: (id: string, policy: any) => void });
  registerTenant(tenantId: string, policy?: ShieldOptions): MultiTenantShield;
  getTenant(tenantId: string): any;
  scan(tenantId: string, text: string, options?: any): ScanResult & { tenantId: string };
  scanInput(tenantId: string, text: string): ScanResult;
  scanOutput(tenantId: string, text: string): ScanResult;
  updatePolicy(tenantId: string, policy: Partial<ShieldOptions>): any;
  getAllStats(): Record<string, any>;
  removeTenant(tenantId: string): boolean;
  readonly size: number;
}

export interface RoleConfig {
  name: string;
  sensitivity: string;
  blockOnThreat: boolean;
  allowedTools: string[] | '*';
  blockedTools: string[] | '*';
  bypassCircuitBreaker: boolean;
  canViewAuditTrail: boolean;
  canModifyPolicy: boolean;
}

export declare class RoleBasedPolicy {
  constructor(options?: { customRoles?: Record<string, Partial<RoleConfig>> });
  assignRole(userId: string, role: string): RoleBasedPolicy;
  getPolicy(userId: string): RoleConfig & { role: string };
  scan(userId: string, text: string, options?: any): ScanResult & { userId: string; role: string };
  checkToolAccess(userId: string, toolName: string): ToolCheckResult;
  defineRole(name: string, config: Partial<RoleConfig>): RoleBasedPolicy;
  getRoles(): Array<{ key: string } & RoleConfig>;
}

export declare class DebugShield {
  constructor(options?: ShieldOptions & { debug?: boolean; maxTraces?: number; verbose?: boolean });
  scan(text: string, options?: any): ScanResult & { _trace: any };
  getTraces(): any[];
  getRecentTraces(n?: number): any[];
  exportTraces(): string;
  clearTraces(): void;
  getTimingStats(): { count: number; min: number; max: number; avg: number; median: number; p95: number; p99: number } | null;
}

// =========================================================================
// Badges
// =========================================================================

export declare class BadgeGenerator {
  static shieldScore(score: number): string;
  static protectionStatus(enabled?: boolean): string;
  static detectionRate(rate: string | number): string;
  static scanCount(count: number): string;
  static compliance(framework: string, rate: string | number): string;
  static custom(label: string, value: string, color?: string): string;
  static markdownBadges(options?: { score?: number; detectionRate?: string }): string;
  static generateSVG(label: string, value: string, color: string): string;
}

export declare class GitHubActionReporter {
  constructor();
  reportScan(result: ScanResult, file?: string, line?: number): void;
  setOutputs(results: ScanResult): void;
  createSummary(shieldScore: ShieldScore | null, scanResults: ScanResult | null): string;
}

// =========================================================================
// Allowlist & Feedback
// =========================================================================

export declare class Allowlist {
  constructor(options?: { patterns?: Array<string | RegExp> });
  addRule(pattern: string | RegExp, options?: { threat?: string; reason?: string }): void;
  removeRule(pattern: string): boolean;
  check(text: string): boolean;
  filterThreats(threats: Threat[], text: string): Threat[];
  getRules(): any[];
  getStats(): { totalChecks: number; totalBypasses: number; ruleCount: number };
  exportRules(): string;
  importRules(json: string): void;
}

export declare class ConfidenceCalibrator {
  constructor();
  record(predicted: number, actual: boolean): void;
  getMetrics(): { total: number; accuracy: number; precision: number; recall: number };
  getCategoryBreakdown(): Record<string, any>;
  suggestThresholds(): any[];
  reset(): void;
}

export declare class FeedbackLoop {
  constructor(options?: { onFeedback?: (entry: any) => void });
  reportFalsePositive(scanResult: ScanResult, reason?: string): any;
  reportMissed(text: string, expectedCategory?: string): any;
  confirmDetection(id: string): void;
  confirmSafe(id: string): void;
  autoAllowlist(allowlist: Allowlist): number;
  getPendingReviews(): any[];
  getSuggestions(): any[];
  getStats(): { falsePositives: number; missed: number; confirmed: number; pending: number; total: number };
}

export declare class ScanCache {
  constructor(options?: { maxSize?: number; ttlMs?: number });
  get(text: string, sensitivity?: string): ScanResult | null;
  set(text: string, sensitivity: string, result: ScanResult): void;
  wrap(scanFn: (text: string, sensitivity: string) => ScanResult): (text: string, sensitivity: string) => ScanResult;
  clear(): void;
  prune(): number;
  getStats(): { hits: number; misses: number; evictions: number; size: number; maxSize: number; hitRate: string };
}

// =========================================================================
// Presets & Config Builder
// =========================================================================

export declare class ConfigBuilder {
  constructor();
  sensitivity(level: string): ConfigBuilder;
  blockOnThreat(enabled?: boolean): ConfigBuilder;
  logging(enabled?: boolean): ConfigBuilder;
  onThreat(callback: (result: ScanResult) => void): ConfigBuilder;
  build(): ShieldOptions;
}

export declare class SnippetGenerator {
  constructor();
  generate(options?: { framework?: string; language?: string }): string;
}

export declare function getPresets(): Record<string, any>;
export declare function getPreset(name: string): any;

// =========================================================================
// Advanced Scanners
// =========================================================================

export declare class RAGScanner {
  constructor(options?: ShieldOptions);
  scanDocument(text: string, source?: string): ScanResult;
  scanChunk(chunk: string, metadata?: any): ScanResult;
}

export declare class PromptLinter {
  constructor(options?: { rules?: string[] });
  lint(prompt: string): Array<{ rule: string; severity: string; message: string; line?: number }>;
}

export declare class ToolSchemaValidator {
  constructor(options?: { strict?: boolean });
  validate(tool: any): { valid: boolean; issues: string[] };
}

// =========================================================================
// Production
// =========================================================================

export declare class SamplingScanner {
  constructor(options?: ShieldOptions & { sampleRate?: number });
  scan(text: string, options?: any): ScanResult | null;
}

export declare class ShadowComparison {
  constructor(options?: { primary: AgentShield; shadow: AgentShield });
  scan(text: string): { primary: ScanResult; shadow: ScanResult; diverged: boolean };
}

export declare class GracefulScanner {
  constructor(options?: ShieldOptions & { timeoutMs?: number; fallback?: ScanResult });
  scan(text: string, options?: any): ScanResult;
}

export declare class ThreatReplay {
  constructor();
  record(input: string, result: ScanResult): void;
  replay(scanFn: (text: string) => ScanResult): Array<{ input: string; original: ScanResult; replayed: ScanResult; match: boolean }>;
  replayOne(index: number, scanFn: (text: string) => ScanResult): any;
  getRecordings(): any[];
  clear(): void;
}

export declare class AttackAttributionChain {
  constructor();
  recordMessage(conversationId: string, message: string, scanResult: ScanResult, metadata?: any): void;
  getKillChain(conversationId: string): any;
  getCompromisedConversations(): any[];
  clear(): void;
}

export declare class DiffReporter {
  constructor();
  takeSnapshot(name: string, scanResult: ScanResult): void;
  compare(beforeName: string, afterName: string): { added: Threat[]; removed: Threat[]; unchanged: Threat[]; changed: any };
  getSnapshots(): string[];
}

export declare class PostureTracker {
  constructor();
  record(data: { score: number; detectionRate?: number; [key: string]: any }): void;
  getTrend(): { improving: boolean; scores: number[]; average: number };
  getSummary(): any;
}

// =========================================================================
// Testing & Contracts
// =========================================================================

export declare class TestSuiteGenerator {
  constructor(options?: { shield?: AgentShield });
  generate(options?: { categories?: string[] }): Array<{ name: string; input: string; expectedDetected: boolean; category: string }>;
  run(options?: any): { passed: number; failed: number; total: number; results: any[] };
}

export declare class AgentContract {
  constructor(options?: { rules?: Array<{ name: string; check: (result: ScanResult) => boolean }> });
  addRule(name: string, checkFn: (result: ScanResult) => boolean): AgentContract;
  mustNotExfiltrateData(): AgentContract;
  mustNotExecuteCode(): AgentContract;
  mustNotAccessPath(path: string): AgentContract;
  mustStayOnTopic(topic: string): AgentContract;
  maxResponseLength(maxLen: number): AgentContract;
  validate(result: ScanResult): { valid: boolean; violations: string[] };
  getViolations(): any[];
}

export declare class BreakglassProtocol {
  constructor(options?: { defaultDurationMs?: number; onActivate?: () => void; onDeactivate?: () => void });
  activate(options: { reason: string; user?: string; durationMs?: number }): { success: boolean; reason?: string };
  deactivate(user?: string): void;
  isActive(): boolean;
  wrap(scanFn: (text: string) => ScanResult): (text: string) => ScanResult;
  getAuditLog(): any[];
  getStatus(): any;
}

// =========================================================================
// Multi-Agent Trust
// =========================================================================

export declare class MessageSigner {
  constructor(options?: { algorithm?: string });
  registerAgent(agentId: string, secret: string): boolean;
  generateSecret(agentId: string): string;
  sign(fromAgent: string, message: any): { from: string; timestamp: number; nonce: string; payload: any; signature: string };
  verify(envelope: { from: string; timestamp: number; nonce: string; payload: any; signature: string }, maxAgeMs?: number): { valid: boolean; reason?: string };
  getVerificationLog(): any[];
  getStats(): any;
}

export declare class CapabilityToken {
  constructor(options?: { issuer?: string; secret?: string });
  issue(agentId: string, capabilities: string[], ttlMs?: number): string;
  verify(token: string, requiredCapability?: string): { valid: boolean; agentId?: string; capabilities?: string[]; expired?: boolean };
}

export declare class DelegationManager {
  constructor(options?: { maxDepth?: number; secret?: string });
  issue(agentId: string, capabilities: string[], options?: { ttlMs?: number; constraints?: any }): string;
  check(tokenId: string, capability: string, context?: any): { allowed: boolean; reason?: string };
  revoke(tokenId: string): boolean;
  getAuditLog(): any[];
  getActiveTokens(): any[];
}

export declare class BlastRadiusContainer {
  constructor(options?: { maxIncidents?: number });
  defineZone(zone: { name: string; agents?: string[]; allowedCapabilities?: string[]; blockedCapabilities?: string[]; canCommunicateWith?: string[]; maxConcurrentActions?: number; description?: string }): boolean;
  checkAction(agentId: string, action: string, targetZone?: string): { allowed: boolean; reason?: string };
  releaseAction(agentId: string): void;
  quarantine(zoneName: string, reason?: string): boolean;
  unquarantine(zoneName: string): boolean;
  getZones(): any[];
  getIncidents(): any[];
}

// =========================================================================
// Extended Policy & Intelligence
// =========================================================================

export declare class ABTestRunner {
  constructor(options?: { variants: Array<{ name: string; config: ShieldOptions }> });
  run(text: string): Array<{ variant: string; result: ScanResult }>;
}

export declare class ThreatIntelFeed {
  constructor();
  addIndicator(indicator: { type: string; value: string; severity?: string }): void;
  check(text: string): { matches: any[] };
}

export declare class PatternBuilder {
  constructor();
  add(regex: RegExp, options: { severity: string; category: string; description: string }): PatternBuilder;
  build(): Pattern[];
}

export declare class Doctor {
  constructor();
  diagnose(shield?: AgentShield): { healthy: boolean; issues: string[]; recommendations: string[] };
}

export declare class GitHubActionGenerator {
  constructor();
  generate(options?: { trigger?: string; nodeVersion?: string }): string;
}

export declare class SOCIntegration {
  constructor(options?: { format?: string });
  formatAlert(threat: Threat, metadata?: any): any;
}

export declare class MigrationGuide {
  constructor();
  from(version: string): { steps: string[]; breaking: string[] };
}

export declare class Playground {
  constructor(options?: ShieldOptions);
  configure(options: ShieldOptions): void;
  test(text: string): ScanResult & { latencyMs: number };
  getHistory(): any[];
  clear(): void;
}

// =========================================================================
// Streaming
// =========================================================================

export declare class StreamScanner {
  constructor(options?: { sensitivity?: string; chunkSize?: number; onThreat?: (threat: Threat) => void });
  write(chunk: string): { threats: Threat[]; buffered: number };
  flush(): { threats: Threat[] };
  reset(): void;
}

export declare class TokenStreamScanner {
  constructor(options?: { sensitivity?: string; windowSize?: number });
  addToken(token: string): { threats: Threat[] };
  flush(): { threats: Threat[] };
}

export declare class StreamBuffer {
  constructor(options?: { windowSize?: number });
  push(token: string): void;
  getWindow(): string;
  getFullText(): string;
  lastN(n: number): string;
  clear(): void;
}

export declare function createStreamWrapper(stream: any, options?: { sensitivity?: string; extractText?: (chunk: any) => string; onThreat?: (threat: Threat) => void }): any;
export declare function scanAsyncIterator(iterator: AsyncIterable<any>, options?: { sensitivity?: string; extractText?: (chunk: any) => string; onThreat?: (threat: Threat) => void }): Promise<{ threats: Threat[]; text: string }>;

// =========================================================================
// Plugin System
// =========================================================================

export declare class PluginManager {
  constructor();
  register(plugin: { name: string; version?: string; hooks?: Record<string, Function> }): void;
  unregister(name: string): boolean;
  getPlugins(): Array<{ name: string; version: string }>;
}

export declare class PluginTemplate {
  static create(options: { name: string; version?: string }): any;
}

export declare class PluginSandbox {
  constructor(options?: { timeoutMs?: number });
  run(fn: Function, ...args: any[]): any;
}

// =========================================================================
// Token Analysis
// =========================================================================

export declare class EntropyAnalyzer {
  constructor();
  analyze(text: string): { entropy: number; suspicious: boolean; charDistribution: Record<string, number> };
}

export declare class PerplexityEstimator {
  constructor();
  estimate(text: string): { perplexity: number; suspicious: boolean };
}

export declare class BurstDetector {
  constructor(options?: { windowSize?: number; threshold?: number });
  addEvent(event?: any): { burst: boolean; count: number };
  reset(): void;
}

export declare class TextStatistics {
  static analyze(text: string): { wordCount: number; charCount: number; avgWordLength: number; uniqueWords: number; entropy: number };
}

// =========================================================================
// Document Scanner
// =========================================================================

export declare class DocumentScanner {
  constructor(options?: { sensitivity?: string });
  scan(document: string, metadata?: any): ScanResult;
}

export declare class TextExtractor {
  static fromHTML(html: string): string;
  static fromMarkdown(md: string): string;
}

export declare class IndirectInjectionScanner {
  constructor(options?: { sensitivity?: string });
  scan(text: string, source?: string): ScanResult;
}

// =========================================================================
// Tool Output Validator
// =========================================================================

export declare class ToolOutputValidator {
  constructor(options?: { sensitivity?: string; maxOutputSize?: number });
  validate(toolName: string, output: any): { safe: boolean; threats: Threat[]; sanitized?: any };
}

export declare class OutputSanitizer {
  constructor(options?: { stripHTML?: boolean; maxLength?: number });
  sanitize(output: string): string;
}

// =========================================================================
// Response Handler
// =========================================================================

export declare class ResponseHandler {
  constructor(options?: { templates?: Record<string, string>; defaultAction?: string });
  handle(scanResult: ScanResult): { action: string; response: string; original?: any };
}

export declare class ResponseTemplates {
  static get(name: string): string;
  static getAll(): Record<string, string>;
}

export declare class ReviewQueue {
  constructor(options?: { maxSize?: number });
  add(item: any): string;
  approve(id: string): any;
  reject(id: string): any;
  getPending(): any[];
  getStats(): { pending: number; approved: number; rejected: number };
}

// =========================================================================
// Worker Scanner
// =========================================================================

export declare class WorkerScanner {
  constructor(options?: { workerCount?: number });
  scan(text: string): Promise<ScanResult>;
  shutdown(): void;
}

export declare class ScanQueue {
  constructor(options?: { concurrency?: number; maxQueue?: number });
  enqueue(text: string): Promise<ScanResult>;
  getStats(): { queued: number; processing: number; completed: number };
}

// =========================================================================
// Alert Tuning
// =========================================================================

export declare class AlertFatigueAnalyzer {
  constructor(options?: { windowMs?: number; maxAlerts?: number });
  record(alert: any): { fatigued: boolean; suppressed: boolean; count: number };
  getStats(): { total: number; suppressed: number; fatigueRate: string };
}

export declare class AutoTuner {
  constructor(options?: { targetFPRate?: number });
  record(scanResult: ScanResult, wasActuallyMalicious: boolean): void;
  getSuggestions(): Array<{ action: string; reason: string }>;
}

export declare class AlertCorrelator {
  constructor(options?: { windowMs?: number });
  correlate(alert: any): { correlated: boolean; group?: string; relatedAlerts?: any[] };
}

// =========================================================================
// OpenTelemetry
// =========================================================================

export declare class ShieldMetrics {
  constructor(options?: { serviceName?: string });
  recordScan(result: ScanResult, durationMs: number): void;
  recordBlock(reason: string): void;
  getMetrics(): Record<string, number>;
}

export declare class ShieldTracer {
  constructor(options?: { serviceName?: string });
  startSpan(name: string): { end: () => void; setAttribute: (key: string, value: any) => void };
}

export declare class MetricsDashboard {
  constructor(options?: { refreshInterval?: number });
  getSummary(): any;
}

// =========================================================================
// Certification
// =========================================================================

export declare class CertificationRunner {
  constructor(options?: { sensitivity?: string });
  runCertification(): Promise<{ passed: boolean; score: number; certificate: Certificate }>;
}

export declare class Certificate {
  constructor(data: any);
  toText(): string;
  toJSON(): any;
}

export declare class CertificationHistory {
  constructor();
  record(cert: Certificate): void;
  getHistory(): Certificate[];
}

// =========================================================================
// MCP Server
// =========================================================================

export declare class MCPServer {
  constructor(options?: { port?: number });
  start(): Promise<void>;
  stop(): Promise<void>;
}

export declare class MCPToolHandler {
  constructor(shield: AgentShield);
  handleToolCall(name: string, args: any): Promise<any>;
}

// =========================================================================
// MCP Bridge (v6.0)
// =========================================================================

export declare class MCPBridge {
  constructor(options?: { scanner?: Function; allowedTools?: string[]; blockedTools?: string[]; scanInputs?: boolean; scanOutputs?: boolean; maxToolCallsPerMinute?: number });
  wrapToolCall(toolName: string, args?: object): { allowed: boolean; threats: Threat[]; sanitizedArgs: object; reason: string | null };
  wrapToolResult(toolName: string, result: any): { safe: boolean; threats: Threat[]; sanitizedResult?: any };
  validateToolSchema(schema?: object): { valid: boolean; issues: string[] };
  getStats(): object;
}

export declare class MCPToolPolicy {
  constructor(rules?: Array<{ id?: string; tool: string; action: string; conditions?: object }>);
  evaluate(toolName: string, args?: object, context?: object): { action: string; rule: string | null };
  addRule(rule: object): void;
  removeRule(ruleId: string): boolean;
  toJSON(): object;
}

export declare class MCPSessionGuard {
  constructor(sessionId: string, options?: { maxToolCalls?: number; maxTokenBudget?: number; ttlMs?: number });
  trackToolCall(toolName: string, args?: object): { allowed: boolean; reason?: string };
  checkBudget(): { withinBudget: boolean; remaining: number };
  getSessionReport(): object;
  reset(): void;
}

export declare class MCPResourceScanner {
  constructor(options?: { scanner?: Function });
  scanResource(uri: string, content: string, mimeType?: string): { safe: boolean; threats: Threat[]; uri: string };
  scanPromptTemplate(template: string): { safe: boolean; threats: Threat[] };
}

export declare function createMCPMiddleware(options?: { scanner?: Function; allowedTools?: string[]; blockedTools?: string[]; scanInputs?: boolean; scanOutputs?: boolean }): {
  onToolCall(toolName: string, args: object): { allowed: boolean; threats: Threat[]; sanitizedArgs: object; reason: string | null };
  onToolResult(toolName: string, result: any): { safe: boolean; threats: Threat[] };
  onResourceAccess(uri: string, content: string, mimeType?: string): { safe: boolean; threats: Threat[] };
  getBridge(): MCPBridge;
};

// =========================================================================
// MCP SDK Integration (v7.1)
// =========================================================================

export declare function shieldMCPServer(server: any, options?: { scanInputs?: boolean; scanOutputs?: boolean; blockOnThreat?: boolean; sensitivity?: string; onThreat?: (info: any) => void }): any;
export declare function createMCPSecurityLayer(options?: { scanInputs?: boolean; scanOutputs?: boolean; blockOnThreat?: boolean; sensitivity?: string }): object;

// =========================================================================
// CTF
// =========================================================================

export declare class CTFEngine {
  constructor(options?: { difficulty?: string });
  getChallenge(id: string): any;
  submitAnswer(id: string, answer: string): { correct: boolean; score: number };
  getScoreboard(): any;
}

export declare class CTFReporter {
  constructor();
  formatReport(scoreboard: any): string;
}

export declare const CHALLENGES: any[];

// =========================================================================
// Observability
// =========================================================================

export declare class PrometheusExporter {
  constructor(options?: { prefix?: string });
  increment(name: string, labels?: Record<string, string>): void;
  observe(name: string, value: number, labels?: Record<string, string>): void;
  set(name: string, value: number, labels?: Record<string, string>): void;
  metrics(): string;
  wrapShield(shield: AgentShield): AgentShield;
}

export declare class DatadogLogger {
  constructor(options?: { service?: string; env?: string; version?: string; maxBuffer?: number });
  log(event: string, data?: any): void;
  logScan(result: ScanResult, metadata?: any): void;
  logThreat(threat: Threat, metadata?: any): void;
  logBlock(reason: string, metadata?: any): void;
  flush(): any[];
}

export declare class MetricsCollector {
  constructor(options?: { ttlMs?: number; maxEvents?: number });
  record(event: { type: string; durationMs?: number; threats?: number; category?: string }): void;
  getSummary(windowMs?: number): { scansPerSec: number; threatsPerSec: number; p50: number; p95: number; p99: number; topCategories: Array<{ category: string; count: number }> };
}

// =========================================================================
// Adaptive Detection
// =========================================================================

export declare class AdaptiveDetector {
  constructor(options?: { storagePath?: string });
  recordFalsePositive(text: string, category: string): void;
  recordFalseNegative(text: string, category: string): void;
  shouldSuppress(text: string, category: string): boolean;
  getBoost(text: string, category: string): number;
  adjustResult(scanResult: ScanResult): ScanResult;
  getStats(): { falsePositives: number; falseNegatives: number };
  save(): void;
  load(): void;
}

export declare class SemanticAnalysisHook {
  constructor(options: { classifier: (text: string, threats: Threat[]) => Promise<{ override: boolean; reason: string }>; timeoutMs?: number });
  analyze(text: string, scanResult: ScanResult): Promise<ScanResult>;
  getStats(): { overrides: number; errors: number; avgLatencyMs: number };
}

export declare class CommunityPatterns {
  constructor(options?: { path?: string });
  load(): void;
  getPatterns(): Pattern[];
  merge(existingPatterns: Pattern[]): Pattern[];
  getVersion(): string;
}

// =========================================================================
// OWASP LLM Top 10 v2025 (v6.0)
// =========================================================================

export declare class OWASPCoverageMatrix {
  constructor(options?: { agentShield?: AgentShield; organizationName?: string });
  getCoverage(): object;
  getCoverageScore(): { score: number; covered: number; total: number };
  getGaps(): Array<{ id: string; name: string; recommendation: string }>;
  getRecommendations(): Array<{ id: string; priority: string; action: string }>;
  validateCompliance(scanResults?: object): object;
  getCoverageReport(format?: 'text' | 'markdown'): string;
}

// =========================================================================
// NIST AI RMF Mapping (v6.0)
// =========================================================================

export declare class NISTMapper {
  constructor(options?: { organizationName?: string; systemName?: string; riskLevel?: 'low' | 'medium' | 'high' | 'critical' });
  getCoverageMap(): object;
  getCoverageScore(): { score: number; covered: number; total: number };
  getGaps(): Array<{ id: string; name: string; recommendation: string }>;
  generateProfile(systemDescription?: string): object;
  generateReport(format?: 'text' | 'markdown'): string;
}

export declare class AIBOMGenerator {
  constructor(options?: { format?: 'spdx' | 'cyclonedx' | 'custom'; organizationName?: string; systemName?: string });
  addComponent(component: object): void;
  addModel(model: object): void;
  addDataset(dataset: object): void;
  addService(service: object): void;
  generate(): object;
  validate(): { valid: boolean; errors: string[] };
  toJSON(): object;
  toSPDX(): object;
  toCycloneDX(): object;
}

export declare class NISTComplianceChecker {
  constructor(nistMapper: NISTMapper);
  checkAgainstProfile(profile: object, currentState?: object): object;
  generateActionPlan(): object;
  generateAuditArtifact(format?: 'json' | 'text'): any;
}

// =========================================================================
// EU AI Act Compliance (v6.0)
// =========================================================================

export declare class RiskClassifier {
  constructor(options?: { sector?: string; purpose?: string; dataTypes?: string[] });
  classify(systemDescription?: string): { riskLevel: string; category: string; articles: string[] };
  getApplicableArticles(): object[];
  generateRiskAssessment(): object;
}

export declare class ConformityAssessment {
  constructor(systemInfo?: { name?: string; provider?: string; version?: string });
  addEvidence(reqArticle: string, evidence: string): void;
  checkRequirement(reqArticle: string): object;
  getStatus(): object;
  generateReport(format?: 'json' | 'text'): any;
  generateTechnicalDocumentation(): object;
  generateDeclarationOfConformity(): object;
}

export declare class TransparencyReporter {
  constructor(options?: { providerName?: string });
  generateModelCard(modelInfo?: object): object;
  generateTrainingDataSummary(dataInfo?: object): object;
  generateCopyrightPolicy(): object;
  generateEnergyReport(metrics?: object): object;
}

export declare class EUIncidentReporter {
  constructor(options?: { providerName?: string; contactEmail?: string; nationalAuthority?: string });
  createReport(incident?: object): object;
  getNotificationDeadline(severity?: string): object;
  generateCorrective(incident?: object): object;
}

export declare class EUAIActDashboard {
  constructor(riskClassifier?: RiskClassifier, conformity?: ConformityAssessment);
  getComplianceStatus(): object;
  getDeadlines(): object[];
  getActionItems(): object[];
}

// =========================================================================
// Prompt Leakage Detection (v6.0)
// =========================================================================

export declare class PromptFingerprinter {
  constructor();
  fingerprint(text: string): object;
  compare(fp: object, text: string): { similarity: number; leaked: boolean };
  detectPartialLeak(fp: object, output: string): { leaked: boolean; matches: any[] };
}

export declare class SystemPromptGuard {
  constructor(options?: { systemPrompt?: string; sensitivity?: 'low' | 'medium' | 'high'; enableFingerprinting?: boolean });
  registerSystemPrompt(prompt: string): void;
  scanInput(input: string): { suspicious: boolean; threats: any[]; action: string };
  scanOutput(output: string): { leaked: boolean; findings: any[]; leakageScore: number };
  getLeakageScore(output: string): number;
  getStats(): object;
}

export declare class PromptLeakageMitigation {
  constructor();
  addDefenseLayer(prompt: string): string;
  wrapPrompt(prompt: string): string;
  generateDecoy(): string;
}

// =========================================================================
// RAG Vulnerability Scanning (v6.0)
// =========================================================================

export declare class RAGVulnerabilityScanner {
  constructor(options?: { chunkSize?: number; overlapSize?: number; maxRetrievedDocs?: number });
  scanChunk(chunk: string, metadata?: object): object;
  scanRetrievalSet(chunks: string[], query: string): object;
  analyzeChunkBoundaries(chunks: string[]): object;
  validateMetadata(metadata: object): object;
  assessContextWindowRisk(systemPrompt: string, retrievedDocs: string[], userQuery: string, contextWindowSize?: number): object;
  getStats(): object;
}

export declare class EmbeddingIntegrityChecker {
  constructor(options?: { distanceThreshold?: number; anomalyMethod?: 'zscore' | 'isolation' });
  checkDistribution(embeddings: number[][]): object;
  detectOutliers(embeddings: number[][], labels?: string[]): object;
  measureDrift(baselineEmbeddings: number[][], currentEmbeddings: number[][]): object;
  validateEmbeddingConsistency(text: string, embedding: number[]): object;
}

export declare class RAGPipelineAuditor {
  constructor(pipelineConfig?: { chunkingStrategy?: string; embeddingModel?: string; vectorDB?: string });
  audit(): object;
  getVulnerabilities(): object[];
  getRecommendations(): object[];
  generateReport(format?: 'text' | 'markdown'): string;
}

// =========================================================================
// Benchmark Harness (v5.0)
// =========================================================================

export declare class DatasetLoader {
  load(filePath: string): { entries: object[]; meta: object };
  validate(entries: object[]): { valid: boolean; errors: string[] };
  fromBIPIA(entries: object[]): object[];
  fromGarak(entries: object[]): object[];
}

export declare class BenchmarkMetrics {
  compute(results: Array<{ entry: object; detected: boolean; expected: boolean; latencyMs: number }>): object;
}

export declare class RegressionTracker {
  constructor(options?: { f1Threshold?: number; latencyThreshold?: number });
  saveBaseline(metrics: object, filePath: string): void;
  loadBaseline(filePath: string): object;
  compare(current: object, baseline: object): object;
}

export declare class BenchmarkReportGenerator {
  text(metrics: object, options?: { title?: string }): string;
  json(metrics: object): string;
  markdown(metrics: object, options?: { title?: string }): string;
  comparisonText(comparison: object): string;
}

export declare class BenchmarkHarness {
  constructor(options?: { warmupRuns?: number });
  loadDataset(filePath: string): void;
  loadEntries(entries: object[]): void;
  run(detectorFn: (text: string) => any): object;
  compare(detectors: Record<string, (text: string) => any>): object;
  formatReport(results: object): string;
  formatComparison(comparison: object): string;
  formatMarkdown(results: object): string;
}

// =========================================================================
// Adaptive Defense (v7.1)
// =========================================================================

export declare class LearningLoop {
  constructor(options?: { minHitsToPromote?: number; maxLearnedPatterns?: number; promotionConfidence?: number });
  ingest(attack: { text: string; category?: string; source?: string }): object;
  check(text: string): { matches: any[]; boosted: boolean };
  recordFeedback(patternId: string, type: 'confirmed' | 'false_positive', reason?: string): void;
  getActivePatterns(): object[];
  getReport(): object;
  exportPatterns(): string;
  importPatterns(data: string): void;
}

export declare class BehaviorContract {
  constructor(spec: { agentId: string; allowedTools?: string[]; deniedTools?: string[]; maxToolCallsPerMinute?: number; maxDelegationDepth?: number; allowedScopes?: string[]; requiredIntents?: boolean; maxResponseLength?: number; timeWindows?: Array<{ start: number; end: number }>; customValidator?: Function });
  verify(action: { type: string; tool?: string; args?: any; depth?: number; scope?: string; intent?: string; responseLength?: number }): { allowed: boolean; violations: any[] };
  getViolations(limit?: number): any[];
  getComplianceRate(): { total: number; passed: number; violated: number; rate: string };
  toJSON(): object;
}

export declare class ContractRegistry {
  constructor();
  register(contract: BehaviorContract): void;
  onViolation(callback: (violation: any) => void): void;
  enforce(agentId: string, action: object): { allowed: boolean; violations: any[] };
  getComplianceReport(): object;
  getRegisteredAgents(): string[];
}

export declare class ComplianceAttestor {
  constructor(options?: { frameworks?: string[]; attestationIntervalMs?: number; onComplianceDrift?: Function });
  updateSignal(signal: string, value: any): void;
  updateSignals(signals: Record<string, any>): void;
  attest(): object;
  getCurrentState(): object;
  getHistory(limit?: number): object[];
  getTrend(): object;
  generateProof(signingKey?: string): object;
}

// =========================================================================
// Constants
// =========================================================================

export declare const SEVERITY_ORDER: Record<string, number>;
export declare const API_KEY_PATTERNS: any[];
export declare const PII_PATTERNS: Record<string, any>;
export declare const CONTENT_CATEGORIES: Record<string, any>;
export declare const SUSPICIOUS_SEQUENCES: any[];
export declare const STEGO_PATTERNS: any[];
export declare const ATTACK_PAYLOADS: Record<string, any>;
export declare const SCORE_CATEGORIES: Record<string, any>;
export declare const THREAT_ENCYCLOPEDIA: any[];
export declare const DAILY_PATTERNS: any[];
export declare const COMPLIANCE_FRAMEWORKS: Record<string, any>;
export declare const INCIDENT_PLAYBOOKS: Record<string, any>;
export declare const DEFAULT_ROLES: Record<string, any>;
export declare const PRESETS: Record<string, any>;
export declare const RAG_INJECTION_PATTERNS: any[];
export declare const LINT_RULES: any[];
export declare const DANGEROUS_TOOL_PATTERNS: any[];
export declare const ATTACK_TEMPLATES: Record<string, any>;

// =========================================================================
// Utilities
// =========================================================================

export declare function getGrade(score: number): string;
export declare function getGradeLabel(score: number): string;
export declare function makeBar(value: number, max: number, width?: number): string;
export declare function truncate(text: string, maxLength?: number): string;
export declare function formatHeader(text: string): string;
export declare function generateId(): string;
export declare function extractTextFromBody(body: any): string;

export interface GracefulShutdownOptions {
  timeoutMs?: number;
  cleanupFns?: Array<() => void | Promise<void>>;
  logger?: (...args: any[]) => void;
}

export declare function createGracefulShutdown(options?: GracefulShutdownOptions): {
  shutdown: (signal?: string) => Promise<void>;
  onShutdown: (fn: () => void | Promise<void>) => void;
};

export interface LoadEnvResult {
  loaded: number;
  errors: string[];
}

export declare function loadEnvFile(options?: { path?: string; overwrite?: boolean }): LoadEnvResult;

// =========================================================================
// Errors
// =========================================================================

export declare function createShieldError(code: string, details?: object): Error;
export declare function deprecationWarning(feature: string, replacement: string, removeVersion: string): void;

// =========================================================================
// OpenClaw Integration
// =========================================================================

export declare class OpenClawShieldSkill {
  constructor(options?: ShieldOptions & { pii?: boolean; circuitBreaker?: CircuitBreakerOptions; onThreat?: (info: any) => void });
  getSkillMetadata(): string;
  scanInbound(message: string | object): { safe: boolean; blocked: boolean; threats: Threat[]; redacted?: string; pii?: any; stats?: any };
  scanOutbound(message: string | object): { safe: boolean; blocked: boolean; threats: Threat[]; redacted?: string };
  scanTool(toolName: string, args: object): { safe: boolean; blocked: boolean; threats: Threat[] };
  handleToolCall(params?: object): object;
}

export declare function shieldOpenClawMessages(options?: ShieldOptions): { scan: (message: string) => ScanResult };
export declare function generateOpenClawSkill(outputDir: string): Promise<void>;

// =========================================================================
// Semantic Detection (v1.2)
// =========================================================================

export declare class SemanticClassifier {
  constructor(options?: { endpoint?: string; model?: string; timeoutMs?: number; apiKey?: string; mode?: string; confidenceThreshold?: number; enabled?: boolean });
  classify(text: string, context?: object): Promise<{ isThreat: boolean; confidence: number; category: string; reasoning: string; latencyMs: number }>;
  enhancedScan(text: string, options?: object): Promise<ScanResult>;
  isAvailable(): Promise<boolean>;
  getStats(): { totalClassifications: number; threats: number; avgLatencyMs: number };
  clearCache(): void;
}

export declare function httpPost(url: string, body: object, options?: { timeoutMs?: number; apiKey?: string }): Promise<object>;

// =========================================================================
// Embedding Similarity (v1.2)
// =========================================================================

export declare class EmbeddingSimilarityDetector {
  constructor(options?: { similarityThreshold?: number; topK?: number; customCorpus?: Array<{ text: string; category: string }>; enabled?: boolean });
  check(text: string): { isSimilar: boolean; topMatches: Array<{ text: string; category: string; similarity: number }>; bestMatch: { text: string; category: string; similarity: number } | null };
  enhancedScan(text: string, options?: object): ScanResult;
  addPattern(text: string, category: string): void;
  getStats(): object;
}

export declare const ATTACK_CORPUS: Array<{ text: string; category: string }>;
export declare function tokenizeText(text: string): string[];
export declare function cosineSimilarity(vecA: Map<string, number>, vecB: Map<string, number>): number;

// =========================================================================
// Context-Aware Scoring (v1.2)
// =========================================================================

export declare class ConversationContextAnalyzer {
  constructor(options?: { maxHistory?: number; escalationThreshold?: number; decayFactor?: number; trackTopics?: boolean });
  addMessage(text: string, role?: string): object;
  contextualScan(text: string): ScanResult;
  getSummary(): object;
  reset(): void;
}

export declare const ESCALATION_SIGNALS: Array<{ phase: string; patterns: RegExp[]; weight: number }>;
export declare const TOPIC_PIVOT_SIGNALS: Array<{ from: string; to: string; severity: string }>;

// =========================================================================
// Confidence Tuning (v1.2)
// =========================================================================

export declare class ConfidenceTuner {
  constructor(options?: { dataDir?: string; defaultThreshold?: number; learningRate?: number; minSamples?: number });
  recordFeedback(scanResult: ScanResult, label: string, notes?: string): object;
  getThreshold(category: string): number;
  applyThresholds(scanResult: ScanResult): ScanResult;
  tunedScan(text: string, options?: object): ScanResult;
  getMetrics(): { precision: number; recall: number; f1: number; accuracy: number; perCategory: Record<string, any> };
  getRecommendations(): Array<{ category: string; action: string; reason: string }>;
  reset(): void;
}

// =========================================================================
// Plugin Marketplace (v2.0)
// =========================================================================

export declare class PluginValidator {
  validate(manifest: object): { valid: boolean; errors: string[]; warnings: string[]; score: number; grade: string };
  runTests(manifest: object): { passed: number; failed: number; total: number; results: any[] };
}

export declare class PluginRegistry {
  constructor(options?: { pluginDir?: string; autoValidate?: boolean });
  register(manifest: object): { success: boolean; validation?: object; error?: string };
  unregister(name: string): boolean;
  enable(name: string): boolean;
  disable(name: string): boolean;
  get(name: string): object | null;
  list(): Array<object>;
  search(query: string): Array<object>;
  scan(text: string): { threats: Threat[]; pluginsUsed: string[] };
  getStats(): object;
}

export declare class MarketplaceClient {
  constructor(options?: { registryUrl?: string; timeoutMs?: number; registry?: PluginRegistry });
  browse(filters?: object): Promise<{ plugins: object[]; error?: string }>;
  install(name: string): Promise<{ success: boolean; plugin?: object; error?: string }>;
  publish(manifest: object): Promise<{ success: boolean; error?: string; validation?: object }>;
}

// =========================================================================
// Distributed Scanning (v2.1)
// =========================================================================

export declare class DistributedAdapter {
  set(key: string, value: any, ttlMs?: number): Promise<void>;
  get(key: string): Promise<any>;
  del(key: string): Promise<boolean>;
  publish(channel: string, message: any): Promise<void>;
  subscribe(channel: string, handler: (message: any) => void): Promise<void>;
  incr(key: string, amount?: number): Promise<number>;
}

export declare class MemoryAdapter extends DistributedAdapter {
  constructor();
  keys(prefix: string): Promise<string[]>;
  destroy(): void;
}

export declare class RedisAdapter extends DistributedAdapter {
  constructor(options: { client: object; prefix?: string });
}

export declare class DistributedShield {
  constructor(options?: { adapter?: DistributedAdapter; instanceId?: string; syncIntervalMs?: number; threatTTLMs?: number });
  start(): Promise<void>;
  reportThreat(threat: object): Promise<void>;
  getGlobalStats(): Promise<object>;
  isKnownThreat(signature: string): Promise<boolean>;
  markKnownThreat(signature: string, metadata?: object): Promise<void>;
  stop(): Promise<void>;
}

// =========================================================================
// Audit Streaming (v2.1)
// =========================================================================

export declare class AuditTransport {
  send(event: object): Promise<void>;
  sendBatch(events: object[]): Promise<void>;
  flush(): Promise<void>;
  close(): Promise<void>;
}

export declare class FileTransport extends AuditTransport {
  constructor(options?: { filePath?: string; maxSizeMB?: number; maxFiles?: number });
}

export declare class SplunkTransport extends AuditTransport {
  constructor(options: { url: string; token: string; index?: string; source?: string; sourcetype?: string; batchSize?: number; flushIntervalMs?: number });
  getStats(): object;
}

export declare class ElasticsearchTransport extends AuditTransport {
  constructor(options: { url: string; index?: string; apiKey?: string; batchSize?: number; flushIntervalMs?: number });
  getStats(): object;
}

export declare class AuditStreamManager {
  constructor(options?: { transports?: AuditTransport[]; includeMetadata?: boolean; environment?: string });
  addTransport(transport: AuditTransport): void;
  emit(type: string, data?: object): Promise<void>;
  emitScan(scanResult: ScanResult, context?: object): Promise<void>;
  emitThreat(threat: Threat, context?: object): Promise<void>;
  emitBlock(reason: string, context?: object): Promise<void>;
  flush(): Promise<void>;
  close(): Promise<void>;
  getStats(): object;
}

// =========================================================================
// Immutable Audit Log (v2.1)
// =========================================================================

export declare class AuditEntry {
  id: string;
  sequence: number;
  timestamp: string;
  type: string;
  data: object;
  actor: { type: string; id: string; name?: string };
  previousHash: string;
  hash: string;
  constructor(params: { id: string; timestamp: string; type: string; data: object; actor: { type: string; id: string; name?: string }; previousHash: string; hash: string; sequence: number });
  toJSON(): object;
}

export declare class AuditProof {
  proofId: string;
  generatedAt: string;
  anchorHash: string;
  entries: AuditEntry[];
  startId: string;
  endId: string;
  entryCount: number;
  chainHead: string;
  proofHash: string;
  constructor(params: { proofId: string; generatedAt: string; anchorHash: string; entries: AuditEntry[]; startId: string; endId: string; entryCount: number; chainHead: string; proofHash: string });
  verify(): { valid: boolean; error: string | null };
  toJSON(): object;
}

export declare class ImmutableAuditLog {
  constructor(options?: { store?: object; maxEntries?: number; maxAge?: number; archiveCallback?: (entries: AuditEntry[]) => void; genesisHash?: string });
  append(type: string, data: object, actor: { type: string; id: string; name?: string }): Promise<AuditEntry>;
  verify(): Promise<{ valid: boolean; brokenAt: number | null; totalEntries: number }>;
  exportProof(startId: string, endId: string): Promise<AuditProof>;
  query(filters?: { type?: string; actorId?: string; since?: string; until?: string }): Promise<AuditEntry[]>;
  export(format?: 'json' | 'csv'): Promise<string>;
  getStats(): Promise<object>;
  getChainHead(): Promise<string | null>;
  count(): Promise<number>;
}

// =========================================================================
// Self-Healing (v3.0)
// =========================================================================

export declare class SelfHealingEngine {
  constructor(options?: { maxPatterns?: number; autoApply?: boolean; onHeal?: (patterns: Pattern[]) => void });
  reportFalseNegative(attackText: string, metadata?: object): { healed: boolean; patterns: Pattern[]; error?: string };
  scan(text: string, options?: object): ScanResult;
  getPatterns(): Pattern[];
  getStats(): object;
  exportPatterns(): string;
  reset(): void;
}

export declare class SelfHealingPatternGenerator {
  constructor();
  generate(attackText: string, options?: { category?: string }): Pattern | null;
  generateVariants(attackText: string, options?: object): Pattern[];
}

// =========================================================================
// Honeypot (v3.0)
// =========================================================================

export declare class HoneypotSession {
  constructor(sessionId: string, metadata?: object);
  addMessage(text: string, scanResult: ScanResult): void;
  getSummary(): object;
  end(): void;
}

export declare class HoneypotEngine {
  constructor(options?: { maxSessions?: number; sessionTimeoutMs?: number; responseGenerator?: (text: string) => string; onAttack?: (info: any) => void; enabled?: boolean });
  process(text: string, sessionId?: string): { response: string; session: HoneypotSession; scanResult: ScanResult; isAttack: boolean; honeypotActive: boolean };
  getIntelligenceReport(): object;
  getCompletedSessions(): HoneypotSession[];
  endAllSessions(): void;
  getStats(): object;
  reset(): void;
}

// =========================================================================
// Multi-Modal (v3.0)
// =========================================================================

export declare class ModalityExtractor {
  constructor();
  extractFromImage(imageData: object): Array<{ text: string; source: string }>;
  extractFromAudio(audioData: object): Array<{ text: string; source: string }>;
  extractFromPDF(pdfData: object): Array<{ text: string; source: string }>;
  extractFromToolOutput(toolOutput: object, toolName?: string): Array<{ text: string; source: string }>;
}

export declare class MultiModalScanner {
  constructor(options?: { sensitivity?: string; onThreat?: (threat: Threat) => void });
  scanImage(imageData: object): ScanResult;
  scanAudio(audioData: object): ScanResult;
  scanPDF(pdfData: object): ScanResult;
  scanToolOutput(toolOutput: object, toolName?: string): ScanResult;
  scanRaw(modality: string, texts: Array<{ text: string; source: string }>): ScanResult;
  getStats(): object;
}

// =========================================================================
// Behavior Profiling (v3.0)
// =========================================================================

export declare class BehaviorProfile {
  constructor(options?: { windowSize?: number; learningPeriod?: number; anomalyThreshold?: number });
  record(observation: { responseLength?: number; responseTimeMs?: number; toolsCalled?: string[]; threatScore?: number; topic?: string }): { anomalies: any[]; isLearning: boolean };
  getBaseline(): object;
  getReport(): object;
  healthCheck(): { normal: boolean; riskLevel: string; concerns: string[] };
  reset(): void;
}

// =========================================================================
// SSO/SAML (v2.1)
// =========================================================================

export declare class SSOSession {
  constructor(identity: object, role: string, permissions: string[], ttl: number);
  isValid(): boolean;
  hasPermission(permission: string): boolean;
  toJSON(): object;
}

export declare class IdentityMapper {
  constructor(mappingRules?: Array<{ idpGroup: string; shieldRole: string; permissions: string[] }>);
  addRule(rule: { idpGroup: string; shieldRole: string; permissions: string[] }): this;
  mapIdentity(identity: object): { role: string; permissions: string[] };
}

export declare class SAMLParser {
  constructor();
  parseAssertion(xml: string): { issuer: string; subject: string; conditions: object; attributes: object; raw: string };
  validateAssertion(assertion: object, provider: object): { valid: boolean; errors: string[] };
  extractAttributes(assertion: object): { email: string; name: string; groups: string[]; roles: string[]; custom: Record<string, any> };
  buildAuthnRequest(provider: object): string;
}

export declare class OIDCHandler {
  constructor(config?: { clientId?: string; issuer?: string; redirectUri?: string });
  buildAuthorizationUrl(state: string): string;
  exchangeCode(code: string): { access_token: string; id_token: string; token_type: string; expires_in: number };
  validateIdToken(token: string): { valid: boolean; claims: object; errors: string[] };
  getUserInfo(accessToken: string): { sub: string; email: string; name: string; groups: string[] };
}

export declare class SSOManager {
  constructor(config?: { providers?: object[]; defaultRole?: string; sessionTTL?: number; auditLog?: boolean });
  registerProvider(provider: object): this;
  authenticate(providerType: string, assertion: string): SSOSession;
  mapToRole(identity: object): { role: string; permissions: string[] };
  getSession(sessionId: string): SSOSession | null;
  revokeSession(sessionId: string): boolean;
  listActiveSessions(): SSOSession[];
  getAuditLog(): object[];
}

export declare const SSO_DEFAULT_MAPPINGS: Array<{ idpGroup: string; shieldRole: string; permissions: string[] }>;

// =========================================================================
// Model Fine-Tuning (v2.1)
// =========================================================================

export declare class FineTunedModel {
  constructor(weights: number[], vocabulary: string[], config: object);
  predict(text: string): { label: string; confidence: number };
  predictBatch(texts: string[]): Array<{ label: string; confidence: number }>;
  export(): object;
  static load(json: object): FineTunedModel;
  getFeatureImportance(topN?: number): Array<{ term: string; weight: number }>;
}

export declare class DatasetManager {
  constructor();
  addSample(text: string, label: string, metadata?: object): this;
  addFromScanHistory(scanResults: ScanResult[]): this;
  augment(): this;
  split(ratio?: number): { train: any[]; validation: any[]; test: any[] };
  getStats(): object;
  export(): object;
}

export declare class ModelTrainer {
  constructor(config?: { learningRate?: number; epochs?: number; batchSize?: number; validationSplit?: number });
  train(dataset: Array<{ text: string; label: string }>): FineTunedModel;
}

export declare class ModelEvaluator {
  constructor();
  evaluate(model: FineTunedModel, testSet: Array<{ text: string; label: string }>): { accuracy: number; precision: number; recall: number; f1: number; confusionMatrix: object; roc_auc: number };
  generateReport(): string;
}

export declare class TrainingPipeline {
  constructor(options?: { config?: object; datasetManager?: DatasetManager; trainer?: ModelTrainer; evaluator?: ModelEvaluator });
  run(dataset: Array<{ text: string; label: string }>): Promise<{ model: FineTunedModel; evaluation: object }>;
}

// =========================================================================
// Threat Intelligence Network (v3.0)
// =========================================================================

export declare class PatternAnonymizer {
  constructor(level?: 'low' | 'medium' | 'high');
  anonymize(pattern: object): object;
  hashPattern(pattern: object): string;
  generalize(regex: string): string;
  stripMetadata(metadata: object): object;
  addNoise(stats: object, sensitivity?: number, epsilon?: number): object;
}

export declare class PeerNode {
  constructor(nodeId: string, config?: { heartbeatIntervalMs?: number; heartbeatTimeoutMs?: number });
  connect(peerInfo: object): boolean;
  send(message: object): boolean;
}

export declare class ConsensusEngine {
  constructor(options?: { quorum?: number; votingTimeoutMs?: number });
  propose(pattern: object): Promise<{ accepted: boolean; votes: number }>;
  vote(proposalId: string, accept: boolean): void;
}

export declare class ThreatFeed {
  constructor(options?: { maxPatterns?: number; ttlMs?: number });
  add(pattern: object): void;
  getPatterns(): object[];
  getRecent(count?: number): object[];
}

export declare class ThreatIntelNetwork {
  constructor(options?: { nodeId?: string; anonymizationLevel?: string; consensusQuorum?: number });
  start(): Promise<void>;
  sharePattern(pattern: object): Promise<void>;
  getSharedPatterns(): object[];
  stop(): void;
}

export declare const NETWORK_DEFAULTS: object;

// =========================================================================
// I18n Patterns (v4.0)
// =========================================================================

export declare class I18nPatternManager {
  constructor(options?: { languages?: string[] });
  getPatterns(language?: string): Pattern[];
  addPattern(language: string, pattern: Pattern): void;
  getAllPatterns(): Pattern[];
  getSupportedLanguages(): string[];
}

export declare const CJK_PATTERNS: Array<{ regex: RegExp; severity: string; category: string; description: string; language: string }>;
export declare const ARABIC_PATTERNS: Array<{ regex: RegExp; severity: string; category: string; description: string; language: string }>;
export declare const CYRILLIC_PATTERNS: Array<{ regex: RegExp; severity: string; category: string; description: string; language: string }>;
export declare const INDIC_PATTERNS: Array<{ regex: RegExp; severity: string; category: string; description: string; language: string }>;
export declare const MULTILINGUAL_PATTERNS: any[];
export declare function getI18nPatterns(language?: string): Pattern[];

// =========================================================================
// LLM Red Team Suite (v4.0)
// =========================================================================

export declare class AdversarialGenerator {
  constructor();
  generatePayloads(category: string, count?: number): Array<{ payload: string; category: string; technique: string }>;
  mutate(payload: string): string;
  chainAttacks(payloads: string[]): Array<string[]>;
  generateEvasion(payload: string, technique: string): string;
}

export declare class JailbreakLibrary {
  constructor();
  getTemplates(category: string): string[];
  getCategories(): string[];
  addTemplate(category: string, template: string): void;
  search(keyword: string): string[];
}

export declare class EvasionTester {
  constructor(options?: { sensitivity?: string; mutations?: number });
  test(payload: string): { totalMutations: number; detected: number; evaded: number; evasionRate: string; evasions: Array<{ mutation: string; text: string }> };
}

export declare class LLMRedTeamSuite {
  constructor(options?: { sensitivity?: string });
  runAll(): object;
  runCategory(category: string): object;
  generateReport(): object;
  formatReport(): string;
}

export declare const JAILBREAK_TEMPLATES: Record<string, string[]>;
export declare const MUTATION_TECHNIQUES: string[];

// =========================================================================
// Agent Protocol (v5.0)
// =========================================================================

export declare class ProtocolMessage {
  constructor(type: string, payload: any, senderId: string, sequenceNum: number);
  serialize(): string;
  static deserialize(raw: string): ProtocolMessage;
  isExpired(timeout: number): boolean;
  static TYPES: string[];
}

export declare class AgentIdentity {
  constructor(agentId: string, capabilities?: string[], metadata?: object);
  sign(secretKey: string): string;
  verify(signature: string, secretKey: string): boolean;
  hasCapability(cap: string): boolean;
  toJSON(): object;
  static fromJSON(json: object): AgentIdentity;
  static TRUST_LEVELS: string[];
}

export declare class SecureChannel {
  constructor(localIdentity: AgentIdentity, remoteIdentity: AgentIdentity, sharedSecret: string);
  send(payload: any, type?: string): string;
  receive(encrypted: string): { valid: boolean; message?: ProtocolMessage; error?: string };
  getStats(): object;
}

export declare class HandshakeManager {
  constructor(options?: { timeoutMs?: number });
  initiate(localIdentity: AgentIdentity, remoteIdentity: AgentIdentity): { challenge: string; sessionId: string };
  respond(challenge: string, identity: AgentIdentity): { response: string; sessionId: string };
  verify(response: string, sessionId: string): { valid: boolean; channel?: SecureChannel };
}

export declare class MessageRouter {
  constructor();
  register(agentId: string, handler: (message: ProtocolMessage) => void): void;
  unregister(agentId: string): void;
  route(message: ProtocolMessage): boolean;
  broadcast(message: ProtocolMessage, exclude?: string[]): number;
}

export declare class AgentProtocol {
  constructor(options?: { identity?: AgentIdentity; secret?: string });
  connect(remoteIdentity: AgentIdentity): SecureChannel;
  listen(handler: (message: ProtocolMessage, channel: SecureChannel) => void): void;
  getConnections(): object[];
}

export declare const PROTOCOL_VERSION: string;

// =========================================================================
// Policy DSL (v5.0)
// =========================================================================

export declare class PolicyParser {
  constructor();
  tokenize(source: string): Array<{ type: string; value: string; line: number; col: number }>;
  parse(tokens: any[]): { type: string; policies: any[] };
}

export declare class PolicyCompiler {
  constructor();
  compile(ast: object): { execute: (context: object) => object };
}

export declare class PolicyRuntime {
  constructor(options?: { builtins?: Record<string, Function> });
  load(source: string): void;
  evaluate(context: object): { allowed: boolean; violations: string[]; actions: string[] };
}

export declare class PolicyValidator {
  constructor();
  validate(source: string): { valid: boolean; errors: string[]; warnings: string[] };
}

export declare class PolicyDSL {
  constructor(options?: { source?: string; strict?: boolean });
  load(source: string): void;
  evaluate(context: object): { allowed: boolean; violations: string[]; actions: string[] };
  validate(): { valid: boolean; errors: string[]; warnings: string[] };
}

export declare const DSL_BUILTINS: Record<string, Function>;
export declare const EXAMPLE_STRICT_POLICY: string;
export declare const EXAMPLE_PERMISSIVE_POLICY: string;
export declare const EXAMPLE_CUSTOM_RULES_POLICY: string;

// =========================================================================
// Fuzzing Harness (v5.0)
// =========================================================================

export declare class InputGenerator {
  constructor(options?: { seed?: number });
  generate(count?: number): string[];
  generateFromGrammar(grammar?: object): string;
}

export declare class FuzzMutationEngine {
  constructor(options?: { seed?: number });
  mutate(input: string): string;
}

export declare class CoverageTracker {
  constructor();
  record(input: string, result: ScanResult): void;
  getCoverage(): { categories: string[]; patterns: number; totalInputs: number; coverageRate: string };
  getUncovered(): string[];
}

export declare class FuzzReport {
  constructor(results: any[]);
  getSummary(): { total: number; crashes: number; uniqueFindings: number; coverageRate: string };
  format(): string;
}

export declare class CrashCollector {
  constructor(options?: { maxCrashes?: number });
  record(input: string, error: Error): void;
  getCrashes(): Array<{ input: string; error: string; timestamp: number }>;
  deduplicate(): Array<{ input: string; error: string; count: number }>;
}

export declare class FuzzingHarness {
  constructor(options?: { iterations?: number; seed?: number; timeoutMs?: number; scanFn?: (text: string) => ScanResult });
  run(options?: { iterations?: number }): FuzzReport;
  getResults(): any[];
  getCoverage(): object;
}

export declare const SEED_CORPUS: string[];

// =========================================================================
// Model Fingerprinting (v5.0)
// =========================================================================

export declare class ResponseAnalyzer {
  constructor();
  analyze(text: string): { features: Record<string, number>; wordCount: number; sentenceCount: number };
}

export declare class StyleProfile {
  constructor(samples?: string[]);
  addSample(text: string): void;
  getProfile(): { mean: Record<string, number>; stddev: Record<string, number>; sampleCount: number };
  similarity(other: StyleProfile): number;
}

export declare class FingerprintDatabase {
  constructor();
  register(name: string, profile: StyleProfile): void;
  identify(text: string): Array<{ name: string; similarity: number }>;
  list(): string[];
}

export declare class SupplyChainDetector {
  constructor(options?: { database?: FingerprintDatabase });
  check(text: string, expectedModel?: string): { match: boolean; detectedModel: string; confidence: number; warning?: string };
}

export declare class ModelFingerprinter {
  constructor(options?: { database?: FingerprintDatabase });
  fingerprint(text: string): { profile: object; bestMatch: { name: string; similarity: number } | null };
  register(name: string, samples: string[]): void;
  identify(text: string): Array<{ name: string; similarity: number }>;
}

export declare const MODEL_SIGNATURES: Record<string, { mean: Record<string, number>; stddev: Record<string, number> }>;

// =========================================================================
// Cost/Latency Optimizer (v5.0)
// =========================================================================

export declare class ScanPlan {
  constructor(tier: string, config?: { costPerStep?: number; description?: string });
  addStep(name: string, config?: { timeout?: number; cost?: number; required?: boolean; type?: string }): this;
  getEstimatedLatency(): number;
  getEstimatedCost(): number;
  getSteps(): object[];
  toJSON(): object;
}

export declare class TierManager {
  constructor();
  defineTier(name: string, config: object): void;
  getTier(name: string): object | null;
  listTiers(): string[];
}

export declare class LatencyBudget {
  constructor(options?: { budgetMs?: number; overheadMs?: number });
  allocate(stepName: string, estimatedMs: number): { allowed: boolean; allocated: number; remaining: number };
  isExhausted(): boolean;
  reset(): void;
}

export declare class AdaptiveScanner {
  constructor(options?: ShieldOptions & { tiers?: Record<string, object>; defaultTier?: string });
  scan(text: string, options?: { tier?: string; budgetMs?: number }): ScanResult;
  selectTier(text: string): string;
  getStats(): object;
}

export declare class PerformanceMonitor {
  constructor(options?: { windowMs?: number; maxSamples?: number });
  record(durationMs: number, tier: string): void;
  getPercentiles(): { p50: number; p95: number; p99: number; mean: number };
  getTierBreakdown(): Record<string, { count: number; avgMs: number }>;
}

export declare class CostOptimizer {
  constructor(options?: { budgetPerMinute?: number; latencyTargetMs?: number });
  optimize(text: string, shield: AgentShield): ScanResult;
  getRecommendations(): Array<{ action: string; reason: string; impact: string }>;
  getStats(): object;
}

export declare const OPTIMIZATION_PRESETS: Record<string, object>;

// =========================================================================
// Worker Scanner (additional)
// =========================================================================

export declare class ThreadedWorkerScanner {
  constructor(options?: { poolSize?: number; timeout?: number });
  scan(text: string, options?: object): Promise<ScanResult>;
  scanBatch(texts: string[], options?: object): Promise<ScanResult[]>;
  getStats(): { activeWorkers: number; queuedJobs: number; completed: number; errors: number; poolSize: number; terminated: boolean };
  terminate(): void;
}

// =========================================================================
// v7.0 — MCP Security Runtime
// =========================================================================

export interface MCPSecurityRuntimeOptions {
  signingKey?: string;
  enforceAuth?: boolean;
  enableBehaviorMonitoring?: boolean;
  enableStateMachine?: boolean;
  maxSessionsPerUser?: number;
  maxDelegationDepth?: number;
  sessionTtlMs?: number;
  maxToolCallsPerMinute?: number;
  maxAuditEntries?: number;
  allowedTools?: string[];
  blockedTools?: string[];
  policies?: any[];
  onThreat?: (event: any) => void;
  onBlock?: (event: any) => void;
  onAudit?: (event: any) => void;
}

export interface SecureToolCallResult {
  allowed: boolean;
  threats: Threat[];
  violations: Array<{ type: string; message: string; tool?: string }>;
  anomalies: any[];
  token: { tokenId: string; token: string; expiresAt: number; scopes: string[] } | null;
  reason?: string;
  sanitizedArgs?: any;
}

export interface MCPSessionInfo {
  sessionId: string;
  authCtx: AuthorizationContext;
}

export declare class MCPSecurityRuntime {
  stats: {
    sessionsCreated: number;
    toolCallsProcessed: number;
    toolCallsBlocked: number;
    threatsDetected: number;
    authFailures: number;
    behaviorAnomalies: number;
    stateViolations: number;
  };
  constructor(options?: MCPSecurityRuntimeOptions);
  createSession(params: { userId: string; agentId: string; roles?: string[]; scopes?: string[]; intent?: string; maxToolCalls?: number; maxTokenBudget?: number; allowedTools?: string[] }): MCPSessionInfo;
  terminateSession(sessionId: string): boolean;
  secureToolCall(sessionId: string, toolName: string, args?: any): SecureToolCallResult;
  secureToolResult(sessionId: string, toolName: string, result: any): { safe: boolean; threats: Threat[]; sanitizedResult?: any };
  secureResource(uri: string, content: string, mimeType?: string): { safe: boolean; threats: Threat[] };
  registerTool(toolName: string, requirements?: { scopes?: string[]; roles?: string[]; requiresHumanApproval?: boolean; allowedIntents?: string[] }): void;
  addPolicy(rule: any): void;
  delegateSession(sessionId: string, delegateAgentId: string, delegateScopes?: string[]): MCPSessionInfo;
  createMiddleware(): {
    createSession(params: any): MCPSessionInfo;
    onToolCall(sessionId: string, toolName: string, args: any): SecureToolCallResult;
    onToolResult(sessionId: string, toolName: string, result: any): { safe: boolean; threats: Threat[] };
    onResourceAccess(uri: string, content: string, mimeType: string): { safe: boolean; threats: Threat[] };
    terminateSession(sessionId: string): boolean;
    getStats(): any;
  };
  getReport(): any;
  getAuditLog(limit?: number): any[];
  getBehaviorProfile(userId: string): any | null;
  shutdown(): void;
}

export declare class MCPSessionStateMachine {
  sessionId: string;
  state: string;
  transitions: Array<{ from: string; to: string; timestamp: number }>;
  constructor(sessionId: string);
  transition(newState: string): { allowed: boolean; from: string; to: string; reason?: string };
  isTerminated(): boolean;
}

export declare const SESSION_STATES: Readonly<Record<string, string[]>>;

// =========================================================================
// v7.0 — MCP Certification & Trust
// =========================================================================

export interface CertificationResult {
  certified: boolean;
  level: string;
  score: number;
  badge: string;
  timestamp: number;
  results: Array<{ id: string; name: string; category: string; severity: string; passed: boolean; description: string }>;
  recommendations: Array<{ id: string; priority: string; action: string }>;
  summary: { total: number; passed: number; failed: number; criticalFailures: number };
}

export declare class MCPCertification {
  static evaluate(config: any): CertificationResult;
  static formatReport(evaluation: CertificationResult): string;
}

export declare class AgentThreatIntelligence {
  stats: { patternsLearned: number; attacksObserved: number; trendsGenerated: number };
  constructor(options?: { maxPatterns?: number; decayHalfLifeMs?: number; minConfidence?: number });
  recordAttack(attack: { category: string; pattern: string; source?: string; context?: any; blocked?: boolean }): { patternId: string; isNew: boolean; confidence: number };
  checkAgainstIntel(input: string): { matches: any[]; riskScore: number };
  getTrends(windowMs?: number): { topCategories: any[]; attackRate: number; trendDirection: string; bypassRate: number; totalObserved: number };
  exportCorpus(): any;
  importCorpus(corpus: any): { imported: number; merged: number; skipped: number };
}

export declare class CrossOrgAgentTrust {
  stats: { issued: number; verified: number; rejected: number; revoked: number };
  constructor(options: { orgId: string; signingKey: string; certificateTtlMs?: number; maxCertificates?: number });
  issueCertificate(params: { agentId: string; capabilities?: string[]; allowedOrgs?: string[]; trustLevel?: number }): any;
  verifyCertificate(certificate: any): { valid: boolean; reason?: string; trustLevel: number };
  revokeCertificate(certId: string): boolean;
  trustOrganization(orgId: string, publicKey: string, trustLevel?: number): void;
  untrustOrganization(orgId: string): void;
  getTrustReport(): any;
}

export declare const MCP_THREAT_CATEGORIES: Readonly<Record<string, { severity: string; weight: number }>>;
export declare const CERTIFICATION_REQUIREMENTS: ReadonlyArray<{ id: string; name: string; category: string; severity: string; description: string }>;
export declare const CERTIFICATION_LEVELS: Readonly<Record<string, { minScore: number; label: string; badge: string }>>;

// =========================================================================
// v7.0 — Authorization Context (enhanced)
// =========================================================================

export declare class AuthorizationContext {
  contextId: string;
  userId: string;
  agentId: string;
  roles: readonly string[];
  scopes: readonly string[];
  intent: string | null;
  createdAt: number;
  expiresAt: number;
  parentContextId: string | null;
  delegationDepth: number;
  constructor(params: { userId: string; agentId: string; roles?: string[]; scopes?: string[]; intent?: string; ttlMs?: number; parentContextId?: string; signingKey?: string });
  isExpired(): boolean;
  hasScope(scope: string): boolean;
  hasRole(role: string): boolean;
  delegate(delegateAgentId: string, delegateScopes?: string[]): AuthorizationContext;
  verify(): boolean;
}

export declare class EphemeralTokenManager {
  constructor(options?: { tokenTtlMs?: number; maxTokensPerUser?: number; rotationWindowMs?: number; signingKey?: string });
  issueToken(authCtx: AuthorizationContext, scopes?: string[]): { tokenId: string; token: string; expiresAt: number; scopes: string[] };
  validateToken(tokenId: string): { valid: boolean; reason: string | null; userId: string | null; scopes: string[] };
  rotateToken(tokenId: string, authCtx: AuthorizationContext): any;
  revokeToken(tokenId: string): void;
  startCleanup(intervalMs?: number): void;
  stopCleanup(): void;
  getStats(): { issued: number; rotated: number; revoked: number; expired: number; validated: number };
}

export declare class IntentValidator {
  constructor(options?: any);
  addPolicy(policy: { tool: string; requiredScopes?: string[]; requiredRoles?: string[]; allowedIntents?: string[]; requiresHumanApproval?: boolean }): void;
  validateAction(toolName: string, args: any, authCtx: AuthorizationContext): { allowed: boolean; violations: any[]; requiresApproval: boolean };
  getAuditLog(limit?: number): any[];
}

export declare class ConfusedDeputyGuard {
  stats: { checked: number; allowed: number; denied: number; escalations: number };
  constructor(options?: { enforceContext?: boolean; logOnly?: boolean; signingKey?: string });
  registerTool(toolName: string, requirements?: { scopes?: string[]; roles?: string[]; requiresHumanApproval?: boolean }): void;
  wrapToolCall(toolName: string, args: any, authCtx?: AuthorizationContext): { allowed: boolean; violations: any[]; requiresApproval: boolean; token: any | null };
  getStats(): any;
  getAuditLog(limit?: number): any[];
}

// =========================================================================
// v7.2 — IPIA Detector
// =========================================================================

export interface IPIAResult {
  isInjection: boolean;
  confidence: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  reason: string;
  features: Record<string, number>;
  source: string;
  metadata: any | null;
  patternScan: any | null;
  timestamp: number;
}

export interface EmbeddingBackend {
  embed(text: string): Promise<number[]>;
  similarity?(a: number[], b: number[]): number;
}

export interface IPIADetectorOptions {
  threshold?: number;
  separator?: string;
  embeddingBackend?: EmbeddingBackend;
  usePatternScan?: boolean;
  maxContentLength?: number;
  maxIntentLength?: number;
  enabled?: boolean;
}

export declare class IPIADetector {
  threshold: number;
  enabled: boolean;
  constructor(options?: IPIADetectorOptions);
  scan(externalContent: string, userIntent: string, options?: { source?: string; metadata?: any }): IPIAResult;
  scanAsync(externalContent: string, userIntent: string, options?: { source?: string; metadata?: any }): Promise<IPIAResult>;
  scanBatch(contentItems: string[], userIntent: string, options?: { source?: string; metadata?: any }): { results: IPIAResult[]; summary: { total: number; blocked: number; safe: number; maxConfidence: number } };
  getStats(): { total: number; blocked: number; safe: number; blockRate: string };
  setThreshold(threshold: number): void;
}

export declare class ContextConstructor {
  constructor(options?: { separator?: string; maxContentLength?: number; maxIntentLength?: number });
  build(externalContent: string, userIntent: string): { joint: string; content: string; intent: string };
}

export declare class FeatureExtractor {
  extract(ctx: { joint: string; content: string; intent: string }): { features: number[]; featureMap: Record<string, number> };
}

export declare class TreeClassifier {
  threshold: number;
  constructor(options?: { threshold?: number });
  classify(features: number[], featureMap: Record<string, number>): { isInjection: boolean; confidence: number; reason: string };
}

export declare class ExternalEmbedder {
  constructor(backend: EmbeddingBackend);
  static defaultSimilarity(a: number[], b: number[]): number;
  extractCosineFeatures(ctx: { joint: string; content: string; intent: string }): Promise<{ cosine_intent_content: number; cosine_joint_intent: number; cosine_joint_content: number }>;
}

export declare function createIPIAScanner(options?: IPIADetectorOptions): (content: string, intent: string, options?: any) => IPIAResult;
export declare function ipiaMiddleware(options?: { contentField?: string; intentField?: string; action?: 'block' | 'flag' | 'log'; threshold?: number }): (req: any, res: any, next: any) => void;

export declare const IPIA_FEATURE_NAMES: string[];
export declare const IPIA_INJECTION_LEXICON: Record<string, number>;

// =========================================================================
// v8.0 — Smart Config
// =========================================================================

export type PresetName =
  | 'chatbot'
  | 'coding_agent'
  | 'rag_pipeline'
  | 'customer_support'
  | 'internal_tool'
  | 'multi_agent'
  | 'high_security'
  | 'minimal'
  | 'mcp_server';

export type SensitivityLevel = 'low' | 'medium' | 'high';

export type BlockThresholdLevel = 'low' | 'medium' | 'high' | 'critical';

export type VoterName = 'pattern' | 'tfidf' | 'entropy' | 'ipia' | 'semantic' | 'behavioral' | 'heuristic';

export interface IntentConfig {
  purpose?: string;
  allowedTools?: string[];
  allowedTopics?: string[];
  maxDriftScore?: number;
}

export interface LearningConfig {
  persist?: boolean;
  persistPath?: string;
  promotionThreshold?: number;
  maxPatterns?: number;
}

export interface FeedbackConfig {
  autoRetrain?: boolean;
  maxPending?: number;
  cooldownMs?: number;
}

export interface EnsembleConfig {
  voters?: VoterName[];
  threshold?: number;
  requireUnanimous?: boolean;
}

export interface GoalDriftConfig {
  checkInterval?: number;
  driftThreshold?: number;
  windowSize?: number;
}

export interface CrossTurnConfig {
  windowSize?: number;
  scanInterval?: number;
  accumulateAll?: boolean;
}

export interface ToolSequenceConfig {
  learningPeriod?: number;
  anomalyThreshold?: number;
  maxChainLength?: number;
}

export interface AdaptiveThresholdsConfig {
  calibrationSamples?: number;
  adjustInterval?: number;
  minConfidence?: number;
}

export interface SelfTrainingConfig {
  generations?: number;
  populationSize?: number;
  mutationRate?: number;
  interval?: number;
}

export interface ShieldCallbacks {
  onThreat?: ((threatInfo: any) => void) | null;
  onDrift?: ((driftInfo: any) => void) | null;
  onAnomaly?: ((anomalyInfo: any) => void) | null;
}

export interface ShieldConfig {
  preset: PresetName | null;
  sensitivity: SensitivityLevel;
  blockOnThreat: boolean;
  blockThreshold: BlockThresholdLevel;
  intent: IntentConfig | null;
  learning: LearningConfig | null;
  feedback: FeedbackConfig | null;
  ensemble: EnsembleConfig | null;
  goalDrift: GoalDriftConfig | null;
  crossTurn: CrossTurnConfig | null;
  toolSequence: ToolSequenceConfig | null;
  adaptiveThresholds: AdaptiveThresholdsConfig | null;
  selfTraining: SelfTrainingConfig | null;
  readonly callbacks: ShieldCallbacks;
}

export interface ConfigValidationResult {
  valid: boolean;
  errors: string[];
}

export declare class ShieldBuilder {
  constructor();
  preset(name: PresetName): this;
  sensitivity(level: SensitivityLevel): this;
  blockOnThreat(bool: boolean): this;
  blockThreshold(level: BlockThresholdLevel): this;
  enableIntent(opts?: IntentConfig): this;
  enableLearning(opts?: LearningConfig): this;
  enableFeedback(opts?: FeedbackConfig): this;
  enableEnsemble(opts?: EnsembleConfig): this;
  enableGoalDrift(opts?: GoalDriftConfig): this;
  enableCrossTurn(opts?: CrossTurnConfig): this;
  enableToolSequence(opts?: ToolSequenceConfig): this;
  enableAdaptiveThresholds(opts?: AdaptiveThresholdsConfig): this;
  enableSelfTraining(opts?: SelfTrainingConfig): this;
  onThreat(callback: (threatInfo: any) => void): this;
  onDrift(callback: (driftInfo: any) => void): this;
  onAnomaly(callback: (anomalyInfo: any) => void): this;
  build(): ShieldConfig;
}

export declare function createShield(): ShieldBuilder;
export declare function createShield(preset: PresetName): ShieldConfig;
export declare function createShield(config: {
  preset?: PresetName;
  sensitivity?: SensitivityLevel;
  blockOnThreat?: boolean;
  blockThreshold?: BlockThresholdLevel;
  intent?: IntentConfig | boolean;
  learning?: LearningConfig | boolean;
  feedback?: FeedbackConfig | boolean;
  ensemble?: EnsembleConfig | boolean;
  goalDrift?: GoalDriftConfig | boolean;
  crossTurn?: CrossTurnConfig | boolean;
  toolSequence?: ToolSequenceConfig | boolean;
  adaptiveThresholds?: AdaptiveThresholdsConfig | boolean;
  selfTraining?: SelfTrainingConfig | boolean;
  onThreat?: (threatInfo: any) => void;
  onDrift?: (driftInfo: any) => void;
  onAnomaly?: (anomalyInfo: any) => void;
}): ShieldConfig;
export declare function createShield(builder: ShieldBuilder): ShieldConfig;

export declare function validateConfig(config: any): ConfigValidationResult;
export declare function describeConfig(config: ShieldConfig): string;

export declare const FEATURE_DEFAULTS: {
  intent: Required<IntentConfig>;
  learning: Required<LearningConfig>;
  feedback: Required<FeedbackConfig>;
  ensemble: Required<EnsembleConfig>;
  goalDrift: Required<GoalDriftConfig>;
  crossTurn: Required<CrossTurnConfig>;
  toolSequence: Required<ToolSequenceConfig>;
  adaptiveThresholds: Required<AdaptiveThresholdsConfig>;
  selfTraining: Required<SelfTrainingConfig>;
};

export declare const VALID_PRESETS: PresetName[];

// =========================================================================
// v8.0 — Ensemble Voting Classifier
// =========================================================================

export interface VoteResult {
  voter: string;
  isInjection: boolean;
  confidence: number;
  reason: string;
}

export interface EnsembleScanResult {
  isInjection: boolean;
  confidence: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  votes: VoteResult[];
  agreement: number;
  method: string;
  timestamp: string;
}

export interface EnsembleStats {
  totalScans: number;
  injections: number;
  safe: number;
  averageAgreement: number;
  averageConfidence: number;
  voterCount: number;
  voters: string[];
}

export interface EnsembleClassifierOptions {
  voters?: VoterName[];
  threshold?: number;
  requireUnanimous?: boolean;
  weights?: Record<string, number>;
  minVoters?: number;
  voterOptions?: Record<string, any>;
}

export declare class EnsembleClassifier {
  threshold: number;
  requireUnanimous: boolean;
  minVoters: number;
  weights: Record<string, number>;
  constructor(config?: EnsembleClassifierOptions);
  scan(text: string, context?: { intent?: string; source?: string; conversationHistory?: string[] }): EnsembleScanResult;
  getStats(): EnsembleStats;
}

export declare class PatternVoter {
  name: string;
  constructor(options?: { source?: string });
  vote(text: string, context?: any): VoteResult;
}

export declare class TFIDFVoter {
  name: string;
  constructor(options?: { similarityThreshold?: number });
  vote(text: string, context?: any): VoteResult;
}

export declare class EntropyVoter {
  name: string;
  constructor(options?: { entropyThreshold?: number; ngramSize?: number });
  vote(text: string, context?: any): VoteResult;
}

export declare class IPIAVoter {
  name: string;
  constructor(options?: { classifierThreshold?: number });
  vote(text: string, context?: { intent?: string }): VoteResult;
}

export declare const VOTER_NAMES: string[];

// =========================================================================
// v8.0 — Agent Intent & Goal Drift
// =========================================================================

export interface MessageCheckResult {
  onTopic: boolean;
  relevanceScore: number;
  drift: number;
  reason: string;
}

export interface ToolCheckResult2 {
  allowed: boolean;
  reason: string;
}

export interface DriftResult {
  driftScore: number;
  driftDetected: boolean;
  trend: 'stable' | 'drifting' | 'recovering';
  turnsSincePurpose: number;
  topicShift: boolean;
  reason: string;
}

export interface GoalDriftStats {
  totalMessages: number;
  messagesInWindow: number;
  driftEvents: number;
  topicShifts: number;
  averageDrift: number;
  maxDrift: number;
  currentTrend: 'stable' | 'drifting' | 'recovering';
  historyLength: number;
}

export interface ToolSequenceResult {
  allowed: boolean;
  anomalyScore: number;
  probability: number;
  isLearning: boolean;
  reason: string;
}

export interface ToolSequenceStats {
  totalCalls: number;
  uniqueTools: number;
  transitionCount: number;
  anomalyCount: number;
  isLearning: boolean;
  learningProgress: number;
  toolCounts: Record<string, number>;
}

export interface ToolSequenceExportData {
  transitions: Record<string, Record<string, number>>;
  toolCounts: Record<string, number>;
  totalCalls: number;
  anomalyCount: number;
  learningPeriod: number;
  anomalyThreshold: number;
  exportedAt: string;
}

export interface AgentIntentOptions {
  purpose: string;
  allowedTools?: string[];
  allowedTopics?: string[];
  maxDriftScore?: number;
  onDrift?: (info: any) => void;
}

export declare class AgentIntent {
  purpose: string;
  allowedTools: string[] | null;
  allowedTopics: string[] | null;
  maxDriftScore: number;
  constructor(config: AgentIntentOptions);
  checkMessage(message: string): MessageCheckResult;
  checkTool(toolName: string, args?: any): ToolCheckResult2;
  getPurposeVector(): Map<string, number>;
}

export interface GoalDriftDetectorOptions {
  windowSize?: number;
  driftThreshold?: number;
  checkInterval?: number;
  onDrift?: (info: any) => void;
}

export declare class GoalDriftDetector {
  intent: AgentIntent;
  windowSize: number;
  driftThreshold: number;
  checkInterval: number;
  constructor(intent: AgentIntent, config?: GoalDriftDetectorOptions);
  addMessage(message: string, role?: string): DriftResult;
  getHistory(): number[];
  reset(): void;
  getStats(): GoalDriftStats;
}

export interface ToolSequenceModelerOptions {
  learningPeriod?: number;
  anomalyThreshold?: number;
  maxChainLength?: number;
}

export declare class ToolSequenceModeler {
  learningPeriod: number;
  anomalyThreshold: number;
  maxChainLength: number;
  constructor(config?: ToolSequenceModelerOptions);
  recordToolCall(toolName: string, context?: { args?: any; userId?: string; agentId?: string }): ToolSequenceResult;
  getTransitionMatrix(): Record<string, Record<string, number>>;
  getCommonSequences(topN?: number): Array<{ from: string; to: string; count: number; probability: number }>;
  exportModel(): ToolSequenceExportData;
  importModel(data: ToolSequenceExportData): void;
  getStats(): ToolSequenceStats;
}

// =========================================================================
// v8.0 — Persistent Learning & Feedback
// =========================================================================

export interface LearnedPatternMatch {
  patternId: string;
  pattern: string;
  source: string;
  confidence: number;
  categories: string[];
  severity: string;
}

export interface LearningCheckResult {
  matches: LearnedPatternMatch[];
  count: number;
}

export interface IngestResult {
  candidates: number;
  signatures: string[];
}

export interface FalsePositiveResult {
  revoked: boolean;
  fpCount: number;
  remaining: number;
}

export interface LearningExportData {
  version: string;
  timestamp: string;
  patterns: any[];
  candidates: any[];
  stats: any;
}

export interface LearningStats {
  attacksIngested: number;
  candidatesCreated: number;
  patternsPromoted: number;
  patternsRevoked: number;
  falsePositivesReported: number;
  saves: number;
  loads: number;
  activePatterns: number;
  revokedPatterns: number;
  candidates: number;
  totalPromoted: number;
}

export interface PersistentLearningLoopOptions {
  persist?: boolean;
  persistPath?: string;
  promotionThreshold?: number;
  maxPatterns?: number;
  decayMs?: number;
  maxFalsePositives?: number;
}

export declare class PersistentLearningLoop {
  constructor(config?: PersistentLearningLoopOptions);
  ingest(text: string, meta?: { category?: string; source?: string; severity?: string }): IngestResult;
  check(text: string): LearningCheckResult;
  reportFalsePositive(patternId: string): FalsePositiveResult;
  save(): boolean;
  load(): boolean;
  export(): LearningExportData;
  import(data: LearningExportData): number;
  decay(): number;
  getStats(): LearningStats;
  getActivePatterns(): any[];
}

export interface FeedbackReportResult {
  id: string;
  status: string;
  pendingCount: number;
}

export interface FeedbackProcessResult {
  processed: number;
  patternsAdded: number;
  patternsRevoked: number;
  retrainTriggered: boolean;
}

export interface FeedbackStats {
  falsePositives: number;
  falseNegatives: number;
  totalProcessed: number;
  patternsAdded: number;
  patternsRevoked: number;
  retrainCount: number;
  pendingCount: number;
  processedCount: number;
}

export interface FeedbackCollectorOptions {
  autoRetrain?: boolean;
  maxPending?: number;
  cooldownMs?: number;
  learningLoop?: PersistentLearningLoop;
}

export declare class FeedbackCollector {
  constructor(config?: FeedbackCollectorOptions);
  reportFalsePositive(text: string, meta?: { scanId?: string; category?: string; patternId?: string; reason?: string }): FeedbackReportResult;
  reportFalseNegative(text: string, meta?: { expectedCategory?: string; severity?: string; source?: string }): FeedbackReportResult;
  getPending(): any[];
  process(): FeedbackProcessResult;
  getStats(): FeedbackStats;
  export(): any;
}

// =========================================================================
// v8.0 — Cross-Turn Tracking & Adaptive Thresholds
// =========================================================================

export interface CrossTurnAddResult {
  tracked: boolean;
  messageCount: number;
  scanTriggered: boolean;
  threats: Threat[];
  crossTurnDetection: boolean;
}

export interface CrossTurnScanResult {
  threats: Threat[];
  combinedLength: number;
  messageCount: number;
}

export interface CrossTurnStats {
  totalMessages: number;
  scansTriggered: number;
  crossTurnDetections: number;
  individualDetections: number;
  currentWindowSize: number;
  maxWindowSize: number;
  scanInterval: number;
}

export interface CrossTurnTrackerOptions {
  windowSize?: number;
  scanInterval?: number;
  accumulateAll?: boolean;
  sensitivity?: string;
  onDetection?: (info: { threats: any[]; messages: Array<{ text: string; role: string }>; timestamp: number }) => void;
}

export declare class CrossTurnTracker {
  windowSize: number;
  scanInterval: number;
  accumulateAll: boolean;
  sensitivity: string;
  constructor(config?: CrossTurnTrackerOptions);
  addMessage(text: string, role?: string): CrossTurnAddResult;
  scanNow(): CrossTurnScanResult;
  getAccumulatedText(): string;
  getMostSuspicious(): { text: string; role: string; confidence: number; threats: Threat[] } | null;
  reset(): void;
  getStats(): CrossTurnStats;
}

export interface CalibrationRecordResult {
  recorded: boolean;
  isCalibrating: boolean;
  samplesRemaining: number;
  currentThreshold: number;
}

export interface CalibrationStats {
  totalSamples: number;
  calibrationCount: number;
  isCalibrating: boolean;
  targetFPRate: number;
  categories: Record<string, {
    threshold: number;
    totalSamples: number;
    benignSamples: number;
    injectionSamples: number;
    feedbackSamples: number;
    estimatedFPRate: number;
  }>;
}

export interface CalibrationExportData {
  version: number;
  totalSamples: number;
  calibrationCount: number;
  calibrationSamples: number;
  adjustInterval: number;
  minConfidence: number;
  maxConfidence: number;
  targetFPRate: number;
  categories: Record<string, { threshold: number; samples: any[] }>;
  exportedAt: number;
}

export interface AdaptiveThresholdCalibratorOptions {
  calibrationSamples?: number;
  adjustInterval?: number;
  minConfidence?: number;
  maxConfidence?: number;
  targetFPRate?: number;
}

export declare class AdaptiveThresholdCalibrator {
  calibrationSamples: number;
  adjustInterval: number;
  minConfidence: number;
  maxConfidence: number;
  targetFPRate: number;
  constructor(config?: AdaptiveThresholdCalibratorOptions);
  record(result: { confidence: number; isInjection: boolean; category?: string }, isTruePositive?: boolean): CalibrationRecordResult;
  getThreshold(category?: string): number;
  shouldFlag(confidence: number, category?: string): boolean;
  recalibrate(): { thresholds: Record<string, number>; samplesUsed: number };
  getStats(): CalibrationStats;
  export(): CalibrationExportData;
  import(data: CalibrationExportData): void;
}

// =========================================================================
// v8.0 — Adversarial Self-Training
// =========================================================================

export interface SelfTrainingCycleResult {
  generation: number;
  tested: number;
  detected: number;
  evaded: number;
  detectionRate: number;
  newPatterns: string[];
  evasiveExamples: string[];
  duration: number;
}

export interface SelfTrainingResult {
  cycles: number;
  totalTested: number;
  totalEvaded: number;
  patternsGenerated: string[];
  improvementCurve: number[];
  duration: number;
}

export interface SelfTrainerStats {
  cyclesCompleted: number;
  totalTested: number;
  totalDetected: number;
  totalEvaded: number;
  overallDetectionRate: number;
  evasiveAttacksFound: number;
  patternsGenerated: number;
  currentPopulationSize: number;
  config: {
    generations: number;
    populationSize: number;
    mutationRate: number;
    seedAttackCount: number;
  };
}

export interface SelfTrainerOptions {
  generations?: number;
  populationSize?: number;
  mutationRate?: number;
  seedAttacks?: string[];
  detector?: (text: string) => { detected: boolean; confidence: number };
  onEvasion?: (info: { attack: string; generation: number; cycle: number; confidence: number }) => void;
}

export declare class SelfTrainer {
  generations: number;
  populationSize: number;
  mutationRate: number;
  seedAttacks: string[];
  constructor(config?: SelfTrainerOptions);
  runCycle(): SelfTrainingCycleResult;
  train(cycles?: number): SelfTrainingResult;
  getEvasiveAttacks(): string[];
  getGeneratedPatterns(): string[];
  getStats(): SelfTrainerStats;
}

export declare class MutationEngine {
  mutationRate: number;
  constructor(mutationRate?: number);
  mutate(text: string): string;
  getStrategies(): string[];
}

export declare const SEED_ATTACKS: string[];
export declare const MUTATION_STRATEGIES: string[];
