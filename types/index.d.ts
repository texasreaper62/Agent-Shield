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

export interface BenchmarkResults {
  throughput: { totalScans: number; elapsedMs: number; scansPerSecond: number };
  latency: { minMs: number; maxMs: number; avgMs: number; medianMs: number; p95Ms: number; p99Ms: number; samples: number };
  accuracy: { truePositives: number; falseNegatives: number; trueNegatives: number; falsePositives: number; accuracy: string; detectionRate: string; falsePositiveRate: string; precision: string; recall: string };
  scalability: { byInputSize: Array<{ inputChars: number; scanTimeMs: number; charsPerMs: number }>; linearScaling: boolean };
  summary: { avgLatencyMs: number; p95LatencyMs: number; p99LatencyMs: number; scansPerSecond: number; detectionRate: string; falsePositiveRate: string; grade: string };
  timestamp: string;
}

export declare class BenchmarkSuite {
  constructor(options?: { sensitivity?: string; iterations?: number });
  run(): BenchmarkResults;
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
