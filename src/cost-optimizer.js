'use strict';

/**
 * Agent Shield — Cost Optimizer
 *
 * Automatically tunes detection depth based on threat level and latency budget.
 * Balances cost, latency, and accuracy across scanning tiers. All detection
 * runs locally — no data ever leaves your environment.
 *
 * Exports: CostOptimizer, LatencyBudget, AdaptiveScanner, TierManager,
 *          PerformanceMonitor, ScanPlan, OPTIMIZATION_PRESETS
 */

// =========================================================================
// OPTIMIZATION PRESETS
// =========================================================================

/**
 * Pre-built optimization configurations.
 * @type {Object<string, object>}
 */
const OPTIMIZATION_PRESETS = {
  realtime: {
    name: 'realtime',
    description: 'Maximum speed, fast tier only, throughput priority',
    maxLatencyMs: 10,
    costPerScan: 0,
    targetThroughput: 10000,
    adaptiveEnabled: false,
    tiers: ['fast'],
    defaultTier: 'fast',
    priority: 'throughput'
  },
  balanced: {
    name: 'balanced',
    description: 'Balanced cost/latency/accuracy with adaptive tiers',
    maxLatencyMs: 50,
    costPerScan: 0,
    targetThroughput: 1000,
    adaptiveEnabled: true,
    tiers: ['fast', 'standard', 'deep'],
    defaultTier: 'standard',
    priority: 'balanced'
  },
  thorough: {
    name: 'thorough',
    description: 'Deep scanning with accuracy priority',
    maxLatencyMs: 200,
    costPerScan: 0,
    targetThroughput: 200,
    adaptiveEnabled: true,
    tiers: ['standard', 'deep'],
    defaultTier: 'deep',
    priority: 'accuracy'
  },
  paranoid: {
    name: 'paranoid',
    description: 'All checks enabled, maximum security',
    maxLatencyMs: 500,
    costPerScan: 0,
    targetThroughput: 50,
    adaptiveEnabled: false,
    tiers: ['paranoid'],
    defaultTier: 'paranoid',
    priority: 'security'
  }
};

// =========================================================================
// ScanPlan
// =========================================================================

/**
 * Describes a planned scan execution with ordered steps.
 */
class ScanPlan {
  /**
   * @param {string} tier - The scanning tier for this plan.
   * @param {object} [config] - Plan configuration.
   * @param {number} [config.costPerStep=0] - Base cost per step.
   * @param {string} [config.description=''] - Plan description.
   */
  constructor(tier, config = {}) {
    this.tier = tier;
    this.costPerStep = config.costPerStep || 0;
    this.description = config.description || '';
    this.steps = [];
    this.createdAt = Date.now();
  }

  /**
   * Add a scan step to the plan.
   * @param {string} name - Step name.
   * @param {object} [config] - Step configuration.
   * @param {number} [config.timeout=10] - Step timeout in ms.
   * @param {number} [config.cost=0] - Step cost.
   * @param {boolean} [config.required=true] - Whether step is required.
   * @param {string} [config.type='pattern'] - Step type.
   * @returns {ScanPlan} This plan for chaining.
   */
  addStep(name, config = {}) {
    this.steps.push({
      name,
      timeout: config.timeout || 10,
      cost: config.cost || 0,
      required: config.required !== undefined ? config.required : true,
      type: config.type || 'pattern',
      order: this.steps.length
    });
    return this;
  }

  /**
   * Get estimated total latency (sum of step timeouts).
   * @returns {number} Estimated latency in ms.
   */
  getEstimatedLatency() {
    return this.steps.reduce((sum, step) => sum + step.timeout, 0);
  }

  /**
   * Get estimated total cost.
   * @returns {number} Estimated cost.
   */
  getEstimatedCost() {
    const stepCosts = this.steps.reduce((sum, step) => sum + step.cost, 0);
    return stepCosts + (this.steps.length * this.costPerStep);
  }

  /**
   * Get ordered steps.
   * @returns {Array<object>} Steps sorted by order.
   */
  getSteps() {
    return [...this.steps].sort((a, b) => a.order - b.order);
  }

  /**
   * Serialize plan to JSON-safe object.
   * @returns {object} Serializable plan.
   */
  toJSON() {
    return {
      tier: this.tier,
      description: this.description,
      steps: this.getSteps(),
      estimatedLatency: this.getEstimatedLatency(),
      estimatedCost: this.getEstimatedCost(),
      createdAt: this.createdAt
    };
  }
}

// =========================================================================
// TierManager
// =========================================================================

/**
 * Defines and manages scanning tiers with pre-built defaults.
 */
class TierManager {
  /**
   * Creates a TierManager with pre-defined tiers.
   */
  constructor() {
    /** @type {Map<string, object>} */
    this.tiers = new Map();
    this._initDefaults();
  }

  /**
   * Initialize default scanning tiers.
   * @private
   */
  _initDefaults() {
    this.defineTier('fast', {
      patterns: 'critical',
      maxPatterns: 10,
      enableSemantic: false,
      enableEncoding: false,
      timeout: 5,
      priority: 1
    });

    this.defineTier('standard', {
      patterns: 'all',
      maxPatterns: 0, // 0 = unlimited
      enableSemantic: false,
      enableEncoding: true,
      timeout: 50,
      priority: 2
    });

    this.defineTier('deep', {
      patterns: 'extended',
      maxPatterns: 0,
      enableSemantic: true,
      enableEncoding: true,
      timeout: 200,
      priority: 3
    });

    this.defineTier('paranoid', {
      patterns: 'extended',
      maxPatterns: 0,
      enableSemantic: true,
      enableEncoding: true,
      timeout: 500,
      priority: 4,
      multiplePass: true
    });
  }

  /**
   * Define or update a scanning tier.
   * @param {string} name - Tier name.
   * @param {object} config - Tier configuration.
   * @param {string} [config.patterns='all'] - Pattern set: 'critical', 'all', or 'extended'.
   * @param {number} [config.maxPatterns=0] - Max patterns to check (0 = unlimited).
   * @param {boolean} [config.enableSemantic=false] - Enable semantic analysis.
   * @param {boolean} [config.enableEncoding=false] - Enable encoding decode.
   * @param {number} [config.timeout=50] - Timeout in ms.
   * @param {number} [config.priority=1] - Priority (higher = more thorough).
   */
  defineTier(name, config) {
    this.tiers.set(name, {
      name,
      patterns: config.patterns || 'all',
      maxPatterns: config.maxPatterns || 0,
      enableSemantic: config.enableSemantic || false,
      enableEncoding: config.enableEncoding || false,
      timeout: config.timeout || 50,
      priority: config.priority || 1,
      multiplePass: config.multiplePass || false
    });
  }

  /**
   * Get configuration for a tier.
   * @param {string} name - Tier name.
   * @returns {object|null} Tier configuration or null if not found.
   */
  getTier(name) {
    return this.tiers.get(name) || null;
  }

  /**
   * List all tiers sorted by priority (ascending).
   * @returns {Array<object>} All tiers sorted by priority.
   */
  listTiers() {
    return [...this.tiers.values()].sort((a, b) => a.priority - b.priority);
  }
}

// =========================================================================
// LatencyBudget
// =========================================================================

/** Valid scan stages. */
const STAGES = ['preprocessing', 'pattern_matching', 'semantic_analysis', 'postprocessing'];

/**
 * Manages time budgets across scan stages.
 */
class LatencyBudget {
  /**
   * @param {number} totalBudgetMs - Total latency budget in milliseconds.
   */
  constructor(totalBudgetMs) {
    this.totalBudgetMs = totalBudgetMs;
    /** @type {Map<string, number>} Proportion allocated per stage. */
    this.allocations = new Map();
    /** @type {Map<string, number>} Time spent per stage. */
    this.spent = new Map();

    // Default allocations
    this.allocate('preprocessing', 0.1);
    this.allocate('pattern_matching', 0.6);
    this.allocate('semantic_analysis', 0.2);
    this.allocate('postprocessing', 0.1);
  }

  /**
   * Allocate a proportion of the total budget to a stage.
   * @param {string} stage - Stage name.
   * @param {number} proportion - Proportion (0-1) of total budget.
   */
  allocate(stage, proportion) {
    if (!STAGES.includes(stage)) {
      console.log(`[Agent Shield] Warning: unknown stage "${stage}"`);
    }
    this.allocations.set(stage, Math.max(0, Math.min(1, proportion)));
    if (!this.spent.has(stage)) {
      this.spent.set(stage, 0);
    }
  }

  /**
   * Record time spent on a stage.
   * @param {string} stage - Stage name.
   * @param {number} timeMs - Time spent in milliseconds.
   */
  spend(stage, timeMs) {
    const current = this.spent.get(stage) || 0;
    this.spent.set(stage, current + timeMs);
  }

  /**
   * Get remaining budget for a stage.
   * @param {string} stage - Stage name.
   * @returns {number} Remaining time in ms.
   */
  remaining(stage) {
    const proportion = this.allocations.get(stage) || 0;
    const budgetMs = this.totalBudgetMs * proportion;
    const spentMs = this.spent.get(stage) || 0;
    return Math.max(0, budgetMs - spentMs);
  }

  /**
   * Check if budget for a stage is exhausted.
   * @param {string} stage - Stage name.
   * @returns {boolean} True if budget is exhausted.
   */
  isExhausted(stage) {
    return this.remaining(stage) <= 0;
  }

  /**
   * Get a report of budget vs actual for all stages.
   * @returns {object} Per-stage budget report.
   */
  getReport() {
    const stages = {};
    for (const stage of STAGES) {
      const proportion = this.allocations.get(stage) || 0;
      const budgetMs = this.totalBudgetMs * proportion;
      const spentMs = this.spent.get(stage) || 0;
      stages[stage] = {
        budgetMs: Math.round(budgetMs * 100) / 100,
        spentMs: Math.round(spentMs * 100) / 100,
        remainingMs: Math.round(Math.max(0, budgetMs - spentMs) * 100) / 100,
        proportion,
        exhausted: spentMs >= budgetMs
      };
    }

    const totalSpent = [...this.spent.values()].reduce((s, v) => s + v, 0);
    return {
      totalBudgetMs: this.totalBudgetMs,
      totalSpentMs: Math.round(totalSpent * 100) / 100,
      totalRemainingMs: Math.round(Math.max(0, this.totalBudgetMs - totalSpent) * 100) / 100,
      stages
    };
  }
}

// =========================================================================
// PerformanceMonitor
// =========================================================================

/**
 * Tracks real-time performance metrics with a rolling window.
 */
class PerformanceMonitor {
  /**
   * @param {number} [windowSize=1000] - Number of scans to keep in the rolling window.
   */
  constructor(windowSize = 1000) {
    this.windowSize = windowSize;
    /** @type {Array<{latency: number, tier: string, threatCount: number, timestamp: number}>} */
    this.records = [];
  }

  /**
   * Record a completed scan.
   * @param {number} latency - Scan latency in ms.
   * @param {string} tier - Tier used for the scan.
   * @param {number} [threatCount=0] - Number of threats found.
   */
  recordScan(latency, tier, threatCount = 0) {
    this.records.push({
      latency,
      tier,
      threatCount,
      timestamp: Date.now()
    });

    // Trim to window size
    if (this.records.length > this.windowSize) {
      this.records = this.records.slice(-this.windowSize);
    }
  }

  /**
   * Get sorted latencies from the current window.
   * @private
   * @returns {number[]}
   */
  _sortedLatencies() {
    return this.records.map(r => r.latency).sort((a, b) => a - b);
  }

  /**
   * Get a percentile value from the latency distribution.
   * @private
   * @param {number} p - Percentile (0-100).
   * @returns {number} Latency at the given percentile.
   */
  _percentile(p) {
    const sorted = this._sortedLatencies();
    if (sorted.length === 0) return 0;
    const index = Math.ceil((p / 100) * sorted.length) - 1;
    return sorted[Math.max(0, index)];
  }

  /**
   * Get the 50th percentile (median) latency.
   * @returns {number} P50 latency in ms.
   */
  getP50() {
    return this._percentile(50);
  }

  /**
   * Get the 95th percentile latency.
   * @returns {number} P95 latency in ms.
   */
  getP95() {
    return this._percentile(95);
  }

  /**
   * Get the 99th percentile latency.
   * @returns {number} P99 latency in ms.
   */
  getP99() {
    return this._percentile(99);
  }

  /**
   * Get rolling throughput (scans per second).
   * @returns {number} Scans per second.
   */
  getThroughput() {
    if (this.records.length < 2) return 0;
    const oldest = this.records[0].timestamp;
    const newest = this.records[this.records.length - 1].timestamp;
    const durationSec = (newest - oldest) / 1000;
    if (durationSec <= 0) return this.records.length;
    return Math.round((this.records.length / durationSec) * 100) / 100;
  }

  /**
   * Get average latency across the window.
   * @returns {number} Mean latency in ms.
   */
  getAverageLatency() {
    if (this.records.length === 0) return 0;
    const total = this.records.reduce((sum, r) => sum + r.latency, 0);
    return Math.round((total / this.records.length) * 100) / 100;
  }

  /**
   * Get average latency broken down by tier.
   * @returns {Object<string, number>} Average latency per tier.
   */
  getLatencyByTier() {
    const tiers = {};
    const counts = {};

    for (const r of this.records) {
      tiers[r.tier] = (tiers[r.tier] || 0) + r.latency;
      counts[r.tier] = (counts[r.tier] || 0) + 1;
    }

    const result = {};
    for (const tier of Object.keys(tiers)) {
      result[tier] = Math.round((tiers[tier] / counts[tier]) * 100) / 100;
    }
    return result;
  }

  /**
   * Check if p95 latency is within the given budget.
   * @param {number} maxLatencyMs - Maximum acceptable p95 latency.
   * @returns {boolean} True if within budget.
   */
  isWithinBudget(maxLatencyMs) {
    return this.getP95() <= maxLatencyMs;
  }

  /**
   * Determine if latency is trending up, down, or stable.
   * Compares first half vs second half of the window.
   * @returns {string} 'up', 'down', or 'stable'.
   */
  getTrend() {
    if (this.records.length < 10) return 'stable';

    const mid = Math.floor(this.records.length / 2);
    const firstHalf = this.records.slice(0, mid);
    const secondHalf = this.records.slice(mid);

    const avgFirst = firstHalf.reduce((s, r) => s + r.latency, 0) / firstHalf.length;
    const avgSecond = secondHalf.reduce((s, r) => s + r.latency, 0) / secondHalf.length;

    const changeRatio = (avgSecond - avgFirst) / (avgFirst || 1);

    if (changeRatio > 0.1) return 'up';
    if (changeRatio < -0.1) return 'down';
    return 'stable';
  }

  /**
   * Get a full performance summary report.
   * @returns {object} Performance report.
   */
  getReport() {
    return {
      totalScans: this.records.length,
      windowSize: this.windowSize,
      latency: {
        average: this.getAverageLatency(),
        p50: this.getP50(),
        p95: this.getP95(),
        p99: this.getP99(),
        trend: this.getTrend()
      },
      throughput: this.getThroughput(),
      latencyByTier: this.getLatencyByTier(),
      threatsDetected: this.records.reduce((s, r) => s + r.threatCount, 0)
    };
  }
}

// =========================================================================
// AdaptiveScanner
// =========================================================================

/**
 * Wraps a scanner with adaptive depth that escalates/de-escalates
 * based on threat signals.
 */
class AdaptiveScanner {
  /**
   * @param {object} scanner - Scanner object with a scan(text) method.
   * @param {object} [config] - Adaptive configuration.
   * @param {string} [config.initialTier='standard'] - Starting tier.
   * @param {number} [config.escalationThreshold=0.5] - Threat rate to escalate.
   * @param {number} [config.deescalationThreshold=0.1] - Threat rate to de-escalate.
   * @param {number} [config.windowSize=100] - Rolling window for threat rate.
   */
  constructor(scanner, config = {}) {
    this.scanner = scanner;
    this.initialTier = config.initialTier || 'standard';
    this.escalationThreshold = config.escalationThreshold || 0.5;
    this.deescalationThreshold = config.deescalationThreshold || 0.1;
    this.windowSize = config.windowSize || 100;

    this.currentTier = this.initialTier;
    this.tierManager = new TierManager();

    /** @type {Array<{tier: string, hadThreats: boolean, escalated: boolean, latency: number}>} */
    this.history = [];
    this.stats = {
      scans_by_tier: { fast: 0, standard: 0, deep: 0, paranoid: 0 },
      avg_latency_by_tier: { fast: 0, standard: 0, deep: 0, paranoid: 0 },
      escalation_rate: 0,
      threats_by_tier: { fast: 0, standard: 0, deep: 0, paranoid: 0 }
    };
    this._latencyTotals = { fast: 0, standard: 0, deep: 0, paranoid: 0 };
  }

  /**
   * Scan text with adaptive depth. Starts fast, escalates if suspicious.
   * @param {text} text - Input text to scan.
   * @returns {object} Scan result with tier info.
   */
  scan(text) {
    const startTime = Date.now();
    let tier = this.currentTier;
    let escalated = false;

    // --- Stage 1: Fast pre-check ---
    const signals = this._detectSignals(text);

    if (signals.suspicious && tier === 'fast') {
      tier = 'standard';
      escalated = true;
    }

    // --- Stage 2: Run scan at selected tier ---
    const tierConfig = this.tierManager.getTier(tier);
    const result = this._executeScan(text, tierConfig);

    // --- Stage 3: Escalate if threats found at 'standard' ---
    if (tier === 'standard' && result.threats && result.threats.length > 0) {
      tier = 'deep';
      escalated = true;
      const deepConfig = this.tierManager.getTier('deep');
      const deepResult = this._executeScan(text, deepConfig);
      // Merge results
      if (deepResult.threats) {
        const existingIds = new Set(result.threats.map(t => t.description || t.pattern));
        for (const t of deepResult.threats) {
          const id = t.description || t.pattern;
          if (!existingIds.has(id)) {
            result.threats.push(t);
          }
        }
      }
    }

    const latency = Date.now() - startTime;
    const hadThreats = result.threats && result.threats.length > 0;

    // --- Record history ---
    this.history.push({ tier, hadThreats, escalated, latency });
    if (this.history.length > this.windowSize) {
      this.history = this.history.slice(-this.windowSize);
    }

    // --- Update stats ---
    this.stats.scans_by_tier[tier] = (this.stats.scans_by_tier[tier] || 0) + 1;
    this._latencyTotals[tier] = (this._latencyTotals[tier] || 0) + latency;
    if (this.stats.scans_by_tier[tier] > 0) {
      this.stats.avg_latency_by_tier[tier] =
        Math.round((this._latencyTotals[tier] / this.stats.scans_by_tier[tier]) * 100) / 100;
    }
    if (hadThreats) {
      this.stats.threats_by_tier[tier] = (this.stats.threats_by_tier[tier] || 0) + 1;
    }
    this.stats.escalation_rate = this.getEscalationRate();

    // --- Adapt default tier based on historical threat rate ---
    this._adaptDefaultTier();

    return {
      ...result,
      tier,
      escalated,
      latency
    };
  }

  /**
   * Detect suspicious signals in input text for escalation decisions.
   * @private
   * @param {string} text - Input text.
   * @returns {object} Signal analysis.
   */
  _detectSignals(text) {
    const suspicious =
      text.length > 2000 ||
      this._calcEntropy(text) > 4.5 ||
      /ignore|override|system|admin|execute|eval/i.test(text) ||
      /base64|hex|encode|decode/i.test(text);

    return { suspicious };
  }

  /**
   * Calculate Shannon entropy of a string.
   * @private
   * @param {string} str - Input string.
   * @returns {number} Entropy value.
   */
  _calcEntropy(str) {
    if (!str || str.length === 0) return 0;
    const freq = {};
    for (const ch of str) {
      freq[ch] = (freq[ch] || 0) + 1;
    }
    let entropy = 0;
    const len = str.length;
    for (const count of Object.values(freq)) {
      const p = count / len;
      if (p > 0) entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  /**
   * Execute a scan with the given tier configuration.
   * @private
   * @param {string} text - Input text.
   * @param {object} tierConfig - Tier configuration.
   * @returns {object} Scan result.
   */
  _executeScan(text, tierConfig) {
    if (this.scanner && typeof this.scanner.scan === 'function') {
      return this.scanner.scan(text);
    }
    // Fallback: basic pattern check
    return { threats: [], status: 'safe', tier: tierConfig ? tierConfig.name : 'unknown' };
  }

  /**
   * Adapt the default tier based on recent threat rate.
   * @private
   */
  _adaptDefaultTier() {
    if (this.history.length < 10) return;

    const recent = this.history.slice(-this.windowSize);
    const threatRate = recent.filter(h => h.hadThreats).length / recent.length;

    if (threatRate >= this.escalationThreshold) {
      this.currentTier = 'standard';
    } else if (threatRate <= this.deescalationThreshold) {
      this.currentTier = 'fast';
    }
  }

  /**
   * Get the current default scanning tier.
   * @returns {string} Current tier name.
   */
  getCurrentTier() {
    return this.currentTier;
  }

  /**
   * Get the percentage of scans that escalated to a higher tier.
   * @returns {number} Escalation rate (0-1).
   */
  getEscalationRate() {
    if (this.history.length === 0) return 0;
    const escalated = this.history.filter(h => h.escalated).length;
    return Math.round((escalated / this.history.length) * 1000) / 1000;
  }

  /**
   * Get adaptive scanner statistics.
   * @returns {object} Stats including scans_by_tier, avg_latency_by_tier, escalation_rate, threats_by_tier.
   */
  getStats() {
    return { ...this.stats };
  }
}

// =========================================================================
// CostOptimizer
// =========================================================================

/**
 * Main optimization engine. Balances cost, latency, and detection accuracy
 * by selecting the right scanning tier and building optimized scan plans.
 */
class CostOptimizer {
  /**
   * @param {object} [config] - Optimizer configuration.
   * @param {number} [config.maxLatencyMs=50] - Maximum acceptable latency in ms.
   * @param {number} [config.costPerScan=0] - Base cost per scan.
   * @param {number} [config.targetThroughput=1000] - Target scans per second.
   * @param {boolean} [config.adaptiveEnabled=true] - Enable adaptive tier selection.
   * @param {string[]} [config.tiers=['fast','standard','deep']] - Allowed tiers.
   */
  constructor(config = {}) {
    this.maxLatencyMs = config.maxLatencyMs !== undefined ? config.maxLatencyMs : 50;
    this.costPerScan = config.costPerScan || 0;
    this.targetThroughput = config.targetThroughput || 1000;
    this.adaptiveEnabled = config.adaptiveEnabled !== undefined ? config.adaptiveEnabled : true;
    this.allowedTiers = config.tiers || ['fast', 'standard', 'deep'];

    this.tierManager = new TierManager();
    this.monitor = new PerformanceMonitor();

    this._optimizationCount = 0;
    this._tierSelections = {};
    this._totalCostEstimate = 0;
    this._totalLatencyEstimate = 0;
  }

  /**
   * Optimize a scan configuration given constraints.
   * Returns a ScanPlan balancing cost, latency, and accuracy.
   * @param {object} [scanConfig] - Scan configuration hints.
   * @param {string} [scanConfig.inputType='text'] - Type of input.
   * @param {number} [scanConfig.inputLength=0] - Input length in chars.
   * @param {string} [scanConfig.context='general'] - Scan context.
   * @param {object} [constraints] - External constraints.
   * @param {number} [constraints.maxLatencyMs] - Override max latency.
   * @param {number} [constraints.maxCost] - Maximum cost.
   * @param {string} [constraints.minimumTier] - Minimum tier to use.
   * @returns {ScanPlan} Optimized scan plan.
   */
  optimize(scanConfig = {}, constraints = {}) {
    this._optimizationCount++;

    const maxLatency = constraints.maxLatencyMs || this.maxLatencyMs;
    const inputLength = scanConfig.inputLength || 0;

    // Select the best tier that fits within constraints
    let selectedTier = this._selectBestTier(maxLatency, constraints.minimumTier);
    const tierConfig = this.tierManager.getTier(selectedTier);

    // Build a scan plan
    const plan = new ScanPlan(selectedTier, {
      costPerStep: this.costPerScan,
      description: `Optimized plan for ${selectedTier} tier`
    });

    // Add preprocessing step
    plan.addStep('preprocessing', {
      timeout: Math.min(tierConfig.timeout * 0.1, maxLatency * 0.1),
      type: 'preprocessing'
    });

    // Add pattern matching step
    plan.addStep('pattern_matching', {
      timeout: tierConfig.timeout * 0.6,
      type: 'pattern',
      cost: this.costPerScan * 0.5
    });

    // Add semantic analysis if tier supports it
    if (tierConfig.enableSemantic) {
      plan.addStep('semantic_analysis', {
        timeout: tierConfig.timeout * 0.2,
        type: 'semantic',
        cost: this.costPerScan * 0.3,
        required: inputLength > 500
      });
    }

    // Add encoding decode if tier supports it
    if (tierConfig.enableEncoding) {
      plan.addStep('encoding_decode', {
        timeout: tierConfig.timeout * 0.15,
        type: 'encoding',
        cost: this.costPerScan * 0.15
      });
    }

    // Add postprocessing
    plan.addStep('postprocessing', {
      timeout: Math.min(tierConfig.timeout * 0.05, 5),
      type: 'postprocessing'
    });

    // Track stats
    this._tierSelections[selectedTier] = (this._tierSelections[selectedTier] || 0) + 1;
    this._totalCostEstimate += plan.getEstimatedCost();
    this._totalLatencyEstimate += plan.getEstimatedLatency();

    return plan;
  }

  /**
   * Select the best tier that fits within the latency budget.
   * @private
   * @param {number} maxLatency - Maximum latency in ms.
   * @param {string} [minimumTier] - Minimum tier to use.
   * @returns {string} Selected tier name.
   */
  _selectBestTier(maxLatency, minimumTier) {
    const tiers = this.tierManager.listTiers()
      .filter(t => this.allowedTiers.includes(t.name));

    let minPriority = 0;
    if (minimumTier) {
      const minTier = this.tierManager.getTier(minimumTier);
      if (minTier) minPriority = minTier.priority;
    }

    // Pick the highest-priority tier that fits in budget
    let best = tiers[0];
    for (const tier of tiers) {
      if (tier.priority < minPriority) continue;
      if (tier.timeout <= maxLatency) {
        best = tier;
      }
    }

    return best ? best.name : 'fast';
  }

  /**
   * Automatically select a scanning tier based on input characteristics and context.
   * @param {string} input - Input text to analyze.
   * @param {object} [context] - Additional context.
   * @param {string} [context.source='unknown'] - Input source.
   * @param {boolean} [context.isUserFacing=false] - Whether input is user-facing.
   * @param {number} [context.recentThreatRate=0] - Recent threat detection rate.
   * @returns {object} Tier selection with reasoning.
   */
  selectTier(input, context = {}) {
    const length = (input || '').length;
    const recentThreatRate = context.recentThreatRate || 0;

    let tier = 'fast';
    const reasons = [];

    // Length-based escalation
    if (length > 5000) {
      tier = 'deep';
      reasons.push('long input (>5000 chars)');
    } else if (length > 1000) {
      tier = 'standard';
      reasons.push('medium input (>1000 chars)');
    } else {
      reasons.push('short input');
    }

    // Threat rate escalation
    if (recentThreatRate > 0.3) {
      tier = 'deep';
      reasons.push('high recent threat rate');
    } else if (recentThreatRate > 0.1 && tier === 'fast') {
      tier = 'standard';
      reasons.push('elevated threat rate');
    }

    // User-facing gets extra scrutiny
    if (context.isUserFacing && tier === 'fast') {
      tier = 'standard';
      reasons.push('user-facing input');
    }

    // Suspicious pattern quick-check
    if (/ignore|override|system|admin|execute/i.test(input || '')) {
      if (tier === 'fast') tier = 'standard';
      reasons.push('suspicious keywords detected');
    }

    // Adaptive override
    if (this.adaptiveEnabled && !this.monitor.isWithinBudget(this.maxLatencyMs)) {
      // Under latency pressure, downgrade
      if (tier === 'deep') tier = 'standard';
      else if (tier === 'standard') tier = 'fast';
      reasons.push('latency pressure downgrade');
    }

    // Filter to allowed tiers
    if (!this.allowedTiers.includes(tier)) {
      tier = this.allowedTiers[0] || 'fast';
      reasons.push('tier not in allowed list, falling back');
    }

    return {
      tier,
      reasons,
      inputLength: length,
      tierConfig: this.tierManager.getTier(tier)
    };
  }

  /**
   * Estimate cost for a scan plan.
   * @param {ScanPlan} plan - The scan plan.
   * @returns {object} Cost breakdown.
   */
  getCostEstimate(plan) {
    const baseCost = plan.getEstimatedCost();
    const steps = plan.getSteps();

    return {
      totalCost: baseCost + this.costPerScan,
      baseCost: this.costPerScan,
      stepCosts: steps.map(s => ({ name: s.name, cost: s.cost })),
      tier: plan.tier
    };
  }

  /**
   * Estimate latency for a scan plan.
   * @param {ScanPlan} plan - The scan plan.
   * @returns {object} Latency breakdown.
   */
  getLatencyEstimate(plan) {
    const totalLatency = plan.getEstimatedLatency();
    const steps = plan.getSteps();

    return {
      totalMs: totalLatency,
      withinBudget: totalLatency <= this.maxLatencyMs,
      budgetMs: this.maxLatencyMs,
      stepLatencies: steps.map(s => ({ name: s.name, timeoutMs: s.timeout })),
      tier: plan.tier
    };
  }

  /**
   * Get optimization statistics.
   * @returns {object} Optimization stats.
   */
  getStats() {
    return {
      optimizationCount: this._optimizationCount,
      tierSelections: { ...this._tierSelections },
      averageCostEstimate: this._optimizationCount > 0
        ? Math.round((this._totalCostEstimate / this._optimizationCount) * 100) / 100
        : 0,
      averageLatencyEstimate: this._optimizationCount > 0
        ? Math.round((this._totalLatencyEstimate / this._optimizationCount) * 100) / 100
        : 0,
      config: {
        maxLatencyMs: this.maxLatencyMs,
        costPerScan: this.costPerScan,
        targetThroughput: this.targetThroughput,
        adaptiveEnabled: this.adaptiveEnabled,
        allowedTiers: this.allowedTiers
      },
      performance: this.monitor.getReport()
    };
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
  CostOptimizer,
  LatencyBudget,
  AdaptiveScanner,
  TierManager,
  PerformanceMonitor,
  ScanPlan,
  OPTIMIZATION_PRESETS
};
