'use strict';

/**
 * Agent Shield — Systemic Trap Defenses (Trap 5)
 *
 * Based on DeepMind's "AI Agent Traps" paper, this module defends against
 * systemic risks in multi-agent fleets: coordinated attacks, cascade
 * failures, financial manipulation, and single points of failure.
 *
 * Four defense layers:
 *  1. FleetCorrelationEngine — detects coordinated behavior changes
 *  2. CascadeBreaker — tracks data lineage and quarantines compromised agents
 *  3. FinancialContentValidator — flags unverified financial claims
 *  4. DependencyDiversityScanner — maps single points of failure
 *
 * All detection runs locally — no data ever leaves your environment.
 *
 * @module fleet-defense
 */

// =========================================================================
// CONSTANTS
// =========================================================================

/** Default correlation time window in milliseconds. */
const DEFAULT_CORRELATION_WINDOW_MS = 60_000;

/** Minimum agents for a correlated behavior alert. */
const DEFAULT_CORRELATION_THRESHOLD = 3;

/** Patterns for financial content detection. */
const FINANCIAL_PATTERNS = [
  { regex: /\$[\d,]+(?:\.\d{1,2})?/g, category: 'price', label: 'Dollar amount' },
  { regex: /(?:price|cost|fee|rate)\s*(?:is|was|of|:)\s*\$?[\d,]+/gi, category: 'price', label: 'Price statement' },
  { regex: /(?:revenue|earnings|profit|income|loss)\s*(?:of|is|was|:)\s*\$?[\d,]+/gi, category: 'earnings', label: 'Earnings claim' },
  { regex: /market\s*cap(?:italization)?\s*(?:of|is|was|:)\s*\$?[\d,]+/gi, category: 'market_cap', label: 'Market cap claim' },
  { regex: /(?:up|down|rose|fell|gained|lost|increased|decreased)\s+[\d.]+\s*%/gi, category: 'movement', label: 'Price movement' },
  { regex: /(?:buy|sell|trade|invest|short|long)\s+(?:[\d,]+\s+)?(?:shares?|stocks?|options?|contracts?)/gi, category: 'trade_instruction', label: 'Trading instruction' },
  { regex: /(?:transfer|send|wire|pay|remit)\s+\$?[\d,]+/gi, category: 'transfer', label: 'Transfer instruction' },
  { regex: /(?:dividend|yield|roi|return)\s*(?:of|is|was|:)\s*[\d.]+\s*%/gi, category: 'return', label: 'Return claim' }
];

/** Actions requiring human approval for financial operations. */
const FINANCIAL_APPROVAL_ACTIONS = [
  'trade', 'trading', 'buy', 'sell', 'transfer', 'payment', 'pay',
  'wire', 'withdraw', 'deposit', 'invest', 'short', 'liquidate'
];

// =========================================================================
// 1. FleetCorrelationEngine
// =========================================================================

/**
 * Monitors all agents in a fleet for coordinated behavior changes.
 * Detects when multiple agents simultaneously change behavior in the
 * same direction, which may indicate a coordinated attack.
 */
class FleetCorrelationEngine {
  /**
   * @param {object} [options]
   * @param {number} [options.windowMs=60000] - Time window for correlation detection
   * @param {number} [options.threshold=3] - Minimum agents for a correlated alert
   */
  constructor(options = {}) {
    this._windowMs = options.windowMs || DEFAULT_CORRELATION_WINDOW_MS;
    this._threshold = options.threshold || DEFAULT_CORRELATION_THRESHOLD;
    /** @type {Array<{agentId: string, action: string, topic: string, timestamp: number, threat: string|null}>} */
    this._events = [];
  }

  /**
   * Record an event from an agent.
   * @param {string} agentId - Agent identifier
   * @param {{ action: string, topic?: string, timestamp?: number, threat?: string }} event
   */
  recordAgentEvent(agentId, event) {
    this._events.push({
      agentId,
      action: event.action,
      topic: event.topic || '',
      timestamp: event.timestamp || Date.now(),
      threat: event.threat || null
    });
    if (this._events.length > 50000) this._events = this._events.slice(-50000);
  }

  /**
   * Detect correlated behavior across agents within a time window.
   * @param {number} [windowMs] - Override detection window
   * @returns {{ correlated: boolean, agentCount: number, commonAction: string, timeWindow: number, severity: string }}
   */
  detectCorrelation(windowMs) {
    const window = windowMs || this._windowMs;
    const now = Date.now();
    const cutoff = now - window;

    // Get recent events
    const recent = this._events.filter(e => e.timestamp >= cutoff);

    // Group by action
    const actionGroups = {};
    for (const event of recent) {
      const key = event.action;
      if (!actionGroups[key]) actionGroups[key] = new Set();
      actionGroups[key].add(event.agentId);
    }

    // Find the most common action
    let maxAction = '';
    let maxAgents = 0;
    for (const [action, agents] of Object.entries(actionGroups)) {
      if (agents.size > maxAgents) {
        maxAgents = agents.size;
        maxAction = action;
      }
    }

    const correlated = maxAgents >= this._threshold;
    let severity = 'low';
    if (maxAgents >= this._threshold * 2) severity = 'critical';
    else if (maxAgents >= this._threshold) severity = 'high';

    if (correlated) {
      console.log(`[Agent Shield] Fleet: Correlated behavior detected — ${maxAgents} agents performing "${maxAction}" within ${window}ms`);
    }

    return {
      correlated,
      agentCount: maxAgents,
      commonAction: maxAction,
      timeWindow: window,
      severity
    };
  }

  /**
   * Get all recorded events.
   * @returns {Array}
   */
  getEvents() {
    return [...this._events];
  }

  /** Clear all events. */
  reset() {
    this._events = [];
  }
}

// =========================================================================
// 2. CascadeBreaker
// =========================================================================

/**
 * Tracks data lineage across agents and quarantines data from
 * compromised agents to prevent cascade failures.
 */
class CascadeBreaker {
  constructor() {
    /** @type {Array<{fromAgent: string, toAgent: string, dataHash: string, timestamp: number}>} */
    this._flows = [];
    /** @type {Set<string>} */
    this._compromised = new Set();
    /** @type {Set<string>} Quarantined data hashes */
    this._quarantined = new Set();
  }

  /**
   * Register a data flow between agents.
   * @param {string} fromAgent - Source agent ID
   * @param {string} toAgent - Destination agent ID
   * @param {string} dataHash - Hash identifying the data
   */
  registerDataFlow(fromAgent, toAgent, dataHash) {
    this._flows.push({ fromAgent, toAgent, dataHash, timestamp: Date.now() });
  }

  /**
   * Mark an agent as compromised.
   * @param {string} agentId - Agent to mark
   */
  markCompromised(agentId) {
    this._compromised.add(agentId);
    console.log(`[Agent Shield] Fleet: Agent "${agentId}" marked as compromised`);
  }

  /**
   * Check whether a data hash originates from a compromised agent.
   * @param {string} dataHash - Data hash to check
   * @returns {{ safe: boolean, originAgent: string|null, compromised: boolean }}
   */
  checkData(dataHash) {
    if (this._quarantined.has(dataHash)) {
      return { safe: false, originAgent: null, compromised: true };
    }

    // Find origin
    const flow = this._flows.find(f => f.dataHash === dataHash);
    if (!flow) {
      return { safe: true, originAgent: null, compromised: false };
    }

    // Trace back to original sender
    let origin = flow.fromAgent;
    const visited = new Set();
    while (true) {
      if (visited.has(origin)) break;
      visited.add(origin);
      const upstream = this._flows.find(f => f.toAgent === origin && f.dataHash === dataHash);
      if (!upstream) break;
      origin = upstream.fromAgent;
    }

    const compromised = this._compromised.has(origin);
    return { safe: !compromised, originAgent: origin, compromised };
  }

  /**
   * Quarantine all data from a compromised agent, blocking downstream propagation.
   * @param {string} agentId - Compromised agent ID
   * @returns {{ quarantinedHashes: string[], affectedAgents: string[] }}
   */
  quarantineDownstream(agentId) {
    const quarantinedHashes = [];
    const affectedAgents = new Set();

    // Find all data that originated from or passed through this agent
    const agentHashes = new Set();
    for (const flow of this._flows) {
      if (flow.fromAgent === agentId) {
        agentHashes.add(flow.dataHash);
      }
    }

    // Mark all downstream flows as quarantined
    const queue = [...agentHashes];
    while (queue.length > 0) {
      const hash = queue.pop();
      if (this._quarantined.has(hash)) continue;
      this._quarantined.add(hash);
      quarantinedHashes.push(hash);

      // Find downstream agents that received this data
      for (const flow of this._flows) {
        if (flow.dataHash === hash) {
          affectedAgents.add(flow.toAgent);
        }
      }
    }

    if (quarantinedHashes.length > 0) {
      console.log(`[Agent Shield] Fleet: Quarantined ${quarantinedHashes.length} data hash(es) from agent "${agentId}"`);
    }

    return {
      quarantinedHashes,
      affectedAgents: [...affectedAgents]
    };
  }

  /**
   * Get list of compromised agents.
   * @returns {string[]}
   */
  getCompromised() {
    return [...this._compromised];
  }

  /** Reset all state. */
  reset() {
    this._flows = [];
    this._compromised.clear();
    this._quarantined.clear();
  }
}

// =========================================================================
// 3. FinancialContentValidator
// =========================================================================

/**
 * Scans content for financial claims and flags actions requiring
 * human approval for financial operations.
 */
class FinancialContentValidator {
  /**
   * @param {object} [options]
   * @param {Array} [options.additionalPatterns] - Extra financial patterns
   * @param {string[]} [options.approvalActions] - Actions requiring approval
   */
  constructor(options = {}) {
    this._patterns = [...FINANCIAL_PATTERNS, ...(options.additionalPatterns || [])];
    this._approvalActions = options.approvalActions || FINANCIAL_APPROVAL_ACTIONS;
  }

  /**
   * Validate content for financial claims and determine if human approval is needed.
   * @param {string} content - Content to scan
   * @returns {{ requiresHumanApproval: boolean, financialClaims: Array<{text: string, category: string, label: string}>, riskLevel: string }}
   */
  validate(content) {
    const financialClaims = [];
    const contentLower = content.toLowerCase();

    // Scan for financial patterns
    for (const pattern of this._patterns) {
      // Reset regex lastIndex for global patterns
      pattern.regex.lastIndex = 0;
      let match;
      while ((match = pattern.regex.exec(content)) !== null) {
        financialClaims.push({
          text: match[0],
          category: pattern.category,
          label: pattern.label
        });
        // Avoid infinite loops on zero-length matches
        if (match[0].length === 0) break;
      }
    }

    // Check if content mentions approval-required actions
    const mentionsApprovalAction = this._approvalActions.some(action =>
      contentLower.includes(action)
    );

    // Determine risk level
    let riskLevel = 'low';
    const hasTradeInstructions = financialClaims.some(c =>
      c.category === 'trade_instruction' || c.category === 'transfer'
    );

    if (hasTradeInstructions) {
      riskLevel = 'critical';
    } else if (financialClaims.length > 3) {
      riskLevel = 'high';
    } else if (financialClaims.length > 0) {
      riskLevel = 'medium';
    }

    const requiresHumanApproval = mentionsApprovalAction || hasTradeInstructions;

    if (requiresHumanApproval) {
      console.log(`[Agent Shield] Fleet: Financial content requires human approval — ${financialClaims.length} claim(s), risk: ${riskLevel}`);
    }

    return { requiresHumanApproval, financialClaims, riskLevel };
  }
}

// =========================================================================
// 4. DependencyDiversityScanner
// =========================================================================

/**
 * Maps agent-to-server dependencies and identifies single points of
 * failure where all agents depend on the same server/service.
 */
class DependencyDiversityScanner {
  constructor() {
    /** @type {Map<string, Set<string>>} agentId -> Set<serverId> */
    this._agentDeps = new Map();
    /** @type {Map<string, Set<string>>} serverId -> Set<agentId> */
    this._serverDeps = new Map();
  }

  /**
   * Register a dependency: agent depends on server.
   * @param {string} agentId - Agent identifier
   * @param {string} serverId - Server/service identifier
   */
  registerDependency(agentId, serverId) {
    if (!this._agentDeps.has(agentId)) this._agentDeps.set(agentId, new Set());
    this._agentDeps.get(agentId).add(serverId);

    if (!this._serverDeps.has(serverId)) this._serverDeps.set(serverId, new Set());
    this._serverDeps.get(serverId).add(agentId);
  }

  /**
   * Analyze dependencies for single points of failure.
   * @returns {{ singlePointsOfFailure: Array<{serverId: string, dependentAgents: string[]}>, diversityScore: number }}
   */
  analyze() {
    const totalAgents = this._agentDeps.size;
    const singlePointsOfFailure = [];

    // A SPOF is a server that ALL registered agents depend on
    for (const [serverId, agents] of this._serverDeps.entries()) {
      if (totalAgents > 0 && agents.size === totalAgents) {
        singlePointsOfFailure.push({
          serverId,
          dependentAgents: [...agents]
        });
      }
    }

    // Diversity score: 1.0 = no SPOFs, 0.0 = all servers are SPOFs
    const totalServers = this._serverDeps.size;
    const diversityScore = totalServers > 0
      ? 1 - (singlePointsOfFailure.length / totalServers)
      : 1;

    if (singlePointsOfFailure.length > 0) {
      console.log(`[Agent Shield] Fleet: ${singlePointsOfFailure.length} single point(s) of failure detected`);
    }

    return {
      singlePointsOfFailure,
      diversityScore: Math.round(diversityScore * 1000) / 1000
    };
  }

  /**
   * Get dependencies for a specific agent.
   * @param {string} agentId
   * @returns {string[]}
   */
  getAgentDependencies(agentId) {
    const deps = this._agentDeps.get(agentId);
    return deps ? [...deps] : [];
  }

  /** Reset all state. */
  reset() {
    this._agentDeps.clear();
    this._serverDeps.clear();
  }
}

// =========================================================================
// FleetDefense — Unified Wrapper
// =========================================================================

/**
 * Fleet Defense — wraps all four defense layers into a single class.
 */
class FleetDefense {
  /**
   * @param {object} [options]
   * @param {object} [options.correlation] - Options for FleetCorrelationEngine
   * @param {object} [options.financial] - Options for FinancialContentValidator
   */
  constructor(options = {}) {
    this.correlationEngine = new FleetCorrelationEngine(options.correlation);
    this.cascadeBreaker = new CascadeBreaker();
    this.financialValidator = new FinancialContentValidator(options.financial);
    this.dependencyScanner = new DependencyDiversityScanner();
  }

  /**
   * Run a fleet health check.
   * @returns {{ correlation: object, spof: object }}
   */
  healthCheck() {
    const correlation = this.correlationEngine.detectCorrelation();
    const spof = this.dependencyScanner.analyze();

    return { correlation, spof };
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
  FleetDefense,
  FleetCorrelationEngine,
  CascadeBreaker,
  FinancialContentValidator,
  DependencyDiversityScanner,
  FINANCIAL_PATTERNS,
  FINANCIAL_APPROVAL_ACTIONS,
  DEFAULT_CORRELATION_WINDOW_MS,
  DEFAULT_CORRELATION_THRESHOLD
};
