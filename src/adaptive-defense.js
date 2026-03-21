'use strict';

/**
 * Agent Shield — Adaptive Defense System
 *
 * Three interconnected systems that make Agent Shield learn and improve:
 *
 * 1. LearningLoop — blocked attacks feed into threat intelligence, which
 *    generates new detection patterns automatically. The system gets smarter
 *    with every attack it sees.
 *
 * 2. AgentContract — declarative behavioral specifications that define what
 *    an agent is ALLOWED to do. Verified continuously at runtime, not just
 *    at deploy time. Violations are caught instantly.
 *
 * 3. ComplianceAttestor — real-time proof that your agents meet NIST, OWASP,
 *    EU AI Act requirements. Not a report you generate once — a live signal
 *    that updates with every action your agent takes.
 *
 * Together these create a closed-loop system: attacks improve detection,
 * contracts prevent drift, and compliance is proven continuously.
 *
 * All processing runs locally — no data ever leaves your environment.
 */

const crypto = require('crypto');

const LOG_PREFIX = '[Agent Shield]';

// =========================================================================
// 1. LearningLoop — self-improving detection
// =========================================================================

/**
 * Closed-loop system that feeds blocked attacks back into threat intelligence,
 * which generates new detection patterns. Every attack makes the system smarter.
 *
 * Flow:
 *   Attack blocked → extract signature → record in intel → generate pattern
 *   → add to scanner → next attack caught faster
 */
class LearningLoop {
  /**
   * @param {object} [options]
   * @param {number} [options.minHitsToPromote=3] - Hits before a pattern becomes active
   * @param {number} [options.maxLearnedPatterns=500] - Max auto-generated patterns
   * @param {number} [options.promotionConfidence=0.75] - Min confidence to promote
   * @param {Function} [options.onPatternLearned] - Callback when new pattern is promoted
   * @param {Function} [options.onFeedback] - Callback for operator feedback
   */
  constructor(options = {}) {
    this._minHitsToPromote = options.minHitsToPromote || 3;
    this._maxLearnedPatterns = options.maxLearnedPatterns || 500;
    this._promotionConfidence = options.promotionConfidence || 0.75;
    this._onPatternLearned = options.onPatternLearned || null;
    this._onFeedback = options.onFeedback || null;

    // Candidate patterns (not yet promoted)
    this._candidates = new Map(); // signature → CandidatePattern
    // Promoted patterns (active detection)
    this._promoted = new Map();   // patternId → PromotedPattern
    // Feedback from operators
    this._feedback = [];

    this.stats = {
      attacksIngested: 0,
      candidatesCreated: 0,
      patternsPromoted: 0,
      falsePositivesReported: 0,
      patternsRevoked: 0
    };
  }

  /**
   * Ingests a blocked attack and extracts learnable signatures.
   * Call this every time the scanner blocks something.
   *
   * @param {object} attack
   * @param {string} attack.text - The blocked text
   * @param {string} attack.category - Threat category
   * @param {Array} [attack.threats] - Detected threats
   * @param {string} [attack.toolName] - Tool that was targeted
   * @param {string} [attack.sessionId] - Session context
   * @returns {{ signatures: string[], candidatesUpdated: number, promoted: string[] }}
   */
  ingest(attack) {
    if (!attack || !attack.text || !attack.category) {
      return { signatures: [], candidatesUpdated: 0, promoted: [] };
    }

    this.stats.attacksIngested++;
    const signatures = this._extractSignatures(attack.text, attack.category);
    let candidatesUpdated = 0;
    const promoted = [];

    for (const sig of signatures) {
      const sigHash = this._hash(sig);
      const existing = this._candidates.get(sigHash);

      if (existing) {
        // Existing candidate — increment hit count
        existing.hitCount++;
        existing.lastSeen = Date.now();
        existing.contexts.push({
          category: attack.category,
          toolName: attack.toolName || null,
          timestamp: Date.now()
        });
        if (existing.contexts.length > 20) existing.contexts.shift();
        candidatesUpdated++;

        // Check if ready for promotion
        if (existing.hitCount >= this._minHitsToPromote &&
            !existing.promoted &&
            this._promoted.size < this._maxLearnedPatterns) {
          const confidence = Math.min(1.0, 0.5 + (existing.hitCount * 0.05));
          if (confidence >= this._promotionConfidence) {
            existing.promoted = true;
            const patternId = `LP_${sigHash.substring(0, 12)}`;
            this._promoted.set(patternId, {
              patternId,
              signature: sig,
              category: attack.category,
              confidence,
              hitCount: existing.hitCount,
              promotedAt: Date.now(),
              active: true,
              source: 'learning_loop'
            });
            this.stats.patternsPromoted++;
            promoted.push(patternId);
            if (this._onPatternLearned) {
              try { this._onPatternLearned({ patternId, signature: sig, category: attack.category, confidence }); } catch (_e) { /* */ }
            }
          }
        }
      } else {
        // New candidate
        this._candidates.set(sigHash, {
          signature: sig,
          sigHash,
          category: attack.category,
          hitCount: 1,
          firstSeen: Date.now(),
          lastSeen: Date.now(),
          promoted: false,
          contexts: [{
            category: attack.category,
            toolName: attack.toolName || null,
            timestamp: Date.now()
          }]
        });
        this.stats.candidatesCreated++;
        candidatesUpdated++;
      }
    }

    return { signatures, candidatesUpdated, promoted };
  }

  /**
   * Checks input against learned patterns.
   * @param {string} text
   * @returns {{ matches: Array<{ patternId: string, category: string, confidence: number }> }}
   */
  check(text) {
    if (!text) return { matches: [] };
    const lower = text.toLowerCase();
    const matches = [];

    for (const [patternId, pattern] of this._promoted) {
      if (!pattern.active) continue;
      if (lower.includes(pattern.signature.toLowerCase())) {
        matches.push({
          patternId,
          category: pattern.category,
          confidence: pattern.confidence,
          source: 'learned'
        });
      }
    }

    return { matches };
  }

  /**
   * Records operator feedback — false positive or confirmed threat.
   * @param {string} patternId
   * @param {'false_positive' | 'confirmed'} type
   * @param {string} [reason]
   */
  recordFeedback(patternId, type, reason) {
    this._feedback.push({
      patternId,
      type,
      reason: reason || null,
      timestamp: Date.now()
    });

    if (type === 'false_positive') {
      this.stats.falsePositivesReported++;
      const pattern = this._promoted.get(patternId);
      if (pattern) {
        pattern.confidence = Math.max(0.1, pattern.confidence - 0.15);
        // Revoke if confidence drops too low
        if (pattern.confidence < 0.4) {
          pattern.active = false;
          this.stats.patternsRevoked++;
        }
      }
    } else if (type === 'confirmed') {
      const pattern = this._promoted.get(patternId);
      if (pattern) {
        pattern.confidence = Math.min(1.0, pattern.confidence + 0.1);
      }
    }

    if (this._onFeedback) {
      try { this._onFeedback({ patternId, type, reason }); } catch (_e) { /* */ }
    }
  }

  /**
   * Returns all active learned patterns.
   * @returns {Array}
   */
  getActivePatterns() {
    const patterns = [];
    for (const [_id, p] of this._promoted) {
      if (p.active) patterns.push({ ...p });
    }
    return patterns;
  }

  /**
   * Returns learning statistics.
   * @returns {object}
   */
  getReport() {
    return {
      stats: { ...this.stats },
      candidates: this._candidates.size,
      activePatterns: [...this._promoted.values()].filter(p => p.active).length,
      revokedPatterns: [...this._promoted.values()].filter(p => !p.active).length,
      recentFeedback: this._feedback.slice(-10)
    };
  }

  /**
   * Exports learned patterns for sharing across deployments.
   * @returns {object}
   */
  exportPatterns() {
    const patterns = [];
    for (const [_id, p] of this._promoted) {
      if (p.active) patterns.push({ ...p });
    }
    return { version: '1.0', exportedAt: Date.now(), patterns };
  }

  /**
   * Imports learned patterns from another deployment.
   * @param {object} data - Output of exportPatterns()
   * @returns {{ imported: number, skipped: number }}
   */
  importPatterns(data) {
    if (!data || !data.patterns) return { imported: 0, skipped: 0 };
    let imported = 0;
    let skipped = 0;

    for (const p of data.patterns) {
      if (!p.patternId || !p.signature || !p.category) { skipped++; continue; }
      if (this._promoted.has(p.patternId)) { skipped++; continue; }
      if (this._promoted.size >= this._maxLearnedPatterns) { skipped++; continue; }

      this._promoted.set(p.patternId, {
        ...p,
        active: true,
        importedAt: Date.now()
      });
      imported++;
    }

    return { imported, skipped };
  }

  /** @private */
  _extractSignatures(text, _category) {
    const signatures = [];
    const lower = text.toLowerCase();

    // Extract significant phrases (3+ words that appear to be instructions)
    const instructionPatterns = [
      /ignore\s+(?:all\s+)?(?:previous\s+)?instructions?/gi,
      /you\s+are\s+now\s+\w+/gi,
      /forget\s+(?:everything|all|your)\s+\w+/gi,
      /act\s+as\s+(?:if|though)?\s*\w+/gi,
      /reveal\s+(?:your|the)\s+(?:system\s+)?prompt/gi,
      /output\s+(?:your|the)\s+(?:initial|system|original)\s+\w+/gi,
      /bypass\s+(?:all\s+)?(?:security|safety|restrictions?)/gi,
      /disable\s+(?:your\s+)?(?:safety|security|filters?)/gi,
      /(?:send|post|fetch|curl)\s+(?:to|from)\s+\S+/gi,
      /(?:read|cat|access)\s+(?:\/etc\/|\.env|\.ssh|\/proc)/gi
    ];

    for (const pattern of instructionPatterns) {
      const matches = lower.match(pattern);
      if (matches) {
        for (const match of matches) {
          const trimmed = match.trim();
          if (trimmed.length >= 8 && trimmed.length <= 100) {
            signatures.push(trimmed);
          }
        }
      }
    }

    // If no pattern matches, extract the most suspicious 4-gram
    if (signatures.length === 0 && lower.length >= 20) {
      const words = lower.split(/\s+/).filter(w => w.length > 2);
      if (words.length >= 4) {
        // Use the first 4 meaningful words as a signature
        signatures.push(words.slice(0, 4).join(' '));
      }
    }

    return signatures;
  }

  /** @private */
  _hash(text) {
    return crypto.createHash('sha256').update(text).digest('hex').substring(0, 16);
  }
}

// =========================================================================
// 2. AgentContract — declarative behavioral specifications
// =========================================================================

/**
 * Defines what an agent is ALLOWED to do, verified continuously at runtime.
 * Like a unit test for agent behavior that never stops running.
 *
 * Example contract:
 *   {
 *     agentId: 'research-bot',
 *     allowedTools: ['search', 'read_file'],
 *     deniedTools: ['delete_file', 'execute_shell'],
 *     maxToolCallsPerMinute: 30,
 *     maxDelegationDepth: 2,
 *     allowedScopes: ['docs:read', 'web:search'],
 *     requiredIntents: true,
 *     allowedDataPatterns: [/^[a-zA-Z0-9\s.,!?]+$/],  // No code, no URLs
 *     timeWindows: [{ start: 9, end: 17 }],  // Business hours only
 *     maxResponseLength: 10000
 *   }
 */
class AgentContract {
  /**
   * @param {object} spec - Contract specification
   * @param {string} spec.agentId - Agent this contract applies to
   * @param {string[]} [spec.allowedTools] - Whitelist of permitted tools
   * @param {string[]} [spec.deniedTools] - Blacklist of forbidden tools
   * @param {number} [spec.maxToolCallsPerMinute=60] - Rate limit
   * @param {number} [spec.maxDelegationDepth=3] - Max delegation chain depth
   * @param {string[]} [spec.allowedScopes] - Permitted permission scopes
   * @param {boolean} [spec.requiredIntents=false] - Must declare intent
   * @param {number} [spec.maxResponseLength=50000] - Max output length
   * @param {Array<{start: number, end: number}>} [spec.timeWindows] - Allowed hours (0-23)
   * @param {Function} [spec.customValidator] - Custom validation function
   */
  constructor(spec) {
    if (!spec || !spec.agentId) {
      throw new Error(`${LOG_PREFIX} AgentContract requires agentId`);
    }

    this.agentId = spec.agentId;
    this.allowedTools = spec.allowedTools ? new Set(spec.allowedTools) : null;
    this.deniedTools = spec.deniedTools ? new Set(spec.deniedTools) : new Set();
    this.maxToolCallsPerMinute = spec.maxToolCallsPerMinute || 60;
    this.maxDelegationDepth = spec.maxDelegationDepth || 3;
    this.allowedScopes = spec.allowedScopes ? new Set(spec.allowedScopes) : null;
    this.requiredIntents = spec.requiredIntents || false;
    this.maxResponseLength = spec.maxResponseLength || 50000;
    this.timeWindows = spec.timeWindows || null;
    this.customValidator = spec.customValidator || null;
    this.createdAt = Date.now();

    // Runtime tracking
    this._toolCallTimestamps = [];
    this._violations = [];
    this._maxViolations = 1000;
    this.stats = { checked: 0, passed: 0, violated: 0 };
  }

  /**
   * Verifies an action against this contract.
   * @param {object} action
   * @param {string} action.type - 'tool_call' | 'delegation' | 'response' | 'scope_request'
   * @param {string} [action.toolName] - For tool_call type
   * @param {object} [action.args] - Tool arguments
   * @param {string} [action.intent] - Declared intent
   * @param {number} [action.delegationDepth] - Current delegation depth
   * @param {string} [action.responseText] - For response type
   * @param {string[]} [action.requestedScopes] - For scope_request type
   * @returns {{ allowed: boolean, violations: Array<{ rule: string, message: string, severity: string }> }}
   */
  verify(action) {
    this.stats.checked++;
    const violations = [];

    // Tool whitelist/blacklist
    if (action.type === 'tool_call' && action.toolName) {
      if (this.allowedTools && !this.allowedTools.has(action.toolName)) {
        violations.push({
          rule: 'allowed_tools',
          message: `Tool "${action.toolName}" not in contract whitelist`,
          severity: 'high'
        });
      }
      if (this.deniedTools.has(action.toolName)) {
        violations.push({
          rule: 'denied_tools',
          message: `Tool "${action.toolName}" explicitly denied by contract`,
          severity: 'critical'
        });
      }

      // Rate limiting
      const now = Date.now();
      this._toolCallTimestamps.push(now);
      const cutoff = now - 60000;
      this._toolCallTimestamps = this._toolCallTimestamps.filter(t => t > cutoff);
      if (this._toolCallTimestamps.length > this.maxToolCallsPerMinute) {
        violations.push({
          rule: 'rate_limit',
          message: `Rate limit exceeded: ${this._toolCallTimestamps.length}/${this.maxToolCallsPerMinute} calls/min`,
          severity: 'high'
        });
      }
    }

    // Delegation depth
    if (action.type === 'delegation' && action.delegationDepth !== undefined) {
      if (action.delegationDepth >= this.maxDelegationDepth) {
        violations.push({
          rule: 'delegation_depth',
          message: `Delegation depth ${action.delegationDepth} exceeds contract max ${this.maxDelegationDepth}`,
          severity: 'critical'
        });
      }
    }

    // Scope checking
    if (action.type === 'scope_request' && action.requestedScopes && this.allowedScopes) {
      for (const scope of action.requestedScopes) {
        if (!this.allowedScopes.has(scope) && !this.allowedScopes.has('*')) {
          violations.push({
            rule: 'allowed_scopes',
            message: `Scope "${scope}" not permitted by contract`,
            severity: 'high'
          });
        }
      }
    }

    // Intent requirement
    if (this.requiredIntents && !action.intent) {
      violations.push({
        rule: 'required_intent',
        message: 'Contract requires declared intent but none provided',
        severity: 'medium'
      });
    }

    // Response length
    if (action.type === 'response' && action.responseText) {
      if (action.responseText.length > this.maxResponseLength) {
        violations.push({
          rule: 'response_length',
          message: `Response length ${action.responseText.length} exceeds contract max ${this.maxResponseLength}`,
          severity: 'medium'
        });
      }
    }

    // Time windows
    if (this.timeWindows && this.timeWindows.length > 0) {
      const hour = new Date().getHours();
      const inWindow = this.timeWindows.some(w => hour >= w.start && hour < w.end);
      if (!inWindow) {
        violations.push({
          rule: 'time_window',
          message: `Action at hour ${hour} outside permitted windows`,
          severity: 'medium'
        });
      }
    }

    // Custom validator
    if (this.customValidator) {
      try {
        const customResult = this.customValidator(action);
        if (customResult && customResult.violations) {
          violations.push(...customResult.violations);
        }
      } catch (_e) { /* custom validator errors don't break the contract check */ }
    }

    // Record result
    if (violations.length > 0) {
      this.stats.violated++;
      if (this._violations.length >= this._maxViolations) {
        this._violations = this._violations.slice(-Math.floor(this._maxViolations * 0.75));
      }
      this._violations.push({
        timestamp: Date.now(),
        action: { type: action.type, toolName: action.toolName },
        violations
      });
    } else {
      this.stats.passed++;
    }

    return { allowed: violations.length === 0, violations };
  }

  /**
   * Returns violation history.
   * @param {number} [limit=50]
   * @returns {Array}
   */
  getViolations(limit = 50) {
    return this._violations.slice(-limit);
  }

  /**
   * Returns contract compliance percentage.
   * @returns {{ complianceRate: number, checked: number, passed: number, violated: number }}
   */
  getComplianceRate() {
    const rate = this.stats.checked > 0
      ? Math.round(this.stats.passed / this.stats.checked * 10000) / 100
      : 100;
    return {
      complianceRate: rate,
      ...this.stats
    };
  }

  /**
   * Serializes the contract for storage/transfer.
   * @returns {object}
   */
  toJSON() {
    return {
      agentId: this.agentId,
      allowedTools: this.allowedTools ? [...this.allowedTools] : null,
      deniedTools: [...this.deniedTools],
      maxToolCallsPerMinute: this.maxToolCallsPerMinute,
      maxDelegationDepth: this.maxDelegationDepth,
      allowedScopes: this.allowedScopes ? [...this.allowedScopes] : null,
      requiredIntents: this.requiredIntents,
      maxResponseLength: this.maxResponseLength,
      timeWindows: this.timeWindows,
      createdAt: this.createdAt
    };
  }

  /**
   * Creates a contract from a JSON specification.
   * @param {object} json
   * @returns {AgentContract}
   */
  static fromJSON(json) {
    return new AgentContract(json);
  }
}

/**
 * Manages multiple agent contracts and enforces them at runtime.
 */
class ContractRegistry {
  constructor() {
    this._contracts = new Map(); // agentId → AgentContract
    this._onViolation = null;
  }

  /**
   * Registers a contract for an agent.
   * @param {AgentContract} contract
   */
  register(contract) {
    this._contracts.set(contract.agentId, contract);
  }

  /**
   * Sets a callback for contract violations.
   * @param {Function} callback
   */
  onViolation(callback) {
    this._onViolation = callback;
  }

  /**
   * Enforces the contract for a given agent action.
   * @param {string} agentId
   * @param {object} action
   * @returns {{ allowed: boolean, violations: Array, hasContract: boolean }}
   */
  enforce(agentId, action) {
    const contract = this._contracts.get(agentId);
    if (!contract) {
      return { allowed: true, violations: [], hasContract: false };
    }

    const result = contract.verify(action);
    if (!result.allowed && this._onViolation) {
      try { this._onViolation({ agentId, action, violations: result.violations }); } catch (_e) { /* */ }
    }

    return { ...result, hasContract: true };
  }

  /**
   * Returns compliance rates for all registered agents.
   * @returns {object}
   */
  getComplianceReport() {
    const report = {};
    for (const [agentId, contract] of this._contracts) {
      report[agentId] = contract.getComplianceRate();
    }
    return report;
  }

  /**
   * Returns all registered contract IDs.
   * @returns {string[]}
   */
  getRegisteredAgents() {
    return [...this._contracts.keys()];
  }
}

// =========================================================================
// 3. ComplianceAttestor — continuous real-time compliance
// =========================================================================

/** Compliance frameworks with their requirements mapped to observable signals. */
const ATTESTATION_FRAMEWORKS = Object.freeze({
  'OWASP-LLM-2025': {
    name: 'OWASP LLM Top 10 (2025)',
    requirements: [
      { id: 'LLM01', name: 'Prompt Injection', signal: 'injection_scans_active', weight: 3 },
      { id: 'LLM02', name: 'Sensitive Info Disclosure', signal: 'pii_scanning_active', weight: 3 },
      { id: 'LLM05', name: 'Improper Output Handling', signal: 'output_scanning_active', weight: 2 },
      { id: 'LLM06', name: 'Excessive Agency', signal: 'tool_authorization_active', weight: 3 },
      { id: 'LLM07', name: 'System Prompt Leakage', signal: 'prompt_leak_scanning', weight: 2 },
      { id: 'LLM08', name: 'Vector/Embedding Weakness', signal: 'rag_scanning_active', weight: 1 },
      { id: 'LLM10', name: 'Unbounded Consumption', signal: 'rate_limiting_active', weight: 2 }
    ]
  },
  'NIST-AI-RMF': {
    name: 'NIST AI Risk Management Framework',
    requirements: [
      { id: 'GOVERN-1', name: 'Policies & Procedures', signal: 'policy_engine_active', weight: 2 },
      { id: 'MAP-1', name: 'Risk Identification', signal: 'threat_scanning_active', weight: 2 },
      { id: 'MEASURE-1', name: 'Risk Measurement', signal: 'behavior_monitoring_active', weight: 2 },
      { id: 'MANAGE-1', name: 'Risk Response', signal: 'blocking_enabled', weight: 3 },
      { id: 'MONITOR-1', name: 'Continuous Monitoring', signal: 'audit_trail_active', weight: 3 }
    ]
  },
  'EU-AI-ACT': {
    name: 'EU AI Act',
    requirements: [
      { id: 'ART-9', name: 'Risk Management', signal: 'threat_scanning_active', weight: 3 },
      { id: 'ART-10', name: 'Data Governance', signal: 'pii_scanning_active', weight: 2 },
      { id: 'ART-12', name: 'Record Keeping', signal: 'audit_trail_active', weight: 3 },
      { id: 'ART-13', name: 'Transparency', signal: 'contract_enforcement_active', weight: 2 },
      { id: 'ART-14', name: 'Human Oversight', signal: 'human_approval_gates', weight: 2 },
      { id: 'ART-15', name: 'Accuracy & Robustness', signal: 'behavior_monitoring_active', weight: 2 }
    ]
  }
});

/**
 * Continuous compliance attestation engine.
 * Instead of generating reports, it maintains a live compliance state
 * that updates with every action the system takes.
 *
 * At any moment, you can ask: "Are we compliant?" and get a real-time answer.
 */
class ComplianceAttestor {
  /**
   * @param {object} [options]
   * @param {string[]} [options.frameworks] - Which frameworks to attest against
   * @param {number} [options.attestationIntervalMs=30000] - How often to re-evaluate (default 30s)
   * @param {Function} [options.onComplianceDrift] - Callback when compliance drops
   * @param {number} [options.driftThreshold=0.9] - Compliance rate below this triggers drift alert
   */
  constructor(options = {}) {
    this._frameworks = options.frameworks || Object.keys(ATTESTATION_FRAMEWORKS);
    this._driftThreshold = options.driftThreshold || 0.9;
    this._onComplianceDrift = options.onComplianceDrift || null;

    // Live signal state — updated by the runtime
    this._signals = {
      injection_scans_active: false,
      pii_scanning_active: false,
      output_scanning_active: false,
      tool_authorization_active: false,
      prompt_leak_scanning: false,
      rag_scanning_active: false,
      rate_limiting_active: false,
      policy_engine_active: false,
      threat_scanning_active: false,
      behavior_monitoring_active: false,
      blocking_enabled: false,
      audit_trail_active: false,
      contract_enforcement_active: false,
      human_approval_gates: false
    };

    // Attestation history — proof over time
    this._attestations = [];
    this._maxAttestations = 10000;

    // Current compliance state
    this._currentState = {};
    this._lastAttestationTime = 0;

    this.stats = { attestations: 0, driftsDetected: 0 };
  }

  /**
   * Updates a compliance signal. Call this as the runtime operates.
   * @param {string} signal - Signal name
   * @param {boolean} value - Whether the signal is active
   */
  updateSignal(signal, value) {
    if (signal in this._signals) {
      this._signals[signal] = value;
    }
  }

  /**
   * Updates multiple signals at once.
   * @param {object} signals - { signalName: boolean }
   */
  updateSignals(signals) {
    for (const [key, value] of Object.entries(signals)) {
      if (key in this._signals) {
        this._signals[key] = value;
      }
    }
  }

  /**
   * Generates a real-time attestation — the current compliance state.
   * This is the core API. Call it anytime to get proof of compliance.
   *
   * @returns {{ compliant: boolean, overallScore: number, frameworks: object, timestamp: number, attestationId: string }}
   */
  attest() {
    this.stats.attestations++;
    const timestamp = Date.now();
    const attestationId = crypto.randomUUID();
    const frameworks = {};
    let totalScore = 0;
    let totalWeight = 0;

    for (const frameworkId of this._frameworks) {
      const framework = ATTESTATION_FRAMEWORKS[frameworkId];
      if (!framework) continue;

      let fwScore = 0;
      let fwWeight = 0;
      const requirements = [];

      for (const req of framework.requirements) {
        const met = this._signals[req.signal] === true;
        fwWeight += req.weight;
        if (met) fwScore += req.weight;

        requirements.push({
          id: req.id,
          name: req.name,
          signal: req.signal,
          met,
          weight: req.weight
        });
      }

      const complianceRate = fwWeight > 0 ? Math.round(fwScore / fwWeight * 100) / 100 : 0;
      frameworks[frameworkId] = {
        name: framework.name,
        complianceRate,
        score: fwScore,
        maxScore: fwWeight,
        requirements
      };

      totalScore += fwScore;
      totalWeight += fwWeight;
    }

    const overallScore = totalWeight > 0 ? Math.round(totalScore / totalWeight * 100) / 100 : 0;
    const compliant = overallScore >= this._driftThreshold;

    const attestation = {
      attestationId,
      timestamp,
      compliant,
      overallScore,
      frameworks,
      signals: { ...this._signals }
    };

    // Record attestation
    if (this._attestations.length >= this._maxAttestations) {
      this._attestations = this._attestations.slice(-Math.floor(this._maxAttestations * 0.75));
    }
    this._attestations.push({
      attestationId,
      timestamp,
      compliant,
      overallScore
    });

    // Check for compliance drift
    if (!compliant && this._onComplianceDrift) {
      this.stats.driftsDetected++;
      try {
        this._onComplianceDrift({
          attestationId,
          overallScore,
          threshold: this._driftThreshold,
          failedFrameworks: Object.entries(frameworks)
            .filter(([_k, v]) => v.complianceRate < this._driftThreshold)
            .map(([k, v]) => ({ framework: k, rate: v.complianceRate }))
        });
      } catch (_e) { /* */ }
    }

    this._currentState = attestation;
    this._lastAttestationTime = timestamp;

    return attestation;
  }

  /**
   * Returns the most recent attestation without re-computing.
   * @returns {object|null}
   */
  getCurrentState() {
    return this._currentState || null;
  }

  /**
   * Returns compliance trend over time.
   * @param {number} [limit=100]
   * @returns {Array}
   */
  getHistory(limit = 100) {
    return this._attestations.slice(-limit);
  }

  /**
   * Returns the compliance trend direction.
   * @returns {'improving' | 'stable' | 'degrading' | 'unknown'}
   */
  getTrend() {
    const recent = this._attestations.slice(-20);
    if (recent.length < 5) return 'unknown';

    const midpoint = Math.floor(recent.length / 2);
    const firstHalf = recent.slice(0, midpoint);
    const secondHalf = recent.slice(midpoint);

    const avgFirst = firstHalf.reduce((s, a) => s + a.overallScore, 0) / firstHalf.length;
    const avgSecond = secondHalf.reduce((s, a) => s + a.overallScore, 0) / secondHalf.length;

    if (avgSecond > avgFirst + 0.05) return 'improving';
    if (avgSecond < avgFirst - 0.05) return 'degrading';
    return 'stable';
  }

  /**
   * Generates a signed attestation proof that can be verified externally.
   * @param {string} signingKey - HMAC key for signing
   * @returns {{ attestation: object, signature: string }}
   */
  generateProof(signingKey) {
    const attestation = this.attest();
    const data = JSON.stringify({
      attestationId: attestation.attestationId,
      timestamp: attestation.timestamp,
      compliant: attestation.compliant,
      overallScore: attestation.overallScore
    });
    const signature = crypto.createHmac('sha256', signingKey).update(data).digest('hex');
    return { attestation, signature };
  }

  /**
   * Verifies a signed attestation proof.
   * @param {object} proof - Output of generateProof()
   * @param {string} signingKey
   * @returns {boolean}
   */
  static verifyProof(proof, signingKey) {
    if (!proof || !proof.attestation || !proof.signature) return false;
    const data = JSON.stringify({
      attestationId: proof.attestation.attestationId,
      timestamp: proof.attestation.timestamp,
      compliant: proof.attestation.compliant,
      overallScore: proof.attestation.overallScore
    });
    const expected = crypto.createHmac('sha256', signingKey).update(data).digest('hex');
    try {
      return crypto.timingSafeEqual(
        Buffer.from(proof.signature, 'hex'),
        Buffer.from(expected, 'hex')
      );
    } catch {
      return false;
    }
  }
}

// =========================================================================
// Exports
// =========================================================================

module.exports = {
  LearningLoop,
  AgentContract,
  ContractRegistry,
  ComplianceAttestor,
  ATTESTATION_FRAMEWORKS
};
