'use strict';

/**
 * Agent Shield — Agent Behavioral Fingerprinting (v12.0)
 *
 * Captures an agent's normal behavior profile by tracking tool call frequency,
 * argument patterns, response patterns, and timing profiles. Generates a
 * portable fingerprint hash for comparison and compromise detection.
 *
 * All detection runs locally — no data ever leaves your environment.
 *
 * @module agent-intent
 */

const crypto = require('crypto');

// =========================================================================
// CONSTANTS
// =========================================================================

/** Default deviation threshold for compromise detection (z-score). */
const DEFAULT_DEVIATION_THRESHOLD = 2.5;

/** Minimum observations before fingerprint is considered stable. */
const MIN_OBSERVATIONS = 10;

/** Maximum history entries per metric to prevent unbounded growth. */
const MAX_HISTORY = 10000;

/** Similarity score thresholds. */
const SIMILARITY_THRESHOLDS = {
  identical: 0.95,
  similar: 0.75,
  related: 0.50,
  different: 0.25
};

// =========================================================================
// UTILITY FUNCTIONS
// =========================================================================

/**
 * Compute mean of an array of numbers.
 * @param {number[]} arr
 * @returns {number}
 */
function mean(arr) {
  if (!arr || arr.length === 0) return 0;
  let sum = 0;
  for (let i = 0; i < arr.length; i++) sum += arr[i];
  return sum / arr.length;
}

/**
 * Compute standard deviation of an array of numbers.
 * @param {number[]} arr
 * @returns {number}
 */
function stddev(arr) {
  if (!arr || arr.length < 2) return 0;
  const m = mean(arr);
  let sumSq = 0;
  for (let i = 0; i < arr.length; i++) {
    const d = arr[i] - m;
    sumSq += d * d;
  }
  return Math.sqrt(sumSq / (arr.length - 1));
}

/**
 * Compute cosine similarity between two frequency maps.
 * @param {Map<string, number>} a
 * @param {Map<string, number>} b
 * @returns {number} 0..1
 */
function cosineSimilarity(a, b) {
  if (a.size === 0 && b.size === 0) return 1;
  if (a.size === 0 || b.size === 0) return 0;

  const keys = new Set([...a.keys(), ...b.keys()]);
  let dot = 0;
  let magA = 0;
  let magB = 0;

  for (const k of keys) {
    const va = a.get(k) || 0;
    const vb = b.get(k) || 0;
    dot += va * vb;
    magA += va * va;
    magB += vb * vb;
  }

  const denom = Math.sqrt(magA) * Math.sqrt(magB);
  return denom === 0 ? 0 : dot / denom;
}

/**
 * Jensen-Shannon divergence between two distributions (lower = more similar).
 * @param {Map<string, number>} p
 * @param {Map<string, number>} q
 * @returns {number} 0..1
 */
function jsDivergence(p, q) {
  const keys = new Set([...p.keys(), ...q.keys()]);
  const total = keys.size;
  if (total === 0) return 0;

  // Normalize to probability distributions
  let sumP = 0;
  let sumQ = 0;
  for (const k of keys) {
    sumP += p.get(k) || 0;
    sumQ += q.get(k) || 0;
  }
  if (sumP === 0 && sumQ === 0) return 0;
  if (sumP === 0 || sumQ === 0) return 1;

  let jsd = 0;
  for (const k of keys) {
    const pi = (p.get(k) || 0) / sumP;
    const qi = (q.get(k) || 0) / sumQ;
    const mi = (pi + qi) / 2;
    if (pi > 0 && mi > 0) jsd += 0.5 * pi * Math.log2(pi / mi);
    if (qi > 0 && mi > 0) jsd += 0.5 * qi * Math.log2(qi / mi);
  }

  return Math.min(1, Math.max(0, jsd));
}

// =========================================================================
// AGENT FINGERPRINT
// =========================================================================

/**
 * Agent Behavioral Fingerprint.
 *
 * Captures an agent's normal behavior profile and detects deviations that
 * may indicate compromise.
 *
 * @example
 * const fp = new AgentFingerprint({ agentId: 'my-agent' });
 * fp.recordToolCall('readFile', { path: '/data/config.json' }, 12);
 * fp.recordToolCall('readFile', { path: '/data/users.json' }, 15);
 * fp.recordResponse('text', 150);
 * const hash = fp.generateHash();
 * const result = fp.detectCompromise({ tool: 'execCommand', args: { cmd: 'curl evil.com' }, latencyMs: 500 });
 */
class AgentFingerprint {
  /**
   * @param {object} [options]
   * @param {string} [options.agentId] - Unique agent identifier
   * @param {number} [options.deviationThreshold] - Z-score threshold for anomaly (default 2.5)
   * @param {number} [options.minObservations] - Minimum observations before stable (default 10)
   */
  constructor(options = {}) {
    this.agentId = options.agentId || `agent-${Date.now()}`;
    this.deviationThreshold = options.deviationThreshold || DEFAULT_DEVIATION_THRESHOLD;
    this.minObservations = options.minObservations || MIN_OBSERVATIONS;
    this.createdAt = Date.now();

    /** @type {Map<string, number>} Tool call frequency counts. */
    this.toolFrequency = new Map();

    /** @type {Map<string, Set<string>>} Argument key patterns per tool. */
    this.argumentPatterns = new Map();

    /** @type {Map<string, number[]>} Latency observations per tool. */
    this.timingProfiles = new Map();

    /** @type {Map<string, number>} Response type frequency counts. */
    this.responsePatterns = new Map();

    /** @type {number[]} Inter-call intervals in ms. */
    this.callIntervals = [];

    /** @type {number} Total observations recorded. */
    this.totalObservations = 0;

    /** @type {number|null} Timestamp of last recorded event. */
    this._lastCallTime = null;

    console.log(`[Agent Shield] AgentFingerprint created for ${this.agentId}`);
  }

  /**
   * Record a tool call observation.
   * @param {string} toolName - Name of the tool invoked
   * @param {object} [args] - Arguments passed to the tool
   * @param {number} [latencyMs] - Call latency in milliseconds
   */
  recordToolCall(toolName, args = {}, latencyMs = 0) {
    if (!toolName || typeof toolName !== 'string') return;

    // Track frequency
    this.toolFrequency.set(toolName, (this.toolFrequency.get(toolName) || 0) + 1);

    // Track argument key patterns
    if (!this.argumentPatterns.has(toolName)) {
      this.argumentPatterns.set(toolName, new Set());
    }
    const argKeys = Object.keys(args || {}).sort().join(',');
    if (argKeys) {
      this.argumentPatterns.get(toolName).add(argKeys);
    }

    // Track timing
    if (!this.timingProfiles.has(toolName)) {
      this.timingProfiles.set(toolName, []);
    }
    const timings = this.timingProfiles.get(toolName);
    if (timings.length < MAX_HISTORY) {
      timings.push(latencyMs);
    }

    // Track call intervals
    const now = Date.now();
    if (this._lastCallTime !== null) {
      const interval = now - this._lastCallTime;
      if (this.callIntervals.length < MAX_HISTORY) {
        this.callIntervals.push(interval);
      }
    }
    this._lastCallTime = now;

    this.totalObservations++;
  }

  /**
   * Record a response observation.
   * @param {string} responseType - Type of response (e.g. 'text', 'json', 'error')
   * @param {number} [length] - Response length in characters
   */
  recordResponse(responseType, length = 0) {
    if (!responseType || typeof responseType !== 'string') return;
    this.responsePatterns.set(responseType, (this.responsePatterns.get(responseType) || 0) + 1);
    this.totalObservations++;
  }

  /**
   * Check if the fingerprint has enough data to be considered stable.
   * @returns {boolean}
   */
  isStable() {
    return this.totalObservations >= this.minObservations;
  }

  /**
   * Generate a portable hash that uniquely identifies this agent's behavior.
   * @returns {string} SHA-256 hex hash
   */
  generateHash() {
    const profile = {
      agentId: this.agentId,
      toolFrequency: Object.fromEntries(this.toolFrequency),
      argumentPatterns: {},
      timingStats: {},
      responsePatterns: Object.fromEntries(this.responsePatterns),
      totalObservations: this.totalObservations
    };

    // Serialize argument patterns
    for (const [tool, patterns] of this.argumentPatterns) {
      profile.argumentPatterns[tool] = [...patterns].sort();
    }

    // Serialize timing statistics (mean + stddev, not raw data)
    for (const [tool, timings] of this.timingProfiles) {
      profile.timingStats[tool] = {
        mean: Math.round(mean(timings) * 100) / 100,
        stddev: Math.round(stddev(timings) * 100) / 100,
        count: timings.length
      };
    }

    const serialized = JSON.stringify(profile, Object.keys(profile).sort());
    return crypto.createHash('sha256').update(serialized).digest('hex');
  }

  /**
   * Compare this fingerprint with another and return a similarity score.
   * @param {AgentFingerprint} other - Another fingerprint to compare against
   * @returns {{ score: number, label: string, details: object }}
   */
  compare(other) {
    if (!(other instanceof AgentFingerprint)) {
      return { score: 0, label: 'invalid', details: { error: 'Not an AgentFingerprint instance' } };
    }

    const details = {};

    // 1. Tool frequency similarity (cosine)
    details.toolFrequency = cosineSimilarity(this.toolFrequency, other.toolFrequency);

    // 2. Argument pattern overlap (Jaccard)
    let argOverlap = 0;
    let argTotal = 0;
    const allTools = new Set([...this.argumentPatterns.keys(), ...other.argumentPatterns.keys()]);
    for (const tool of allTools) {
      const a = this.argumentPatterns.get(tool) || new Set();
      const b = other.argumentPatterns.get(tool) || new Set();
      const union = new Set([...a, ...b]);
      const intersection = [...a].filter(x => b.has(x));
      if (union.size > 0) {
        argOverlap += intersection.length / union.size;
        argTotal++;
      }
    }
    details.argumentPatterns = argTotal > 0 ? argOverlap / argTotal : (allTools.size === 0 ? 1 : 0);

    // 3. Response pattern similarity (cosine)
    details.responsePatterns = cosineSimilarity(this.responsePatterns, other.responsePatterns);

    // 4. Timing profile similarity (1 - JS divergence of mean latencies)
    const timingA = new Map();
    const timingB = new Map();
    for (const [tool, timings] of this.timingProfiles) {
      timingA.set(tool, mean(timings));
    }
    for (const [tool, timings] of other.timingProfiles) {
      timingB.set(tool, mean(timings));
    }
    details.timingProfile = 1 - jsDivergence(timingA, timingB);

    // Weighted aggregate
    const weights = { toolFrequency: 0.35, argumentPatterns: 0.25, responsePatterns: 0.20, timingProfile: 0.20 };
    let score = 0;
    for (const [key, weight] of Object.entries(weights)) {
      score += (details[key] || 0) * weight;
    }
    score = Math.round(score * 1000) / 1000;

    let label = 'different';
    if (score >= SIMILARITY_THRESHOLDS.identical) label = 'identical';
    else if (score >= SIMILARITY_THRESHOLDS.similar) label = 'similar';
    else if (score >= SIMILARITY_THRESHOLDS.related) label = 'related';

    return { score, label, details };
  }

  /**
   * Check if current behavior deviates from the fingerprint (possible compromise).
   * @param {object} observation - Current observed behavior
   * @param {string} [observation.tool] - Tool being called
   * @param {object} [observation.args] - Arguments to the tool
   * @param {number} [observation.latencyMs] - Observed latency in ms
   * @returns {{ compromised: boolean, score: number, reasons: string[] }}
   */
  detectCompromise(observation = {}) {
    const reasons = [];
    let anomalyScore = 0;

    if (!this.isStable()) {
      return {
        compromised: false,
        score: 0,
        reasons: ['Fingerprint not yet stable (insufficient observations)']
      };
    }

    const { tool, args, latencyMs } = observation;

    // 1. Unknown tool check
    if (tool && !this.toolFrequency.has(tool)) {
      reasons.push(`Unknown tool "${tool}" not in behavioral profile`);
      anomalyScore += 3;
    }

    // 2. Tool frequency deviation
    if (tool && this.toolFrequency.has(tool)) {
      const totalCalls = [...this.toolFrequency.values()].reduce((a, b) => a + b, 0);
      const expectedFreq = this.toolFrequency.get(tool) / totalCalls;
      // If this tool is very rarely used (<5% of calls), calling it is mildly suspicious
      if (expectedFreq < 0.05) {
        reasons.push(`Tool "${tool}" is rarely used (${(expectedFreq * 100).toFixed(1)}% of calls)`);
        anomalyScore += 1;
      }
    }

    // 3. Argument pattern deviation
    if (tool && args && this.argumentPatterns.has(tool)) {
      const knownPatterns = this.argumentPatterns.get(tool);
      const currentPattern = Object.keys(args || {}).sort().join(',');
      if (currentPattern && !knownPatterns.has(currentPattern)) {
        reasons.push(`Unusual argument pattern for "${tool}": "${currentPattern}"`);
        anomalyScore += 2;
      }
    }

    // 4. Timing anomaly (z-score)
    if (tool && typeof latencyMs === 'number' && this.timingProfiles.has(tool)) {
      const timings = this.timingProfiles.get(tool);
      const m = mean(timings);
      const sd = stddev(timings);
      if (sd > 0) {
        const zScore = Math.abs(latencyMs - m) / sd;
        if (zScore > this.deviationThreshold) {
          reasons.push(`Timing anomaly for "${tool}": z-score ${zScore.toFixed(2)} (latency ${latencyMs}ms vs mean ${m.toFixed(0)}ms)`);
          anomalyScore += zScore > 4 ? 3 : 1;
        }
      }
    }

    // 5. Check for suspicious argument values
    if (args) {
      const argStr = JSON.stringify(args).toLowerCase();
      const suspiciousPatterns = [
        /curl\s+/,
        /wget\s+/,
        /eval\s*\(/,
        /base64/,
        /\/etc\/passwd/,
        /\.\.\//,
        /exfiltrat/
      ];
      for (const pattern of suspiciousPatterns) {
        if (pattern.test(argStr)) {
          reasons.push(`Suspicious argument content detected: ${pattern.source}`);
          anomalyScore += 2;
        }
      }
    }

    const compromised = anomalyScore >= this.deviationThreshold;

    return {
      compromised,
      score: Math.round(anomalyScore * 100) / 100,
      reasons
    };
  }

  /**
   * Export fingerprint as a portable JSON object.
   * @returns {object}
   */
  toJSON() {
    const obj = {
      agentId: this.agentId,
      createdAt: this.createdAt,
      totalObservations: this.totalObservations,
      stable: this.isStable(),
      hash: this.generateHash(),
      toolFrequency: Object.fromEntries(this.toolFrequency),
      argumentPatterns: {},
      timingStats: {},
      responsePatterns: Object.fromEntries(this.responsePatterns)
    };

    for (const [tool, patterns] of this.argumentPatterns) {
      obj.argumentPatterns[tool] = [...patterns];
    }
    for (const [tool, timings] of this.timingProfiles) {
      obj.timingStats[tool] = { mean: mean(timings), stddev: stddev(timings), count: timings.length };
    }

    return obj;
  }

  /**
   * Restore fingerprint from a previously exported JSON object.
   * @param {object} data - Output from toJSON()
   * @returns {AgentFingerprint}
   */
  static fromJSON(data) {
    const fp = new AgentFingerprint({ agentId: data.agentId });
    fp.createdAt = data.createdAt || Date.now();
    fp.totalObservations = data.totalObservations || 0;

    if (data.toolFrequency) {
      fp.toolFrequency = new Map(Object.entries(data.toolFrequency));
    }
    if (data.argumentPatterns) {
      for (const [tool, patterns] of Object.entries(data.argumentPatterns)) {
        fp.argumentPatterns.set(tool, new Set(patterns));
      }
    }
    if (data.responsePatterns) {
      fp.responsePatterns = new Map(Object.entries(data.responsePatterns));
    }

    return fp;
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
  AgentFingerprint,
  SIMILARITY_THRESHOLDS,
  DEFAULT_DEVIATION_THRESHOLD,
  MIN_OBSERVATIONS
};
