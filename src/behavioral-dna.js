'use strict';

/**
 * Agent Shield -- Agent Behavioral DNA (v7.5)
 *
 * Creates a comprehensive fingerprint of what "normal" looks like for a
 * specific agent deployment, then detects compromise by comparing current
 * behavior against the learned baseline.
 *
 * Goes beyond z-score anomaly detection (behavior-profiling.js) by tracking
 * multi-dimensional feature vectors, categorical distributions, cross-feature
 * correlations, and producing a portable DNA fingerprint.
 *
 * All processing runs locally -- no data ever leaves your environment.
 */

// =========================================================================
// STATISTICAL HELPERS
// =========================================================================

/**
 * Calculate mean of a numeric array.
 * @param {number[]} arr
 * @returns {number}
 */
function mean(arr) {
  return arr.length > 0 ? arr.reduce((a, b) => a + b, 0) / arr.length : 0;
}

/**
 * Calculate sample standard deviation.
 * @param {number[]} arr
 * @returns {number}
 */
function stdDev(arr) {
  if (arr.length < 2) return 0;
  const m = mean(arr);
  const squaredDiffs = arr.map(x => (x - m) ** 2);
  return Math.sqrt(squaredDiffs.reduce((a, b) => a + b, 0) / (arr.length - 1));
}

/**
 * Calculate the z-score for a value given mean and standard deviation.
 * @param {number} value
 * @param {number} m
 * @param {number} sd
 * @returns {number}
 */
function zScore(value, m, sd) {
  if (sd === 0) return value === m ? 0 : Infinity;
  return (value - m) / sd;
}

/**
 * Calculate Pearson correlation between two arrays.
 * @param {number[]} xs
 * @param {number[]} ys
 * @returns {number}
 */
function pearsonCorrelation(xs, ys) {
  const n = Math.min(xs.length, ys.length);
  if (n < 3) return 0;
  const mx = mean(xs.slice(0, n));
  const my = mean(ys.slice(0, n));
  let num = 0;
  let dx2 = 0;
  let dy2 = 0;
  for (let i = 0; i < n; i++) {
    const dx = xs[i] - mx;
    const dy = ys[i] - my;
    num += dx * dy;
    dx2 += dx * dx;
    dy2 += dy * dy;
  }
  const denom = Math.sqrt(dx2 * dy2);
  return denom === 0 ? 0 : num / denom;
}

/**
 * Shannon entropy of a frequency distribution (object with counts).
 * @param {Object<string, number>} dist
 * @returns {number}
 */
function shannonEntropy(dist) {
  const total = Object.values(dist).reduce((a, b) => a + b, 0);
  if (total === 0) return 0;
  let h = 0;
  for (const count of Object.values(dist)) {
    if (count === 0) continue;
    const p = count / total;
    h -= p * Math.log2(p);
  }
  return h;
}

// =========================================================================
// DEFAULT FEATURES
// =========================================================================

/**
 * Default numeric features tracked by BehavioralDNA.
 * @type {string[]}
 */
const DEFAULT_NUMERIC_FEATURES = [
  'responseLength',
  'responseTimeMs',
  'toolCount',
  'threatScore',
  'sentimentScore'
];

/**
 * Default categorical features tracked by BehavioralDNA.
 * @type {string[]}
 */
const DEFAULT_CATEGORICAL_FEATURES = [
  'topicCategory',
  'languageUsed'
];

// =========================================================================
// BEHAVIORAL DNA
// =========================================================================

/**
 * Comprehensive behavioral fingerprint for an agent deployment.
 * Learns what "normal" looks like, then detects deviations.
 */
class BehavioralDNA {
  /**
   * @param {object} [options]
   * @param {number} [options.learningPeriod=50] - Observations before detection activates.
   * @param {number} [options.anomalyThreshold=2.5] - Std deviations for anomaly detection.
   * @param {string[]} [options.features] - Numeric features to track.
   * @param {string[]} [options.categoricalFeatures] - Categorical features to track.
   * @param {number} [options.windowSize=500] - Max observations to retain per feature.
   * @param {boolean} [options.trackCorrelations=true] - Track cross-feature correlations.
   */
  constructor(options = {}) {
    this.learningPeriod = options.learningPeriod || 50;
    this.anomalyThreshold = options.anomalyThreshold || 2.5;
    this.windowSize = options.windowSize || 500;
    this.trackCorrelations = options.trackCorrelations !== false;

    this._numericFeatures = options.features || DEFAULT_NUMERIC_FEATURES.slice();
    this._categoricalFeatures = options.categoricalFeatures || DEFAULT_CATEGORICAL_FEATURES.slice();

    this._numericData = {};
    for (const f of this._numericFeatures) {
      this._numericData[f] = [];
    }

    this._categoricalData = {};
    for (const f of this._categoricalFeatures) {
      this._categoricalData[f] = {};
    }

    this._toolDistribution = {};
    this._observationCount = 0;
    this._createdAt = Date.now();
    this._lastObservation = null;

    console.log('[Agent Shield] BehavioralDNA initialized (learningPeriod: %d, threshold: %s)',
      this.learningPeriod, this.anomalyThreshold);
  }

  /**
   * Record an observation of agent behavior.
   * @param {object} observation
   * @param {string[]} [observation.toolsCalled] - Tools used in this interaction.
   * @param {number} [observation.responseLength] - Length of agent response.
   * @param {number} [observation.responseTimeMs] - Time taken to respond in ms.
   * @param {number} [observation.threatScore] - Threat score from scanning (0-1).
   * @param {string} [observation.topicCategory] - Detected topic category.
   * @param {number} [observation.sentimentScore] - Sentiment score (-1 to 1).
   * @param {string} [observation.languageUsed] - Language of response.
   */
  observe(observation) {
    if (!observation || typeof observation !== 'object') return;

    this._observationCount++;
    this._lastObservation = Date.now();

    // Record numeric features
    for (const f of this._numericFeatures) {
      if (f === 'toolCount' && observation.toolsCalled !== undefined) {
        this._pushNumeric(f, Array.isArray(observation.toolsCalled) ? observation.toolsCalled.length : 0);
      } else if (observation[f] !== undefined && typeof observation[f] === 'number') {
        this._pushNumeric(f, observation[f]);
      }
    }

    // Record categorical features
    for (const f of this._categoricalFeatures) {
      if (observation[f] !== undefined && observation[f] !== null) {
        const val = String(observation[f]);
        if (!this._categoricalData[f]) this._categoricalData[f] = {};
        this._categoricalData[f][val] = (this._categoricalData[f][val] || 0) + 1;
      }
    }

    // Record tool distribution
    if (Array.isArray(observation.toolsCalled)) {
      for (const tool of observation.toolsCalled) {
        this._toolDistribution[tool] = (this._toolDistribution[tool] || 0) + 1;
      }
    }
  }

  /**
   * Returns true if still in the learning period.
   * @returns {boolean}
   */
  isLearning() {
    return this._observationCount < this.learningPeriod;
  }

  /**
   * Returns the learned baseline statistics.
   * @returns {object} Baseline with mean, stdDev, min, max, samples for each numeric feature,
   *                    plus categorical distributions and tool usage.
   */
  getBaseline() {
    const numeric = {};
    for (const f of this._numericFeatures) {
      const values = this._numericData[f] || [];
      if (values.length > 0) {
        numeric[f] = {
          mean: _round(mean(values)),
          stdDev: _round(stdDev(values)),
          min: Math.min(...values),
          max: Math.max(...values),
          samples: values.length
        };
      }
    }

    const categorical = {};
    for (const f of this._categoricalFeatures) {
      const dist = this._categoricalData[f] || {};
      const total = Object.values(dist).reduce((a, b) => a + b, 0);
      if (total > 0) {
        const normalized = {};
        for (const [key, count] of Object.entries(dist)) {
          normalized[key] = _round(count / total);
        }
        categorical[f] = {
          distribution: normalized,
          entropy: _round(shannonEntropy(dist)),
          totalSamples: total
        };
      }
    }

    const toolTotal = Object.values(this._toolDistribution).reduce((a, b) => a + b, 0);
    const toolNormalized = {};
    if (toolTotal > 0) {
      for (const [tool, count] of Object.entries(this._toolDistribution)) {
        toolNormalized[tool] = _round(count / toolTotal);
      }
    }

    const correlations = {};
    if (this.trackCorrelations) {
      const featureNames = this._numericFeatures.filter(f => (this._numericData[f] || []).length >= 3);
      for (let i = 0; i < featureNames.length; i++) {
        for (let j = i + 1; j < featureNames.length; j++) {
          const key = featureNames[i] + ':' + featureNames[j];
          correlations[key] = _round(
            pearsonCorrelation(this._numericData[featureNames[i]], this._numericData[featureNames[j]])
          );
        }
      }
    }

    return {
      numeric,
      categorical,
      toolDistribution: toolNormalized,
      correlations,
      observationCount: this._observationCount,
      isLearning: this.isLearning()
    };
  }

  /**
   * Compare an observation against the learned baseline.
   * Only works after the learning period is complete.
   * @param {object} observation - Same shape as observe().
   * @returns {object} { anomaly, score, deviations, explanation }
   */
  detect(observation) {
    if (this.isLearning()) {
      return {
        anomaly: false,
        score: 0,
        deviations: [],
        explanation: 'Still in learning period (' + this._observationCount + '/' + this.learningPeriod + ' observations).'
      };
    }

    const deviations = [];

    // Check numeric features
    for (const f of this._numericFeatures) {
      let value;
      if (f === 'toolCount' && observation.toolsCalled !== undefined) {
        value = Array.isArray(observation.toolsCalled) ? observation.toolsCalled.length : 0;
      } else {
        value = observation[f];
      }
      if (value === undefined || typeof value !== 'number') continue;

      const values = this._numericData[f] || [];
      if (values.length < 2) continue;

      const m = mean(values);
      const sd = stdDev(values);
      const z = zScore(value, m, sd);

      if (Math.abs(z) > this.anomalyThreshold) {
        deviations.push({
          feature: f,
          type: 'numeric',
          value,
          expected: { mean: _round(m), stdDev: _round(sd) },
          zScore: _round(z),
          direction: z > 0 ? 'above' : 'below',
          severity: _deviationSeverity(Math.abs(z), this.anomalyThreshold)
        });
      }
    }

    // Check categorical features for novel or rare values
    for (const f of this._categoricalFeatures) {
      if (observation[f] === undefined || observation[f] === null) continue;
      const val = String(observation[f]);
      const dist = this._categoricalData[f] || {};
      const total = Object.values(dist).reduce((a, b) => a + b, 0);

      if (total === 0) continue;

      const count = dist[val] || 0;
      const freq = count / total;

      if (count === 0) {
        // Completely new category value never seen during learning
        deviations.push({
          feature: f,
          type: 'categorical',
          value: val,
          expected: Object.keys(dist),
          frequency: 0,
          severity: 'high',
          reason: 'Never-before-seen value'
        });
      } else if (freq < 0.01 && total > 20) {
        // Extremely rare value
        deviations.push({
          feature: f,
          type: 'categorical',
          value: val,
          frequency: _round(freq),
          severity: 'medium',
          reason: 'Extremely rare value (seen in <1% of observations)'
        });
      }
    }

    // Check tool usage for novel tools
    if (Array.isArray(observation.toolsCalled)) {
      const totalTools = Object.values(this._toolDistribution).reduce((a, b) => a + b, 0);
      for (const tool of observation.toolsCalled) {
        if (totalTools > 0 && !this._toolDistribution[tool]) {
          deviations.push({
            feature: 'toolsCalled',
            type: 'tool',
            value: tool,
            severity: 'high',
            reason: 'Tool never seen in baseline'
          });
        }
      }
    }

    // Compute composite anomaly score (0 to 1)
    const score = _compositeScore(deviations, this.anomalyThreshold);

    // Build explanation
    let explanation = '';
    if (deviations.length === 0) {
      explanation = 'Observation is within normal behavioral parameters.';
    } else {
      const parts = deviations.map(d => {
        if (d.type === 'numeric') {
          return d.feature + ' is ' + d.direction + ' normal (z=' + d.zScore + ')';
        }
        if (d.type === 'categorical') {
          return d.feature + '="' + d.value + '" - ' + d.reason;
        }
        return d.feature + '="' + d.value + '" - ' + d.reason;
      });
      explanation = 'Anomalous behavior detected: ' + parts.join('; ') + '.';
    }

    return {
      anomaly: deviations.length > 0,
      score: _round(score),
      deviations,
      explanation
    };
  }

  /**
   * Return the full behavioral DNA fingerprint as a portable JSON-safe object.
   * Can be saved and loaded later with loadFingerprint().
   * @returns {object}
   */
  getFingerprint() {
    return {
      version: 1,
      createdAt: this._createdAt,
      lastObservation: this._lastObservation,
      observationCount: this._observationCount,
      config: {
        learningPeriod: this.learningPeriod,
        anomalyThreshold: this.anomalyThreshold,
        windowSize: this.windowSize,
        trackCorrelations: this.trackCorrelations,
        numericFeatures: this._numericFeatures.slice(),
        categoricalFeatures: this._categoricalFeatures.slice()
      },
      numericData: _deepCopyNumeric(this._numericData),
      categoricalData: _deepCopyCategorical(this._categoricalData),
      toolDistribution: { ...this._toolDistribution },
      baseline: this.getBaseline()
    };
  }

  /**
   * Load a previously saved fingerprint, restoring full state.
   * @param {object} data - Fingerprint object from getFingerprint().
   */
  loadFingerprint(data) {
    if (!data || typeof data !== 'object') {
      throw new Error('[Agent Shield] Invalid fingerprint data');
    }
    if (data.version !== 1) {
      throw new Error('[Agent Shield] Unsupported fingerprint version: ' + data.version);
    }

    this._createdAt = data.createdAt || Date.now();
    this._lastObservation = data.lastObservation || null;
    this._observationCount = data.observationCount || 0;

    if (data.config) {
      this.learningPeriod = data.config.learningPeriod || this.learningPeriod;
      this.anomalyThreshold = data.config.anomalyThreshold || this.anomalyThreshold;
      this.windowSize = data.config.windowSize || this.windowSize;
      this.trackCorrelations = data.config.trackCorrelations !== false;
      this._numericFeatures = data.config.numericFeatures || this._numericFeatures;
      this._categoricalFeatures = data.config.categoricalFeatures || this._categoricalFeatures;
    }

    this._numericData = {};
    for (const f of this._numericFeatures) {
      this._numericData[f] = (data.numericData && Array.isArray(data.numericData[f]))
        ? data.numericData[f].slice()
        : [];
    }

    this._categoricalData = {};
    for (const f of this._categoricalFeatures) {
      this._categoricalData[f] = (data.categoricalData && data.categoricalData[f])
        ? { ...data.categoricalData[f] }
        : {};
    }

    this._toolDistribution = data.toolDistribution ? { ...data.toolDistribution } : {};

    console.log('[Agent Shield] BehavioralDNA fingerprint loaded (%d observations)',
      this._observationCount);
  }

  /**
   * Clear all learned data and reset to initial state.
   */
  reset() {
    for (const f of this._numericFeatures) {
      this._numericData[f] = [];
    }
    for (const f of this._categoricalFeatures) {
      this._categoricalData[f] = {};
    }
    this._toolDistribution = {};
    this._observationCount = 0;
    this._createdAt = Date.now();
    this._lastObservation = null;
  }

  /** @private */
  _pushNumeric(feature, value) {
    if (!this._numericData[feature]) this._numericData[feature] = [];
    this._numericData[feature].push(value);
    if (this._numericData[feature].length > this.windowSize) {
      this._numericData[feature].shift();
    }
  }
}

// =========================================================================
// AGENT PROFILER
// =========================================================================

/**
 * Manages BehavioralDNA profiles for multiple agents.
 */
class AgentProfiler {
  /**
   * @param {object} [defaultOptions] - Default BehavioralDNA options for new profiles.
   */
  constructor(defaultOptions = {}) {
    this._defaultOptions = defaultOptions;
    this._profiles = new Map();
  }

  /**
   * Create a new BehavioralDNA profile for an agent.
   * @param {string} agentId - Unique identifier for the agent.
   * @param {object} [options] - Override default options for this agent.
   * @returns {BehavioralDNA}
   */
  createProfile(agentId, options = {}) {
    const merged = { ...this._defaultOptions, ...options };
    const dna = new BehavioralDNA(merged);
    this._profiles.set(agentId, dna);
    console.log('[Agent Shield] AgentProfiler: created profile for "%s"', agentId);
    return dna;
  }

  /**
   * Get an existing profile for an agent.
   * @param {string} agentId
   * @returns {BehavioralDNA|null}
   */
  getProfile(agentId) {
    return this._profiles.get(agentId) || null;
  }

  /**
   * Check an observation against an agent's DNA.
   * If the agent has no profile yet, one is created automatically.
   * The observation is also recorded (observe) after detection.
   * @param {object} observation - Observation object.
   * @param {string} agentId - Agent identifier.
   * @returns {object} Detection result from BehavioralDNA.detect().
   */
  checkAll(observation, agentId) {
    let dna = this._profiles.get(agentId);
    if (!dna) {
      dna = this.createProfile(agentId);
    }
    const result = dna.detect(observation);
    dna.observe(observation);
    return result;
  }

  /**
   * Get a summary report of all profiled agents.
   * @returns {object} { agents: Array, totalAgents, learningCount, anomalousCount }
   */
  getReport() {
    const agents = [];
    let learningCount = 0;
    let anomalousCount = 0;

    for (const [agentId, dna] of this._profiles) {
      const baseline = dna.getBaseline();
      const isLearning = dna.isLearning();
      if (isLearning) learningCount++;

      agents.push({
        agentId,
        observationCount: baseline.observationCount,
        isLearning,
        numericFeatures: Object.keys(baseline.numeric),
        categoricalFeatures: Object.keys(baseline.categorical),
        toolCount: Object.keys(baseline.toolDistribution).length
      });
    }

    return {
      agents,
      totalAgents: this._profiles.size,
      learningCount,
      anomalousCount
    };
  }
}

// =========================================================================
// FEATURE EXTRACTORS
// =========================================================================

/**
 * Convert a scan result and metadata into a BehavioralDNA observation.
 * @param {object} scanResult - Result from AgentShield.scan() or scanText().
 * @param {object} [metadata] - Additional context about the interaction.
 * @param {string[]} [metadata.toolsCalled] - Tools used in this interaction.
 * @param {number} [metadata.responseTimeMs] - Response time in ms.
 * @param {string} [metadata.topicCategory] - Topic category.
 * @param {number} [metadata.sentimentScore] - Sentiment score (-1 to 1).
 * @param {string} [metadata.languageUsed] - Language of the response.
 * @param {string} [metadata.responseText] - Full response text (used for length).
 * @returns {object} Observation suitable for BehavioralDNA.observe() or .detect().
 */
function extractFeatures(scanResult, metadata = {}) {
  const observation = {};

  // Extract from scan result
  if (scanResult) {
    if (typeof scanResult === 'object') {
      // Threat score: use overall score if present, otherwise derive from threats
      if (typeof scanResult.score === 'number') {
        observation.threatScore = scanResult.score;
      } else if (typeof scanResult.threatScore === 'number') {
        observation.threatScore = scanResult.threatScore;
      } else if (Array.isArray(scanResult.threats) && scanResult.threats.length > 0) {
        // Derive a score from number of threats (normalized to 0-1)
        observation.threatScore = Math.min(scanResult.threats.length / 10, 1);
      } else {
        observation.threatScore = 0;
      }
    }
  }

  // Extract from metadata
  if (Array.isArray(metadata.toolsCalled)) {
    observation.toolsCalled = metadata.toolsCalled;
  }

  if (typeof metadata.responseTimeMs === 'number') {
    observation.responseTimeMs = metadata.responseTimeMs;
  }

  if (typeof metadata.topicCategory === 'string') {
    observation.topicCategory = metadata.topicCategory;
  }

  if (typeof metadata.sentimentScore === 'number') {
    observation.sentimentScore = metadata.sentimentScore;
  }

  if (typeof metadata.languageUsed === 'string') {
    observation.languageUsed = metadata.languageUsed;
  }

  // Response length from metadata
  if (typeof metadata.responseText === 'string') {
    observation.responseLength = metadata.responseText.length;
  } else if (typeof metadata.responseLength === 'number') {
    observation.responseLength = metadata.responseLength;
  }

  return observation;
}

// =========================================================================
// PRIVATE HELPERS
// =========================================================================

/**
 * Round a number to 4 decimal places.
 * @param {number} n
 * @returns {number}
 */
function _round(n) {
  return Math.round(n * 10000) / 10000;
}

/**
 * Determine severity based on how far a z-score exceeds the threshold.
 * @param {number} absZ
 * @param {number} threshold
 * @returns {string}
 */
function _deviationSeverity(absZ, threshold) {
  if (absZ > threshold * 3) return 'critical';
  if (absZ > threshold * 2) return 'high';
  if (absZ > threshold * 1.5) return 'medium';
  return 'low';
}

/**
 * Compute a composite anomaly score (0 to 1) from deviations.
 * @param {object[]} deviations
 * @param {number} threshold
 * @returns {number}
 */
function _compositeScore(deviations, threshold) {
  if (deviations.length === 0) return 0;

  const severityWeights = { critical: 1.0, high: 0.7, medium: 0.4, low: 0.2 };
  let totalWeight = 0;

  for (const d of deviations) {
    const w = severityWeights[d.severity] || 0.3;
    totalWeight += w;
  }

  // Normalize: cap at 1.0
  return Math.min(totalWeight / 3, 1);
}

/**
 * Deep copy numeric data object.
 * @param {Object<string, number[]>} data
 * @returns {Object<string, number[]>}
 */
function _deepCopyNumeric(data) {
  const copy = {};
  for (const [key, arr] of Object.entries(data)) {
    copy[key] = arr.slice();
  }
  return copy;
}

/**
 * Deep copy categorical data object.
 * @param {Object<string, Object<string, number>>} data
 * @returns {Object<string, Object<string, number>>}
 */
function _deepCopyCategorical(data) {
  const copy = {};
  for (const [key, dist] of Object.entries(data)) {
    copy[key] = { ...dist };
  }
  return copy;
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
  BehavioralDNA,
  AgentProfiler,
  extractFeatures,
  DEFAULT_NUMERIC_FEATURES,
  DEFAULT_CATEGORICAL_FEATURES,
  // Expose helpers for testing
  mean,
  stdDev,
  zScore,
  pearsonCorrelation,
  shannonEntropy
};
