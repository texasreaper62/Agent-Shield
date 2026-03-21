'use strict';

/**
 * Agent Shield — Agent Behavior Profiling (v3.0)
 *
 * Establishes baselines for normal agent behavior and detects anomalies
 * that may indicate compromise, drift, or attack influence.
 *
 * Tracks: response patterns, tool usage, topic distribution, timing,
 * output length, sentiment shifts, and more.
 *
 * All processing runs locally — no data ever leaves your environment.
 */

// =========================================================================
// STATISTICAL HELPERS
// =========================================================================

/**
 * Calculate mean of an array.
 * @param {number[]} arr
 * @returns {number}
 */
function mean(arr) {
  return arr.length > 0 ? arr.reduce((a, b) => a + b, 0) / arr.length : 0;
}

/**
 * Calculate standard deviation.
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
 * Check if a value is anomalous (beyond N standard deviations from mean).
 * @param {number} value
 * @param {number} m - Mean.
 * @param {number} sd - Standard deviation.
 * @param {number} [threshold=2] - Number of standard deviations.
 * @returns {boolean}
 */
function isAnomaly(value, m, sd, threshold = 2) {
  if (sd === 0) return value !== m;
  return Math.abs(value - m) > threshold * sd;
}

// =========================================================================
// BEHAVIOR PROFILE
// =========================================================================

/**
 * Maintains a statistical profile of agent behavior.
 */
class BehaviorProfile {
  /**
   * @param {object} [options]
   * @param {number} [options.windowSize=200] - Number of observations to maintain.
   * @param {number} [options.learningPeriod=20] - Observations before anomaly detection activates.
   * @param {number} [options.anomalyThreshold=2.5] - Standard deviations for anomaly detection.
   */
  constructor(options = {}) {
    this.windowSize = options.windowSize || 200;
    this.learningPeriod = options.learningPeriod || 20;
    this.anomalyThreshold = options.anomalyThreshold || 2.5;

    this._metrics = {
      responseLength: [],
      responseTime: [],
      toolCallCount: [],
      threatScore: [],
      topicEntropy: []
    };

    this._toolUsage = {};
    this._topicDistribution = {};
    this._totalObservations = 0;
    this._anomalies = [];

    console.log('[Agent Shield] BehaviorProfile initialized (windowSize: %d, learningPeriod: %d)', this.windowSize, this.learningPeriod);
  }

  /**
   * Record an observation of agent behavior.
   *
   * @param {object} observation
   * @param {number} [observation.responseLength] - Length of agent response.
   * @param {number} [observation.responseTimeMs] - Time taken to respond.
   * @param {string[]} [observation.toolsCalled] - Tools used in this turn.
   * @param {number} [observation.threatScore] - Threat score from scanning.
   * @param {string} [observation.topic] - Detected topic/category.
   * @returns {object} { anomalies: Array, isLearning: boolean }
   */
  record(observation) {
    this._totalObservations++;

    // Record metrics
    if (observation.responseLength !== undefined) {
      this._addMetric('responseLength', observation.responseLength);
    }
    if (observation.responseTimeMs !== undefined) {
      this._addMetric('responseTime', observation.responseTimeMs);
    }
    if (observation.toolsCalled) {
      this._addMetric('toolCallCount', observation.toolsCalled.length);
      for (const tool of observation.toolsCalled) {
        this._toolUsage[tool] = (this._toolUsage[tool] || 0) + 1;
      }
    }
    if (observation.threatScore !== undefined) {
      this._addMetric('threatScore', observation.threatScore);
    }
    if (observation.topic) {
      this._topicDistribution[observation.topic] = (this._topicDistribution[observation.topic] || 0) + 1;
    }

    // Check for anomalies (only after learning period)
    const isLearning = this._totalObservations < this.learningPeriod;
    const anomalies = isLearning ? [] : this._detectAnomalies(observation);

    if (anomalies.length > 0) {
      this._anomalies.push({
        timestamp: Date.now(),
        observation: this._totalObservations,
        anomalies
      });
    }

    return { anomalies, isLearning };
  }

  /**
   * Get the current behavior baseline.
   * @returns {object}
   */
  getBaseline() {
    const baseline = {};
    for (const [metric, values] of Object.entries(this._metrics)) {
      if (values.length > 0) {
        let min = values[0];
        let max = values[0];
        for (let i = 1; i < values.length; i++) {
          if (values[i] < min) min = values[i];
          if (values[i] > max) max = values[i];
        }
        baseline[metric] = {
          mean: Math.round(mean(values) * 100) / 100,
          stdDev: Math.round(stdDev(values) * 100) / 100,
          min,
          max,
          samples: values.length
        };
      }
    }
    return baseline;
  }

  /**
   * Get a full behavior report.
   * @returns {object}
   */
  getReport() {
    return {
      totalObservations: this._totalObservations,
      isLearning: this._totalObservations < this.learningPeriod,
      baseline: this.getBaseline(),
      toolUsage: { ...this._toolUsage },
      topicDistribution: { ...this._topicDistribution },
      anomalyCount: this._anomalies.length,
      recentAnomalies: this._anomalies.slice(-10),
      riskLevel: this._calculateRiskLevel()
    };
  }

  /**
   * Check if the agent appears to be behaving normally.
   * @returns {object} { normal: boolean, riskLevel, concerns: string[] }
   */
  healthCheck() {
    const concerns = [];
    const report = this.getReport();

    if (report.isLearning) {
      return { normal: true, riskLevel: 'unknown', concerns: ['Still in learning period.'] };
    }

    // Check for sudden tool usage changes
    const totalToolCalls = Object.values(this._toolUsage).reduce((a, b) => a + b, 0);
    if (totalToolCalls > 0) {
      for (const [tool, count] of Object.entries(this._toolUsage)) {
        const ratio = count / totalToolCalls;
        if (ratio > 0.7 && totalToolCalls > 10) {
          concerns.push(`Tool "${tool}" dominates usage at ${(ratio * 100).toFixed(0)}%.`);
        }
      }
    }

    // Check for high threat score trend
    const recentThreats = this._metrics.threatScore.slice(-20);
    if (recentThreats.length >= 5 && mean(recentThreats) > 0.5) {
      concerns.push('Recent threat scores are elevated.');
    }

    // Check for anomaly frequency
    const recentAnomalies = this._anomalies.filter(a => Date.now() - a.timestamp < 300000);
    if (recentAnomalies.length > 5) {
      concerns.push(`${recentAnomalies.length} anomalies in the last 5 minutes.`);
    }

    return {
      normal: concerns.length === 0,
      riskLevel: report.riskLevel,
      concerns
    };
  }

  /** Reset the profile. */
  reset() {
    for (const key of Object.keys(this._metrics)) {
      this._metrics[key] = [];
    }
    this._toolUsage = {};
    this._topicDistribution = {};
    this._totalObservations = 0;
    this._anomalies = [];
  }

  /** @private */
  _addMetric(name, value) {
    if (!this._metrics[name]) this._metrics[name] = [];
    this._metrics[name].push(value);
    if (this._metrics[name].length > this.windowSize) {
      this._metrics[name].shift();
    }
  }

  /** @private */
  _detectAnomalies(observation) {
    const anomalies = [];

    const checks = [
      { metric: 'responseLength', value: observation.responseLength, label: 'Response length' },
      { metric: 'responseTime', value: observation.responseTimeMs, label: 'Response time' },
      { metric: 'toolCallCount', value: observation.toolsCalled ? observation.toolsCalled.length : undefined, label: 'Tool call count' },
      { metric: 'threatScore', value: observation.threatScore, label: 'Threat score' }
    ];

    for (const check of checks) {
      if (check.value === undefined) continue;

      const values = this._metrics[check.metric];
      if (values.length < this.learningPeriod) continue;

      const m = mean(values.slice(0, -1)); // Exclude current observation
      const sd = stdDev(values.slice(0, -1));

      if (isAnomaly(check.value, m, sd, this.anomalyThreshold)) {
        const zScore = sd > 0 ? Math.round(((check.value - m) / sd) * 100) / 100 : 0;
        anomalies.push({
          metric: check.metric,
          label: check.label,
          value: check.value,
          expected: { mean: Math.round(m * 100) / 100, stdDev: Math.round(sd * 100) / 100 },
          zScore,
          direction: check.value > m ? 'above' : 'below'
        });
      }
    }

    return anomalies;
  }

  /** @private */
  _calculateRiskLevel() {
    if (this._totalObservations < this.learningPeriod) return 'unknown';

    const recentAnomalies = this._anomalies.filter(a => Date.now() - a.timestamp < 600000);
    if (recentAnomalies.length > 10) return 'critical';
    if (recentAnomalies.length > 5) return 'high';
    if (recentAnomalies.length > 2) return 'medium';
    if (recentAnomalies.length > 0) return 'low';
    return 'normal';
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = { BehaviorProfile, mean, stdDev, isAnomaly };
