'use strict';

/**
 * Agent Shield — Agent Behavioral Drift Monitor
 *
 * IDS (Intrusion Detection System) for AI agents. Builds behavioral
 * baselines over a configurable window, then detects drift via z-score
 * anomaly detection, KL divergence, and sliding window analysis.
 *
 * Alert actions: JSON logs, webhook notifications, auto-tighten contracts,
 * optional circuit breaker integration.
 *
 * Supports Prometheus and OpenTelemetry metric export.
 *
 * All detection runs locally — no data ever leaves your environment.
 *
 * @module drift-monitor
 */

const { CircuitBreaker } = require('./circuit-breaker');

// =========================================================================
// STATISTICAL HELPERS
// =========================================================================

/**
 * Calculate mean of a numeric array.
 * @param {number[]} values
 * @returns {number}
 */
function mean(values) {
  return values.length ? values.reduce((a, b) => a + b, 0) / values.length : 0;
}

/**
 * Calculate sample standard deviation.
 * @param {number[]} values
 * @returns {number}
 */
function std(values) {
  if (values.length < 2) return 0;
  const m = mean(values);
  return Math.sqrt(values.reduce((acc, v) => acc + ((v - m) ** 2), 0) / (values.length - 1));
}

/**
 * Calculate z-score for a value given mean and std deviation.
 * @param {number} value
 * @param {number} m
 * @param {number} s
 * @returns {number}
 */
function zScore(value, m, s) {
  if (s === 0) return value === m ? 0 : Infinity;
  return (value - m) / s;
}

/**
 * Calculate KL divergence between two distributions (object with proportions).
 * @param {object} p - Source distribution.
 * @param {object} q - Reference distribution.
 * @returns {number}
 */
function klDivergence(p, q) {
  const eps = 1e-9;
  let sum = 0;
  const keys = new Set([...Object.keys(p), ...Object.keys(q)]);
  for (const key of keys) {
    const pk = (p[key] || 0) + eps;
    const qk = (q[key] || 0) + eps;
    sum += pk * Math.log(pk / qk);
  }
  return sum;
}

// =========================================================================
// DriftMonitor
// =========================================================================

/**
 * Behavioral drift monitor for AI agents.
 * Builds baselines and detects anomalous behavioral shifts.
 */
class DriftMonitor {
  /**
   * @param {object} [options]
   * @param {number} [options.windowSize=50] - Number of observations for baseline.
   * @param {number} [options.alertThreshold=2.5] - Z-score threshold for alerts.
   * @param {number} [options.klThreshold=0.8] - KL divergence threshold for topic drift.
   * @param {boolean} [options.enableCircuitBreaker=false] - Enable circuit breaker on alerts.
   * @param {object} [options.circuitBreaker] - Circuit breaker options.
   * @param {object} [options.prometheus] - Prometheus exporter instance (setGauge method).
   * @param {object} [options.metrics] - OTel metrics instance (recordMetric method).
   * @param {Function} [options.onAlert] - Webhook/callback for alerts.
   */
  constructor(options = {}) {
    this.windowSize = options.windowSize || 50;
    this.alertThreshold = options.alertThreshold || 2.5;
    this.klThreshold = options.klThreshold || 0.8;
    this.current = [];
    this.baseline = null;
    this.prometheus = options.prometheus || null;
    this.metrics = options.metrics || null;
    this.onAlert = options.onAlert || null;
    this.circuitBreaker = options.enableCircuitBreaker
      ? new CircuitBreaker(options.circuitBreaker || {})
      : null;
    this.alertHistory = [];
  }

  /**
   * Record an observation event. During the learning phase, builds the
   * baseline. After baseline is ready, detects drift.
   *
   * @param {object} event
   * @param {number} [event.callFreq] - Tool call frequency.
   * @param {number} [event.responseLength] - Response length in chars/tokens.
   * @param {number} [event.errorRate] - Error rate (0-1).
   * @param {number} [event.timingMs] - Response timing in ms.
   * @param {string} [event.topic] - Topic/category of the interaction.
   * @returns {object} Drift detection result.
   */
  observe(event) {
    const normalized = this._normalizeEvent(event);
    this.current.push(normalized);
    if (this.current.length > this.windowSize * 2) {
      this.current = this.current.slice(-this.windowSize * 2);
    }

    // Learning phase
    if (!this.baseline && this.current.length >= this.windowSize) {
      this.baseline = this._buildBaseline(this.current);
      return { learning: false, baselineReady: true, alert: false };
    }

    if (!this.baseline) {
      return { learning: true, baselineReady: false, alert: false };
    }

    // Detection phase
    const drift = this._detectDrift(normalized);
    if (drift.alert) {
      this._emitAlert(drift, normalized);
    }
    return drift;
  }

  /**
   * Force-rebuild the baseline from current observations.
   */
  rebuildBaseline() {
    if (this.current.length >= 5) {
      this.baseline = this._buildBaseline(this.current);
    }
  }

  /**
   * Get a periodic drift summary report.
   * @returns {object}
   */
  getPeriodicSummary() {
    if (!this.baseline) {
      return { baselineReady: false, observations: this.current.length, windowSize: this.windowSize };
    }

    // Compute current window stats for comparison
    const recentWindow = this.current.slice(-this.windowSize);
    const currentStats = this._buildBaseline(recentWindow);

    return {
      baselineReady: true,
      observations: this.current.length,
      windowSize: this.windowSize,
      baseline: this.baseline,
      currentStats,
      alertCount: this.alertHistory.length,
      recentAlerts: this.alertHistory.slice(-10)
    };
  }

  /**
   * Get alert history.
   * @returns {Array<object>}
   */
  getAlertHistory() {
    return [...this.alertHistory];
  }

  /**
   * Reset the monitor (clear baseline and observations).
   */
  reset() {
    this.current = [];
    this.baseline = null;
    this.alertHistory = [];
  }

  // -----------------------------------------------------------------------
  // Private
  // -----------------------------------------------------------------------

  /**
   * Build a statistical baseline from a window of observations.
   * @private
   */
  _buildBaseline(window) {
    // Topic distribution
    const topicCounts = {};
    for (const item of window) {
      topicCounts[item.topic] = (topicCounts[item.topic] || 0) + 1;
    }
    const total = window.length || 1;
    const topicDistribution = {};
    for (const key of Object.keys(topicCounts)) {
      topicDistribution[key] = topicCounts[key] / total;
    }

    return {
      callFreqMean: mean(window.map(v => v.callFreq)),
      callFreqStd: std(window.map(v => v.callFreq)),
      responseLenMean: mean(window.map(v => v.responseLength)),
      responseLenStd: std(window.map(v => v.responseLength)),
      errorRateMean: mean(window.map(v => v.errorRate)),
      errorRateStd: std(window.map(v => v.errorRate)),
      timingMean: mean(window.map(v => v.timingMs)),
      timingStd: std(window.map(v => v.timingMs)),
      topicDistribution,
      observationCount: window.length
    };
  }

  /**
   * Detect drift in a single observation against the baseline.
   * @private
   */
  _detectDrift(event) {
    // Use minimum std floor to avoid Infinity z-scores on constant baselines
    // If all baseline values were identical (std=0), small deviations are normal variance, not anomalies
    const safeStd = (s, m) => s > 0 ? s : Math.max(Math.abs(m) * 0.1, 1);

    const zScores = {
      callFreq: Math.abs(zScore(event.callFreq, this.baseline.callFreqMean, safeStd(this.baseline.callFreqStd, this.baseline.callFreqMean))),
      responseLength: Math.abs(zScore(event.responseLength, this.baseline.responseLenMean, safeStd(this.baseline.responseLenStd, this.baseline.responseLenMean))),
      errorRate: Math.abs(zScore(event.errorRate, this.baseline.errorRateMean, safeStd(this.baseline.errorRateStd, this.baseline.errorRateMean))),
      timingMs: Math.abs(zScore(event.timingMs, this.baseline.timingMean, safeStd(this.baseline.timingStd, this.baseline.timingMean)))
    };

    // KL divergence for topic distribution — use sliding window, not single event
    // Single-event distributions cause extreme KL values for any new topic
    const recentTopics = this.current.slice(-Math.max(10, Math.floor(this.windowSize / 2)));
    const currentDist = {};
    for (const obs of recentTopics) {
      currentDist[obs.topic] = (currentDist[obs.topic] || 0) + 1;
    }
    const recentTotal = recentTopics.length || 1;
    for (const key of Object.keys(currentDist)) {
      currentDist[key] = currentDist[key] / recentTotal;
    }
    const kl = klDivergence(currentDist, this.baseline.topicDistribution || {});

    const maxZ = Math.max(...Object.values(zScores));
    const alert = maxZ >= this.alertThreshold || kl > this.klThreshold;

    return {
      alert,
      zScores,
      klDivergence: kl,
      maxZScore: maxZ,
      actionTaken: alert ? this._autoTighten() : 'none'
    };
  }

  /**
   * Auto-tighten action when drift detected.
   * @private
   */
  _autoTighten() {
    if (this.circuitBreaker) {
      this.circuitBreaker.recordThreat();
      const check = this.circuitBreaker.check();
      if (!check.allowed) {
        return 'circuit_breaker_open';
      }
    }
    return 'tighten_contracts';
  }

  /**
   * Emit an alert via logging, webhook, and metric export.
   * @private
   */
  _emitAlert(drift, event) {
    const alert = {
      timestamp: Date.now(),
      type: 'behavioral_drift',
      severity: 'high',
      zScores: drift.zScores,
      klDivergence: drift.klDivergence,
      maxZScore: drift.maxZScore,
      topic: event.topic,
      actionTaken: drift.actionTaken
    };

    this.alertHistory.push(alert);
    // Keep history bounded
    if (this.alertHistory.length > 1000) {
      this.alertHistory = this.alertHistory.slice(-1000);
    }

    console.log(`[Agent Shield] Drift alert: z=${drift.maxZScore.toFixed(2)} kl=${drift.klDivergence.toFixed(4)} topic=${event.topic} action=${drift.actionTaken}`);

    // Webhook notification
    if (this.onAlert) {
      try { this.onAlert(alert); } catch { /* ignore callback errors */ }
    }

    // Prometheus metric export
    if (this.prometheus && typeof this.prometheus.setGauge === 'function') {
      this.prometheus.setGauge('agentshield_drift_max_zscore', drift.maxZScore);
      this.prometheus.setGauge('agentshield_drift_kl_divergence', drift.klDivergence);
    }

    // OTel metric export
    if (this.metrics && typeof this.metrics.recordMetric === 'function') {
      this.metrics.recordMetric('drift.alert', 1, { topic: event.topic });
      this.metrics.recordMetric('drift.max_zscore', drift.maxZScore, { topic: event.topic });
    }
  }

  /**
   * Normalize an event to consistent numeric types.
   * @private
   */
  _normalizeEvent(event = {}) {
    return {
      callFreq: Number(event.callFreq || 0),
      responseLength: Number(event.responseLength || 0),
      errorRate: Number(event.errorRate || 0),
      timingMs: Number(event.timingMs || 0),
      topic: String(event.topic || 'general'),
      timestamp: Date.now()
    };
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
  DriftMonitor,
  klDivergence,
  mean,
  std,
  zScore
};
