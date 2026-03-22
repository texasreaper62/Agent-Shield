'use strict';

/**
 * Agent Shield — Cross-Turn Injection Tracking & Adaptive Thresholds (v8)
 *
 * Detects injection attacks spread across multiple conversation turns and
 * auto-calibrates detection thresholds based on observed scan results.
 *
 * All computation is pure JavaScript — no external dependencies.
 * No data ever leaves the user's environment.
 */

const { scanText } = require('./detector-core');

// =========================================================================
// CROSS-TURN TRACKER
// =========================================================================

/**
 * Accumulates conversation text across turns and periodically scans the
 * full accumulated context for injections that only become visible when
 * messages are combined (e.g. "Ig" + "nore all" + "previous instructions").
 */
class CrossTurnTracker {
  /**
   * @param {object} [config]
   * @param {number} [config.windowSize=20] - Max messages to keep in window
   * @param {number} [config.scanInterval=3] - Scan every N messages
   * @param {boolean} [config.accumulateAll=true] - Keep all text or just user messages
   * @param {string} [config.sensitivity='high'] - Scan sensitivity
   * @param {function} [config.onDetection] - Callback when cross-turn threat found
   */
  constructor(config = {}) {
    this.windowSize = config.windowSize !== undefined ? config.windowSize : 20;
    this.scanInterval = config.scanInterval !== undefined ? config.scanInterval : 3;
    this.accumulateAll = config.accumulateAll !== undefined ? config.accumulateAll : true;
    this.sensitivity = config.sensitivity || 'high';
    this.onDetection = config.onDetection || null;

    this.messages = [];
    this._stats = {
      totalMessages: 0,
      scansTriggered: 0,
      crossTurnDetections: 0,
      individualDetections: 0
    };
  }

  /**
   * Add a message to the conversation.
   * @param {string} text - Message text
   * @param {string} [role='user'] - 'user' or 'assistant'
   * @returns {object} {
   *   tracked: boolean,
   *   messageCount: number,
   *   scanTriggered: boolean,
   *   threats: Array (empty if no scan or no threats),
   *   crossTurnDetection: boolean (true if threat only visible in combined text)
   * }
   */
  addMessage(text, role = 'user') {
    if (!text || typeof text !== 'string') {
      return {
        tracked: false,
        messageCount: this.messages.length,
        scanTriggered: false,
        threats: [],
        crossTurnDetection: false
      };
    }

    const message = {
      text,
      role,
      timestamp: Date.now(),
      index: this._stats.totalMessages
    };

    this.messages.push(message);
    this._stats.totalMessages++;

    // Enforce sliding window
    if (this.messages.length > this.windowSize) {
      this.messages.shift();
    }

    // Determine if we should scan
    const scanTriggered = this._stats.totalMessages % this.scanInterval === 0;

    if (!scanTriggered) {
      return {
        tracked: true,
        messageCount: this.messages.length,
        scanTriggered: false,
        threats: [],
        crossTurnDetection: false
      };
    }

    // Perform cross-turn scan
    this._stats.scansTriggered++;
    const scanResult = this._performCrossTurnScan();

    return {
      tracked: true,
      messageCount: this.messages.length,
      scanTriggered: true,
      threats: scanResult.threats,
      crossTurnDetection: scanResult.crossTurnDetection
    };
  }

  /**
   * Force a scan of accumulated text right now.
   * @returns {object} { threats: Array, combinedLength: number, messageCount: number }
   */
  scanNow() {
    this._stats.scansTriggered++;
    const combined = this.getAccumulatedText();
    const result = scanText(combined, {
      source: 'cross_turn_scan',
      sensitivity: this.sensitivity
    });

    return {
      threats: result.threats,
      combinedLength: combined.length,
      messageCount: this.messages.length
    };
  }

  /**
   * Get the current accumulated text.
   * @returns {string}
   */
  getAccumulatedText() {
    const eligible = this.accumulateAll
      ? this.messages
      : this.messages.filter(m => m.role === 'user');

    return eligible.map(m => m.text).join(' ');
  }

  /**
   * Get the individual message that was most suspicious.
   * @returns {object|null} { text, role, confidence, threats } or null
   */
  getMostSuspicious() {
    if (this.messages.length === 0) return null;

    let mostSuspicious = null;
    let highestThreatCount = -1;

    for (const msg of this.messages) {
      const result = scanText(msg.text, {
        source: 'individual_scan',
        sensitivity: this.sensitivity
      });

      if (result.threats.length > highestThreatCount) {
        highestThreatCount = result.threats.length;
        mostSuspicious = {
          text: msg.text,
          role: msg.role,
          timestamp: msg.timestamp,
          confidence: result.threats.length > 0
            ? Math.max(...result.threats.map(t => _severityToConfidence(t.severity)))
            : 0,
          threats: result.threats
        };
      }
    }

    return mostSuspicious;
  }

  /**
   * Reset the tracker to initial state.
   */
  reset() {
    this.messages = [];
    this._stats = {
      totalMessages: 0,
      scansTriggered: 0,
      crossTurnDetections: 0,
      individualDetections: 0
    };
  }

  /**
   * Get tracker statistics.
   * @returns {object}
   */
  getStats() {
    return {
      ...this._stats,
      currentWindowSize: this.messages.length,
      maxWindowSize: this.windowSize,
      scanInterval: this.scanInterval
    };
  }

  /**
   * Perform the cross-turn detection scan.
   * Compares combined scan results against individual message scans.
   * @private
   * @returns {object} { threats: Array, crossTurnDetection: boolean }
   */
  _performCrossTurnScan() {
    const eligible = this.accumulateAll
      ? this.messages
      : this.messages.filter(m => m.role === 'user');

    if (eligible.length === 0) {
      return { threats: [], crossTurnDetection: false };
    }

    // Scan concatenated text
    const combinedText = eligible.map(m => m.text).join(' ');
    const combinedResult = scanText(combinedText, {
      source: 'cross_turn_combined',
      sensitivity: this.sensitivity
    });

    if (combinedResult.threats.length === 0) {
      return { threats: [], crossTurnDetection: false };
    }

    // Scan each individual message and collect all individually-detected threats
    const individualCategories = new Set();
    for (const msg of eligible) {
      const result = scanText(msg.text, {
        source: 'cross_turn_individual',
        sensitivity: this.sensitivity
      });
      for (const t of result.threats) {
        individualCategories.add(`${t.category}|${t.detail}`);
      }
      if (result.threats.length > 0) {
        this._stats.individualDetections++;
      }
    }

    // Cross-turn threats: found in combined scan but NOT in any individual scan
    const crossTurnThreats = [];
    const regularThreats = [];

    for (const threat of combinedResult.threats) {
      const key = `${threat.category}|${threat.detail}`;
      if (!individualCategories.has(key)) {
        crossTurnThreats.push({
          ...threat,
          crossTurn: true,
          description: `Cross-turn attack: ${threat.description} (split across ${eligible.length} messages)`,
          windowSize: eligible.length
        });
      } else {
        regularThreats.push(threat);
      }
    }

    const crossTurnDetection = crossTurnThreats.length > 0;

    if (crossTurnDetection) {
      this._stats.crossTurnDetections++;
      console.log(
        '[Agent Shield] Cross-turn injection detected: ' +
        crossTurnThreats.length + ' threat(s) found across ' +
        eligible.length + ' messages'
      );

      if (this.onDetection) {
        try {
          this.onDetection({
            threats: crossTurnThreats,
            messages: eligible.map(m => ({ text: m.text, role: m.role })),
            timestamp: Date.now()
          });
        } catch (e) {
          console.error('[Agent Shield] onDetection callback error:', e.message);
        }
      }
    }

    return {
      threats: [...crossTurnThreats, ...regularThreats],
      crossTurnDetection
    };
  }
}

// =========================================================================
// ADAPTIVE THRESHOLD CALIBRATOR
// =========================================================================

/**
 * Automatically adjusts detection thresholds based on observed scan results.
 * Learns what "normal" looks like for each deployment and calibrates
 * per-category thresholds to achieve a target false positive rate.
 */
class AdaptiveThresholdCalibrator {
  /**
   * @param {object} [config]
   * @param {number} [config.calibrationSamples=100] - Samples before adjusting
   * @param {number} [config.adjustInterval=50] - Recalibrate every N samples
   * @param {number} [config.minConfidence=0.3] - Never drop below this
   * @param {number} [config.maxConfidence=0.95] - Never go above this
   * @param {number} [config.targetFPRate=0.02] - Target false positive rate (2%)
   */
  constructor(config = {}) {
    this.calibrationSamples = config.calibrationSamples !== undefined ? config.calibrationSamples : 100;
    this.adjustInterval = config.adjustInterval !== undefined ? config.adjustInterval : 50;
    this.minConfidence = config.minConfidence !== undefined ? config.minConfidence : 0.3;
    this.maxConfidence = config.maxConfidence !== undefined ? config.maxConfidence : 0.95;
    this.targetFPRate = config.targetFPRate !== undefined ? config.targetFPRate : 0.02;

    // Per-category data
    this._categories = {};
    // Default category always exists
    this._categories['default'] = this._createCategoryData();

    this._totalSamples = 0;
    this._calibrationCount = 0;
  }

  /**
   * Record a scan result for calibration.
   * @param {object} result - { confidence: number, isInjection: boolean, category: string }
   * @param {boolean} [isTruePositive] - If known (from feedback), whether this was correct
   * @returns {object} {
   *   recorded: boolean,
   *   isCalibrating: boolean,
   *   samplesRemaining: number,
   *   currentThreshold: number
   * }
   */
  record(result, isTruePositive) {
    if (!result || typeof result.confidence !== 'number') {
      return {
        recorded: false,
        isCalibrating: this._totalSamples < this.calibrationSamples,
        samplesRemaining: Math.max(0, this.calibrationSamples - this._totalSamples),
        currentThreshold: this.getThreshold('default')
      };
    }

    const category = result.category || 'default';
    const confidence = Math.max(0, Math.min(1, result.confidence));
    const isInjection = !!result.isInjection;

    // Ensure category data exists
    if (!this._categories[category]) {
      this._categories[category] = this._createCategoryData();
    }

    const catData = this._categories[category];

    // Record the sample
    catData.samples.push({
      confidence,
      isInjection,
      isTruePositive: isTruePositive !== undefined ? isTruePositive : null,
      timestamp: Date.now()
    });

    // Also record in default if not already default
    if (category !== 'default') {
      this._categories['default'].samples.push({
        confidence,
        isInjection,
        isTruePositive: isTruePositive !== undefined ? isTruePositive : null,
        timestamp: Date.now()
      });
    }

    this._totalSamples++;

    // Cap stored samples to prevent unbounded growth
    const maxStoredSamples = this.calibrationSamples * 10;
    if (catData.samples.length > maxStoredSamples) {
      catData.samples = catData.samples.slice(-maxStoredSamples);
    }
    if (category !== 'default' && this._categories['default'].samples.length > maxStoredSamples) {
      this._categories['default'].samples = this._categories['default'].samples.slice(-maxStoredSamples);
    }

    // Check if we should recalibrate
    const isCalibrating = this._totalSamples < this.calibrationSamples;
    const shouldRecalibrate = !isCalibrating &&
      (this._totalSamples % this.adjustInterval === 0);

    if (shouldRecalibrate) {
      this.recalibrate();
    }

    return {
      recorded: true,
      isCalibrating,
      samplesRemaining: Math.max(0, this.calibrationSamples - this._totalSamples),
      currentThreshold: this.getThreshold(category)
    };
  }

  /**
   * Get the current calibrated threshold for a category.
   * @param {string} [category='default']
   * @returns {number} threshold 0-1
   */
  getThreshold(category = 'default') {
    const catData = this._categories[category] || this._categories['default'];
    return catData.threshold;
  }

  /**
   * Check if a confidence score exceeds the calibrated threshold.
   * @param {number} confidence
   * @param {string} [category='default']
   * @returns {boolean}
   */
  shouldFlag(confidence, category = 'default') {
    return confidence >= this.getThreshold(category);
  }

  /**
   * Force recalibration now.
   * @returns {object} { thresholds: object, samplesUsed: number }
   */
  recalibrate() {
    this._calibrationCount++;
    const thresholds = {};

    for (const [category, catData] of Object.entries(this._categories)) {
      const newThreshold = this._calibrateCategory(catData);
      catData.threshold = newThreshold;
      thresholds[category] = newThreshold;
    }

    console.log(
      '[Agent Shield] Adaptive thresholds recalibrated (round ' +
      this._calibrationCount + '): ' +
      Object.entries(thresholds)
        .map(([cat, th]) => cat + '=' + th.toFixed(3))
        .join(', ')
    );

    return {
      thresholds,
      samplesUsed: this._totalSamples
    };
  }

  /**
   * Get calibration stats.
   * @returns {object}
   */
  getStats() {
    const categoryStats = {};
    for (const [category, catData] of Object.entries(this._categories)) {
      const benignSamples = catData.samples.filter(s => !s.isInjection);
      const injectionSamples = catData.samples.filter(s => s.isInjection);
      const feedbackSamples = catData.samples.filter(s => s.isTruePositive !== null);

      // Estimate current FP rate
      let estimatedFPRate = 0;
      if (benignSamples.length > 0) {
        const falsePositives = benignSamples.filter(
          s => s.confidence >= catData.threshold
        ).length;
        estimatedFPRate = falsePositives / benignSamples.length;
      }

      categoryStats[category] = {
        threshold: catData.threshold,
        totalSamples: catData.samples.length,
        benignSamples: benignSamples.length,
        injectionSamples: injectionSamples.length,
        feedbackSamples: feedbackSamples.length,
        estimatedFPRate: Math.round(estimatedFPRate * 10000) / 10000
      };
    }

    return {
      totalSamples: this._totalSamples,
      calibrationCount: this._calibrationCount,
      isCalibrating: this._totalSamples < this.calibrationSamples,
      targetFPRate: this.targetFPRate,
      categories: categoryStats
    };
  }

  /**
   * Export calibration data for persistence.
   * @returns {object}
   */
  export() {
    const categories = {};
    for (const [category, catData] of Object.entries(this._categories)) {
      categories[category] = {
        threshold: catData.threshold,
        samples: catData.samples
      };
    }

    return {
      version: 1,
      totalSamples: this._totalSamples,
      calibrationCount: this._calibrationCount,
      calibrationSamples: this.calibrationSamples,
      adjustInterval: this.adjustInterval,
      minConfidence: this.minConfidence,
      maxConfidence: this.maxConfidence,
      targetFPRate: this.targetFPRate,
      categories,
      exportedAt: Date.now()
    };
  }

  /**
   * Import calibration data from a previous export.
   * @param {object} data - Previously exported calibration data
   */
  import(data) {
    if (!data || typeof data !== 'object') {
      console.error('[Agent Shield] Invalid calibration data for import');
      return;
    }

    if (data.version !== 1) {
      console.error('[Agent Shield] Unsupported calibration data version: ' + data.version);
      return;
    }

    this._totalSamples = data.totalSamples || 0;
    this._calibrationCount = data.calibrationCount || 0;

    if (data.calibrationSamples !== undefined) this.calibrationSamples = data.calibrationSamples;
    if (data.adjustInterval !== undefined) this.adjustInterval = data.adjustInterval;
    if (data.minConfidence !== undefined) this.minConfidence = data.minConfidence;
    if (data.maxConfidence !== undefined) this.maxConfidence = data.maxConfidence;
    if (data.targetFPRate !== undefined) this.targetFPRate = data.targetFPRate;

    if (data.categories) {
      this._categories = {};
      for (const [category, catData] of Object.entries(data.categories)) {
        this._categories[category] = {
          threshold: catData.threshold || this._defaultThreshold(),
          samples: Array.isArray(catData.samples) ? catData.samples : []
        };
      }
    }

    // Ensure default category exists
    if (!this._categories['default']) {
      this._categories['default'] = this._createCategoryData();
    }

    console.log(
      '[Agent Shield] Calibration data imported: ' +
      this._totalSamples + ' samples, ' +
      Object.keys(this._categories).length + ' categories'
    );
  }

  /**
   * Create initial data structure for a category.
   * @private
   * @returns {object}
   */
  _createCategoryData() {
    return {
      threshold: this._defaultThreshold(),
      samples: []
    };
  }

  /**
   * Get the default starting threshold.
   * @private
   * @returns {number}
   */
  _defaultThreshold() {
    return 0.5;
  }

  /**
   * Calibrate a single category using the percentile-based approach.
   * Finds the threshold that achieves the target FP rate on benign samples.
   * @private
   * @param {object} catData - Category data with samples array
   * @returns {number} Calibrated threshold
   */
  _calibrateCategory(catData) {
    const samples = catData.samples;

    if (samples.length === 0) {
      return catData.threshold;
    }

    // Separate benign and injection samples
    const benignConfidences = [];
    const injectionConfidences = [];

    for (const s of samples) {
      // Use feedback if available, otherwise use isInjection flag
      const actuallyBenign = s.isTruePositive === false || (!s.isInjection && s.isTruePositive === null);
      const actuallyInjection = s.isTruePositive === true || (s.isInjection && s.isTruePositive === null);

      if (actuallyBenign) {
        benignConfidences.push(s.confidence);
      } else if (actuallyInjection) {
        injectionConfidences.push(s.confidence);
      }
    }

    // If we have no benign samples, keep current threshold
    if (benignConfidences.length === 0) {
      return catData.threshold;
    }

    // Sort benign confidence scores ascending
    benignConfidences.sort((a, b) => a - b);

    // Find the threshold at the (1 - targetFPRate) percentile of benign samples
    // This means only targetFPRate of benign samples would be above the threshold
    const percentileIndex = Math.floor(benignConfidences.length * (1 - this.targetFPRate));
    const clampedIndex = Math.min(percentileIndex, benignConfidences.length - 1);
    let threshold = benignConfidences[clampedIndex];

    // Clamp between min and max
    threshold = Math.max(this.minConfidence, Math.min(this.maxConfidence, threshold));

    return Math.round(threshold * 1000) / 1000;
  }
}

// =========================================================================
// UTILITY FUNCTIONS
// =========================================================================

/**
 * Map severity string to a numeric confidence value.
 * @param {string} severity - 'critical', 'high', 'medium', or 'low'
 * @returns {number} Confidence between 0 and 1
 * @private
 */
function _severityToConfidence(severity) {
  const map = {
    critical: 0.95,
    high: 0.8,
    medium: 0.6,
    low: 0.4
  };
  return map[severity] || 0.5;
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
  CrossTurnTracker,
  AdaptiveThresholdCalibrator
};
