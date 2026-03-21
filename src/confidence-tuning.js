'use strict';

/**
 * Agent Shield — Confidence Calibration & Tuning (v1.2)
 *
 * Learns from real-world feedback (true positives, false positives, false negatives)
 * to tune detection confidence thresholds and reduce alert noise.
 *
 * All data stored locally — no external calls.
 */

const fs = require('fs');
const path = require('path');
const { scanText } = require('./detector-core');

// =========================================================================
// CONFIDENCE TUNER
// =========================================================================

/**
 * Learns optimal confidence thresholds from labeled feedback data.
 * Tracks performance metrics and suggests tuning adjustments.
 */
class ConfidenceTuner {
  /**
   * @param {object} [options]
   * @param {string} [options.dataDir] - Directory to persist tuning data.
   * @param {number} [options.defaultThreshold=50] - Default confidence threshold (0-100).
   * @param {number} [options.learningRate=0.05] - How quickly thresholds adapt.
   * @param {number} [options.minSamples=10] - Minimum samples before adjusting thresholds.
   */
  constructor(options = {}) {
    this.dataDir = options.dataDir || null;
    this.defaultThreshold = options.defaultThreshold || 50;
    this.learningRate = options.learningRate || 0.05;
    this.minSamples = options.minSamples || 10;
    this.maxFeedback = options.maxFeedback || 10000;

    // Per-category thresholds
    this._thresholds = {};
    this._feedback = [];
    this._categoryStats = {};
    this._globalStats = { tp: 0, fp: 0, fn: 0, tn: 0 };

    // Load persisted data if available
    if (this.dataDir) {
      this._load();
    }

    console.log('[Agent Shield] ConfidenceTuner initialized (defaultThreshold: %d, learningRate: %s)', this.defaultThreshold, this.learningRate);
  }

  /**
   * Record feedback for a scan result.
   *
   * @param {object} scanResult - The original scan result from scanText/AgentShield.
   * @param {string} label - Ground truth: 'tp' (true positive), 'fp' (false positive), 'fn' (false negative), 'tn' (true negative).
   * @param {string} [notes] - Optional notes about the feedback.
   */
  recordFeedback(scanResult, label, notes = '') {
    const entry = {
      timestamp: Date.now(),
      label,
      status: scanResult.status,
      threatCount: scanResult.threats ? scanResult.threats.length : 0,
      categories: scanResult.threats ? scanResult.threats.map(t => t.category) : [],
      confidences: scanResult.threats ? scanResult.threats.map(t => t.confidence || 0) : [],
      notes
    };

    this._feedback.push(entry);
    while (this._feedback.length > this.maxFeedback) {
      this._feedback.shift();
    }
    this._globalStats[label] = (this._globalStats[label] || 0) + 1;

    // Update per-category stats
    for (const category of entry.categories) {
      if (!this._categoryStats[category]) {
        this._categoryStats[category] = { tp: 0, fp: 0, fn: 0, tn: 0, samples: 0, avgConfidence: 0, totalConfidence: 0 };
      }
      this._categoryStats[category][label]++;
      this._categoryStats[category].samples++;
    }

    // If false positive, consider raising the threshold for those categories
    if (label === 'fp') {
      for (let i = 0; i < entry.categories.length; i++) {
        this._adjustThreshold(entry.categories[i], entry.confidences[i], 'up');
      }
    }

    // If false negative, consider lowering the threshold
    if (label === 'fn' && entry.categories.length > 0) {
      for (const cat of entry.categories) {
        this._adjustThreshold(cat, 30, 'down');
      }
    }

    // Persist
    if (this.dataDir) {
      this._save();
    }

    return entry;
  }

  /**
   * Get the tuned confidence threshold for a category.
   * @param {string} category
   * @returns {number} Threshold (0-100).
   */
  getThreshold(category) {
    return this._thresholds[category] || this.defaultThreshold;
  }

  /**
   * Apply tuned thresholds to a scan result, filtering out low-confidence detections.
   *
   * @param {object} scanResult - Original scan result.
   * @returns {object} Filtered scan result.
   */
  applyThresholds(scanResult) {
    if (!scanResult.threats || scanResult.threats.length === 0) return scanResult;

    const filtered = scanResult.threats.filter(t => {
      const threshold = this.getThreshold(t.category);
      return (t.confidence || 50) >= threshold;
    });

    const suppressed = scanResult.threats.length - filtered.length;

    const stats = { totalThreats: filtered.length, critical: 0, high: 0, medium: 0, low: 0, scanTimeMs: scanResult.stats.scanTimeMs };
    for (const t of filtered) {
      stats[t.severity]++;
    }

    let status = 'safe';
    if (stats.critical > 0) status = 'danger';
    else if (stats.high > 0) status = 'warning';
    else if (stats.medium > 0) status = 'caution';

    return {
      ...scanResult,
      status,
      threats: filtered,
      stats,
      tuning: {
        applied: true,
        suppressed,
        thresholds: { ...this._thresholds }
      }
    };
  }

  /**
   * Scan text with tuned confidence thresholds applied.
   *
   * @param {string} text - Text to scan.
   * @param {object} [options] - Options passed to scanText.
   * @returns {object} Tuned scan result.
   */
  tunedScan(text, options = {}) {
    const result = scanText(text, options);
    return this.applyThresholds(result);
  }

  /**
   * Get performance metrics.
   * @returns {object} { precision, recall, f1, accuracy, perCategory }
   */
  getMetrics() {
    const { tp, fp, fn, tn } = this._globalStats;
    const total = tp + fp + fn + tn;

    const precision = (tp + fp) > 0 ? tp / (tp + fp) : 0;
    const recall = (tp + fn) > 0 ? tp / (tp + fn) : 0;
    const f1 = (precision + recall) > 0 ? 2 * (precision * recall) / (precision + recall) : 0;
    const accuracy = total > 0 ? (tp + tn) / total : 0;

    const perCategory = {};
    for (const [cat, stats] of Object.entries(this._categoryStats)) {
      const catPrecision = (stats.tp + stats.fp) > 0 ? stats.tp / (stats.tp + stats.fp) : 0;
      const catRecall = (stats.tp + stats.fn) > 0 ? stats.tp / (stats.tp + stats.fn) : 0;
      perCategory[cat] = {
        precision: Math.round(catPrecision * 100) / 100,
        recall: Math.round(catRecall * 100) / 100,
        samples: stats.samples,
        threshold: this.getThreshold(cat)
      };
    }

    return {
      precision: Math.round(precision * 100) / 100,
      recall: Math.round(recall * 100) / 100,
      f1: Math.round(f1 * 100) / 100,
      accuracy: Math.round(accuracy * 100) / 100,
      totalFeedback: this._feedback.length,
      globalStats: { ...this._globalStats },
      perCategory,
      thresholds: { ...this._thresholds }
    };
  }

  /**
   * Get tuning recommendations based on collected feedback.
   * @returns {Array<object>} List of recommendations.
   */
  getRecommendations() {
    const recommendations = [];
    const metrics = this.getMetrics();

    if (metrics.totalFeedback < this.minSamples) {
      recommendations.push({
        type: 'info',
        message: `Need at least ${this.minSamples} feedback samples to make recommendations. Current: ${metrics.totalFeedback}.`
      });
      return recommendations;
    }

    // High false positive rate
    if (this._globalStats.fp > this._globalStats.tp * 0.3) {
      recommendations.push({
        type: 'warning',
        message: 'High false positive rate detected. Consider raising confidence thresholds.',
        action: 'Increase defaultThreshold or review per-category thresholds.'
      });
    }

    // High false negative rate
    if (this._globalStats.fn > this._globalStats.tp * 0.2) {
      recommendations.push({
        type: 'warning',
        message: 'False negatives detected — some threats are being missed.',
        action: 'Lower thresholds for affected categories or add custom detection patterns.'
      });
    }

    // Per-category recommendations
    for (const [cat, stats] of Object.entries(this._categoryStats)) {
      if (stats.samples >= 5 && stats.fp > stats.tp) {
        recommendations.push({
          type: 'action',
          message: `Category "${cat}" has more false positives than true positives.`,
          action: `Consider raising threshold for "${cat}" (current: ${this.getThreshold(cat)}).`
        });
      }
    }

    if (recommendations.length === 0) {
      recommendations.push({
        type: 'success',
        message: 'Detection thresholds appear well-calibrated based on feedback data.'
      });
    }

    return recommendations;
  }

  /**
   * Reset all tuning data.
   */
  reset() {
    this._thresholds = {};
    this._feedback = [];
    this._categoryStats = {};
    this._globalStats = { tp: 0, fp: 0, fn: 0, tn: 0 };
    if (this.dataDir) this._save();
  }

  /** @private */
  _adjustThreshold(category, confidence, direction) {
    const current = this._thresholds[category] || this.defaultThreshold;
    const catStats = this._categoryStats[category];

    // Only adjust if we have enough samples
    if (catStats && catStats.samples < this.minSamples) return;

    if (direction === 'up') {
      this._thresholds[category] = Math.min(95, current + this.learningRate * (confidence - current));
    } else {
      this._thresholds[category] = Math.max(10, current - this.learningRate * current);
    }
  }

  /** @private */
  _save() {
    if (!this.dataDir) return;
    try {
      if (!fs.existsSync(this.dataDir)) {
        fs.mkdirSync(this.dataDir, { recursive: true });
      }
      const data = {
        thresholds: this._thresholds,
        categoryStats: this._categoryStats,
        globalStats: this._globalStats,
        feedbackCount: this._feedback.length,
        lastUpdated: Date.now()
      };
      fs.writeFileSync(path.join(this.dataDir, 'confidence-tuning.json'), JSON.stringify(data, null, 2));
    } catch (e) {
      console.warn('[Agent Shield] Failed to save tuning data:', e.message);
    }
  }

  /** @private */
  _load() {
    if (!this.dataDir) return;
    try {
      const filePath = path.join(this.dataDir, 'confidence-tuning.json');
      if (fs.existsSync(filePath)) {
        const data = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
        this._thresholds = data.thresholds || {};
        this._categoryStats = data.categoryStats || {};
        this._globalStats = data.globalStats || { tp: 0, fp: 0, fn: 0, tn: 0 };
        console.log('[Agent Shield] Loaded tuning data (%d category thresholds)', Object.keys(this._thresholds).length);
      }
    } catch (e) {
      console.warn('[Agent Shield] Failed to load tuning data:', e.message);
    }
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = { ConfidenceTuner };
