'use strict';

/**
 * Agent Shield — Allowlist, Confidence Calibration, Feedback Loop & Scan Cache
 *
 * Features:
 * - Allowlist/bypass rules for false positive management
 * - Confidence calibration based on traffic patterns
 * - Feedback loop API for continuous improvement
 * - LRU scan result cache for performance
 */

// =========================================================================
// Allowlist / Bypass Rules
// =========================================================================

class Allowlist {
  constructor(options = {}) {
    this.rules = [];
    this.globalPatterns = [];
    this.perCategoryBypasses = {};
    this.stats = { checked: 0, bypassed: 0 };

    if (options.rules) {
      for (const rule of options.rules) {
        this.addRule(rule);
      }
    }
  }

  /**
   * Add an allowlist rule.
   * @param {Object} rule - { pattern: string|RegExp, category?: string, reason: string, addedBy?: string }
   */
  addRule(rule) {
    const compiled = {
      id: `allow_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      pattern: typeof rule.pattern === 'string' ? new RegExp(rule.pattern, 'i') : rule.pattern,
      patternSource: typeof rule.pattern === 'string' ? rule.pattern : rule.pattern.source,
      category: rule.category || null,
      reason: rule.reason || 'No reason provided',
      addedBy: rule.addedBy || 'system',
      addedAt: new Date().toISOString(),
      hitCount: 0
    };

    this.rules.push(compiled);

    if (compiled.category) {
      if (!this.perCategoryBypasses[compiled.category]) {
        this.perCategoryBypasses[compiled.category] = [];
      }
      this.perCategoryBypasses[compiled.category].push(compiled);
    } else {
      this.globalPatterns.push(compiled);
    }

    return compiled.id;
  }

  /**
   * Check if an input should bypass scanning for a specific threat.
   * @param {string} text - Input text
   * @param {Object} threat - Threat object with { category, description }
   * @returns {{ allowed: boolean, rule?: Object }}
   */
  check(text, threat = {}) {
    this.stats.checked++;

    // Check category-specific bypasses first
    if (threat.category && this.perCategoryBypasses[threat.category]) {
      for (const rule of this.perCategoryBypasses[threat.category]) {
        if (rule.pattern.test(text)) {
          rule.hitCount++;
          this.stats.bypassed++;
          return { allowed: true, rule: { id: rule.id, reason: rule.reason } };
        }
      }
    }

    // Check global bypasses
    for (const rule of this.globalPatterns) {
      if (rule.pattern.test(text)) {
        rule.hitCount++;
        this.stats.bypassed++;
        return { allowed: true, rule: { id: rule.id, reason: rule.reason } };
      }
    }

    return { allowed: false };
  }

  /**
   * Filter threats, removing any that match allowlist rules.
   * @param {string} text - Input text
   * @param {Array} threats - Array of threat objects
   * @returns {{ filtered: Array, bypassed: Array }}
   */
  filterThreats(text, threats) {
    const filtered = [];
    const bypassed = [];

    for (const threat of threats) {
      const result = this.check(text, threat);
      if (result.allowed) {
        bypassed.push({ ...threat, bypassRule: result.rule });
      } else {
        filtered.push(threat);
      }
    }

    return { filtered, bypassed };
  }

  /**
   * Remove an allowlist rule by ID.
   */
  removeRule(ruleId) {
    this.rules = this.rules.filter(r => r.id !== ruleId);
    this.globalPatterns = this.globalPatterns.filter(r => r.id !== ruleId);
    for (const cat of Object.keys(this.perCategoryBypasses)) {
      this.perCategoryBypasses[cat] = this.perCategoryBypasses[cat].filter(r => r.id !== ruleId);
    }
    return true;
  }

  /**
   * Get all rules with their hit counts.
   */
  getRules() {
    return this.rules.map(r => ({
      id: r.id,
      pattern: r.patternSource,
      category: r.category,
      reason: r.reason,
      addedBy: r.addedBy,
      addedAt: r.addedAt,
      hitCount: r.hitCount
    }));
  }

  /**
   * Get stats.
   */
  getStats() {
    return {
      ...this.stats,
      ruleCount: this.rules.length,
      bypassRate: this.stats.checked > 0
        ? `${((this.stats.bypassed / this.stats.checked) * 100).toFixed(1)}%`
        : '0%'
    };
  }

  /**
   * Export rules as JSON for persistence.
   */
  exportRules() {
    return JSON.stringify(this.getRules(), null, 2);
  }

  /**
   * Import rules from JSON.
   */
  importRules(json) {
    const rules = typeof json === 'string' ? JSON.parse(json) : json;
    for (const rule of rules) {
      this.addRule(rule);
    }
    return rules.length;
  }
}

// =========================================================================
// Confidence Calibration
// =========================================================================

class ConfidenceCalibrator {
  constructor(options = {}) {
    this.windowSize = options.windowSize || 1000;
    this.history = [];
    this.falsePositives = 0;
    this.truePositives = 0;
    this.falseNegatives = 0;
    this.trueNegatives = 0;
    this.categoryStats = {};
    this.thresholdSuggestions = null;
  }

  /**
   * Record a scan result with ground truth feedback.
   * @param {Object} scanResult - The scan result
   * @param {boolean} wasActuallyMalicious - Ground truth
   */
  record(scanResult, wasActuallyMalicious) {
    const detected = scanResult.threats && scanResult.threats.length > 0;

    if (detected && wasActuallyMalicious) this.truePositives++;
    else if (detected && !wasActuallyMalicious) this.falsePositives++;
    else if (!detected && wasActuallyMalicious) this.falseNegatives++;
    else this.trueNegatives++;

    // Track per-category
    if (detected) {
      for (const threat of scanResult.threats) {
        const cat = threat.category;
        if (!this.categoryStats[cat]) {
          this.categoryStats[cat] = { tp: 0, fp: 0 };
        }
        if (wasActuallyMalicious) this.categoryStats[cat].tp++;
        else this.categoryStats[cat].fp++;
      }
    }

    this.history.push({
      detected,
      actual: wasActuallyMalicious,
      threats: (scanResult.threats || []).map(t => t.category),
      timestamp: Date.now()
    });

    // Trim history
    while (this.history.length > this.windowSize) {
      this.history.shift();
    }
  }

  /**
   * Get current calibration metrics.
   */
  getMetrics() {
    const total = this.truePositives + this.falsePositives + this.falseNegatives + this.trueNegatives;
    if (total === 0) return { status: 'insufficient_data', total: 0 };

    const precision = this.truePositives + this.falsePositives > 0
      ? this.truePositives / (this.truePositives + this.falsePositives)
      : 0;

    const recall = this.truePositives + this.falseNegatives > 0
      ? this.truePositives / (this.truePositives + this.falseNegatives)
      : 0;

    const f1 = precision + recall > 0
      ? 2 * (precision * recall) / (precision + recall)
      : 0;

    const falsePositiveRate = this.falsePositives + this.trueNegatives > 0
      ? this.falsePositives / (this.falsePositives + this.trueNegatives)
      : 0;

    return {
      status: 'calibrated',
      total,
      truePositives: this.truePositives,
      falsePositives: this.falsePositives,
      trueNegatives: this.trueNegatives,
      falseNegatives: this.falseNegatives,
      precision: parseFloat((precision * 100).toFixed(1)),
      recall: parseFloat((recall * 100).toFixed(1)),
      f1Score: parseFloat((f1 * 100).toFixed(1)),
      falsePositiveRate: parseFloat((falsePositiveRate * 100).toFixed(1)),
      categoryBreakdown: this.getCategoryBreakdown()
    };
  }

  getCategoryBreakdown() {
    const result = {};
    for (const [cat, stats] of Object.entries(this.categoryStats)) {
      const total = stats.tp + stats.fp;
      result[cat] = {
        truePositives: stats.tp,
        falsePositives: stats.fp,
        precision: total > 0 ? parseFloat(((stats.tp / total) * 100).toFixed(1)) : 0
      };
    }
    return result;
  }

  /**
   * Suggest threshold adjustments based on collected data.
   */
  suggestThresholds() {
    const metrics = this.getMetrics();
    if (metrics.status === 'insufficient_data') {
      return { status: 'insufficient_data', message: `Need at least 1 data point. Have ${metrics.total}.` };
    }

    const suggestions = [];

    if (metrics.falsePositiveRate > 20) {
      suggestions.push({
        action: 'lower_sensitivity',
        reason: `False positive rate is ${metrics.falsePositiveRate}% (target: <10%)`,
        suggestion: 'Consider switching from "high" to "medium" sensitivity'
      });
    }

    if (metrics.recall < 80) {
      suggestions.push({
        action: 'raise_sensitivity',
        reason: `Recall is ${metrics.recall}% (target: >90%)`,
        suggestion: 'Consider switching from current sensitivity to "high"'
      });
    }

    // Per-category suggestions
    for (const [cat, stats] of Object.entries(this.categoryStats)) {
      const total = stats.tp + stats.fp;
      if (total >= 5 && stats.fp / total > 0.5) {
        suggestions.push({
          action: 'add_allowlist',
          category: cat,
          reason: `Category "${cat}" has ${((stats.fp / total) * 100).toFixed(0)}% false positive rate`,
          suggestion: `Consider adding allowlist rules for "${cat}" category`
        });
      }
    }

    if (suggestions.length === 0) {
      suggestions.push({
        action: 'none',
        reason: 'Current thresholds look good',
        suggestion: `Precision: ${metrics.precision}%, Recall: ${metrics.recall}%`
      });
    }

    this.thresholdSuggestions = suggestions;
    return { status: 'ok', metrics, suggestions };
  }

  /**
   * Reset calibration data.
   */
  reset() {
    this.history = [];
    this.falsePositives = 0;
    this.truePositives = 0;
    this.falseNegatives = 0;
    this.trueNegatives = 0;
    this.categoryStats = {};
    this.thresholdSuggestions = null;
  }
}

// =========================================================================
// Feedback Loop API
// =========================================================================

class FeedbackLoop {
  constructor(options = {}) {
    this.calibrator = options.calibrator || new ConfidenceCalibrator();
    this.allowlist = options.allowlist || new Allowlist();
    this.pendingReviews = [];
    this.maxPending = options.maxPending || 100;
    this.onFeedback = options.onFeedback || null;
    this.stats = { falsePositives: 0, missed: 0, confirmed: 0 };
  }

  /**
   * Report a false positive.
   * @param {string} text - The input that was incorrectly flagged
   * @param {Object} scanResult - The original scan result
   * @param {Object} metadata - Additional context
   */
  reportFalsePositive(text, scanResult, metadata = {}) {
    this.stats.falsePositives++;
    this.calibrator.record(scanResult, false);

    const entry = {
      id: `fp_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      type: 'false_positive',
      text: text.substring(0, 500),
      threats: scanResult.threats || [],
      metadata,
      timestamp: new Date().toISOString(),
      status: 'pending'
    };

    this.pendingReviews.push(entry);
    while (this.pendingReviews.length > this.maxPending) {
      this.pendingReviews.shift();
    }

    if (this.onFeedback) { try { this.onFeedback(entry); } catch (e) { console.error('[Agent Shield] onFeedback callback error:', e.message); } }
    return entry.id;
  }

  /**
   * Report a missed attack (false negative).
   * @param {string} text - The input that should have been flagged
   * @param {Object} scanResult - The original scan result (which missed the threat)
   * @param {Object} metadata - Additional context
   */
  reportMissed(text, scanResult, metadata = {}) {
    this.stats.missed++;
    this.calibrator.record(scanResult, true);

    const entry = {
      id: `fn_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      type: 'false_negative',
      text: text.substring(0, 500),
      threats: scanResult.threats || [],
      metadata,
      timestamp: new Date().toISOString(),
      status: 'pending'
    };

    this.pendingReviews.push(entry);
    while (this.pendingReviews.length > this.maxPending) {
      this.pendingReviews.shift();
    }

    if (this.onFeedback) { try { this.onFeedback(entry); } catch (e) { console.error('[Agent Shield] onFeedback callback error:', e.message); } }
    return entry.id;
  }

  /**
   * Confirm a detection was correct (true positive).
   */
  confirmDetection(scanResult) {
    this.stats.confirmed++;
    this.calibrator.record(scanResult, true);
  }

  /**
   * Confirm a pass was correct (true negative).
   */
  confirmSafe(scanResult) {
    this.calibrator.record(scanResult, false);
  }

  /**
   * Auto-create allowlist rule from a false positive.
   */
  autoAllowlist(feedbackId, options = {}) {
    const entry = this.pendingReviews.find(e => e.id === feedbackId);
    if (!entry || entry.type !== 'false_positive') return null;

    const category = entry.threats.length > 0 ? entry.threats[0].category : null;

    // Create a specific pattern from the text
    const escapedText = entry.text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const ruleId = this.allowlist.addRule({
      pattern: options.pattern || escapedText.substring(0, 100),
      category,
      reason: options.reason || `Auto-allowlisted from feedback ${feedbackId}`,
      addedBy: options.addedBy || 'feedback_loop'
    });

    entry.status = 'resolved';
    entry.resolution = { action: 'allowlisted', ruleId };
    return ruleId;
  }

  /**
   * Get pending reviews.
   */
  getPendingReviews() {
    return this.pendingReviews.filter(e => e.status === 'pending');
  }

  /**
   * Get calibration suggestions.
   */
  getSuggestions() {
    return this.calibrator.suggestThresholds();
  }

  /**
   * Get stats.
   */
  getStats() {
    return {
      ...this.stats,
      pending: this.pendingReviews.filter(e => e.status === 'pending').length,
      calibration: this.calibrator.getMetrics()
    };
  }
}

// =========================================================================
// LRU Scan Cache
// =========================================================================

class ScanCache {
  constructor(options = {}) {
    this.maxSize = options.maxSize || 1000;
    this.ttlMs = options.ttlMs || 60000; // 1 minute default
    this.cache = new Map();
    this.stats = { hits: 0, misses: 0, evictions: 0 };
  }

  /**
   * Generate cache key from text and sensitivity.
   */
  _key(text, sensitivity) {
    // Simple hash: use first 200 chars + length + sensitivity
    const prefix = text.substring(0, 200);
    return `${sensitivity}:${text.length}:${prefix}`;
  }

  /**
   * Get a cached result.
   */
  get(text, sensitivity = 'high') {
    const key = this._key(text, sensitivity);
    const entry = this.cache.get(key);

    if (!entry) {
      this.stats.misses++;
      return null;
    }

    // Check TTL
    if (Date.now() - entry.timestamp > this.ttlMs) {
      this.cache.delete(key);
      this.stats.misses++;
      return null;
    }

    // Move to end (LRU refresh)
    this.cache.delete(key);
    this.cache.set(key, entry);
    this.stats.hits++;

    return entry.result;
  }

  /**
   * Store a result in cache.
   */
  set(text, sensitivity, result) {
    const key = this._key(text, sensitivity);

    // Evict oldest if at capacity
    if (this.cache.size >= this.maxSize && !this.cache.has(key)) {
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
      this.stats.evictions++;
    }

    this.cache.set(key, {
      result,
      timestamp: Date.now()
    });
  }

  /**
   * Wrap a scan function with caching.
   */
  wrap(scanFn) {
    return (text, sensitivity = 'high') => {
      const cached = this.get(text, sensitivity);
      if (cached) return { ...cached, _cached: true };

      const result = scanFn(text, sensitivity);
      this.set(text, sensitivity, result);
      return result;
    };
  }

  /**
   * Get cache stats.
   */
  getStats() {
    const total = this.stats.hits + this.stats.misses;
    return {
      ...this.stats,
      size: this.cache.size,
      maxSize: this.maxSize,
      hitRate: total > 0 ? `${((this.stats.hits / total) * 100).toFixed(1)}%` : '0%'
    };
  }

  /**
   * Clear the cache.
   */
  clear() {
    this.cache.clear();
  }

  /**
   * Prune expired entries.
   */
  prune() {
    const now = Date.now();
    let pruned = 0;
    for (const [key, entry] of this.cache) {
      if (now - entry.timestamp > this.ttlMs) {
        this.cache.delete(key);
        pruned++;
      }
    }
    return pruned;
  }
}

module.exports = {
  Allowlist,
  ConfidenceCalibrator,
  FeedbackLoop,
  ScanCache
};
