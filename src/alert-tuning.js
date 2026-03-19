'use strict';

/**
 * Agent Shield — Alert Fatigue Scoring & Auto-Tuning
 *
 * Features:
 * - Alert fatigue analysis: identifies noisy patterns and high false-positive sources
 * - Auto-tuning: applies suggestions to shield config to reduce alert noise
 * - Alert correlation: groups related alerts by time proximity and category
 */

// =========================================================================
// Alert Fatigue Analyzer
// =========================================================================

class AlertFatigueAnalyzer {
  /**
   * @param {Object} [options]
   * @param {number} [options.windowSize=1000] - Maximum number of events in the analysis window.
   * @param {number} [options.fatigueThreshold=0.7] - Score above which alerting is considered fatigued.
   */
  constructor(options = {}) {
    this.windowSize = options.windowSize || 1000;
    this.fatigueThreshold = options.fatigueThreshold || 0.7;
    this.events = [];
  }

  /**
   * Record an alert event for fatigue analysis.
   * @param {Object} alertEvent - The alert event to record.
   * @param {string} alertEvent.category - Alert category (e.g., 'prompt_injection').
   * @param {string} alertEvent.severity - Severity level ('critical', 'high', 'medium', 'low').
   * @param {string} alertEvent.pattern - The pattern or rule that fired.
   * @param {boolean} [alertEvent.falsePositive=false] - Whether this was a false positive.
   */
  record(alertEvent) {
    const event = {
      category: alertEvent.category || 'unknown',
      severity: alertEvent.severity || 'medium',
      pattern: alertEvent.pattern || 'unknown',
      falsePositive: alertEvent.falsePositive === true,
      timestamp: Date.now()
    };

    this.events.push(event);

    // Trim to window size
    if (this.events.length > this.windowSize) {
      this.events = this.events.slice(this.events.length - this.windowSize);
    }

    return event;
  }

  /**
   * Return the patterns/categories with highest fire rate and lowest true-positive rate.
   * @returns {Array<Object>} Sorted array of noisy sources [{pattern, category, fireCount, falsePositiveRate, truePositiveRate}].
   */
  getTopNoisy() {
    if (this.events.length === 0) return [];

    const patternStats = {};

    for (const event of this.events) {
      const key = `${event.category}::${event.pattern}`;
      if (!patternStats[key]) {
        patternStats[key] = {
          pattern: event.pattern,
          category: event.category,
          fireCount: 0,
          falsePositives: 0
        };
      }
      patternStats[key].fireCount++;
      if (event.falsePositive) {
        patternStats[key].falsePositives++;
      }
    }

    const results = Object.values(patternStats).map(stat => ({
      pattern: stat.pattern,
      category: stat.category,
      fireCount: stat.fireCount,
      falsePositiveRate: stat.fireCount > 0 ? stat.falsePositives / stat.fireCount : 0,
      truePositiveRate: stat.fireCount > 0 ? (stat.fireCount - stat.falsePositives) / stat.fireCount : 1
    }));

    // Sort by highest fire rate and lowest true-positive rate (noisiest first)
    results.sort((a, b) => {
      const noiseA = a.fireCount * a.falsePositiveRate;
      const noiseB = b.fireCount * b.falsePositiveRate;
      return noiseB - noiseA;
    });

    return results;
  }

  /**
   * Calculate a fatigue score from 0 to 1.
   * High fire rate combined with many false positives produces a high fatigue score.
   * @returns {number} Fatigue score between 0 (healthy) and 1 (severely fatigued).
   */
  getFatigueScore() {
    if (this.events.length === 0) return 0;

    const totalEvents = this.events.length;
    const totalFalsePositives = this.events.filter(e => e.falsePositive).length;
    const fpRate = totalFalsePositives / totalEvents;

    // Fire rate: how full is the window relative to capacity
    const fillRate = totalEvents / this.windowSize;

    // Unique pattern count — fewer unique patterns with high volume = more fatigued
    const uniquePatterns = new Set(this.events.map(e => `${e.category}::${e.pattern}`)).size;
    const repetitionFactor = totalEvents > 0 ? 1 - (uniquePatterns / totalEvents) : 0;

    // Weighted combination
    const score = (fpRate * 0.5) + (fillRate * 0.25) + (repetitionFactor * 0.25);

    return Math.min(1, Math.max(0, score));
  }

  /**
   * Generate tuning suggestions to reduce alert fatigue.
   * @returns {Array<Object>} Array of suggestions [{action, target, reason}].
   */
  suggest() {
    const suggestions = [];
    const noisy = this.getTopNoisy();
    const fatigueScore = this.getFatigueScore();

    if (fatigueScore < 0.3) {
      return suggestions; // Alerting is healthy
    }

    for (const source of noisy) {
      if (source.falsePositiveRate > 0.8) {
        // Mostly false positives — suggest disabling
        suggestions.push({
          action: 'disable',
          target: source.pattern,
          reason: `Pattern "${source.pattern}" in category "${source.category}" has ${(source.falsePositiveRate * 100).toFixed(0)}% false positive rate (${source.fireCount} fires).`
        });
      } else if (source.falsePositiveRate > 0.5) {
        // High FP rate — suggest adding allowlist
        suggestions.push({
          action: 'add_allowlist',
          target: source.pattern,
          reason: `Pattern "${source.pattern}" has ${(source.falsePositiveRate * 100).toFixed(0)}% false positive rate. Consider allowlisting common benign matches.`
        });
      } else if (source.fireCount > this.windowSize * 0.1 && source.falsePositiveRate > 0.2) {
        // High volume with moderate FPs — refine the pattern
        suggestions.push({
          action: 'refine_pattern',
          target: source.pattern,
          reason: `Pattern "${source.pattern}" fires frequently (${source.fireCount} times) with ${(source.falsePositiveRate * 100).toFixed(0)}% false positives. Consider tightening the pattern.`
        });
      } else if (source.fireCount > this.windowSize * 0.15) {
        // Very high volume but mostly true positives — lower severity to reduce noise
        suggestions.push({
          action: 'lower_severity',
          target: source.pattern,
          reason: `Pattern "${source.pattern}" fires very frequently (${source.fireCount} times). Consider lowering severity to reduce alert noise.`
        });
      }
    }

    return suggestions;
  }

  /**
   * Reset all recorded events.
   */
  reset() {
    this.events = [];
    console.log('[Agent Shield] AlertFatigueAnalyzer reset.');
  }
}

// =========================================================================
// Auto-Tuner
// =========================================================================

class AutoTuner {
  /**
   * @param {Object} shield - AgentShield instance to tune.
   * @param {Object} [options]
   * @param {boolean} [options.autoApply=false] - Whether to automatically apply suggestions.
   */
  constructor(shield, options = {}) {
    this.shield = shield;
    this.autoApply = options.autoApply || false;
    this.analyzer = new AlertFatigueAnalyzer(options);
    this.history = [];
    this._lastApplied = null;
  }

  /**
   * Run fatigue analysis on the shield's scan history.
   * @returns {Object} Analysis result {fatigueScore, suggestions, topNoisy}.
   */
  analyze() {
    // Pull scan history from the shield if available
    const scanHistory = (this.shield && this.shield.stats && this.shield.stats.history) || [];

    // Feed events into the analyzer
    for (const entry of scanHistory) {
      if (entry.threats && entry.threats.length > 0) {
        for (const threat of entry.threats) {
          this.analyzer.record({
            category: threat.category || 'unknown',
            severity: threat.severity || 'medium',
            pattern: threat.description || threat.pattern || 'unknown',
            falsePositive: threat.falsePositive === true
          });
        }
      }
    }

    const fatigueScore = this.analyzer.getFatigueScore();
    const suggestions = this.analyzer.suggest();
    const topNoisy = this.analyzer.getTopNoisy();

    const result = {
      fatigueScore,
      suggestions,
      topNoisy,
      timestamp: new Date().toISOString()
    };

    if (this.autoApply && suggestions.length > 0) {
      this.apply(suggestions);
      console.log(`[Agent Shield] AutoTuner auto-applied ${suggestions.length} suggestion(s).`);
    }

    return result;
  }

  /**
   * Apply tuning suggestions to the shield config.
   * @param {Array<Object>} suggestions - Array of suggestions from analyze().
   * @returns {Object} Applied changes record.
   */
  apply(suggestions) {
    const applied = {
      timestamp: new Date().toISOString(),
      changes: [],
      previousConfig: this.shield.config ? JSON.parse(JSON.stringify(this.shield.config)) : {}
    };

    for (const suggestion of suggestions) {
      const change = {
        action: suggestion.action,
        target: suggestion.target,
        reason: suggestion.reason
      };

      switch (suggestion.action) {
        case 'disable':
          if (this.shield.config && this.shield.config.disabledPatterns) {
            this.shield.config.disabledPatterns.push(suggestion.target);
          }
          change.applied = true;
          break;

        case 'lower_severity':
          if (this.shield.config && this.shield.config.severityOverrides) {
            this.shield.config.severityOverrides[suggestion.target] = 'low';
          }
          change.applied = true;
          break;

        case 'add_allowlist':
          if (this.shield.config && this.shield.config.allowlist) {
            this.shield.config.allowlist.push({ pattern: suggestion.target, reason: suggestion.reason });
          }
          change.applied = true;
          break;

        case 'refine_pattern':
          // Cannot auto-apply pattern refinement — requires manual review
          change.applied = false;
          change.note = 'Pattern refinement requires manual review.';
          break;

        default:
          change.applied = false;
          break;
      }

      applied.changes.push(change);
    }

    this._lastApplied = applied;
    this.history.push(applied);
    console.log(`[Agent Shield] AutoTuner applied ${applied.changes.filter(c => c.applied).length} change(s).`);

    return applied;
  }

  /**
   * Undo the last applied tuning.
   * @returns {boolean} Whether the revert was successful.
   */
  revert() {
    if (!this._lastApplied) {
      console.log('[Agent Shield] AutoTuner: nothing to revert.');
      return false;
    }

    if (this.shield.config && this._lastApplied.previousConfig) {
      Object.assign(this.shield.config, this._lastApplied.previousConfig);
    }

    const revertRecord = {
      timestamp: new Date().toISOString(),
      action: 'revert',
      reverted: this._lastApplied.timestamp
    };

    this.history.push(revertRecord);
    this._lastApplied = null;
    console.log('[Agent Shield] AutoTuner reverted last tuning.');

    return true;
  }

  /**
   * Get the full tuning history.
   * @returns {Array<Object>} Array of applied/reverted tuning records.
   */
  getHistory() {
    return [...this.history];
  }
}

// =========================================================================
// Alert Correlator
// =========================================================================

class AlertCorrelator {
  /**
   * @param {Object} [options]
   * @param {number} [options.timeWindowMs=60000] - Time window for correlating alerts (default: 1 minute).
   */
  constructor(options = {}) {
    this.timeWindowMs = options.timeWindowMs || 60000;
    this._internalPatterns = [];
  }

  /**
   * Group related alerts by time proximity and category.
   * @param {Array<Object>} alerts - Array of alert objects with timestamp and category.
   * @returns {Array<Object>} Array of correlated groups [{alerts, category, startTime, endTime, count}].
   */
  correlate(alerts) {
    if (!alerts || alerts.length === 0) return [];

    // Sort by timestamp
    const sorted = [...alerts].sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0));

    const groups = [];
    let currentGroup = null;

    for (const alert of sorted) {
      const ts = alert.timestamp || 0;
      const cat = alert.category || 'unknown';

      if (
        currentGroup &&
        currentGroup.category === cat &&
        ts - currentGroup.endTime <= this.timeWindowMs
      ) {
        // Extend current group
        currentGroup.alerts.push(alert);
        currentGroup.endTime = ts;
        currentGroup.count++;
      } else {
        // Start a new group
        if (currentGroup) groups.push(currentGroup);
        currentGroup = {
          alerts: [alert],
          category: cat,
          startTime: ts,
          endTime: ts,
          count: 1
        };
      }
    }

    if (currentGroup) groups.push(currentGroup);

    // Track patterns for getPatterns()
    this._updatePatterns(groups);

    return groups;
  }

  /**
   * Remove duplicate alerts within the time window.
   * Alerts are considered duplicates if they share the same category and pattern within the window.
   * @param {Array<Object>} alerts - Array of alert objects.
   * @returns {Array<Object>} Deduplicated alerts.
   */
  deduplicate(alerts) {
    if (!alerts || alerts.length === 0) return [];

    const sorted = [...alerts].sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0));
    const result = [];
    const seen = new Map();

    for (const alert of sorted) {
      const key = `${alert.category || 'unknown'}::${alert.pattern || 'unknown'}`;
      const ts = alert.timestamp || 0;

      const lastSeen = seen.get(key);
      if (lastSeen === undefined || ts - lastSeen > this.timeWindowMs) {
        result.push(alert);
        seen.set(key, ts);
      }
    }

    return result;
  }

  /**
   * Return recurring alert patterns observed from correlated groups.
   * @returns {Array<Object>} Recurring patterns [{category, avgGroupSize, frequency, firstSeen, lastSeen}].
   */
  getPatterns() {
    return [...this._internalPatterns];
  }

  /**
   * Update internal pattern tracking from correlated groups.
   * @private
   * @param {Array<Object>} groups - Correlated alert groups.
   */
  _updatePatterns(groups) {
    const patternMap = {};

    for (const group of groups) {
      const cat = group.category;
      if (!patternMap[cat]) {
        patternMap[cat] = {
          category: cat,
          groupSizes: [],
          firstSeen: group.startTime,
          lastSeen: group.endTime
        };
      }

      patternMap[cat].groupSizes.push(group.count);
      if (group.startTime < patternMap[cat].firstSeen) {
        patternMap[cat].firstSeen = group.startTime;
      }
      if (group.endTime > patternMap[cat].lastSeen) {
        patternMap[cat].lastSeen = group.endTime;
      }
    }

    this._internalPatterns = Object.values(patternMap).map(p => ({
      category: p.category,
      avgGroupSize: p.groupSizes.reduce((a, b) => a + b, 0) / p.groupSizes.length,
      frequency: p.groupSizes.length,
      firstSeen: p.firstSeen,
      lastSeen: p.lastSeen
    }));
  }
}

// =========================================================================
// Exports
// =========================================================================

module.exports = {
  AlertFatigueAnalyzer,
  AutoTuner,
  AlertCorrelator
};
