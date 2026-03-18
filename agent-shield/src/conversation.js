'use strict';

/**
 * Conversation Tracking: Payload Fragmentation (#13), Language Switching (#35),
 * Token Budget Analysis (#34), Instruction Hierarchy (#36),
 * and Behavioral Fingerprinting (#38)
 */

const { scanText } = require('./detector-core');

// =========================================================================
// PAYLOAD FRAGMENTATION DETECTOR
// =========================================================================

class FragmentationDetector {
  /**
   * Tracks messages over time and scans sliding windows to catch
   * injections split across multiple messages.
   *
   * @param {object} [options]
   * @param {number} [options.windowSize=5] - Number of messages in sliding window.
   * @param {number} [options.maxHistory=50] - Maximum messages to retain.
   * @param {Function} [options.onDetection] - Callback when fragmented injection detected.
   */
  constructor(options = {}) {
    this.windowSize = options.windowSize || 5;
    this.maxHistory = options.maxHistory || 50;
    this.onDetection = options.onDetection || null;
    this.messages = [];
  }

  /**
   * Adds a message and scans sliding windows for fragmented injections.
   *
   * @param {string} text - The message text.
   * @param {string} [source='user'] - Who sent the message.
   * @returns {object} { fragmented: boolean, threats: Array }
   */
  addMessage(text, source = 'user') {
    this.messages.push({ text, source, timestamp: Date.now() });
    if (this.messages.length > this.maxHistory) {
      this.messages.shift();
    }

    // Scan individual message
    const singleResult = scanText(text, { source, sensitivity: 'high' });

    // Scan sliding window (combine recent messages)
    const windowMessages = this.messages.slice(-this.windowSize);
    const combinedText = windowMessages.map(m => m.text).join(' ');
    const windowResult = scanText(combinedText, { source: 'conversation_window', sensitivity: 'high' });

    // Fragmented injection = window catches what individual messages don't
    const newThreats = windowResult.threats.filter(wt =>
      !singleResult.threats.some(st =>
        st.category === wt.category && st.detail === wt.detail
      )
    );

    const fragmentedThreats = newThreats.map(t => ({
      ...t,
      fragmented: true,
      description: `Fragmented attack: ${t.description} (split across ${this.windowSize} messages)`,
      windowSize: windowMessages.length
    }));

    if (fragmentedThreats.length > 0 && this.onDetection) {
      this.onDetection({ threats: fragmentedThreats, window: windowMessages });
    }

    return {
      fragmented: fragmentedThreats.length > 0,
      threats: [...singleResult.threats, ...fragmentedThreats],
      singleThreats: singleResult.threats,
      fragmentedThreats
    };
  }

  getHistory() {
    return [...this.messages];
  }

  reset() {
    this.messages = [];
  }
}

// =========================================================================
// LANGUAGE SWITCHING DETECTOR
// =========================================================================

/**
 * Unicode block ranges for detecting script changes.
 */
const SCRIPT_RANGES = {
  latin: /[\u0000-\u024F]/,
  cyrillic: /[\u0400-\u04FF]/,
  chinese: /[\u4E00-\u9FFF]/,
  japanese_hiragana: /[\u3040-\u309F]/,
  japanese_katakana: /[\u30A0-\u30FF]/,
  korean: /[\uAC00-\uD7AF]/,
  arabic: /[\u0600-\u06FF]/,
  devanagari: /[\u0900-\u097F]/,
  thai: /[\u0E00-\u0E7F]/
};

class LanguageSwitchDetector {
  /**
   * @param {object} [options]
   * @param {Function} [options.onSwitch] - Callback when language switch detected.
   */
  constructor(options = {}) {
    this.onSwitch = options.onSwitch || null;
    this.history = [];
  }

  /**
   * Analyzes text for the dominant script and tracks changes.
   *
   * @param {string} text
   * @returns {object} { scripts: Array, switched: boolean, dominantScript: string, suspiciousSwitch: boolean }
   */
  analyze(text) {
    if (!text) return { scripts: [], switched: false, dominantScript: null, suspiciousSwitch: false };

    const scripts = this._detectScripts(text);
    const dominantScript = scripts.length > 0 ? scripts[0].script : 'unknown';

    this.history.push({ dominantScript, scripts, timestamp: Date.now() });
    if (this.history.length > 50) this.history.shift();

    // Check for switch from previous message
    let switched = false;
    let suspiciousSwitch = false;

    if (this.history.length >= 2) {
      const prev = this.history[this.history.length - 2];
      switched = prev.dominantScript !== dominantScript && prev.dominantScript !== 'unknown' && dominantScript !== 'unknown';

      // Suspicious: switching to a language with known injection patterns
      if (switched) {
        const suspiciousTargets = ['cyrillic', 'chinese', 'japanese_hiragana', 'japanese_katakana', 'arabic'];
        suspiciousSwitch = suspiciousTargets.includes(dominantScript);

        if (suspiciousSwitch && this.onSwitch) {
          this.onSwitch({
            from: prev.dominantScript,
            to: dominantScript,
            text: text.substring(0, 200),
            timestamp: Date.now()
          });
        }
      }
    }

    // Check for mixed scripts within a single message (possible homoglyph attack)
    const mixedScripts = scripts.length > 1 && scripts[0].percentage < 90;

    return {
      scripts,
      switched,
      dominantScript,
      suspiciousSwitch,
      mixedScripts,
      multipleScripts: scripts.map(s => s.script)
    };
  }

  /** @private */
  _detectScripts(text) {
    const counts = {};
    let total = 0;

    for (const char of text) {
      if (/\s/.test(char)) continue;
      total++;
      for (const [script, range] of Object.entries(SCRIPT_RANGES)) {
        if (range.test(char)) {
          counts[script] = (counts[script] || 0) + 1;
          break;
        }
      }
    }

    if (total === 0) return [];

    return Object.entries(counts)
      .map(([script, count]) => ({ script, count, percentage: Math.round((count / total) * 100) }))
      .sort((a, b) => b.count - a.count);
  }

  reset() {
    this.history = [];
  }
}

// =========================================================================
// TOKEN BUDGET ANALYZER
// =========================================================================

class TokenBudgetAnalyzer {
  /**
   * Monitors input sizes to detect padding/context-stuffing attacks.
   *
   * @param {object} [options]
   * @param {number} [options.maxTokens=4096] - Expected max token budget.
   * @param {number} [options.avgCharsPerToken=4] - Rough chars-per-token estimate.
   * @param {number} [options.warningThreshold=0.7] - Warn at this % of budget.
   * @param {number} [options.criticalThreshold=0.9] - Critical at this % of budget.
   * @param {Function} [options.onWarning] - Callback on warning.
   */
  constructor(options = {}) {
    this.maxTokens = options.maxTokens || 4096;
    this.avgCharsPerToken = options.avgCharsPerToken || 4;
    this.warningThreshold = options.warningThreshold || 0.7;
    this.criticalThreshold = options.criticalThreshold || 0.9;
    this.onWarning = options.onWarning || null;
    this.totalCharsConsumed = 0;
  }

  /**
   * Analyzes input size relative to token budget.
   *
   * @param {string} text - Input text.
   * @returns {object} { estimatedTokens, budgetUsed, status, warning }
   */
  analyze(text) {
    if (!text) return { estimatedTokens: 0, budgetUsed: 0, status: 'safe', warning: null };

    const estimatedTokens = Math.ceil(text.length / this.avgCharsPerToken);
    this.totalCharsConsumed += text.length;
    const totalEstimatedTokens = Math.ceil(this.totalCharsConsumed / this.avgCharsPerToken);
    const budgetUsed = totalEstimatedTokens / this.maxTokens;

    let status = 'safe';
    let warning = null;

    if (budgetUsed >= this.criticalThreshold) {
      status = 'critical';
      warning = `Token budget ${Math.round(budgetUsed * 100)}% consumed. Possible context-stuffing attack.`;
    } else if (budgetUsed >= this.warningThreshold) {
      status = 'warning';
      warning = `Token budget ${Math.round(budgetUsed * 100)}% consumed. Approaching limit.`;
    }

    // Detect suspiciously large single inputs
    const singleInputRatio = estimatedTokens / this.maxTokens;
    let paddingAttack = false;
    if (singleInputRatio > 0.5) {
      paddingAttack = true;
      warning = `Single input uses ${Math.round(singleInputRatio * 100)}% of token budget. Possible padding attack.`;
      status = 'critical';
    }

    if (warning && this.onWarning) {
      this.onWarning({ status, warning, budgetUsed, estimatedTokens });
    }

    return {
      estimatedTokens,
      totalEstimatedTokens,
      budgetUsed: Math.round(budgetUsed * 100) / 100,
      status,
      warning,
      paddingAttack
    };
  }

  reset() {
    this.totalCharsConsumed = 0;
  }
}

// =========================================================================
// INSTRUCTION HIERARCHY ENFORCER
// =========================================================================

class InstructionHierarchy {
  /**
   * Enforces a strict priority order: system > developer > user.
   * Flags inputs that attempt to contradict higher-priority instructions.
   *
   * @param {object} [options]
   * @param {Array<string>} [options.systemRules=[]] - Immutable system rules.
   * @param {Array<string>} [options.developerRules=[]] - Developer-defined rules.
   * @param {Function} [options.onViolation] - Callback on hierarchy violation.
   */
  constructor(options = {}) {
    this.systemRules = options.systemRules || [];
    this.developerRules = options.developerRules || [];
    this.onViolation = options.onViolation || null;
  }

  /**
   * Checks if user input contradicts system or developer rules.
   *
   * @param {string} text - User input.
   * @returns {object} { allowed: boolean, violations: Array }
   */
  check(text) {
    if (!text) return { allowed: true, violations: [] };

    const violations = [];
    const lower = text.toLowerCase();

    // Check against system rules
    for (const rule of this.systemRules) {
      const negated = this._findNegation(lower, rule.toLowerCase());
      if (negated) {
        violations.push({
          level: 'system',
          rule,
          severity: 'critical',
          description: `User input contradicts system rule: "${rule}"`
        });
      }
    }

    // Check against developer rules
    for (const rule of this.developerRules) {
      const negated = this._findNegation(lower, rule.toLowerCase());
      if (negated) {
        violations.push({
          level: 'developer',
          rule,
          severity: 'high',
          description: `User input contradicts developer rule: "${rule}"`
        });
      }
    }

    if (violations.length > 0 && this.onViolation) {
      this.onViolation({ violations, text: text.substring(0, 200) });
    }

    return { allowed: violations.length === 0, violations };
  }

  /**
   * Checks if text contains a negation or contradiction of a rule.
   * @private
   */
  _findNegation(text, rule) {
    // Extract key phrases from the rule
    const words = rule.split(/\s+/).filter(w => w.length > 3);
    if (words.length === 0) return false;

    // Check if text mentions the rule topic with negation
    const ruleKeywords = words.slice(0, 5).join('|');
    const negationPattern = new RegExp(
      `(?:don'?t|do\\s+not|never|stop|disable|remove|ignore|skip|bypass|override)\\s+.*(?:${ruleKeywords})`,
      'i'
    );

    return negationPattern.test(text);
  }
}

// =========================================================================
// BEHAVIORAL FINGERPRINT
// =========================================================================

class BehavioralFingerprint {
  /**
   * Learns normal behavior patterns and flags anomalies.
   *
   * @param {object} [options]
   * @param {number} [options.learningPeriod=50] - Number of events before flagging anomalies.
   * @param {number} [options.stdDevThreshold=2] - Standard deviations for anomaly threshold.
   * @param {Function} [options.onAnomaly] - Callback on anomaly detection.
   */
  constructor(options = {}) {
    this.learningPeriod = options.learningPeriod || 50;
    this.stdDevThreshold = options.stdDevThreshold || 2;
    this.onAnomaly = options.onAnomaly || null;

    this.metrics = {
      inputLengths: [],
      responseTimesMs: [],
      toolCallFrequency: {},
      threatFrequency: []
    };
  }

  /**
   * Records an event and checks for anomalies.
   *
   * @param {object} event
   * @param {number} [event.inputLength] - Length of input text.
   * @param {number} [event.responseTimeMs] - Response time in ms.
   * @param {string} [event.toolName] - Tool that was called.
   * @param {number} [event.threatCount=0] - Number of threats detected.
   * @returns {object} { anomalies: Array, isLearning: boolean }
   */
  record(event) {
    const anomalies = [];
    const isLearning = this.metrics.inputLengths.length < this.learningPeriod;

    if (event.inputLength !== undefined) {
      this.metrics.inputLengths.push(event.inputLength);
      if (!isLearning) {
        const stats = this._calcStats(this.metrics.inputLengths.slice(0, -1));
        if (Math.abs(event.inputLength - stats.mean) > stats.stdDev * this.stdDevThreshold) {
          anomalies.push({
            type: 'input_length',
            value: event.inputLength,
            expected: `${Math.round(stats.mean)} ± ${Math.round(stats.stdDev * this.stdDevThreshold)}`,
            severity: 'medium',
            description: `Unusual input length: ${event.inputLength} chars (normal: ~${Math.round(stats.mean)})`
          });
        }
      }
    }

    if (event.responseTimeMs !== undefined) {
      this.metrics.responseTimesMs.push(event.responseTimeMs);
    }

    if (event.toolName) {
      this.metrics.toolCallFrequency[event.toolName] = (this.metrics.toolCallFrequency[event.toolName] || 0) + 1;
    }

    if (event.threatCount !== undefined) {
      this.metrics.threatFrequency.push(event.threatCount);
      if (!isLearning && event.threatCount > 0) {
        const recentThreats = this.metrics.threatFrequency.slice(-10);
        const avgThreats = recentThreats.reduce((a, b) => a + b, 0) / recentThreats.length;
        if (avgThreats > 2) {
          anomalies.push({
            type: 'threat_spike',
            value: avgThreats,
            severity: 'high',
            description: `Sustained threat spike: avg ${avgThreats.toFixed(1)} threats per input over last 10 inputs.`
          });
        }
      }
    }

    // Cap stored metrics
    const maxMetrics = 500;
    if (this.metrics.inputLengths.length > maxMetrics) this.metrics.inputLengths = this.metrics.inputLengths.slice(-maxMetrics);
    if (this.metrics.responseTimesMs.length > maxMetrics) this.metrics.responseTimesMs = this.metrics.responseTimesMs.slice(-maxMetrics);
    if (this.metrics.threatFrequency.length > maxMetrics) this.metrics.threatFrequency = this.metrics.threatFrequency.slice(-maxMetrics);

    if (anomalies.length > 0 && this.onAnomaly) {
      this.onAnomaly({ anomalies, timestamp: Date.now() });
    }

    return { anomalies, isLearning };
  }

  /** @private */
  _calcStats(values) {
    if (values.length === 0) return { mean: 0, stdDev: 0 };
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const variance = values.reduce((sum, v) => sum + (v - mean) ** 2, 0) / values.length;
    return { mean, stdDev: Math.sqrt(variance) };
  }

  getProfile() {
    const inputStats = this._calcStats(this.metrics.inputLengths);
    const responseStats = this._calcStats(this.metrics.responseTimesMs);
    return {
      sampleSize: this.metrics.inputLengths.length,
      isLearning: this.metrics.inputLengths.length < this.learningPeriod,
      avgInputLength: Math.round(inputStats.mean),
      avgResponseTimeMs: Math.round(responseStats.mean),
      topTools: Object.entries(this.metrics.toolCallFrequency)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([tool, count]) => ({ tool, count }))
    };
  }

  reset() {
    this.metrics = { inputLengths: [], responseTimesMs: [], toolCallFrequency: {}, threatFrequency: [] };
  }
}

module.exports = {
  FragmentationDetector,
  LanguageSwitchDetector,
  TokenBudgetAnalyzer,
  InstructionHierarchy,
  BehavioralFingerprint
};
