'use strict';

/**
 * Agent Shield — Context-Aware Scoring (v1.2)
 *
 * Analyzes conversation history to detect multi-turn attacks, escalation
 * patterns, and contextual threats that single-message scanning misses.
 *
 * All processing runs locally — no data ever leaves your environment.
 */

const { scanText } = require('./detector-core');

// =========================================================================
// ESCALATION PATTERNS
// =========================================================================

/**
 * Patterns that indicate multi-turn escalation when seen in sequence.
 */
const ESCALATION_SIGNALS = [
  { phase: 'rapport', patterns: [/how are you/i, /can you help/i, /i have a question/i, /you seem/i], weight: 0.1 },
  { phase: 'boundary_test', patterns: [/can you.*if i asked/i, /hypothetically/i, /what would happen/i, /in theory/i, /would you be able to/i], weight: 0.3 },
  { phase: 'authority_claim', patterns: [/i am.*(?:admin|developer|owner|creator)/i, /i have permission/i, /i'm authorized/i, /my boss said/i], weight: 0.5 },
  { phase: 'soft_override', patterns: [/just this once/i, /make an exception/i, /no one will know/i, /it's for testing/i, /it's okay to/i], weight: 0.6 },
  { phase: 'direct_attack', patterns: [/ignore.*instructions/i, /override.*safety/i, /you are now/i, /jailbreak/i, /forget.*training/i], weight: 1.0 }
];

/**
 * Suspicious topic pivots that may indicate an attack setup.
 */
const TOPIC_PIVOT_SIGNALS = [
  { from: /(?:weather|sports|cooking|travel|homework)/i, to: /(?:system|prompt|instructions|override|ignore|bypass)/i, severity: 'high' },
  { from: /(?:coding|programming|help|debug)/i, to: /(?:admin|root|password|secret|credential)/i, severity: 'medium' },
];

// =========================================================================
// CONVERSATION CONTEXT ANALYZER
// =========================================================================

/**
 * Maintains conversation state and provides context-aware threat scoring.
 */
class ConversationContextAnalyzer {
  /**
   * @param {object} [options]
   * @param {number} [options.maxHistory=50] - Maximum messages to retain.
   * @param {number} [options.escalationThreshold=0.6] - Threshold for flagging escalation.
   * @param {number} [options.decayFactor=0.9] - Weight decay for older messages.
   * @param {boolean} [options.trackTopics=true] - Enable topic pivot detection.
   */
  constructor(options = {}) {
    this.maxHistory = options.maxHistory || 50;
    this.escalationThreshold = options.escalationThreshold || 0.6;
    this.decayFactor = options.decayFactor || 0.9;
    this.trackTopics = options.trackTopics !== false;

    this._history = [];
    this._escalationScore = 0;
    this._phasesDetected = new Set();
    this._threatCount = 0;
    this._sessionStart = Date.now();
    this._topicHistory = [];

    console.log('[Agent Shield] ConversationContextAnalyzer initialized (maxHistory: %d, threshold: %s)', this.maxHistory, this.escalationThreshold);
  }

  /**
   * Add a message and analyze it in context.
   *
   * @param {string} text - The message text.
   * @param {string} [role='user'] - Message role: 'user', 'assistant', 'system'.
   * @returns {object} Context-aware analysis result.
   */
  addMessage(text, role = 'user') {
    const timestamp = Date.now();
    const patternResult = scanText(text, { source: `conversation_${role}`, sensitivity: 'high' });

    const message = {
      text: text.substring(0, 5000),
      role,
      timestamp,
      threats: patternResult.threats,
      status: patternResult.status
    };

    this._history.push(message);

    // Trim history
    if (this._history.length > this.maxHistory) {
      this._history = this._history.slice(-this.maxHistory);
    }

    if (patternResult.threats.length > 0) {
      this._threatCount++;
    }

    // Only analyze user messages for escalation
    if (role !== 'user') {
      return {
        message,
        escalation: this._getEscalationState(),
        contextScore: this._calculateContextScore(message),
        patternResult
      };
    }

    // Detect escalation phase
    this._updateEscalation(text);

    // Detect topic pivots
    const pivot = this._detectTopicPivot(text);

    // Calculate context-aware score
    const contextScore = this._calculateContextScore(message);

    // Check for velocity anomalies (many messages in short time)
    const velocity = this._checkVelocity();

    // Check for repetition patterns (probing)
    const repetition = this._checkRepetition(text);

    const result = {
      message,
      escalation: this._getEscalationState(),
      contextScore,
      patternResult,
      pivot,
      velocity,
      repetition,
      recommendation: this._recommend(contextScore, patternResult)
    };

    return result;
  }

  /**
   * Get the current escalation state.
   * @returns {object} { score, phases, isEscalating, threatCount }
   */
  _getEscalationState() {
    return {
      score: Math.round(this._escalationScore * 100) / 100,
      phases: [...this._phasesDetected],
      isEscalating: this._escalationScore >= this.escalationThreshold,
      threatCount: this._threatCount,
      messageCount: this._history.length
    };
  }

  /**
   * Scan text with full conversation context applied.
   *
   * @param {string} text - New message to scan.
   * @returns {object} Enhanced scan result with context.
   */
  contextualScan(text) {
    const analysis = this.addMessage(text, 'user');
    const { patternResult, contextScore, escalation, pivot } = analysis;

    // Elevate severity based on context
    const contextThreats = [...patternResult.threats];

    if (escalation.isEscalating && patternResult.threats.length === 0) {
      contextThreats.push({
        severity: 'medium',
        category: 'multi_turn_escalation',
        description: 'This conversation shows a multi-turn escalation pattern consistent with social engineering.',
        detail: `Escalation score: ${escalation.score.toFixed(2)}, phases detected: [${escalation.phases.join(', ')}]`,
        confidence: Math.round(escalation.score * 100),
        confidenceLabel: escalation.score >= 0.8 ? 'Very likely a threat' : 'Likely a threat'
      });
    }

    if (pivot) {
      contextThreats.push({
        severity: pivot.severity,
        category: 'topic_pivot',
        description: 'Sudden topic shift from benign to security-sensitive subjects detected.',
        detail: `Topic pivot from "${pivot.fromTopic}" to security-sensitive content.`,
        confidence: 70,
        confidenceLabel: 'Likely a threat'
      });
    }

    const status = contextThreats.some(t => t.severity === 'critical') ? 'danger'
      : contextThreats.some(t => t.severity === 'high') ? 'warning'
      : contextThreats.length > 0 ? 'caution'
      : 'safe';

    return {
      status,
      threats: contextThreats,
      stats: {
        totalThreats: contextThreats.length,
        critical: contextThreats.filter(t => t.severity === 'critical').length,
        high: contextThreats.filter(t => t.severity === 'high').length,
        medium: contextThreats.filter(t => t.severity === 'medium').length,
        low: contextThreats.filter(t => t.severity === 'low').length,
        scanTimeMs: patternResult.stats.scanTimeMs
      },
      context: {
        escalation,
        contextScore,
        messageCount: this._history.length,
        sessionDurationMs: Date.now() - this._sessionStart
      },
      timestamp: Date.now()
    };
  }

  /**
   * Get conversation summary and threat statistics.
   * @returns {object}
   */
  getSummary() {
    const userMessages = this._history.filter(m => m.role === 'user');
    const threatMessages = userMessages.filter(m => m.threats.length > 0);

    return {
      totalMessages: this._history.length,
      userMessages: userMessages.length,
      threatMessages: threatMessages.length,
      threatRate: userMessages.length > 0 ? threatMessages.length / userMessages.length : 0,
      escalation: this._getEscalationState(),
      sessionDurationMs: Date.now() - this._sessionStart,
      phasesDetected: [...this._phasesDetected]
    };
  }

  /**
   * Reset the conversation context.
   */
  reset() {
    this._history = [];
    this._escalationScore = 0;
    this._phasesDetected.clear();
    this._threatCount = 0;
    this._sessionStart = Date.now();
    this._topicHistory = [];
  }

  /** @private */
  _updateEscalation(text) {
    for (const signal of ESCALATION_SIGNALS) {
      for (const pattern of signal.patterns) {
        if (pattern.test(text)) {
          this._phasesDetected.add(signal.phase);
          // Escalation score increases with phase weight, with decay
          this._escalationScore = Math.max(this._escalationScore, signal.weight);
          // Bonus for progressing through phases
          if (this._phasesDetected.size > 1) {
            this._escalationScore = Math.min(1, this._escalationScore + 0.1 * this._phasesDetected.size);
          }
          break;
        }
      }
    }
  }

  /** @private */
  _detectTopicPivot(text) {
    if (!this.trackTopics || this._history.length < 2) return null;

    const recentUser = this._history
      .filter(m => m.role === 'user')
      .slice(-3);

    if (recentUser.length < 2) return null;

    const previousText = recentUser.slice(0, -1).map(m => m.text).join(' ');

    for (const signal of TOPIC_PIVOT_SIGNALS) {
      if (signal.from.test(previousText) && signal.to.test(text)) {
        return {
          severity: signal.severity,
          fromTopic: previousText.substring(0, 50),
          toTopic: text.substring(0, 50)
        };
      }
    }

    return null;
  }

  /** @private */
  _calculateContextScore(message) {
    let score = 0;

    // Base score from current message threats
    if (message.threats.length > 0) score += 0.4;

    // Escalation contribution
    score += this._escalationScore * 0.3;

    // Threat frequency in recent history
    const recentThreats = this._history.slice(-10).filter(m => m.threats.length > 0).length;
    score += (recentThreats / 10) * 0.2;

    // Velocity factor
    const recentMessages = this._history.filter(m => (Date.now() - m.timestamp) < 60000);
    if (recentMessages.length > 10) score += 0.1;

    return Math.min(1, Math.round(score * 100) / 100);
  }

  /** @private */
  _checkVelocity() {
    const oneMinuteAgo = Date.now() - 60000;
    const recentCount = this._history.filter(m => m.timestamp > oneMinuteAgo && m.role === 'user').length;
    return {
      messagesPerMinute: recentCount,
      isAnomalous: recentCount > 15
    };
  }

  /** @private */
  _checkRepetition(text) {
    // Exclude the last message (just added) to avoid self-matching
    const recent = this._history.slice(-11, -1).filter(m => m.role === 'user');
    const lowerText = text.toLowerCase().substring(0, 200);
    let similarCount = 0;

    for (const msg of recent) {
      const lowerMsg = msg.text.toLowerCase().substring(0, 200);
      if (lowerMsg === lowerText) {
        similarCount++;
      } else {
        // Simple word overlap check
        const wordsA = new Set(lowerText.split(/\s+/));
        const wordsB = new Set(lowerMsg.split(/\s+/));
        const intersection = [...wordsA].filter(w => wordsB.has(w)).length;
        const union = new Set([...wordsA, ...wordsB]).size;
        if (union > 0 && intersection / union > 0.7) similarCount++;
      }
    }

    return {
      similarMessages: similarCount,
      isProbing: similarCount >= 3
    };
  }

  /** @private */
  _recommend(contextScore, patternResult) {
    if (contextScore >= 0.8 || patternResult.stats.critical > 0) return 'block';
    if (contextScore >= 0.5 || patternResult.stats.high > 0) return 'review';
    if (contextScore >= 0.3 || patternResult.threats.length > 0) return 'monitor';
    return 'allow';
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
  ConversationContextAnalyzer,
  ESCALATION_SIGNALS,
  TOPIC_PIVOT_SIGNALS
};
