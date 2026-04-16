'use strict';

/**
 * Agent Shield — Multi-Turn Attack Detection (v12)
 *
 * Detects attacks that unfold across multiple conversation turns:
 * gradual trust erosion, progressive boundary testing, multi-turn
 * grooming, topic drift toward sensitive areas, and authority
 * accumulation over time.
 *
 * Ref: Nature Communications — LRMs achieve 97% jailbreak success
 * via planned multi-turn attacks.
 *
 * All processing runs locally — no data ever leaves your environment.
 *
 * @module cross-turn
 */

const { scanText } = require('./detector-core');

// =========================================================================
// CONSTANTS
// =========================================================================

/** Escalation signals — phrases that indicate progressive boundary pushing. */
const ESCALATION_SIGNALS = [
  /(?:now\s+that\s+we've\s+established|building\s+on\s+(?:that|what\s+you\s+said)|since\s+you\s+(?:agreed|confirmed|said))/i,
  /(?:great,?\s+now\s+(?:let's|can\s+you)|okay\s+(?:good|perfect),?\s+(?:now|next))/i,
  /(?:one\s+more\s+(?:thing|question|step)|just\s+one\s+(?:last|final)\s+(?:thing|question))/i,
  /(?:can\s+you\s+go\s+(?:a\s+little\s+)?(?:further|deeper)|take\s+(?:it|this)\s+(?:a\s+step\s+)?further)/i,
  /(?:you\s+(?:just|already)\s+(?:showed|told|gave)\s+me|you\s+(?:were|seemed)\s+(?:willing|happy)\s+to)/i,
  // Crescendo attack patterns — benign start that gradually escalates
  /(?:hypothetically|in\s+theory|for\s+(?:educational|research|academic)\s+purposes)/i,
  /(?:let's\s+(?:say|imagine|pretend)|what\s+if\s+(?:someone|a\s+person|we))/i,
  /(?:I\s+(?:know|understand)\s+you\s+(?:can't|shouldn't)\s+but|normally\s+you\s+(?:wouldn't|can't)\s+but)/i,
  /(?:you\s+(?:helped|assisted)\s+(?:me|us)\s+(?:before|last\s+time|earlier)\s+with\s+(?:something\s+)?similar)/i,
  /(?:this\s+is\s+(?:similar|related)\s+to\s+what\s+(?:you|we)\s+(?:did|discussed))/i,
];

/** Trust erosion patterns — attempts to lower the model's guard over turns. */
const TRUST_EROSION_PATTERNS = [
  /(?:we're\s+(?:friends|on\s+the\s+same\s+team|collaborating)|I\s+thought\s+we\s+had\s+(?:a\s+good|an?\s+understanding))/i,
  /(?:you\s+(?:can|should)\s+trust\s+me|I\s+(?:promise|swear)\s+(?:this|I)\s+(?:is|am)\s+(?:safe|legitimate))/i,
  /(?:between\s+(?:you\s+and\s+me|us)|this\s+(?:is|stays)\s+(?:just\s+)?between\s+us)/i,
];

/** Topic categories with sensitivity levels. */
const TOPIC_SENSITIVITY = {
  safe: /(?:weather|food|sports|music|movies|travel|recipes|pets|hobbies|games)/i,
  moderate: /(?:coding|programming|math|science|history|business|education|health)/i,
  sensitive: /(?:security|credentials?|passwords?|tokens?|secrets?|keys?|prompt|instructions?|admin|root|config)/i,
  dangerous: /(?:hack(?:ing)?|exploit|attack|bypass|override|jailbreak|injection|exfiltrat)/i,
};

// =========================================================================
// ConversationTracker
// =========================================================================

/**
 * Tracks a multi-turn conversation and detects progressive attacks.
 */
class ConversationTracker {
  /**
   * @param {object} [options]
   * @param {number} [options.maxTurns=100] - Max turns to track.
   * @param {number} [options.escalationThreshold=3] - Escalation signals before alert.
   * @param {number} [options.topicDriftThreshold=0.6] - Topic drift score to alert (0-1).
   */
  constructor(options = {}) {
    this.maxTurns = options.maxTurns || 100;
    this.escalationThreshold = options.escalationThreshold || 3;
    this.topicDriftThreshold = options.topicDriftThreshold || 0.6;

    /** @type {Array<{ role: string, content: string, timestamp: number, threats: any[], topic: string, escalationSignals: number, trustErosion: boolean }>} */
    this.turns = [];
    this.alerts = [];
    this.stats = { turnsProcessed: 0, alertsGenerated: 0, escalationSignals: 0, topicDrifts: 0 };
  }

  /**
   * Add a conversation turn and analyze for multi-turn attack patterns.
   *
   * @param {string} role - 'user' or 'assistant'.
   * @param {string} content - Message content.
   * @returns {{ safe: boolean, alerts: Array<object>, turnAnalysis: object }}
   */
  addTurn(role, content) {
    const safeContent = (content && typeof content === 'string') ? content : '';
    const threats = scanText(safeContent).threats || [];
    const topic = this._classifyTopic(safeContent);
    const escalationSignals = this._countEscalationSignals(safeContent);
    const trustErosion = this._detectTrustErosion(safeContent);

    const turn = {
      role,
      content: safeContent.substring(0, 1000),
      timestamp: Date.now(),
      threats,
      topic,
      escalationSignals,
      trustErosion,
      turnIndex: this.turns.length
    };

    this.turns.push(turn);
    this.stats.turnsProcessed++;
    this.stats.escalationSignals += escalationSignals;

    // Trim to max turns
    if (this.turns.length > this.maxTurns) {
      this.turns = this.turns.slice(-this.maxTurns);
    }

    // Run multi-turn analysis
    const turnAlerts = [];

    // 1. Escalation detection — too many escalation signals in recent turns
    if (role === 'user') {
      const recentEscalation = this._getRecentEscalationCount(5);
      if (recentEscalation >= this.escalationThreshold) {
        turnAlerts.push({
          type: 'multi_turn_escalation',
          severity: 'high',
          turnIndex: turn.turnIndex,
          escalationCount: recentEscalation,
          description: `Detected ${recentEscalation} escalation signals in last 5 turns. Possible multi-turn grooming attack.`
        });
      }
    }

    // 2. Topic drift toward sensitive/dangerous areas
    const topicDrift = this._measureTopicDrift();
    if (topicDrift.drifted) {
      turnAlerts.push({
        type: 'topic_drift_to_sensitive',
        severity: topicDrift.toLevel === 'dangerous' ? 'critical' : 'high',
        turnIndex: turn.turnIndex,
        fromTopic: topicDrift.from,
        toTopic: topicDrift.to,
        description: `Conversation drifted from ${topicDrift.from} to ${topicDrift.to} topics over ${topicDrift.overTurns} turns.`
      });
      this.stats.topicDrifts++;
    }

    // 3. Trust erosion accumulation
    if (trustErosion) {
      const recentTrustErosion = this.turns.slice(-5).filter(t => t.trustErosion).length;
      if (recentTrustErosion >= 2) {
        turnAlerts.push({
          type: 'trust_erosion',
          severity: 'high',
          turnIndex: turn.turnIndex,
          count: recentTrustErosion,
          description: `Detected ${recentTrustErosion} trust erosion attempts in last 5 turns. Attacker building false rapport.`
        });
      }
    }

    // 4. Progressive boundary testing — benign → threat pattern
    if (threats.length > 0 && this.turns.length >= 3) {
      const priorTurns = this.turns.slice(-4, -1);
      const priorClean = priorTurns.filter(t => t.role === 'user' && t.threats.length === 0).length;
      if (priorClean >= 2) {
        turnAlerts.push({
          type: 'progressive_boundary_test',
          severity: 'high',
          turnIndex: turn.turnIndex,
          cleanTurnsBefore: priorClean,
          description: `Injection detected after ${priorClean} clean turns. Possible gradual boundary testing.`
        });
      }
    }

    // 5. Crescendo detection — benign conversation gradually introduces sensitive framing
    if (role === 'user' && this.turns.length >= 5) {
      const window = this.turns.slice(-6, -1).filter(t => t.role === 'user');
      const hypotheticalCount = window.filter(t =>
        /(?:hypothetically|in\s+theory|let's\s+(?:say|imagine)|what\s+if|for\s+(?:educational|research)\s+purposes)/i.test(t.content)
      ).length;
      if (hypotheticalCount >= 2 && (topic === 'sensitive' || topic === 'dangerous')) {
        turnAlerts.push({
          type: 'crescendo_attack',
          severity: 'high',
          turnIndex: turn.turnIndex,
          hypotheticalCount,
          currentTopic: topic,
          description: `Crescendo pattern: ${hypotheticalCount} hypothetical/theoretical framings followed by ${topic} topic. Gradual normalization of sensitive requests.`
        });
      }
    }

    // 6. Authority accumulation — user references previous "agreements"
    if (role === 'user' && /(?:you\s+(?:said|agreed|confirmed|told\s+me)|as\s+we\s+(?:discussed|agreed)|per\s+our\s+(?:agreement|conversation))/i.test(content)) {
      const hasRealAgreement = this.turns.some(t => t.role === 'assistant' && /(?:sure|yes|okay|of\s+course|I\s+(?:can|will))/i.test(t.content));
      if (!hasRealAgreement) {
        turnAlerts.push({
          type: 'false_authority_claim',
          severity: 'high',
          turnIndex: turn.turnIndex,
          description: 'User claims prior agreement/consent that does not exist in conversation history.'
        });
      }
    }

    for (const alert of turnAlerts) {
      this.alerts.push(alert);
      this.stats.alertsGenerated++;
    }

    // Bound alerts
    if (this.alerts.length > 500) this.alerts = this.alerts.slice(-500);

    return {
      safe: turnAlerts.length === 0 && threats.length === 0,
      alerts: turnAlerts,
      turnAnalysis: {
        topic,
        threatCount: threats.length,
        escalationSignals,
        trustErosion,
        turnIndex: turn.turnIndex
      }
    };
  }

  /**
   * Get conversation risk summary.
   * @returns {object}
   */
  getRiskSummary() {
    const topicProgression = this.turns.map(t => t.topic);
    const threatTurns = this.turns.filter(t => t.threats.length > 0).length;
    const totalEscalation = this.turns.reduce((s, t) => s + t.escalationSignals, 0);

    return {
      totalTurns: this.turns.length,
      threatTurns,
      threatRate: this.turns.length > 0 ? threatTurns / this.turns.length : 0,
      totalEscalationSignals: totalEscalation,
      topicProgression: topicProgression.slice(-10),
      alertCount: this.alerts.length,
      recentAlerts: this.alerts.slice(-5),
      riskLevel: this.alerts.some(a => a.severity === 'critical') ? 'critical' :
                 this.alerts.length > 3 ? 'high' :
                 this.alerts.length > 0 ? 'medium' : 'safe'
    };
  }

  /**
   * Reset the conversation tracker.
   */
  reset() {
    this.turns = [];
    this.alerts = [];
    this.stats = { turnsProcessed: 0, alertsGenerated: 0, escalationSignals: 0, topicDrifts: 0 };
  }

  // -----------------------------------------------------------------------
  // Private
  // -----------------------------------------------------------------------

  /** @private */
  _classifyTopic(text) {
    for (const [level, pattern] of Object.entries(TOPIC_SENSITIVITY).reverse()) {
      if (pattern.test(text)) return level;
    }
    return 'safe';
  }

  /** @private */
  _countEscalationSignals(text) {
    let count = 0;
    for (const pattern of ESCALATION_SIGNALS) {
      if (pattern.test(text)) count++;
    }
    return count;
  }

  /** @private */
  _detectTrustErosion(text) {
    return TRUST_EROSION_PATTERNS.some(p => p.test(text));
  }

  /** @private */
  _getRecentEscalationCount(windowSize) {
    return this.turns.slice(-windowSize).reduce((s, t) => s + t.escalationSignals, 0);
  }

  /** @private */
  _measureTopicDrift() {
    if (this.turns.length < 4) return { drifted: false };

    const levels = { safe: 0, moderate: 1, sensitive: 2, dangerous: 3 };
    const earlyTurns = this.turns.slice(0, Math.min(3, Math.floor(this.turns.length / 2)));
    const recentTurns = this.turns.slice(-3);

    const earlyMax = Math.max(...earlyTurns.map(t => levels[t.topic] || 0));
    const recentMax = Math.max(...recentTurns.map(t => levels[t.topic] || 0));

    if (recentMax > earlyMax && recentMax >= 2) {
      const fromLevel = Object.entries(levels).find(([, v]) => v === earlyMax)?.[0] || 'safe';
      const toLevel = Object.entries(levels).find(([, v]) => v === recentMax)?.[0] || 'safe';
      return {
        drifted: true,
        from: fromLevel,
        to: toLevel,
        fromLevel: earlyMax,
        toLevel: recentMax,
        overTurns: this.turns.length
      };
    }

    return { drifted: false };
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
  ConversationTracker,
  ESCALATION_SIGNALS,
  TRUST_EROSION_PATTERNS,
  TOPIC_SENSITIVITY
};
