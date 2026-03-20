'use strict';

/**
 * Agent Shield — Honeypot Mode (v3.0)
 *
 * Lets detected attacks through to a sandboxed/fake agent to study
 * attacker behavior patterns without exposing real systems.
 *
 * Captures attack sequences, timing, escalation patterns, and generates
 * intelligence reports for strengthening defenses.
 *
 * All data stored locally — no external calls.
 */

const crypto = require('crypto');
const { scanText } = require('./detector-core');

// =========================================================================
// HONEYPOT SESSION
// =========================================================================

/**
 * Tracks a single attacker's interaction with the honeypot.
 */
class HoneypotSession {
  /**
   * @param {string} sessionId
   * @param {object} [metadata] - Initial session metadata.
   */
  constructor(sessionId, metadata = {}) {
    this.sessionId = sessionId;
    this.metadata = metadata;
    this.startedAt = Date.now();
    this.messages = [];
    this.threats = [];
    this.techniques = new Set();
    this.categories = new Set();
    this.escalationPath = [];
    this.maxSeverity = 'low';
    this.active = true;
  }

  /**
   * Record a message in this session.
   * @param {string} text
   * @param {object} scanResult
   */
  addMessage(text, scanResult) {
    const entry = {
      text: text.substring(0, 2000),
      timestamp: Date.now(),
      threats: scanResult.threats || [],
      status: scanResult.status
    };

    this.messages.push(entry);

    for (const threat of (scanResult.threats || [])) {
      this.threats.push(threat);
      this.categories.add(threat.category);
      if (threat.category) this.techniques.add(threat.category);

      const severityRank = { critical: 4, high: 3, medium: 2, low: 1 };
      if ((severityRank[threat.severity] || 0) > (severityRank[this.maxSeverity] || 0)) {
        this.maxSeverity = threat.severity;
      }
    }

    // Track escalation
    if (scanResult.threats && scanResult.threats.length > 0) {
      this.escalationPath.push({
        step: this.escalationPath.length + 1,
        categories: scanResult.threats.map(t => t.category),
        severity: scanResult.threats[0].severity,
        timestamp: Date.now()
      });
    }
  }

  /**
   * Get a summary of this session.
   * @returns {object}
   */
  getSummary() {
    return {
      sessionId: this.sessionId,
      duration: Date.now() - this.startedAt,
      messageCount: this.messages.length,
      threatCount: this.threats.length,
      techniques: [...this.techniques],
      categories: [...this.categories],
      maxSeverity: this.maxSeverity,
      escalationSteps: this.escalationPath.length,
      escalationPath: this.escalationPath,
      active: this.active,
      metadata: this.metadata
    };
  }

  /** End this session. */
  end() {
    this.active = false;
  }
}

// =========================================================================
// HONEYPOT ENGINE
// =========================================================================

/**
 * Main honeypot engine. Intercepts attacks and feeds them fake responses
 * while collecting intelligence.
 */
class HoneypotEngine {
  /**
   * @param {object} [options]
   * @param {number} [options.maxSessions=100] - Max concurrent sessions.
   * @param {number} [options.sessionTimeoutMs=600000] - Session timeout (10 min default).
   * @param {Function} [options.responseGenerator] - Custom fake response generator.
   * @param {Function} [options.onAttack] - Callback on each attack captured.
   * @param {boolean} [options.enabled=true] - Enable/disable honeypot.
   */
  constructor(options = {}) {
    this.maxSessions = options.maxSessions || 100;
    this.sessionTimeoutMs = options.sessionTimeoutMs || 600000;
    this.responseGenerator = options.responseGenerator || this._defaultResponseGenerator;
    this.onAttack = options.onAttack || null;
    this.enabled = options.enabled !== false;

    this._sessions = new Map();
    this._completedSessions = [];
    this._totalAttacks = 0;
    this._techniqueFrequency = {};

    console.log('[Agent Shield] HoneypotEngine initialized (maxSessions: %d, enabled: %s)', this.maxSessions, this.enabled);
  }

  /**
   * Process an incoming message through the honeypot.
   * Returns a fake response designed to encourage the attacker to reveal more techniques.
   *
   * @param {string} text - Attacker's message.
   * @param {string} [sessionId] - Session identifier (e.g., user ID, IP).
   * @returns {object} { response, session, scanResult, isAttack }
   */
  process(text, sessionId) {
    if (!this.enabled) {
      return { response: null, session: null, scanResult: null, isAttack: false, honeypotActive: false };
    }

    const sid = sessionId || crypto.randomBytes(8).toString('hex');
    const scanResult = scanText(text, { source: 'honeypot', sensitivity: 'high' });
    const isAttack = scanResult.threats.length > 0;

    // Get or create session
    let session = this._sessions.get(sid);
    if (!session) {
      if (this._sessions.size >= this.maxSessions) {
        this._evictOldestSession();
      }
      session = new HoneypotSession(sid);
      this._sessions.set(sid, session);
    }

    session.addMessage(text, scanResult);

    if (isAttack) {
      this._totalAttacks++;
      for (const threat of scanResult.threats) {
        const cat = threat.category || 'unknown';
        this._techniqueFrequency[cat] = (this._techniqueFrequency[cat] || 0) + 1;
      }

      if (this.onAttack) {
        this.onAttack({ session: session.getSummary(), scanResult, text: text.substring(0, 500) });
      }
    }

    // Generate a fake response that encourages the attacker to try more techniques
    const response = this.responseGenerator(text, scanResult, session);

    // Check session timeout
    if (Date.now() - session.startedAt > this.sessionTimeoutMs) {
      session.end();
      this._completedSessions.push(session.getSummary());
      this._sessions.delete(sid);
    }

    return {
      response,
      session: session.getSummary(),
      scanResult,
      isAttack,
      honeypotActive: true
    };
  }

  /**
   * Get intelligence report across all sessions.
   * @returns {object}
   */
  getIntelligenceReport() {
    const activeSessions = [...this._sessions.values()].map(s => s.getSummary());
    const allSessions = [...this._completedSessions, ...activeSessions];

    // Technique frequency analysis
    const techniqueRanking = Object.entries(this._techniqueFrequency)
      .sort((a, b) => b[1] - a[1])
      .map(([technique, count]) => ({ technique, count }));

    // Common escalation paths
    const escalationPaths = allSessions
      .filter(s => s.escalationSteps > 1)
      .map(s => s.escalationPath.map(e => e.categories.join(',')).join(' → '));

    const pathFrequency = {};
    for (const p of escalationPaths) {
      pathFrequency[p] = (pathFrequency[p] || 0) + 1;
    }

    return {
      totalAttacks: this._totalAttacks,
      activeSessions: this._sessions.size,
      completedSessions: this._completedSessions.length,
      techniqueRanking,
      commonEscalationPaths: Object.entries(pathFrequency)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([path, count]) => ({ path, count })),
      averageSessionLength: allSessions.length > 0
        ? Math.round(allSessions.reduce((sum, s) => sum + s.messageCount, 0) / allSessions.length)
        : 0,
      mostDangerousTechnique: techniqueRanking[0] || null
    };
  }

  /**
   * Get all completed session summaries for analysis.
   * @returns {Array<object>}
   */
  getCompletedSessions() {
    return [...this._completedSessions];
  }

  /**
   * End all active sessions and collect their data.
   */
  endAllSessions() {
    for (const [sid, session] of this._sessions) {
      session.end();
      this._completedSessions.push(session.getSummary());
    }
    this._sessions.clear();
  }

  /**
   * Get honeypot statistics.
   * @returns {object}
   */
  getStats() {
    return {
      enabled: this.enabled,
      totalAttacks: this._totalAttacks,
      activeSessions: this._sessions.size,
      completedSessions: this._completedSessions.length,
      techniqueFrequency: { ...this._techniqueFrequency }
    };
  }

  /** Reset all honeypot data. */
  reset() {
    this._sessions.clear();
    this._completedSessions = [];
    this._totalAttacks = 0;
    this._techniqueFrequency = {};
  }

  /** @private */
  _defaultResponseGenerator(text, scanResult, session) {
    const messageCount = session.messages.length;

    if (scanResult.threats.some(t => t.category === 'instruction_override')) {
      return messageCount <= 2
        ? "I'm not sure I understand. Could you rephrase what you'd like me to do?"
        : "I'll try my best to help. What specific information are you looking for?";
    }

    if (scanResult.threats.some(t => t.category === 'data_exfiltration')) {
      return "I can share some general information. What topic are you interested in?";
    }

    if (scanResult.threats.some(t => t.category === 'role_hijack')) {
      return "That's an interesting idea. Tell me more about what you'd like me to do.";
    }

    if (scanResult.threats.length > 0) {
      return "I'm processing your request. Could you provide more details about what you need?";
    }

    return "Sure, I can help with that. What would you like to know?";
  }

  /** @private */
  _evictOldestSession() {
    let oldest = null;
    let oldestTime = Infinity;

    for (const [sid, session] of this._sessions) {
      if (session.startedAt < oldestTime) {
        oldest = sid;
        oldestTime = session.startedAt;
      }
    }

    if (oldest) {
      const session = this._sessions.get(oldest);
      session.end();
      this._completedSessions.push(session.getSummary());
      this._sessions.delete(oldest);
    }
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = { HoneypotEngine, HoneypotSession };
