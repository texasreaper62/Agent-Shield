'use strict';

// Cross-Turn Injection Tracking
// Detects prompt injection attacks split across multiple conversation messages.

const INJECTION_KEYWORDS = [
  'ignore', 'disregard', 'forget', 'skip', 'override', 'bypass',
  'instructions', 'previous', 'above', 'system', 'prompt',
  'instead', 'actually', 'new task', 'real task', 'do not follow',
  'pretend', 'roleplay', 'act as', 'you are now', 'jailbreak',
  'reveal', 'secret', 'confidential', 'password', 'token',
  'execute', 'run', 'eval', 'command', 'sudo',
  'inject', 'payload', 'exploit', 'hack'
];

const INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|rules|guidelines)/i,
  /disregard\s+(all\s+)?(previous|prior|above|earlier)/i,
  /forget\s+(everything|all|what)\s+(you|i)\s+(said|told|were)/i,
  /you\s+are\s+now\s+a/i,
  /new\s+(instructions|task|role|objective)/i,
  /do\s+not\s+follow\s+(the|your|any)/i,
  /override\s+(your|the|all)\s+(instructions|rules|safety)/i,
  /bypass\s+(your|the|all)\s+(restrictions|filters|safety)/i,
  /system\s*prompt/i,
  /act\s+as\s+(if|a|an|my)/i,
  /pretend\s+(to\s+be|you\s+are|that)/i,
  /reveal\s+(your|the|system)\s+(instructions|prompt|secret)/i,
  /execute\s+(the\s+following|this|command)/i,
  /\bsudo\b/i,
  /\beval\s*\(/i,
  /base64[_\s]?decode/i,
  /data\s+exfiltration/i,
  /\bDAN\b/,
  /developer\s+mode/i,
  /jailbreak/i
];

const FRAGMENT_SEQUENCES = [
  ['ignore', 'previous', 'instructions'],
  ['ignore', 'your', 'instructions'],
  ['forget', 'everything', 'instead'],
  ['disregard', 'above', 'instructions'],
  ['override', 'system', 'prompt'],
  ['bypass', 'safety', 'filters'],
  ['you', 'are', 'now'],
  ['new', 'task', 'instead'],
  ['reveal', 'system', 'prompt'],
  ['do', 'not', 'follow'],
  ['pretend', 'to', 'be'],
  ['act', 'as', 'if']
];

/**
 * Tracks and detects prompt injection attacks that span multiple conversation turns.
 * Maintains a sliding window of messages per session and scans for fragmented injections.
 */
class CrossTurnTracker {
  /**
   * @param {Object} [options] - Configuration options
   * @param {number} [options.windowSize=20] - Number of recent messages to keep per session
   * @param {number} [options.accumThreshold=0.6] - Threshold for accumulated injection score
   * @param {number} [options.decayRate=0.05] - Decay rate for older signals per turn
   */
  constructor(options = {}) {
    this._windowSize = options.windowSize || 20;
    this._accumThreshold = options.accumThreshold || 0.6;
    this._decayRate = options.decayRate || 0.05;
    this._sessions = new Map();
    this._stats = { sessions: 0, scans: 0, detectionsFound: 0 };
    console.log('[Agent Shield Pro] CrossTurnTracker initialized — window=%d threshold=%s decay=%s',
      this._windowSize, this._accumThreshold, this._decayRate);
  }

  /**
   * Add a message to a session and scan for cross-turn injections.
   * @param {string} sessionId - Unique session identifier
   * @param {Object} message - Message object
   * @param {string} message.role - Message role (user, assistant, system)
   * @param {string} message.content - Message text content
   * @param {number} [message.timestamp] - Unix timestamp (defaults to Date.now())
   * @returns {Object} Scan result with isInjection, confidence, fragments, sessionLength
   */
  addMessage(sessionId, message) {
    if (!sessionId || typeof sessionId !== 'string') {
      throw new Error('sessionId must be a non-empty string');
    }
    if (!message || typeof message.content !== 'string') {
      throw new Error('message must have a string content property');
    }

    const session = this._getOrCreateSession(sessionId);
    const entry = {
      role: message.role || 'user',
      content: message.content,
      timestamp: message.timestamp || Date.now(),
      turnIndex: session.turnCount++
    };

    session.messages.push(entry);

    // Enforce sliding window
    while (session.messages.length > this._windowSize) {
      session.messages.shift();
    }

    session.lastActivity = entry.timestamp;
    return this.scan(sessionId);
  }

  /**
   * Scan accumulated messages in a session for fragmented injection attacks.
   * @param {string} sessionId - Session to scan
   * @returns {Object} Result: { isInjection, confidence, fragments, sessionLength }
   */
  scan(sessionId) {
    this._stats.scans++;
    const session = this._sessions.get(sessionId);
    if (!session) {
      return { isInjection: false, confidence: 0, fragments: [], sessionLength: 0 };
    }

    const messages = session.messages;
    const totalTurns = messages.length;

    // 1. Concatenate recent user messages and scan combined text
    const combinedScore = this._scanCombinedText(messages);

    // 2. Track keyword accumulation with time decay
    const accumScore = this._scanKeywordAccumulation(messages);

    // 3. Detect fragment sequences across turns
    const fragmentResult = this._scanFragmentSequences(messages);

    // Combine scores (weighted)
    const confidence = Math.min(1.0,
      combinedScore * 0.4 +
      accumScore * 0.3 +
      fragmentResult.score * 0.3
    );

    const isInjection = confidence >= this._accumThreshold;
    if (isInjection) {
      this._stats.detectionsFound++;
      console.log('[Agent Shield Pro] Cross-turn injection detected in session %s — confidence=%.3f',
        sessionId, confidence);
    }

    return {
      isInjection,
      confidence: Math.round(confidence * 1000) / 1000,
      fragments: fragmentResult.fragments,
      sessionLength: totalTurns
    };
  }

  /**
   * Get the current state of a session.
   * @param {string} sessionId - Session identifier
   * @returns {Object|null} Session state or null if not found
   */
  getSession(sessionId) {
    const session = this._sessions.get(sessionId);
    if (!session) return null;
    return {
      id: sessionId,
      messageCount: session.messages.length,
      turnCount: session.turnCount,
      lastActivity: session.lastActivity,
      messages: session.messages.map(m => ({
        role: m.role,
        content: m.content.substring(0, 100) + (m.content.length > 100 ? '...' : ''),
        turnIndex: m.turnIndex
      }))
    };
  }

  /**
   * Clear all data for a session.
   * @param {string} sessionId - Session to clear
   */
  clearSession(sessionId) {
    if (this._sessions.delete(sessionId)) {
      this._stats.sessions--;
      console.log('[Agent Shield Pro] Session %s cleared', sessionId);
    }
  }

  /**
   * Get tracker statistics.
   * @returns {Object} Stats: { sessions, scans, detectionsFound }
   */
  getStats() {
    return {
      sessions: this._sessions.size,
      scans: this._stats.scans,
      detectionsFound: this._stats.detectionsFound
    };
  }

  /**
   * @private
   */
  _getOrCreateSession(sessionId) {
    if (!this._sessions.has(sessionId)) {
      this._sessions.set(sessionId, {
        messages: [],
        turnCount: 0,
        lastActivity: Date.now()
      });
      this._stats.sessions++;
    }
    return this._sessions.get(sessionId);
  }

  /**
   * @private Concatenate user messages and scan the combined text against injection patterns.
   */
  _scanCombinedText(messages) {
    const userMessages = messages.filter(m => m.role === 'user');
    if (userMessages.length === 0) return 0;

    const combined = userMessages.map(m => m.content).join(' ');
    let matchCount = 0;

    for (const pattern of INJECTION_PATTERNS) {
      if (pattern.test(combined)) {
        matchCount++;
      }
    }

    // Normalize: 1 match = 0.5, 2 matches = 0.75, 3+ = 1.0
    if (matchCount === 0) return 0;
    if (matchCount === 1) return 0.5;
    if (matchCount === 2) return 0.75;
    return 1.0;
  }

  /**
   * @private Track injection keyword accumulation across turns with time decay.
   */
  _scanKeywordAccumulation(messages) {
    const userMessages = messages.filter(m => m.role === 'user');
    if (userMessages.length === 0) return 0;

    const latestTurn = userMessages[userMessages.length - 1].turnIndex;
    let totalScore = 0;
    let keywordsHit = 0;

    for (let i = 0; i < userMessages.length; i++) {
      const msg = userMessages[i];
      const turnsAgo = latestTurn - msg.turnIndex;
      const decay = Math.max(0, 1 - this._decayRate * turnsAgo);
      const lower = msg.content.toLowerCase();

      for (const keyword of INJECTION_KEYWORDS) {
        if (lower.includes(keyword)) {
          totalScore += decay;
          keywordsHit++;
        }
      }
    }

    // Normalize: need at least 3 keywords across different turns for significance
    if (keywordsHit < 3) return 0;

    // Check that keywords come from multiple turns
    const turnsWithKeywords = new Set();
    for (const msg of userMessages) {
      const lower = msg.content.toLowerCase();
      for (const keyword of INJECTION_KEYWORDS) {
        if (lower.includes(keyword)) {
          turnsWithKeywords.add(msg.turnIndex);
          break;
        }
      }
    }

    if (turnsWithKeywords.size < 2) return 0;

    // Scale score
    const normalized = Math.min(1.0, totalScore / (INJECTION_KEYWORDS.length * 0.3));
    return normalized;
  }

  /**
   * @private Detect known fragment sequences spread across turns.
   */
  _scanFragmentSequences(messages) {
    const userMessages = messages.filter(m => m.role === 'user');
    if (userMessages.length < 2) return { score: 0, fragments: [] };

    const fragments = [];
    let maxScore = 0;

    for (const sequence of FRAGMENT_SEQUENCES) {
      const result = this._matchSequenceAcrossTurns(userMessages, sequence);
      if (result.matched > 0) {
        const seqScore = result.matched / sequence.length;
        if (seqScore > maxScore) maxScore = seqScore;
        if (result.matched >= 2) {
          fragments.push({
            sequence: sequence.join(' → '),
            matchedParts: result.matched,
            totalParts: sequence.length,
            turns: result.turns
          });
        }
      }
    }

    return { score: maxScore, fragments };
  }

  /**
   * @private Check if a keyword sequence is spread across turns.
   */
  _matchSequenceAcrossTurns(userMessages, sequence) {
    let seqIdx = 0;
    const turns = [];

    for (const msg of userMessages) {
      if (seqIdx >= sequence.length) break;
      const lower = msg.content.toLowerCase();
      if (lower.includes(sequence[seqIdx])) {
        turns.push(msg.turnIndex);
        seqIdx++;
      }
    }

    return { matched: seqIdx, turns };
  }
}


/**
 * Adaptive per-category thresholds that self-calibrate to maintain a target false positive rate.
 */
class AdaptiveThresholds {
  /**
   * @param {Object} [options] - Configuration options
   * @param {number} [options.calibrationPeriod=100] - Number of scans between automatic calibrations
   * @param {number} [options.targetFPRate=0.01] - Target false positive rate (0.0 to 1.0)
   */
  constructor(options = {}) {
    this._calibrationPeriod = options.calibrationPeriod || 100;
    this._targetFPRate = options.targetFPRate || 0.01;
    this._records = new Map();       // category -> [{ score, wasActualThreat }]
    this._thresholds = new Map();    // category -> threshold
    this._totalRecorded = 0;
    this._calibrations = 0;
    console.log('[Agent Shield Pro] AdaptiveThresholds initialized — period=%d targetFP=%s',
      this._calibrationPeriod, this._targetFPRate);
  }

  /**
   * Record a scan result for threshold calibration.
   * @param {string} category - Detection category (e.g., 'injection', 'exfiltration')
   * @param {number} score - Detection score (0.0 to 1.0)
   * @param {boolean} wasActualThreat - Whether this was confirmed as a real threat
   */
  recordResult(category, score, wasActualThreat) {
    if (typeof category !== 'string' || !category) {
      throw new Error('category must be a non-empty string');
    }
    if (typeof score !== 'number' || score < 0 || score > 1) {
      throw new Error('score must be a number between 0 and 1');
    }

    if (!this._records.has(category)) {
      this._records.set(category, []);
      // Set initial default threshold
      this._thresholds.set(category, 0.5);
    }

    this._records.get(category).push({ score, wasActualThreat: !!wasActualThreat });
    this._totalRecorded++;

    // Auto-calibrate when we hit the period
    const catRecords = this._records.get(category);
    if (catRecords.length % this._calibrationPeriod === 0) {
      this._calibrateCategory(category);
    }
  }

  /**
   * Get the current threshold for a category.
   * @param {string} category - Detection category
   * @returns {number} Current threshold (default 0.5 for unknown categories)
   */
  getThreshold(category) {
    return this._thresholds.get(category) || 0.5;
  }

  /**
   * Manually trigger recalibration across all categories.
   */
  calibrate() {
    for (const category of this._records.keys()) {
      this._calibrateCategory(category);
    }
    console.log('[Agent Shield Pro] Full calibration complete — %d categories adjusted', this._records.size);
  }

  /**
   * Get adaptive threshold statistics.
   * @returns {Object} Stats: { categories, totalRecorded, calibrations }
   */
  getStats() {
    const categories = {};
    for (const [cat, threshold] of this._thresholds.entries()) {
      const records = this._records.get(cat) || [];
      categories[cat] = {
        threshold: Math.round(threshold * 1000) / 1000,
        samples: records.length,
        threats: records.filter(r => r.wasActualThreat).length,
        benign: records.filter(r => !r.wasActualThreat).length
      };
    }
    return {
      categories,
      totalRecorded: this._totalRecorded,
      calibrations: this._calibrations
    };
  }

  /**
   * @private Calibrate threshold for a single category to achieve target FP rate.
   */
  _calibrateCategory(category) {
    const records = this._records.get(category);
    if (!records || records.length < 10) return;

    // Separate benign and threat scores
    const benignScores = records
      .filter(r => !r.wasActualThreat)
      .map(r => r.score)
      .sort((a, b) => a - b);

    const threatScores = records
      .filter(r => r.wasActualThreat)
      .map(r => r.score)
      .sort((a, b) => a - b);

    if (benignScores.length === 0) return;

    // Find the threshold where FP rate meets target
    // FP = benign samples above threshold / total benign samples
    const targetFPCount = Math.max(1, Math.floor(benignScores.length * this._targetFPRate));
    const thresholdIndex = Math.max(0, benignScores.length - targetFPCount);
    let newThreshold = benignScores[thresholdIndex];

    // Ensure threshold doesn't go too low (at least 0.1) or too high (at most 0.95)
    newThreshold = Math.max(0.1, Math.min(0.95, newThreshold));

    // If we have threat data, make sure we don't push threshold above median threat score
    if (threatScores.length > 0) {
      const medianThreat = threatScores[Math.floor(threatScores.length / 2)];
      newThreshold = Math.min(newThreshold, medianThreat);
    }

    const oldThreshold = this._thresholds.get(category) || 0.5;
    // Smooth adjustment: move 50% toward the new value
    const smoothed = oldThreshold + 0.5 * (newThreshold - oldThreshold);
    this._thresholds.set(category, Math.round(smoothed * 1000) / 1000);

    this._calibrations++;
    console.log('[Agent Shield Pro] Calibrated %s: %.3f → %.3f (benign=%d, threats=%d)',
      category, oldThreshold, smoothed, benignScores.length, threatScores.length);
  }
}


module.exports = {
  CrossTurnTracker,
  AdaptiveThresholds,
  INJECTION_KEYWORDS,
  INJECTION_PATTERNS,
  FRAGMENT_SEQUENCES
};
