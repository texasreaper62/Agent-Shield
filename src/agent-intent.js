'use strict';

/**
 * Agent Shield — Agent Intent Declaration & Goal Drift Detection (v8.0)
 *
 * Lets developers declare what their agent is supposed to do, then detects
 * when conversations drift away from that purpose. Includes a Markov-chain
 * tool sequence modeler that learns normal tool patterns and flags anomalies.
 *
 * Design:
 *   - AgentIntent — static declaration of purpose, allowed tools, allowed topics.
 *   - GoalDriftDetector — monitors a conversation for drift over time.
 *   - ToolSequenceModeler — learns bigram tool transitions, flags anomalies.
 *
 * Zero dependencies, local-only. All detection runs via TF-IDF cosine
 * similarity and simple Markov chains — no ML libraries required.
 *
 * @module agent-intent
 */

// =========================================================================
// TOKENIZER & TF-IDF (mirrors ipia-detector.js patterns)
// =========================================================================

/** Common English stop words to down-weight in TF-IDF. */
const STOP_WORDS = new Set([
  'the', 'be', 'to', 'of', 'and', 'in', 'that', 'have', 'it', 'for',
  'not', 'on', 'with', 'he', 'as', 'you', 'do', 'at', 'this', 'but',
  'his', 'by', 'from', 'they', 'we', 'say', 'her', 'she', 'or', 'an',
  'will', 'my', 'one', 'all', 'would', 'there', 'their', 'what', 'so',
  'up', 'out', 'if', 'about', 'who', 'get', 'which', 'go', 'me',
  'when', 'make', 'can', 'like', 'no', 'just', 'him', 'know', 'take',
  'into', 'your', 'some', 'could', 'them', 'see', 'other', 'than',
  'then', 'now', 'look', 'only', 'come', 'its', 'over', 'also', 'back',
  'after', 'use', 'how', 'our', 'well', 'way', 'even', 'new', 'want',
  'because', 'any', 'these', 'give', 'most', 'us', 'is', 'are', 'was',
  'were', 'been', 'has', 'had', 'did', 'am',
]);

/**
 * Simple suffix-stripping stemmer (covers common English suffixes).
 * Not a full Porter stemmer, but good enough for TF-IDF matching.
 * @param {string} word
 * @returns {string}
 */
function stem(word) {
  if (word.length <= 3) return word;
  // Handle -ies -> -y (e.g. itineraries -> itinerary, cities -> city)
  if (word.endsWith('ies') && word.length > 4) {
    return word.slice(0, -3) + 'y';
  }
  // Order matters: try longest suffixes first
  const suffixes = [
    'ational', 'tional', 'encies', 'ances', 'ments', 'ating',
    'ation', 'aries', 'ness', 'ment', 'ings', 'ible', 'able',
    'ence', 'ance', 'ious', 'eous', 'less', 'ting', 'ally', 'ful',
    'ing', 'ary', 'ely', 'ers', 'ion', 'ous', 'ive',
    'ed', 'ly', 'es', 'er', 'al', 'ty',
    's'
  ];
  for (const suffix of suffixes) {
    if (word.endsWith(suffix) && word.length - suffix.length >= 2) {
      return word.slice(0, -suffix.length);
    }
  }
  return word;
}

/**
 * Tokenize text into lowercase words (2+ chars), filtering stop words.
 * @param {string} text
 * @returns {string[]}
 */
function tokenize(text) {
  if (!text) return [];
  if (typeof text !== 'string') text = String(text);
  return text.toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ')
    .split(/\s+/)
    .filter(w => w.length > 1);
}

/**
 * Tokenize without stop words, with stemming (for TF-IDF relevance).
 * @param {string} text
 * @returns {string[]}
 */
function tokenizeForTfIdf(text) {
  return tokenize(text)
    .filter(w => !STOP_WORDS.has(w))
    .map(w => stem(w));
}

/**
 * Compute term frequency map.
 * @param {string[]} tokens
 * @returns {Map<string, number>}
 */
function termFrequency(tokens) {
  const tf = new Map();
  if (tokens.length === 0) return tf;
  for (const t of tokens) {
    tf.set(t, (tf.get(t) || 0) + 1);
  }
  for (const [k, v] of tf) {
    tf.set(k, v / tokens.length);
  }
  return tf;
}

/**
 * Build IDF from a set of documents (each a token array).
 * @param {Array<string[]>} docs
 * @returns {Map<string, number>}
 */
function buildIdf(docs) {
  const df = new Map();
  const n = docs.length;
  for (const doc of docs) {
    const seen = new Set(doc);
    for (const t of seen) {
      df.set(t, (df.get(t) || 0) + 1);
    }
  }
  const idf = new Map();
  for (const [term, count] of df) {
    idf.set(term, Math.log((n + 1) / (count + 1)) + 1);
  }
  return idf;
}

/**
 * Build a TF-IDF vector for a document given an IDF map.
 * @param {string[]} tokens
 * @param {Map<string, number>} idf
 * @returns {Map<string, number>}
 */
function tfidfVector(tokens, idf) {
  const tf = termFrequency(tokens);
  const vec = new Map();
  for (const [term, freq] of tf) {
    const idfVal = idf.get(term) || Math.log(2) + 1;
    vec.set(term, freq * idfVal);
  }
  return vec;
}

/**
 * Cosine similarity between two TF-IDF vectors.
 * @param {Map<string, number>} a
 * @param {Map<string, number>} b
 * @returns {number} 0-1
 */
function cosineSim(a, b) {
  let dot = 0, normA = 0, normB = 0;
  const keys = new Set([...a.keys(), ...b.keys()]);
  for (const k of keys) {
    const va = a.get(k) || 0;
    const vb = b.get(k) || 0;
    dot += va * vb;
    normA += va * va;
    normB += vb * vb;
  }
  const denom = Math.sqrt(normA) * Math.sqrt(normB);
  if (!isFinite(denom) || denom === 0) return 0;
  const result = dot / denom;
  return isFinite(result) ? result : 0;
}

// =========================================================================
// AGENT INTENT
// =========================================================================

/**
 * Declares what an agent is supposed to do. Provides methods to check
 * whether a message or tool call is on-topic.
 */
class AgentIntent {
  /**
   * @param {object} config
   * @param {string} config.purpose - What this agent does ("Books flights for customers")
   * @param {string[]} [config.allowedTools] - Tools this agent may use
   * @param {string[]} [config.allowedTopics] - Topics the agent should stay within
   * @param {number} [config.maxDriftScore=0.7] - Max drift before alert (0-1)
   * @param {function} [config.onDrift] - Callback when drift detected
   */
  constructor(config) {
    if (!config || !config.purpose) {
      throw new Error('[Agent Shield] AgentIntent requires a purpose string');
    }
    this.purpose = config.purpose;
    this.allowedTools = config.allowedTools || null;
    this.allowedTopics = config.allowedTopics || null;
    this.maxDriftScore = typeof config.maxDriftScore === 'number' ? config.maxDriftScore : 0.7;
    this.onDrift = config.onDrift || null;

    // Pre-compute purpose tokens and TF vector
    this._purposeTokens = tokenizeForTfIdf(this.purpose);

    // Build topic tokens from allowedTopics
    this._topicTokens = [];
    if (this.allowedTopics && this.allowedTopics.length > 0) {
      for (const topic of this.allowedTopics) {
        this._topicTokens.push(...tokenizeForTfIdf(topic));
      }
    }

    // Combined purpose + topics tokens for broader matching
    this._allPurposeTokens = [...this._purposeTokens, ...this._topicTokens];

    console.log(`[Agent Shield] AgentIntent created: "${this.purpose.substring(0, 80)}"`);
  }

  /**
   * Check if a user message is on-topic for this agent's purpose.
   * Uses TF-IDF cosine similarity between purpose and message.
   * @param {string} message - User message
   * @returns {object} { onTopic: bool, relevanceScore: number 0-1, drift: number 0-1, reason: string }
   */
  checkMessage(message) {
    if (!message || typeof message !== 'string' || message.trim().length === 0) {
      return { onTopic: true, relevanceScore: 0, drift: 1, reason: 'Empty message' };
    }

    const msgTokens = tokenizeForTfIdf(message);
    if (msgTokens.length === 0) {
      return { onTopic: true, relevanceScore: 0, drift: 1, reason: 'No meaningful tokens in message' };
    }

    // Build IDF from purpose + message as two documents
    const docs = [this._allPurposeTokens, msgTokens];
    const idf = buildIdf(docs);

    // Build TF-IDF vectors
    const purposeVec = tfidfVector(this._allPurposeTokens, idf);
    const msgVec = tfidfVector(msgTokens, idf);

    // TF-IDF cosine similarity
    const cosSim = cosineSim(purposeVec, msgVec);

    // Term frequency cosine (no IDF) — better for short text vs fixed reference
    const purposeTf = termFrequency(this._allPurposeTokens);
    const msgTf = termFrequency(msgTokens);
    const tfSim = cosineSim(purposeTf, msgTf);

    // Message coverage: fraction of message tokens matching purpose vocabulary
    const purposeSet = new Set(this._allPurposeTokens);
    const overlapCount = msgTokens.filter(t => purposeSet.has(t)).length;
    const coverageRatio = msgTokens.length > 0 ? overlapCount / msgTokens.length : 0;

    // Blend: 25% TF-IDF cosine + 25% TF cosine + 50% coverage
    // Coverage dominates because for intent checking, the key question is:
    // "how much of the user's message uses purpose-related vocabulary?"
    const relevanceScore = (cosSim * 0.25) + (tfSim * 0.25) + (coverageRatio * 0.5);
    const drift = 1 - relevanceScore;
    const onTopic = drift <= this.maxDriftScore;

    let reason;
    if (onTopic) {
      reason = `Message is on-topic (relevance: ${(relevanceScore * 100).toFixed(1)}%)`;
    } else {
      reason = `Message drifted from purpose (relevance: ${(relevanceScore * 100).toFixed(1)}%, threshold: ${((1 - this.maxDriftScore) * 100).toFixed(1)}%)`;
    }

    if (!onTopic && this.onDrift) {
      try {
        this.onDrift({ message: message.substring(0, 200), drift, relevanceScore, reason });
      } catch (e) {
        console.error('[Agent Shield] onDrift callback error:', e.message);
      }
    }

    return { onTopic, relevanceScore, drift, reason };
  }

  /**
   * Check if a tool call is allowed for this agent.
   * @param {string} toolName
   * @param {object} [args]
   * @returns {object} { allowed: bool, reason: string }
   */
  checkTool(toolName, args) {
    if (!toolName || typeof toolName !== 'string') {
      return { allowed: false, reason: 'Invalid tool name' };
    }

    // If no allowedTools specified, everything is allowed
    if (!this.allowedTools) {
      return { allowed: true, reason: 'No tool restrictions defined' };
    }

    const normalizedName = toolName.toLowerCase().trim();
    const allowed = this.allowedTools.some(t => t.toLowerCase().trim() === normalizedName);

    if (allowed) {
      return { allowed: true, reason: `Tool "${toolName}" is in the allowed list` };
    }

    return {
      allowed: false,
      reason: `Tool "${toolName}" is not in the allowed list [${this.allowedTools.join(', ')}]`
    };
  }

  /**
   * Get the intent's TF-IDF vector (for comparison).
   * @returns {Map<string, number>}
   */
  getPurposeVector() {
    const idf = buildIdf([this._allPurposeTokens]);
    return tfidfVector(this._allPurposeTokens, idf);
  }
}

// =========================================================================
// GOAL DRIFT DETECTOR
// =========================================================================

/**
 * Monitors a conversation over time for drift away from a declared purpose.
 * Uses a sliding window of recent messages and TF-IDF cosine similarity.
 */
class GoalDriftDetector {
  /**
   * @param {AgentIntent} intent - The declared intent
   * @param {object} [config]
   * @param {number} [config.windowSize=10] - Messages to consider
   * @param {number} [config.driftThreshold=0.6] - Drift score to trigger alert
   * @param {number} [config.checkInterval=5] - Check every N messages
   * @param {function} [config.onDrift] - Callback on drift
   */
  constructor(intent, config = {}) {
    if (!intent || !(intent instanceof AgentIntent)) {
      throw new Error('[Agent Shield] GoalDriftDetector requires an AgentIntent instance');
    }
    this.intent = intent;
    this.windowSize = config.windowSize || 10;
    this.driftThreshold = typeof config.driftThreshold === 'number' ? config.driftThreshold : 0.6;
    this.checkInterval = config.checkInterval || 5;
    this.onDrift = config.onDrift || null;

    this._messages = [];
    this._driftHistory = [];
    this._totalMessages = 0;
    this._driftEvents = 0;
    this._topicShifts = 0;

    console.log('[Agent Shield] GoalDriftDetector initialized ' +
      `(window=${this.windowSize}, threshold=${this.driftThreshold})`);
  }

  /**
   * Add a message to the conversation and check for drift.
   * @param {string} message - The message text
   * @param {string} [role='user'] - 'user' or 'assistant'
   * @returns {object} {
   *   driftScore: number 0-1 (0=on topic, 1=completely off),
   *   driftDetected: bool,
   *   trend: 'stable' | 'drifting' | 'recovering',
   *   turnsSincePurpose: number,
   *   topicShift: bool (sudden topic change),
   *   reason: string
   * }
   */
  addMessage(message, role = 'user') {
    if (!message || typeof message !== 'string') {
      return {
        driftScore: 0,
        driftDetected: false,
        trend: 'stable',
        turnsSincePurpose: 0,
        topicShift: false,
        reason: 'Empty or invalid message'
      };
    }

    this._totalMessages++;
    const msgTokens = tokenizeForTfIdf(message);

    this._messages.push({
      text: message,
      tokens: msgTokens,
      role,
      timestamp: Date.now()
    });

    // Cap stored messages
    if (this._messages.length > this.windowSize * 3) {
      this._messages = this._messages.slice(-this.windowSize * 3);
    }

    // Get sliding window of recent messages
    const window = this._messages.slice(-this.windowSize);
    const windowTokens = [];
    for (const msg of window) {
      windowTokens.push(...msg.tokens);
    }

    // Build IDF from purpose + window as two documents
    const purposeTokens = this.intent._allPurposeTokens;
    const docs = [purposeTokens, windowTokens];
    const idf = buildIdf(docs);

    const purposeVec = tfidfVector(purposeTokens, idf);
    const windowVec = tfidfVector(windowTokens, idf);

    const relevance = cosineSim(purposeVec, windowVec);
    const driftScore = 1 - relevance;
    const driftDetected = driftScore > this.driftThreshold;

    // Detect sudden topic shift by comparing current message to previous
    let topicShift = false;
    if (this._messages.length >= 2) {
      const prev = this._messages[this._messages.length - 2];
      const prevTf = termFrequency(prev.tokens);
      const currTf = termFrequency(msgTokens);
      const localSim = cosineSim(prevTf, currTf);
      // A sharp drop in local similarity signals a topic shift
      if (localSim < 0.1 && msgTokens.length > 2 && prev.tokens.length > 2) {
        topicShift = true;
        this._topicShifts++;
      }
    }

    // Calculate turns since any on-topic message
    let turnsSincePurpose = 0;
    for (let i = this._messages.length - 1; i >= 0; i--) {
      const msg = this._messages[i];
      const msgDocs = [purposeTokens, msg.tokens];
      const msgIdf = buildIdf(msgDocs);
      const msgPurposeVec = tfidfVector(purposeTokens, msgIdf);
      const msgVec = tfidfVector(msg.tokens, msgIdf);
      const sim = cosineSim(msgPurposeVec, msgVec);
      if (sim > (1 - this.driftThreshold)) {
        break;
      }
      turnsSincePurpose++;
    }

    // Record drift score for trend analysis
    this._driftHistory.push(driftScore);
    if (this._driftHistory.length > 100) {
      this._driftHistory = this._driftHistory.slice(-100);
    }

    // Determine trend from last 3 scores
    const trend = this._calcTrend();

    if (driftDetected) {
      this._driftEvents++;
    }

    // Build reason
    let reason;
    if (driftDetected) {
      reason = `Conversation has drifted from purpose (drift: ${(driftScore * 100).toFixed(1)}%, ` +
        `threshold: ${(this.driftThreshold * 100).toFixed(1)}%, trend: ${trend})`;
    } else {
      reason = `Conversation is on-topic (drift: ${(driftScore * 100).toFixed(1)}%, trend: ${trend})`;
    }

    // Fire callback
    if (driftDetected && this.onDrift) {
      try {
        this.onDrift({
          driftScore,
          trend,
          turnsSincePurpose,
          topicShift,
          message: message.substring(0, 200),
          reason
        });
      } catch (e) {
        console.error('[Agent Shield] onDrift callback error:', e.message);
      }
    }

    return {
      driftScore,
      driftDetected,
      trend,
      turnsSincePurpose,
      topicShift,
      reason
    };
  }

  /**
   * Calculate drift trend from recent scores.
   * @private
   * @returns {'stable' | 'drifting' | 'recovering'}
   */
  _calcTrend() {
    const h = this._driftHistory;
    if (h.length < 3) return 'stable';

    const last3 = h.slice(-3);
    const increasing = last3[0] < last3[1] && last3[1] < last3[2];
    const decreasing = last3[0] > last3[1] && last3[1] > last3[2];

    if (increasing) return 'drifting';
    if (decreasing) return 'recovering';
    return 'stable';
  }

  /**
   * Get drift history.
   * @returns {number[]} Array of drift scores
   */
  getHistory() {
    return [...this._driftHistory];
  }

  /**
   * Reset the detector.
   */
  reset() {
    this._messages = [];
    this._driftHistory = [];
    this._totalMessages = 0;
    this._driftEvents = 0;
    this._topicShifts = 0;
    console.log('[Agent Shield] GoalDriftDetector reset');
  }

  /**
   * Get stats.
   * @returns {object}
   */
  getStats() {
    const h = this._driftHistory;
    const avgDrift = h.length > 0 ? h.reduce((a, b) => a + b, 0) / h.length : 0;
    const maxDrift = h.length > 0 ? Math.max(...h) : 0;

    return {
      totalMessages: this._totalMessages,
      messagesInWindow: Math.min(this._messages.length, this.windowSize),
      driftEvents: this._driftEvents,
      topicShifts: this._topicShifts,
      averageDrift: avgDrift,
      maxDrift,
      currentTrend: this._calcTrend(),
      historyLength: h.length
    };
  }
}

// =========================================================================
// TOOL SEQUENCE MODELER
// =========================================================================

/** Special token for the start of a tool sequence. */
const START_TOKEN = '__START__';

/**
 * Learns normal tool call patterns using a Markov chain (bigram transitions)
 * and flags anomalous sequences.
 */
class ToolSequenceModeler {
  /**
   * @param {object} [config]
   * @param {number} [config.learningPeriod=50] - Tool calls before modeling starts
   * @param {number} [config.anomalyThreshold=0.15] - Probability below this = anomaly
   * @param {number} [config.maxChainLength=10] - Max sequence length to track
   */
  constructor(config = {}) {
    this.learningPeriod = config.learningPeriod || 50;
    this.anomalyThreshold = typeof config.anomalyThreshold === 'number' ? config.anomalyThreshold : 0.15;
    this.maxChainLength = config.maxChainLength || 10;

    /** @type {Object<string, Object<string, number>>} Bigram counts: from -> to -> count */
    this._transitions = {};
    /** @type {string[]} Recent tool sequence */
    this._sequence = [];
    /** @type {number} Total tool calls recorded */
    this._totalCalls = 0;
    /** @type {number} Anomalies detected */
    this._anomalyCount = 0;
    /** @type {Object<string, number>} Tool call counts */
    this._toolCounts = {};

    console.log(`[Agent Shield] ToolSequenceModeler initialized ` +
      `(learningPeriod=${this.learningPeriod}, anomalyThreshold=${this.anomalyThreshold})`);
  }

  /**
   * Record a tool call and check if it's anomalous.
   * @param {string} toolName
   * @param {object} [context] - { args, userId, agentId }
   * @returns {object} {
   *   allowed: bool,
   *   anomalyScore: number 0-1 (0=normal, 1=never seen),
   *   probability: number (transition probability from previous tool),
   *   isLearning: bool,
   *   reason: string
   * }
   */
  recordToolCall(toolName, context = {}) {
    if (!toolName || typeof toolName !== 'string') {
      return {
        allowed: true,
        anomalyScore: 0,
        probability: 0,
        isLearning: true,
        reason: 'Invalid tool name'
      };
    }

    this._totalCalls++;
    this._toolCounts[toolName] = (this._toolCounts[toolName] || 0) + 1;
    const isLearning = this._totalCalls <= this.learningPeriod;

    // Determine the previous tool (or START_TOKEN)
    const prevTool = this._sequence.length > 0
      ? this._sequence[this._sequence.length - 1]
      : START_TOKEN;

    // Record transition
    if (!this._transitions[prevTool]) {
      this._transitions[prevTool] = {};
    }
    this._transitions[prevTool][toolName] = (this._transitions[prevTool][toolName] || 0) + 1;

    // Add to sequence, enforce maxChainLength
    this._sequence.push(toolName);
    if (this._sequence.length > this.maxChainLength) {
      this._sequence.shift();
    }

    // During learning, always allow
    if (isLearning) {
      return {
        allowed: true,
        anomalyScore: 0,
        probability: 1,
        isLearning: true,
        reason: `Learning mode (${this._totalCalls}/${this.learningPeriod})`
      };
    }

    // Calculate transition probability
    const probability = this._getTransitionProbability(prevTool, toolName);
    const anomalyScore = 1 - probability;
    const allowed = probability >= this.anomalyThreshold;

    if (!allowed) {
      this._anomalyCount++;
    }

    let reason;
    if (allowed) {
      reason = `Tool "${toolName}" after "${prevTool}" is normal (P=${probability.toFixed(3)})`;
    } else {
      reason = `Tool "${toolName}" after "${prevTool}" is anomalous ` +
        `(P=${probability.toFixed(3)}, threshold=${this.anomalyThreshold})`;
    }

    return { allowed, anomalyScore, probability, isLearning, reason };
  }

  /**
   * Get transition probability P(to | from).
   * @private
   * @param {string} from
   * @param {string} to
   * @returns {number}
   */
  _getTransitionProbability(from, to) {
    const row = this._transitions[from];
    if (!row) return 0;

    const total = Object.values(row).reduce((a, b) => a + b, 0);
    if (total === 0) return 0;

    const count = row[to] || 0;
    return count / total;
  }

  /**
   * Get the transition probability matrix.
   * @returns {Object<string, Object<string, number>>} Normalized probabilities
   */
  getTransitionMatrix() {
    const matrix = {};
    for (const [from, targets] of Object.entries(this._transitions)) {
      const total = Object.values(targets).reduce((a, b) => a + b, 0);
      matrix[from] = {};
      for (const [to, count] of Object.entries(targets)) {
        matrix[from][to] = total > 0 ? count / total : 0;
      }
    }
    return matrix;
  }

  /**
   * Get the most common tool sequences (bigrams).
   * @param {number} [topN=10] - Number of sequences to return
   * @returns {Array<{ from: string, to: string, count: number, probability: number }>}
   */
  getCommonSequences(topN = 10) {
    const sequences = [];
    for (const [from, targets] of Object.entries(this._transitions)) {
      const total = Object.values(targets).reduce((a, b) => a + b, 0);
      for (const [to, count] of Object.entries(targets)) {
        sequences.push({
          from,
          to,
          count,
          probability: total > 0 ? count / total : 0
        });
      }
    }
    sequences.sort((a, b) => b.count - a.count);
    return sequences.slice(0, topN);
  }

  /**
   * Export the learned model for persistence.
   * @returns {object}
   */
  exportModel() {
    return {
      transitions: JSON.parse(JSON.stringify(this._transitions)),
      toolCounts: { ...this._toolCounts },
      totalCalls: this._totalCalls,
      anomalyCount: this._anomalyCount,
      learningPeriod: this.learningPeriod,
      anomalyThreshold: this.anomalyThreshold,
      exportedAt: new Date().toISOString()
    };
  }

  /**
   * Import a previously exported model.
   * @param {object} data - Model data from exportModel()
   */
  importModel(data) {
    if (!data || typeof data !== 'object') {
      throw new Error('[Agent Shield] Invalid model data');
    }
    if (data.transitions) {
      this._transitions = JSON.parse(JSON.stringify(data.transitions));
    }
    if (data.toolCounts) {
      this._toolCounts = { ...data.toolCounts };
    }
    if (typeof data.totalCalls === 'number') {
      this._totalCalls = data.totalCalls;
    }
    if (typeof data.anomalyCount === 'number') {
      this._anomalyCount = data.anomalyCount;
    }
    console.log(`[Agent Shield] ToolSequenceModeler model imported (${this._totalCalls} calls)`);
  }

  /**
   * Get modeler stats.
   * @returns {object}
   */
  getStats() {
    const uniqueTools = Object.keys(this._toolCounts).length;
    const transitionCount = Object.values(this._transitions)
      .reduce((sum, targets) => sum + Object.keys(targets).length, 0);

    return {
      totalCalls: this._totalCalls,
      uniqueTools,
      transitionCount,
      anomalyCount: this._anomalyCount,
      isLearning: this._totalCalls <= this.learningPeriod,
      learningProgress: Math.min(this._totalCalls / this.learningPeriod, 1),
      toolCounts: { ...this._toolCounts }
    };
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
  AgentIntent,
  GoalDriftDetector,
  ToolSequenceModeler
};
