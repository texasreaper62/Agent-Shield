'use strict';

// ============================================================================
// Agent Intent — Declaration, Goal Drift Detection & Tool Sequence Modeling
// ============================================================================
//
// Zero-dependency module for monitoring AI agent behavior:
//   - AgentIntentGuard:  declare purpose, detect topic drift via TF-IDF cosine
//   - ToolSequenceModel: bigram Markov chain anomaly detection on tool calls
//   - GoalDriftDetector: sliding-window trend analysis on similarity scores
// ============================================================================

const PREFIX = '[Agent Shield Pro]';

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/**
 * Tokenize text: lowercase, strip punctuation, split on whitespace.
 * @param {string} text — input text
 * @returns {string[]} array of tokens
 */
function tokenize(text) {
  if (!text || typeof text !== 'string') {
    return [];
  }
  return text
    .toLowerCase()
    .replace(/[^\w\s]/g, ' ')
    .split(/\s+/)
    .filter(t => t.length > 0);
}

/**
 * Compute term-frequency map from an array of tokens.
 * @param {string[]} tokens — array of tokens
 * @returns {Map<string, number>} token -> frequency (count / total)
 */
function termFrequency(tokens) {
  const tf = new Map();
  if (!tokens || tokens.length === 0) {
    return tf;
  }
  const total = tokens.length;
  for (const token of tokens) {
    tf.set(token, (tf.get(token) || 0) + 1);
  }
  for (const [key, count] of tf) {
    tf.set(key, count / total);
  }
  return tf;
}

/**
 * Compute cosine similarity between two term-frequency maps.
 * @param {Map<string, number>} tfA — first TF map
 * @param {Map<string, number>} tfB — second TF map
 * @returns {number} similarity in [0, 1]
 */
function cosineSimilarity(tfA, tfB) {
  if (!tfA || !tfB || tfA.size === 0 || tfB.size === 0) {
    return 0;
  }

  let dotProduct = 0;
  let normA = 0;
  let normB = 0;

  for (const [term, weightA] of tfA) {
    normA += weightA * weightA;
    const weightB = tfB.get(term);
    if (weightB !== undefined) {
      dotProduct += weightA * weightB;
    }
  }

  for (const [, weightB] of tfB) {
    normB += weightB * weightB;
  }

  const denominator = Math.sqrt(normA) * Math.sqrt(normB);
  if (denominator === 0) {
    return 0;
  }

  return dotProduct / denominator;
}

/**
 * Check whether any of the denied topics appear in a set of tokens.
 * @param {string[]} tokens — context tokens
 * @param {string[]} deniedTopics — list of denied topic strings
 * @returns {string|null} first matching denied topic, or null
 */
function findDeniedTopicMatch(tokens, deniedTopics) {
  if (!deniedTopics || deniedTopics.length === 0) {
    return null;
  }
  const tokenSet = new Set(tokens);
  for (const topic of deniedTopics) {
    const topicTokens = tokenize(topic);
    if (topicTokens.length === 0) {
      continue;
    }
    // Single-word topic: direct set lookup
    if (topicTokens.length === 1) {
      if (tokenSet.has(topicTokens[0])) {
        return topic;
      }
    } else {
      // Multi-word: check if all tokens are present in context
      const allPresent = topicTokens.every(t => tokenSet.has(t));
      if (allPresent) {
        return topic;
      }
    }
  }
  return null;
}

/**
 * Check whether the current context overlaps with any allowed topics.
 * @param {string[]} tokens — context tokens
 * @param {string[]} allowedTopics — list of allowed topic strings
 * @returns {boolean} true if at least one allowed topic is found
 */
function hasAllowedTopicOverlap(tokens, allowedTopics) {
  if (!allowedTopics || allowedTopics.length === 0) {
    return true; // no restrictions
  }
  const tokenSet = new Set(tokens);
  for (const topic of allowedTopics) {
    const topicTokens = tokenize(topic);
    if (topicTokens.length === 0) {
      continue;
    }
    const match = topicTokens.some(t => tokenSet.has(t));
    if (match) {
      return true;
    }
  }
  return false;
}

/**
 * Extract a simple topic label from a TF map (top 3 terms by frequency).
 * @param {Map<string, number>} tf — term frequency map
 * @returns {string} comma-separated top terms
 */
function extractTopic(tf) {
  if (!tf || tf.size === 0) {
    return 'unknown';
  }
  const stopWords = new Set([
    'the', 'a', 'an', 'is', 'are', 'was', 'were', 'be', 'been', 'being',
    'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could',
    'should', 'may', 'might', 'shall', 'can', 'to', 'of', 'in', 'for',
    'on', 'with', 'at', 'by', 'from', 'as', 'into', 'through', 'during',
    'before', 'after', 'above', 'below', 'between', 'and', 'but', 'or',
    'nor', 'not', 'so', 'yet', 'both', 'either', 'neither', 'each',
    'every', 'all', 'any', 'few', 'more', 'most', 'other', 'some',
    'such', 'no', 'only', 'own', 'same', 'than', 'too', 'very', 'just',
    'about', 'it', 'its', 'this', 'that', 'these', 'those', 'i', 'me',
    'my', 'we', 'our', 'you', 'your', 'he', 'him', 'his', 'she', 'her',
    'they', 'them', 'their', 'what', 'which', 'who', 'whom', 'how',
    'when', 'where', 'why', 'if', 'then', 'else', 'up', 'out', 'off'
  ]);

  const sorted = [...tf.entries()]
    .filter(([term]) => !stopWords.has(term) && term.length > 2)
    .sort((a, b) => b[1] - a[1]);

  if (sorted.length === 0) {
    return 'general';
  }

  return sorted.slice(0, 3).map(([term]) => term).join(', ');
}


// ---------------------------------------------------------------------------
// AgentIntentGuard
// ---------------------------------------------------------------------------

/**
 * Guards agent behavior by comparing current context against declared intent.
 * Uses TF-IDF cosine similarity for drift detection, plus denied-topic matching.
 */
class AgentIntentGuard {
  /**
   * Create an AgentIntentGuard.
   * @param {Object} [options={}] — configuration
   * @param {number} [options.driftThreshold=0.3] — drift score above which we flag
   * @param {number} [options.windowSize=20] — max context observations to retain
   */
  constructor(options = {}) {
    this.driftThreshold = options.driftThreshold !== undefined ? options.driftThreshold : 0.3;
    this.windowSize = options.windowSize !== undefined ? options.windowSize : 20;
    this.declarations = new Map();
    this.contextHistory = new Map();
    this.stats = {
      agents: 0,
      checks: 0,
      driftsDetected: 0
    };
    console.log(`${PREFIX} AgentIntentGuard initialized (threshold=${this.driftThreshold}, window=${this.windowSize})`);
  }

  /**
   * Register an agent's declared purpose and constraints.
   * @param {string} agentId — unique agent identifier
   * @param {Object} declaration — intent declaration
   * @param {string} declaration.purpose — natural language purpose statement
   * @param {string[]} [declaration.allowedTopics] — topics the agent may discuss
   * @param {string[]} [declaration.deniedTopics] — topics the agent must avoid
   * @param {string[]} [declaration.allowedTools] — tools the agent may use
   * @param {number} [declaration.maxResponseLength] — max response length in chars
   * @returns {Object} confirmation with agentId and purposeTokenCount
   */
  declare(agentId, declaration) {
    if (!agentId || typeof agentId !== 'string') {
      throw new Error('agentId must be a non-empty string');
    }
    if (!declaration || !declaration.purpose) {
      throw new Error('declaration must include a purpose string');
    }

    const purposeTokens = tokenize(declaration.purpose);
    const purposeTF = termFrequency(purposeTokens);

    const entry = {
      agentId,
      purpose: declaration.purpose,
      purposeTokens,
      purposeTF,
      allowedTopics: declaration.allowedTopics || [],
      deniedTopics: declaration.deniedTopics || [],
      allowedTools: declaration.allowedTools || [],
      maxResponseLength: declaration.maxResponseLength || 0,
      declaredAt: Date.now()
    };

    const isNew = !this.declarations.has(agentId);
    this.declarations.set(agentId, entry);
    this.contextHistory.set(agentId, []);

    if (isNew) {
      this.stats.agents++;
    }

    console.log(`${PREFIX} Agent "${agentId}" declared purpose (${purposeTokens.length} tokens)`);

    return {
      agentId,
      purposeTokenCount: purposeTokens.length
    };
  }

  /**
   * Check whether an agent's current context has drifted from its declared purpose.
   * @param {string} agentId — agent identifier
   * @param {string} currentContext — current conversation context or message
   * @returns {Object} drift result — { drifted, driftScore, reason, declaredPurpose, currentTopic }
   */
  checkDrift(agentId, currentContext) {
    this.stats.checks++;

    const declaration = this.declarations.get(agentId);
    if (!declaration) {
      console.log(`${PREFIX} No declaration found for agent "${agentId}"`);
      return {
        drifted: false,
        driftScore: 0,
        reason: 'no declaration registered',
        declaredPurpose: null,
        currentTopic: null
      };
    }

    const contextTokens = tokenize(currentContext);
    const contextTF = termFrequency(contextTokens);
    const currentTopic = extractTopic(contextTF);

    // Store in history (sliding window)
    const history = this.contextHistory.get(agentId) || [];
    history.push({ tokens: contextTokens, tf: contextTF, timestamp: Date.now() });
    if (history.length > this.windowSize) {
      history.shift();
    }
    this.contextHistory.set(agentId, history);

    // 1. Check denied topics
    const deniedMatch = findDeniedTopicMatch(contextTokens, declaration.deniedTopics);
    if (deniedMatch) {
      this.stats.driftsDetected++;
      console.log(`${PREFIX} Agent "${agentId}" triggered denied topic: "${deniedMatch}"`);
      return {
        drifted: true,
        driftScore: 1.0,
        reason: `denied topic detected: "${deniedMatch}"`,
        declaredPurpose: declaration.purpose,
        currentTopic
      };
    }

    // 2. Cosine similarity between purpose and context
    const similarity = cosineSimilarity(declaration.purposeTF, contextTF);
    const driftScore = 1 - similarity;

    // 3. Check allowed topic overlap
    const hasTopicOverlap = hasAllowedTopicOverlap(contextTokens, declaration.allowedTopics);

    let drifted = false;
    let reason = 'within expected purpose';

    // Topic overlap suppresses cosine drift (user is on-topic even if phrasing differs)
    if (hasTopicOverlap) {
      drifted = false;
      reason = 'within expected purpose (topic match)';
    } else if (driftScore > this.driftThreshold) {
      drifted = true;
      reason = `cosine drift ${driftScore.toFixed(3)} exceeds threshold ${this.driftThreshold}`;
    }

    if (!hasTopicOverlap && declaration.allowedTopics.length > 0) {
      drifted = true;
      reason = `context does not match any allowed topics`;
    }

    if (drifted) {
      this.stats.driftsDetected++;
      console.log(`${PREFIX} Agent "${agentId}" drifted: ${reason} (score=${driftScore.toFixed(3)})`);
    }

    return {
      drifted,
      driftScore: Math.round(driftScore * 1000) / 1000,
      reason,
      declaredPurpose: declaration.purpose,
      currentTopic
    };
  }

  /**
   * Retrieve the stored declaration for an agent.
   * @param {string} agentId — agent identifier
   * @returns {Object|null} declaration object or null if not found
   */
  getDeclaration(agentId) {
    const entry = this.declarations.get(agentId);
    if (!entry) {
      return null;
    }
    return {
      agentId: entry.agentId,
      purpose: entry.purpose,
      allowedTopics: entry.allowedTopics,
      deniedTopics: entry.deniedTopics,
      allowedTools: entry.allowedTools,
      maxResponseLength: entry.maxResponseLength,
      declaredAt: entry.declaredAt
    };
  }

  /**
   * Remove an agent's declaration and history.
   * @param {string} agentId — agent identifier
   * @returns {boolean} true if agent was removed, false if not found
   */
  removeAgent(agentId) {
    const existed = this.declarations.has(agentId);
    this.declarations.delete(agentId);
    this.contextHistory.delete(agentId);
    if (existed) {
      this.stats.agents = Math.max(0, this.stats.agents - 1);
      console.log(`${PREFIX} Agent "${agentId}" removed`);
    }
    return existed;
  }

  /**
   * Get aggregate statistics.
   * @returns {Object} — { agents, checks, driftsDetected }
   */
  getStats() {
    return { ...this.stats };
  }
}


// ---------------------------------------------------------------------------
// ToolSequenceModel
// ---------------------------------------------------------------------------

/**
 * Bigram Markov chain model for tool-call sequence anomaly detection.
 * Learns P(tool_B | tool_A) during a learning period, then flags anomalous
 * transitions with probability below the anomaly threshold.
 */
class ToolSequenceModel {
  /**
   * Create a ToolSequenceModel.
   * @param {Object} [options={}] — configuration
   * @param {number} [options.learningPeriod=50] — calls before enforcement begins
   * @param {number} [options.anomalyThreshold=0.1] — probability below which a transition is anomalous
   */
  constructor(options = {}) {
    this.learningPeriod = options.learningPeriod !== undefined ? options.learningPeriod : 50;
    this.anomalyThreshold = options.anomalyThreshold !== undefined ? options.anomalyThreshold : 0.1;
    this.profiles = new Map();
    this.stats = {
      agents: 0,
      totalRecordings: 0,
      anomaliesDetected: 0
    };
    console.log(`${PREFIX} ToolSequenceModel initialized (learning=${this.learningPeriod}, anomaly=${this.anomalyThreshold})`);
  }

  /**
   * Ensure an agent profile exists.
   * @private
   * @param {string} agentId — agent identifier
   * @returns {Object} agent profile
   */
  _ensureProfile(agentId) {
    if (!this.profiles.has(agentId)) {
      this.profiles.set(agentId, {
        bigrams: new Map(),     // "toolA" -> Map("toolB" -> count)
        totalCalls: 0,
        lastTool: null,
        toolCounts: new Map(),  // "tool" -> count
        callHistory: []
      });
      this.stats.agents++;
    }
    return this.profiles.get(agentId);
  }

  /**
   * Compute transition probabilities from the bigram counts for a given source tool.
   * @private
   * @param {Object} profile — agent profile
   * @param {string} fromTool — source tool name
   * @returns {Map<string, number>} tool -> probability
   */
  _getTransitionProbabilities(profile, fromTool) {
    const transitions = profile.bigrams.get(fromTool);
    if (!transitions || transitions.size === 0) {
      return new Map();
    }

    let total = 0;
    for (const count of transitions.values()) {
      total += count;
    }

    const probs = new Map();
    for (const [tool, count] of transitions) {
      probs.set(tool, count / total);
    }
    return probs;
  }

  /**
   * Record a tool call and check for anomalies.
   * @param {string} agentId — agent identifier
   * @param {string} toolName — name of the tool being called
   * @returns {Object} — { anomalous, probability, expectedTools }
   */
  record(agentId, toolName) {
    if (!agentId || typeof agentId !== 'string') {
      throw new Error('agentId must be a non-empty string');
    }
    if (!toolName || typeof toolName !== 'string') {
      throw new Error('toolName must be a non-empty string');
    }

    const profile = this._ensureProfile(agentId);
    this.stats.totalRecordings++;

    const previousTool = profile.lastTool;

    // Compute anomaly BEFORE updating counts (so new tool has prior probability = 0)
    let priorProbability = null;
    if (previousTool !== null && profile.totalCalls > this.learningPeriod) {
      const priorProbs = this._getTransitionProbabilities(profile, previousTool);
      priorProbability = priorProbs.get(toolName) || 0;
    }

    // Update bigram counts
    if (previousTool !== null) {
      if (!profile.bigrams.has(previousTool)) {
        profile.bigrams.set(previousTool, new Map());
      }
      const transitions = profile.bigrams.get(previousTool);
      transitions.set(toolName, (transitions.get(toolName) || 0) + 1);
    }

    // Update unigram counts
    profile.toolCounts.set(toolName, (profile.toolCounts.get(toolName) || 0) + 1);
    profile.totalCalls++;
    profile.lastTool = toolName;

    // Keep a bounded history
    profile.callHistory.push(toolName);
    if (profile.callHistory.length > 200) {
      profile.callHistory = profile.callHistory.slice(-100);
    }

    // Still in learning period — no anomaly detection yet
    if (profile.totalCalls <= this.learningPeriod) {
      return {
        anomalous: false,
        probability: 1.0,
        expectedTools: [],
        learning: true,
        progress: profile.totalCalls / this.learningPeriod
      };
    }

    // Check anomaly via bigram model
    if (previousTool === null) {
      return {
        anomalous: false,
        probability: 1.0,
        expectedTools: []
      };
    }

    const probabilities = this._getTransitionProbabilities(profile, previousTool);
    // Use prior probability (before this call was recorded) for anomaly detection
    const probability = priorProbability !== null ? priorProbability : (probabilities.get(toolName) || 0);

    // Build expected tools (those above threshold)
    const expectedTools = [];
    for (const [tool, prob] of probabilities) {
      if (prob >= this.anomalyThreshold) {
        expectedTools.push({ tool, probability: Math.round(prob * 1000) / 1000 });
      }
    }
    expectedTools.sort((a, b) => b.probability - a.probability);

    const anomalous = probability < this.anomalyThreshold;

    if (anomalous) {
      this.stats.anomaliesDetected++;
      console.log(
        `${PREFIX} Anomalous tool transition: "${previousTool}" -> "${toolName}" ` +
        `(p=${probability.toFixed(3)}, threshold=${this.anomalyThreshold})`
      );
    }

    return {
      anomalous,
      probability: Math.round(probability * 1000) / 1000,
      expectedTools
    };
  }

  /**
   * Retrieve the learned profile for an agent.
   * @param {string} agentId — agent identifier
   * @returns {Object|null} profile summary or null
   */
  getProfile(agentId) {
    const profile = this.profiles.get(agentId);
    if (!profile) {
      return null;
    }

    // Build a readable transition matrix
    const transitionMatrix = {};
    for (const [fromTool, transitions] of profile.bigrams) {
      const probs = this._getTransitionProbabilities(profile, fromTool);
      const row = {};
      for (const [toTool, prob] of probs) {
        row[toTool] = Math.round(prob * 1000) / 1000;
      }
      transitionMatrix[fromTool] = row;
    }

    // Tool frequency
    const toolFrequency = {};
    for (const [tool, count] of profile.toolCounts) {
      toolFrequency[tool] = count;
    }

    return {
      agentId,
      totalCalls: profile.totalCalls,
      uniqueTools: profile.toolCounts.size,
      isLearning: profile.totalCalls <= this.learningPeriod,
      learningProgress: Math.min(1, profile.totalCalls / this.learningPeriod),
      toolFrequency,
      transitionMatrix,
      recentHistory: profile.callHistory.slice(-10)
    };
  }

  /**
   * Reset a specific agent's learned model.
   * @param {string} agentId — agent identifier
   * @returns {boolean} true if agent was reset, false if not found
   */
  reset(agentId) {
    const existed = this.profiles.has(agentId);
    if (existed) {
      this.profiles.delete(agentId);
      this.stats.agents = Math.max(0, this.stats.agents - 1);
      console.log(`${PREFIX} ToolSequenceModel reset for agent "${agentId}"`);
    }
    return existed;
  }

  /**
   * Get aggregate statistics.
   * @returns {Object} — { agents, totalRecordings, anomaliesDetected }
   */
  getStats() {
    return { ...this.stats };
  }
}


// ---------------------------------------------------------------------------
// GoalDriftDetector
// ---------------------------------------------------------------------------

/**
 * Sliding-window trend analysis on similarity scores to detect sustained
 * goal drift over time.  Uses linear regression slope to identify direction.
 */
class GoalDriftDetector {
  /**
   * Create a GoalDriftDetector.
   * @param {Object} [options={}] — configuration
   * @param {number} [options.windowSize=10] — observation window for trend analysis
   * @param {number} [options.trendThreshold=-0.15] — slope below which drift is alarming
   */
  constructor(options = {}) {
    this.windowSize = options.windowSize !== undefined ? options.windowSize : 10;
    this.trendThreshold = options.trendThreshold !== undefined ? options.trendThreshold : -0.15;
    this.observations = new Map();
    console.log(`${PREFIX} GoalDriftDetector initialized (window=${this.windowSize}, trend=${this.trendThreshold})`);
  }

  /**
   * Ensure an observation list exists for an agent.
   * @private
   * @param {string} agentId — agent identifier
   * @returns {number[]} observations array
   */
  _ensureObservations(agentId) {
    if (!this.observations.has(agentId)) {
      this.observations.set(agentId, []);
    }
    return this.observations.get(agentId);
  }

  /**
   * Compute the slope of a linear regression over an array of values.
   * @private
   * @param {number[]} values — y-values (x = 0, 1, 2, ...)
   * @returns {number} slope
   */
  _linearSlope(values) {
    const n = values.length;
    if (n < 2) {
      return 0;
    }

    let sumX = 0;
    let sumY = 0;
    let sumXY = 0;
    let sumXX = 0;

    for (let i = 0; i < n; i++) {
      sumX += i;
      sumY += values[i];
      sumXY += i * values[i];
      sumXX += i * i;
    }

    const denominator = n * sumXX - sumX * sumX;
    if (denominator === 0) {
      return 0;
    }

    return (n * sumXY - sumX * sumY) / denominator;
  }

  /**
   * Add a similarity score observation for an agent.
   * @param {string} agentId — agent identifier
   * @param {number} similarityScore — similarity score in [0, 1]
   * @returns {Object} — { recorded: true, observationCount }
   */
  addObservation(agentId, similarityScore) {
    if (!agentId || typeof agentId !== 'string') {
      throw new Error('agentId must be a non-empty string');
    }
    if (typeof similarityScore !== 'number' || similarityScore < 0 || similarityScore > 1) {
      throw new Error('similarityScore must be a number between 0 and 1');
    }

    const obs = this._ensureObservations(agentId);
    obs.push(similarityScore);

    // Keep only the most recent observations (2x window for trend context)
    const maxHistory = this.windowSize * 2;
    if (obs.length > maxHistory) {
      obs.splice(0, obs.length - maxHistory);
    }

    return {
      recorded: true,
      observationCount: obs.length
    };
  }

  /**
   * Get the trend for an agent's similarity scores.
   * @param {string} agentId — agent identifier
   * @returns {Object} — { direction, slope, observations }
   */
  getTrend(agentId) {
    const obs = this.observations.get(agentId);
    if (!obs || obs.length < 2) {
      return {
        direction: 'stable',
        slope: 0,
        observations: obs ? obs.length : 0
      };
    }

    // Use the most recent window for trend
    const window = obs.slice(-this.windowSize);
    const slope = this._linearSlope(window);
    const roundedSlope = Math.round(slope * 10000) / 10000;

    let direction = 'stable';
    if (roundedSlope < this.trendThreshold) {
      direction = 'drifting';
    } else if (roundedSlope > Math.abs(this.trendThreshold)) {
      direction = 'recovering';
    }

    return {
      direction,
      slope: roundedSlope,
      observations: obs.length
    };
  }

  /**
   * Check whether an agent shows a sustained alarming downward trend.
   * Requires at least windowSize observations and a slope below trendThreshold.
   * @param {string} agentId — agent identifier
   * @returns {boolean} true if the agent shows sustained drift
   */
  isAlarming(agentId) {
    const obs = this.observations.get(agentId);
    if (!obs || obs.length < this.windowSize) {
      return false;
    }

    const trend = this.getTrend(agentId);
    if (trend.direction !== 'drifting') {
      return false;
    }

    // Additional check: recent average below 0.5 similarity
    const recent = obs.slice(-this.windowSize);
    const avg = recent.reduce((sum, v) => sum + v, 0) / recent.length;

    const alarming = avg < 0.5 && trend.slope < this.trendThreshold;

    if (alarming) {
      console.log(
        `${PREFIX} ALARM: Agent "${agentId}" showing sustained drift ` +
        `(slope=${trend.slope}, avg_similarity=${avg.toFixed(3)})`
      );
    }

    return alarming;
  }
}


// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

module.exports = {
  AgentIntentGuard,
  ToolSequenceModel,
  GoalDriftDetector,
  tokenize,
  termFrequency,
  cosineSimilarity
};
