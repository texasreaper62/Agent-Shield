'use strict';

/**
 * Agent Shield — Sybil Attack Detector
 *
 * Detects coordinated fake agents acting in concert — Sybil attacks where
 * multiple agents collude to manipulate outcomes, bypass voting/consensus
 * mechanisms, or overwhelm defenses.
 *
 * Detection signals: behavioral similarity, temporal correlation, content
 * similarity (Jaccard), creation burst patterns, and voting collusion.
 *
 * All processing runs locally — no data ever leaves your environment.
 *
 * @module sybil-detector
 */

const crypto = require('crypto');

const LOG_PREFIX = '[Agent Shield]';

// =========================================================================
// Utility helpers
// =========================================================================

/**
 * Compute Jaccard similarity between two sets.
 * @param {Set<string>} a
 * @param {Set<string>} b
 * @returns {number} Similarity in [0, 1].
 */
function jaccardSimilarity(a, b) {
  if (a.size === 0 && b.size === 0) return 1;
  let intersection = 0;
  for (const item of a) {
    if (b.has(item)) intersection++;
  }
  const union = a.size + b.size - intersection;
  return union === 0 ? 1 : intersection / union;
}

/**
 * Tokenize a string into a set of lowercase words.
 * @param {string} text
 * @returns {Set<string>}
 */
function tokenize(text) {
  if (!text || typeof text !== 'string') return new Set();
  return new Set(text.toLowerCase().split(/\s+/).filter(Boolean));
}

// =========================================================================
// SybilDetector
// =========================================================================

/**
 * Detects Sybil clusters among registered agents by analyzing behavioral
 * similarity, temporal correlation, content overlap, creation bursts, and
 * voting collusion.
 */
class SybilDetector {
  /**
   * @param {object} [options]
   * @param {number} [options.similarityThreshold=0.7] - Minimum similarity score to consider agents as part of a cluster.
   * @param {number} [options.timeWindowMs=60000] - Time window in ms for temporal correlation analysis.
   * @param {number} [options.minClusterSize=3] - Minimum number of agents to form a Sybil cluster.
   */
  constructor(options = {}) {
    this.similarityThreshold = options.similarityThreshold != null ? options.similarityThreshold : 0.7;
    this.timeWindowMs = options.timeWindowMs != null ? options.timeWindowMs : 60000;
    this.minClusterSize = options.minClusterSize != null ? options.minClusterSize : 3;

    /** @type {Map<string, object>} */
    this._agents = new Map();

    /** @type {Map<string, Array<object>>} */
    this._actions = new Map();

    console.log('%s SybilDetector initialized (threshold: %s, window: %dms, minCluster: %d)',
      LOG_PREFIX, this.similarityThreshold, this.timeWindowMs, this.minClusterSize);
  }

  /**
   * Register an agent with metadata.
   * @param {string} agentId - Unique agent identifier.
   * @param {object} metadata - Agent metadata (name, capabilities, createdAt, etc.).
   */
  registerAgent(agentId, metadata) {
    if (!agentId || typeof agentId !== 'string') return;
    const record = {
      id: agentId,
      name: metadata && metadata.name || agentId,
      capabilities: metadata && metadata.capabilities || [],
      createdAt: metadata && metadata.createdAt || Date.now(),
      registeredAt: Date.now(),
      metadata: metadata || {}
    };
    this._agents.set(agentId, record);
    if (!this._actions.has(agentId)) {
      this._actions.set(agentId, []);
    }
    console.log('%s Registered agent: %s', LOG_PREFIX, agentId);
  }

  /**
   * Record an action performed by an agent.
   * @param {string} agentId - Agent identifier.
   * @param {object} action - Action details { type, target, timestamp, content }.
   */
  recordAction(agentId, action) {
    if (!agentId || typeof agentId !== 'string') return;
    if (!action || typeof action !== 'object') return;
    if (!this._actions.has(agentId)) {
      this._actions.set(agentId, []);
    }
    const record = {
      type: action.type || 'unknown',
      target: action.target || null,
      timestamp: action.timestamp || Date.now(),
      content: action.content || ''
    };
    this._actions.get(agentId).push(record);
  }

  /**
   * Analyze all registered agents for Sybil clusters.
   * @returns {{ clusters: Array<{ agents: string[], similarity: number, evidence: string[] }>, sybilRisk: 'none'|'low'|'medium'|'high' }}
   */
  detectClusters() {
    const agentIds = Array.from(this._agents.keys());
    if (agentIds.length < 2) {
      return { clusters: [], sybilRisk: 'none' };
    }

    // Compute pairwise similarity scores
    const pairScores = new Map(); // "id1|id2" -> { score, evidence }

    for (let i = 0; i < agentIds.length; i++) {
      for (let j = i + 1; j < agentIds.length; j++) {
        const a = agentIds[i];
        const b = agentIds[j];
        const result = this._computePairSimilarity(a, b);
        const key = a + '|' + b;
        pairScores.set(key, result);
      }
    }

    // Build clusters using greedy union-find approach
    const parent = new Map();
    for (const id of agentIds) parent.set(id, id);

    const find = (x) => {
      while (parent.get(x) !== x) {
        parent.set(x, parent.get(parent.get(x)));
        x = parent.get(x);
      }
      return x;
    };

    const union = (x, y) => {
      const rx = find(x);
      const ry = find(y);
      if (rx !== ry) parent.set(rx, ry);
    };

    // Merge agents that exceed threshold
    for (const [key, result] of pairScores) {
      if (result.score >= this.similarityThreshold) {
        const [a, b] = key.split('|');
        union(a, b);
      }
    }

    // Group by root
    const groups = new Map();
    for (const id of agentIds) {
      const root = find(id);
      if (!groups.has(root)) groups.set(root, []);
      groups.get(root).push(id);
    }

    // Filter to clusters meeting minimum size
    const clusters = [];
    for (const [, members] of groups) {
      if (members.length >= this.minClusterSize) {
        // Compute average similarity and collect evidence
        let totalSim = 0;
        let pairCount = 0;
        const evidenceSet = new Set();
        for (let i = 0; i < members.length; i++) {
          for (let j = i + 1; j < members.length; j++) {
            const key = members[i] + '|' + members[j];
            const altKey = members[j] + '|' + members[i];
            const result = pairScores.get(key) || pairScores.get(altKey);
            if (result) {
              totalSim += result.score;
              pairCount++;
              for (const ev of result.evidence) evidenceSet.add(ev);
            }
          }
        }
        const avgSim = pairCount > 0 ? totalSim / pairCount : 0;
        clusters.push({
          agents: members,
          similarity: Math.round(avgSim * 1000) / 1000,
          evidence: Array.from(evidenceSet)
        });
      }
    }

    // Determine overall risk
    let sybilRisk = 'none';
    if (clusters.length > 0) {
      const maxSim = Math.max(...clusters.map(c => c.similarity));
      const maxSize = Math.max(...clusters.map(c => c.agents.length));
      if (maxSim >= 0.9 || maxSize >= 5) {
        sybilRisk = 'high';
      } else if (maxSim >= 0.7) {
        sybilRisk = 'medium';
      } else {
        sybilRisk = 'low';
      }
    }

    console.log('%s Sybil detection complete: %d cluster(s), risk=%s',
      LOG_PREFIX, clusters.length, sybilRisk);

    return { clusters, sybilRisk };
  }

  // -----------------------------------------------------------------------
  // Internal similarity computation
  // -----------------------------------------------------------------------

  /**
   * Compute composite similarity between two agents.
   * @private
   * @param {string} agentA
   * @param {string} agentB
   * @returns {{ score: number, evidence: string[] }}
   */
  _computePairSimilarity(agentA, agentB) {
    const evidence = [];
    const scores = [];

    // 1. Behavioral similarity — same action types on same targets in similar order
    const behaviorSim = this._behavioralSimilarity(agentA, agentB);
    if (behaviorSim > 0.5) {
      evidence.push(`behavioral_similarity: ${behaviorSim.toFixed(3)}`);
    }
    scores.push(behaviorSim);

    // 2. Temporal correlation — actions in tight time windows
    const temporalSim = this._temporalCorrelation(agentA, agentB);
    if (temporalSim > 0.5) {
      evidence.push(`temporal_correlation: ${temporalSim.toFixed(3)}`);
    }
    scores.push(temporalSim);

    // 3. Content similarity — Jaccard on action content
    const contentSim = this._contentSimilarity(agentA, agentB);
    if (contentSim > 0.5) {
      evidence.push(`content_similarity: ${contentSim.toFixed(3)}`);
    }
    scores.push(contentSim);

    // 4. Creation pattern — burst detection
    const creationSim = this._creationBurstScore(agentA, agentB);
    if (creationSim > 0.5) {
      evidence.push(`creation_burst: ${creationSim.toFixed(3)}`);
    }
    scores.push(creationSim);

    // 5. Voting collusion — lockstep approval
    const voteSim = this._votingCollusion(agentA, agentB);
    if (voteSim > 0.5) {
      evidence.push(`voting_collusion: ${voteSim.toFixed(3)}`);
    }
    scores.push(voteSim);

    // Composite: weighted average
    const total = scores.reduce((a, b) => a + b, 0);
    const composite = scores.length > 0 ? total / scores.length : 0;

    return { score: Math.round(composite * 1000) / 1000, evidence };
  }

  /**
   * Behavioral similarity: compare action type+target sequences.
   * @private
   */
  _behavioralSimilarity(agentA, agentB) {
    const actionsA = this._actions.get(agentA) || [];
    const actionsB = this._actions.get(agentB) || [];
    if (actionsA.length === 0 || actionsB.length === 0) return 0;

    const seqA = new Set(actionsA.map(a => `${a.type}:${a.target}`));
    const seqB = new Set(actionsB.map(a => `${a.type}:${a.target}`));
    return jaccardSimilarity(seqA, seqB);
  }

  /**
   * Temporal correlation: fraction of actions that have a matching
   * action from the other agent within the time window.
   * @private
   */
  _temporalCorrelation(agentA, agentB) {
    const actionsA = this._actions.get(agentA) || [];
    const actionsB = this._actions.get(agentB) || [];
    if (actionsA.length === 0 || actionsB.length === 0) return 0;

    let matched = 0;
    for (const aAct of actionsA) {
      for (const bAct of actionsB) {
        if (aAct.type === bAct.type &&
            Math.abs(aAct.timestamp - bAct.timestamp) <= this.timeWindowMs) {
          matched++;
          break;
        }
      }
    }
    return matched / actionsA.length;
  }

  /**
   * Content similarity: Jaccard similarity of tokenized content across all actions.
   * @private
   */
  _contentSimilarity(agentA, agentB) {
    const actionsA = this._actions.get(agentA) || [];
    const actionsB = this._actions.get(agentB) || [];
    if (actionsA.length === 0 || actionsB.length === 0) return 0;

    const tokensA = new Set();
    const tokensB = new Set();
    for (const a of actionsA) {
      for (const t of tokenize(a.content)) tokensA.add(t);
    }
    for (const b of actionsB) {
      for (const t of tokenize(b.content)) tokensB.add(t);
    }
    return jaccardSimilarity(tokensA, tokensB);
  }

  /**
   * Creation burst score: returns 1.0 if agents were created within the
   * time window, 0.0 otherwise.
   * @private
   */
  _creationBurstScore(agentA, agentB) {
    const metaA = this._agents.get(agentA);
    const metaB = this._agents.get(agentB);
    if (!metaA || !metaB) return 0;
    const diff = Math.abs(metaA.createdAt - metaB.createdAt);
    if (diff <= this.timeWindowMs) {
      return 1.0;
    }
    // Gradual decay up to 5x window
    const maxWindow = this.timeWindowMs * 5;
    if (diff <= maxWindow) {
      return 1.0 - (diff - this.timeWindowMs) / (maxWindow - this.timeWindowMs);
    }
    return 0;
  }

  /**
   * Voting collusion: fraction of vote/approve actions that target the
   * same proposals.
   * @private
   */
  _votingCollusion(agentA, agentB) {
    const actionsA = this._actions.get(agentA) || [];
    const actionsB = this._actions.get(agentB) || [];

    const votesA = new Set(
      actionsA.filter(a => a.type === 'vote' || a.type === 'approve')
        .map(a => a.target)
    );
    const votesB = new Set(
      actionsB.filter(a => a.type === 'vote' || a.type === 'approve')
        .map(a => a.target)
    );

    if (votesA.size === 0 && votesB.size === 0) return 0;
    return jaccardSimilarity(votesA, votesB);
  }
}

// =========================================================================
// AgentIdentityVerifier
// =========================================================================

/**
 * Verifies agent uniqueness through challenge-response and shared secret detection.
 */
class AgentIdentityVerifier {
  constructor() {
    /** @type {Map<string, { nonce: string, issuedAt: number }>} */
    this._challenges = new Map();

    /** @type {Map<string, string>} */
    this._agentKeys = new Map();

    /** @type {number} Challenge expiration in ms (default 30s). */
    this.challengeExpiryMs = 30000;

    console.log('%s AgentIdentityVerifier initialized', LOG_PREFIX);
  }

  /**
   * Generate a unique challenge (nonce-based).
   * @returns {{ challengeId: string, nonce: string, issuedAt: number }}
   */
  generateChallenge() {
    const nonce = crypto.randomBytes(32).toString('hex');
    const challengeId = crypto.randomBytes(16).toString('hex');
    const issuedAt = Date.now();
    this._challenges.set(challengeId, { nonce, issuedAt });
    return { challengeId, nonce, issuedAt };
  }

  /**
   * Verify a challenge-response from an agent.
   *
   * The expected response is HMAC-SHA256(nonce, agentKey). If the agent has
   * previously registered a key, it is used for verification; otherwise
   * the response is accepted and the key is stored.
   *
   * @param {string} agentId - Agent identifier.
   * @param {string} challengeId - The challenge ID returned by generateChallenge().
   * @param {string} response - The agent's HMAC response.
   * @param {string} [agentKey] - The agent's signing key (required on first verification).
   * @returns {{ valid: boolean, reason: string }}
   */
  verifyResponse(agentId, challengeId, response, agentKey) {
    if (!agentId || !challengeId || !response) {
      return { valid: false, reason: 'missing_parameters' };
    }

    const challenge = this._challenges.get(challengeId);
    if (!challenge) {
      return { valid: false, reason: 'unknown_challenge' };
    }

    // Check expiry
    if (Date.now() - challenge.issuedAt > this.challengeExpiryMs) {
      this._challenges.delete(challengeId);
      return { valid: false, reason: 'challenge_expired' };
    }

    // Determine the key
    const key = agentKey || this._agentKeys.get(agentId);
    if (!key) {
      return { valid: false, reason: 'no_key_registered' };
    }

    // Compute expected HMAC
    const expected = crypto.createHmac('sha256', key)
      .update(challenge.nonce)
      .digest('hex');

    const valid = crypto.timingSafeEqual(
      Buffer.from(expected, 'hex'),
      Buffer.from(response, 'hex')
    );

    if (valid) {
      // Store key for future verifications
      this._agentKeys.set(agentId, key);
      this._challenges.delete(challengeId);
    }

    return {
      valid,
      reason: valid ? 'verified' : 'invalid_response'
    };
  }

  /**
   * Detect if multiple agents share the same signing key by comparing
   * HMAC outputs on a fixed probe message.
   *
   * @param {Array<{ agentId: string, key: string }>} agents - List of agents with their keys.
   * @returns {{ sharedKeyGroups: Array<{ agents: string[], keyFingerprint: string }>, hasSharedKeys: boolean }}
   */
  detectSharedSecrets(agents) {
    if (!Array.isArray(agents) || agents.length === 0) {
      return { sharedKeyGroups: [], hasSharedKeys: false };
    }

    const probeMessage = 'agent-shield-sybil-probe-v1';
    const fingerprintMap = new Map(); // fingerprint -> [agentIds]

    for (const agent of agents) {
      if (!agent || !agent.agentId || !agent.key) continue;
      const fingerprint = crypto.createHmac('sha256', agent.key)
        .update(probeMessage)
        .digest('hex');
      if (!fingerprintMap.has(fingerprint)) {
        fingerprintMap.set(fingerprint, []);
      }
      fingerprintMap.get(fingerprint).push(agent.agentId);
    }

    const sharedKeyGroups = [];
    for (const [fingerprint, agentIds] of fingerprintMap) {
      if (agentIds.length > 1) {
        sharedKeyGroups.push({
          agents: agentIds,
          keyFingerprint: fingerprint.slice(0, 16) + '...'
        });
      }
    }

    const hasSharedKeys = sharedKeyGroups.length > 0;
    if (hasSharedKeys) {
      console.log('%s Shared secret detected among %d group(s)',
        LOG_PREFIX, sharedKeyGroups.length);
    }

    return { sharedKeyGroups, hasSharedKeys };
  }
}

// =========================================================================
// Exports
// =========================================================================

module.exports = { SybilDetector, AgentIdentityVerifier, jaccardSimilarity, tokenize };
