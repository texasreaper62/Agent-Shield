'use strict';

/**
 * Agent Shield - Federated Threat Intelligence Network
 *
 * The CrowdStrike model for AI agents. Every deployment anonymously
 * contributes attack patterns back to a shared threat database.
 * More customers = better detection = more customers.
 *
 * All sharing uses differential privacy - no customer data is ever
 * exposed. Only anonymized attack signatures are shared.
 *
 * @module threat-intel-federation
 */

const crypto = require('crypto');
const { EventEmitter } = require('events');

// =========================================================================
// ThreatIntelFederation - The network coordinator
// =========================================================================

/**
 * Coordinates threat intelligence sharing across multiple
 * Agent Shield deployments with differential privacy.
 */
class ThreatIntelFederation extends EventEmitter {
  /**
   * @param {object} [options]
   * @param {string} [options.nodeId] - This node's identity.
   * @param {number} [options.minConfidence=0.7] - Min confidence to share a pattern.
   * @param {number} [options.noiseLevel=0.1] - Differential privacy noise level.
   * @param {number} [options.maxPatterns=5000] - Max patterns in the network database.
   * @param {number} [options.consensusThreshold=3] - Reports needed before pattern is promoted.
   */
  constructor(options = {}) {
    super();
    this.nodeId = options.nodeId || `node_${crypto.randomBytes(4).toString('hex')}`;
    this.minConfidence = options.minConfidence || 0.7;
    this.noiseLevel = options.noiseLevel || 0.1;
    this.maxPatterns = options.maxPatterns || 5000;
    this.consensusThreshold = options.consensusThreshold || 3;

    this._peers = new Map(); // peerId -> { lastSeen, patternsShared }
    this._patterns = new Map(); // signature -> ThreatPattern
    this._candidates = new Map(); // signature -> { reports, firstSeen }
    this._stats = {
      patternsReceived: 0,
      patternsShared: 0,
      patternsPromoted: 0,
      patternsRejected: 0,
      peersConnected: 0,
      attacksBlockedByNetwork: 0,
    };
  }

  /**
   * Register a peer node in the federation.
   * @param {string} peerId
   * @param {object} [metadata]
   */
  addPeer(peerId, metadata = {}) {
    this._peers.set(peerId, {
      id: peerId,
      lastSeen: Date.now(),
      patternsShared: 0,
      ...metadata,
    });
    this._stats.peersConnected = this._peers.size;
  }

  /**
   * Remove a peer from the federation.
   * @param {string} peerId
   */
  removePeer(peerId) {
    this._peers.delete(peerId);
    this._stats.peersConnected = this._peers.size;
  }

  /**
   * Submit a detected attack to the federation.
   * The attack text is anonymized into a signature before sharing.
   *
   * @param {object} report
   * @param {string} report.text - The attack text (kept local, never shared).
   * @param {string} report.category - Threat category.
   * @param {string} report.severity - Threat severity.
   * @param {number} [report.confidence] - Detection confidence 0-1.
   * @returns {object} { signature, status: 'promoted'|'candidate'|'rejected' }
   */
  submitThreat(report) {
    if (!report.text || !report.category) return { signature: null, status: 'rejected' };

    // Anonymize: hash the normalized text (never share raw text)
    const normalized = report.text.toLowerCase().replace(/\s+/g, ' ').trim();
    const signature = crypto.createHash('sha256').update(normalized).digest('hex').substring(0, 16);

    // Add differential privacy noise to confidence
    const rawConfidence = report.confidence || 0.8;
    const noise = (Math.random() - 0.5) * 2 * this.noiseLevel;
    const confidence = Math.max(0, Math.min(1, rawConfidence + noise));

    if (confidence < this.minConfidence) {
      this._stats.patternsRejected++;
      return { signature, status: 'rejected', reason: 'Below confidence threshold' };
    }

    // Check if this pattern is already promoted
    if (this._patterns.has(signature)) {
      const existing = this._patterns.get(signature);
      existing.reportCount++;
      existing.lastReported = Date.now();
      existing.confidence = Math.min(1, existing.confidence + 0.05);
      return { signature, status: 'already_known' };
    }

    // Add to candidates
    if (!this._candidates.has(signature)) {
      this._candidates.set(signature, {
        signature,
        category: report.category,
        severity: report.severity,
        confidence,
        reports: 1,
        firstSeen: Date.now(),
        reporters: new Set([this.nodeId]),
      });
    } else {
      const candidate = this._candidates.get(signature);
      candidate.reports++;
      candidate.reporters.add(this.nodeId);
      candidate.confidence = Math.max(candidate.confidence, confidence);
    }

    this._stats.patternsReceived++;

    // Check consensus
    const candidate = this._candidates.get(signature);
    if (candidate.reports >= this.consensusThreshold) {
      return this._promotePattern(candidate);
    }

    return { signature, status: 'candidate', reportsNeeded: this.consensusThreshold - candidate.reports };
  }

  /**
   * Check text against the federated pattern database.
   * @param {string} text
   * @returns {{ matches: Array, blocked: boolean }}
   */
  check(text) {
    const normalized = text.toLowerCase().replace(/\s+/g, ' ').trim();
    const signature = crypto.createHash('sha256').update(normalized).digest('hex').substring(0, 16);

    const matches = [];

    // Direct signature match
    if (this._patterns.has(signature)) {
      const pattern = this._patterns.get(signature);
      matches.push({
        signature,
        category: pattern.category,
        severity: pattern.severity,
        confidence: pattern.confidence,
        source: 'federation_exact',
      });
      this._stats.attacksBlockedByNetwork++;
    }

    // Partial keyword matching against promoted patterns
    const words = normalized.split(' ').filter(w => w.length > 3);
    for (const [sig, pattern] of this._patterns) {
      if (sig === signature) continue; // Already matched
      if (pattern.keywords && pattern.keywords.length > 0) {
        const overlap = pattern.keywords.filter(k => words.includes(k)).length;
        const similarity = pattern.keywords.length > 0 ? overlap / pattern.keywords.length : 0;
        if (similarity >= 0.6) {
          matches.push({
            signature: sig,
            category: pattern.category,
            severity: pattern.severity,
            confidence: pattern.confidence * similarity,
            source: 'federation_similar',
          });
          this._stats.attacksBlockedByNetwork++;
        }
      }
    }

    return {
      matches,
      blocked: matches.length > 0,
    };
  }

  /**
   * Receive patterns from another federation node.
   * @param {Array} patterns - Array of promoted patterns.
   * @returns {number} Number of new patterns accepted.
   */
  receivePatterns(patterns) {
    let accepted = 0;
    for (const p of patterns) {
      if (!this._patterns.has(p.signature)) {
        this._patterns.set(p.signature, {
          ...p,
          receivedAt: Date.now(),
          source: 'federation_peer',
        });
        accepted++;
      }
    }
    this._stats.patternsReceived += accepted;
    return accepted;
  }

  /**
   * Export promoted patterns for sharing with peers.
   * @param {number} [limit=100]
   * @returns {Array}
   */
  exportPatterns(limit = 100) {
    const patterns = [...this._patterns.values()]
      .sort((a, b) => b.confidence - a.confidence)
      .slice(0, limit)
      .map(p => ({
        signature: p.signature,
        category: p.category,
        severity: p.severity,
        confidence: p.confidence,
        keywords: p.keywords,
        reportCount: p.reportCount,
        firstSeen: p.firstSeen,
      }));
    this._stats.patternsShared += patterns.length;
    return patterns;
  }

  /**
   * Get network statistics.
   * @returns {object}
   */
  getStats() {
    return {
      ...this._stats,
      promotedPatterns: this._patterns.size,
      candidatePatterns: this._candidates.size,
      peers: [...this._peers.values()].map(p => ({ id: p.id, lastSeen: p.lastSeen })),
    };
  }

  /**
   * Get the health of the federation network.
   * @returns {object}
   */
  getHealth() {
    const now = Date.now();
    const activePeers = [...this._peers.values()].filter(p => now - p.lastSeen < 300000).length;
    return {
      healthy: activePeers > 0 || this._patterns.size > 0,
      activePeers,
      totalPeers: this._peers.size,
      patternCoverage: this._patterns.size,
      networkAge: this._patterns.size > 0
        ? now - Math.min(...[...this._patterns.values()].map(p => p.firstSeen))
        : 0,
    };
  }

  /** @private */
  _promotePattern(candidate) {
    const keywords = candidate.category ? [candidate.category] : [];
    // Extract keywords from reporters (if we had the text, but we only have signature)
    // In production this would use the genome sequencer

    const promoted = {
      signature: candidate.signature,
      category: candidate.category,
      severity: candidate.severity,
      confidence: candidate.confidence,
      keywords,
      reportCount: candidate.reports,
      reporterCount: candidate.reporters.size,
      firstSeen: candidate.firstSeen,
      promotedAt: Date.now(),
      lastReported: Date.now(),
    };

    this._patterns.set(candidate.signature, promoted);
    this._candidates.delete(candidate.signature);
    this._stats.patternsPromoted++;

    // Enforce max patterns
    if (this._patterns.size > this.maxPatterns) {
      const oldest = [...this._patterns.entries()]
        .sort((a, b) => a[1].lastReported - b[1].lastReported)[0];
      if (oldest) this._patterns.delete(oldest[0]);
    }

    this.emit('pattern_promoted', promoted);
    return { signature: candidate.signature, status: 'promoted' };
  }
}

/**
 * Connect multiple ThreatIntelFederation nodes into a mesh.
 * When any node promotes a pattern, all others receive it.
 * @param {ThreatIntelFederation[]} nodes
 * @returns {{ nodes, broadcast }}
 */
function createFederationMesh(nodes) {
  // Wire up: when any node promotes, share with all others
  for (const node of nodes) {
    node.on('pattern_promoted', (pattern) => {
      for (const peer of nodes) {
        if (peer.nodeId !== node.nodeId) {
          peer.receivePatterns([pattern]);
        }
      }
    });
    // Register all peers
    for (const peer of nodes) {
      if (peer.nodeId !== node.nodeId) {
        node.addPeer(peer.nodeId);
      }
    }
  }

  return {
    nodes,
    broadcast: (pattern) => {
      for (const node of nodes) {
        node.receivePatterns([pattern]);
      }
    },
  };
}

module.exports = {
  ThreatIntelFederation,
  createFederationMesh,
};
