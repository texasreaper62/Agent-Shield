'use strict';

/**
 * Agent Shield — Federated Threat Intelligence Node (v12)
 *
 * A local threat intelligence node that can share and receive
 * anonymized attack patterns with differential privacy.
 *
 * All processing runs locally — no data ever leaves your environment
 * unless explicitly exported via exportPatterns().
 *
 * @module persistent-learning
 */

const crypto = require('crypto');

/**
 * Local threat intelligence node.
 */
class ThreatIntelNode {
  /**
   * @param {object} [options]
   * @param {string} [options.nodeId] - Unique node identifier.
   * @param {number} [options.noiseLevel=0.1] - Differential privacy noise level (0-1).
   */
  constructor(options = {}) {
    this.nodeId = options.nodeId || crypto.randomBytes(4).toString('hex');
    this.noiseLevel = options.noiseLevel || 0.1;

    /** @type {Map<string, { pattern: string, hash: string, count: number, confidence: number, firstSeen: number, lastSeen: number, category: string }>} */
    this.patterns = new Map();
    this.stats = { reported: 0, imported: 0, exported: 0 };
  }

  /**
   * Report a locally observed attack pattern.
   * @param {object} attack
   * @param {string} attack.text - Attack text.
   * @param {string} attack.category - Attack category.
   * @param {string} [attack.severity] - Severity level.
   * @returns {{ hash: string, isNew: boolean }}
   */
  reportAttack(attack) {
    const hash = crypto.createHash('sha256').update(attack.text || '').digest('hex').substring(0, 16);
    const existing = this.patterns.get(hash);

    if (existing) {
      existing.count++;
      existing.lastSeen = Date.now();
      existing.confidence = Math.min(1, existing.confidence + 0.1);
      this.stats.reported++;
      return { hash, isNew: false };
    }

    this.patterns.set(hash, {
      pattern: (attack.text || '').substring(0, 200),
      hash,
      count: 1,
      confidence: 0.5,
      firstSeen: Date.now(),
      lastSeen: Date.now(),
      category: attack.category || 'unknown',
      severity: attack.severity || 'medium'
    });

    this.stats.reported++;
    return { hash, isNew: true };
  }

  /**
   * Export anonymized patterns with differential privacy.
   * @returns {Array<object>} Anonymized patterns.
   */
  exportPatterns() {
    const exported = [];
    for (const [, p] of this.patterns) {
      // Differential privacy: add noise to counts, truncate patterns
      const noisyCount = Math.max(1, Math.round(p.count + (Math.random() - 0.5) * p.count * this.noiseLevel));
      const noisyConfidence = Math.min(1, Math.max(0, p.confidence + (Math.random() - 0.5) * this.noiseLevel));

      exported.push({
        hash: p.hash,
        category: p.category,
        severity: p.severity,
        count: noisyCount,
        confidence: Math.round(noisyConfidence * 100) / 100,
        // Do NOT export the actual pattern text — only hash + metadata
        sourceNode: this.nodeId
      });
    }
    this.stats.exported += exported.length;
    return exported;
  }

  /**
   * Import patterns from another node.
   * @param {Array<object>} patterns - Patterns from exportPatterns().
   * @returns {{ imported: number, merged: number, new: number }}
   */
  importPatterns(patterns) {
    let merged = 0;
    let newPatterns = 0;

    for (const p of (patterns || [])) {
      if (!p.hash) continue;
      const existing = this.patterns.get(p.hash);

      if (existing) {
        // Merge: average confidence, sum counts
        existing.confidence = (existing.confidence + (p.confidence || 0.5)) / 2;
        existing.count += p.count || 1;
        existing.lastSeen = Date.now();
        merged++;
      } else {
        this.patterns.set(p.hash, {
          pattern: '[imported]',
          hash: p.hash,
          count: p.count || 1,
          confidence: p.confidence || 0.5,
          firstSeen: Date.now(),
          lastSeen: Date.now(),
          category: p.category || 'unknown',
          severity: p.severity || 'medium'
        });
        newPatterns++;
      }
    }

    this.stats.imported += merged + newPatterns;
    return { imported: merged + newPatterns, merged, new: newPatterns };
  }

  /**
   * Get all known patterns.
   * @returns {Array<object>}
   */
  getKnownPatterns() {
    return [...this.patterns.values()].sort((a, b) => b.confidence - a.confidence);
  }

  /**
   * Check if a text matches any known pattern.
   * @param {string} text
   * @returns {{ matches: boolean, pattern: object|null }}
   */
  checkAgainstKnown(text) {
    const hash = crypto.createHash('sha256').update(text || '').digest('hex').substring(0, 16);
    const match = this.patterns.get(hash);
    return { matches: !!match, pattern: match || null };
  }

  /**
   * Get stats.
   * @returns {object}
   */
  getStats() {
    return { ...this.stats, totalPatterns: this.patterns.size, nodeId: this.nodeId };
  }
}

module.exports = { ThreatIntelNode };
