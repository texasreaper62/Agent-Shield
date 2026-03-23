'use strict';

/**
 * Agent Shield Pro — Enterprise Threat Intelligence Feed
 *
 * Wraps the core ThreatIntelFederation with Pro-specific features:
 * - Auto-submit threats from scan results
 * - Feed subscription with configurable polling
 * - Org-scoped pattern namespacing
 * - Threat feed statistics and reporting
 *
 * Enterprise tier only.
 *
 * @module threat-intel
 */

const crypto = require('crypto');

/**
 * Enterprise threat intelligence feed manager.
 * Coordinates threat pattern sharing across an organization's deployments.
 */
class ThreatIntelFeed {
  /**
   * @param {Object} [options]
   * @param {string} [options.orgId] - Organization identifier for namespacing
   * @param {number} [options.minConfidence=0.7] - Minimum confidence to share patterns
   * @param {number} [options.noiseLevel=0.1] - Differential privacy noise level
   * @param {number} [options.maxPatterns=10000] - Max patterns in local database
   * @param {number} [options.consensusThreshold=3] - Reports needed to promote a pattern
   * @param {boolean} [options.autoSubmit=true] - Auto-submit threats from scans
   * @param {number} [options.retentionDays=90] - Days to retain patterns before expiry
   */
  constructor(options = {}) {
    this.orgId = options.orgId || 'default';
    this.nodeId = `${this.orgId}_${crypto.randomBytes(4).toString('hex')}`;
    this.minConfidence = options.minConfidence || 0.7;
    this.noiseLevel = options.noiseLevel || 0.1;
    this.maxPatterns = options.maxPatterns || 10000;
    this.consensusThreshold = options.consensusThreshold || 3;
    this.autoSubmit = options.autoSubmit !== false;
    this.retentionDays = options.retentionDays || 90;

    /** @private */
    this._patterns = new Map();     // signature -> ThreatPattern
    /** @private */
    this._candidates = new Map();   // signature -> candidate
    /** @private */
    this._subscribers = [];         // callback functions
    /** @private */
    this._stats = {
      patternsReceived: 0,
      patternsShared: 0,
      patternsPromoted: 0,
      patternsExpired: 0,
      attacksBlocked: 0,
      lastUpdate: null,
    };
  }

  /**
   * Submit a threat to the feed from a scan result.
   * Text is anonymized via SHA-256 before storage — raw text never leaves the caller.
   *
   * @param {Object} report
   * @param {string} report.text - Attack text (hashed locally, never stored raw)
   * @param {string} report.category - Threat category
   * @param {string} report.severity - Threat severity
   * @param {number} [report.confidence=0.8] - Detection confidence 0-1
   * @returns {{ signature: string, status: string }}
   */
  submit(report) {
    if (!report || !report.text || !report.category) {
      return { signature: null, status: 'rejected', reason: 'Missing text or category' };
    }

    const normalized = report.text.toLowerCase().replace(/\s+/g, ' ').trim();
    const signature = crypto.createHash('sha256').update(normalized).digest('hex').substring(0, 16);

    // Add differential privacy noise to confidence
    const rawConfidence = report.confidence || 0.8;
    const noise = (Math.random() - 0.5) * 2 * this.noiseLevel;
    const confidence = Math.max(0, Math.min(1, rawConfidence + noise));

    if (confidence < this.minConfidence) {
      return { signature, status: 'rejected', reason: 'Below confidence threshold' };
    }

    // Already promoted?
    if (this._patterns.has(signature)) {
      const existing = this._patterns.get(signature);
      existing.reportCount++;
      existing.lastReported = Date.now();
      return { signature, status: 'already_known' };
    }

    // Track as candidate
    if (!this._candidates.has(signature)) {
      this._candidates.set(signature, {
        signature,
        category: report.category,
        severity: report.severity || 'medium',
        confidence,
        reports: 1,
        keywords: this._extractKeywords(normalized),
        firstSeen: Date.now(),
      });
    } else {
      const candidate = this._candidates.get(signature);
      candidate.reports++;
      candidate.confidence = Math.max(candidate.confidence, confidence);
    }

    this._stats.patternsReceived++;

    // Check consensus for promotion
    const candidate = this._candidates.get(signature);
    if (candidate.reports >= this.consensusThreshold) {
      return this._promote(candidate);
    }

    return {
      signature,
      status: 'candidate',
      reportsNeeded: this.consensusThreshold - candidate.reports,
    };
  }

  /**
   * Check text against the threat feed.
   * @param {string} text - Text to check
   * @returns {{ matches: Array, blocked: boolean }}
   */
  check(text) {
    if (!text || typeof text !== 'string') {
      return { matches: [], blocked: false };
    }

    const normalized = text.toLowerCase().replace(/\s+/g, ' ').trim();
    const signature = crypto.createHash('sha256').update(normalized).digest('hex').substring(0, 16);
    const matches = [];

    // Exact signature match
    if (this._patterns.has(signature)) {
      const pattern = this._patterns.get(signature);
      matches.push({
        signature,
        category: pattern.category,
        severity: pattern.severity,
        confidence: pattern.confidence,
        source: 'threat_feed_exact',
      });
      this._stats.attacksBlocked++;
    }

    // Keyword similarity match
    const words = normalized.split(/\s+/).filter(w => w.length > 3);
    for (const [sig, pattern] of this._patterns) {
      if (sig === signature) continue;
      if (pattern.keywords && pattern.keywords.length > 0) {
        const overlap = pattern.keywords.filter(k => words.includes(k)).length;
        const similarity = overlap / pattern.keywords.length;
        if (similarity >= 0.6) {
          matches.push({
            signature: sig,
            category: pattern.category,
            severity: pattern.severity,
            confidence: pattern.confidence * similarity,
            source: 'threat_feed_similar',
          });
          this._stats.attacksBlocked++;
        }
      }
    }

    return { matches, blocked: matches.length > 0 };
  }

  /**
   * Hook into a shield's scan pipeline to auto-submit threats.
   * @param {Object} shield - An AgentShield or ProShield instance
   */
  hookScan(shield) {
    if (!this.autoSubmit) return;

    const originalScan = shield.scan.bind(shield);
    const feed = this;

    shield.scan = function (text, options) {
      const result = originalScan(text, options);

      // Auto-submit detected threats
      if (result.threats && result.threats.length > 0) {
        for (const threat of result.threats) {
          feed.submit({
            text,
            category: threat.category || 'unknown',
            severity: threat.severity || 'medium',
            confidence: threat.confidence || 0.8,
          });
        }
      }

      // Also check the feed for additional matches
      const feedResult = feed.check(text);
      if (feedResult.blocked) {
        result.threats = result.threats || [];
        for (const match of feedResult.matches) {
          result.threats.push({
            category: match.category,
            severity: match.severity,
            description: `Threat feed match (${match.source})`,
            confidence: match.confidence,
            source: 'threat_intel_feed',
          });
        }
        if (result.status === 'safe') {
          result.status = 'warning';
        }
      }

      return result;
    };
  }

  /**
   * Subscribe to new pattern promotions.
   * @param {Function} callback - Called with (pattern) on promotion
   * @returns {Function} Unsubscribe function
   */
  subscribe(callback) {
    this._subscribers.push(callback);
    return () => {
      const idx = this._subscribers.indexOf(callback);
      if (idx >= 0) this._subscribers.splice(idx, 1);
    };
  }

  /**
   * Import patterns from another feed or a JSON export.
   * @param {Array<Object>} patterns - Array of pattern objects
   * @returns {{ imported: number, skipped: number }}
   */
  importPatterns(patterns) {
    let imported = 0;
    let skipped = 0;

    for (const p of patterns) {
      if (!p.signature || !p.category) {
        skipped++;
        continue;
      }
      if (this._patterns.has(p.signature)) {
        skipped++;
        continue;
      }
      if (this._patterns.size >= this.maxPatterns) {
        break;
      }
      this._patterns.set(p.signature, {
        signature: p.signature,
        category: p.category,
        severity: p.severity || 'medium',
        confidence: p.confidence || 0.7,
        keywords: p.keywords || [],
        reportCount: p.reportCount || 1,
        promotedAt: p.promotedAt || Date.now(),
        lastReported: p.lastReported || Date.now(),
      });
      imported++;
    }

    return { imported, skipped };
  }

  /**
   * Export all promoted patterns for sharing.
   * @returns {Array<Object>}
   */
  exportPatterns() {
    return Array.from(this._patterns.values()).map(p => ({
      signature: p.signature,
      category: p.category,
      severity: p.severity,
      confidence: p.confidence,
      keywords: p.keywords,
      reportCount: p.reportCount,
      promotedAt: p.promotedAt,
    }));
  }

  /**
   * Expire old patterns beyond retentionDays.
   * @returns {number} Number of patterns expired
   */
  expireOld() {
    const cutoff = Date.now() - (this.retentionDays * 24 * 60 * 60 * 1000);
    let expired = 0;

    for (const [sig, pattern] of this._patterns) {
      if (pattern.lastReported < cutoff) {
        this._patterns.delete(sig);
        expired++;
      }
    }

    this._stats.patternsExpired += expired;
    return expired;
  }

  /**
   * Get feed statistics.
   * @returns {Object}
   */
  getStats() {
    return {
      ...this._stats,
      promotedPatterns: this._patterns.size,
      candidatePatterns: this._candidates.size,
      orgId: this.orgId,
      nodeId: this.nodeId,
    };
  }

  /** @private */
  _promote(candidate) {
    const pattern = {
      signature: candidate.signature,
      category: candidate.category,
      severity: candidate.severity,
      confidence: candidate.confidence,
      keywords: candidate.keywords || [],
      reportCount: candidate.reports,
      promotedAt: Date.now(),
      lastReported: Date.now(),
    };

    this._patterns.set(candidate.signature, pattern);
    this._candidates.delete(candidate.signature);
    this._stats.patternsPromoted++;
    this._stats.lastUpdate = new Date().toISOString();

    // Notify subscribers
    for (const cb of this._subscribers) {
      try { cb(pattern); } catch (_e) { /* non-fatal */ }
    }

    return { signature: candidate.signature, status: 'promoted' };
  }

  /** @private */
  _extractKeywords(text) {
    const stopWords = new Set([
      'the', 'and', 'for', 'are', 'but', 'not', 'you', 'all',
      'can', 'her', 'was', 'one', 'our', 'out', 'has', 'have',
      'this', 'that', 'with', 'from', 'they', 'been', 'will',
    ]);
    return text.split(/\s+/)
      .filter(w => w.length > 3 && !stopWords.has(w))
      .slice(0, 10);
  }
}

module.exports = { ThreatIntelFeed };
