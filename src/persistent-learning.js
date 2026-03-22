'use strict';

/**
 * Agent Shield — Persistent Learning + Feedback API (v8.0)
 *
 * Makes detection smarter over time by persisting learned patterns to disk
 * and accepting user feedback. Extends the concepts from LearningLoop
 * (adaptive-defense.js) with disk persistence, pattern decay, and a
 * structured feedback collector.
 *
 * - PersistentLearningLoop: Learns from attacks, promotes patterns,
 *   persists to disk, decays stale patterns, handles false-positive revocation.
 *
 * - FeedbackCollector: Collects FP/FN reports, processes them through the
 *   learning loop, and triggers retraining when enough data accumulates.
 *
 * Zero external dependencies. All processing runs locally.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const LOG_PREFIX = '[Agent Shield]';

// Injection-related keywords used to filter n-gram candidates
const INJECTION_KEYWORDS = [
  'ignore', 'forget', 'disregard', 'system', 'override', 'bypass',
  'reveal', 'output', 'print', 'show', 'dump', 'extract', 'delete',
  'execute', 'admin', 'sudo', 'prompt', 'instruction', 'disable',
  'security', 'safety', 'restrict', 'password', 'secret', 'token',
  'credential', 'exfiltrate', 'inject', 'escalat', 'jailbreak',
  'roleplay', 'pretend', 'act', 'fetch', 'curl', 'wget'
];

/**
 * Generate a unique ID. Uses crypto.randomUUID() when available,
 * falls back to timestamp + random hex.
 * @returns {string}
 * @private
 */
function generateId(prefix) {
  let uid;
  if (typeof crypto.randomUUID === 'function') {
    uid = crypto.randomUUID();
  } else {
    uid = Date.now().toString(16) + Math.random().toString(16).slice(2, 10);
  }
  return prefix ? `${prefix}_${uid}` : uid;
}

/**
 * Compute a short SHA-256 hash of a string.
 * @param {string} text
 * @returns {string}
 * @private
 */
function shortHash(text) {
  return crypto.createHash('sha256').update(text).digest('hex').substring(0, 16);
}

// =========================================================================
// PersistentLearningLoop
// =========================================================================

/**
 * Self-improving detection loop with disk persistence.
 *
 * Ingests attacks, extracts n-gram signatures, promotes candidates to active
 * patterns after repeated hits, persists state to disk, and decays stale
 * patterns automatically.
 */
class PersistentLearningLoop {
  /**
   * @param {object} [config]
   * @param {boolean} [config.persist=false] - Write patterns to disk
   * @param {string} [config.persistPath='./.agentshield/learned-patterns.json'] - File path
   * @param {number} [config.promotionThreshold=3] - Hits before pattern is promoted
   * @param {number} [config.maxPatterns=500] - Max active patterns
   * @param {number} [config.decayMs=604800000] - Pattern decay time (7 days default)
   * @param {number} [config.maxFalsePositives=3] - FP reports before revocation
   */
  constructor(config = {}) {
    this._persist = config.persist === true;
    this._persistPath = config.persistPath || './.agentshield/learned-patterns.json';
    this._promotionThreshold = config.promotionThreshold || 3;
    this._maxPatterns = config.maxPatterns || 500;
    this._decayMs = config.decayMs || 604800000; // 7 days
    this._maxFalsePositives = config.maxFalsePositives || 3;

    /** @type {Map<string, object>} sigHash → candidate */
    this._candidates = new Map();
    /** @type {Map<string, object>} patternId → promoted pattern */
    this._promoted = new Map();

    this.stats = {
      attacksIngested: 0,
      candidatesCreated: 0,
      patternsPromoted: 0,
      falsePositivesReported: 0,
      patternsRevoked: 0,
      patternsDecayed: 0,
      saves: 0,
      loads: 0
    };

    // Attempt to load from disk on construction
    if (this._persist) {
      this.load();
    }
  }

  /**
   * Ingest an attack that was detected by other means.
   * Extracts signature patterns and adds to candidate pool.
   * @param {string} text - The attack text
   * @param {object} [meta] - { category, source, severity }
   * @returns {object} { candidates: number, signatures: string[] }
   */
  ingest(text, meta = {}) {
    if (!text || typeof text !== 'string') {
      return { candidates: 0, signatures: [] };
    }

    this.stats.attacksIngested++;
    const signatures = this._extractSignatures(text);
    let candidatesUpdated = 0;
    const promoted = [];

    for (const sig of signatures) {
      const sigHash = shortHash(sig);
      const existing = this._candidates.get(sigHash);

      if (existing) {
        existing.hitCount++;
        existing.lastSeen = Date.now();
        existing.category = meta.category || existing.category;
        candidatesUpdated++;

        // Check for promotion
        if (existing.hitCount >= this._promotionThreshold &&
            !existing.promoted &&
            this._promoted.size < this._maxPatterns) {
          existing.promoted = true;
          const patternId = `PL_${sigHash.substring(0, 12)}`;
          const confidence = Math.min(1.0, 0.5 + (existing.hitCount * 0.05));
          this._promoted.set(patternId, {
            patternId,
            signature: sig,
            category: meta.category || 'learned',
            confidence,
            hitCount: existing.hitCount,
            fpCount: 0,
            promotedAt: Date.now(),
            lastSeen: Date.now(),
            active: true,
            source: meta.source || 'persistent_learning'
          });
          this.stats.patternsPromoted++;
          promoted.push(patternId);
          console.log(`${LOG_PREFIX} Pattern promoted: ${patternId} (signature: "${sig.substring(0, 40)}")`);

          // Auto-save after promotion
          if (this._persist) {
            this.save();
          }
        }
      } else {
        this._candidates.set(sigHash, {
          signature: sig,
          sigHash,
          category: meta.category || 'unknown',
          hitCount: 1,
          firstSeen: Date.now(),
          lastSeen: Date.now(),
          promoted: false
        });
        this.stats.candidatesCreated++;
        candidatesUpdated++;
      }
    }

    return { candidates: candidatesUpdated, signatures };
  }

  /**
   * Check text against learned patterns.
   * @param {string} text
   * @returns {object} { matches: Array<{ pattern, source: 'learned', confidence }>, count: number }
   */
  check(text) {
    if (!text || typeof text !== 'string') {
      return { matches: [], count: 0 };
    }

    const lower = text.toLowerCase();
    const matches = [];

    for (const [patternId, pattern] of this._promoted) {
      if (!pattern.active) continue;
      if (lower.includes(pattern.signature.toLowerCase())) {
        pattern.lastSeen = Date.now();
        matches.push({
          patternId,
          pattern: pattern.signature,
          source: 'learned',
          category: pattern.category,
          confidence: pattern.confidence
        });
      }
    }

    return { matches, count: matches.length };
  }

  /**
   * Report a false positive on a learned pattern.
   * @param {string} patternId
   * @returns {object} { revoked: boolean, fpCount: number, remaining: number }
   */
  reportFalsePositive(patternId) {
    const pattern = this._promoted.get(patternId);
    if (!pattern) {
      return { revoked: false, fpCount: 0, remaining: 0 };
    }

    pattern.fpCount = (pattern.fpCount || 0) + 1;
    this.stats.falsePositivesReported++;

    let revoked = false;
    if (pattern.fpCount >= this._maxFalsePositives) {
      pattern.active = false;
      this.stats.patternsRevoked++;
      revoked = true;
      console.log(`${LOG_PREFIX} Pattern revoked due to false positives: ${patternId}`);

      if (this._persist) {
        this.save();
      }
    }

    const remaining = [...this._promoted.values()].filter(p => p.active).length;
    return { revoked, fpCount: pattern.fpCount, remaining };
  }

  /**
   * Save learned patterns to disk (if persist=true).
   * Writes atomically via temp file + rename.
   * @returns {boolean} success
   */
  save() {
    if (!this._persist) {
      return false;
    }

    // Run decay before saving
    this.decay();

    try {
      const dir = path.dirname(this._persistPath);
      fs.mkdirSync(dir, { recursive: true });

      const data = this.export();
      const json = JSON.stringify(data, null, 2);
      const tmpPath = this._persistPath + '.tmp';

      fs.writeFileSync(tmpPath, json, 'utf8');
      fs.renameSync(tmpPath, this._persistPath);

      this.stats.saves++;
      return true;
    } catch (err) {
      console.error(`${LOG_PREFIX} Failed to save learned patterns: ${err.message}`);
      return false;
    }
  }

  /**
   * Load learned patterns from disk.
   * @returns {boolean} success
   */
  load() {
    try {
      if (!fs.existsSync(this._persistPath)) {
        return false;
      }

      const json = fs.readFileSync(this._persistPath, 'utf8');
      const data = JSON.parse(json);
      this.import(data);
      this.stats.loads++;
      console.log(`${LOG_PREFIX} Loaded learned patterns from ${this._persistPath}`);
      return true;
    } catch (err) {
      console.error(`${LOG_PREFIX} Failed to load learned patterns: ${err.message}`);
      return false;
    }
  }

  /**
   * Export patterns as JSON (regardless of persist setting).
   * @returns {object} { version, timestamp, patterns, candidates, stats }
   */
  export() {
    const patterns = [];
    for (const [_id, p] of this._promoted) {
      patterns.push({ ...p });
    }

    const candidates = [];
    for (const [_hash, c] of this._candidates) {
      candidates.push({ ...c });
    }

    return {
      version: '1.0',
      timestamp: Date.now(),
      patterns,
      candidates,
      stats: { ...this.stats }
    };
  }

  /**
   * Import patterns from JSON.
   * @param {object} data - Output of export()
   * @returns {number} imported count
   */
  import(data) {
    if (!data || typeof data !== 'object') {
      return 0;
    }

    let imported = 0;

    // Import promoted patterns
    if (Array.isArray(data.patterns)) {
      for (const p of data.patterns) {
        if (!p.patternId || !p.signature) continue;
        if (this._promoted.has(p.patternId)) continue;
        if (this._promoted.size >= this._maxPatterns) break;

        this._promoted.set(p.patternId, {
          patternId: p.patternId,
          signature: p.signature,
          category: p.category || 'learned',
          confidence: p.confidence || 0.75,
          hitCount: p.hitCount || 0,
          fpCount: p.fpCount || 0,
          promotedAt: p.promotedAt || Date.now(),
          lastSeen: p.lastSeen || Date.now(),
          active: p.active !== false,
          source: p.source || 'imported'
        });
        imported++;
      }
    }

    // Import candidates
    if (Array.isArray(data.candidates)) {
      for (const c of data.candidates) {
        if (!c.sigHash || !c.signature) continue;
        if (this._candidates.has(c.sigHash)) continue;

        this._candidates.set(c.sigHash, {
          signature: c.signature,
          sigHash: c.sigHash,
          category: c.category || 'unknown',
          hitCount: c.hitCount || 1,
          firstSeen: c.firstSeen || Date.now(),
          lastSeen: c.lastSeen || Date.now(),
          promoted: c.promoted || false
        });
      }
    }

    return imported;
  }

  /**
   * Decay old patterns that haven't been seen recently.
   * @returns {number} patterns removed
   */
  decay() {
    const now = Date.now();
    let removed = 0;

    for (const [patternId, pattern] of this._promoted) {
      if (!pattern.active) continue;
      if (now - (pattern.lastSeen || pattern.promotedAt) > this._decayMs) {
        pattern.active = false;
        removed++;
        this.stats.patternsDecayed++;
      }
    }

    // Also decay old candidates
    for (const [sigHash, candidate] of this._candidates) {
      if (now - candidate.lastSeen > this._decayMs * 2) {
        this._candidates.delete(sigHash);
      }
    }

    return removed;
  }

  /**
   * Get learning statistics.
   * @returns {object}
   */
  getStats() {
    const activePatterns = [...this._promoted.values()].filter(p => p.active).length;
    const revokedPatterns = [...this._promoted.values()].filter(p => !p.active).length;

    return {
      ...this.stats,
      candidates: this._candidates.size,
      activePatterns,
      revokedPatterns,
      totalPromoted: this._promoted.size
    };
  }

  /**
   * Get all active learned patterns.
   * @returns {Array}
   */
  getActivePatterns() {
    const patterns = [];
    for (const [_id, p] of this._promoted) {
      if (p.active) patterns.push({ ...p });
    }
    return patterns;
  }

  /**
   * Extract n-gram signatures from attack text.
   * Filters to n-grams containing injection-related keywords.
   * @param {string} text
   * @returns {string[]}
   * @private
   */
  _extractSignatures(text) {
    const lower = text.toLowerCase();
    const words = lower.split(/\s+/).filter(w => w.length > 1);
    const signatures = [];

    if (words.length < 3) {
      return signatures;
    }

    // Extract 3-to-5-word n-grams
    for (let n = 3; n <= Math.min(5, words.length); n++) {
      for (let i = 0; i <= words.length - n; i++) {
        const ngram = words.slice(i, i + n).join(' ');

        // Only keep n-grams that contain at least one injection keyword
        const hasKeyword = INJECTION_KEYWORDS.some(kw => ngram.includes(kw));
        if (hasKeyword && ngram.length >= 8 && ngram.length <= 120) {
          signatures.push(ngram);
        }
      }
    }

    // Deduplicate: if a 3-gram is a substring of a 5-gram we already have, keep both
    // (they serve different detection granularities). But remove exact duplicates.
    const unique = [...new Set(signatures)];

    // Cap to avoid excessive candidates from long texts
    return unique.slice(0, 10);
  }
}

// =========================================================================
// FeedbackCollector
// =========================================================================

/**
 * Collects user feedback (false positives / false negatives) and feeds
 * them into the persistent learning loop. Supports cooldown-gated
 * retraining triggers and full audit trail export.
 */
class FeedbackCollector {
  /**
   * @param {object} [config]
   * @param {boolean} [config.autoRetrain=true] - Auto retrain after enough feedback
   * @param {number} [config.maxPending=100] - Max pending reviews
   * @param {number} [config.cooldownMs=5000] - Min time between retrains
   * @param {PersistentLearningLoop} [config.learningLoop] - Connected learning loop
   */
  constructor(config = {}) {
    this._autoRetrain = config.autoRetrain !== false;
    this._maxPending = config.maxPending || 100;
    this._cooldownMs = config.cooldownMs || 5000;
    this._learningLoop = config.learningLoop || null;

    /** @type {Array<object>} */
    this._pending = [];
    /** @type {Array<object>} */
    this._processed = [];
    this._lastRetrainAt = 0;

    this.stats = {
      falsePositives: 0,
      falseNegatives: 0,
      processed: 0,
      retrains: 0,
      patternsAdded: 0,
      patternsRevoked: 0
    };
  }

  /**
   * Report a false positive — something was flagged that shouldn't have been.
   * @param {string} text - The text that was incorrectly flagged
   * @param {object} [meta] - { scanId, category, patternId, reason }
   * @returns {object} { id: string, status: 'recorded', pendingCount: number }
   */
  reportFalsePositive(text, meta = {}) {
    const id = generateId('fp');

    const entry = {
      id,
      type: 'false_positive',
      text: typeof text === 'string' ? text.substring(0, 1000) : '',
      meta: { ...meta },
      timestamp: Date.now(),
      status: 'pending'
    };

    this._pending.push(entry);
    this.stats.falsePositives++;

    // Trim if over max
    while (this._pending.length > this._maxPending) {
      this._pending.shift();
    }

    console.log(`${LOG_PREFIX} False positive reported: ${id}`);
    return { id, status: 'recorded', pendingCount: this._pending.length };
  }

  /**
   * Report a false negative — something should have been caught but wasn't.
   * @param {string} text - The text that should have been detected
   * @param {object} [meta] - { expectedCategory, severity, source }
   * @returns {object} { id: string, status: 'recorded', pendingCount: number }
   */
  reportFalseNegative(text, meta = {}) {
    const id = generateId('fn');

    const entry = {
      id,
      type: 'false_negative',
      text: typeof text === 'string' ? text.substring(0, 1000) : '',
      meta: { ...meta },
      timestamp: Date.now(),
      status: 'pending'
    };

    this._pending.push(entry);
    this.stats.falseNegatives++;

    while (this._pending.length > this._maxPending) {
      this._pending.shift();
    }

    console.log(`${LOG_PREFIX} False negative reported: ${id}`);
    return { id, status: 'recorded', pendingCount: this._pending.length };
  }

  /**
   * Get pending feedback that hasn't been processed.
   * @returns {Array}
   */
  getPending() {
    return this._pending.filter(e => e.status === 'pending');
  }

  /**
   * Process all pending feedback:
   * - FPs: report to learning loop for potential revocation
   * - FNs: ingest into learning loop for pattern generation
   * - If autoRetrain and cooldown elapsed: trigger retrain event
   * @returns {object} { processed: number, patternsAdded: number, patternsRevoked: number, retrainTriggered: boolean }
   */
  process() {
    const pending = this.getPending();
    let patternsAdded = 0;
    let patternsRevoked = 0;

    for (const entry of pending) {
      entry.status = 'processed';
      entry.processedAt = Date.now();

      if (entry.type === 'false_positive' && this._learningLoop) {
        // If we have a patternId, report it directly
        const patternId = entry.meta && entry.meta.patternId;
        if (patternId) {
          const result = this._learningLoop.reportFalsePositive(patternId);
          if (result.revoked) {
            patternsRevoked++;
          }
        }
      } else if (entry.type === 'false_negative' && this._learningLoop) {
        // Ingest the missed attack so the loop can learn from it
        const result = this._learningLoop.ingest(entry.text, {
          category: (entry.meta && entry.meta.expectedCategory) || 'unknown',
          source: 'feedback',
          severity: (entry.meta && entry.meta.severity) || 'medium'
        });
        patternsAdded += result.candidates;
      }

      this._processed.push(entry);
    }

    // Remove processed from pending
    this._pending = this._pending.filter(e => e.status === 'pending');

    this.stats.processed += pending.length;
    this.stats.patternsAdded += patternsAdded;
    this.stats.patternsRevoked += patternsRevoked;

    // Check if retrain should be triggered
    let retrainTriggered = false;
    const now = Date.now();
    if (this._autoRetrain &&
        pending.length > 0 &&
        (now - this._lastRetrainAt) >= this._cooldownMs) {
      this._lastRetrainAt = now;
      this.stats.retrains++;
      retrainTriggered = true;
      console.log(`${LOG_PREFIX} Retrain triggered after processing ${pending.length} feedback items`);
    }

    return {
      processed: pending.length,
      patternsAdded,
      patternsRevoked,
      retrainTriggered
    };
  }

  /**
   * Get feedback stats.
   * @returns {object}
   */
  getStats() {
    return {
      ...this.stats,
      pending: this._pending.filter(e => e.status === 'pending').length,
      totalProcessed: this._processed.length
    };
  }

  /**
   * Export all feedback data (pending + processed) for audit trail.
   * @returns {object}
   */
  export() {
    return {
      version: '1.0',
      timestamp: Date.now(),
      pending: this._pending.map(e => ({ ...e })),
      processed: this._processed.map(e => ({ ...e })),
      stats: this.getStats()
    };
  }
}

// =========================================================================
// Exports
// =========================================================================

module.exports = {
  PersistentLearningLoop,
  FeedbackCollector
};
