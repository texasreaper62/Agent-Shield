'use strict';

/**
 * Agent Shield — Persistent Learning + Feedback API (v8.0)
 *
 * Makes detection smarter over time by persisting learned patterns to disk
 * and accepting structured user feedback. Enhances the LearningLoop from
 * adaptive-defense.js with disk persistence, pattern decay, and a dedicated
 * FeedbackCollector that bridges operator input into the learning pipeline.
 *
 * - PersistentLearningLoop: disk-backed pattern learning with decay & promotion
 * - FeedbackCollector: structured FP/FN feedback → learning loop integration
 *
 * Zero external dependencies. All processing runs locally.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const LOG_PREFIX = '[Agent Shield]';

// =========================================================================
// Helpers
// =========================================================================

/**
 * Generate a unique ID. Uses crypto.randomUUID() when available,
 * falls back to timestamp + random hex.
 * @returns {string}
 */
function generateId() {
  if (typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  const ts = Date.now().toString(36);
  const rand = Math.random().toString(16).slice(2, 10);
  return `${ts}-${rand}`;
}

/**
 * SHA-256 hash truncated to 16 hex chars.
 * @param {string} text
 * @returns {string}
 */
function hashText(text) {
  return crypto.createHash('sha256').update(text).digest('hex').substring(0, 16);
}

/** Injection-related keywords used to filter n-grams. */
const INJECTION_KEYWORDS = [
  'ignore', 'forget', 'disregard', 'override', 'bypass', 'disable',
  'system', 'prompt', 'reveal', 'output', 'instructions', 'previous',
  'jailbreak', 'sudo', 'admin', 'execute', 'inject', 'extract',
  'exfiltrate', 'delete', 'drop', 'curl', 'fetch', 'eval',
  'pretend', 'roleplay', 'act', 'imagine', 'hypothetically'
];

/**
 * Extract n-grams (3-5 words) from text, filtered to those containing
 * injection-related keywords.
 * @param {string} text
 * @returns {string[]}
 */
function extractNgrams(text) {
  const lower = text.toLowerCase().replace(/[^\w\s]/g, ' ');
  const words = lower.split(/\s+/).filter(w => w.length > 1);
  const ngrams = [];

  for (let n = 3; n <= 5; n++) {
    for (let i = 0; i <= words.length - n; i++) {
      const gram = words.slice(i, i + n).join(' ');
      const hasKeyword = INJECTION_KEYWORDS.some(kw => gram.includes(kw));
      if (hasKeyword) {
        ngrams.push(gram);
      }
    }
  }

  return ngrams;
}

// =========================================================================
// 1. PersistentLearningLoop
// =========================================================================

/**
 * Disk-backed learning loop that extracts signature patterns from observed
 * attacks, promotes them after repeated sightings, and persists everything
 * to JSON on disk. Patterns decay over time if not re-observed.
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

    this._stats = {
      attacksIngested: 0,
      candidatesCreated: 0,
      patternsPromoted: 0,
      patternsRevoked: 0,
      falsePositivesReported: 0,
      saves: 0,
      loads: 0
    };

    // Auto-load from disk if persistence is enabled
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

    this._stats.attacksIngested++;
    const ngrams = extractNgrams(text);
    const signatures = [];
    let promotedAny = false;

    for (const gram of ngrams) {
      const sigHash = hashText(gram);
      const existing = this._candidates.get(sigHash);

      if (existing) {
        existing.hitCount++;
        existing.lastSeen = Date.now();
        if (meta.category && !existing.categories.includes(meta.category)) {
          existing.categories.push(meta.category);
        }

        // Promote if threshold reached and not already promoted
        if (existing.hitCount >= this._promotionThreshold &&
            !existing.promoted &&
            this._promoted.size < this._maxPatterns) {
          existing.promoted = true;
          const patternId = `PL_${sigHash.substring(0, 12)}`;
          const confidence = Math.min(1.0, 0.5 + (existing.hitCount * 0.05));
          this._promoted.set(patternId, {
            patternId,
            signature: gram,
            sigHash,
            categories: [...existing.categories],
            confidence,
            hitCount: existing.hitCount,
            fpCount: 0,
            source: meta.source || 'persistent_learning',
            severity: meta.severity || 'medium',
            promotedAt: Date.now(),
            lastSeen: Date.now(),
            active: true
          });
          this._stats.patternsPromoted++;
          promotedAny = true;
          console.log(`${LOG_PREFIX} Pattern promoted: "${gram}" (${patternId})`);
        }
      } else {
        // New candidate
        this._candidates.set(sigHash, {
          signature: gram,
          sigHash,
          hitCount: 1,
          categories: meta.category ? [meta.category] : [],
          firstSeen: Date.now(),
          lastSeen: Date.now(),
          promoted: false
        });
        this._stats.candidatesCreated++;
      }

      signatures.push(gram);
    }

    // Auto-save after promotion
    if (promotedAny && this._persist) {
      this.save();
    }

    return { candidates: ngrams.length, signatures };
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

    for (const [_patternId, pattern] of this._promoted) {
      if (!pattern.active) continue;
      if (lower.includes(pattern.signature.toLowerCase())) {
        pattern.lastSeen = Date.now();
        pattern.hitCount++;
        matches.push({
          patternId: pattern.patternId,
          pattern: pattern.signature,
          source: 'learned',
          confidence: pattern.confidence,
          categories: pattern.categories,
          severity: pattern.severity
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

    pattern.fpCount++;
    this._stats.falsePositivesReported++;
    let revoked = false;

    if (pattern.fpCount >= this._maxFalsePositives) {
      pattern.active = false;
      revoked = true;
      this._stats.patternsRevoked++;
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
   * Uses atomic write: write to .tmp then rename.
   * @returns {boolean} success
   */
  save() {
    if (!this._persist) {
      return false;
    }

    try {
      // Run decay before saving
      this.decay();

      const dir = path.dirname(this._persistPath);
      fs.mkdirSync(dir, { recursive: true });

      const data = this.export();
      const json = JSON.stringify(data, null, 2);
      const tmpPath = this._persistPath + '.tmp';

      fs.writeFileSync(tmpPath, json, 'utf8');
      fs.renameSync(tmpPath, this._persistPath);

      this._stats.saves++;
      console.log(`${LOG_PREFIX} Saved ${data.patterns.length} patterns to ${this._persistPath}`);
      return true;
    } catch (err) {
      console.error(`${LOG_PREFIX} Failed to save patterns: ${err.message}`);
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

      const raw = fs.readFileSync(this._persistPath, 'utf8');
      const data = JSON.parse(raw);
      this.import(data);
      this._stats.loads++;
      console.log(`${LOG_PREFIX} Loaded patterns from ${this._persistPath}`);
      return true;
    } catch (err) {
      console.error(`${LOG_PREFIX} Failed to load patterns: ${err.message}`);
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
      version: '8.0',
      timestamp: new Date().toISOString(),
      patterns,
      candidates,
      stats: { ...this._stats }
    };
  }

  /**
   * Import patterns from JSON.
   * @param {object} data
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
          sigHash: p.sigHash || hashText(p.signature),
          categories: p.categories || [],
          confidence: p.confidence || 0.75,
          hitCount: p.hitCount || 0,
          fpCount: p.fpCount || 0,
          source: p.source || 'imported',
          severity: p.severity || 'medium',
          promotedAt: p.promotedAt || Date.now(),
          lastSeen: p.lastSeen || Date.now(),
          active: p.active !== false
        });
        imported++;
      }
    }

    // Import candidates
    if (Array.isArray(data.candidates)) {
      for (const c of data.candidates) {
        if (!c.signature || !c.sigHash) continue;
        if (this._candidates.has(c.sigHash)) continue;

        this._candidates.set(c.sigHash, {
          signature: c.signature,
          sigHash: c.sigHash,
          hitCount: c.hitCount || 1,
          categories: c.categories || [],
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
   * Removes patterns where Date.now() - lastSeen > decayMs.
   * @returns {number} patterns removed
   */
  decay() {
    const now = Date.now();
    let removed = 0;

    // Decay promoted patterns
    for (const [patternId, pattern] of this._promoted) {
      if (now - pattern.lastSeen > this._decayMs) {
        this._promoted.delete(patternId);
        removed++;
      }
    }

    // Decay candidates
    for (const [sigHash, candidate] of this._candidates) {
      if (now - candidate.lastSeen > this._decayMs) {
        this._candidates.delete(sigHash);
      }
    }

    if (removed > 0) {
      console.log(`${LOG_PREFIX} Decayed ${removed} stale patterns`);
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
      ...this._stats,
      activePatterns,
      revokedPatterns,
      candidates: this._candidates.size,
      totalPromoted: this._promoted.size
    };
  }

  /**
   * Get all active patterns.
   * @returns {Array<object>}
   */
  getActivePatterns() {
    const patterns = [];
    for (const [_id, p] of this._promoted) {
      if (p.active) patterns.push({ ...p });
    }
    return patterns;
  }
}

// =========================================================================
// 2. FeedbackCollector
// =========================================================================

/**
 * Collects user feedback (false positives / false negatives) and feeds them
 * into the PersistentLearningLoop. Tracks all feedback with IDs for audit.
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

    this._stats = {
      falsePositives: 0,
      falseNegatives: 0,
      totalProcessed: 0,
      patternsAdded: 0,
      patternsRevoked: 0,
      retrainCount: 0
    };
  }

  /**
   * Report a false positive — something was flagged that shouldn't have been.
   * @param {string} text - The text that was incorrectly flagged
   * @param {object} [meta] - { scanId, category, patternId, reason }
   * @returns {object} { id: string, status: 'recorded', pendingCount: number }
   */
  reportFalsePositive(text, meta = {}) {
    const id = `fp_${generateId()}`;

    const entry = {
      id,
      type: 'false_positive',
      text: typeof text === 'string' ? text.substring(0, 2000) : '',
      meta: { ...meta },
      timestamp: new Date().toISOString(),
      status: 'pending'
    };

    this._pending.push(entry);
    this._stats.falsePositives++;

    // Enforce max pending
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
    const id = `fn_${generateId()}`;

    const entry = {
      id,
      type: 'false_negative',
      text: typeof text === 'string' ? text.substring(0, 2000) : '',
      meta: { ...meta },
      timestamp: new Date().toISOString(),
      status: 'pending'
    };

    this._pending.push(entry);
    this._stats.falseNegatives++;

    // Enforce max pending
    while (this._pending.length > this._maxPending) {
      this._pending.shift();
    }

    console.log(`${LOG_PREFIX} False negative reported: ${id}`);

    return { id, status: 'recorded', pendingCount: this._pending.length };
  }

  /**
   * Get pending feedback that hasn't been processed.
   * @returns {Array<object>}
   */
  getPending() {
    return this._pending.filter(e => e.status === 'pending');
  }

  /**
   * Process all pending feedback:
   * - FPs: report to learning loop for potential revocation
   * - FNs: ingest into learning loop for pattern generation
   * - If autoRetrain: trigger retrain event
   * @returns {object} { processed: number, patternsAdded: number, patternsRevoked: number, retrainTriggered: boolean }
   */
  process() {
    const pending = this.getPending();
    let patternsAdded = 0;
    let patternsRevoked = 0;

    for (const entry of pending) {
      entry.status = 'processed';
      entry.processedAt = new Date().toISOString();

      if (entry.type === 'false_positive') {
        // Report to learning loop for potential revocation
        if (this._learningLoop && entry.meta.patternId) {
          const result = this._learningLoop.reportFalsePositive(entry.meta.patternId);
          if (result.revoked) {
            patternsRevoked++;
          }
          entry.result = result;
        }
      } else if (entry.type === 'false_negative') {
        // Ingest into learning loop for pattern generation
        if (this._learningLoop) {
          const result = this._learningLoop.ingest(entry.text, {
            category: entry.meta.expectedCategory || 'unknown',
            source: 'feedback',
            severity: entry.meta.severity || 'medium'
          });
          patternsAdded += result.candidates;
          entry.result = result;
        }
      }

      this._processed.push(entry);
      this._stats.totalProcessed++;
    }

    this._stats.patternsAdded += patternsAdded;
    this._stats.patternsRevoked += patternsRevoked;

    // Check if retrain should be triggered
    let retrainTriggered = false;
    const now = Date.now();
    if (this._autoRetrain && pending.length > 0 && (now - this._lastRetrainAt) >= this._cooldownMs) {
      this._lastRetrainAt = now;
      this._stats.retrainCount++;
      retrainTriggered = true;
      console.log(`${LOG_PREFIX} Retrain triggered after processing ${pending.length} feedback items`);
    }

    // Remove processed entries from pending
    this._pending = this._pending.filter(e => e.status === 'pending');

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
      ...this._stats,
      pendingCount: this._pending.filter(e => e.status === 'pending').length,
      processedCount: this._processed.length
    };
  }

  /**
   * Export all feedback data.
   * @returns {object}
   */
  export() {
    return {
      version: '8.0',
      timestamp: new Date().toISOString(),
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
