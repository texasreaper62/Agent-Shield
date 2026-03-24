'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const LOG_PREFIX = '[Agent Shield Pro]';

const STOP_WORDS = new Set([
  'the', 'a', 'an', 'is', 'are', 'was', 'were', 'be', 'been', 'being',
  'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'shall',
  'should', 'may', 'might', 'must', 'can', 'could', 'of', 'in', 'to',
  'for', 'with', 'on', 'at', 'from', 'by', 'up', 'about', 'into',
  'through', 'during', 'before', 'after', 'between', 'out', 'off',
  'over', 'under', 'again', 'then', 'once', 'here', 'there', 'when',
  'where', 'why', 'how', 'all', 'each', 'every', 'both', 'few', 'more',
  'most', 'other', 'some', 'no', 'nor', 'not', 'only', 'own', 'same',
  'so', 'than', 'too', 'very', 'just', 'and', 'but', 'or', 'if', 'it',
  'its', 'this', 'that', 'these', 'those', 'i', 'me', 'my', 'we', 'our',
  'you', 'your', 'he', 'him', 'his', 'she', 'her', 'they', 'them', 'their'
]);

const INJECTION_MARKERS = [
  'ignore previous', 'ignore above', 'disregard', 'forget your instructions',
  'new instructions', 'system prompt', 'you are now', 'act as',
  'pretend you', 'override', 'jailbreak', 'bypass', 'reveal your',
  'tell me your', 'output your', 'print your', 'show me your',
  'do not follow', 'stop being', 'instead of', 'from now on',
  'ignore all', 'forget everything', 'reset your', 'developer mode',
  'sudo mode', 'admin mode', 'debug mode', 'maintenance mode',
  'base64', 'rot13', 'hex encode', 'encode as', 'decode this',
  'execute code', 'run command', 'eval(', 'exec(', '<script',
  'data exfil', 'send to', 'post to', 'fetch(', 'curl '
];

/** @returns {string} 12-character hex ID */
function generateId() {
  return crypto.randomBytes(6).toString('hex');
}

/** @param {string} str @returns {string} Regex-escaped string */
function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** @param {string} text @returns {string[]} Significant words (no stop words) */
function significantWords(text) {
  return text.toLowerCase().replace(/[^a-z0-9\s]/g, ' ').split(/\s+/)
    .filter(w => w.length > 2 && !STOP_WORDS.has(w));
}

/** @param {string[]} words @returns {string[]} 3-gram strings */
function extractNGrams(words) {
  const ngrams = [];
  for (let i = 0; i <= words.length - 3; i++) {
    ngrams.push(words.slice(i, i + 3).join(' '));
  }
  return ngrams;
}

/** @param {string} dirPath - Ensure directory exists recursively */
function ensureDir(dirPath) {
  try { fs.mkdirSync(dirPath, { recursive: true }); }
  catch (err) { if (err.code !== 'EEXIST') console.error(`${LOG_PREFIX} mkdir failed:`, err.message); }
}

/**
 * Persistent pattern learner that extracts signatures from blocked attacks,
 * promotes candidates to active patterns after sufficient hits, and supports
 * false positive/negative feedback to refine detection.
 * All state persists to disk as JSON and survives process restarts.
 */
class PersistentLearner {
  /**
   * @param {Object} [options={}]
   * @param {string} [options.storagePath='.agentshield/learned-patterns.json']
   * @param {number} [options.promotionThreshold=3] - Hits before promotion
   * @param {number} [options.maxPatterns=500]
   * @param {boolean} [options.autoSave=true]
   */
  constructor(options = {}) {
    this.storagePath = options.storagePath || '.agentshield/learned-patterns.json';
    this.promotionThreshold = options.promotionThreshold || 3;
    this.maxPatterns = options.maxPatterns || 500;
    this.autoSave = options.autoSave !== undefined ? options.autoSave : true;
    /** @type {Map<string, Object>} */
    this.patterns = new Map();
    this.stats = { totalIngested: 0, fpReported: 0, fnReported: 0 };
    this.load();
  }

  /**
   * Extract signatures from blocked attack text and store as candidate patterns.
   * Existing candidates get their hit counts bumped and may be promoted.
   * @param {string} text - The blocked attack text
   * @param {string} category - Threat category (e.g. 'prompt_injection')
   * @param {Object} [metadata={}] - Optional metadata
   * @returns {Object[]} Created or updated pattern objects
   */
  ingestAttack(text, category, metadata = {}) {
    if (!text || typeof text !== 'string') {
      console.warn(`${LOG_PREFIX} ingestAttack: text must be a non-empty string`);
      return [];
    }
    this.stats.totalIngested++;
    const now = new Date().toISOString();
    const ngrams = extractNGrams(significantWords(text));
    const injectionPhrases = this._extractInjectionPhrases(text);
    const affected = [];

    for (const ngram of ngrams) {
      const existing = this._findByKeyword(ngram, category);
      if (existing) {
        existing.hitCount++;
        existing.lastSeenAt = now;
        this._maybePromote(existing);
        affected.push(existing);
      } else if (this.patterns.size < this.maxPatterns) {
        const p = this._createPattern({ keyword: ngram, category, metadata, now });
        this.patterns.set(p.id, p);
        affected.push(p);
      }
    }

    for (const phrase of injectionPhrases) {
      const existing = this._findByRegex(phrase, category);
      if (existing) {
        existing.hitCount++;
        existing.lastSeenAt = now;
        this._maybePromote(existing);
        affected.push(existing);
      } else if (this.patterns.size < this.maxPatterns) {
        const p = this._createPattern({ regex: escapeRegex(phrase), category, metadata, now });
        this.patterns.set(p.id, p);
        affected.push(p);
      }
    }

    if (affected.length > 0) {
      console.log(`${LOG_PREFIX} Ingested attack — ${affected.length} pattern(s) created/updated [${category}]`);
    }
    if (this.autoSave) this.save();
    return affected;
  }

  /**
   * Report a false positive. Reduces confidence; revokes if FPs are excessive.
   * @param {string} patternId - Pattern ID to report against
   * @param {Object} [details={}] - Details about the false positive
   * @returns {Object|null} Updated pattern or null if not found
   */
  reportFP(patternId, details = {}) {
    const pattern = this.patterns.get(patternId);
    if (!pattern) {
      console.warn(`${LOG_PREFIX} reportFP: pattern ${patternId} not found`);
      return null;
    }
    this.stats.fpReported++;
    pattern.fpCount++;
    pattern.confidence = Math.max(0, pattern.confidence - 0.15);

    if (pattern.fpCount > Math.ceil(pattern.hitCount / 2) || pattern.confidence < 0.2) {
      pattern.status = 'revoked';
      console.log(`${LOG_PREFIX} Pattern ${patternId} revoked (fp=${pattern.fpCount}, conf=${pattern.confidence.toFixed(2)})`);
    } else if (pattern.status === 'active' && pattern.confidence < 0.5) {
      pattern.status = 'candidate';
      console.log(`${LOG_PREFIX} Pattern ${patternId} demoted to candidate (conf=${pattern.confidence.toFixed(2)})`);
    }

    if (this.autoSave) this.save();
    return pattern;
  }

  /**
   * Report a false negative — an attack that was missed. Creates new candidates.
   * @param {string} text - Attack text that was not detected
   * @param {Object} [details={}] - Details (e.g. expected category)
   * @returns {Object[]} Newly created candidate patterns
   */
  reportFN(text, details = {}) {
    if (!text || typeof text !== 'string') {
      console.warn(`${LOG_PREFIX} reportFN: text must be a non-empty string`);
      return [];
    }
    this.stats.fnReported++;
    const category = details.category || 'unknown';
    const now = new Date().toISOString();
    const created = [];

    for (const phrase of this._extractInjectionPhrases(text)) {
      if (this.patterns.size >= this.maxPatterns) break;
      const p = this._createPattern({ regex: escapeRegex(phrase), category, metadata: { source: 'fn_report', ...details }, now });
      p.confidence = 0.6;
      p.hitCount = 1;
      this.patterns.set(p.id, p);
      created.push(p);
    }

    const ngrams = extractNGrams(significantWords(text));
    for (const ngram of ngrams.slice(0, 5)) {
      if (this.patterns.size >= this.maxPatterns) break;
      if (!this._findByKeyword(ngram, category)) {
        const p = this._createPattern({ keyword: ngram, category, metadata: { source: 'fn_report', ...details }, now });
        p.confidence = 0.5;
        p.hitCount = 1;
        this.patterns.set(p.id, p);
        created.push(p);
      }
    }

    if (created.length > 0) {
      console.log(`${LOG_PREFIX} FN report — ${created.length} new candidate(s) [${category}]`);
    }
    if (this.autoSave) this.save();
    return created;
  }

  /**
   * Get all promoted (active) patterns.
   * @returns {Object[]} Active pattern objects
   */
  getActivePatterns() {
    return Array.from(this.patterns.values()).filter(p => p.status === 'active');
  }

  /**
   * Get all candidate patterns (not yet promoted).
   * @returns {Object[]} Candidate pattern objects
   */
  getCandidates() {
    return Array.from(this.patterns.values()).filter(p => p.status === 'candidate');
  }

  /**
   * Test input against all active learned patterns.
   * @param {string} text - Input text to match
   * @returns {Object[]} Matching patterns with match details
   */
  matchInput(text) {
    if (!text || typeof text !== 'string') return [];
    const matches = [];
    const lower = text.toLowerCase();

    for (const pattern of this.patterns.values()) {
      if (pattern.status !== 'active') continue;
      let matched = false;
      if (pattern.keyword && lower.includes(pattern.keyword)) matched = true;
      if (pattern.regex) {
        try { if (new RegExp(pattern.regex, 'i').test(text)) matched = true; }
        catch (_) { /* invalid regex — skip */ }
      }
      if (matched) {
        matches.push({
          patternId: pattern.id, category: pattern.category,
          confidence: pattern.confidence,
          keyword: pattern.keyword || null, regex: pattern.regex || null
        });
      }
    }
    return matches;
  }

  /** Persist current state to disk. */
  save() {
    try {
      ensureDir(path.dirname(path.resolve(this.storagePath)));
      const data = {
        version: 1, savedAt: new Date().toISOString(),
        stats: this.stats, patterns: Array.from(this.patterns.entries())
      };
      fs.writeFileSync(path.resolve(this.storagePath), JSON.stringify(data, null, 2), 'utf8');
    } catch (err) {
      console.error(`${LOG_PREFIX} Failed to save patterns:`, err.message);
    }
  }

  /** Load state from disk. Handles missing files gracefully. */
  load() {
    try {
      const data = JSON.parse(fs.readFileSync(path.resolve(this.storagePath), 'utf8'));
      if (data.patterns && Array.isArray(data.patterns)) this.patterns = new Map(data.patterns);
      if (data.stats) Object.assign(this.stats, data.stats);
      console.log(`${LOG_PREFIX} Loaded ${this.patterns.size} patterns from ${this.storagePath}`);
    } catch (err) {
      if (err.code === 'ENOENT') console.log(`${LOG_PREFIX} No existing patterns file, starting fresh`);
      else console.error(`${LOG_PREFIX} Failed to load patterns:`, err.message);
    }
  }

  /**
   * Export full learner state as a JSON-serializable object.
   * @returns {Object} Serializable state
   */
  export() {
    return {
      version: 1, exportedAt: new Date().toISOString(),
      stats: { ...this.stats }, patterns: Array.from(this.patterns.entries())
    };
  }

  /**
   * Import state from an exported object, replacing current state.
   * @param {Object} data - Previously exported state
   */
  import(data) {
    if (!data || !data.patterns) {
      console.warn(`${LOG_PREFIX} import: invalid data structure`);
      return;
    }
    this.patterns = new Map(data.patterns);
    if (data.stats) Object.assign(this.stats, data.stats);
    console.log(`${LOG_PREFIX} Imported ${this.patterns.size} patterns`);
    if (this.autoSave) this.save();
  }

  /**
   * Get aggregate statistics about the learner state.
   * @returns {{ candidates: number, active: number, revoked: number, totalIngested: number, fpReported: number, fnReported: number }}
   */
  getStats() {
    const all = Array.from(this.patterns.values());
    return {
      candidates: all.filter(p => p.status === 'candidate').length,
      active: all.filter(p => p.status === 'active').length,
      revoked: all.filter(p => p.status === 'revoked').length,
      totalIngested: this.stats.totalIngested,
      fpReported: this.stats.fpReported,
      fnReported: this.stats.fnReported
    };
  }

  /** @private Extract injection-like phrases by matching known markers. */
  _extractInjectionPhrases(text) {
    const lower = text.toLowerCase();
    const found = [];
    for (const marker of INJECTION_MARKERS) {
      const idx = lower.indexOf(marker);
      if (idx !== -1) {
        const snippet = text.slice(idx, Math.min(text.length, idx + marker.length + 30)).trim();
        if (snippet.length >= 6) found.push(snippet);
      }
    }
    return found;
  }

  /** @private Find existing keyword pattern by value and category. */
  _findByKeyword(keyword, category) {
    for (const p of this.patterns.values()) {
      if (p.keyword === keyword && p.category === category && p.status !== 'revoked') return p;
    }
    return null;
  }

  /** @private Find existing regex pattern by escaped phrase and category. */
  _findByRegex(phrase, category) {
    const escaped = escapeRegex(phrase);
    for (const p of this.patterns.values()) {
      if (p.regex === escaped && p.category === category && p.status !== 'revoked') return p;
    }
    return null;
  }

  /** @private Create a new pattern object with default fields. */
  _createPattern(opts) {
    return {
      id: generateId(), keyword: opts.keyword || null, regex: opts.regex || null,
      category: opts.category, confidence: 0.4, hitCount: 0, fpCount: 0,
      status: 'candidate', metadata: opts.metadata || {},
      createdAt: opts.now || new Date().toISOString(),
      lastSeenAt: opts.now || new Date().toISOString()
    };
  }

  /** @private Promote candidate to active if hit count meets threshold. */
  _maybePromote(pattern) {
    if (pattern.status === 'candidate' && pattern.hitCount >= this.promotionThreshold) {
      pattern.status = 'active';
      pattern.confidence = Math.min(1, pattern.confidence + 0.3);
      console.log(`${LOG_PREFIX} Pattern ${pattern.id} promoted to active (hits=${pattern.hitCount}, conf=${pattern.confidence.toFixed(2)})`);
    }
  }
}

/**
 * Collects and manages false positive / false negative feedback entries.
 * Persists to disk for later processing by PersistentLearner or external tooling.
 */
class FeedbackCollector {
  /**
   * @param {Object} [options={}]
   * @param {string} [options.storagePath='.agentshield/feedback.json']
   */
  constructor(options = {}) {
    this.storagePath = options.storagePath || '.agentshield/feedback.json';
    /** @type {Map<string, Object>} */
    this.entries = new Map();
    this.load();
  }

  /**
   * Record a feedback entry (false positive or false negative).
   * @param {string} type - 'fp' or 'fn'
   * @param {string} scanId - ID of the original scan
   * @param {string} text - The scanned text
   * @param {Object} [details={}] - Additional details
   * @returns {Object} Created feedback entry
   */
  recordFeedback(type, scanId, text, details = {}) {
    if (type !== 'fp' && type !== 'fn') {
      console.warn(`${LOG_PREFIX} recordFeedback: type must be 'fp' or 'fn', got '${type}'`);
      type = 'fp';
    }
    const entry = {
      id: generateId(), type, scanId: scanId || null,
      text: text || '', details, status: 'pending',
      createdAt: new Date().toISOString()
    };
    this.entries.set(entry.id, entry);
    console.log(`${LOG_PREFIX} Feedback recorded: ${type} for scan ${scanId || 'unknown'} [${entry.id}]`);
    this.save();
    return entry;
  }

  /**
   * Get all unprocessed feedback entries.
   * @returns {Object[]} Pending feedback objects
   */
  getPending() {
    return Array.from(this.entries.values()).filter(e => e.status === 'pending');
  }

  /**
   * Mark a feedback entry as processed.
   * @param {string} feedbackId - Feedback ID
   * @returns {boolean} True if found and marked
   */
  markProcessed(feedbackId) {
    const entry = this.entries.get(feedbackId);
    if (!entry) {
      console.warn(`${LOG_PREFIX} markProcessed: feedback ${feedbackId} not found`);
      return false;
    }
    entry.status = 'processed';
    entry.processedAt = new Date().toISOString();
    this.save();
    return true;
  }

  /**
   * Get aggregate feedback statistics.
   * @returns {{ total: number, fps: number, fns: number, pending: number, processed: number }}
   */
  getStats() {
    const all = Array.from(this.entries.values());
    return {
      total: all.length,
      fps: all.filter(e => e.type === 'fp').length,
      fns: all.filter(e => e.type === 'fn').length,
      pending: all.filter(e => e.status === 'pending').length,
      processed: all.filter(e => e.status === 'processed').length
    };
  }

  /** Persist feedback entries to disk. */
  save() {
    try {
      ensureDir(path.dirname(path.resolve(this.storagePath)));
      const data = {
        version: 1, savedAt: new Date().toISOString(),
        entries: Array.from(this.entries.entries())
      };
      fs.writeFileSync(path.resolve(this.storagePath), JSON.stringify(data, null, 2), 'utf8');
    } catch (err) {
      console.error(`${LOG_PREFIX} Failed to save feedback:`, err.message);
    }
  }

  /** Load feedback from disk. Handles missing files gracefully. */
  load() {
    try {
      const data = JSON.parse(fs.readFileSync(path.resolve(this.storagePath), 'utf8'));
      if (data.entries && Array.isArray(data.entries)) this.entries = new Map(data.entries);
      console.log(`${LOG_PREFIX} Loaded ${this.entries.size} feedback entries from ${this.storagePath}`);
    } catch (err) {
      if (err.code === 'ENOENT') console.log(`${LOG_PREFIX} No existing feedback file, starting fresh`);
      else console.error(`${LOG_PREFIX} Failed to load feedback:`, err.message);
    }
  }
}

module.exports = { PersistentLearner, FeedbackCollector };
