'use strict';

/**
 * Agent Shield — Adaptive Detection, Semantic Hooks & Community Patterns
 *
 * - AdaptiveDetector: learns from false positives/negatives over time
 * - SemanticAnalysisHook: pluggable LLM-based post-processing classifier
 * - CommunityPatterns: load and merge detection patterns from local JSON
 *
 * All data stored locally — nothing is ever transmitted externally.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const LOG = '[Agent Shield]';

/** Extract character trigrams from a string. @param {string} text @returns {Set<string>} */
function trigrams(text) {
  const t = text.toLowerCase().replace(/\s+/g, ' ').trim();
  const set = new Set();
  for (let i = 0; i <= t.length - 3; i++) set.add(t.substring(i, i + 3));
  return set;
}

/**
 * Compute trigram similarity between two strings (0-1).
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
function trigramSimilarity(a, b) {
  const ta = trigrams(a);
  const tb = trigrams(b);
  if (ta.size === 0 || tb.size === 0) return 0;
  let overlap = 0;
  for (const t of ta) { if (tb.has(t)) overlap++; }
  return overlap / Math.max(ta.size, tb.size);
}

/** SHA-256 hash of a string (hex). @param {string} text @returns {string} */
function hash(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

/**
 * Learns from false positives and false negatives to improve detection
 * accuracy over time. Uses local file storage — no network calls.
 */
class AdaptiveDetector {
  /**
   * @param {object} [options]
   * @param {string} [options.storePath] - Path to the JSON store file.
   * @param {number} [options.similarityThreshold] - Trigram similarity threshold (0-1). Default 0.65.
   */
  constructor(options = {}) {
    this.storePath = options.storePath || path.join('.agent-shield', 'adaptive.json');
    this.similarityThreshold = options.similarityThreshold || 0.65;
    this.falsePositives = [];
    this.falseNegatives = [];
    this.stats = { suppressions: 0, boosts: 0, adjustments: 0 };
    this.load();
  }

  /**
   * Record a false positive so similar inputs can be suppressed in the future.
   * @param {string} text - The input that was incorrectly flagged.
   * @param {string} category - The threat category that was flagged.
   */
  recordFalsePositive(text, category) {
    const h = hash(text);
    if (this.falsePositives.some(fp => fp.hash === h && fp.category === category)) return;
    this.falsePositives.push({ hash: h, text, category, ts: Date.now() });
    console.log(`${LOG} Recorded false positive for category "${category}"`);
    this.save();
  }

  /**
   * Record a false negative (missed attack) to boost future detection.
   * @param {string} text - The input that should have been flagged.
   * @param {string} category - The threat category that was missed.
   */
  recordFalseNegative(text, category) {
    const h = hash(text);
    if (this.falseNegatives.some(fn => fn.hash === h && fn.category === category)) return;
    this.falseNegatives.push({ hash: h, text, category, ts: Date.now() });
    console.log(`${LOG} Recorded false negative for category "${category}"`);
    this.save();
  }

  /**
   * Check if text should be suppressed based on learned FP data.
   * @param {string} text
   * @param {string} category
   * @returns {boolean}
   */
  shouldSuppress(text, category) {
    return this.falsePositives
      .filter(fp => fp.category === category)
      .some(fp => trigramSimilarity(text, fp.text) >= this.similarityThreshold);
  }

  /**
   * Get a confidence boost (0-20) if text resembles known false negatives.
   * @param {string} text
   * @param {string} category
   * @returns {number}
   */
  getBoost(text, category) {
    let maxSim = 0;
    for (const fn of this.falseNegatives) {
      if (fn.category !== category) continue;
      const sim = trigramSimilarity(text, fn.text);
      if (sim > maxSim) maxSim = sim;
    }
    if (maxSim < this.similarityThreshold) return 0;
    return Math.round(maxSim * 20);
  }

  /**
   * Adjust a scan result based on learned data. Suppresses known FPs and
   * boosts confidence for patterns similar to known FNs.
   * @param {object} scanResult - A scan result object with threats array.
   * @returns {object} Adjusted scan result.
   */
  adjustResult(scanResult) {
    if (!scanResult || !Array.isArray(scanResult.threats)) return scanResult;
    const inputText = scanResult.input || '';
    const adjusted = { ...scanResult, threats: [] };
    for (const threat of scanResult.threats) {
      const cat = threat.category || 'unknown';
      if (this.shouldSuppress(inputText, cat)) {
        this.stats.suppressions++;
        this.stats.adjustments++;
        console.log(`${LOG} Suppressing known false positive: ${cat}`);
        continue;
      }
      const boost = this.getBoost(inputText, cat);
      if (boost > 0) {
        this.stats.boosts++;
        this.stats.adjustments++;
        adjusted.threats.push({ ...threat, confidence: Math.min(100, (threat.confidence || 50) + boost) });
      } else {
        adjusted.threats.push(threat);
      }
    }
    adjusted.threatCount = adjusted.threats.length;
    adjusted.blocked = adjusted.threats.some(t => t.severity === 'critical' || t.severity === 'high');
    return adjusted;
  }

  /** Return learning statistics. @returns {object} */
  getStats() {
    return {
      falsePositives: this.falsePositives.length,
      falseNegatives: this.falseNegatives.length,
      suppressions: this.stats.suppressions,
      boosts: this.stats.boosts,
      adjustments: this.stats.adjustments
    };
  }

  /** Persist learned data to disk. */
  save() {
    try {
      const dir = path.dirname(this.storePath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      const data = JSON.stringify({
        version: 1,
        falsePositives: this.falsePositives,
        falseNegatives: this.falseNegatives
      }, null, 2);
      fs.writeFileSync(this.storePath, data, 'utf8');
    } catch (err) {
      console.log(`${LOG} Failed to save adaptive data: ${err.message}`);
    }
  }

  /** Load learned data from disk. */
  load() {
    try {
      if (!fs.existsSync(this.storePath)) return;
      const raw = fs.readFileSync(this.storePath, 'utf8');
      const data = JSON.parse(raw);
      this.falsePositives = Array.isArray(data.falsePositives) ? data.falsePositives : [];
      this.falseNegatives = Array.isArray(data.falseNegatives) ? data.falseNegatives : [];
      console.log(`${LOG} Loaded adaptive data: ${this.falsePositives.length} FPs, ${this.falseNegatives.length} FNs`);
    } catch (err) {
      console.log(`${LOG} Failed to load adaptive data: ${err.message}`);
    }
  }
}

/**
 * Pluggable post-processing hook for user-supplied LLM classifiers.
 * Falls back gracefully on errors or timeouts.
 */
class SemanticAnalysisHook {
  /**
   * @param {object} options
   * @param {function} options.classifier - Async fn (text, threats) => { override: boolean, reason: string }
   * @param {number} [options.timeoutMs=5000] - Classifier timeout in ms.
   */
  constructor(options = {}) {
    if (typeof options.classifier !== 'function') {
      throw new Error('SemanticAnalysisHook requires a classifier function');
    }
    this.classifier = options.classifier;
    this.timeoutMs = options.timeoutMs || 5000;
    this.overrideCount = 0;
    this.errorCount = 0;
    this.totalLatency = 0;
    this.callCount = 0;
  }

  /**
   * Run the user's classifier and return an adjusted scan result.
   * @param {string} text - The input text that was scanned.
   * @param {object} scanResult - The original scan result.
   * @returns {Promise<object>} Adjusted scan result.
   */
  async analyze(text, scanResult) {
    const start = Date.now();
    try {
      const threats = scanResult && Array.isArray(scanResult.threats) ? scanResult.threats : [];
      const result = await Promise.race([
        this.classifier(text, threats),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('Classifier timed out')), this.timeoutMs)
        )
      ]);
      this.totalLatency += Date.now() - start;
      this.callCount++;
      if (result && result.override === true) {
        this.overrideCount++;
        console.log(`${LOG} Semantic hook override: ${result.reason || 'no reason given'}`);
        return { ...scanResult, threats: [], threatCount: 0, semanticOverride: true, semanticReason: result.reason || '' };
      }
      return scanResult;
    } catch (err) {
      this.totalLatency += Date.now() - start;
      this.callCount++;
      this.errorCount++;
      console.log(`${LOG} Semantic hook error: ${err.message}`);
      return scanResult;
    }
  }

  /** Return hook statistics. @returns {object} */
  getStats() {
    return {
      overrideCount: this.overrideCount,
      errorCount: this.errorCount,
      callCount: this.callCount,
      avgLatencyMs: this.callCount > 0 ? Math.round(this.totalLatency / this.callCount) : 0
    };
  }
}

/**
 * Loads and merges detection patterns from a local JSON file. The user is
 * responsible for downloading/maintaining the file — no network calls.
 */
class CommunityPatterns {
  /**
   * @param {object} [options]
   * @param {string} [options.path] - Path to the community patterns JSON file.
   */
  constructor(options = {}) {
    this.filePath = options.path || 'community-patterns.json';
    this.patterns = [];
    this.version = null;
  }

  /**
   * Read and parse the patterns file.
   * @returns {boolean} True if loaded successfully.
   */
  load() {
    try {
      const raw = fs.readFileSync(this.filePath, 'utf8');
      const data = JSON.parse(raw);
      this.version = data.version || null;
      this.patterns = Array.isArray(data.patterns) ? data.patterns.map(p => ({
        regex: p.regex || '',
        severity: p.severity || 'medium',
        category: p.category || 'community',
        description: p.description || ''
      })) : [];
      console.log(`${LOG} Loaded ${this.patterns.length} community patterns (v${this.version})`);
      return true;
    } catch (err) {
      console.log(`${LOG} Failed to load community patterns: ${err.message}`);
      return false;
    }
  }

  /**
   * Return the loaded patterns.
   * @returns {Array<{regex: string, severity: string, category: string, description: string}>}
   */
  getPatterns() {
    return this.patterns;
  }

  /**
   * Merge community patterns into an existing patterns array.
   * @param {Array} existingPatterns - The current detection patterns.
   * @returns {Array} Combined pattern array.
   */
  merge(existingPatterns) {
    const existing = Array.isArray(existingPatterns) ? existingPatterns : [];
    const merged = [...existing];
    for (const cp of this.patterns) {
      if (!cp.regex) continue;
      const alreadyExists = merged.some(p => (p.regex || p.pattern || '').toString() === cp.regex);
      if (!alreadyExists) merged.push(cp);
    }
    console.log(`${LOG} Merged: ${existing.length} existing + ${merged.length - existing.length} community = ${merged.length} total`);
    return merged;
  }

  /** Return the version string from the pattern file. @returns {string|null} */
  getVersion() {
    return this.version;
  }
}

module.exports = { AdaptiveDetector, SemanticAnalysisHook, CommunityPatterns, trigramSimilarity };
