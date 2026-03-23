'use strict';

/**
 * Agent Shield — ML-Powered Detection (Pro/Enterprise)
 *
 * Bridge module that integrates the agentshield-ml ONNX inference engine
 * into the main SDK. This is a premium feature — ML detection is only
 * available on Pro and Enterprise tiers.
 *
 * Free tier users get pattern-based detection (fast, zero-dependency).
 * Pro/Enterprise users get pattern + ML ensemble detection for higher
 * accuracy and resistance to novel/obfuscated attacks.
 *
 * All inference runs locally via ONNX Runtime — no data leaves your environment.
 */

const PREFIX = '[Agent Shield]';

/** Tiers that unlock ML detection. */
const ML_ENABLED_TIERS = ['pro', 'enterprise'];

/** All valid tier names. */
const VALID_TIERS = ['free', 'pro', 'enterprise'];

/**
 * Check whether a tier unlocks ML features.
 * @param {string} tier
 * @returns {boolean}
 */
function isMLTier(tier) {
  return ML_ENABLED_TIERS.includes((tier || '').toLowerCase());
}

/**
 * Validate a tier string.
 * @param {string} tier
 * @returns {boolean}
 */
function isValidTier(tier) {
  return VALID_TIERS.includes((tier || '').toLowerCase());
}

/**
 * Try to load agentshield-ml. Returns null if not installed.
 * @returns {Object|null}
 */
function loadMLPackage() {
  try {
    return require('agentshield-ml');
  } catch (_e) {
    // Try relative path for monorepo development
    try {
      return require('../packages/agentshield-ml/src/inference');
    } catch (_e2) {
      return null;
    }
  }
}

/**
 * MLShield — Pro/Enterprise ML-enhanced scanning.
 *
 * Wraps an AgentShield instance and adds ML-based classification.
 * Pattern matching always runs (free). ML runs on top for Pro/Enterprise.
 *
 * @example
 * const { AgentShield } = require('agentshield-sdk');
 * const { MLShield } = require('agentshield-sdk/src/ml-detector');
 *
 * const shield = new AgentShield({ blockOnThreat: true });
 * const ml = new MLShield(shield, { tier: 'pro' });
 *
 * await ml.init();
 * const result = await ml.scan('ignore all previous instructions');
 * // result.ml.isInjection === true
 * // result.ml.confidence === 0.987
 */
class MLShield {
  /**
   * @param {Object} shield - AgentShield instance
   * @param {Object} options
   * @param {string} options.tier - License tier: 'free', 'pro', or 'enterprise'
   * @param {string} [options.licenseKey] - License key for validation
   * @param {number} [options.threshold=0.5] - ML classification threshold
   * @param {string} [options.modelPath] - Custom path to ONNX model
   * @param {string} [options.tokenizerPath] - Custom path to tokenizer.json
   * @param {boolean} [options.mlRequired=false] - If true, throws when ML unavailable
   */
  constructor(shield, options = {}) {
    if (!shield || typeof shield.scan !== 'function') {
      throw new Error(`${PREFIX} MLShield requires an AgentShield instance`);
    }

    this.shield = shield;
    this.tier = (options.tier || 'free').toLowerCase();
    this.licenseKey = options.licenseKey || null;
    this.threshold = options.threshold || 0.5;
    this.mlRequired = options.mlRequired || false;
    this.modelPath = options.modelPath || null;
    this.tokenizerPath = options.tokenizerPath || null;

    if (!isValidTier(this.tier)) {
      throw new Error(`${PREFIX} Invalid tier "${this.tier}". Valid tiers: ${VALID_TIERS.join(', ')}`);
    }

    this._mlDetector = null;
    this._mlAvailable = false;
    this._initialized = false;

    this._stats = {
      totalScans: 0,
      mlScans: 0,
      mlUpgrades: 0,     // times ML caught something patterns missed
      mlConfirmed: 0,     // times ML agreed with pattern detection
      avgMlLatencyMs: 0
    };
  }

  /**
   * Initialize the ML detector. Must be called before scanning.
   * No-op on free tier (patterns still work without init).
   * @returns {Promise<{ ready: boolean, tier: string, mlAvailable: boolean }>}
   */
  async init() {
    if (this._initialized) {
      return this._status();
    }

    if (!isMLTier(this.tier)) {
      console.log(`${PREFIX} Free tier — pattern-based detection active. Upgrade to Pro for ML detection.`);
      this._initialized = true;
      return this._status();
    }

    // Pro/Enterprise — try to load ML
    const mlPkg = loadMLPackage();
    if (!mlPkg || !mlPkg.MLDetector) {
      const msg = `${PREFIX} agentshield-ml package not found. Install: npm install agentshield-ml`;
      if (this.mlRequired) {
        throw new Error(msg);
      }
      console.warn(msg);
      console.warn(`${PREFIX} Falling back to pattern-only detection.`);
      this._initialized = true;
      return this._status();
    }

    // Create ML detector
    const detectorOpts = { threshold: this.threshold };
    if (this.modelPath) detectorOpts.modelPath = this.modelPath;
    if (this.tokenizerPath) detectorOpts.tokenizerPath = this.tokenizerPath;

    this._mlDetector = new mlPkg.MLDetector(detectorOpts);

    // Check model availability
    if (!this._mlDetector.isModelAvailable()) {
      const msg = `${PREFIX} ML model not found. See agentshield-ml training guide.`;
      if (this.mlRequired) {
        throw new Error(msg);
      }
      console.warn(msg);
      this._initialized = true;
      return this._status();
    }

    // Load the model
    const loaded = await this._mlDetector.load();
    this._mlAvailable = loaded;

    if (loaded) {
      console.log(`${PREFIX} ML detection active (${this.tier} tier)`);
    } else {
      console.warn(`${PREFIX} ML model failed to load — falling back to patterns.`);
    }

    this._initialized = true;
    return this._status();
  }

  /**
   * Scan text with pattern + ML ensemble detection.
   *
   * Free tier: pattern scan only (sync, returns immediately).
   * Pro/Enterprise: pattern scan + async ML classification.
   *
   * @param {string} text - Text to scan
   * @param {Object} [options] - Passed to shield.scan()
   * @returns {Promise<Object>} Enhanced scan result
   */
  async scan(text, options = {}) {
    if (!this._initialized) {
      await this.init();
    }

    // Always run pattern scan (free tier baseline)
    const patternResult = this.shield.scan(text, options);
    this._stats.totalScans++;

    // Free tier or ML not available — return pattern result only
    if (!this._mlAvailable) {
      return { ...patternResult, tier: this.tier, mlAvailable: false };
    }

    // Pro/Enterprise — run ML classification
    const mlResult = await this._mlDetector.classify(text);
    this._stats.mlScans++;
    this._updateLatency(mlResult.latencyMs);

    const combined = {
      ...patternResult,
      tier: this.tier,
      mlAvailable: true,
      ml: {
        isInjection: mlResult.isInjection,
        confidence: mlResult.confidence,
        severity: mlResult.severity,
        latencyMs: mlResult.latencyMs
      }
    };

    // ML caught something patterns missed — upgrade the result
    if (mlResult.isInjection && patternResult.status === 'safe') {
      combined.status = 'warning';
      combined.threats = [...(combined.threats || []), {
        category: 'ml_detection',
        severity: mlResult.severity,
        description: 'ML model detected potential prompt injection',
        detail: `ML confidence: ${(mlResult.confidence * 100).toFixed(1)}%`,
        confidence: Math.round(mlResult.confidence * 100),
        source: 'ml-model'
      }];
      this._stats.mlUpgrades++;
    }

    // Both agree — high confidence
    if (mlResult.isInjection && patternResult.status !== 'safe') {
      combined.mlConfirmed = true;
      this._stats.mlConfirmed++;
    }

    return combined;
  }

  /**
   * Scan input with blocking logic (Pro/Enterprise ML-enhanced).
   * @param {string} text
   * @param {Object} [options]
   * @returns {Promise<Object>}
   */
  async scanInput(text, options = {}) {
    const result = await this.scan(text, { source: 'user_input', ...options });
    result.blocked = this.shield._shouldBlock(result.threats);
    return result;
  }

  /**
   * Scan output with blocking logic (Pro/Enterprise ML-enhanced).
   * @param {string} text
   * @param {Object} [options]
   * @returns {Promise<Object>}
   */
  async scanOutput(text, options = {}) {
    const result = await this.scan(text, { source: 'agent_output', ...options });
    result.blocked = this.shield._shouldBlock(result.threats);
    return result;
  }

  /**
   * Classify text with ML only (Pro/Enterprise).
   * Throws on free tier.
   * @param {string} text
   * @returns {Promise<Object>}
   */
  async classify(text) {
    if (!isMLTier(this.tier)) {
      throw new Error(`${PREFIX} ML classification requires Pro or Enterprise tier. Current: ${this.tier}`);
    }
    if (!this._mlAvailable) {
      throw new Error(`${PREFIX} ML model not available. Call init() first.`);
    }
    return this._mlDetector.classify(text);
  }

  /**
   * Batch classify with ML (Pro/Enterprise).
   * @param {string[]} texts
   * @returns {Promise<Object[]>}
   */
  async classifyBatch(texts) {
    if (!isMLTier(this.tier)) {
      throw new Error(`${PREFIX} ML batch classification requires Pro or Enterprise tier. Current: ${this.tier}`);
    }
    if (!this._mlAvailable) {
      throw new Error(`${PREFIX} ML model not available. Call init() first.`);
    }
    return this._mlDetector.classifyBatch(texts);
  }

  /**
   * Get combined stats (pattern + ML).
   * @returns {Object}
   */
  getStats() {
    return {
      ...this._stats,
      pattern: this.shield.getStats(),
      ml: this._mlDetector ? this._mlDetector.getStats() : null,
      tier: this.tier,
      mlAvailable: this._mlAvailable
    };
  }

  /** @private */
  _status() {
    return {
      ready: this._initialized,
      tier: this.tier,
      mlAvailable: this._mlAvailable
    };
  }

  /** @private */
  _updateLatency(ms) {
    const n = this._stats.mlScans;
    this._stats.avgMlLatencyMs = (this._stats.avgMlLatencyMs * (n - 1) + ms) / n;
  }
}

module.exports = {
  MLShield,
  isMLTier,
  isValidTier,
  loadMLPackage,
  ML_ENABLED_TIERS,
  VALID_TIERS
};
