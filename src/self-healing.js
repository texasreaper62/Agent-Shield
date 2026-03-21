'use strict';

/**
 * Agent Shield — Self-Healing Patterns (v3.0)
 *
 * When a new attack bypasses detection, automatically generates and deploys
 * a new pattern to catch it. Learns from false negatives to continuously
 * strengthen the detection engine.
 *
 * All processing runs locally — no data ever leaves your environment.
 */

const { scanText } = require('./detector-core');

// =========================================================================
// PATTERN GENERATOR
// =========================================================================

/**
 * Generates regex patterns from attack text by extracting key phrases
 * and building flexible matchers.
 */
class PatternGenerator {
  constructor() {
    /** Attack vocabulary — words that are strong indicators of malicious intent */
    this._attackVerbs = ['ignore', 'disregard', 'forget', 'override', 'bypass', 'skip', 'abandon', 'cancel', 'disable', 'remove', 'drop', 'circumvent', 'violate', 'break'];
    this._attackNouns = ['instructions', 'rules', 'guidelines', 'restrictions', 'safety', 'training', 'constraints', 'filters', 'limits', 'guardrails', 'protocols', 'policies', 'prompt', 'system'];
    this._attackAdjectives = ['previous', 'prior', 'all', 'your', 'above', 'original', 'initial', 'earlier', 'any', 'every'];
    this._roleWords = ['you are now', 'act as', 'pretend', 'behave as', 'from now on', 'henceforth', 'going forward'];
    this._exfilWords = ['send', 'transmit', 'reveal', 'show', 'output', 'display', 'extract', 'leak', 'share'];
  }

  /**
   * Generate a detection pattern from an attack text.
   * @param {string} attackText - The bypassing attack text.
   * @param {object} [options]
   * @param {string} [options.category] - Suggested category.
   * @returns {object|null} Generated pattern { regex, severity, category, description, detail, source }
   */
  generate(attackText, options = {}) {
    if (!attackText || attackText.length < 15) return null;

    const lower = attackText.toLowerCase();
    const words = lower.split(/\s+/);

    // Find attack verb + noun combinations
    const foundVerbs = words.filter(w => this._attackVerbs.includes(w));
    const foundNouns = words.filter(w => this._attackNouns.includes(w));
    const foundAdjs = words.filter(w => this._attackAdjectives.includes(w));

    if (foundVerbs.length === 0 && foundNouns.length === 0) {
      // Try role-based pattern
      for (const phrase of this._roleWords) {
        if (lower.includes(phrase)) {
          return this._buildRolePattern(attackText, phrase, options);
        }
      }

      // Try exfil-based pattern
      for (const word of this._exfilWords) {
        if (lower.includes(word)) {
          return this._buildExfilPattern(attackText, word, options);
        }
      }

      // Fallback: extract longest n-gram that looks attack-like
      return this._buildNgramPattern(attackText, options);
    }

    return this._buildVerbNounPattern(attackText, foundVerbs, foundNouns, foundAdjs, options);
  }

  /**
   * Generate multiple pattern variants for better coverage.
   * @param {string} attackText
   * @param {object} [options]
   * @returns {Array<object>} Array of generated patterns.
   */
  generateVariants(attackText, options = {}) {
    const base = this.generate(attackText, options);
    if (!base) return [];

    const variants = [base];

    // Generate a looser variant
    const lower = attackText.toLowerCase();
    const words = lower.split(/\s+/).filter(w => w.length > 3);
    const keyWords = words.filter(w =>
      this._attackVerbs.includes(w) ||
      this._attackNouns.includes(w) ||
      this._exfilWords.includes(w)
    );

    if (keyWords.length >= 2) {
      const looseRegex = keyWords.map(w => w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('\\b.{0,50}\\b');
      variants.push({
        regex: new RegExp(looseRegex, 'i'),
        severity: 'medium',
        category: base.category,
        description: `Loose variant: ${base.description}`,
        detail: `Auto-generated loose pattern from: "${attackText.substring(0, 80)}"`,
        source: 'self_healing_loose'
      });
    }

    return variants;
  }

  /** @private */
  _buildVerbNounPattern(text, verbs, nouns, adjs, options) {
    const verb = verbs[0];
    const noun = nouns[0];
    const adjPart = adjs.length > 0 ? `(?:\\s+(?:${adjs.join('|')}))` : '(?:\\s+\\w+)?';

    const regexStr = `${this._esc(verb)}${adjPart}?\\s+(?:\\w+\\s+){0,3}${this._esc(noun)}`;

    return {
      regex: new RegExp(regexStr, 'i'),
      severity: 'high',
      category: options.category || 'instruction_override',
      description: `Auto-healed: detects "${verb} ... ${noun}" attack pattern.`,
      detail: `Self-healing pattern generated from: "${text.substring(0, 80)}"`,
      source: 'self_healing'
    };
  }

  /** @private */
  _buildRolePattern(text, phrase, options) {
    const escaped = this._esc(phrase);
    return {
      regex: new RegExp(`${escaped}\\s+.{5,}`, 'i'),
      severity: 'high',
      category: options.category || 'role_hijack',
      description: `Auto-healed: detects "${phrase}" role hijack pattern.`,
      detail: `Self-healing pattern generated from: "${text.substring(0, 80)}"`,
      source: 'self_healing'
    };
  }

  /** @private */
  _buildExfilPattern(text, word, options) {
    return {
      regex: new RegExp(`${this._esc(word)}\\s+(?:\\w+\\s+){0,5}(?:data|information|secret|credentials?|prompt|instructions)`, 'i'),
      severity: 'high',
      category: options.category || 'data_exfiltration',
      description: `Auto-healed: detects "${word}" data exfiltration pattern.`,
      detail: `Self-healing pattern generated from: "${text.substring(0, 80)}"`,
      source: 'self_healing'
    };
  }

  /** @private */
  _buildNgramPattern(text, options) {
    // Extract a meaningful 3-5 word phrase from the attack
    const words = text.split(/\s+/).filter(w => w.length > 2);
    if (words.length < 3) return null;

    const escapedWords = words.slice(0, Math.min(5, words.length)).map(w => this._esc(w));
    const phrase = escapedWords.join('\\s+');
    return {
      regex: new RegExp(phrase, 'i'),
      severity: 'medium',
      category: options.category || 'unknown',
      description: `Auto-healed: detects n-gram pattern from bypassing attack.`,
      detail: `Self-healing n-gram pattern from: "${text.substring(0, 80)}"`,
      source: 'self_healing_ngram'
    };
  }

  /** @private */
  _esc(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }
}

// =========================================================================
// SELF-HEALING ENGINE
// =========================================================================

/**
 * Monitors for detection failures and auto-generates patches.
 */
class SelfHealingEngine {
  /**
   * @param {object} [options]
   * @param {number} [options.maxPatterns=100] - Max auto-generated patterns to keep.
   * @param {boolean} [options.autoApply=true] - Auto-apply generated patterns.
   * @param {Function} [options.onHeal] - Callback when a new pattern is generated.
   */
  constructor(options = {}) {
    this.maxPatterns = options.maxPatterns || 100;
    this.autoApply = options.autoApply !== false;
    this.onHeal = options.onHeal || null;

    this._generator = new PatternGenerator();
    this._generatedPatterns = [];
    this._healHistory = [];
    this._falseNegatives = [];

    console.log('[Agent Shield] SelfHealingEngine initialized (maxPatterns: %d, autoApply: %s)', this.maxPatterns, this.autoApply);
  }

  /**
   * Report a false negative — an attack that was not detected.
   * @param {string} attackText - The undetected attack text.
   * @param {object} [metadata] - Additional context.
   * @returns {object} { healed: boolean, patterns: Array, error?: string }
   */
  reportFalseNegative(attackText, metadata = {}) {
    this._falseNegatives.push({
      text: attackText,
      metadata,
      timestamp: Date.now()
    });
    // Prevent unbounded growth
    if (this._falseNegatives.length > this.maxPatterns * 2) {
      this._falseNegatives = this._falseNegatives.slice(-this.maxPatterns);
    }

    // Generate patterns
    const patterns = this._generator.generateVariants(attackText, {
      category: metadata.category
    });

    if (patterns.length === 0) {
      return { healed: false, patterns: [], error: 'Could not generate patterns from this input.' };
    }

    // Validate: make sure the generated pattern actually catches the attack
    const validated = patterns.filter(p => {
      try {
        return p.regex.test(attackText);
      } catch (e) {
        return false;
      }
    });

    if (validated.length === 0) {
      return { healed: false, patterns: [], error: 'Generated patterns did not match the original attack.' };
    }

    // Store and apply
    for (const pattern of validated) {
      if (this._generatedPatterns.length >= this.maxPatterns) {
        this._generatedPatterns.shift(); // Remove oldest
      }
      this._generatedPatterns.push(pattern);
    }

    this._healHistory.push({
      attackText: attackText.substring(0, 200),
      patternsGenerated: validated.length,
      timestamp: Date.now()
    });

    if (this.onHeal) {
      this.onHeal({ patterns: validated, attackText: attackText.substring(0, 200) });
    }

    console.log('[Agent Shield] Self-healed: generated %d pattern(s) for bypassing attack.', validated.length);

    return { healed: true, patterns: validated };
  }

  /**
   * Scan text using both core patterns and self-healed patterns.
   * @param {string} text
   * @param {object} [options]
   * @returns {object} Enhanced scan result.
   */
  scan(text, options = {}) {
    const coreResult = scanText(text, options);

    // Also check against self-healed patterns
    const healedThreats = [];
    for (const pattern of this._generatedPatterns) {
      try {
        if (pattern.regex.test(text)) {
          healedThreats.push({
            severity: pattern.severity,
            category: pattern.category,
            description: pattern.description,
            detail: pattern.detail,
            confidence: 60,
            confidenceLabel: 'Likely a threat',
            source: 'self_healing'
          });
        }
      } catch (e) {
        // Skip broken patterns
      }
    }

    if (healedThreats.length > 0 && coreResult.threats.length === 0) {
      return {
        ...coreResult,
        status: healedThreats.some(t => t.severity === 'critical') ? 'danger' :
                healedThreats.some(t => t.severity === 'high') ? 'warning' : 'caution',
        threats: [...coreResult.threats, ...healedThreats],
        stats: {
          ...coreResult.stats,
          totalThreats: coreResult.threats.length + healedThreats.length
        },
        selfHealed: true
      };
    }

    return {
      ...coreResult,
      threats: [...coreResult.threats, ...healedThreats],
      selfHealed: healedThreats.length > 0
    };
  }

  /**
   * Get all generated patterns.
   * @returns {Array}
   */
  getPatterns() {
    return this._generatedPatterns.map(p => ({
      category: p.category,
      severity: p.severity,
      description: p.description,
      source: p.source
    }));
  }

  /**
   * Get healing statistics.
   * @returns {object}
   */
  getStats() {
    return {
      generatedPatterns: this._generatedPatterns.length,
      falseNegatives: this._falseNegatives.length,
      healEvents: this._healHistory.length,
      history: this._healHistory.slice(-10)
    };
  }

  /**
   * Export generated patterns for review.
   * @returns {string} JSON string of patterns.
   */
  exportPatterns() {
    return JSON.stringify(this._generatedPatterns.map(p => ({
      regex: p.regex.source,
      flags: p.regex.flags,
      severity: p.severity,
      category: p.category,
      description: p.description,
      detail: p.detail
    })), null, 2);
  }

  /** Reset all generated patterns. */
  reset() {
    this._generatedPatterns = [];
    this._healHistory = [];
    this._falseNegatives = [];
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = { SelfHealingEngine, PatternGenerator };
