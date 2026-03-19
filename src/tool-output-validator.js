'use strict';

/**
 * Agent Shield — Tool Output Validator
 *
 * Scans what tools RETURN, not just what gets called. Validates tool output
 * for prompt injection, data exfiltration, and other threats that may be
 * smuggled in through tool responses.
 *
 * All detection runs locally — no data ever leaves your environment.
 */

const { scanText } = require('./detector-core');

// =========================================================================
// CONSTANTS
// =========================================================================

/** Default maximum output size in bytes (100KB). */
const DEFAULT_MAX_OUTPUT_SIZE = 100 * 1024;

/** Zero-width and invisible Unicode characters. */
const INVISIBLE_CHAR_REGEX = /[\u200B\u200C\u200D\u200E\u200F\u202A-\u202E\u2060\u2061\u2062\u2063\u2064\u2066-\u2069\uFEFF\u00AD]/g;

/** Suspicious URL patterns (known exfiltration vectors). */
const SUSPICIOUS_URL_PATTERNS = [
  /https?:\/\/[^/]*\.(ngrok|burpcollaborator|requestbin|pipedream|webhook\.site|hookbin)\./i,
  /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,
  /https?:\/\/[^/]*\.onion\b/i,
  /https?:\/\/[^/]+\/.*\?(.*=.*&){4,}/i
];

/** Safe URL domain patterns. */
const SAFE_URL_PATTERNS = [
  /^https?:\/\/([^/]*\.)?(github\.com|gitlab\.com|stackoverflow\.com|npmjs\.com|docs\.google\.com|developer\.mozilla\.org|wikipedia\.org)\b/i
];

/** Dangerous code patterns inside code blocks. */
const DANGEROUS_CODE_PATTERNS = [
  { regex: /eval\s*\(/, description: 'eval() call' },
  { regex: /Function\s*\(/, description: 'Function constructor' },
  { regex: /child_process|exec\s*\(|spawn\s*\(/, description: 'shell execution' },
  { regex: /process\.env/, description: 'environment variable access' },
  { regex: /fs\.(read|write|unlink|rmdir)/, description: 'filesystem operation' },
  { regex: /require\s*\(\s*['"]https?['"]/, description: 'remote module loading' },
  { regex: /XMLHttpRequest|fetch\s*\(|\.ajax\s*\(/, description: 'network request' },
  { regex: /document\.cookie|localStorage|sessionStorage/, description: 'browser storage access' }
];

// =========================================================================
// OUTPUT SANITIZER
// =========================================================================

/**
 * Sanitizes tool output by removing or replacing dangerous content.
 */
class OutputSanitizer {
  /**
   * Remove or replace dangerous content from tool output.
   * @param {string} text - The text to sanitize.
   * @param {object} [options] - Sanitization options.
   * @param {boolean} [options.stripInvisible=true] - Remove invisible characters.
   * @param {boolean} [options.redactUrls=true] - Redact suspicious URLs.
   * @param {boolean} [options.redactCode=false] - Redact dangerous code blocks.
   * @param {number} [options.maxLength] - Maximum output length.
   * @returns {string} Sanitized text.
   */
  static sanitize(text, options = {}) {
    if (!text || typeof text !== 'string') return '';

    const {
      stripInvisible = true,
      redactUrls = true,
      redactCode = false,
      maxLength
    } = options;

    let result = text;

    if (stripInvisible) {
      result = OutputSanitizer.stripInvisibleChars(result);
    }

    if (redactUrls) {
      result = OutputSanitizer.redactUrls(result);
    }

    if (redactCode) {
      result = OutputSanitizer.redactCodeBlocks(result);
    }

    if (maxLength && maxLength > 0) {
      result = OutputSanitizer.truncate(result, maxLength);
    }

    return result;
  }

  /**
   * Remove zero-width, bidirectional, and other invisible Unicode characters.
   * @param {string} text - The text to strip.
   * @returns {string} Cleaned text.
   */
  static stripInvisibleChars(text) {
    if (!text || typeof text !== 'string') return '';
    return text.replace(INVISIBLE_CHAR_REGEX, '');
  }

  /**
   * Safe truncation that does not break multi-byte Unicode encoding.
   * @param {string} text - The text to truncate.
   * @param {number} maxLength - Maximum character length.
   * @returns {string} Truncated text.
   */
  static truncate(text, maxLength) {
    if (!text || typeof text !== 'string') return '';
    if (text.length <= maxLength) return text;

    // Use Array.from to handle surrogate pairs correctly
    const chars = Array.from(text);
    if (chars.length <= maxLength) return text;

    return chars.slice(0, maxLength).join('') + '... [truncated]';
  }

  /**
   * Redact suspicious URLs while keeping safe, well-known ones.
   * @param {string} text - The text containing URLs.
   * @returns {string} Text with suspicious URLs redacted.
   */
  static redactUrls(text) {
    if (!text || typeof text !== 'string') return '';

    return text.replace(/https?:\/\/[^\s<>"')\]]+/gi, (url) => {
      // Allow known-safe domains
      for (const safePattern of SAFE_URL_PATTERNS) {
        if (safePattern.test(url)) return url;
      }

      // Redact known-suspicious domains
      for (const suspiciousPattern of SUSPICIOUS_URL_PATTERNS) {
        if (suspiciousPattern.test(url)) {
          return '[REDACTED_URL]';
        }
      }

      // Let other URLs through
      return url;
    });
  }

  /**
   * Flag or redact code blocks containing dangerous patterns.
   * @param {string} text - The text containing code blocks.
   * @param {object} [options] - Redaction options.
   * @param {boolean} [options.redact=false] - If true, replace dangerous blocks entirely; otherwise, add warnings.
   * @returns {string} Text with dangerous code blocks flagged or redacted.
   */
  static redactCodeBlocks(text, options = {}) {
    if (!text || typeof text !== 'string') return '';
    const { redact = false } = options;

    return text.replace(/```[\s\S]*?```/g, (block) => {
      const found = [];
      for (const pattern of DANGEROUS_CODE_PATTERNS) {
        if (pattern.regex.test(block)) {
          found.push(pattern.description);
        }
      }

      if (found.length === 0) return block;

      if (redact) {
        return '```\n[REDACTED: code block contained dangerous patterns: ' + found.join(', ') + ']\n```';
      }

      return '[Agent Shield WARNING: dangerous patterns detected (' + found.join(', ') + ')]\n' + block;
    });
  }
}

// =========================================================================
// TOOL OUTPUT VALIDATOR
// =========================================================================

/**
 * Validates tool output for security threats.
 * Scans what tools return and flags prompt injection, exfiltration vectors,
 * invisible characters, and other threats embedded in tool responses.
 */
class ToolOutputValidator {
  /**
   * @param {object} [options]
   * @param {string} [options.sensitivity='medium'] - Scan sensitivity: 'low', 'medium', 'high'.
   * @param {RegExp[]} [options.blockedPatterns=[]] - Custom regexes to flag in output.
   * @param {number} [options.maxOutputSize=102400] - Maximum output size in bytes (default 100KB).
   */
  constructor(options = {}) {
    this.sensitivity = options.sensitivity || 'medium';
    this.blockedPatterns = options.blockedPatterns || [];
    this.maxOutputSize = options.maxOutputSize || DEFAULT_MAX_OUTPUT_SIZE;

    /** @type {Map<string, {name: string, check: Function}[]>} */
    this._rules = new Map();

    /** @type {Map<string, {total: number, threats: number, truncated: number}>} */
    this._stats = new Map();

    console.log('[Agent Shield] ToolOutputValidator initialized (sensitivity: %s, maxOutput: %d bytes)', this.sensitivity, this.maxOutputSize);
  }

  /**
   * Validate tool output for threats.
   * @param {string} toolName - The name of the tool that produced the output.
   * @param {string} output - The tool's output text.
   * @param {object} [context] - Additional context (e.g., calling agent, request ID).
   * @returns {object} Validation result: { safe, threats, sanitized, truncated }.
   */
  validate(toolName, output, context = {}) {
    const stat = this._ensureStat(toolName);
    stat.total++;

    const result = {
      safe: true,
      threats: [],
      sanitized: null,
      truncated: false
    };

    if (!output || typeof output !== 'string') {
      return result;
    }

    // Check output size
    const byteLength = Buffer.byteLength(output, 'utf8');
    if (byteLength > this.maxOutputSize) {
      result.truncated = true;
      stat.truncated++;
      output = OutputSanitizer.truncate(output, this.maxOutputSize);
      result.threats.push({
        severity: 'medium',
        category: 'output_size',
        description: `Tool "${toolName}" output exceeded max size (${byteLength} bytes > ${this.maxOutputSize} bytes).`,
        detail: 'Output was truncated to comply with size limits.'
      });
    }

    // Run core threat scan
    const scanResult = scanText(output, {
      source: `tool_output:${toolName}`,
      sensitivity: this.sensitivity
    });

    if (scanResult.threats.length > 0) {
      result.threats.push(...scanResult.threats);
    }

    // Check custom blocked patterns
    for (const pattern of this.blockedPatterns) {
      if (pattern.test(output)) {
        result.threats.push({
          severity: 'high',
          category: 'blocked_pattern',
          description: `Tool "${toolName}" output matched a blocked pattern.`,
          detail: `Pattern: ${pattern.toString()}`
        });
      }
    }

    // Run per-tool custom rules
    const rules = this._rules.get(toolName) || [];
    for (const rule of rules) {
      try {
        const ruleResult = rule.check(output);
        if (ruleResult && !ruleResult.valid) {
          result.threats.push({
            severity: 'medium',
            category: 'custom_rule',
            description: `Tool "${toolName}" failed rule "${rule.name}".`,
            detail: ruleResult.reason || 'Custom rule violation.'
          });
        }
      } catch (err) {
        console.log('[Agent Shield] Custom rule "%s" threw an error for tool "%s": %s', rule.name, toolName, err.message);
      }
    }

    // Determine safety
    if (result.threats.length > 0) {
      result.safe = false;
      stat.threats++;
    }

    // Provide sanitized output
    result.sanitized = OutputSanitizer.sanitize(output, {
      stripInvisible: true,
      redactUrls: true,
      maxLength: this.maxOutputSize
    });

    return result;
  }

  /**
   * Add a custom validation rule for a specific tool.
   * @param {string} toolName - The tool name to apply the rule to.
   * @param {object} rule - The rule definition.
   * @param {string} rule.name - Human-readable rule name.
   * @param {Function} rule.check - Function that receives output and returns { valid, reason }.
   */
  addRule(toolName, rule) {
    if (!rule || typeof rule.name !== 'string' || typeof rule.check !== 'function') {
      throw new Error('Rule must have a "name" (string) and "check" (function).');
    }

    if (!this._rules.has(toolName)) {
      this._rules.set(toolName, []);
    }

    this._rules.get(toolName).push(rule);
    console.log('[Agent Shield] Added rule "%s" for tool "%s"', rule.name, toolName);
  }

  /**
   * Get per-tool validation statistics.
   * @returns {object} Map of tool names to { total, threats, truncated }.
   */
  getStats() {
    const stats = {};
    for (const [tool, data] of this._stats) {
      stats[tool] = { ...data };
    }
    return stats;
  }

  /**
   * Ensure a stats entry exists for a tool.
   * @param {string} toolName
   * @returns {object}
   * @private
   */
  _ensureStat(toolName) {
    if (!this._stats.has(toolName)) {
      this._stats.set(toolName, { total: 0, threats: 0, truncated: 0 });
    }
    return this._stats.get(toolName);
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = { ToolOutputValidator, OutputSanitizer };
