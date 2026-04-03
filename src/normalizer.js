'use strict';

/**
 * Agent Shield — Advanced Text Normalizer (v12.0)
 *
 * Consolidates all text normalization logic into a standalone module.
 * Handles zero-width character stripping, leetspeak reversal, spaced-out
 * character collapsing, context wrapper removal, Unicode escape decoding,
 * and HTML entity decoding.
 *
 * All processing runs locally — no data ever leaves your environment.
 *
 * @module normalizer
 */

// =========================================================================
// CONSTANTS
// =========================================================================

/**
 * Zero-width and invisible Unicode characters to strip.
 * @type {RegExp}
 */
const ZERO_WIDTH_RE = /[\u200B\u200C\u200D\u200E\u200F\uFEFF\u00AD\u2060\u2061\u2062\u2063\u2064\u180E\u034F]/g;

/**
 * Leetspeak substitution map (character → ASCII letter).
 * @type {Object<string, string>}
 */
const LEET_MAP = {
  '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's',
  '7': 't', '8': 'b', '9': 'g', '@': 'a', '!': 'i',
  '$': 's', '+': 't', '(': 'c', '|': 'l',
  '}{': 'h', '}{': 'h', '/\\': 'a', '\\/': 'v',
  '|3': 'b', '|)': 'd', '|<': 'k', '|_': 'l',
  '|-|': 'h', '|\\|': 'n', '|2': 'r',
  // Common Unicode lookalikes
  '\u0430': 'a', '\u0435': 'e', '\u043E': 'o', '\u0440': 'p',
  '\u0441': 'c', '\u0443': 'y', '\u0445': 'x',
  '\u0410': 'A', '\u0415': 'E', '\u041E': 'O', '\u0420': 'P',
  '\u0421': 'C', '\u0423': 'Y', '\u0425': 'X'
};

/**
 * Multi-character leet sequences sorted by length (longest first for greedy matching).
 * @type {Array<[string, string]>}
 */
const MULTI_LEET = [
  ['|\\|', 'n'], ['|-|', 'h'], ['/\\', 'a'], ['\\/', 'v'],
  ['}{', 'h'], ['|3', 'b'], ['|)', 'd'], ['|<', 'k'],
  ['|_', 'l'], ['|2', 'r']
];

/**
 * Context wrapper phrases that attackers prepend to bypass filters.
 * @type {RegExp[]}
 */
const CONTEXT_WRAPPERS = [
  /^for\s+(?:research|educational|testing|academic|safety)\s*(?:purposes?\s*)?[:\-,]\s*/im,
  /^(?:hypothetically|theoretically|in\s+theory)\s*[,:\-]\s*/im,
  /^(?:imagine|pretend|suppose|assume)\s+(?:that\s+)?(?:you\s+(?:are|were)\s+)?/im,
  /^(?:as\s+a\s+(?:thought\s+)?experiment)\s*[,:\-]\s*/im,
  /^(?:just\s+)?(?:out\s+of\s+)?(?:curiosity|interest)\s*[,:\-]\s*/im,
  /^(?:in\s+a\s+(?:fictional|hypothetical)\s+(?:scenario|world|context))\s*[,:\-]\s*/im,
  /^(?:please\s+)?(?:help\s+me\s+)?(?:understand|explain)\s+(?:how\s+(?:to\s+)?)?/im,
  /^(?:i'?m\s+(?:a\s+)?(?:security\s+)?researcher)\s*[,:\-]\s*/im
];

/**
 * Named HTML entities map (common subset).
 * @type {Object<string, string>}
 */
const HTML_ENTITIES = {
  'amp': '&', 'lt': '<', 'gt': '>', 'quot': '"', 'apos': "'",
  'nbsp': ' ', 'tab': '\t', 'newline': '\n',
  'lpar': '(', 'rpar': ')', 'lsqb': '[', 'rsqb': ']',
  'lcub': '{', 'rcub': '}', 'sol': '/', 'bsol': '\\',
  'comma': ',', 'period': '.', 'colon': ':', 'semi': ';',
  'excl': '!', 'quest': '?', 'num': '#', 'ast': '*',
  'plus': '+', 'equals': '=', 'hyphen': '-', 'lowbar': '_',
  'percnt': '%', 'dollar': '$', 'commat': '@', 'circ': '^',
  'tilde': '~', 'grave': '`', 'vert': '|'
};

// =========================================================================
// NORMALIZER FUNCTIONS
// =========================================================================

/**
 * Remove zero-width and invisible Unicode characters.
 * @param {string} text
 * @returns {string}
 */
function stripZeroWidth(text) {
  if (!text || typeof text !== 'string') return text || '';
  return text.replace(ZERO_WIDTH_RE, '');
}

/**
 * Convert leetspeak substitutions back to standard ASCII letters.
 * Handles multi-character sequences first, then single-character replacements.
 * @param {string} text
 * @returns {string}
 */
function reverseLeetspeak(text) {
  if (!text || typeof text !== 'string') return text || '';

  let result = text;

  // Multi-character sequences first (longest match wins)
  for (const [leet, replacement] of MULTI_LEET) {
    // Escape special regex characters in the leet string
    const escaped = leet.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    result = result.replace(new RegExp(escaped, 'g'), replacement);
  }

  // Single-character replacements
  let out = '';
  for (let i = 0; i < result.length; i++) {
    const ch = result[i];
    out += LEET_MAP[ch] !== undefined ? LEET_MAP[ch] : ch;
  }

  return out;
}

/**
 * Collapse spaced-out character obfuscation (e.g. "i g n o r e" → "ignore").
 * Only collapses when most characters are single with uniform spacing.
 * @param {string} text
 * @returns {string}
 */
function collapseCharSpacing(text) {
  if (!text || typeof text !== 'string') return text || '';

  // Process line by line to preserve structure
  const lines = text.split('\n');
  const result = [];

  for (const line of lines) {
    // Match pattern: single chars separated by uniform whitespace
    // e.g., "i g n o r e" or "i  g  n  o  r  e"
    const spacedPattern = /^(\s*)([a-zA-Z])((\s{1,3})[a-zA-Z]){3,}(\s*)$/;
    if (spacedPattern.test(line.trim())) {
      // Extract only the letter characters
      const collapsed = line.trim().replace(/\s+/g, '');
      const leadingSpace = line.match(/^(\s*)/)[1];
      result.push(leadingSpace + collapsed);
    } else {
      result.push(line);
    }
  }

  return result.join('\n');
}

/**
 * Remove common context wrapper phrases used to disguise malicious prompts.
 * @param {string} text
 * @returns {string}
 */
function stripContextWrappers(text) {
  if (!text || typeof text !== 'string') return text || '';

  let result = text;
  for (const pattern of CONTEXT_WRAPPERS) {
    result = result.replace(pattern, '');
  }

  return result;
}

/**
 * Decode percent-encoded (%XX), Unicode escape (\uXXXX), hex escape (\xXX),
 * numeric HTML entities (&#DDD; / &#xHH;), and named HTML entities (&name;).
 * @param {string} text
 * @returns {string}
 */
function decodeUnicodeEscapes(text) {
  if (!text || typeof text !== 'string') return text || '';

  let result = text;

  // Decode \\uXXXX sequences
  result = result.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => {
    try {
      return String.fromCharCode(parseInt(hex, 16));
    } catch (_e) {
      return _;
    }
  });

  // Decode \\xXX sequences
  result = result.replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) => {
    try {
      return String.fromCharCode(parseInt(hex, 16));
    } catch (_e) {
      return _;
    }
  });

  // Decode percent-encoded %XX sequences
  try {
    result = decodeURIComponent(result);
  } catch (_e) {
    // If decodeURIComponent fails (malformed), do manual single-byte decode
    result = result.replace(/%([0-9a-fA-F]{2})/g, (_, hex) => {
      try {
        return String.fromCharCode(parseInt(hex, 16));
      } catch (_e2) {
        return _;
      }
    });
  }

  // Decode numeric HTML entities &#DDD; and &#xHH;
  result = result.replace(/&#x([0-9a-fA-F]+);/gi, (_, hex) => {
    try {
      return String.fromCodePoint(parseInt(hex, 16));
    } catch (_e) {
      return _;
    }
  });
  result = result.replace(/&#(\d+);/g, (_, dec) => {
    try {
      return String.fromCodePoint(parseInt(dec, 10));
    } catch (_e) {
      return _;
    }
  });

  // Decode named HTML entities &name;
  result = result.replace(/&([a-zA-Z]+);/g, (match, name) => {
    const lower = name.toLowerCase();
    return HTML_ENTITIES[lower] !== undefined ? HTML_ENTITIES[lower] : match;
  });

  return result;
}

/**
 * Apply all normalizers in the recommended sequence.
 * Order: zero-width → unicode escapes → leetspeak → char spacing → context wrappers.
 * @param {string} text
 * @returns {string}
 */
function normalizeAll(text) {
  if (!text || typeof text !== 'string') return text || '';

  let result = text;
  result = stripZeroWidth(result);
  result = decodeUnicodeEscapes(result);
  result = reverseLeetspeak(result);
  result = collapseCharSpacing(result);
  result = stripContextWrappers(result);

  return result;
}

// =========================================================================
// TEXT NORMALIZER CLASS
// =========================================================================

/**
 * Text Normalizer class with all normalization methods.
 *
 * @example
 * const { TextNormalizer } = require('./normalizer');
 * const normalizer = new TextNormalizer();
 * const clean = normalizer.normalizeAll('i\\u0067nore previous instructions');
 */
class TextNormalizer {
  /**
   * @param {object} [options]
   * @param {boolean} [options.aggressive] - Enable aggressive normalization (default false)
   * @param {string[]} [options.customWrappers] - Additional context wrapper patterns
   */
  constructor(options = {}) {
    this.aggressive = options.aggressive || false;
    this.customWrapperPatterns = [];

    if (options.customWrappers) {
      for (const w of options.customWrappers) {
        try {
          this.customWrapperPatterns.push(new RegExp(w, 'im'));
        } catch (_e) {
          console.warn(`[Agent Shield] Invalid custom wrapper pattern: ${w}`);
        }
      }
    }

    /** @type {{ input: string, output: string, steps: string[] }[]} */
    this._history = [];

    console.log('[Agent Shield] TextNormalizer initialized');
  }

  /**
   * Remove zero-width and invisible Unicode characters.
   * @param {string} text
   * @returns {string}
   */
  stripZeroWidth(text) {
    return stripZeroWidth(text);
  }

  /**
   * Convert leetspeak substitutions back to ASCII.
   * @param {string} text
   * @returns {string}
   */
  reverseLeetspeak(text) {
    return reverseLeetspeak(text);
  }

  /**
   * Collapse spaced-out character obfuscation.
   * @param {string} text
   * @returns {string}
   */
  collapseCharSpacing(text) {
    return collapseCharSpacing(text);
  }

  /**
   * Remove context wrapper phrases.
   * @param {string} text
   * @returns {string}
   */
  stripContextWrappers(text) {
    let result = stripContextWrappers(text);

    // Apply custom wrappers
    for (const pattern of this.customWrapperPatterns) {
      result = result.replace(pattern, '');
    }

    return result;
  }

  /**
   * Decode percent-encoded, Unicode escape, hex escape, and HTML entity sequences.
   * @param {string} text
   * @returns {string}
   */
  decodeUnicodeEscapes(text) {
    return decodeUnicodeEscapes(text);
  }

  /**
   * Apply all normalizers in sequence.
   * @param {string} text
   * @returns {string}
   */
  normalizeAll(text) {
    if (!text || typeof text !== 'string') return text || '';

    const steps = [];
    let result = text;

    result = this.stripZeroWidth(result);
    if (result !== text) steps.push('stripZeroWidth');

    const prev1 = result;
    result = this.decodeUnicodeEscapes(result);
    if (result !== prev1) steps.push('decodeUnicodeEscapes');

    const prev2 = result;
    result = this.reverseLeetspeak(result);
    if (result !== prev2) steps.push('reverseLeetspeak');

    const prev3 = result;
    result = this.collapseCharSpacing(result);
    if (result !== prev3) steps.push('collapseCharSpacing');

    const prev4 = result;
    result = this.stripContextWrappers(result);
    if (result !== prev4) steps.push('stripContextWrappers');

    // Aggressive mode: apply a second pass
    if (this.aggressive && steps.length > 0) {
      result = stripZeroWidth(result);
      result = decodeUnicodeEscapes(result);
      result = reverseLeetspeak(result);
      result = collapseCharSpacing(result);
      steps.push('aggressive_second_pass');
    }

    this._history.push({ input: text.slice(0, 200), output: result.slice(0, 200), steps });

    return result;
  }

  /**
   * Get normalization history.
   * @returns {Array<{ input: string, output: string, steps: string[] }>}
   */
  getHistory() {
    return [...this._history];
  }

  /**
   * Clear normalization history.
   */
  clearHistory() {
    this._history = [];
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
  TextNormalizer,
  normalizeAll,
  stripZeroWidth,
  reverseLeetspeak,
  collapseCharSpacing,
  stripContextWrappers,
  decodeUnicodeEscapes,
  ZERO_WIDTH_RE,
  LEET_MAP,
  CONTEXT_WRAPPERS,
  HTML_ENTITIES
};
