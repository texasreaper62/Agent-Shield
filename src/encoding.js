'use strict';

/**
 * Advanced Encoding Detection: Steganographic Detection (#37),
 * Encoding Bruteforce Detection (#14), Indirect Injection via
 * Structured Data (#15)
 */

const { scanText } = require('./detector-core');

// =========================================================================
// STEGANOGRAPHIC DETECTION
// =========================================================================

/**
 * Patterns that indicate steganographic hiding techniques.
 */
const STEGO_PATTERNS = {
  // Unicode direction markers used to hide text
  bidi_override: /[\u200E\u200F\u202A-\u202E\u2066-\u2069]/g,

  // Invisible Unicode characters beyond zero-width (excludes common whitespace)
  invisible_chars: /[\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180E\u200B-\u200F\u2060-\u2064\u2066-\u206F\uFEFF\uFFF9-\uFFFB]/g,

  // Whitespace variations used as binary encoding
  whitespace_encoding: /[\u0009\u000A\u000B\u000C\u000D\u0020\u0085\u00A0\u1680\u2000-\u200A\u2028\u2029\u202F\u205F\u3000]/g,

  // Tag characters (Unicode Tags block U+E0001–U+E007F) — can encode hidden text
  tag_characters: /(?:\uDB40[\uDC01-\uDC7F])/g,

  // Variation selectors (can modify rendering without visible change)
  variation_selectors: /[\uFE00-\uFE0F]|(?:\uDB40[\uDD00-\uDDEF])/g
};

class SteganographyDetector {
  /**
   * @param {object} [options]
   * @param {Function} [options.onDetection] - Callback on steganographic content found.
   */
  constructor(options = {}) {
    this.onDetection = options.onDetection || null;
  }

  /**
   * Scans text for steganographic hiding techniques.
   *
   * @param {string} text
   * @returns {object} { found: boolean, techniques: Array, cleaned: string }
   */
  scan(text) {
    if (!text) return { found: false, techniques: [], cleaned: text };

    const techniques = [];
    let cleaned = text;

    // Check for bidirectional override characters
    const bidiMatches = text.match(STEGO_PATTERNS.bidi_override);
    if (bidiMatches && bidiMatches.length > 0) {
      techniques.push({
        type: 'bidi_override',
        count: bidiMatches.length,
        severity: 'high',
        description: `${bidiMatches.length} bidirectional override character(s) found. Text direction may be manipulated to hide content.`
      });
      cleaned = cleaned.replace(STEGO_PATTERNS.bidi_override, '');
    }

    // Check for invisible characters
    const invisibleMatches = text.match(STEGO_PATTERNS.invisible_chars);
    if (invisibleMatches && invisibleMatches.length > 3) {
      techniques.push({
        type: 'invisible_chars',
        count: invisibleMatches.length,
        severity: 'medium',
        description: `${invisibleMatches.length} invisible Unicode characters found. May encode hidden messages.`
      });
      cleaned = cleaned.replace(STEGO_PATTERNS.invisible_chars, '');
    }

    // Check for suspicious whitespace patterns (potential binary encoding)
    const words = text.split(/\S+/);
    const spaceCounts = words.map(w => w.length).filter(l => l > 0);
    if (spaceCounts.length > 10) {
      const uniqueSpacings = new Set(spaceCounts);
      // Binary encoding would show exactly 2 space widths
      if (uniqueSpacings.size === 2 && spaceCounts.length > 20) {
        techniques.push({
          type: 'whitespace_binary',
          severity: 'high',
          description: 'Suspicious binary whitespace pattern detected. Spaces may encode hidden data.'
        });
      }
    }

    // Check for Unicode tag characters
    const tagMatches = text.match(STEGO_PATTERNS.tag_characters);
    if (tagMatches && tagMatches.length > 0) {
      techniques.push({
        type: 'tag_characters',
        count: tagMatches.length,
        severity: 'critical',
        description: `${tagMatches.length} Unicode tag character(s) found. These can encode entire hidden messages.`
      });
      cleaned = cleaned.replace(STEGO_PATTERNS.tag_characters, '');
    }

    // After cleaning, re-scan for injections that were hidden
    if (techniques.length > 0 && cleaned !== text) {
      const cleanedResult = scanText(cleaned, { source: 'stego_cleaned', sensitivity: 'high' });
      if (cleanedResult.threats.length > 0) {
        techniques.push({
          type: 'hidden_injection',
          severity: 'critical',
          description: 'After removing steganographic characters, injection patterns were revealed.',
          hiddenThreats: cleanedResult.threats
        });
      }
    }

    if (techniques.length > 0 && this.onDetection) {
      this.onDetection({ techniques, timestamp: Date.now() });
    }

    return { found: techniques.length > 0, techniques, cleaned };
  }
}

// =========================================================================
// ENCODING BRUTEFORCE DETECTOR
// =========================================================================

class EncodingBruteforceDetector {
  /**
   * Detects rapid-fire attempts with different encodings.
   *
   * @param {object} [options]
   * @param {number} [options.windowMs=60000] - Time window.
   * @param {number} [options.threshold=5] - Number of encoded inputs to flag as bruteforce.
   * @param {Function} [options.onDetection] - Callback on bruteforce detected.
   */
  constructor(options = {}) {
    this.windowMs = options.windowMs || 60000;
    this.threshold = options.threshold || 5;
    this.onDetection = options.onDetection || null;
    this.encodedInputs = [];
  }

  /**
   * Checks an input for encoding and tracks frequency.
   *
   * @param {string} text
   * @returns {object} { encoded: boolean, encodingType: string|null, bruteforce: boolean, count: number }
   */
  check(text) {
    if (!text) return { encoded: false, encodingType: null, bruteforce: false, count: 0 };

    const encoding = this._detectEncoding(text);

    if (encoding) {
      const now = Date.now();
      this.encodedInputs.push({ type: encoding, timestamp: now });

      // Prune old entries
      const cutoff = now - this.windowMs;
      this.encodedInputs = this.encodedInputs.filter(e => e.timestamp > cutoff);

      const isBruteforce = this.encodedInputs.length >= this.threshold;

      if (isBruteforce && this.onDetection) {
        const typeCounts = {};
        for (const e of this.encodedInputs) {
          typeCounts[e.type] = (typeCounts[e.type] || 0) + 1;
        }
        this.onDetection({
          count: this.encodedInputs.length,
          types: typeCounts,
          timestamp: now
        });
      }

      return {
        encoded: true,
        encodingType: encoding,
        bruteforce: isBruteforce,
        count: this.encodedInputs.length
      };
    }

    return { encoded: false, encodingType: null, bruteforce: false, count: this.encodedInputs.length };
  }

  /** @private */
  _detectEncoding(text) {
    // Base64
    if (/^[A-Za-z0-9+/]{20,}={0,2}$/.test(text.trim())) return 'base64';

    // Hex encoding
    if (/^(?:0x)?[0-9a-fA-F]{20,}$/i.test(text.trim())) return 'hex';
    if (/(?:\\x[0-9a-fA-F]{2}){5,}/.test(text)) return 'hex_escape';

    // URL encoding (high density)
    const pctCount = (text.match(/%[0-9a-fA-F]{2}/g) || []).length;
    if (pctCount > 5 && pctCount / text.length > 0.1) return 'url_encoding';

    // HTML entities (high density)
    const entityCount = (text.match(/&#\w+;/g) || []).length;
    if (entityCount > 5) return 'html_entities';

    // Unicode escapes
    if (/(?:\\u[0-9a-fA-F]{4}){3,}/.test(text)) return 'unicode_escape';

    // ROT13 heuristic (text looks like garbled English)
    if (this._looksLikeRot13(text)) return 'rot13';

    // Morse code
    if (/^[\s./-]{20,}$/.test(text.trim()) && /\.{1,3}/.test(text) && /-{1,3}/.test(text)) return 'morse';

    // Binary
    if (/^[01\s]{20,}$/.test(text.trim()) && text.replace(/\s/g, '').length % 8 === 0) return 'binary';

    return null;
  }

  /** @private */
  _looksLikeRot13(text) {
    if (text.length < 20 || !/^[a-zA-Z\s.,!?]+$/.test(text)) return false;

    // Decode ROT13 and check if result has common English words
    const decoded = text.replace(/[a-zA-Z]/g, c => {
      const base = c <= 'Z' ? 65 : 97;
      return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
    });

    const commonWords = /\b(?:the|and|for|are|but|not|you|all|can|had|her|was|one|our|ignore|previous|instructions|system|forget|override)\b/i;
    return commonWords.test(decoded) && !commonWords.test(text);
  }

  reset() {
    this.encodedInputs = [];
  }
}

// =========================================================================
// STRUCTURED DATA INJECTION SCANNER
// =========================================================================

class StructuredDataScanner {
  /**
   * Scans JSON, XML, YAML, CSV, and other structured data for injections.
   *
   * @param {object} [options]
   * @param {Function} [options.onDetection] - Callback on injection found.
   */
  constructor(options = {}) {
    this.onDetection = options.onDetection || null;
  }

  /**
   * Scans a JSON object for injection patterns in string values.
   *
   * @param {object|string} data - JSON object or JSON string.
   * @param {string} [source='json_data'] - Source label.
   * @returns {object} { clean: boolean, threats: Array }
   */
  scanJSON(data, source = 'json_data') {
    let obj = data;
    if (typeof data === 'string') {
      try { obj = JSON.parse(data); } catch (e) { return { clean: true, threats: [] }; }
    }

    const strings = this._extractStrings(obj);
    return this._scanStrings(strings, source);
  }

  /**
   * Scans XML/HTML-like text for injections in attributes and content.
   *
   * @param {string} xml
   * @param {string} [source='xml_data']
   * @returns {object} { clean: boolean, threats: Array }
   */
  scanXML(xml, source = 'xml_data') {
    if (!xml) return { clean: true, threats: [] };

    const strings = [];

    // Extract attribute values
    const attrRegex = /\w+\s*=\s*["']([^"']+)["']/g;
    let match;
    while ((match = attrRegex.exec(xml)) !== null) {
      strings.push({ value: match[1], path: `attribute:${match[0].split('=')[0].trim()}` });
    }

    // Extract text content between tags
    const contentRegex = />([^<]+)</g;
    while ((match = contentRegex.exec(xml)) !== null) {
      const text = match[1].trim();
      if (text.length > 5) {
        strings.push({ value: text, path: 'text_content' });
      }
    }

    // Extract CDATA sections
    const cdataRegex = /<!\[CDATA\[([\s\S]*?)\]\]>/g;
    while ((match = cdataRegex.exec(xml)) !== null) {
      strings.push({ value: match[1], path: 'cdata' });
    }

    return this._scanStrings(strings, source);
  }

  /**
   * Scans CSV data for injections.
   *
   * @param {string} csv
   * @param {string} [source='csv_data']
   * @returns {object} { clean: boolean, threats: Array }
   */
  scanCSV(csv, source = 'csv_data') {
    if (!csv) return { clean: true, threats: [] };

    const strings = [];
    const lines = csv.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const cells = lines[i].split(',').map(c => c.trim().replace(/^["']|["']$/g, ''));
      for (let j = 0; j < cells.length; j++) {
        if (cells[j].length > 5) {
          strings.push({ value: cells[j], path: `row${i + 1}:col${j + 1}` });
        }
      }
    }

    return this._scanStrings(strings, source);
  }

  /**
   * Scans Markdown for injections in various elements.
   *
   * @param {string} markdown
   * @param {string} [source='markdown']
   * @returns {object} { clean: boolean, threats: Array }
   */
  scanMarkdown(markdown, source = 'markdown') {
    if (!markdown) return { clean: true, threats: [] };

    // Scan the full markdown text
    const result = scanText(markdown, { source, sensitivity: 'high' });

    // Additionally check for suspicious elements
    const strings = [];

    // Link text and URLs
    const linkRegex = /\[([^\]]*)\]\(([^)]*)\)/g;
    let match;
    while ((match = linkRegex.exec(markdown)) !== null) {
      strings.push({ value: match[1], path: 'link_text' });
      strings.push({ value: match[2], path: 'link_url' });
    }

    // Image alt text
    const imgRegex = /!\[([^\]]*)\]\(([^)]*)\)/g;
    while ((match = imgRegex.exec(markdown)) !== null) {
      strings.push({ value: match[1], path: 'image_alt' });
    }

    // HTML comments in markdown
    const commentRegex = /<!--([\s\S]*?)-->/g;
    while ((match = commentRegex.exec(markdown)) !== null) {
      strings.push({ value: match[1], path: 'html_comment' });
    }

    const structuredResult = this._scanStrings(strings, source);

    return {
      clean: result.threats.length === 0 && structuredResult.clean,
      threats: [...result.threats, ...structuredResult.threats]
    };
  }

  /** @private */
  _extractStrings(obj, path = '', depth = 0) {
    const strings = [];
    if (depth > 10) return strings;

    if (typeof obj === 'string' && obj.length > 5) {
      strings.push({ value: obj, path: path || 'root' });
    } else if (Array.isArray(obj)) {
      obj.forEach((item, i) => {
        strings.push(...this._extractStrings(item, `${path}[${i}]`, depth + 1));
      });
    } else if (obj && typeof obj === 'object') {
      for (const [key, value] of Object.entries(obj)) {
        strings.push(...this._extractStrings(value, path ? `${path}.${key}` : key, depth + 1));
      }
    }

    return strings;
  }

  /** @private */
  _scanStrings(strings, source) {
    const threats = [];

    for (const { value, path } of strings) {
      const result = scanText(value, { source: `${source}:${path}`, sensitivity: 'high' });
      if (result.threats.length > 0) {
        threats.push(...result.threats.map(t => ({
          ...t,
          dataPath: path,
          description: `${t.description} (found in structured data at ${path})`
        })));
      }
    }

    if (threats.length > 0 && this.onDetection) {
      this.onDetection({ threats, source, timestamp: Date.now() });
    }

    return { clean: threats.length === 0, threats };
  }
}

module.exports = {
  SteganographyDetector,
  EncodingBruteforceDetector,
  StructuredDataScanner,
  STEGO_PATTERNS
};
