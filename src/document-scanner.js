'use strict';

/**
 * Agent Shield — Document Scanner
 *
 * Extracts text from various file formats and scans for threats,
 * with a focus on detecting indirect prompt injection attacks hidden
 * inside documents uploaded to AI agents.
 *
 * All detection runs locally — no data ever leaves your environment.
 */

const fs = require('fs');
const path = require('path');
const { scanText, SEVERITY_ORDER } = require('./detector-core');

// =========================================================================
// TEXT EXTRACTOR
// =========================================================================

/**
 * Extracts plain text from common file formats using only Node.js built-ins.
 * No external dependencies required.
 */
class TextExtractor {
  /**
   * Extract text from a plain text file buffer.
   * @param {Buffer} buffer - The file contents.
   * @returns {string} The extracted text.
   */
  static extractFromPlainText(buffer) {
    return buffer.toString('utf-8');
  }

  /**
   * Extract text from an HTML buffer by stripping tags and decoding entities.
   * @param {Buffer} buffer - The HTML file contents.
   * @returns {string} The extracted text.
   */
  static extractFromHTML(buffer) {
    let html = buffer.toString('utf-8');

    // Remove script and style blocks entirely
    html = html.replace(/<script[\s\S]*?<\/script>/gi, ' ');
    html = html.replace(/<style[\s\S]*?<\/style>/gi, ' ');

    // Remove HTML comments
    html = html.replace(/<!--[\s\S]*?-->/g, ' ');

    // Extract alt text from images (important for injection detection)
    html = html.replace(/<img[^>]*alt\s*=\s*"([^"]*)"[^>]*>/gi, ' $1 ');
    html = html.replace(/<img[^>]*alt\s*=\s*'([^']*)'[^>]*>/gi, ' $1 ');

    // Strip all remaining HTML tags
    html = html.replace(/<[^>]+>/g, ' ');

    // Decode common HTML entities
    const entities = {
      '&amp;': '&',
      '&lt;': '<',
      '&gt;': '>',
      '&quot;': '"',
      '&#39;': "'",
      '&apos;': "'",
      '&nbsp;': ' ',
      '&#x2F;': '/',
      '&#x27;': "'",
      '&hellip;': '...',
      '&mdash;': '—',
      '&ndash;': '–',
      '&copy;': '(c)',
      '&reg;': '(R)',
      '&trade;': '(TM)'
    };
    for (const [entity, replacement] of Object.entries(entities)) {
      html = html.split(entity).join(replacement);
    }

    // Decode numeric HTML entities
    html = html.replace(/&#(\d+);/g, (_, code) => {
      return String.fromCharCode(parseInt(code, 10));
    });
    html = html.replace(/&#x([0-9a-fA-F]+);/g, (_, code) => {
      return String.fromCharCode(parseInt(code, 16));
    });

    // Collapse whitespace
    html = html.replace(/\s+/g, ' ').trim();

    return html;
  }

  /**
   * Extract text from a CSV buffer by parsing rows and joining cell values.
   * @param {Buffer} buffer - The CSV file contents.
   * @returns {string} The extracted text.
   */
  static extractFromCSV(buffer) {
    const text = buffer.toString('utf-8');
    const lines = text.split(/\r?\n/);
    const cells = [];

    for (const line of lines) {
      if (!line.trim()) continue;

      // Basic CSV parsing: handle quoted fields
      let current = '';
      let inQuotes = false;
      for (let i = 0; i < line.length; i++) {
        const ch = line[i];
        if (ch === '"') {
          if (inQuotes && line[i + 1] === '"') {
            current += '"';
            i++;
          } else {
            inQuotes = !inQuotes;
          }
        } else if (ch === ',' && !inQuotes) {
          cells.push(current.trim());
          current = '';
        } else {
          current += ch;
        }
      }
      cells.push(current.trim());
    }

    return cells.filter(c => c.length > 0).join(' ');
  }

  /**
   * Extract all string values from a JSON buffer recursively.
   * @param {Buffer} buffer - The JSON file contents.
   * @returns {string} All string values concatenated.
   */
  static extractFromJSON(buffer) {
    const text = buffer.toString('utf-8');
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch (e) {
      // If invalid JSON, return raw text
      return text;
    }

    const strings = [];
    const extract = (value) => {
      if (typeof value === 'string') {
        strings.push(value);
      } else if (Array.isArray(value)) {
        for (const item of value) {
          extract(item);
        }
      } else if (value !== null && typeof value === 'object') {
        for (const key of Object.keys(value)) {
          strings.push(key);
          extract(value[key]);
        }
      }
    };
    extract(parsed);

    return strings.join(' ');
  }

  /**
   * Extract text from a Markdown buffer by stripping formatting.
   * @param {Buffer} buffer - The Markdown file contents.
   * @returns {string} The extracted text.
   */
  static extractFromMarkdown(buffer) {
    let md = buffer.toString('utf-8');

    // Remove code blocks
    md = md.replace(/```[\s\S]*?```/g, ' ');
    md = md.replace(/`[^`]+`/g, ' ');

    // Remove images but keep alt text
    md = md.replace(/!\[([^\]]*)\]\([^)]*\)/g, ' $1 ');

    // Remove links but keep text
    md = md.replace(/\[([^\]]*)\]\([^)]*\)/g, ' $1 ');

    // Remove headings markers
    md = md.replace(/^#{1,6}\s+/gm, '');

    // Remove bold/italic markers
    md = md.replace(/\*\*([^*]+)\*\*/g, '$1');
    md = md.replace(/\*([^*]+)\*/g, '$1');
    md = md.replace(/__([^_]+)__/g, '$1');
    md = md.replace(/_([^_]+)_/g, '$1');
    md = md.replace(/~~([^~]+)~~/g, '$1');

    // Remove blockquote markers
    md = md.replace(/^>\s+/gm, '');

    // Remove horizontal rules
    md = md.replace(/^[-*_]{3,}\s*$/gm, '');

    // Remove list markers
    md = md.replace(/^[\s]*[-*+]\s+/gm, '');
    md = md.replace(/^[\s]*\d+\.\s+/gm, '');

    // Remove HTML tags that might be embedded
    md = md.replace(/<[^>]+>/g, ' ');

    // Collapse whitespace
    md = md.replace(/\s+/g, ' ').trim();

    return md;
  }

  /**
   * Extract text from an XML buffer by stripping tags.
   * @param {Buffer} buffer - The XML file contents.
   * @returns {string} The extracted text.
   */
  static extractFromXML(buffer) {
    let xml = buffer.toString('utf-8');

    // Remove XML declarations and processing instructions
    xml = xml.replace(/<\?[\s\S]*?\?>/g, '');

    // Remove CDATA wrappers but keep content
    xml = xml.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1');

    // Remove comments
    xml = xml.replace(/<!--[\s\S]*?-->/g, ' ');

    // Strip all XML tags
    xml = xml.replace(/<[^>]+>/g, ' ');

    // Decode common XML entities
    xml = xml.replace(/&amp;/g, '&');
    xml = xml.replace(/&lt;/g, '<');
    xml = xml.replace(/&gt;/g, '>');
    xml = xml.replace(/&quot;/g, '"');
    xml = xml.replace(/&apos;/g, "'");

    // Collapse whitespace
    xml = xml.replace(/\s+/g, ' ').trim();

    return xml;
  }

  /**
   * Detect the file type from buffer content using basic heuristics.
   * @param {Buffer} buffer - The file contents.
   * @returns {string} The detected MIME type.
   */
  static detect(buffer) {
    if (!buffer || buffer.length === 0) {
      return 'application/octet-stream';
    }

    const head = buffer.slice(0, 512).toString('utf-8').trimStart();

    // JSON: starts with { or [
    if (head.startsWith('{') || head.startsWith('[')) {
      return 'application/json';
    }

    // XML: starts with <?xml or <!DOCTYPE ... xml
    if (head.startsWith('<?xml') || /^<!DOCTYPE\s+[^>]*xml/i.test(head)) {
      return 'application/xml';
    }

    // HTML: starts with <!DOCTYPE html or <html
    if (/^<!DOCTYPE\s+html/i.test(head) || /^<html[\s>]/i.test(head)) {
      return 'text/html';
    }

    // Generic tag-based: if it starts with < it might be XML or HTML
    if (head.startsWith('<')) {
      // Look for html-like tags
      if (/<(?:div|span|p|body|head|table|form|input|a\s)/i.test(head)) {
        return 'text/html';
      }
      return 'application/xml';
    }

    // CSV: multiple lines with commas and consistent column counts
    const lines = head.split(/\r?\n/).filter(l => l.trim());
    if (lines.length >= 2) {
      const commaCount0 = (lines[0].match(/,/g) || []).length;
      const commaCount1 = (lines[1].match(/,/g) || []).length;
      if (commaCount0 > 0 && commaCount0 === commaCount1) {
        return 'text/csv';
      }
    }

    // Markdown: check for common markers
    if (/^#{1,6}\s/.test(head) || /^\s*[-*+]\s/.test(head) || /\[.*\]\(.*\)/.test(head)) {
      return 'text/markdown';
    }

    // Default to plain text
    return 'text/plain';
  }
}

// =========================================================================
// MIME TYPE TO EXTRACTOR MAPPING
// =========================================================================

const EXTRACTORS = {
  'text/plain': TextExtractor.extractFromPlainText,
  'text/html': TextExtractor.extractFromHTML,
  'text/csv': TextExtractor.extractFromCSV,
  'application/json': TextExtractor.extractFromJSON,
  'text/markdown': TextExtractor.extractFromMarkdown,
  'application/xml': TextExtractor.extractFromXML,
  'text/xml': TextExtractor.extractFromXML
};

const SUPPORTED_TYPES = Object.keys(EXTRACTORS);

// =========================================================================
// INDIRECT INJECTION SCANNER
// =========================================================================

/**
 * Scans text extracted from documents for indirect prompt injection attacks.
 * These are attacks where malicious instructions are hidden inside documents
 * that an AI agent will process.
 */
class IndirectInjectionScanner {
  /**
   * Create an IndirectInjectionScanner.
   * @param {Object} [options={}] - Scanner options.
   * @param {string} [options.sensitivity='medium'] - Detection sensitivity.
   */
  constructor(options = {}) {
    this.sensitivity = options.sensitivity || 'medium';
  }

  /**
   * Scan extracted text for indirect prompt injection patterns.
   * @param {string} text - The extracted text to scan.
   * @param {string} [source='document'] - The source description.
   * @returns {{ threats: Array, hiddenContent: Array, riskScore: number }}
   */
  scan(text, source = 'document') {
    const threats = [];
    const hiddenContent = [];
    let riskScore = 0;

    if (!text || text.trim().length === 0) {
      return { threats, hiddenContent, riskScore };
    }

    // 1. Check for hidden instructions disguised as data
    const instructionPatterns = [
      {
        regex: /(?:SYSTEM|ADMIN|ASSISTANT|AI)\s*:\s*.{10,}/gi,
        description: 'Role-prefixed instructions hidden in document',
        severity: 'high'
      },
      {
        regex: /(?:BEGIN|START)\s+(?:HIDDEN|SECRET|PRIVATE)\s+(?:INSTRUCTIONS?|COMMANDS?|SECTION)/gi,
        description: 'Hidden instruction block markers in document',
        severity: 'critical'
      },
      {
        regex: /(?:when|if)\s+(?:the\s+)?(?:AI|assistant|model|agent|you)\s+(?:reads?|processes?|sees?|parses?|receives?)\s+this/gi,
        description: 'Conditional instructions targeting AI processing',
        severity: 'high'
      },
      {
        regex: /(?:do\s+not|don'?t)\s+(?:tell|inform|reveal|mention|show)\s+(?:the\s+)?(?:user|human|person|operator)/gi,
        description: 'Instructions to hide information from the user',
        severity: 'critical'
      },
      {
        regex: /(?:you\s+are|you're)\s+(?:now|actually)\s+(?:a|an|in)\s+/gi,
        description: 'Identity reassignment attempt in document',
        severity: 'high'
      },
      {
        regex: /(?:execute|run|perform|call)\s+(?:the\s+)?(?:following|this|these)\s+(?:tool|function|command|action|code)/gi,
        description: 'Tool execution instructions hidden in document',
        severity: 'critical'
      }
    ];

    for (const pattern of instructionPatterns) {
      const matches = text.match(pattern.regex);
      if (matches) {
        for (const match of matches) {
          threats.push({
            type: 'indirect_injection',
            severity: pattern.severity,
            description: pattern.description,
            source,
            match: match.substring(0, 200)
          });
          riskScore += pattern.severity === 'critical' ? 40 : 20;
        }
      }
    }

    // 2. Check for invisible/zero-width characters (used to hide instructions)
    const invisibleChars = [
      { char: '\u200B', name: 'zero-width space' },
      { char: '\u200C', name: 'zero-width non-joiner' },
      { char: '\u200D', name: 'zero-width joiner' },
      { char: '\u2060', name: 'word joiner' },
      { char: '\uFEFF', name: 'zero-width no-break space' },
      { char: '\u00AD', name: 'soft hyphen' },
      { char: '\u200E', name: 'left-to-right mark' },
      { char: '\u200F', name: 'right-to-left mark' },
      { char: '\u2061', name: 'function application' },
      { char: '\u2062', name: 'invisible times' },
      { char: '\u2063', name: 'invisible separator' },
      { char: '\u2064', name: 'invisible plus' }
    ];

    let invisibleCount = 0;
    const foundInvisible = [];

    for (const { char, name } of invisibleChars) {
      const count = (text.split(char).length - 1);
      if (count > 0) {
        invisibleCount += count;
        foundInvisible.push({ name, count });
      }
    }

    if (invisibleCount > 5) {
      hiddenContent.push({
        type: 'invisible_characters',
        description: `Found ${invisibleCount} invisible/zero-width characters`,
        details: foundInvisible
      });

      // Try to extract hidden content by removing visible chars
      const invisibleOnly = text.replace(/[^\u200B\u200C\u200D\u2060\uFEFF]/g, '');
      if (invisibleOnly.length > 10) {
        hiddenContent.push({
          type: 'steganographic_content',
          description: 'Possible steganographic content via invisible characters',
          length: invisibleOnly.length
        });
      }

      threats.push({
        type: 'hidden_content',
        severity: 'high',
        description: `Suspicious invisible characters detected (${invisibleCount} found)`,
        source,
        details: foundInvisible
      });
      riskScore += 25;
    }

    // 3. Check for markdown rendering attacks
    const markdownAttacks = [
      {
        regex: /!\[([^\]]{50,})\]\(/g,
        description: 'Oversized image alt text (possible hidden instructions)',
        severity: 'medium'
      },
      {
        regex: /\[([^\]]*)\]\(javascript:/gi,
        description: 'JavaScript URI in markdown link',
        severity: 'high'
      },
      {
        regex: /\[([^\]]*)\]\(data:/gi,
        description: 'Data URI in markdown link',
        severity: 'medium'
      },
      {
        regex: /<!--[\s\S]{20,}?-->/g,
        description: 'Large HTML comment block (possible hidden content)',
        severity: 'medium'
      }
    ];

    for (const pattern of markdownAttacks) {
      const matches = text.match(pattern.regex);
      if (matches) {
        for (const match of matches) {
          threats.push({
            type: 'markdown_injection',
            severity: pattern.severity,
            description: pattern.description,
            source,
            match: match.substring(0, 200)
          });
          riskScore += pattern.severity === 'high' ? 15 : 10;
        }
      }
    }

    // 4. Check for text that looks like it was encoded or obfuscated
    const base64Regex = /(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g;
    const base64Matches = text.match(base64Regex);
    if (base64Matches) {
      for (const match of base64Matches) {
        try {
          const decoded = Buffer.from(match, 'base64').toString('utf-8');
          // Check if decoded text contains instruction-like content
          if (/(?:ignore|override|system|execute|admin|secret)/i.test(decoded)) {
            threats.push({
              type: 'encoded_injection',
              severity: 'high',
              description: 'Base64-encoded content contains suspicious instructions',
              source,
              decodedPreview: decoded.substring(0, 200)
            });
            riskScore += 30;
          }
        } catch (e) {
          // Not valid base64, skip
        }
      }
    }

    // Cap risk score at 100
    riskScore = Math.min(100, riskScore);

    // Filter by sensitivity
    const filteredThreats = this._filterBySensitivity(threats);

    return {
      threats: filteredThreats,
      hiddenContent,
      riskScore
    };
  }

  /**
   * Filter threats based on configured sensitivity.
   * @param {Array} threats - The threats to filter.
   * @returns {Array} Filtered threats.
   * @private
   */
  _filterBySensitivity(threats) {
    if (this.sensitivity === 'low') {
      return threats.filter(t => t.severity === 'critical' || t.severity === 'high');
    }
    if (this.sensitivity === 'medium') {
      return threats.filter(t => t.severity !== 'low');
    }
    // 'high' sensitivity = return everything
    return threats;
  }
}

// =========================================================================
// DOCUMENT SCANNER
// =========================================================================

/**
 * Scans documents for threats by extracting text and running it through
 * the Agent Shield detection engine. Designed to catch indirect prompt
 * injection attacks hidden in uploaded documents.
 */
class DocumentScanner {
  /**
   * Create a DocumentScanner.
   * @param {Object} [options={}] - Scanner options.
   * @param {string} [options.sensitivity='medium'] - Detection sensitivity ('low', 'medium', 'high').
   * @param {boolean} [options.logging=false] - Whether to log scan results.
   * @param {boolean} [options.scanForInjection=true] - Whether to run indirect injection scanning.
   */
  constructor(options = {}) {
    this.sensitivity = options.sensitivity || 'medium';
    this.logging = options.logging || false;
    this.scanForInjection = options.scanForInjection !== false;
    this.injectionScanner = new IndirectInjectionScanner({ sensitivity: this.sensitivity });
  }

  /**
   * Scan a file from disk. Reads the file, detects its type, extracts text,
   * and scans it for threats.
   * @param {string} filePath - Path to the file to scan.
   * @returns {{ fileType: string, textLength: number, threats: Array, status: string }}
   */
  scanFile(filePath) {
    const resolvedPath = path.resolve(filePath);
    const ext = path.extname(resolvedPath).toLowerCase();

    let buffer;
    try {
      buffer = fs.readFileSync(resolvedPath);
    } catch (err) {
      if (this.logging) {
        console.log(`[Agent Shield] Document scanner failed to read file: ${resolvedPath}`);
      }
      return {
        fileType: 'unknown',
        textLength: 0,
        threats: [{
          type: 'scan_error',
          severity: 'medium',
          description: `Failed to read file: ${err.message}`,
          source: resolvedPath
        }],
        status: 'caution'
      };
    }

    // Determine MIME type from extension first, fall back to content detection
    const mimeType = this._mimeFromExtension(ext) || TextExtractor.detect(buffer);

    if (this.logging) {
      console.log(`[Agent Shield] Scanning document: ${resolvedPath} (${mimeType})`);
    }

    return this.scanBuffer(buffer, mimeType, resolvedPath);
  }

  /**
   * Scan a Buffer with a known MIME type.
   * @param {Buffer} buffer - The file contents.
   * @param {string} [mimeType] - The MIME type of the file. Auto-detected if not provided.
   * @param {string} [source='buffer'] - Source description for logging.
   * @returns {{ fileType: string, textLength: number, threats: Array, status: string }}
   */
  scanBuffer(buffer, mimeType, source = 'buffer') {
    if (!Buffer.isBuffer(buffer)) {
      return {
        fileType: 'unknown',
        textLength: 0,
        threats: [{
          type: 'scan_error',
          severity: 'medium',
          description: 'Input is not a valid Buffer',
          source
        }],
        status: 'caution'
      };
    }

    // Auto-detect if no MIME type provided
    const detectedType = mimeType || TextExtractor.detect(buffer);
    const extractor = EXTRACTORS[detectedType];

    if (!extractor) {
      if (this.logging) {
        console.log(`[Agent Shield] Unsupported file type: ${detectedType}`);
      }
      return {
        fileType: detectedType,
        textLength: 0,
        threats: [],
        status: 'safe'
      };
    }

    let extractedText;
    try {
      extractedText = extractor(buffer);
    } catch (err) {
      return {
        fileType: detectedType,
        textLength: 0,
        threats: [{
          type: 'extraction_error',
          severity: 'medium',
          description: `Failed to extract text: ${err.message}`,
          source
        }],
        status: 'caution'
      };
    }

    return this.scanText(extractedText, { source, fileType: detectedType });
  }

  /**
   * Scan pre-extracted text with source metadata.
   * @param {string} text - The extracted text to scan.
   * @param {Object} [metadata={}] - Source metadata.
   * @param {string} [metadata.source='text'] - Where the text came from.
   * @param {string} [metadata.fileType='text/plain'] - The original file type.
   * @returns {{ fileType: string, textLength: number, threats: Array, status: string }}
   */
  scanText(text, metadata = {}) {
    const source = metadata.source || 'text';
    const fileType = metadata.fileType || 'text/plain';

    if (!text || text.trim().length === 0) {
      return {
        fileType,
        textLength: 0,
        threats: [],
        status: 'safe'
      };
    }

    // Run core threat detection
    const coreResult = scanText(text, {
      source: `document:${source}`,
      sensitivity: this.sensitivity
    });

    // Combine threats from core detection
    let allThreats = [...coreResult.threats];

    // Run indirect injection scanning
    if (this.scanForInjection) {
      const injectionResult = this.injectionScanner.scan(text, source);
      allThreats = allThreats.concat(injectionResult.threats);

      // Add hidden content as threats if found
      for (const hidden of injectionResult.hiddenContent) {
        allThreats.push({
          type: 'hidden_content',
          severity: 'medium',
          description: hidden.description,
          source,
          details: hidden
        });
      }
    }

    // Deduplicate threats by description
    const seen = new Set();
    allThreats = allThreats.filter(t => {
      const key = `${t.type || t.category}:${t.description}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    // Sort by severity
    allThreats.sort((a, b) => {
      const sevA = SEVERITY_ORDER[a.severity] !== undefined ? SEVERITY_ORDER[a.severity] : 3;
      const sevB = SEVERITY_ORDER[b.severity] !== undefined ? SEVERITY_ORDER[b.severity] : 3;
      return sevA - sevB;
    });

    // Determine overall status
    let status = 'safe';
    const hasCritical = allThreats.some(t => t.severity === 'critical');
    const hasHigh = allThreats.some(t => t.severity === 'high');
    const hasMedium = allThreats.some(t => t.severity === 'medium');

    if (hasCritical) status = 'danger';
    else if (hasHigh) status = 'warning';
    else if (hasMedium) status = 'caution';

    if (this.logging) {
      console.log(`[Agent Shield] Document scan complete: ${allThreats.length} threat(s), status=${status}`);
    }

    return {
      fileType,
      textLength: text.length,
      threats: allThreats,
      status
    };
  }

  /**
   * Returns the list of supported file MIME types.
   * @returns {string[]} Array of supported MIME types.
   */
  getSupportedTypes() {
    return [...SUPPORTED_TYPES];
  }

  /**
   * Map file extension to MIME type.
   * @param {string} ext - The file extension (e.g. '.html').
   * @returns {string|null} The MIME type, or null if unknown.
   * @private
   */
  _mimeFromExtension(ext) {
    const map = {
      '.txt': 'text/plain',
      '.text': 'text/plain',
      '.log': 'text/plain',
      '.html': 'text/html',
      '.htm': 'text/html',
      '.csv': 'text/csv',
      '.json': 'application/json',
      '.md': 'text/markdown',
      '.markdown': 'text/markdown',
      '.xml': 'application/xml',
      '.svg': 'application/xml',
      '.xhtml': 'text/html'
    };
    return map[ext] || null;
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = { DocumentScanner, TextExtractor, IndirectInjectionScanner };
