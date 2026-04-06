'use strict';

/**
 * Agent Shield — Render Differential Analyzer
 *
 * Detects content that renders differently than it reads — visual deception
 * attacks where attackers hide malicious instructions in LaTeX, Markdown,
 * HTML, or other markup that looks benign in raw text but renders as
 * something dangerous.
 *
 * All processing runs locally — no data ever leaves your environment.
 */

const crypto = require('crypto');

// =========================================================================
// Constants
// =========================================================================

const SEVERITY = Object.freeze({
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low'
});

// =========================================================================
// Markdown deception patterns
// =========================================================================

const MARKDOWN_PATTERNS = [
  // HTML tags that hide content in markdown rendering
  {
    regex: /<span[^>]*style\s*=\s*["'][^"']*(?:display\s*:\s*none|font-size\s*:\s*0|visibility\s*:\s*hidden|opacity\s*:\s*0)[^"']*["'][^>]*>[\s\S]*?<\/span>/gi,
    type: 'markdown_hidden_span',
    description: 'Hidden content via inline HTML span with concealing CSS',
    severity: SEVERITY.CRITICAL
  },
  {
    regex: /<div[^>]*style\s*=\s*["'][^"']*(?:display\s*:\s*none|font-size\s*:\s*0|visibility\s*:\s*hidden|opacity\s*:\s*0)[^"']*["'][^>]*>[\s\S]*?<\/div>/gi,
    type: 'markdown_hidden_div',
    description: 'Hidden content via inline HTML div with concealing CSS',
    severity: SEVERITY.CRITICAL
  },
  // Links where display text differs substantially from URL
  {
    regex: /\[([^\]]+)\]\(([^)]+)\)/g,
    type: 'markdown_deceptive_link',
    description: 'Link display text differs from URL target',
    severity: SEVERITY.HIGH,
    validator: (match, displayText, url) => {
      // Flag if display text looks like a URL but differs from actual URL
      const displayLooksLikeUrl = /^https?:\/\//.test(displayText.trim());
      if (!displayLooksLikeUrl) return false;
      const displayDomain = extractDomain(displayText.trim());
      const urlDomain = extractDomain(url.trim());
      return displayDomain && urlDomain && displayDomain !== urlDomain;
    }
  },
  // Image alt text with injection payload
  {
    regex: /!\[([^\]]{50,})\]\([^)]*\)/g,
    type: 'markdown_image_alt_injection',
    description: 'Suspiciously long image alt text may contain injected instructions',
    severity: SEVERITY.MEDIUM,
    validator: (match, altText) => {
      const injectionHints = /(?:ignore|system|prompt|instruction|execute|eval|admin|override)/i;
      return injectionHints.test(altText);
    }
  },
  // HTML comments hiding content
  {
    regex: /<!--[\s\S]*?-->/g,
    type: 'markdown_comment_hiding',
    description: 'HTML comment may hide instructions invisible when rendered',
    severity: SEVERITY.MEDIUM,
    validator: (match) => {
      const content = match.replace(/^<!--/, '').replace(/-->$/, '').trim();
      if (content.length < 10) return false;
      const injectionHints = /(?:ignore|system|prompt|instruction|execute|override|inject|admin)/i;
      return injectionHints.test(content);
    }
  },
  // Zero-width characters in markdown
  {
    regex: /[\u200B\u200C\u200D\u2060\uFEFF]{2,}/g,
    type: 'markdown_zero_width',
    description: 'Zero-width characters hiding content between visible text',
    severity: SEVERITY.HIGH
  },
  // Tiny text via HTML sup/sub abuse with small font
  {
    regex: /<(?:sup|sub)[^>]*style\s*=\s*["'][^"']*font-size\s*:\s*(?:0|1px|0\.[\d]+px)[^"']*["'][^>]*>[\s\S]*?<\/(?:sup|sub)>/gi,
    type: 'markdown_tiny_text',
    description: 'Extremely small text hidden via HTML sup/sub tags',
    severity: SEVERITY.HIGH
  }
];

// =========================================================================
// HTML deception patterns
// =========================================================================

const HTML_PATTERNS = [
  // display:none with content
  {
    regex: /<[^>]+style\s*=\s*["'][^"']*display\s*:\s*none[^"']*["'][^>]*>([\s\S]*?)<\/[^>]+>/gi,
    type: 'html_display_none',
    description: 'Content hidden with CSS display:none',
    severity: SEVERITY.CRITICAL,
    validator: (_match, content) => content && content.trim().length > 0
  },
  // font-size:0 hiding
  {
    regex: /<[^>]+style\s*=\s*["'][^"']*font-size\s*:\s*0(?:px|em|rem|%)?\s*[;"'][^>]*>([\s\S]*?)<\/[^>]+>/gi,
    type: 'html_zero_font',
    description: 'Content hidden with zero-size font',
    severity: SEVERITY.CRITICAL,
    validator: (_match, content) => content && content.trim().length > 0
  },
  // Same-color text on background
  {
    regex: /<[^>]+style\s*=\s*["'][^"']*color\s*:\s*(white|#fff(?:fff)?|rgba?\(\s*255\s*,\s*255\s*,\s*255[\s\S]*?\))[^"']*["'][^>]*>([\s\S]*?)<\/[^>]+>/gi,
    type: 'html_same_color',
    description: 'Text color matches background making content invisible',
    severity: SEVERITY.HIGH,
    validator: (_match, _color, content) => content && content.trim().length > 0
  },
  // overflow:hidden with larger content
  {
    regex: /<[^>]+style\s*=\s*["'][^"']*overflow\s*:\s*hidden[^"']*(?:height\s*:\s*0|max-height\s*:\s*0|width\s*:\s*0|max-width\s*:\s*0)[^"']*["'][^>]*>([\s\S]*?)<\/[^>]+>/gi,
    type: 'html_overflow_hidden',
    description: 'Content hidden via overflow:hidden with zero dimensions',
    severity: SEVERITY.HIGH,
    validator: (_match, content) => content && content.trim().length > 0
  },
  // position:absolute off-screen
  {
    regex: /<[^>]+style\s*=\s*["'][^"']*position\s*:\s*(?:absolute|fixed)[^"']*(?:left\s*:\s*-\d{3,}|top\s*:\s*-\d{3,}|right\s*:\s*-\d{3,})[^"']*["'][^>]*>([\s\S]*?)<\/[^>]+>/gi,
    type: 'html_offscreen',
    description: 'Content positioned off-screen with absolute/fixed positioning',
    severity: SEVERITY.HIGH,
    validator: (_match, content) => content && content.trim().length > 0
  },
  // opacity:0 hiding
  {
    regex: /<[^>]+style\s*=\s*["'][^"']*opacity\s*:\s*0[^"']*["'][^>]*>([\s\S]*?)<\/[^>]+>/gi,
    type: 'html_opacity_zero',
    description: 'Content hidden with opacity:0',
    severity: SEVERITY.CRITICAL,
    validator: (_match, content) => content && content.trim().length > 0
  },
  // visibility:hidden
  {
    regex: /<[^>]+style\s*=\s*["'][^"']*visibility\s*:\s*hidden[^"']*["'][^>]*>([\s\S]*?)<\/[^>]+>/gi,
    type: 'html_visibility_hidden',
    description: 'Content hidden with visibility:hidden',
    severity: SEVERITY.CRITICAL,
    validator: (_match, content) => content && content.trim().length > 0
  },
  // Script tags (always suspicious in agent context)
  {
    regex: /<script[^>]*>[\s\S]*?<\/script>/gi,
    type: 'html_script_tag',
    description: 'Script tag with executable content',
    severity: SEVERITY.CRITICAL
  }
];

// =========================================================================
// LaTeX deception patterns
// =========================================================================

const LATEX_PATTERNS = [
  // \phantom — takes space but invisible
  {
    regex: /\\phantom\{([^}]+)\}/g,
    type: 'latex_phantom',
    description: 'Content hidden with \\phantom (invisible but takes space)',
    severity: SEVERITY.HIGH
  },
  // \hphantom — horizontal phantom
  {
    regex: /\\hphantom\{([^}]+)\}/g,
    type: 'latex_hphantom',
    description: 'Content hidden with \\hphantom (horizontal invisible space)',
    severity: SEVERITY.HIGH
  },
  // \vphantom — vertical phantom
  {
    regex: /\\vphantom\{([^}]+)\}/g,
    type: 'latex_vphantom',
    description: 'Content hidden with \\vphantom (vertical invisible space)',
    severity: SEVERITY.HIGH
  },
  // \textcolor{white} — white text on white background
  {
    regex: /\\textcolor\{white\}\{([^}]+)\}/g,
    type: 'latex_white_text',
    description: 'White text on assumed white background (invisible)',
    severity: SEVERITY.CRITICAL
  },
  // \color{white} variant
  {
    regex: /\{\\color\{white\}([^}]*)\}/g,
    type: 'latex_color_white',
    description: 'White-colored text block (invisible on white background)',
    severity: SEVERITY.CRITICAL
  },
  // \tiny followed by suspicious content
  {
    regex: /\\tiny\s*\{?([^}]{10,})\}?/g,
    type: 'latex_tiny_injection',
    description: 'Extremely small text that may contain hidden instructions',
    severity: SEVERITY.MEDIUM,
    validator: (_match, content) => {
      const injectionHints = /(?:ignore|system|prompt|instruction|execute|override|inject|admin)/i;
      return injectionHints.test(content);
    }
  },
  // \renewcommand overrides
  {
    regex: /\\renewcommand\{\\([a-zA-Z]+)\}/g,
    type: 'latex_renewcommand',
    description: 'Command redefinition may alter rendering behavior',
    severity: SEVERITY.HIGH
  },
  // \input / \include of external files
  {
    regex: /\\(?:input|include)\{([^}]+)\}/g,
    type: 'latex_external_input',
    description: 'External file inclusion may inject hidden content',
    severity: SEVERITY.CRITICAL
  },
  // \newcommand defining hidden payloads
  {
    regex: /\\newcommand\{\\([a-zA-Z]+)\}(?:\[\d+\])?\{([^}]*(?:ignore|system|prompt|instruction|execute|override)[^}]*)\}/gi,
    type: 'latex_newcommand_payload',
    description: 'New command definition containing suspicious payload',
    severity: SEVERITY.CRITICAL
  },
  // LaTeX comment-based hiding
  {
    regex: /(?:^|\n)\s*%[^\n]*(?:ignore|system|prompt|instruction|execute|override)[^\n]*/gi,
    type: 'latex_comment_injection',
    description: 'LaTeX comment containing suspicious instructions',
    severity: SEVERITY.MEDIUM
  }
];

// =========================================================================
// Utility functions
// =========================================================================

/**
 * Extract domain from a URL string.
 * @private
 * @param {string} url
 * @returns {string|null}
 */
function extractDomain(url) {
  try {
    const match = url.match(/^https?:\/\/([^/]+)/i);
    return match ? match[1].toLowerCase() : null;
  } catch (_) {
    return null;
  }
}

/**
 * Run a set of patterns against text and collect findings.
 * @private
 * @param {string} text
 * @param {Array} patterns
 * @returns {Array<object>} techniques found
 */
function runPatterns(text, patterns) {
  const techniques = [];

  for (const pattern of patterns) {
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
    let match;

    while ((match = regex.exec(text)) !== null) {
      // If pattern has a validator, call it
      if (pattern.validator) {
        if (!pattern.validator(...match)) continue;
      }

      techniques.push({
        type: pattern.type,
        description: pattern.description,
        severity: pattern.severity,
        location: `offset ${match.index}, length ${match[0].length}`
      });
    }
  }

  return techniques;
}

/**
 * Detect the format of content by inspecting its structure.
 * @private
 * @param {string} content
 * @returns {'markdown'|'html'|'latex'}
 */
function detectFormat(content) {
  if (!content) return 'markdown';

  // LaTeX indicators
  const latexScore = (content.match(/\\(?:begin|end|documentclass|usepackage|section|textcolor|phantom|newcommand|renewcommand|input|include)\b/g) || []).length;
  // HTML indicators
  const htmlScore = (content.match(/<(?:html|head|body|div|span|script|style|p|a|img)\b/gi) || []).length;
  // Markdown indicators
  const mdScore = (content.match(/(?:^#{1,6}\s|^\*\s|^-\s|^\d+\.\s|\[.*\]\(.*\)|!\[.*\]\(.*\)|```)/gm) || []).length;

  if (latexScore > htmlScore && latexScore > mdScore) return 'latex';
  if (htmlScore > mdScore) return 'html';
  return 'markdown';
}

/**
 * Strip all formatting/hidden content to approximate visible rendering.
 * @private
 * @param {string} content
 * @param {string} format
 * @returns {string}
 */
function stripToVisible(content, format) {
  if (!content) return '';

  let visible = content;

  if (format === 'html' || format === 'markdown') {
    // Remove HTML comments
    visible = visible.replace(/<!--[\s\S]*?-->/g, '');
    // Remove content in display:none, opacity:0, visibility:hidden, font-size:0
    visible = visible.replace(/<[^>]+style\s*=\s*["'][^"']*(?:display\s*:\s*none|opacity\s*:\s*0|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px)?)[^"']*["'][^>]*>[\s\S]*?<\/[^>]+>/gi, '');
    // Remove script tags
    visible = visible.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '');
    // Remove style tags
    visible = visible.replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '');
    // Remove off-screen positioned content
    visible = visible.replace(/<[^>]+style\s*=\s*["'][^"']*position\s*:\s*(?:absolute|fixed)[^"']*(?:left|top|right)\s*:\s*-\d{3,}[^"']*["'][^>]*>[\s\S]*?<\/[^>]+>/gi, '');
    // Remove overflow:hidden zero-dimension content
    visible = visible.replace(/<[^>]+style\s*=\s*["'][^"']*overflow\s*:\s*hidden[^"']*(?:height|width|max-height|max-width)\s*:\s*0[^"']*["'][^>]*>[\s\S]*?<\/[^>]+>/gi, '');
    // Strip remaining HTML tags
    visible = visible.replace(/<[^>]+>/g, '');
  }

  if (format === 'markdown') {
    // Remove zero-width characters
    visible = visible.replace(/[\u200B\u200C\u200D\u2060\uFEFF]/g, '');
    // Strip markdown link syntax, keep display text
    visible = visible.replace(/\[([^\]]*)\]\([^)]*\)/g, '$1');
    // Strip image syntax, keep alt text
    visible = visible.replace(/!\[([^\]]*)\]\([^)]*\)/g, '$1');
  }

  if (format === 'latex') {
    // Remove comments
    visible = visible.replace(/(?:^|\n)\s*%[^\n]*/g, '\n');
    // Remove phantom content (invisible)
    visible = visible.replace(/\\(?:phantom|hphantom|vphantom)\{[^}]*\}/g, '');
    // Remove white-colored text
    visible = visible.replace(/\\textcolor\{white\}\{[^}]*\}/g, '');
    visible = visible.replace(/\{\\color\{white\}[^}]*\}/g, '');
    // Remove tiny text
    visible = visible.replace(/\\tiny\s*\{([^}]*)\}/g, '');
    // Flatten commands
    visible = visible.replace(/\\(?:textbf|textit|emph|underline|texttt)\{([^}]*)\}/g, '$1');
    // Remove \input/\include
    visible = visible.replace(/\\(?:input|include)\{[^}]*\}/g, '');
    // Remove \newcommand/\renewcommand definitions
    visible = visible.replace(/\\(?:newcommand|renewcommand)\{[^}]*\}(?:\[\d+\])?\{[^}]*\}/g, '');
    // Remove remaining LaTeX commands
    visible = visible.replace(/\\[a-zA-Z]+(?:\{[^}]*\})?/g, '');
    // Remove braces
    visible = visible.replace(/[{}]/g, '');
  }

  // Normalize whitespace
  visible = visible.replace(/\s+/g, ' ').trim();
  return visible;
}

/**
 * Simple hash using crypto for consistent hashing.
 * @private
 * @param {string} text
 * @returns {string}
 */
function simpleHash(text) {
  return crypto.createHash('sha256').update(text || '').digest('hex').slice(0, 16);
}

/**
 * Compute character-level similarity between two strings (0-1).
 * @private
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
function charSimilarity(a, b) {
  if (!a && !b) return 1;
  if (!a || !b) return 0;
  if (a === b) return 1;

  const maxLen = Math.max(a.length, b.length);
  if (maxLen === 0) return 1;

  // Simple character-level diff: count matching chars at corresponding positions
  const minLen = Math.min(a.length, b.length);
  let matches = 0;
  for (let i = 0; i < minLen; i++) {
    if (a[i] === b[i]) matches++;
  }

  // Length difference penalty
  const lengthPenalty = 1 - (Math.abs(a.length - b.length) / maxLen);
  const posMatch = minLen > 0 ? matches / minLen : 0;

  return posMatch * lengthPenalty;
}

// =========================================================================
// RenderDifferentialAnalyzer
// =========================================================================

/**
 * Analyzes content for visual deception attacks where rendered output
 * differs from raw text — detecting hidden instructions in Markdown,
 * HTML, and LaTeX.
 */
class RenderDifferentialAnalyzer {
  /**
   * @param {object} [options]
   * @param {Function} [options.onDetection] - Callback when deception found.
   */
  constructor(options = {}) {
    this.onDetection = options.onDetection || null;
    console.log('[Agent Shield] RenderDifferentialAnalyzer initialized');
  }

  /**
   * Analyze Markdown content for visual deception techniques.
   *
   * @param {string} text - Raw markdown content.
   * @returns {{ deceptive: boolean, techniques: Array<{ type: string, description: string, severity: string, location: string }> }}
   */
  analyzeMarkdown(text) {
    if (!text || typeof text !== 'string') {
      return { deceptive: false, techniques: [] };
    }

    const techniques = runPatterns(text, MARKDOWN_PATTERNS);

    if (techniques.length > 0 && this.onDetection) {
      this.onDetection({ format: 'markdown', techniques });
    }

    return {
      deceptive: techniques.length > 0,
      techniques
    };
  }

  /**
   * Analyze HTML content for rendering deception techniques.
   *
   * @param {string} html - Raw HTML content.
   * @returns {{ deceptive: boolean, techniques: Array<{ type: string, description: string, severity: string, location: string }> }}
   */
  analyzeHTML(html) {
    if (!html || typeof html !== 'string') {
      return { deceptive: false, techniques: [] };
    }

    const techniques = runPatterns(html, HTML_PATTERNS);

    if (techniques.length > 0 && this.onDetection) {
      this.onDetection({ format: 'html', techniques });
    }

    return {
      deceptive: techniques.length > 0,
      techniques
    };
  }

  /**
   * Analyze LaTeX content for visual deception techniques.
   *
   * @param {string} tex - Raw LaTeX content.
   * @returns {{ deceptive: boolean, techniques: Array<{ type: string, description: string, severity: string, location: string }> }}
   */
  analyzeLatex(tex) {
    if (!tex || typeof tex !== 'string') {
      return { deceptive: false, techniques: [] };
    }

    const techniques = runPatterns(tex, LATEX_PATTERNS);

    if (techniques.length > 0 && this.onDetection) {
      this.onDetection({ format: 'latex', techniques });
    }

    return {
      deceptive: techniques.length > 0,
      techniques
    };
  }

  /**
   * Unified scanner that auto-detects format or uses the specified one.
   *
   * @param {string} content - Content to scan.
   * @param {'markdown'|'html'|'latex'|'auto'} [format='auto'] - Content format.
   * @returns {{ deceptive: boolean, techniques: Array<{ type: string, description: string, severity: string, location: string }>, format: string }}
   */
  scan(content, format = 'auto') {
    if (!content || typeof content !== 'string') {
      return { deceptive: false, techniques: [], format: format === 'auto' ? 'unknown' : format };
    }

    const detectedFormat = format === 'auto' ? detectFormat(content) : format;
    let result;

    switch (detectedFormat) {
      case 'html':
        result = this.analyzeHTML(content);
        break;
      case 'latex':
        result = this.analyzeLatex(content);
        break;
      case 'markdown':
      default:
        result = this.analyzeMarkdown(content);
        break;
    }

    return {
      ...result,
      format: detectedFormat
    };
  }
}

// =========================================================================
// VisualHasher
// =========================================================================

/**
 * Computes a "visual hash" comparing what content looks like rendered
 * versus raw. High divergence indicates hidden or deceptive content.
 */
class VisualHasher {
  /**
   * @param {object} [options]
   * @param {number} [options.divergenceThreshold=0.3] - Divergence above this is suspicious.
   */
  constructor(options = {}) {
    this.divergenceThreshold = options.divergenceThreshold || 0.3;
  }

  /**
   * Compute visual hash and divergence for content.
   *
   * @param {string} content - Raw content to analyze.
   * @param {'markdown'|'html'|'latex'|'auto'} [format='auto'] - Content format.
   * @returns {{ rawHash: string, visualHash: string, divergence: number, suspicious: boolean }}
   */
  hash(content, format = 'auto') {
    if (!content || typeof content !== 'string') {
      return { rawHash: simpleHash(''), visualHash: simpleHash(''), divergence: 0, suspicious: false };
    }

    const detectedFormat = format === 'auto' ? detectFormat(content) : format;

    // Normalize raw content (just whitespace normalization)
    const rawNormalized = content.replace(/\s+/g, ' ').trim();
    const visibleContent = stripToVisible(content, detectedFormat);

    const rawHash = simpleHash(rawNormalized);
    const visualHash = simpleHash(visibleContent);

    // Calculate divergence: 0 = identical, 1 = completely different
    const similarity = charSimilarity(rawNormalized, visibleContent);
    const divergence = Math.round((1 - similarity) * 1000) / 1000;

    return {
      rawHash,
      visualHash,
      divergence,
      suspicious: divergence > this.divergenceThreshold
    };
  }
}

// =========================================================================
// Exports
// =========================================================================

module.exports = {
  RenderDifferentialAnalyzer,
  VisualHasher
};
