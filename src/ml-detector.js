'use strict';

/**
 * Agent Shield — Multimodal Content Scanner (v12)
 *
 * Scans non-text content that agents process: OCR text from images,
 * extracted PDF text, alt text, EXIF metadata, and structured data.
 *
 * All processing runs locally — no data ever leaves your environment.
 *
 * @module ml-detector
 */

const { scanText } = require('./detector-core');

/**
 * Scans multimodal content (text extracted from images, PDFs, structured data)
 * for hidden injection attacks.
 */
class MultimodalDetector {
  /**
   * @param {object} [options]
   * @param {string} [options.sensitivity='high'] - Scan sensitivity.
   */
  constructor(options = {}) {
    this.sensitivity = options.sensitivity || 'high';
    this.stats = { scanned: 0, threats: 0 };
  }

  /**
   * Scan text extracted from an image (OCR, alt text, EXIF metadata).
   * @param {string} text - Extracted image text.
   * @param {object} [metadata] - Image metadata (alt, exif, filename).
   * @returns {{ safe: boolean, threats: Array<object>, source: string }}
   */
  scanImageText(text, metadata = {}) {
    const threats = [];
    const sources = [text || ''];

    if (metadata.alt) sources.push(metadata.alt);
    if (metadata.exif) sources.push(typeof metadata.exif === 'string' ? metadata.exif : JSON.stringify(metadata.exif));
    if (metadata.filename) sources.push(metadata.filename);

    for (const source of sources) {
      if (!source || source.length < 5) continue;
      const result = scanText(source, { source: 'image_content', sensitivity: this.sensitivity });
      if (result.threats && result.threats.length > 0) {
        for (const t of result.threats) {
          threats.push({ ...t, contentSource: 'image', detail: (t.detail || '') + ' [Found in image content]' });
        }
      }
    }

    // Check for invisible text indicators
    if (text && /(?:font-?size\s*:\s*0|opacity\s*:\s*0|color\s*:\s*(?:white|#fff|rgba\(.*?0\)))/i.test(text)) {
      threats.push({
        type: 'hidden_text_in_image',
        severity: 'high',
        category: 'multimodal_injection',
        description: 'Image contains invisible/hidden text styling that may conceal injection.',
        contentSource: 'image'
      });
    }

    this.stats.scanned++;
    if (threats.length > 0) this.stats.threats++;

    return { safe: threats.length === 0, threats, source: 'image' };
  }

  /**
   * Scan text extracted from a PDF document.
   * @param {string} text - Extracted PDF text.
   * @param {object} [metadata] - PDF metadata (title, author, annotations).
   * @returns {{ safe: boolean, threats: Array<object>, source: string }}
   */
  scanPDFText(text, metadata = {}) {
    const threats = [];
    const sources = [text || ''];

    if (metadata.title) sources.push(metadata.title);
    if (metadata.author) sources.push(metadata.author);
    if (metadata.annotations) {
      for (const ann of (Array.isArray(metadata.annotations) ? metadata.annotations : [])) {
        sources.push(typeof ann === 'string' ? ann : JSON.stringify(ann));
      }
    }

    for (const source of sources) {
      if (!source || source.length < 5) continue;
      const result = scanText(source, { source: 'pdf_content', sensitivity: this.sensitivity });
      if (result.threats && result.threats.length > 0) {
        for (const t of result.threats) {
          threats.push({ ...t, contentSource: 'pdf', detail: (t.detail || '') + ' [Found in PDF content]' });
        }
      }
    }

    this.stats.scanned++;
    if (threats.length > 0) this.stats.threats++;

    return { safe: threats.length === 0, threats, source: 'pdf' };
  }

  /**
   * Recursively scan structured data (JSON/XML/YAML) for embedded injection.
   * @param {*} data - Structured data to scan.
   * @param {number} [maxDepth=10] - Maximum recursion depth.
   * @returns {{ safe: boolean, threats: Array<object>, source: string }}
   */
  scanStructuredData(data, maxDepth = 10) {
    const threats = [];
    const strings = this._extractStrings(data, 0, maxDepth);

    for (const str of strings) {
      if (str.length < 10) continue;
      const result = scanText(str, { source: 'structured_data', sensitivity: this.sensitivity });
      if (result.threats && result.threats.length > 0) {
        for (const t of result.threats) {
          threats.push({ ...t, contentSource: 'structured_data', detail: (t.detail || '') + ' [Found in structured data field]' });
        }
      }
    }

    this.stats.scanned++;
    if (threats.length > 0) this.stats.threats++;

    return { safe: threats.length === 0, threats, source: 'structured_data' };
  }

  /**
   * Get stats.
   * @returns {object}
   */
  getStats() {
    return { ...this.stats };
  }

  /** @private */
  _extractStrings(value, depth, maxDepth) {
    if (depth > maxDepth) return [];
    if (typeof value === 'string') return [value];
    if (Array.isArray(value)) {
      const result = [];
      for (const item of value) result.push(...this._extractStrings(item, depth + 1, maxDepth));
      return result;
    }
    if (value && typeof value === 'object') {
      const result = [];
      for (const key of Object.keys(value)) {
        if (typeof key === 'string' && key.length > 10) result.push(key);
        result.push(...this._extractStrings(value[key], depth + 1, maxDepth));
      }
      return result;
    }
    return [];
  }
}

module.exports = { MultimodalDetector };
