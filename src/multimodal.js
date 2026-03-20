'use strict';

/**
 * Agent Shield — Multi-Modal Scanning (v3.0)
 *
 * Scans non-text modalities for injection attacks:
 * - Image alt text and metadata
 * - Audio/video transcripts
 * - PDF extracted text
 * - Structured tool outputs (JSON, XML)
 * - Base64-encoded payloads in any field
 *
 * All processing runs locally — no data ever leaves your environment.
 */

const { scanText } = require('./detector-core');

// =========================================================================
// MODALITY EXTRACTORS
// =========================================================================

/**
 * Extract scannable text from various data formats.
 */
class ModalityExtractor {
  /**
   * Extract text from an image-like object (metadata, alt text, EXIF).
   * @param {object} imageData - { altText, title, caption, metadata, ocrText }
   * @returns {Array<{text: string, source: string}>}
   */
  extractFromImage(imageData) {
    const texts = [];

    if (imageData.altText) texts.push({ text: imageData.altText, source: 'image:alt_text' });
    if (imageData.title) texts.push({ text: imageData.title, source: 'image:title' });
    if (imageData.caption) texts.push({ text: imageData.caption, source: 'image:caption' });
    if (imageData.ocrText) texts.push({ text: imageData.ocrText, source: 'image:ocr' });

    // Check EXIF/metadata fields for hidden payloads
    if (imageData.metadata && typeof imageData.metadata === 'object') {
      for (const [key, value] of Object.entries(imageData.metadata)) {
        if (typeof value === 'string' && value.length > 10) {
          texts.push({ text: value, source: `image:metadata:${key}` });
        }
      }
    }

    // Check for base64 encoded content in any field
    if (imageData.base64) {
      try {
        const decoded = Buffer.from(imageData.base64.substring(0, 10000), 'base64').toString('utf-8');
        const printable = decoded.split('').filter(c => c.charCodeAt(0) >= 32 && c.charCodeAt(0) <= 126).length;
        if (printable / decoded.length > 0.7) {
          texts.push({ text: decoded, source: 'image:base64_decoded' });
        }
      } catch (e) {
        // Not valid base64
      }
    }

    return texts;
  }

  /**
   * Extract text from an audio/video transcript.
   * @param {object} audioData - { transcript, segments, metadata, speakers }
   * @returns {Array<{text: string, source: string}>}
   */
  extractFromAudio(audioData) {
    const texts = [];

    if (audioData.transcript) {
      texts.push({ text: audioData.transcript, source: 'audio:transcript' });
    }

    if (audioData.segments && Array.isArray(audioData.segments)) {
      for (let i = 0; i < audioData.segments.length; i++) {
        const seg = audioData.segments[i];
        if (seg.text && seg.text.length > 10) {
          texts.push({ text: seg.text, source: `audio:segment:${i}` });
        }
      }
    }

    if (audioData.speakers && typeof audioData.speakers === 'object') {
      for (const [speaker, content] of Object.entries(audioData.speakers)) {
        if (typeof content === 'string' && content.length > 10) {
          texts.push({ text: content, source: `audio:speaker:${speaker}` });
        }
      }
    }

    if (audioData.metadata && typeof audioData.metadata === 'object') {
      for (const [key, value] of Object.entries(audioData.metadata)) {
        if (typeof value === 'string' && value.length > 10) {
          texts.push({ text: value, source: `audio:metadata:${key}` });
        }
      }
    }

    return texts;
  }

  /**
   * Extract text from a PDF-like object.
   * @param {object} pdfData - { text, pages, metadata, annotations }
   * @returns {Array<{text: string, source: string}>}
   */
  extractFromPDF(pdfData) {
    const texts = [];

    if (pdfData.text) {
      texts.push({ text: pdfData.text, source: 'pdf:full_text' });
    }

    if (pdfData.pages && Array.isArray(pdfData.pages)) {
      for (let i = 0; i < pdfData.pages.length; i++) {
        const page = pdfData.pages[i];
        const pageText = typeof page === 'string' ? page : page.text;
        if (pageText && pageText.length > 10) {
          texts.push({ text: pageText, source: `pdf:page:${i + 1}` });
        }
      }
    }

    if (pdfData.annotations && Array.isArray(pdfData.annotations)) {
      for (let i = 0; i < pdfData.annotations.length; i++) {
        const ann = pdfData.annotations[i];
        const annText = typeof ann === 'string' ? ann : ann.text || ann.content;
        if (annText && annText.length > 10) {
          texts.push({ text: annText, source: `pdf:annotation:${i}` });
        }
      }
    }

    if (pdfData.metadata && typeof pdfData.metadata === 'object') {
      for (const [key, value] of Object.entries(pdfData.metadata)) {
        if (typeof value === 'string' && value.length > 10) {
          texts.push({ text: value, source: `pdf:metadata:${key}` });
        }
      }
    }

    return texts;
  }

  /**
   * Extract text from a tool call response.
   * @param {object} toolOutput - Any structured object from a tool call.
   * @param {string} [toolName='unknown'] - Name of the tool.
   * @returns {Array<{text: string, source: string}>}
   */
  extractFromToolOutput(toolOutput, toolName = 'unknown') {
    const texts = [];
    this._extractStrings(toolOutput, `tool:${toolName}`, texts, 0);
    return texts;
  }

  /** @private */
  _extractStrings(obj, prefix, results, depth) {
    if (depth > 8) return;

    if (typeof obj === 'string' && obj.length > 10) {
      results.push({ text: obj, source: prefix });
    } else if (Array.isArray(obj)) {
      for (let i = 0; i < Math.min(obj.length, 100); i++) {
        this._extractStrings(obj[i], `${prefix}[${i}]`, results, depth + 1);
      }
    } else if (obj && typeof obj === 'object') {
      for (const [key, value] of Object.entries(obj)) {
        this._extractStrings(value, `${prefix}.${key}`, results, depth + 1);
      }
    }
  }
}

// =========================================================================
// MULTI-MODAL SCANNER
// =========================================================================

/**
 * Scans multi-modal inputs for injection attacks.
 */
class MultiModalScanner {
  /**
   * @param {object} [options]
   * @param {string} [options.sensitivity='high'] - Scan sensitivity.
   * @param {Function} [options.onThreat] - Callback on threat detection.
   */
  constructor(options = {}) {
    this.sensitivity = options.sensitivity || 'high';
    this.onThreat = options.onThreat || null;

    this._extractor = new ModalityExtractor();
    this._stats = { scans: 0, threats: 0, modalities: {} };

    console.log('[Agent Shield] MultiModalScanner initialized (sensitivity: %s)', this.sensitivity);
  }

  /**
   * Scan an image for hidden injections.
   * @param {object} imageData - Image data with text fields.
   * @returns {object} { clean: boolean, threats: Array, modality: 'image' }
   */
  scanImage(imageData) {
    return this._scanModality('image', this._extractor.extractFromImage(imageData));
  }

  /**
   * Scan audio/video transcript for injections.
   * @param {object} audioData - Audio data with transcript/segments.
   * @returns {object}
   */
  scanAudio(audioData) {
    return this._scanModality('audio', this._extractor.extractFromAudio(audioData));
  }

  /**
   * Scan PDF content for injections.
   * @param {object} pdfData - PDF data with text/pages.
   * @returns {object}
   */
  scanPDF(pdfData) {
    return this._scanModality('pdf', this._extractor.extractFromPDF(pdfData));
  }

  /**
   * Scan a tool's output for injections.
   * @param {object} toolOutput - Tool output data.
   * @param {string} [toolName] - Tool name.
   * @returns {object}
   */
  scanToolOutput(toolOutput, toolName) {
    return this._scanModality('tool_output', this._extractor.extractFromToolOutput(toolOutput, toolName));
  }

  /**
   * Scan any modality by providing extracted texts directly.
   * @param {string} modality - Modality label.
   * @param {Array<{text: string, source: string}>} texts - Extracted text items.
   * @returns {object}
   */
  scanRaw(modality, texts) {
    return this._scanModality(modality, texts);
  }

  /**
   * Get scanning statistics.
   * @returns {object}
   */
  getStats() {
    return { ...this._stats };
  }

  /** @private */
  _scanModality(modality, texts) {
    this._stats.scans++;
    this._stats.modalities[modality] = (this._stats.modalities[modality] || 0) + 1;

    const allThreats = [];

    for (const { text, source } of texts) {
      const result = scanText(text, { source, sensitivity: this.sensitivity });
      if (result.threats.length > 0) {
        for (const threat of result.threats) {
          allThreats.push({
            ...threat,
            modality,
            source,
            description: `[${modality.toUpperCase()}] ${threat.description}`
          });
        }
      }
    }

    if (allThreats.length > 0) {
      this._stats.threats += allThreats.length;
      if (this.onThreat) {
        this.onThreat({ modality, threats: allThreats });
      }
    }

    return {
      clean: allThreats.length === 0,
      threats: allThreats,
      modality,
      textsScanned: texts.length
    };
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = { MultiModalScanner, ModalityExtractor };
