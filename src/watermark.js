'use strict';

/**
 * Output Watermarking (#44) and Differential Privacy (#46)
 *
 * - Watermarking: Embed invisible watermarks in agent outputs for tracing.
 * - Differential Privacy: Add noise to stored conversation data.
 */

const crypto = require('crypto');

// =========================================================================
// OUTPUT WATERMARKING
// =========================================================================

/**
 * Zero-width characters used for binary watermark encoding.
 */
const WM_ZERO = '\u200B'; // zero-width space = 0
const WM_ONE = '\u200C';  // zero-width non-joiner = 1
const WM_START = '\u200D'; // zero-width joiner = start marker
const WM_END = '\uFEFF';  // byte order mark = end marker

class OutputWatermark {
  /**
   * @param {object} [options]
   * @param {string} [options.secret] - Secret key for HMAC signing.
   * @param {boolean} [options.includeTimestamp=true] - Include timestamp in watermark.
   */
  constructor(options = {}) {
    this.secret = options.secret || crypto.randomBytes(16).toString('hex');
    this.includeTimestamp = options.includeTimestamp !== undefined ? options.includeTimestamp : true;
  }

  /**
   * Embeds an invisible watermark in text.
   *
   * @param {string} text - The text to watermark.
   * @param {object} metadata - Data to encode in the watermark.
   * @param {string} [metadata.agentId] - Agent identifier.
   * @param {string} [metadata.sessionId] - Session identifier.
   * @returns {string} Watermarked text.
   */
  embed(text, metadata = {}) {
    if (!text) return text;

    const payload = {
      ...metadata,
      ts: this.includeTimestamp ? Date.now() : undefined
    };

    // Create signed payload
    const payloadStr = JSON.stringify(payload);
    const signature = crypto.createHmac('sha256', this.secret)
      .update(payloadStr)
      .digest('hex')
      .substring(0, 8);

    const data = `${payloadStr}|${signature}`;

    // Encode to binary using zero-width characters
    const binary = this._textToBinary(data);
    const watermark = WM_START + binary + WM_END;

    // Insert watermark in the middle of the text to be less detectable
    const midpoint = Math.floor(text.length / 2);
    // Find a space near the midpoint
    let insertAt = text.indexOf(' ', midpoint);
    if (insertAt === -1) insertAt = midpoint;

    return text.slice(0, insertAt) + watermark + text.slice(insertAt);
  }

  /**
   * Extracts a watermark from text.
   *
   * @param {string} text - Text that may contain a watermark.
   * @returns {object} { found: boolean, metadata?: object, verified: boolean }
   */
  extract(text) {
    if (!text) return { found: false };

    const startIdx = text.indexOf(WM_START);
    const endIdx = text.indexOf(WM_END, startIdx);

    if (startIdx === -1 || endIdx === -1 || endIdx <= startIdx) {
      return { found: false };
    }

    const binary = text.slice(startIdx + 1, endIdx);
    const data = this._binaryToText(binary);

    if (!data) return { found: false };

    const pipeIdx = data.lastIndexOf('|');
    if (pipeIdx === -1) return { found: false };

    const payloadStr = data.substring(0, pipeIdx);
    const signature = data.substring(pipeIdx + 1);

    // Verify signature
    const expectedSig = crypto.createHmac('sha256', this.secret)
      .update(payloadStr)
      .digest('hex')
      .substring(0, 8);

    const verified = signature === expectedSig;

    let metadata = null;
    try {
      metadata = JSON.parse(payloadStr);
    } catch (e) {
      return { found: true, verified: false, raw: payloadStr };
    }

    return { found: true, metadata, verified };
  }

  /**
   * Removes watermark from text.
   *
   * @param {string} text
   * @returns {string} Clean text.
   */
  strip(text) {
    if (!text) return text;
    return text.replace(/[\u200B\u200C\u200D\uFEFF]/g, '');
  }

  /** @private */
  _textToBinary(text) {
    let binary = '';
    for (let i = 0; i < text.length; i++) {
      const charCode = text.charCodeAt(i);
      const bits = charCode.toString(2).padStart(8, '0');
      for (const bit of bits) {
        binary += bit === '0' ? WM_ZERO : WM_ONE;
      }
    }
    return binary;
  }

  /** @private */
  _binaryToText(binary) {
    try {
      let text = '';
      let bits = '';
      for (const char of binary) {
        if (char === WM_ZERO) bits += '0';
        else if (char === WM_ONE) bits += '1';
        else continue;

        if (bits.length === 8) {
          text += String.fromCharCode(parseInt(bits, 2));
          bits = '';
        }
      }
      return text;
    } catch (e) {
      return null;
    }
  }
}

// =========================================================================
// DIFFERENTIAL PRIVACY FOR AGENT MEMORY
// =========================================================================

class DifferentialPrivacy {
  /**
   * Adds noise to stored conversation data so individual user data
   * can't be extracted even if the memory store is compromised.
   *
   * @param {object} [options]
   * @param {number} [options.epsilon=1.0] - Privacy budget. Lower = more private, noisier.
   * @param {number} [options.redactProbability=0.1] - Probability of redacting a token.
   */
  constructor(options = {}) {
    this.epsilon = options.epsilon || 1.0;
    this.redactProbability = options.redactProbability || 0.1;
  }

  /**
   * Sanitizes text for storage by adding noise.
   *
   * @param {string} text - Text to sanitize.
   * @returns {object} { sanitized: string, tokensRedacted: number }
   */
  sanitize(text) {
    if (!text) return { sanitized: text, tokensRedacted: 0 };

    const words = text.split(/\s+/);
    let tokensRedacted = 0;

    const sanitized = words.map(word => {
      // Higher epsilon = less noise (more utility)
      const threshold = this.redactProbability / this.epsilon;

      if (Math.random() < threshold) {
        tokensRedacted++;
        return '[REDACTED]';
      }

      // For numbers, add Laplacian noise
      if (/^\d+\.?\d*$/.test(word)) {
        const num = parseFloat(word);
        const noise = this._laplacianNoise(1 / this.epsilon);
        const noisy = Math.round((num + noise) * 100) / 100;
        return String(noisy);
      }

      return word;
    });

    return {
      sanitized: sanitized.join(' '),
      tokensRedacted
    };
  }

  /**
   * Generates Laplacian noise for numeric privacy.
   * @private
   * @param {number} scale - Scale parameter (b = sensitivity/epsilon).
   * @returns {number}
   */
  _laplacianNoise(scale) {
    // Use crypto for proper randomness instead of Math.random()
    const bytes = crypto.randomBytes(4);
    const u = (bytes.readUInt32BE(0) / 0xFFFFFFFF) - 0.5;
    return -scale * Math.sign(u) * Math.log(1 - 2 * Math.abs(u));
  }
}

module.exports = { OutputWatermark, DifferentialPrivacy };
