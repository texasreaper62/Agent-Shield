'use strict';

/**
 * Agent Shield — Response Handler
 *
 * Configurable response handling when threats are detected. Supports multiple
 * strategies: block, sanitize, redirect to human review, log-only, or custom.
 *
 * All detection runs locally — no data ever leaves your environment.
 */

const { scanText } = require('./detector-core');

// =========================================================================
// RESPONSE TEMPLATES
// =========================================================================

/**
 * Pre-built response templates for common threat handling scenarios.
 */
class ResponseTemplates {
  /**
   * Generate a safe block message when a threat is detected.
   * @param {Array} threats - Array of threat objects from a scan result.
   * @param {object} [options] - Template options.
   * @param {string} [options.detailLevel='standard'] - Detail level: 'minimal', 'standard', 'verbose'.
   * @returns {string} A safe block message.
   */
  static block(threats, options = {}) {
    const { detailLevel = 'standard' } = options;
    const count = threats.length;

    if (detailLevel === 'minimal') {
      return 'This request was blocked for security reasons.';
    }

    if (detailLevel === 'standard') {
      const categories = [...new Set(threats.map(t => t.category))];
      return `Request blocked: ${count} threat${count !== 1 ? 's' : ''} detected (${categories.join(', ')}). Contact your administrator if you believe this is an error.`;
    }

    // verbose
    const lines = [`Request blocked: ${count} threat${count !== 1 ? 's' : ''} detected.`];
    for (const threat of threats) {
      lines.push(`  - [${threat.severity.toUpperCase()}] ${threat.category}: ${threat.description}`);
    }
    lines.push('Contact your administrator if you believe this is an error.');
    return lines.join('\n');
  }

  /**
   * Generate a response for sanitized output.
   * @param {string} original - The original text.
   * @param {string} cleaned - The sanitized text.
   * @returns {object} Response with sanitized text and note.
   */
  static sanitized(original, cleaned) {
    const modified = original !== cleaned;
    return {
      text: cleaned,
      modified,
      note: modified
        ? '[Agent Shield] Response was sanitized: some content was removed or redacted for security.'
        : '[Agent Shield] Response passed sanitization without changes.'
    };
  }

  /**
   * Create a review ticket object for human review.
   * @param {Array} threats - Array of threat objects.
   * @param {object} [context] - Additional context.
   * @returns {object} Review ticket object.
   */
  static reviewTicket(threats, context = {}) {
    return {
      id: 'review_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8),
      status: 'pending',
      threats: threats.map(t => ({
        severity: t.severity,
        category: t.category,
        description: t.description
      })),
      context: { ...context },
      createdAt: Date.now(),
      resolvedAt: null,
      resolution: null
    };
  }
}

// =========================================================================
// REVIEW QUEUE
// =========================================================================

/**
 * In-memory queue for items redirected to human review.
 */
class ReviewQueue {
  /**
   * @param {object} [options]
   * @param {number} [options.maxSize=1000] - Maximum number of items in the queue.
   */
  constructor(options = {}) {
    this.maxSize = options.maxSize || 1000;

    /** @type {Map<string, object>} */
    this._items = new Map();
    this._totalAdded = 0;
    this._totalApproved = 0;
    this._totalRejected = 0;

    console.log('[Agent Shield] ReviewQueue initialized (maxSize: %d)', this.maxSize);
  }

  /**
   * Add an item to the review queue.
   * @param {object} item - The review item (should include threats, context, etc.).
   * @returns {string} The ticket ID.
   */
  add(item) {
    if (this._items.size >= this.maxSize) {
      // Evict the oldest item
      const oldestKey = this._items.keys().next().value;
      this._items.delete(oldestKey);
      console.log('[Agent Shield] ReviewQueue full, evicted oldest item: %s', oldestKey);
    }

    const ticket = ResponseTemplates.reviewTicket(
      item.threats || [],
      item.context || {}
    );
    ticket.originalContent = item.content || null;

    this._items.set(ticket.id, ticket);
    this._totalAdded++;

    console.log('[Agent Shield] ReviewQueue item added: %s (%d threats)', ticket.id, ticket.threats.length);
    return ticket.id;
  }

  /**
   * Get a review item by ticket ID.
   * @param {string} ticketId - The ticket ID.
   * @returns {object|null} The review item, or null if not found.
   */
  get(ticketId) {
    return this._items.get(ticketId) || null;
  }

  /**
   * Approve a review item.
   * @param {string} ticketId - The ticket ID.
   * @returns {boolean} True if the item was found and approved.
   */
  approve(ticketId) {
    const item = this._items.get(ticketId);
    if (!item) return false;

    item.status = 'approved';
    item.resolvedAt = Date.now();
    item.resolution = 'approved';
    this._totalApproved++;

    console.log('[Agent Shield] ReviewQueue item approved: %s', ticketId);
    return true;
  }

  /**
   * Reject a review item.
   * @param {string} ticketId - The ticket ID.
   * @returns {boolean} True if the item was found and rejected.
   */
  reject(ticketId) {
    const item = this._items.get(ticketId);
    if (!item) return false;

    item.status = 'rejected';
    item.resolvedAt = Date.now();
    item.resolution = 'rejected';
    this._totalRejected++;

    console.log('[Agent Shield] ReviewQueue item rejected: %s', ticketId);
    return true;
  }

  /**
   * List all pending review items.
   * @returns {Array} Array of pending review items.
   */
  getPending() {
    const pending = [];
    for (const item of this._items.values()) {
      if (item.status === 'pending') {
        pending.push(item);
      }
    }
    return pending;
  }

  /**
   * Get queue statistics.
   * @returns {object} Queue stats: { size, pending, approved, rejected, totalAdded, maxSize }.
   */
  getStats() {
    let pending = 0;
    for (const item of this._items.values()) {
      if (item.status === 'pending') pending++;
    }

    return {
      size: this._items.size,
      pending,
      approved: this._totalApproved,
      rejected: this._totalRejected,
      totalAdded: this._totalAdded,
      maxSize: this.maxSize
    };
  }
}

// =========================================================================
// RESPONSE HANDLER
// =========================================================================

/**
 * Configurable response handler for detected threats.
 * Routes threat detections through a chosen strategy: block, sanitize,
 * redirect, log, or custom handler.
 */
class ResponseHandler {
  /**
   * @param {object} [options]
   * @param {string} [options.strategy='block'] - Response strategy: 'block', 'sanitize', 'redirect', 'log', 'custom'.
   * @param {Function} [options.customHandler] - Custom handler function (required if strategy is 'custom').
   * @param {string} [options.blockMessage] - Custom block message (used with 'block' strategy).
   * @param {string} [options.detailLevel='standard'] - Detail level for block messages: 'minimal', 'standard', 'verbose'.
   * @param {ReviewQueue} [options.reviewQueue] - ReviewQueue instance for 'redirect' strategy.
   */
  constructor(options = {}) {
    this.strategy = options.strategy || 'block';
    this.customHandler = options.customHandler || null;
    this.blockMessage = options.blockMessage || null;
    this.detailLevel = options.detailLevel || 'standard';
    this.reviewQueue = options.reviewQueue || null;

    if (this.strategy === 'custom' && typeof this.customHandler !== 'function') {
      throw new Error('A "customHandler" function is required when strategy is "custom".');
    }

    if (this.strategy === 'redirect' && !this.reviewQueue) {
      this.reviewQueue = new ReviewQueue();
    }

    console.log('[Agent Shield] ResponseHandler initialized (strategy: %s)', this.strategy);
  }

  /**
   * Handle a scan result using the configured strategy.
   * @param {object} scanResult - The scan result from scanText or ToolOutputValidator.
   * @param {object} [context] - Additional context (original text, tool name, etc.).
   * @returns {object} Handler result: { action, response, original, threats }.
   */
  handle(scanResult, context = {}) {
    const threats = scanResult.threats || [];
    const original = context.text || context.original || null;

    // If no threats, pass through
    if (threats.length === 0) {
      return {
        action: 'pass',
        response: original,
        original,
        threats: []
      };
    }

    switch (this.strategy) {
      case 'block':
        return this._handleBlock(threats, original, context);
      case 'sanitize':
        return this._handleSanitize(threats, original, context);
      case 'redirect':
        return this._handleRedirect(threats, original, context);
      case 'log':
        return this._handleLog(threats, original, context);
      case 'custom':
        return this._handleCustom(scanResult, original, context);
      default:
        console.log('[Agent Shield] Unknown strategy "%s", falling back to block', this.strategy);
        return this._handleBlock(threats, original, context);
    }
  }

  /**
   * Block strategy: return a safe error message.
   * @param {Array} threats
   * @param {string} original
   * @param {object} context
   * @returns {object}
   * @private
   */
  _handleBlock(threats, original, context) {
    const message = this.blockMessage || ResponseTemplates.block(threats, { detailLevel: this.detailLevel });
    console.log('[Agent Shield] Response BLOCKED: %d threat(s) detected', threats.length);

    return {
      action: 'block',
      response: message,
      original,
      threats
    };
  }

  /**
   * Sanitize strategy: remove threatening parts, return cleaned text.
   * @param {Array} threats
   * @param {string} original
   * @param {object} context
   * @returns {object}
   * @private
   */
  _handleSanitize(threats, original, context) {
    if (!original || typeof original !== 'string') {
      return {
        action: 'sanitize',
        response: '',
        original,
        threats
      };
    }

    // Use OutputSanitizer to clean the text, with graceful fallback
    let cleaned = original;
    try {
      const { OutputSanitizer } = require('./tool-output-validator');
      cleaned = OutputSanitizer.sanitize(original, {
        stripInvisible: true,
        redactUrls: true,
        redactCode: true
      });
    } catch (err) {
      console.log('[Agent Shield] OutputSanitizer unavailable, using basic sanitization: %s', err.message);
      // Basic fallback: strip invisible characters
      cleaned = original.replace(/[\u200B-\u200F\u2060-\u2064\uFEFF]/g, '');
    }

    const template = ResponseTemplates.sanitized(original, cleaned);
    console.log('[Agent Shield] Response SANITIZED: %d threat(s), modified=%s', threats.length, template.modified);

    return {
      action: 'sanitize',
      response: template.text,
      original,
      threats,
      note: template.note
    };
  }

  /**
   * Redirect strategy: send to human review queue.
   * @param {Array} threats
   * @param {string} original
   * @param {object} context
   * @returns {object}
   * @private
   */
  _handleRedirect(threats, original, context) {
    const ticketId = this.reviewQueue.add({
      threats,
      content: original,
      context
    });

    console.log('[Agent Shield] Response REDIRECTED to review queue: %s', ticketId);

    return {
      action: 'redirect',
      response: `This response has been sent for human review. Ticket: ${ticketId}`,
      original,
      threats,
      ticketId
    };
  }

  /**
   * Log strategy: allow through but log the threat.
   * @param {Array} threats
   * @param {string} original
   * @param {object} context
   * @returns {object}
   * @private
   */
  _handleLog(threats, original, context) {
    for (const threat of threats) {
      console.log('[Agent Shield] Threat logged (pass-through): [%s] %s — %s', threat.severity, threat.category, threat.description);
    }

    return {
      action: 'log',
      response: original,
      original,
      threats
    };
  }

  /**
   * Custom strategy: call user's handler function.
   * @param {object} scanResult
   * @param {string} original
   * @param {object} context
   * @returns {object}
   * @private
   */
  _handleCustom(scanResult, original, context) {
    try {
      const customResult = this.customHandler(scanResult, context);
      console.log('[Agent Shield] Response handled by custom handler');

      return {
        action: 'custom',
        response: customResult,
        original,
        threats: scanResult.threats || []
      };
    } catch (err) {
      console.log('[Agent Shield] Custom handler error: %s — falling back to block', err.message);
      return this._handleBlock(scanResult.threats || [], original, context);
    }
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = { ResponseHandler, ResponseTemplates, ReviewQueue };
