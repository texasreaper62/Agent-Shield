'use strict';

/**
 * Agent Shield — Streaming Scanner
 *
 * Scans text incrementally as it arrives in chunks, designed for LLM streaming
 * responses. Buffers incoming text and scans when a threshold is reached or a
 * sentence boundary is detected, balancing latency with detection coverage.
 *
 * All detection runs locally — no data ever leaves your environment.
 */

const { scanText } = require('../src/detector-core');

const LOG_PREFIX = '[Agent Shield]';

/** Characters that indicate a sentence boundary. */
const SENTENCE_BOUNDARIES = new Set(['.', '!', '?', '\n', '\r']);

// =========================================================================
// StreamScanner
// =========================================================================

/**
 * Buffers incoming text chunks and scans periodically for threats.
 *
 * Scans are triggered when the buffer reaches `bufferSize` characters or when
 * a sentence boundary is detected. This avoids scanning every character while
 * still catching threats as early as possible.
 *
 * @example
 * const scanner = new StreamScanner({ sensitivity: 'high', bufferSize: 80 });
 * scanner.on('threat', (threats) => console.log('Threats detected:', threats));
 * scanner.write('some text chunk');
 * const result = scanner.flush();
 */
class StreamScanner {
  /**
   * Create a new StreamScanner.
   * @param {Object} [options={}] - Configuration options.
   * @param {number} [options.bufferSize=100] - Character count threshold to trigger a scan.
   * @param {number} [options.flushInterval=500] - Auto-flush interval in ms (0 to disable).
   * @param {string} [options.sensitivity='medium'] - Detection sensitivity (low, medium, high).
   * @param {string} [options.source='stream'] - Source label for scan results.
   */
  constructor(options = {}) {
    this._bufferSize = options.bufferSize != null ? options.bufferSize : 100;
    this._flushInterval = options.flushInterval != null ? options.flushInterval : 500;
    this._sensitivity = options.sensitivity || 'medium';
    this._source = options.source || 'stream';

    this._buffer = '';
    this._listeners = { threat: [], scan: [], flush: [] };
    this._stats = { chunksProcessed: 0, totalBytes: 0, threatsFound: 0, scansPerformed: 0 };
    this._flushTimer = null;

    if (this._flushInterval > 0) {
      this._startFlushTimer();
    }
  }

  /**
   * Add a chunk of text to the buffer.
   *
   * If the buffer reaches the configured threshold or a sentence boundary is
   * detected at the end of the chunk, a scan is performed immediately.
   *
   * @param {string} chunk - Text chunk to add.
   * @returns {{ safe: boolean, threats: Array }} Scan result if a scan was triggered, otherwise a safe result.
   */
  write(chunk) {
    if (typeof chunk !== 'string') {
      console.error(`${LOG_PREFIX} StreamScanner.write() expects a string, got ${typeof chunk}`);
      return { safe: true, threats: [] };
    }

    this._buffer += chunk;
    this._stats.chunksProcessed++;
    this._stats.totalBytes += Buffer.byteLength(chunk, 'utf8');

    const shouldScan = this._buffer.length >= this._bufferSize ||
      (chunk.length > 0 && SENTENCE_BOUNDARIES.has(chunk[chunk.length - 1]));

    if (shouldScan) {
      return this._scan();
    }

    return { safe: true, threats: [] };
  }

  /**
   * Force a scan of the remaining buffer contents.
   * @returns {{ safe: boolean, threats: Array }} Scan result.
   */
  flush() {
    this._resetFlushTimer();
    const result = this._scan();
    this._emit('flush', result);
    return result;
  }

  /**
   * Pipe a readable stream through the scanner.
   *
   * Returns a Transform stream that passes data through while scanning each
   * chunk. Threat events are emitted on the scanner instance.
   *
   * @param {import('stream').Readable} readableStream - The stream to scan.
   * @returns {import('stream').Transform} A transform stream that forwards scanned data.
   */
  pipe(readableStream) {
    const { Transform } = require('stream');
    const self = this;

    const transform = new Transform({
      transform(chunk, encoding, callback) {
        try {
          const text = typeof chunk === 'string' ? chunk : chunk.toString('utf8');
          self.write(text);
          callback(null, chunk);
        } catch (err) {
          console.error(`${LOG_PREFIX} Stream transform error: ${err.message}`);
          callback(err);
        }
      },
      flush(callback) {
        try {
          self.flush();
          callback();
        } catch (err) {
          console.error(`${LOG_PREFIX} Stream flush error: ${err.message}`);
          callback(err);
        }
      }
    });

    readableStream.pipe(transform);
    return transform;
  }

  /**
   * Get scanning statistics.
   * @returns {{ chunksProcessed: number, totalBytes: number, threatsFound: number, scansPerformed: number }}
   */
  getStats() {
    return { ...this._stats };
  }

  /**
   * Register an event listener.
   * @param {'threat' | 'scan' | 'flush'} event - Event name.
   * @param {Function} callback - Callback function.
   */
  on(event, callback) {
    if (!this._listeners[event]) {
      console.error(`${LOG_PREFIX} Unknown event: "${event}". Valid events: threat, scan, flush`);
      return;
    }
    if (typeof callback !== 'function') {
      console.error(`${LOG_PREFIX} Event callback must be a function`);
      return;
    }
    this._listeners[event].push(callback);
  }

  /**
   * Clear the buffer, reset stats, and stop timers.
   */
  reset() {
    this._buffer = '';
    this._stats = { chunksProcessed: 0, totalBytes: 0, threatsFound: 0, scansPerformed: 0 };
    this._resetFlushTimer();
    if (this._flushInterval > 0) {
      this._startFlushTimer();
    }
  }

  /**
   * Stop all internal timers. Call this when the scanner is no longer needed.
   */
  destroy() {
    this._resetFlushTimer();
    this._buffer = '';
    this._listeners = { threat: [], scan: [], flush: [] };
  }

  // -- Private methods --

  /**
   * Perform a scan on the current buffer contents.
   * @returns {{ safe: boolean, threats: Array }}
   * @private
   */
  _scan() {
    const text = this._buffer;
    this._buffer = '';
    this._stats.scansPerformed++;

    if (!text || text.trim().length === 0) {
      return { safe: true, threats: [] };
    }

    try {
      const result = scanText(text, {
        source: this._source,
        sensitivity: this._sensitivity
      });

      const safe = result.status === 'safe';
      const threats = result.threats || [];

      if (threats.length > 0) {
        this._stats.threatsFound += threats.length;
        this._emit('threat', threats);
      }

      this._emit('scan', { safe, threats, stats: result.stats });

      return { safe, threats };
    } catch (err) {
      console.error(`${LOG_PREFIX} Scan error: ${err.message}`);
      return { safe: true, threats: [] };
    }
  }

  /**
   * Emit an event to registered listeners.
   * @param {string} event
   * @param {*} data
   * @private
   */
  _emit(event, data) {
    const callbacks = this._listeners[event];
    if (!callbacks) return;
    for (const cb of callbacks) {
      try {
        cb(data);
      } catch (err) {
        console.error(`${LOG_PREFIX} Error in "${event}" listener: ${err.message}`);
      }
    }
  }

  /** @private */
  _startFlushTimer() {
    this._flushTimer = setInterval(() => {
      if (this._buffer.length > 0) {
        this.flush();
      }
    }, this._flushInterval);
    if (this._flushTimer.unref) {
      this._flushTimer.unref();
    }
  }

  /** @private */
  _resetFlushTimer() {
    if (this._flushTimer) {
      clearInterval(this._flushTimer);
      this._flushTimer = null;
    }
  }
}

// =========================================================================
// TokenStreamScanner
// =========================================================================

/**
 * Token-by-token scanner for LLM token streams.
 *
 * Maintains a sliding window of tokens and scans when the window is full.
 * Designed for use with LLM APIs that deliver responses one token at a time.
 *
 * @example
 * const scanner = new TokenStreamScanner({ windowSize: 30 });
 * for (const token of tokenStream) {
 *   const result = scanner.pushToken(token);
 *   if (!result.safe) console.log('Threat in token stream:', result.threats);
 * }
 * const final = scanner.finish();
 */
class TokenStreamScanner {
  /**
   * Create a new TokenStreamScanner.
   * @param {Object} [options={}] - Configuration options.
   * @param {number} [options.windowSize=50] - Number of tokens in the sliding window.
   * @param {string} [options.sensitivity='medium'] - Detection sensitivity (low, medium, high).
   * @param {string} [options.source='token-stream'] - Source label for scan results.
   */
  constructor(options = {}) {
    this._windowSize = options.windowSize != null ? options.windowSize : 50;
    this._sensitivity = options.sensitivity || 'medium';
    this._source = options.source || 'token-stream';

    this._tokens = [];
    this._totalTokens = 0;
    this._scansPerformed = 0;
    this._threatsFound = 0;
  }

  /**
   * Add a token to the sliding window.
   *
   * When the window is full, the accumulated text is scanned and the window
   * is cleared. Returns a safe result if the window is not yet full.
   *
   * @param {string} token - A single token string.
   * @returns {{ safe: boolean, threats: Array }} Scan result if window is full, otherwise safe.
   */
  pushToken(token) {
    if (typeof token !== 'string') {
      console.error(`${LOG_PREFIX} TokenStreamScanner.pushToken() expects a string, got ${typeof token}`);
      return { safe: true, threats: [] };
    }

    this._tokens.push(token);
    this._totalTokens++;

    if (this._tokens.length >= this._windowSize) {
      return this._scanWindow();
    }

    return { safe: true, threats: [] };
  }

  /**
   * Scan any remaining tokens in the window.
   *
   * Call this when the token stream has ended to ensure all tokens are scanned.
   *
   * @returns {{ safe: boolean, threats: Array }} Scan result.
   */
  finish() {
    if (this._tokens.length === 0) {
      return { safe: true, threats: [] };
    }
    return this._scanWindow();
  }

  /**
   * Get the total number of tokens processed so far.
   * @returns {number}
   */
  getTokenCount() {
    return this._totalTokens;
  }

  /**
   * Get scanning statistics.
   * @returns {{ totalTokens: number, scansPerformed: number, threatsFound: number }}
   */
  getStats() {
    return {
      totalTokens: this._totalTokens,
      scansPerformed: this._scansPerformed,
      threatsFound: this._threatsFound
    };
  }

  /**
   * Reset the scanner to its initial state.
   */
  reset() {
    this._tokens = [];
    this._totalTokens = 0;
    this._scansPerformed = 0;
    this._threatsFound = 0;
  }

  // -- Private methods --

  /**
   * Scan the current token window and clear it.
   * @returns {{ safe: boolean, threats: Array }}
   * @private
   */
  _scanWindow() {
    const text = this._tokens.join('');
    this._tokens = [];
    this._scansPerformed++;

    if (!text || text.trim().length === 0) {
      return { safe: true, threats: [] };
    }

    try {
      const result = scanText(text, {
        source: this._source,
        sensitivity: this._sensitivity
      });

      const safe = result.status === 'safe';
      const threats = result.threats || [];

      if (threats.length > 0) {
        this._threatsFound += threats.length;
      }

      return { safe, threats };
    } catch (err) {
      console.error(`${LOG_PREFIX} Token scan error: ${err.message}`);
      return { safe: true, threats: [] };
    }
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = { StreamScanner, TokenStreamScanner };
