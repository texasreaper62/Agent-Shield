'use strict';

/**
 * Agent Shield — Streaming Scanner
 *
 * Production-grade token-by-token scanner for LLM streaming responses.
 * Uses a sliding window approach to detect threats as tokens arrive,
 * without waiting for the full response to complete.
 *
 * Supports Anthropic SDK streams, OpenAI SDK streams, generic async
 * iterables, ReadableStreams, and EventEmitters.
 *
 * Zero dependencies. All detection runs locally.
 *
 * @module stream-scanner
 */

const { EventEmitter } = require('events');
const { scanText, SEVERITY_ORDER } = require('./detector-core');

// =========================================================================
// CONSTANTS
// =========================================================================

/** Default number of tokens in the sliding window. */
const DEFAULT_WINDOW_SIZE = 50;

/** Default number of new tokens before triggering a scan. */
const DEFAULT_SCAN_INTERVAL = 10;

/** Overlap ratio — fraction of window retained when sliding forward. */
const OVERLAP_RATIO = 0.5;

/** Maximum total tokens before forced compaction (memory safety). */
const MAX_TOTAL_TOKENS = 100_000;

/** Log prefix for console messages. */
const LOG_PREFIX = '[Agent Shield]';

// =========================================================================
// StreamBuffer — Sliding Window Token Buffer
// =========================================================================

/**
 * Sliding window buffer that accumulates tokens and provides
 * overlapping windows for pattern scanning.
 *
 * Maintains two views:
 * - The current scan window (configurable size with overlap)
 * - The full accumulated text (for final scan)
 *
 * Memory-safe: compacts old tokens on very long streams to
 * prevent unbounded memory growth.
 */
class StreamBuffer {
  /**
   * @param {object} [options]
   * @param {number} [options.windowSize=50] - Number of tokens in the sliding window.
   */
  constructor(options = {}) {
    /** @type {number} */
    this.windowSize = options.windowSize || DEFAULT_WINDOW_SIZE;

    /** @type {string[]} All tokens currently held in memory. */
    this._tokens = [];

    /** @type {string} Full accumulated text (including compacted). */
    this._fullText = '';

    /** @type {number} Total tokens received (including compacted). */
    this._totalReceived = 0;

    /** @type {string} Text compacted out of the token array. */
    this._compactedText = '';
  }

  /**
   * Add a token to the buffer.
   * @param {string} token - The token string to add.
   */
  push(token) {
    if (typeof token !== 'string') return;
    this._tokens.push(token);
    this._fullText += token;
    this._totalReceived++;

    // Memory safety: compact old tokens if we exceed the limit
    if (this._tokens.length > MAX_TOTAL_TOKENS) {
      this._compact();
    }
  }

  /**
   * Get the current scan window text with overlap from the previous window.
   * The overlap ensures patterns that span window boundaries are caught.
   * @returns {string}
   */
  getWindow() {
    const overlapCount = Math.floor(this.windowSize * OVERLAP_RATIO);
    const start = Math.max(0, this._tokens.length - this.windowSize - overlapCount);
    return this._tokens.slice(start).join('');
  }

  /**
   * Get the full accumulated text (all tokens ever received).
   * @returns {string}
   */
  getFullText() {
    return this._fullText;
  }

  /**
   * Get the number of tokens currently in the buffer.
   * @returns {number}
   */
  get length() {
    return this._tokens.length;
  }

  /**
   * Get total tokens received since creation (including compacted ones).
   * @returns {number}
   */
  get totalReceived() {
    return this._totalReceived;
  }

  /**
   * Get the last N tokens joined as text.
   * @param {number} n - Number of trailing tokens.
   * @returns {string}
   */
  lastN(n) {
    return this._tokens.slice(-n).join('');
  }

  /**
   * Clear the buffer completely.
   */
  clear() {
    this._tokens = [];
    this._fullText = '';
    this._compactedText = '';
  }

  /**
   * Compact old tokens to free memory on very long streams.
   * Keeps the most recent windowSize * 2 tokens.
   * @private
   */
  _compact() {
    const keep = this.windowSize * 2;
    if (this._tokens.length <= keep) return;
    const removed = this._tokens.splice(0, this._tokens.length - keep);
    this._compactedText += removed.join('');
  }
}

// =========================================================================
// StreamScanner — Core Scanner
// =========================================================================

/**
 * Token-by-token streaming scanner for LLM output.
 *
 * Wraps any async iterable, ReadableStream, or EventEmitter and scans
 * tokens as they arrive using a sliding window approach. Threats are
 * detected mid-stream and can optionally halt the stream.
 *
 * @extends EventEmitter
 *
 * @fires StreamScanner#threat - When a new threat is detected mid-stream.
 * @fires StreamScanner#halt - When the stream is halted due to a critical threat.
 * @fires StreamScanner#done - When the stream has ended and final results are ready.
 *
 * @example
 * const scanner = new StreamScanner({
 *   windowSize: 50,
 *   scanInterval: 10,
 *   haltOnSeverity: 'critical',
 *   onThreat: (threat, buffer) => console.log('mid-stream threat:', threat)
 * });
 *
 * // Wrap Anthropic stream
 * const stream = await client.messages.create({ stream: true, ... });
 * const shielded = scanner.wrapAnthropicStream(stream);
 * for await (const event of shielded) {
 *   // events pass through, but threats are detected
 * }
 * const finalResult = scanner.getResult();
 */
class StreamScanner extends EventEmitter {
  /**
   * @param {object} [options]
   * @param {number} [options.windowSize=50] - Tokens in the scan window.
   * @param {number} [options.scanInterval=10] - New tokens between scans.
   * @param {string} [options.haltOnSeverity] - Halt stream if severity >= this level.
   *   One of: 'critical', 'high', 'medium', 'low'. Omit to never halt.
   * @param {Function} [options.onThreat] - Callback invoked on each new threat: (threat, buffer) => void.
   * @param {string} [options.source='stream'] - Source label for scan results.
   * @param {string} [options.sensitivity='medium'] - Sensitivity: 'low', 'medium', 'high'.
   * @param {boolean} [options.scanFinal=true] - Run a final full-text scan when the stream ends.
   */
  constructor(options = {}) {
    super();

    /** @type {number} */
    this.windowSize = options.windowSize || DEFAULT_WINDOW_SIZE;

    /** @type {number} */
    this.scanInterval = options.scanInterval || DEFAULT_SCAN_INTERVAL;

    /** @type {string|null} */
    this.haltOnSeverity = options.haltOnSeverity || null;

    /** @type {Function|null} */
    this.onThreat = options.onThreat || null;

    /** @type {string} */
    this.source = options.source || 'stream';

    /** @type {string} */
    this.sensitivity = options.sensitivity || 'medium';

    /** @type {boolean} */
    this.scanFinal = options.scanFinal !== false;

    /** @type {StreamBuffer} */
    this.buffer = new StreamBuffer({ windowSize: this.windowSize });

    /** @type {number} Tokens received since last window scan. */
    this._tokensSinceLastScan = 0;

    /** @type {Array} All threats detected across all scans. */
    this._threats = [];

    /** @type {Set<string>} Deduplication keys for threats. */
    this._seenThreatKeys = new Set();

    /** @type {boolean} Whether the stream was halted by the scanner. */
    this._halted = false;

    /** @type {string|null} Reason for halting. */
    this._haltReason = null;

    /** @type {number} Total mid-stream scans performed. */
    this._scanCount = 0;

    /** @type {number} Total scan time in ms. */
    this._totalScanTimeMs = 0;

    /** @type {boolean} Whether the stream has ended. */
    this._ended = false;

    /** @type {object|null} Final result, set after stream ends. */
    this._finalResult = null;

    /** @type {Error|null} Error that terminated the stream, if any. */
    this._streamError = null;
  }

  /**
   * Process a single token. Called internally by wrappers, but can also
   * be called directly for manual token-by-token feeding.
   *
   * @param {string} token - The token text.
   * @returns {{ halt: boolean, threats: Array }} Result for this token.
   */
  processToken(token) {
    if (this._halted || this._ended) {
      return { halt: this._halted, threats: [] };
    }

    this.buffer.push(token);
    this._tokensSinceLastScan++;

    // Trigger a window scan once we've accumulated enough new tokens
    if (this._tokensSinceLastScan >= this.scanInterval) {
      return this._runWindowScan();
    }

    return { halt: false, threats: [] };
  }

  /**
   * Run a scan on the current sliding window.
   * @returns {{ halt: boolean, threats: Array }}
   * @private
   */
  _runWindowScan() {
    this._tokensSinceLastScan = 0;
    this._scanCount++;

    const windowText = this.buffer.getWindow();
    if (!windowText || windowText.trim().length < 10) {
      return { halt: false, threats: [] };
    }

    const result = scanText(windowText, {
      source: this.source,
      sensitivity: this.sensitivity
    });

    const newThreats = this._deduplicateThreats(result.threats);
    this._totalScanTimeMs += result.stats.scanTimeMs;

    if (newThreats.length > 0) {
      for (const threat of newThreats) {
        threat.detectedAt = 'mid-stream';
        threat.tokenPosition = this.buffer.totalReceived;
        this._threats.push(threat);

        this.emit('threat', threat, this.buffer);

        if (this.onThreat) {
          try {
            this.onThreat(threat, this.buffer);
          } catch (_) {
            // Swallow callback errors to avoid breaking the stream
          }
        }

        // Check if this severity should halt the stream
        if (this._shouldHalt(threat.severity)) {
          this._halted = true;
          this._haltReason = `Threat detected: ${threat.category} (${threat.severity})`;
          this.emit('halt', threat, this._haltReason);
          return { halt: true, threats: newThreats };
        }
      }
    }

    return { halt: false, threats: newThreats };
  }

  /**
   * Filter out threats already seen in previous scans.
   * Uses category + severity + detail as a composite key.
   * @param {Array} threats
   * @returns {Array} Only threats not previously reported.
   * @private
   */
  _deduplicateThreats(threats) {
    const novel = [];
    for (const t of threats) {
      const key = `${t.category}:${t.severity}:${t.detail}`;
      if (!this._seenThreatKeys.has(key)) {
        this._seenThreatKeys.add(key);
        novel.push(t);
      }
    }
    return novel;
  }

  /**
   * Determine if a given severity level should trigger a stream halt.
   * @param {string} severity - The threat severity.
   * @returns {boolean}
   * @private
   */
  _shouldHalt(severity) {
    if (!this.haltOnSeverity) return false;
    const threshold = SEVERITY_ORDER[this.haltOnSeverity];
    const actual = SEVERITY_ORDER[severity];
    if (threshold === undefined || actual === undefined) return false;
    // Lower number = higher severity; halt if actual severity is as bad or worse
    return actual <= threshold;
  }

  /**
   * Finalize scanning when the stream ends. Optionally runs a full-text
   * scan to catch patterns that span across window boundaries.
   * @returns {object} Final scan result.
   */
  finalize() {
    if (this._ended) return this._finalResult;
    this._ended = true;

    // Run final full-text scan if enabled
    if (this.scanFinal) {
      const fullText = this.buffer.getFullText();
      if (fullText && fullText.trim().length >= 10) {
        const finalScan = scanText(fullText, {
          source: this.source,
          sensitivity: this.sensitivity
        });
        const newThreats = this._deduplicateThreats(finalScan.threats);
        for (const t of newThreats) {
          t.detectedAt = 'final-scan';
          t.tokenPosition = this.buffer.totalReceived;
          this._threats.push(t);
          this.emit('threat', t, this.buffer);
          if (this.onThreat) {
            try { this.onThreat(t, this.buffer); } catch (_) { /* swallow */ }
          }
        }
        this._totalScanTimeMs += finalScan.stats.scanTimeMs;
      }
    }

    // Sort all threats by severity (critical first)
    this._threats.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

    // Build final result
    const stats = {
      totalThreats: this._threats.length,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      scanTimeMs: this._totalScanTimeMs,
      windowScans: this._scanCount,
      totalTokens: this.buffer.totalReceived,
      halted: this._halted
    };
    for (const t of this._threats) {
      stats[t.severity] = (stats[t.severity] || 0) + 1;
    }

    let status = 'safe';
    if (stats.critical > 0) status = 'danger';
    else if (stats.high > 0) status = 'warning';
    else if (stats.medium > 0) status = 'caution';

    this._finalResult = {
      status,
      threats: this._threats,
      stats,
      timestamp: Date.now(),
      halted: this._halted,
      haltReason: this._haltReason,
      error: this._streamError ? this._streamError.message : null
    };

    this.emit('done', this._finalResult);
    return this._finalResult;
  }

  /**
   * Get the final scan result. If the stream has not ended, finalizes it first.
   * @returns {object} Scan result with status, threats, stats, and metadata.
   */
  getResult() {
    if (!this._ended) {
      return this.finalize();
    }
    return this._finalResult;
  }

  /**
   * Reset the scanner for reuse with a new stream.
   * Clears all state: buffer, threats, stats, and flags.
   */
  reset() {
    this.buffer.clear();
    this._tokensSinceLastScan = 0;
    this._threats = [];
    this._seenThreatKeys = new Set();
    this._halted = false;
    this._haltReason = null;
    this._scanCount = 0;
    this._totalScanTimeMs = 0;
    this._ended = false;
    this._finalResult = null;
    this._streamError = null;
  }

  /**
   * Wrap a generic async iterable. Yields the same values as the original
   * but scans text content as it passes through.
   *
   * @param {AsyncIterable} iterable - Any async iterable yielding strings or objects.
   * @param {object} [options]
   * @param {Function} [options.extractText] - Extract text from each chunk.
   *   Signature: (chunk) => string|null. Defaults to treating chunks as strings
   *   or extracting .text / .content properties from objects.
   * @returns {AsyncGenerator} Yields the same chunks with scanning applied.
   */
  async *wrap(iterable, options = {}) {
    const extractText = options.extractText || _defaultTextExtractor;

    try {
      for await (const chunk of iterable) {
        const text = extractText(chunk);
        if (text) {
          const { halt } = this.processToken(text);
          if (halt) {
            this.finalize();
            return;
          }
        }
        yield chunk;
      }
    } catch (err) {
      this._streamError = err;
      this.finalize();
      throw err;
    }

    this.finalize();
  }

  /**
   * Wrap an Anthropic SDK message stream.
   *
   * Anthropic streams yield events with structure:
   *   { type: 'content_block_delta', delta: { type: 'text_delta', text: '...' } }
   *
   * @param {AsyncIterable} stream - Anthropic stream from client.messages.create({ stream: true }).
   * @returns {AsyncGenerator} Yields the same events with scanning applied.
   */
  wrapAnthropicStream(stream) {
    return this.wrap(stream, {
      extractText: _anthropicTextExtractor
    });
  }

  /**
   * Wrap an OpenAI SDK chat completion stream.
   *
   * OpenAI streams yield chunks with structure:
   *   { choices: [{ delta: { content: '...' } }] }
   *
   * @param {AsyncIterable} stream - OpenAI stream from openai.chat.completions.create({ stream: true }).
   * @returns {AsyncGenerator} Yields the same chunks with scanning applied.
   */
  wrapOpenAIStream(stream) {
    return this.wrap(stream, {
      extractText: _openAITextExtractor
    });
  }

  /**
   * Wrap a Node.js ReadableStream or Web ReadableStream.
   *
   * @param {ReadableStream|NodeJS.ReadableStream} stream - A readable stream emitting text.
   * @returns {AsyncGenerator} Yields decoded text chunks with scanning applied.
   */
  wrapReadableStream(stream) {
    const iterable = _readableStreamToAsyncIterable(stream);
    return this.wrap(iterable);
  }

  /**
   * Wrap an EventEmitter that emits 'data' events with string payloads.
   *
   * @param {EventEmitter} emitter - An EventEmitter emitting 'data', 'end', and optionally 'error'.
   * @returns {AsyncGenerator} Yields data payloads with scanning applied.
   */
  wrapEventEmitter(emitter) {
    const iterable = _eventEmitterToAsyncIterable(emitter);
    return this.wrap(iterable);
  }
}

// =========================================================================
// Text Extractors
// =========================================================================

/**
 * Default text extractor. Handles strings, and objects with .text or .content.
 * @param {*} chunk
 * @returns {string|null}
 * @private
 */
function _defaultTextExtractor(chunk) {
  if (typeof chunk === 'string') return chunk;
  if (chunk && typeof chunk === 'object') {
    if (typeof chunk.text === 'string') return chunk.text;
    if (typeof chunk.content === 'string') return chunk.content;
  }
  return null;
}

/**
 * Extract text from Anthropic SDK stream events.
 * Handles content_block_delta (primary) and text events.
 * @param {object} event
 * @returns {string|null}
 * @private
 */
function _anthropicTextExtractor(event) {
  if (!event || typeof event !== 'object') return null;
  if (event.type === 'content_block_delta' && event.delta) {
    if (event.delta.type === 'text_delta' && typeof event.delta.text === 'string') {
      return event.delta.text;
    }
  }
  if (event.type === 'text' && typeof event.text === 'string') {
    return event.text;
  }
  return null;
}

/**
 * Extract text from OpenAI SDK stream chunks.
 * Handles the choices[0].delta.content path.
 * @param {object} chunk
 * @returns {string|null}
 * @private
 */
function _openAITextExtractor(chunk) {
  if (!chunk || typeof chunk !== 'object') return null;
  if (chunk.choices && Array.isArray(chunk.choices) && chunk.choices.length > 0) {
    const delta = chunk.choices[0].delta;
    if (delta && typeof delta.content === 'string') {
      return delta.content;
    }
  }
  return null;
}

// =========================================================================
// Adapters — Convert various stream types to async iterables
// =========================================================================

/**
 * Convert a ReadableStream (Web Streams API or Node.js) to an async iterable.
 * Node.js readable streams are already async iterable and pass through directly.
 * Web ReadableStreams are adapted using getReader().
 * @param {ReadableStream|NodeJS.ReadableStream} stream
 * @returns {AsyncIterable<string>}
 * @private
 */
function _readableStreamToAsyncIterable(stream) {
  // Node.js readable streams are already async iterable
  if (stream && typeof stream[Symbol.asyncIterator] === 'function') {
    return stream;
  }

  // Web ReadableStream — use getReader()
  if (stream && typeof stream.getReader === 'function') {
    return {
      [Symbol.asyncIterator]() {
        const reader = stream.getReader();
        const decoder = new TextDecoder();
        return {
          async next() {
            const { done, value } = await reader.read();
            if (done) return { done: true, value: undefined };
            const text = typeof value === 'string' ? value : decoder.decode(value, { stream: true });
            return { done: false, value: text };
          },
          async return() {
            reader.releaseLock();
            return { done: true, value: undefined };
          }
        };
      }
    };
  }

  throw new Error(`${LOG_PREFIX} StreamScanner: unsupported stream type. Expected ReadableStream or async iterable.`);
}

/**
 * Convert an EventEmitter to an async iterable.
 * Listens for 'data', 'end', and 'error' events.
 * @param {EventEmitter} emitter
 * @returns {AsyncIterable<string>}
 * @private
 */
function _eventEmitterToAsyncIterable(emitter) {
  return {
    [Symbol.asyncIterator]() {
      const queue = [];
      let resolve = null;
      let done = false;
      let error = null;

      emitter.on('data', (chunk) => {
        const text = typeof chunk === 'string' ? chunk : chunk.toString();
        if (resolve) {
          const r = resolve;
          resolve = null;
          r({ done: false, value: text });
        } else {
          queue.push(text);
        }
      });

      emitter.on('end', () => {
        done = true;
        if (resolve) {
          const r = resolve;
          resolve = null;
          r({ done: true, value: undefined });
        }
      });

      emitter.on('error', (err) => {
        error = err;
        done = true;
        if (resolve) {
          const r = resolve;
          resolve = null;
          r(Promise.reject(err));
        }
      });

      return {
        next() {
          if (queue.length > 0) {
            return Promise.resolve({ done: false, value: queue.shift() });
          }
          if (error) {
            return Promise.reject(error);
          }
          if (done) {
            return Promise.resolve({ done: true, value: undefined });
          }
          return new Promise((r) => { resolve = r; });
        },
        return() {
          done = true;
          emitter.removeAllListeners('data');
          emitter.removeAllListeners('end');
          emitter.removeAllListeners('error');
          return Promise.resolve({ done: true, value: undefined });
        }
      };
    }
  };
}

// =========================================================================
// Convenience Functions
// =========================================================================

/**
 * Create a stream wrapper from any async iterable with a single function call.
 * Returns both the wrapped stream and the scanner instance.
 *
 * @param {AsyncIterable} stream - The stream to wrap.
 * @param {object} [options] - Options passed to StreamScanner constructor,
 *   plus an optional extractText function.
 * @param {Function} [options.extractText] - Custom text extractor for each chunk.
 * @returns {{ stream: AsyncGenerator, scanner: StreamScanner }}
 *
 * @example
 * const { stream, scanner } = createStreamWrapper(rawStream, {
 *   haltOnSeverity: 'critical'
 * });
 * for await (const chunk of stream) {
 *   process.stdout.write(chunk);
 * }
 * const result = scanner.getResult();
 */
function createStreamWrapper(stream, options = {}) {
  const extractText = options.extractText;
  const scannerOpts = { ...options };
  delete scannerOpts.extractText;

  const scanner = new StreamScanner(scannerOpts);
  const wrapped = scanner.wrap(stream, { extractText });

  return { stream: wrapped, scanner };
}

/**
 * Scan an async iterator to completion and return the full result.
 * Consumes the entire iterator — tokens are collected but not re-emitted.
 *
 * @param {AsyncIterable} iterator - The async iterable to scan.
 * @param {object} [options] - Options passed to StreamScanner constructor,
 *   plus an optional extractText function.
 * @param {Function} [options.extractText] - Custom text extractor for each chunk.
 * @returns {Promise<{ text: string, result: object }>}
 *   The full accumulated text and the scan result.
 *
 * @example
 * const { text, result } = await scanAsyncIterator(stream);
 * if (result.status === 'danger') {
 *   console.log('Critical threat in streamed response');
 * }
 */
async function scanAsyncIterator(iterator, options = {}) {
  const extractText = options.extractText;
  const scannerOpts = { ...options };
  delete scannerOpts.extractText;

  const scanner = new StreamScanner(scannerOpts);
  const wrapped = scanner.wrap(iterator, { extractText });

  // Consume the wrapped iterator fully
  // eslint-disable-next-line no-unused-vars
  for await (const _chunk of wrapped) {
    // consumed — side effect is the scanning
  }

  return {
    text: scanner.buffer.getFullText(),
    result: scanner.getResult()
  };
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
  StreamScanner,
  StreamBuffer,
  createStreamWrapper,
  scanAsyncIterator
};
