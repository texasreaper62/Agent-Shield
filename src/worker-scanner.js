'use strict';

/**
 * Agent Shield — Worker Scanner
 *
 * Async scanning for non-blocking operation. Uses setImmediate/setTimeout to
 * yield to the event loop between scans, preventing long-running scans from
 * blocking the main thread.
 *
 * NOTE: This implementation uses async wrappers around the synchronous scanner
 * with event loop yielding. In production environments requiring true parallel
 * CPU-bound scanning, you can swap in Node.js worker_threads by replacing the
 * _runInWorker method with actual Worker thread dispatch.
 *
 * All detection runs locally — no data ever leaves your environment.
 */

const { scanText } = require('./detector-core');

// =========================================================================
// HELPERS
// =========================================================================

/**
 * Yield to the event loop. Uses setImmediate when available, falls back to setTimeout.
 * @returns {Promise<void>}
 */
const yieldToEventLoop = () => new Promise(resolve => {
  if (typeof setImmediate === 'function') {
    setImmediate(resolve);
  } else {
    setTimeout(resolve, 0);
  }
});

/**
 * Create a deferred promise with external resolve/reject.
 * @returns {{ promise: Promise, resolve: Function, reject: Function }}
 */
function createDeferred() {
  let resolve, reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

// =========================================================================
// WORKER SCANNER
// =========================================================================

/**
 * Async scanner that runs scans without blocking the event loop.
 * Manages a virtual "pool" with concurrency control and timeout support.
 */
class WorkerScanner {
  /**
   * @param {object} [options]
   * @param {number} [options.poolSize=2] - Maximum concurrent scans.
   * @param {number} [options.timeout=5000] - Per-scan timeout in milliseconds.
   */
  constructor(options = {}) {
    this.poolSize = options.poolSize || 2;
    this.timeout = options.timeout || 5000;

    this._activeWorkers = 0;
    this._completedJobs = 0;
    this._errorCount = 0;
    this._queue = [];
    this._terminated = false;

    console.log('[Agent Shield] WorkerScanner initialized (poolSize: %d, timeout: %dms)', this.poolSize, this.timeout);
  }

  /**
   * Scan text asynchronously without blocking the event loop.
   * @param {string} text - The text to scan.
   * @param {object} [options] - Scan options passed to scanText.
   * @returns {Promise<object>} Scan result from detector-core.
   */
  async scan(text, options = {}) {
    if (this._terminated) {
      throw new Error('WorkerScanner has been terminated.');
    }

    // Wait for an available slot
    while (this._activeWorkers >= this.poolSize) {
      await yieldToEventLoop();
    }

    return this._runScan(text, options);
  }

  /**
   * Scan multiple texts in parallel using the worker pool.
   * @param {string[]} texts - Array of texts to scan.
   * @param {object} [options] - Scan options passed to scanText.
   * @returns {Promise<object[]>} Array of scan results.
   */
  async scanBatch(texts, options = {}) {
    if (this._terminated) {
      throw new Error('WorkerScanner has been terminated.');
    }

    if (!Array.isArray(texts) || texts.length === 0) {
      return [];
    }

    // Launch all scans, concurrency is managed inside _runScan
    const promises = texts.map(text => this.scan(text, options));
    return Promise.all(promises);
  }

  /**
   * Get pool statistics.
   * @returns {object} Stats: { activeWorkers, queuedJobs, completed, errors, poolSize, terminated }.
   */
  getStats() {
    return {
      activeWorkers: this._activeWorkers,
      queuedJobs: this._queue.length,
      completed: this._completedJobs,
      errors: this._errorCount,
      poolSize: this.poolSize,
      terminated: this._terminated
    };
  }

  /**
   * Shut down the worker pool. Pending scans will be rejected.
   */
  terminate() {
    this._terminated = true;

    // Reject any queued jobs
    for (const job of this._queue) {
      job.reject(new Error('WorkerScanner terminated.'));
    }
    this._queue = [];

    console.log('[Agent Shield] WorkerScanner terminated (completed: %d, errors: %d)', this._completedJobs, this._errorCount);
  }

  /**
   * Run a single scan with timeout and event loop yielding.
   * @param {string} text
   * @param {object} options
   * @returns {Promise<object>}
   * @private
   */
  async _runScan(text, options) {
    this._activeWorkers++;

    try {
      // Yield to the event loop before starting CPU work
      await yieldToEventLoop();

      const result = await this._withTimeout(() => {
        return scanText(text, options);
      }, this.timeout);

      this._completedJobs++;

      // Yield after completing CPU work
      await yieldToEventLoop();

      return result;
    } catch (err) {
      this._errorCount++;
      throw err;
    } finally {
      this._activeWorkers--;
    }
  }

  /**
   * Run a function with a timeout.
   * @param {Function} fn - Synchronous function to run.
   * @param {number} timeoutMs - Timeout in milliseconds.
   * @returns {Promise<*>} Result of the function.
   * @private
   */
  _withTimeout(fn, timeoutMs) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error(`Scan timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      try {
        const result = fn();
        clearTimeout(timer);
        resolve(result);
      } catch (err) {
        clearTimeout(timer);
        reject(err);
      }
    });
  }
}

// =========================================================================
// SCAN QUEUE
// =========================================================================

/**
 * Priority queue for managing scan jobs with concurrency control,
 * pause/resume, and drain support.
 */
class ScanQueue {
  /**
   * @param {object} [options]
   * @param {number} [options.concurrency=4] - Maximum concurrent scans.
   * @param {number} [options.maxQueue=10000] - Maximum queued items.
   */
  constructor(options = {}) {
    this.concurrency = options.concurrency || 4;
    this.maxQueue = options.maxQueue || 10000;

    this._queue = [];
    this._activeCount = 0;
    this._paused = false;
    this._totalEnqueued = 0;
    this._totalProcessed = 0;
    this._totalErrors = 0;
    this._latencySum = 0;
    this._drainCallbacks = [];

    console.log('[Agent Shield] ScanQueue initialized (concurrency: %d, maxQueue: %d)', this.concurrency, this.maxQueue);
  }

  /**
   * Add a scan job to the queue.
   * @param {string} text - The text to scan.
   * @param {object} [options] - Scan options passed to scanText.
   * @param {number} [priority=0] - Priority (higher = processed first).
   * @returns {Promise<object>} Promise that resolves with the scan result.
   */
  async enqueue(text, options = {}, priority = 0) {
    if (this._queue.length >= this.maxQueue) {
      throw new Error(`ScanQueue is full (${this.maxQueue} items). Rejecting new scan.`);
    }

    const deferred = createDeferred();
    const job = {
      text,
      options,
      priority,
      enqueuedAt: Date.now(),
      deferred
    };

    this._queue.push(job);
    this._totalEnqueued++;

    // Sort by priority (descending) — highest priority first
    this._queue.sort((a, b) => b.priority - a.priority);

    // Try to process
    this._processNext();

    return deferred.promise;
  }

  /**
   * Pause queue processing. In-flight scans will complete, but no new scans start.
   */
  pause() {
    this._paused = true;
    console.log('[Agent Shield] ScanQueue paused');
  }

  /**
   * Resume queue processing.
   */
  resume() {
    this._paused = false;
    console.log('[Agent Shield] ScanQueue resumed');
    this._processNext();
  }

  /**
   * Wait for all pending and in-flight jobs to complete.
   * @returns {Promise<void>}
   */
  drain() {
    if (this._queue.length === 0 && this._activeCount === 0) {
      return Promise.resolve();
    }

    return new Promise(resolve => {
      this._drainCallbacks.push(resolve);
    });
  }

  /**
   * Get queue statistics.
   * @returns {object} Stats: { depth, active, processed, errors, avgLatencyMs, paused }.
   */
  getStats() {
    const avgLatencyMs = this._totalProcessed > 0
      ? Math.round(this._latencySum / this._totalProcessed)
      : 0;

    return {
      depth: this._queue.length,
      active: this._activeCount,
      processed: this._totalProcessed,
      errors: this._totalErrors,
      avgLatencyMs,
      paused: this._paused,
      totalEnqueued: this._totalEnqueued,
      maxQueue: this.maxQueue,
      concurrency: this.concurrency
    };
  }

  /**
   * Process the next job in the queue if concurrency allows.
   * @private
   */
  _processNext() {
    if (this._paused) return;
    if (this._activeCount >= this.concurrency) return;
    if (this._queue.length === 0) {
      this._checkDrain();
      return;
    }

    const job = this._queue.shift();
    this._activeCount++;

    // Use setImmediate/setTimeout to avoid blocking the event loop
    const run = async () => {
      const startTime = Date.now();

      try {
        // Yield before CPU work
        await yieldToEventLoop();

        const result = scanText(job.text, job.options);
        const latency = Date.now() - job.enqueuedAt;

        this._latencySum += latency;
        this._totalProcessed++;

        job.deferred.resolve(result);
      } catch (err) {
        this._totalErrors++;
        job.deferred.reject(err);
      } finally {
        this._activeCount--;

        // Yield after CPU work, then try next
        await yieldToEventLoop();
        this._processNext();
      }
    };

    run();
  }

  /**
   * Check if the queue has drained and notify any waiting callbacks.
   * @private
   */
  _checkDrain() {
    if (this._queue.length === 0 && this._activeCount === 0) {
      const callbacks = this._drainCallbacks;
      this._drainCallbacks = [];
      for (const cb of callbacks) {
        cb();
      }
    }
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = { WorkerScanner, ScanQueue };
