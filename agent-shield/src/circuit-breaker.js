'use strict';

/**
 * Circuit Breaker (#31), Shadow Mode (#33), and Rate Limiting (#5)
 *
 * - Circuit Breaker: Auto-shuts down an agent after too many threats in a time window.
 * - Shadow Mode: Detection-only mode — logs everything, blocks nothing.
 * - Rate Limiting: Tracks input patterns and flags anomalous spikes.
 */

/**
 * Circuit breaker states.
 */
const STATE = {
  CLOSED: 'closed',     // Normal operation
  OPEN: 'open',         // Tripped — all requests blocked
  HALF_OPEN: 'half_open' // Testing if safe to resume
};

class CircuitBreaker {
  /**
   * @param {object} [options]
   * @param {number} [options.threshold=5] - Number of threats to trip the breaker.
   * @param {number} [options.windowMs=60000] - Time window in ms (default: 1 minute).
   * @param {number} [options.cooldownMs=300000] - Cooldown before half-open (default: 5 minutes).
   * @param {Function} [options.onTrip] - Callback when breaker trips.
   * @param {Function} [options.onReset] - Callback when breaker resets.
   */
  constructor(options = {}) {
    this.threshold = options.threshold || 5;
    this.windowMs = options.windowMs || 60000;
    this.cooldownMs = options.cooldownMs || 300000;
    this.onTrip = options.onTrip || null;
    this.onReset = options.onReset || null;

    this.state = STATE.CLOSED;
    this.threatTimestamps = [];
    this.trippedAt = null;
  }

  /**
   * Records a threat event. Trips the breaker if threshold is exceeded.
   * @param {number} [count=1] - Number of threats to record.
   */
  recordThreat(count = 1) {
    const now = Date.now();
    for (let i = 0; i < count; i++) {
      this.threatTimestamps.push(now);
    }

    // Prune old timestamps outside the window
    const cutoff = now - this.windowMs;
    this.threatTimestamps = this.threatTimestamps.filter(t => t > cutoff);

    if (this.state === STATE.CLOSED && this.threatTimestamps.length >= this.threshold) {
      this._trip();
    }
  }

  /**
   * Checks if the breaker allows a request through.
   * @returns {object} { allowed: boolean, state: string, reason?: string }
   */
  check() {
    if (this.state === STATE.CLOSED) {
      return { allowed: true, state: this.state };
    }

    if (this.state === STATE.OPEN) {
      const elapsed = Date.now() - this.trippedAt;
      if (elapsed >= this.cooldownMs) {
        this.state = STATE.HALF_OPEN;
        return { allowed: true, state: this.state, reason: 'Testing after cooldown' };
      }
      const remainingMs = this.cooldownMs - elapsed;
      return {
        allowed: false,
        state: this.state,
        reason: `Circuit breaker tripped. Resumes in ${Math.ceil(remainingMs / 1000)}s.`
      };
    }

    // HALF_OPEN: allow one request to test
    return { allowed: true, state: this.state, reason: 'Half-open test request' };
  }

  /**
   * Reports the result of a half-open test request.
   * @param {boolean} safe - Whether the test request was safe.
   */
  reportTestResult(safe) {
    if (this.state !== STATE.HALF_OPEN) return;

    if (safe) {
      this._reset();
    } else {
      this._trip();
    }
  }

  /** @private */
  _trip() {
    this.state = STATE.OPEN;
    this.trippedAt = Date.now();
    if (this.onTrip) {
      this.onTrip({
        state: STATE.OPEN,
        threatCount: this.threatTimestamps.length,
        timestamp: this.trippedAt
      });
    }
  }

  /** @private */
  _reset() {
    this.state = STATE.CLOSED;
    this.threatTimestamps = [];
    this.trippedAt = null;
    if (this.onReset) {
      this.onReset({ state: STATE.CLOSED, timestamp: Date.now() });
    }
  }

  /**
   * Manually reset the breaker.
   */
  reset() {
    this._reset();
  }

  /**
   * Returns current breaker status.
   * @returns {object}
   */
  getStatus() {
    return {
      state: this.state,
      recentThreats: this.threatTimestamps.length,
      threshold: this.threshold,
      trippedAt: this.trippedAt
    };
  }
}

// =========================================================================
// SHADOW MODE
// =========================================================================

/**
 * Wraps an AgentShield instance in shadow mode.
 * Logs all detections but never blocks. Perfect for evaluation.
 *
 * @param {object} shield - An AgentShield instance.
 * @param {object} [options]
 * @param {Function} [options.logger] - Custom log function. Defaults to console.log.
 * @returns {object} - A shadow-mode wrapped shield with the same API.
 */
const shadowMode = (shield, options = {}) => {
  const logger = options.logger || console.log;
  const log = [];

  const wrap = (methodName, original) => {
    return function (...args) {
      const result = original.apply(shield, args);

      // If it's a promise (async methods like from middleware), handle accordingly
      if (result && typeof result.then === 'function') {
        return result.then(res => {
          const entry = { method: methodName, result: res, timestamp: Date.now() };
          log.push(entry);
          if (log.length > 1000) log.shift();
          if (res.threats && res.threats.length > 0) {
            logger(`[Agent Shield Shadow] ${methodName}: ${res.threats.length} threat(s) detected (not blocked)`, res.threats.map(t => t.description));
          }
          // Never block in shadow mode
          if ('blocked' in res) res.blocked = false;
          return res;
        });
      }

      const entry = { method: methodName, result, timestamp: Date.now() };
      log.push(entry);
      if (log.length > 1000) log.shift();

      if (result.threats && result.threats.length > 0) {
        logger(`[Agent Shield Shadow] ${methodName}: ${result.threats.length} threat(s) detected (not blocked)`, result.threats.map(t => t.description));
      }

      // Never block in shadow mode
      if ('blocked' in result) result.blocked = false;
      return result;
    };
  };

  return {
    scan: wrap('scan', shield.scan),
    scanInput: wrap('scanInput', shield.scanInput),
    scanOutput: wrap('scanOutput', shield.scanOutput),
    scanToolCall: wrap('scanToolCall', shield.scanToolCall),
    scanBatch: wrap('scanBatch', shield.scanBatch),
    getStats: () => shield.getStats(),
    getLog: () => [...log],
    isShadowMode: true
  };
};

// =========================================================================
// RATE LIMITER
// =========================================================================

class RateLimiter {
  /**
   * @param {object} [options]
   * @param {number} [options.maxRequests=100] - Max requests per window.
   * @param {number} [options.windowMs=60000] - Window size in ms.
   * @param {number} [options.maxThreatsPerWindow=10] - Max threats before flagging anomaly.
   * @param {Function} [options.onLimit] - Callback when rate limit hit.
   * @param {Function} [options.onAnomaly] - Callback when anomaly detected.
   */
  constructor(options = {}) {
    this.maxRequests = options.maxRequests || 100;
    this.windowMs = options.windowMs || 60000;
    this.maxThreatsPerWindow = options.maxThreatsPerWindow || 10;
    this.onLimit = options.onLimit || null;
    this.onAnomaly = options.onAnomaly || null;

    this.requestTimestamps = [];
    this.threatTimestamps = [];
  }

  /**
   * Records a request. Returns whether it's allowed.
   * @returns {object} { allowed: boolean, remaining: number, reason?: string }
   */
  recordRequest() {
    const now = Date.now();
    const cutoff = now - this.windowMs;

    this.requestTimestamps = this.requestTimestamps.filter(t => t > cutoff);
    this.requestTimestamps.push(now);

    if (this.requestTimestamps.length > this.maxRequests) {
      if (this.onLimit) {
        this.onLimit({ count: this.requestTimestamps.length, windowMs: this.windowMs });
      }
      return {
        allowed: false,
        remaining: 0,
        reason: `Rate limit exceeded: ${this.requestTimestamps.length}/${this.maxRequests} requests in ${this.windowMs / 1000}s`
      };
    }

    return {
      allowed: true,
      remaining: this.maxRequests - this.requestTimestamps.length
    };
  }

  /**
   * Records threat detections. Flags anomalies if spike detected.
   * @param {number} [count=1] - Number of threats.
   * @returns {object} { anomaly: boolean, threatCount: number }
   */
  recordThreat(count = 1) {
    const now = Date.now();
    const cutoff = now - this.windowMs;

    for (let i = 0; i < count; i++) {
      this.threatTimestamps.push(now);
    }
    this.threatTimestamps = this.threatTimestamps.filter(t => t > cutoff);

    const isAnomaly = this.threatTimestamps.length >= this.maxThreatsPerWindow;
    if (isAnomaly && this.onAnomaly) {
      this.onAnomaly({ threatCount: this.threatTimestamps.length, windowMs: this.windowMs });
    }

    return {
      anomaly: isAnomaly,
      threatCount: this.threatTimestamps.length
    };
  }

  /**
   * Returns current rate limiter status.
   * @returns {object}
   */
  getStatus() {
    const now = Date.now();
    const cutoff = now - this.windowMs;
    return {
      requests: this.requestTimestamps.filter(t => t > cutoff).length,
      maxRequests: this.maxRequests,
      threats: this.threatTimestamps.filter(t => t > cutoff).length,
      maxThreatsPerWindow: this.maxThreatsPerWindow
    };
  }

  reset() {
    this.requestTimestamps = [];
    this.threatTimestamps = [];
  }
}

module.exports = { CircuitBreaker, shadowMode, RateLimiter, STATE };
