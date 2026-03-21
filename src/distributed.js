'use strict';

/**
 * Agent Shield — Distributed Scanning (v2.1)
 *
 * Share threat state, scan results, and pattern updates across multiple
 * Agent Shield instances. Includes an in-memory adapter for single-process
 * use and adapter interfaces for Redis, Memcached, etc.
 *
 * Zero dependencies — uses Node.js built-in modules only.
 */

const crypto = require('crypto');
const { EventEmitter } = require('events');
const { createShieldError } = require('./errors');

// =========================================================================
// ADAPTER INTERFACE
// =========================================================================

/**
 * Base adapter class. Extend this for custom backends (Redis, Memcached, etc.).
 */
class DistributedAdapter extends EventEmitter {
  /**
   * Store a value.
   * @param {string} key
   * @param {*} value
   * @param {number} [ttlMs] - Time-to-live in milliseconds.
   * @returns {Promise<void>}
   */
  async set(key, value, ttlMs) { throw new Error('Not implemented'); }

  /**
   * Retrieve a value.
   * @param {string} key
   * @returns {Promise<*>}
   */
  async get(key) { throw new Error('Not implemented'); }

  /**
   * Delete a key.
   * @param {string} key
   * @returns {Promise<boolean>}
   */
  async del(key) { throw new Error('Not implemented'); }

  /**
   * Publish a message to a channel.
   * @param {string} channel
   * @param {*} message
   * @returns {Promise<void>}
   */
  async publish(channel, message) { throw new Error('Not implemented'); }

  /**
   * Subscribe to a channel.
   * @param {string} channel
   * @param {Function} handler
   * @returns {Promise<void>}
   */
  async subscribe(channel, handler) { throw new Error('Not implemented'); }

  /**
   * Increment a counter atomically.
   * @param {string} key
   * @param {number} [amount=1]
   * @returns {Promise<number>} New value.
   */
  async incr(key, amount = 1) { throw new Error('Not implemented'); }
}

// =========================================================================
// IN-MEMORY ADAPTER
// =========================================================================

/**
 * In-memory adapter for single-process or testing use.
 */
class MemoryAdapter extends DistributedAdapter {
  constructor() {
    super();
    this._store = new Map();
    this._subscriptions = new Map();
    this._timers = new Map();
  }

  async set(key, value, ttlMs) {
    this._store.set(key, value);
    if (ttlMs) {
      if (this._timers.has(key)) clearTimeout(this._timers.get(key));
      this._timers.set(key, setTimeout(() => {
        this._store.delete(key);
        this._timers.delete(key);
      }, ttlMs));
    }
  }

  async get(key) {
    return this._store.get(key) || null;
  }

  async del(key) {
    if (this._timers.has(key)) clearTimeout(this._timers.get(key));
    this._timers.delete(key);
    return this._store.delete(key);
  }

  async publish(channel, message) {
    const handlers = this._subscriptions.get(channel) || [];
    for (const handler of handlers) {
      handler(message);
    }
  }

  async subscribe(channel, handler) {
    if (!this._subscriptions.has(channel)) {
      this._subscriptions.set(channel, []);
    }
    this._subscriptions.get(channel).push(handler);
  }

  async incr(key, amount = 1) {
    const current = this._store.get(key) || 0;
    const newVal = current + amount;
    this._store.set(key, newVal);
    return newVal;
  }

  /**
   * Get all keys matching a prefix.
   * @param {string} prefix
   * @returns {Promise<string[]>}
   */
  async keys(prefix) {
    return [...this._store.keys()].filter(k => k.startsWith(prefix));
  }

  destroy() {
    for (const timer of this._timers.values()) clearTimeout(timer);
    this._timers.clear();
    this._store.clear();
    this._subscriptions.clear();
  }
}

// =========================================================================
// REDIS ADAPTER TEMPLATE
// =========================================================================

/**
 * Redis adapter template. Users provide their own redis client instance.
 * Usage: new RedisAdapter({ client: require('redis').createClient() })
 */
class RedisAdapter extends DistributedAdapter {
  /**
   * @param {object} options
   * @param {object} options.client - A Redis client instance (e.g., ioredis or node-redis).
   * @param {string} [options.prefix='agent-shield:'] - Key prefix.
   */
  constructor(options = {}) {
    super();
    this.client = options.client;
    this.prefix = options.prefix || 'agent-shield:';

    if (!this.client) {
      throw createShieldError('AS-NET-003', { reason: 'RedisAdapter requires a Redis client instance. Pass { client: redisClient }.' });
    }
  }

  async set(key, value, ttlMs) {
    const serialized = JSON.stringify(value);
    if (ttlMs) {
      await this.client.set(this.prefix + key, serialized, 'PX', ttlMs);
    } else {
      await this.client.set(this.prefix + key, serialized);
    }
  }

  async get(key) {
    const result = await this.client.get(this.prefix + key);
    return result ? JSON.parse(result) : null;
  }

  async del(key) {
    const result = await this.client.del(this.prefix + key);
    return result > 0;
  }

  async publish(channel, message) {
    await this.client.publish(this.prefix + channel, JSON.stringify(message));
  }

  async subscribe(channel, handler) {
    const subscriber = this.client.duplicate();
    await subscriber.subscribe(this.prefix + channel);
    subscriber.on('message', (ch, msg) => {
      try {
        handler(JSON.parse(msg));
      } catch (e) {
        handler(msg);
      }
    });
  }

  async incr(key, amount = 1) {
    return this.client.incrby(this.prefix + key, amount);
  }
}

// =========================================================================
// DISTRIBUTED SHIELD
// =========================================================================

/**
 * Coordinates multiple Agent Shield instances sharing threat state.
 */
class DistributedShield {
  /**
   * @param {object} [options]
   * @param {DistributedAdapter} [options.adapter] - Storage adapter (defaults to MemoryAdapter).
   * @param {string} [options.instanceId] - Unique ID for this instance.
   * @param {number} [options.syncIntervalMs=30000] - How often to sync state.
   * @param {number} [options.threatTTLMs=3600000] - How long threats persist (1 hour default).
   */
  constructor(options = {}) {
    this.adapter = options.adapter || new MemoryAdapter();
    this.instanceId = options.instanceId || crypto.randomBytes(8).toString('hex');
    this.syncIntervalMs = options.syncIntervalMs || 30000;
    this.threatTTLMs = options.threatTTLMs || 3600000;

    this._localThreats = [];
    this._maxLocalThreats = options.maxLocalThreats || 1000;
    this._syncTimer = null;
    this._started = false;

    // Queue depth monitoring
    this._pendingOps = 0;
    this._peakQueueDepth = 0;
    this._totalOpsQueued = 0;

    console.log('[Agent Shield] DistributedShield initialized (instance: %s)', this.instanceId);
  }

  /**
   * Start distributed coordination.
   * @returns {Promise<void>}
   */
  async start() {
    if (this._started) return;
    this._started = true;

    // Register this instance
    await this.adapter.set(`instance:${this.instanceId}`, {
      id: this.instanceId,
      startedAt: Date.now(),
      lastHeartbeat: Date.now()
    }, this.threatTTLMs);

    // Subscribe to threat broadcasts
    await this.adapter.subscribe('threats', (threat) => {
      if (threat.instanceId !== this.instanceId) {
        this._localThreats.push(threat);
        if (this._localThreats.length > this._maxLocalThreats) {
          this._localThreats = this._localThreats.slice(-Math.floor(this._maxLocalThreats * 0.75));
        }
        console.log('[Agent Shield] Received threat from instance %s: %s', threat.instanceId, threat.category);
      }
    });

    // Heartbeat
    this._syncTimer = setInterval(async () => {
      await this.adapter.set(`instance:${this.instanceId}`, {
        id: this.instanceId,
        startedAt: Date.now(),
        lastHeartbeat: Date.now()
      }, this.threatTTLMs);
    }, this.syncIntervalMs);
    if (this._syncTimer.unref) this._syncTimer.unref();

    console.log('[Agent Shield] DistributedShield started');
  }

  /**
   * Report a detected threat to all instances.
   * @param {object} threat - Threat object from a scan result.
   * @returns {Promise<void>}
   */
  async reportThreat(threat) {
    this._trackOp(1);
    try {
      const entry = {
        ...threat,
        instanceId: this.instanceId,
        timestamp: Date.now(),
        id: crypto.randomBytes(8).toString('hex')
      };

      // Store in shared state
      await this.adapter.set(`threat:${entry.id}`, entry, this.threatTTLMs);
      await this.adapter.incr('stats:totalThreats');
      await this.adapter.incr(`stats:category:${threat.category || 'unknown'}`);

      // Broadcast to other instances
      await this.adapter.publish('threats', entry);

      this._localThreats.push(entry);
      if (this._localThreats.length > this._maxLocalThreats) {
        this._localThreats = this._localThreats.slice(-Math.floor(this._maxLocalThreats * 0.75));
      }
    } finally {
      this._trackOp(-1);
    }
  }

  /**
   * Get aggregated threat statistics across all instances.
   * @returns {Promise<object>}
   */
  async getGlobalStats() {
    const totalThreats = await this.adapter.get('stats:totalThreats') || 0;

    return {
      instanceId: this.instanceId,
      totalThreats,
      localThreats: this._localThreats.length,
      started: this._started
    };
  }

  /**
   * Check if a threat signature has been seen by any instance.
   * @param {string} signature - Threat hash/signature.
   * @returns {Promise<boolean>}
   */
  async isKnownThreat(signature) {
    const result = await this.adapter.get(`threat:sig:${signature}`);
    return result !== null;
  }

  /**
   * Mark a threat signature as known.
   * @param {string} signature
   * @param {object} [metadata]
   * @returns {Promise<void>}
   */
  async markKnownThreat(signature, metadata = {}) {
    await this.adapter.set(`threat:sig:${signature}`, {
      ...metadata,
      firstSeen: Date.now(),
      reportedBy: this.instanceId
    }, this.threatTTLMs);
  }

  /**
   * Returns queue depth metrics for monitoring.
   * @returns {{ pending: number, peak: number, totalQueued: number }}
   */
  getQueueDepth() {
    return {
      pending: this._pendingOps,
      peak: this._peakQueueDepth,
      totalQueued: this._totalOpsQueued
    };
  }

  /**
   * Track pending async operations for queue depth monitoring.
   * @param {number} delta - +1 when starting, -1 when completing.
   * @private
   */
  _trackOp(delta) {
    this._pendingOps += delta;
    if (delta > 0) this._totalOpsQueued++;
    if (this._pendingOps > this._peakQueueDepth) {
      this._peakQueueDepth = this._pendingOps;
    }
  }

  /**
   * Stop distributed coordination.
   */
  async stop() {
    if (this._syncTimer) {
      clearInterval(this._syncTimer);
      this._syncTimer = null;
    }
    this._started = false;
    await this.adapter.del(`instance:${this.instanceId}`);
    console.log('[Agent Shield] DistributedShield stopped');
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
  DistributedShield,
  DistributedAdapter,
  MemoryAdapter,
  RedisAdapter
};
