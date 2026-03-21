'use strict';

/**
 * Agent Shield — Audit Log Streaming (v2.1)
 *
 * Stream security audit events to external logging/SIEM systems.
 * Supports Splunk HEC, Elasticsearch, file-based logging, and custom transports.
 *
 * Zero dependencies — uses Node.js built-in http/https/fs modules.
 */

const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');

// =========================================================================
// TRANSPORT INTERFACE
// =========================================================================

/**
 * Base transport class. Extend for custom destinations.
 */
class AuditTransport {
  /**
   * Send an event to the transport.
   * @param {object} event - Audit event.
   * @returns {Promise<void>}
   */
  async send(event) { throw new Error('Not implemented'); }

  /**
   * Send multiple events in a batch.
   * @param {Array<object>} events
   * @returns {Promise<void>}
   */
  async sendBatch(events) {
    for (const event of events) {
      await this.send(event);
    }
  }

  /**
   * Flush any buffered events.
   * @returns {Promise<void>}
   */
  async flush() {}

  /**
   * Close the transport.
   * @returns {Promise<void>}
   */
  async close() {}
}

// =========================================================================
// FILE TRANSPORT
// =========================================================================

/**
 * Writes audit events to a local file (JSONL format).
 */
class FileTransport extends AuditTransport {
  /**
   * @param {object} [options]
   * @param {string} [options.filePath='./agent-shield-audit.log'] - Log file path.
   * @param {number} [options.maxSizeMB=100] - Max file size before rotation.
   * @param {number} [options.maxFiles=5] - Number of rotated files to keep.
   */
  constructor(options = {}) {
    super();
    this.filePath = options.filePath || './agent-shield-audit.log';
    this.maxSizeBytes = (options.maxSizeMB || 100) * 1024 * 1024;
    this.maxFiles = options.maxFiles || 5;
    this._buffer = [];
    this._bufferSize = 0;
    this._flushInterval = setInterval(() => this.flush(), 5000);
    if (this._flushInterval.unref) this._flushInterval.unref();
  }

  async send(event) {
    const line = JSON.stringify(event) + '\n';
    this._buffer.push(line);
    this._bufferSize += line.length;

    if (this._bufferSize >= 64 * 1024) {
      await this.flush();
    }
  }

  async flush() {
    if (this._buffer.length === 0) return;

    const data = this._buffer.join('');
    this._buffer = [];
    this._bufferSize = 0;

    try {
      // Check rotation
      if (fs.existsSync(this.filePath)) {
        const stat = fs.statSync(this.filePath);
        if (stat.size + data.length > this.maxSizeBytes) {
          this._rotate();
        }
      }

      fs.appendFileSync(this.filePath, data);
    } catch (e) {
      console.warn('[Agent Shield] FileTransport write error:', e.message);
    }
  }

  async close() {
    clearInterval(this._flushInterval);
    await this.flush();
  }

  /** @private */
  _rotate() {
    // Delete the oldest rotated file if it exists
    const oldest = `${this.filePath}.${this.maxFiles}`;
    if (fs.existsSync(oldest)) fs.unlinkSync(oldest);

    for (let i = this.maxFiles - 1; i >= 1; i--) {
      const from = `${this.filePath}.${i}`;
      const to = `${this.filePath}.${i + 1}`;
      if (fs.existsSync(from)) {
        fs.renameSync(from, to);
      }
    }
    if (fs.existsSync(this.filePath)) {
      fs.renameSync(this.filePath, `${this.filePath}.1`);
    }
  }
}

// =========================================================================
// SPLUNK HEC TRANSPORT
// =========================================================================

/**
 * Sends audit events to Splunk via HTTP Event Collector (HEC).
 */
class SplunkTransport extends AuditTransport {
  /**
   * @param {object} options
   * @param {string} options.url - Splunk HEC URL (e.g., https://splunk:8088/services/collector/event).
   * @param {string} options.token - HEC token.
   * @param {string} [options.index='main'] - Splunk index.
   * @param {string} [options.source='agent-shield'] - Event source.
   * @param {string} [options.sourcetype='_json'] - Source type.
   * @param {number} [options.batchSize=50] - Events per batch.
   * @param {number} [options.flushIntervalMs=5000] - Auto-flush interval.
   */
  constructor(options = {}) {
    super();
    this.url = options.url;
    this.token = options.token;
    this.index = options.index || 'main';
    this.source = options.source || 'agent-shield';
    this.sourcetype = options.sourcetype || '_json';
    this.batchSize = options.batchSize || 50;
    this._buffer = [];
    this._flushInterval = setInterval(() => this.flush(), options.flushIntervalMs || 5000);
    if (this._flushInterval.unref) this._flushInterval.unref();
    this._stats = { sent: 0, errors: 0 };

    if (!this.url || !this.token) {
      console.warn('[Agent Shield] SplunkTransport: url and token are required.');
    }
  }

  async send(event) {
    this._buffer.push({
      time: event.timestamp ? event.timestamp / 1000 : Date.now() / 1000,
      source: this.source,
      sourcetype: this.sourcetype,
      index: this.index,
      event
    });

    if (this._buffer.length >= this.batchSize) {
      await this.flush();
    }
  }

  async flush() {
    if (this._buffer.length === 0 || !this.url || !this.token) return;

    const events = this._buffer.splice(0, this.batchSize);
    const payload = events.map(e => JSON.stringify(e)).join('\n');

    try {
      await this._post(this.url, payload, {
        'Authorization': `Splunk ${this.token}`,
        'Content-Type': 'application/json'
      });
      this._stats.sent += events.length;
    } catch (e) {
      this._stats.errors += events.length;
      console.warn('[Agent Shield] SplunkTransport error:', e.message);
      // Re-queue failed events (cap buffer to prevent unbounded growth)
      this._buffer.unshift(...events);
      if (this._buffer.length > this.batchSize * 20) {
        const dropped = this._buffer.length - this.batchSize * 10;
        this._buffer.splice(0, dropped);
        console.warn('[Agent Shield] SplunkTransport buffer overflow, dropped %d events', dropped);
      }
    }
  }

  async close() {
    clearInterval(this._flushInterval);
    await this.flush();
  }

  getStats() { return { ...this._stats, buffered: this._buffer.length }; }

  /** @private */
  _post(url, body, headers) {
    return new Promise((resolve, reject) => {
      const parsed = new URL(url);
      const lib = parsed.protocol === 'https:' ? https : http;
      const req = lib.request({
        hostname: parsed.hostname, port: parsed.port,
        path: parsed.pathname, method: 'POST',
        headers: { ...headers, 'Content-Length': Buffer.byteLength(body) },
        rejectUnauthorized: false, timeout: 10000
      }, (res) => {
        let data = '';
        res.on('data', c => data += c);
        res.on('end', () => resolve(data));
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
      req.write(body);
      req.end();
    });
  }
}

// =========================================================================
// ELASTICSEARCH TRANSPORT
// =========================================================================

/**
 * Sends audit events to Elasticsearch.
 */
class ElasticsearchTransport extends AuditTransport {
  /**
   * @param {object} options
   * @param {string} options.url - Elasticsearch URL (e.g., http://localhost:9200).
   * @param {string} [options.index='agent-shield-audit'] - Index name.
   * @param {string} [options.apiKey] - API key for authentication.
   * @param {number} [options.batchSize=100] - Events per bulk request.
   * @param {number} [options.flushIntervalMs=5000]
   */
  constructor(options = {}) {
    super();
    this.url = options.url;
    this.index = options.index || 'agent-shield-audit';
    this.apiKey = options.apiKey || null;
    this.batchSize = options.batchSize || 100;
    this._buffer = [];
    this._flushInterval = setInterval(() => this.flush(), options.flushIntervalMs || 5000);
    if (this._flushInterval.unref) this._flushInterval.unref();
    this._stats = { sent: 0, errors: 0 };

    if (!this.url) {
      console.warn('[Agent Shield] ElasticsearchTransport: url is required.');
    }
  }

  async send(event) {
    this._buffer.push(event);
    if (this._buffer.length >= this.batchSize) {
      await this.flush();
    }
  }

  async flush() {
    if (this._buffer.length === 0 || !this.url) return;

    const events = this._buffer.splice(0, this.batchSize);
    const dateStr = new Date().toISOString().split('T')[0].replace(/-/g, '.');
    const indexName = `${this.index}-${dateStr}`;

    // Build NDJSON bulk payload
    const lines = [];
    for (const event of events) {
      lines.push(JSON.stringify({ index: { _index: indexName } }));
      lines.push(JSON.stringify({ ...event, '@timestamp': event.timestamp || Date.now() }));
    }
    const payload = lines.join('\n') + '\n';

    const headers = { 'Content-Type': 'application/x-ndjson' };
    if (this.apiKey) headers['Authorization'] = `ApiKey ${this.apiKey}`;

    try {
      await this._post(`${this.url}/_bulk`, payload, headers);
      this._stats.sent += events.length;
    } catch (e) {
      this._stats.errors += events.length;
      console.warn('[Agent Shield] ElasticsearchTransport error:', e.message);
      // Re-queue failed events (cap buffer to prevent unbounded growth)
      this._buffer.unshift(...events);
      if (this._buffer.length > this.batchSize * 20) {
        const dropped = this._buffer.length - this.batchSize * 10;
        this._buffer.splice(0, dropped);
        console.warn('[Agent Shield] ElasticsearchTransport buffer overflow, dropped %d events', dropped);
      }
    }
  }

  async close() {
    clearInterval(this._flushInterval);
    await this.flush();
  }

  getStats() { return { ...this._stats, buffered: this._buffer.length }; }

  /** @private */
  _post(url, body, headers) {
    return new Promise((resolve, reject) => {
      const parsed = new URL(url);
      const lib = parsed.protocol === 'https:' ? https : http;
      const req = lib.request({
        hostname: parsed.hostname, port: parsed.port,
        path: parsed.pathname, method: 'POST',
        headers: { ...headers, 'Content-Length': Buffer.byteLength(body) },
        timeout: 10000
      }, (res) => {
        let data = '';
        res.on('data', c => data += c);
        res.on('end', () => resolve(data));
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
      req.write(body);
      req.end();
    });
  }
}

// =========================================================================
// AUDIT STREAM MANAGER
// =========================================================================

/**
 * Manages multiple audit transports and routes events to all of them.
 */
class AuditStreamManager {
  /**
   * @param {object} [options]
   * @param {Array<AuditTransport>} [options.transports] - Initial transports.
   * @param {boolean} [options.includeMetadata=true] - Add instance metadata to events.
   * @param {string} [options.environment='production'] - Environment label.
   */
  constructor(options = {}) {
    this._transports = options.transports || [];
    this.includeMetadata = options.includeMetadata !== false;
    this.environment = options.environment || 'production';
    this._eventCount = 0;

    console.log('[Agent Shield] AuditStreamManager initialized (%d transports)', this._transports.length);
  }

  /**
   * Add a transport.
   * @param {AuditTransport} transport
   */
  addTransport(transport) {
    this._transports.push(transport);
  }

  /**
   * Emit an audit event to all transports.
   * @param {string} type - Event type (e.g., 'scan', 'threat', 'block', 'config_change').
   * @param {object} data - Event data.
   * @returns {Promise<void>}
   */
  async emit(type, data = {}) {
    this._eventCount++;

    const event = {
      type,
      ...data,
      timestamp: Date.now(),
      eventId: `evt_${this._eventCount}_${Date.now()}`
    };

    if (this.includeMetadata) {
      event.environment = this.environment;
      event.agentShieldVersion = '2.1.0';
    }

    const promises = this._transports.map(t =>
      t.send(event).catch(e => console.warn('[Agent Shield] Transport error:', e.message))
    );

    await Promise.all(promises);
  }

  /**
   * Emit a scan event.
   * @param {object} scanResult - Result from scanText/AgentShield.
   * @param {object} [context] - Additional context.
   */
  async emitScan(scanResult, context = {}) {
    await this.emit('scan', {
      status: scanResult.status,
      threatCount: scanResult.threats ? scanResult.threats.length : 0,
      categories: scanResult.threats ? [...new Set(scanResult.threats.map(t => t.category))] : [],
      scanTimeMs: scanResult.stats ? scanResult.stats.scanTimeMs : 0,
      ...context
    });
  }

  /**
   * Emit a threat event.
   * @param {object} threat - Individual threat object.
   * @param {object} [context]
   */
  async emitThreat(threat, context = {}) {
    await this.emit('threat', {
      severity: threat.severity,
      category: threat.category,
      description: threat.description,
      confidence: threat.confidence,
      ...context
    });
  }

  /**
   * Emit a block event.
   * @param {string} reason
   * @param {object} [context]
   */
  async emitBlock(reason, context = {}) {
    await this.emit('block', { reason, ...context });
  }

  /**
   * Flush all transports.
   * @returns {Promise<void>}
   */
  async flush() {
    await Promise.all(this._transports.map(t => t.flush()));
  }

  /**
   * Close all transports.
   * @returns {Promise<void>}
   */
  async close() {
    await Promise.all(this._transports.map(t => t.close()));
  }

  /**
   * Get streaming statistics.
   * @returns {object}
   */
  getStats() {
    return {
      eventCount: this._eventCount,
      transports: this._transports.length,
      transportStats: this._transports.map((t, i) => ({
        index: i,
        type: t.constructor.name,
        stats: typeof t.getStats === 'function' ? t.getStats() : null
      }))
    };
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
  AuditStreamManager,
  AuditTransport,
  FileTransport,
  SplunkTransport,
  ElasticsearchTransport
};
