'use strict';

/**
 * Agent Shield — Observability Module
 *
 * Production-grade observability: Prometheus metrics export, structured JSON
 * logging (Datadog/Splunk/ELK), and in-memory metrics aggregation.
 * All processing runs locally — no data ever leaves your environment.
 */

// -- PrometheusExporter ------------------------------------------------------

/** Exports metrics in Prometheus exposition format. */
class PrometheusExporter {
  /** @param {object} [options] @param {string} [options.prefix=''] */
  constructor(options = {}) {
    this._prefix = options.prefix || '';
    this._counters = new Map();   // Map<name, Map<labelKey, number>>
    this._histograms = new Map(); // Map<name, Map<labelKey, number[]>>
    this._gauges = new Map();     // Map<name, Map<labelKey, number>>
  }

  /** @param {object} labels @returns {string} */
  _labelKey(labels) {
    const keys = Object.keys(labels).sort();
    return keys.length === 0 ? '' : keys.map(k => `${k}="${labels[k]}"`).join(',');
  }

  _fmt(key) { return key ? `{${key}}` : ''; }

  /**
   * Increment a counter.
   * @param {string} name @param {object} [labels={}] @param {number} [value=1]
   */
  increment(name, labels = {}, value = 1) {
    const full = this._prefix + name;
    if (!this._counters.has(full)) this._counters.set(full, new Map());
    const key = this._labelKey(labels);
    const map = this._counters.get(full);
    map.set(key, (map.get(key) || 0) + value);
  }

  /**
   * Observe a histogram value.
   * @param {string} name @param {number} value @param {object} [labels={}]
   */
  observe(name, value, labels = {}) {
    const full = this._prefix + name;
    if (!this._histograms.has(full)) this._histograms.set(full, new Map());
    const key = this._labelKey(labels);
    const map = this._histograms.get(full);
    if (!map.has(key)) map.set(key, []);
    map.get(key).push(value);
  }

  /**
   * Set a gauge value.
   * @param {string} name @param {number} value @param {object} [labels={}]
   */
  set(name, value, labels = {}) {
    const full = this._prefix + name;
    if (!this._gauges.has(full)) this._gauges.set(full, new Map());
    this._gauges.get(full).set(this._labelKey(labels), value);
  }

  /**
   * Returns all metrics in Prometheus exposition text format.
   * @returns {string}
   */
  metrics() {
    const lines = [];
    for (const [name, map] of this._counters) {
      lines.push(`# TYPE ${name} counter`);
      for (const [key, val] of map) {
        lines.push(`${name}${this._fmt(key)} ${val}`);
      }
    }
    for (const [name, map] of this._histograms) {
      lines.push(`# TYPE ${name} histogram`);
      for (const [key, values] of map) {
        const sorted = values.slice().sort((a, b) => a - b);
        const sum = values.reduce((a, b) => a + b, 0);
        const count = values.length;
        const extra = key ? `,${key}` : '';
        const buckets = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10];
        for (const b of buckets) {
          lines.push(`${name}_bucket{le="${b}"${extra}} ${sorted.filter(v => v <= b).length}`);
        }
        lines.push(`${name}_bucket{le="+Inf"${extra}} ${count}`);
        lines.push(`${name}_sum${this._fmt(key)} ${sum}`);
        lines.push(`${name}_count${this._fmt(key)} ${count}`);
      }
    }
    for (const [name, map] of this._gauges) {
      lines.push(`# TYPE ${name} gauge`);
      for (const [key, val] of map) {
        lines.push(`${name}${this._fmt(key)} ${val}`);
      }
    }
    return lines.join('\n') + '\n';
  }

  /**
   * Wraps an AgentShield instance to auto-record metrics on every scan.
   * Pre-built metrics: shield_scans_total, shield_threats_total,
   * shield_scan_duration_seconds, shield_blocks_total.
   * @param {object} shield - An AgentShield instance.
   * @returns {object} The same shield instance (mutated).
   */
  wrapShield(shield) {
    const exporter = this;
    const origScan = shield.scan.bind(shield);
    shield.scan = function wrappedScan(text, options = {}) {
      const start = Date.now();
      const result = origScan(text, options);
      const durationSec = (Date.now() - start) / 1000;
      const source = options.source || 'unknown';
      exporter.increment('shield_scans_total', { source });
      exporter.observe('shield_scan_duration_seconds', durationSec, { source });
      if (result.threats && result.threats.length > 0) {
        for (const threat of result.threats) {
          exporter.increment('shield_threats_total', {
            severity: threat.severity || 'unknown',
            category: threat.category || 'unknown'
          });
        }
      }
      if (result.blocked) {
        exporter.increment('shield_blocks_total', { source });
      }
      return result;
    };
    console.log('[Agent Shield] Prometheus metrics wired to shield instance');
    return shield;
  }
}

// -- DatadogLogger -----------------------------------------------------------

/**
 * Structured JSON logger formatted for Datadog, Splunk, and ELK ingestion.
 * Buffers log entries and flushes to stdout.
 */
class DatadogLogger {
  /**
   * @param {object} [options]
   * @param {string} [options.service='agent-shield'] - Service name.
   * @param {string} [options.env='production'] - Environment name.
   * @param {string} [options.version='1.0.0'] - Service version.
   * @param {number} [options.maxSize=100] - Max buffer size before auto-flush.
   * @param {function} [options.writer] - Custom writer fn (default: stdout).
   */
  constructor(options = {}) {
    this.service = options.service || 'agent-shield';
    this.env = options.env || 'production';
    this.version = options.version || '1.0.0';
    this.maxSize = options.maxSize || 100;
    this._writer = options.writer || ((line) => process.stdout.write(line + '\n'));
    this._buffer = [];
  }

  /** @returns {string} Pseudo-random 64-bit hex ID. */
  _randomId() {
    let id = '';
    for (let i = 0; i < 16; i++) id += Math.floor(Math.random() * 16).toString(16);
    return id;
  }

  /**
   * Emit a structured JSON log entry.
   * @param {string} event - Event name.
   * @param {object} [data={}] - Additional data fields.
   * @param {string} [level='info'] - Log level.
   */
  log(event, data = {}, level = 'info') {
    const entry = {
      timestamp: new Date().toISOString(),
      level,
      service: this.service,
      env: this.env,
      version: this.version,
      'dd.trace_id': data['dd.trace_id'] || this._randomId(),
      'dd.span_id': data['dd.span_id'] || this._randomId(),
      event,
      ...data
    };
    this._buffer.push(entry);
    if (this._buffer.length >= this.maxSize) this.flush();
  }

  /**
   * Log a scan result.
   * @param {object} result - Scan result from AgentShield.scan().
   * @param {object} [metadata={}]
   */
  logScan(result, metadata = {}) {
    this.log('shield.scan', {
      status: result.status,
      threatCount: result.threats ? result.threats.length : 0,
      source: result.source || 'unknown',
      blocked: !!result.blocked,
      ...metadata
    }, 'info');
  }

  /**
   * Log a detected threat.
   * @param {object} threat - Threat object.
   * @param {object} [metadata={}]
   */
  logThreat(threat, metadata = {}) {
    this.log('shield.threat', {
      severity: threat.severity || 'unknown',
      category: threat.category || 'unknown',
      description: threat.description || '',
      ...metadata
    }, 'warn');
  }

  /**
   * Log a blocked request.
   * @param {string} reason - Reason for the block.
   * @param {object} [metadata={}]
   */
  logBlock(reason, metadata = {}) {
    this.log('shield.block', { reason, ...metadata }, 'error');
  }

  /** Flush the buffer: write all entries to stdout and clear. */
  flush() {
    for (const entry of this._buffer) this._writer(JSON.stringify(entry));
    this._buffer = [];
  }

  /** @returns {number} Current buffer length. */
  get bufferSize() { return this._buffer.length; }
}

// -- MetricsCollector --------------------------------------------------------

/**
 * In-memory metrics aggregation for dashboards.
 * Records scan/threat/block events and computes windowed summaries.
 */
class MetricsCollector {
  /**
   * @param {object} [options]
   * @param {number} [options.ttl=3600000] - TTL for events in ms (default 1h).
   * @param {number} [options.pruneInterval=60000] - Auto-prune interval in ms.
   */
  constructor(options = {}) {
    this.ttl = options.ttl || 3600000;
    this._events = [];
    this._pruneInterval = options.pruneInterval || 60000;
    this._timer = setInterval(() => this._prune(), this._pruneInterval);
    if (this._timer.unref) this._timer.unref();
  }

  /**
   * Record an event.
   * @param {object} event
   * @param {string} event.type - One of 'scan', 'threat', 'block'.
   * @param {number} [event.duration] - Scan duration in ms.
   * @param {string} [event.category] - Threat category.
   * @param {string} [event.severity] - Threat severity.
   */
  record(event) {
    this._events.push({ ...event, timestamp: event.timestamp || Date.now() });
  }

  /** Remove events older than the TTL. */
  _prune() {
    const cutoff = Date.now() - this.ttl;
    this._events = this._events.filter(e => e.timestamp >= cutoff);
  }

  /** @param {number[]} sorted @param {number} p @returns {number} */
  _percentile(sorted, p) {
    if (sorted.length === 0) return 0;
    return sorted[Math.max(0, Math.ceil(p * sorted.length) - 1)];
  }

  /**
   * Returns a summary of metrics for a given time window.
   * @param {number} [windowMs=60000] - Window size in ms (default 60s).
   * @returns {object} Summary: scansPerSec, threatsPerSec, p50/p95/p99, topCategories.
   */
  getSummary(windowMs = 60000) {
    const cutoff = Date.now() - windowMs;
    const win = this._events.filter(e => e.timestamp >= cutoff);
    const windowSec = windowMs / 1000;
    const scans = win.filter(e => e.type === 'scan');
    const threats = win.filter(e => e.type === 'threat');
    const blocks = win.filter(e => e.type === 'block');
    const durations = scans
      .filter(e => typeof e.duration === 'number')
      .map(e => e.duration)
      .sort((a, b) => a - b);
    const categoryCounts = {};
    for (const t of threats) {
      const cat = t.category || 'unknown';
      categoryCounts[cat] = (categoryCounts[cat] || 0) + 1;
    }
    const topCategories = Object.entries(categoryCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([category, count]) => ({ category, count }));
    return {
      scansPerSec: scans.length / windowSec,
      threatsPerSec: threats.length / windowSec,
      blocksPerSec: blocks.length / windowSec,
      totalScans: scans.length,
      totalThreats: threats.length,
      totalBlocks: blocks.length,
      p50: this._percentile(durations, 0.5),
      p95: this._percentile(durations, 0.95),
      p99: this._percentile(durations, 0.99),
      topCategories
    };
  }

  /** Stop the auto-prune timer. */
  destroy() {
    if (this._timer) { clearInterval(this._timer); this._timer = null; }
  }
}

// -- Exports -----------------------------------------------------------------

module.exports = { PrometheusExporter, DatadogLogger, MetricsCollector };
