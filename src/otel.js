'use strict';

/**
 * Agent Shield — OpenTelemetry-Compatible Metrics & Tracing
 *
 * Emits OTel-compatible data formats without requiring the OTel SDK dependency.
 * Features:
 * - ShieldMetrics: counters, histograms in OTel/Prometheus format
 * - ShieldTracer: spans and traces in OTLP-compatible JSON
 * - MetricsDashboard: human-readable summaries and percentiles
 */

const crypto = require('crypto');

// =========================================================================
// Shield Metrics
// =========================================================================

class ShieldMetrics {
  /**
   * @param {Object} [options]
   * @param {string} [options.serviceName='agent-shield'] - Service name for metric labels.
   * @param {number} [options.interval=60000] - Metric flush interval in ms.
   */
  constructor(options = {}) {
    this.serviceName = options.serviceName || 'agent-shield';
    this.interval = options.interval || 60000;

    this._scans = { total: 0, blocked: 0, latencies: [] };
    this._threats = {};
    this._blocks = { total: 0, contexts: [] };
    this._windows = [];
    this._startTime = Date.now();
    this._lastFlush = Date.now();
  }

  /**
   * Record a scan event with timing information.
   * @param {Object} result - Scan result.
   * @param {number} [result.latencyMs] - Scan latency in milliseconds.
   * @param {boolean} [result.blocked] - Whether the scan resulted in a block.
   * @param {number} [result.threatCount] - Number of threats detected.
   */
  recordScan(result) {
    this._scans.total++;

    if (result.latencyMs !== undefined) {
      this._scans.latencies.push(result.latencyMs);
      // Keep latencies bounded
      if (this._scans.latencies.length > 10000) {
        this._scans.latencies = this._scans.latencies.slice(-5000);
      }
    }

    if (result.blocked) {
      this._scans.blocked++;
    }

    // Record window snapshot for throughput tracking
    const now = Date.now();
    if (now - this._lastFlush >= this.interval) {
      this._windows.push({
        timestamp: now,
        scans: this._scans.total,
        blocked: this._scans.blocked
      });
      this._lastFlush = now;
      // Keep max 1440 windows (~24h at 1-min intervals)
      if (this._windows.length > 1440) {
        this._windows = this._windows.slice(-1440);
      }
    }
  }

  /**
   * Record a threat detection event.
   * @param {Object} threat - Threat information.
   * @param {string} [threat.category] - Threat category.
   * @param {string} [threat.severity] - Threat severity level.
   */
  recordThreat(threat) {
    const category = threat.category || 'unknown';
    const severity = threat.severity || 'medium';

    if (!this._threats[category]) {
      this._threats[category] = { count: 0, severities: {} };
    }

    this._threats[category].count++;

    if (!this._threats[category].severities[severity]) {
      this._threats[category].severities[severity] = 0;
    }
    this._threats[category].severities[severity]++;
  }

  /**
   * Record a block event.
   * @param {Object} context - Block context.
   * @param {string} [context.reason] - Reason for blocking.
   * @param {string} [context.category] - Threat category that triggered the block.
   */
  recordBlock(context) {
    this._blocks.total++;
    this._blocks.contexts.push({
      reason: context.reason || 'unknown',
      category: context.category || 'unknown',
      timestamp: Date.now()
    });

    // Keep bounded
    if (this._blocks.contexts.length > 1000) {
      this._blocks.contexts = this._blocks.contexts.slice(-500);
    }
  }

  /**
   * Return OTel-compatible metric objects.
   * @returns {Array<Object>} Array of metric objects {name, type, value, labels, timestamp}.
   */
  getMetrics() {
    const now = Date.now();
    const metrics = [];

    metrics.push({
      name: 'agent_shield_scans_total',
      type: 'counter',
      value: this._scans.total,
      labels: { service: this.serviceName },
      timestamp: now
    });

    metrics.push({
      name: 'agent_shield_blocks_total',
      type: 'counter',
      value: this._blocks.total,
      labels: { service: this.serviceName },
      timestamp: now
    });

    metrics.push({
      name: 'agent_shield_scans_blocked_total',
      type: 'counter',
      value: this._scans.blocked,
      labels: { service: this.serviceName },
      timestamp: now
    });

    // Threat counters per category
    for (const [category, data] of Object.entries(this._threats)) {
      metrics.push({
        name: 'agent_shield_threats_total',
        type: 'counter',
        value: data.count,
        labels: { service: this.serviceName, category },
        timestamp: now
      });
    }

    // Latency histogram summary
    if (this._scans.latencies.length > 0) {
      const sorted = [...this._scans.latencies].sort((a, b) => a - b);
      const p50 = sorted[Math.floor(sorted.length * 0.5)];
      const p95 = sorted[Math.floor(sorted.length * 0.95)];
      const p99 = sorted[Math.floor(sorted.length * 0.99)];

      metrics.push({
        name: 'agent_shield_scan_latency_ms',
        type: 'histogram',
        value: { p50, p95, p99, count: sorted.length, sum: sorted.reduce((a, b) => a + b, 0) },
        labels: { service: this.serviceName },
        timestamp: now
      });
    }

    return metrics;
  }

  /**
   * Export metrics in Prometheus text exposition format.
   * @returns {string} Prometheus-formatted metrics.
   */
  toPrometheus() {
    const lines = [];
    const metrics = this.getMetrics();

    for (const metric of metrics) {
      const labelStr = Object.entries(metric.labels)
        .map(([k, v]) => `${k}="${v}"`)
        .join(',');

      if (metric.type === 'histogram' && typeof metric.value === 'object') {
        lines.push(`# HELP ${metric.name} Agent Shield scan latency histogram`);
        lines.push(`# TYPE ${metric.name} summary`);
        lines.push(`${metric.name}{${labelStr},quantile="0.5"} ${metric.value.p50}`);
        lines.push(`${metric.name}{${labelStr},quantile="0.95"} ${metric.value.p95}`);
        lines.push(`${metric.name}{${labelStr},quantile="0.99"} ${metric.value.p99}`);
        lines.push(`${metric.name}_count{${labelStr}} ${metric.value.count}`);
        lines.push(`${metric.name}_sum{${labelStr}} ${metric.value.sum}`);
      } else {
        lines.push(`# HELP ${metric.name} Agent Shield metric`);
        lines.push(`# TYPE ${metric.name} ${metric.type}`);
        lines.push(`${metric.name}{${labelStr}} ${metric.value}`);
      }
    }

    return lines.join('\n') + '\n';
  }

  /**
   * Export metrics as JSON (OTLP/JSON compatible).
   * @returns {Object} JSON metrics payload.
   */
  toJSON() {
    return {
      resourceMetrics: [{
        resource: {
          attributes: [
            { key: 'service.name', value: { stringValue: this.serviceName } }
          ]
        },
        scopeMetrics: [{
          scope: { name: 'agent-shield', version: '1.0.0' },
          metrics: this.getMetrics().map(m => ({
            name: m.name,
            description: `Agent Shield: ${m.name}`,
            unit: m.name.includes('latency') ? 'ms' : '1',
            [m.type]: {
              dataPoints: [{
                asDouble: typeof m.value === 'object' ? m.value.sum : m.value,
                timeUnixNano: String(m.timestamp * 1000000),
                attributes: Object.entries(m.labels).map(([k, v]) => ({
                  key: k,
                  value: { stringValue: v }
                }))
              }]
            }
          }))
        }]
      }]
    };
  }

  /**
   * Reset all metrics.
   */
  reset() {
    this._scans = { total: 0, blocked: 0, latencies: [] };
    this._threats = {};
    this._blocks = { total: 0, contexts: [] };
    this._windows = [];
    this._lastFlush = Date.now();
    console.log('[Agent Shield] ShieldMetrics reset.');
  }
}

// =========================================================================
// Shield Tracer
// =========================================================================

class ShieldTracer {
  /**
   * @param {Object} [options]
   * @param {string} [options.serviceName='agent-shield'] - Service name for traces.
   * @param {number} [options.sampleRate=1.0] - Sampling rate (0.0 to 1.0).
   */
  constructor(options = {}) {
    this.serviceName = options.serviceName || 'agent-shield';
    this.sampleRate = options.sampleRate !== undefined ? options.sampleRate : 1.0;
    this._traces = [];
    this._activeSpans = new Map();
  }

  /**
   * Generate a random hex ID of a given byte length.
   * @private
   * @param {number} bytes - Number of bytes.
   * @returns {string} Hex string.
   */
  _generateId(bytes) {
    return crypto.randomBytes(bytes).toString('hex');
  }

  /**
   * Start a new span.
   * @param {string} name - Span name (e.g., 'shield.scan', 'shield.detect').
   * @param {Object} [attributes={}] - Span attributes.
   * @returns {Object|null} Span object with {traceId, spanId, name, startTime, attributes, events, end()}, or null if not sampled.
   */
  startSpan(name, attributes = {}) {
    if (Math.random() > this.sampleRate) {
      return null;
    }

    const span = {
      traceId: this._generateId(16),
      spanId: this._generateId(8),
      name,
      startTime: Date.now(),
      endTime: null,
      attributes: { ...attributes, 'service.name': this.serviceName },
      events: [],
      status: 'OK',

      /**
       * Add an event to this span.
       * @param {string} eventName - Event name.
       * @param {Object} [eventAttributes={}] - Event attributes.
       */
      addEvent: (eventName, eventAttributes = {}) => {
        span.events.push({
          name: eventName,
          timestamp: Date.now(),
          attributes: eventAttributes
        });
      },

      /**
       * End this span.
       * @param {string} [status='OK'] - Final status ('OK', 'ERROR').
       */
      end: (status) => {
        span.endTime = Date.now();
        span.status = status || 'OK';
        span.durationMs = span.endTime - span.startTime;
        this._activeSpans.delete(span.spanId);
        this._traces.push(span);

        // Keep traces bounded
        if (this._traces.length > 10000) {
          this._traces = this._traces.slice(-5000);
        }
      }
    };

    this._activeSpans.set(span.spanId, span);
    return span;
  }

  /**
   * Wrap a function call in a span, auto-ending on completion.
   * @param {string} name - Span name.
   * @param {Function} fn - Function to execute.
   * @returns {*} The return value of fn.
   */
  withSpan(name, fn) {
    const span = this.startSpan(name);

    try {
      const result = fn(span);

      // Handle async functions
      if (result && typeof result.then === 'function') {
        return result
          .then(val => {
            if (span) span.end('OK');
            return val;
          })
          .catch(err => {
            if (span) {
              span.addEvent('exception', { message: err.message });
              span.end('ERROR');
            }
            throw err;
          });
      }

      if (span) span.end('OK');
      return result;
    } catch (err) {
      if (span) {
        span.addEvent('exception', { message: err.message });
        span.end('ERROR');
      }
      throw err;
    }
  }

  /**
   * Get all completed traces.
   * @returns {Array<Object>} Array of completed span objects.
   */
  getTraces() {
    return [...this._traces];
  }

  /**
   * Export traces in OTLP-compatible JSON format.
   * @returns {Object} OTLP trace payload.
   */
  toOTLP() {
    return {
      resourceSpans: [{
        resource: {
          attributes: [
            { key: 'service.name', value: { stringValue: this.serviceName } }
          ]
        },
        scopeSpans: [{
          scope: { name: 'agent-shield', version: '1.0.0' },
          spans: this._traces.map(span => ({
            traceId: span.traceId,
            spanId: span.spanId,
            name: span.name,
            kind: 1, // INTERNAL
            startTimeUnixNano: String(span.startTime * 1000000),
            endTimeUnixNano: span.endTime ? String(span.endTime * 1000000) : undefined,
            attributes: Object.entries(span.attributes).map(([k, v]) => ({
              key: k,
              value: { stringValue: String(v) }
            })),
            events: span.events.map(e => ({
              name: e.name,
              timeUnixNano: String(e.timestamp * 1000000),
              attributes: Object.entries(e.attributes).map(([k, v]) => ({
                key: k,
                value: { stringValue: String(v) }
              }))
            })),
            status: { code: span.status === 'OK' ? 1 : 2 }
          }))
        }]
      }]
    };
  }
}

// =========================================================================
// Metrics Dashboard
// =========================================================================

class MetricsDashboard {
  /**
   * @param {ShieldMetrics} metrics - ShieldMetrics instance to read from.
   */
  constructor(metrics) {
    this.metrics = metrics;
  }

  /**
   * Return a formatted text summary of current metrics.
   * @returns {string} Human-readable metrics summary.
   */
  summary() {
    const m = this.metrics;
    const uptime = ((Date.now() - m._startTime) / 1000).toFixed(0);
    const blockRate = m._scans.total > 0
      ? ((m._scans.blocked / m._scans.total) * 100).toFixed(1)
      : '0.0';

    const threatCount = Object.values(m._threats).reduce((sum, t) => sum + t.count, 0);
    const percentiles = this.latencyPercentiles();

    const lines = [
      '=== Agent Shield Metrics Summary ===',
      `Uptime: ${uptime}s`,
      `Total Scans: ${m._scans.total}`,
      `Blocked: ${m._scans.blocked} (${blockRate}%)`,
      `Threats Detected: ${threatCount}`,
      `Block Events: ${m._blocks.total}`,
      ''
    ];

    if (percentiles) {
      lines.push(`Latency p50: ${percentiles.p50.toFixed(2)}ms`);
      lines.push(`Latency p95: ${percentiles.p95.toFixed(2)}ms`);
      lines.push(`Latency p99: ${percentiles.p99.toFixed(2)}ms`);
      lines.push('');
    }

    const top = this.topThreats(5);
    if (top.length > 0) {
      lines.push('Top Threats:');
      for (const t of top) {
        lines.push(`  ${t.category}: ${t.count}`);
      }
    }

    return lines.join('\n');
  }

  /**
   * Return the top N threat categories by count.
   * @param {number} [n=10] - Number of top threats to return.
   * @returns {Array<Object>} Sorted array [{category, count, severities}].
   */
  topThreats(n = 10) {
    const threats = Object.entries(this.metrics._threats).map(([category, data]) => ({
      category,
      count: data.count,
      severities: { ...data.severities }
    }));

    threats.sort((a, b) => b.count - a.count);
    return threats.slice(0, n);
  }

  /**
   * Return scans-per-second over recorded time windows.
   * @returns {Array<Object>} Array of [{timestamp, scansPerSec}].
   */
  throughputHistory() {
    const windows = this.metrics._windows;
    if (windows.length < 2) return [];

    const result = [];
    for (let i = 1; i < windows.length; i++) {
      const dt = (windows[i].timestamp - windows[i - 1].timestamp) / 1000;
      const dScans = windows[i].scans - windows[i - 1].scans;
      result.push({
        timestamp: windows[i].timestamp,
        scansPerSec: dt > 0 ? dScans / dt : 0
      });
    }

    return result;
  }

  /**
   * Return p50, p95, p99 latency percentiles.
   * @returns {Object|null} {p50, p95, p99} in ms, or null if no data.
   */
  latencyPercentiles() {
    const latencies = this.metrics._scans.latencies;
    if (latencies.length === 0) return null;

    const sorted = [...latencies].sort((a, b) => a - b);
    return {
      p50: sorted[Math.floor(sorted.length * 0.5)],
      p95: sorted[Math.floor(sorted.length * 0.95)],
      p99: sorted[Math.floor(sorted.length * 0.99)]
    };
  }
}

// =========================================================================
// Exports
// =========================================================================

module.exports = {
  ShieldMetrics,
  ShieldTracer,
  MetricsDashboard
};
