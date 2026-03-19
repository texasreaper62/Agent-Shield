'use strict';

/**
 * Policy-as-Code (#23), Structured Logging (#4), and Webhook Alerts (#22)
 *
 * - Policy Engine: JSON config files defining security policies for an agent.
 * - Structured Logger: JSON-formatted threat events for SIEM/dashboards.
 * - Webhooks: Real-time notifications to Slack, Discord, HTTP endpoints.
 */

const { AgentShield } = require('./index');
const { CircuitBreaker, RateLimiter } = require('./circuit-breaker');
const { PermissionBoundary } = require('./tool-guard');
const { PIIRedactor, DLPEngine, ContentPolicy } = require('./pii');

// =========================================================================
// POLICY ENGINE
// =========================================================================

/**
 * Creates a fully configured AgentShield from a JSON policy object.
 *
 * @param {object} policy - The policy configuration.
 * @returns {object} { shield, circuitBreaker, rateLimiter, permissions, piiRedactor, dlp, contentPolicy }
 *
 * @example
 * const policy = {
 *   sensitivity: 'high',
 *   blockOnThreat: true,
 *   blockThreshold: 'high',
 *   circuitBreaker: { threshold: 5, windowMs: 60000 },
 *   rateLimiter: { maxRequests: 100, windowMs: 60000 },
 *   permissions: {
 *     allowedTools: ['search', 'calculator'],
 *     tools: {
 *       search: { blockArgs: ['password', 'secret'] }
 *     }
 *   },
 *   pii: { categories: ['email', 'ssn', 'credit_card'] },
 *   dlp: {
 *     rules: [
 *       { name: 'internal_project', pattern: 'Project\\s+Phoenix', action: 'block' }
 *     ]
 *   },
 *   contentPolicy: { blockedCategories: ['medical_advice', 'legal_advice'] }
 * };
 *
 * const stack = loadPolicy(policy);
 */
const loadPolicy = (policy) => {
  const stack = {};

  // Core shield
  stack.shield = new AgentShield({
    sensitivity: policy.sensitivity || 'medium',
    blockOnThreat: policy.blockOnThreat !== undefined ? policy.blockOnThreat : false,
    blockThreshold: policy.blockThreshold || 'high',
    logging: policy.logging || false,
    dangerousTools: policy.dangerousTools,
    sensitiveFilePatterns: policy.sensitiveFilePatterns
  });

  // Circuit breaker
  if (policy.circuitBreaker) {
    stack.circuitBreaker = new CircuitBreaker(policy.circuitBreaker);
  }

  // Rate limiter
  if (policy.rateLimiter) {
    stack.rateLimiter = new RateLimiter(policy.rateLimiter);
  }

  // Permission boundaries
  if (policy.permissions) {
    stack.permissions = new PermissionBoundary({
      allowedTools: policy.permissions.allowedTools,
      blockedTools: policy.permissions.blockedTools
    });

    if (policy.permissions.tools) {
      for (const [toolName, perms] of Object.entries(policy.permissions.tools)) {
        stack.permissions.defineTool(toolName, perms);
      }
    }
  }

  // PII redaction
  if (policy.pii) {
    stack.piiRedactor = new PIIRedactor(policy.pii);
  }

  // DLP
  if (policy.dlp) {
    stack.dlp = new DLPEngine();
    if (policy.dlp.rules) {
      for (const rule of policy.dlp.rules) {
        stack.dlp.addRule(rule);
      }
    }
  }

  // Content policy
  if (policy.contentPolicy) {
    stack.contentPolicy = new ContentPolicy(policy.contentPolicy);
  }

  return stack;
};

/**
 * Loads a policy from a JSON file path.
 *
 * @param {string} filePath - Path to JSON policy file.
 * @returns {object} Configured security stack.
 */
const loadPolicyFile = (filePath) => {
  const fs = require('fs');
  const content = fs.readFileSync(filePath, 'utf-8');
  const policy = JSON.parse(content);
  return loadPolicy(policy);
};

// =========================================================================
// STRUCTURED LOGGER
// =========================================================================

/**
 * Log levels for structured logging.
 */
const LOG_LEVEL = {
  DEBUG: 'debug',
  INFO: 'info',
  WARN: 'warn',
  ERROR: 'error',
  CRITICAL: 'critical'
};

class StructuredLogger {
  /**
   * @param {object} [options]
   * @param {string} [options.serviceName='agent-shield'] - Service name for log entries.
   * @param {string} [options.environment='production'] - Environment name.
   * @param {Function} [options.transport] - Custom transport function. Receives log entry object.
   * @param {boolean} [options.console=true] - Also log to console.
   * @param {number} [options.maxBuffer=1000] - Max buffered log entries.
   */
  constructor(options = {}) {
    this.serviceName = options.serviceName || 'agent-shield';
    this.environment = options.environment || 'production';
    this.transport = options.transport || null;
    this.useConsole = options.console !== undefined ? options.console : true;
    this.maxBuffer = options.maxBuffer || 1000;
    this.buffer = [];
  }

  /**
   * Logs a structured event.
   *
   * @param {string} level - Log level.
   * @param {string} event - Event name.
   * @param {object} [data={}] - Event data.
   * @returns {object} The log entry.
   */
  log(level, event, data = {}) {
    const entry = {
      timestamp: new Date().toISOString(),
      level,
      service: this.serviceName,
      environment: this.environment,
      event,
      ...data
    };

    this.buffer.push(entry);
    if (this.buffer.length > this.maxBuffer) {
      this.buffer.shift();
    }

    if (this.useConsole) {
      const method = level === 'error' || level === 'critical' ? 'error' : level === 'warn' ? 'warn' : 'log';
      console[method](JSON.stringify(entry));
    }

    if (this.transport) {
      try { this.transport(entry); } catch (e) { console.error('[Agent Shield] transport callback error:', e.message); }
    }

    return entry;
  }

  /** Log a threat detection event. */
  logThreat(scanResult, source) {
    return this.log(
      scanResult.stats.critical > 0 ? LOG_LEVEL.CRITICAL : LOG_LEVEL.WARN,
      'threat_detected',
      {
        source,
        status: scanResult.status,
        threatCount: scanResult.threats.length,
        threats: scanResult.threats.map(t => ({
          severity: t.severity,
          category: t.category,
          description: t.description,
          confidence: t.confidence
        })),
        stats: scanResult.stats
      }
    );
  }

  /** Log a blocked request. */
  logBlock(reason, source, details = {}) {
    return this.log(LOG_LEVEL.ERROR, 'request_blocked', { reason, source, ...details });
  }

  /** Log a circuit breaker trip. */
  logCircuitBreaker(state, details = {}) {
    return this.log(LOG_LEVEL.CRITICAL, 'circuit_breaker', { state, ...details });
  }

  /** Log a PII redaction. */
  logPIIRedaction(findings, source) {
    return this.log(LOG_LEVEL.WARN, 'pii_redacted', {
      source,
      count: findings.length,
      categories: findings.map(f => f.category)
    });
  }

  /** Log a DLP violation. */
  logDLPViolation(violations, source) {
    return this.log(LOG_LEVEL.ERROR, 'dlp_violation', {
      source,
      violations: violations.map(v => ({ rule: v.rule, action: v.action, severity: v.severity }))
    });
  }

  /**
   * Returns buffered log entries.
   * @param {object} [filter] - Optional filter.
   * @param {string} [filter.level] - Filter by level.
   * @param {string} [filter.event] - Filter by event name.
   * @param {number} [filter.since] - Filter by timestamp (ms).
   * @returns {Array}
   */
  getEntries(filter = {}) {
    let entries = [...this.buffer];

    if (filter.level) {
      entries = entries.filter(e => e.level === filter.level);
    }
    if (filter.event) {
      entries = entries.filter(e => e.event === filter.event);
    }
    if (filter.since) {
      const sinceDate = new Date(filter.since).toISOString();
      entries = entries.filter(e => e.timestamp >= sinceDate);
    }

    return entries;
  }

  clear() {
    this.buffer = [];
  }
}

// =========================================================================
// WEBHOOK ALERTS
// =========================================================================

class WebhookAlert {
  /**
   * @param {object} [options]
   * @param {Array<object>} [options.endpoints=[]] - Webhook endpoints.
   * @param {string} [options.minSeverity='high'] - Minimum severity to trigger alert.
   * @param {number} [options.cooldownMs=60000] - Minimum time between alerts to same endpoint.
   */
  constructor(options = {}) {
    this.endpoints = options.endpoints || [];
    this.minSeverity = options.minSeverity || 'high';
    this.cooldownMs = options.cooldownMs || 60000;
    this.lastAlertTimes = new Map();
    this.alertHistory = [];
  }

  /**
   * Adds a webhook endpoint.
   *
   * @param {object} endpoint
   * @param {string} endpoint.url - Webhook URL.
   * @param {string} [endpoint.type='generic'] - Type: 'generic', 'slack', 'discord'.
   * @param {object} [endpoint.headers={}] - Custom headers.
   * @returns {WebhookAlert} this
   */
  addEndpoint(endpoint) {
    this.endpoints.push({
      url: endpoint.url,
      type: endpoint.type || 'generic',
      headers: endpoint.headers || {}
    });
    return this;
  }

  /**
   * Sends an alert if severity threshold is met and cooldown has elapsed.
   *
   * @param {object} event - The threat event.
   * @param {string} event.severity - Threat severity.
   * @param {string} event.description - What happened.
   * @param {object} [event.details] - Additional details.
   * @returns {Promise<Array>} Results of webhook sends.
   */
  async alert(event) {
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    const minLevel = severityOrder[this.minSeverity] ?? 1;
    const eventLevel = severityOrder[event.severity] ?? 3;

    if (eventLevel > minLevel) {
      return [];
    }

    const results = [];
    const now = Date.now();

    for (const endpoint of this.endpoints) {
      // Check cooldown
      const lastAlert = this.lastAlertTimes.get(endpoint.url) || 0;
      if (now - lastAlert < this.cooldownMs) {
        results.push({ url: endpoint.url, sent: false, reason: 'cooldown' });
        continue;
      }

      const payload = this._formatPayload(endpoint.type, event);

      try {
        // Use dynamic import for fetch in Node 18+ or fall back to http
        const response = await this._send(endpoint, payload);
        this.lastAlertTimes.set(endpoint.url, now);
        const record = { url: endpoint.url, sent: true, timestamp: now, event: event.description };
        results.push(record);
        this.alertHistory.push(record);
      } catch (err) {
        results.push({ url: endpoint.url, sent: false, error: err.message });
      }
    }

    // Cap alert history
    if (this.alertHistory.length > 100) {
      this.alertHistory = this.alertHistory.slice(-100);
    }

    // Prune stale cooldown entries (older than 2x cooldown period)
    if (this.lastAlertTimes.size > 100) {
      const staleThreshold = now - this.cooldownMs * 2;
      for (const [url, time] of this.lastAlertTimes) {
        if (time < staleThreshold) this.lastAlertTimes.delete(url);
      }
    }

    return results;
  }

  /** @private */
  _formatPayload(type, event) {
    if (type === 'slack') {
      return {
        text: `🛡️ *Agent Shield Alert*`,
        blocks: [
          {
            type: 'section',
            text: {
              type: 'mrkdwn',
              text: `*Severity:* ${event.severity.toUpperCase()}\n*Event:* ${event.description}\n*Time:* ${new Date().toISOString()}`
            }
          }
        ]
      };
    }

    if (type === 'discord') {
      return {
        embeds: [{
          title: 'Agent Shield Alert',
          description: event.description,
          color: event.severity === 'critical' ? 0xFF0000 : event.severity === 'high' ? 0xFF8800 : 0xFFCC00,
          fields: [
            { name: 'Severity', value: event.severity.toUpperCase(), inline: true },
            { name: 'Time', value: new Date().toISOString(), inline: true }
          ]
        }]
      };
    }

    // Generic
    return {
      service: 'agent-shield',
      severity: event.severity,
      description: event.description,
      details: event.details || {},
      timestamp: new Date().toISOString()
    };
  }

  /** @private */
  async _send(endpoint, payload) {
    const https = require('https');
    const http = require('http');
    const url = new URL(endpoint.url);
    const transport = url.protocol === 'https:' ? https : http;
    const body = JSON.stringify(payload);

    return new Promise((resolve, reject) => {
      const req = transport.request({
        hostname: url.hostname,
        port: url.port,
        path: url.pathname + url.search,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
          ...endpoint.headers
        },
        timeout: 10000
      }, (res) => {
        let data = '';
        res.on('data', chunk => { data += chunk; });
        res.on('end', () => resolve({ status: res.statusCode, body: data }));
      });

      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('Webhook timeout')); });
      req.write(body);
      req.end();
    });
  }

  getHistory() {
    return [...this.alertHistory];
  }
}

module.exports = { loadPolicy, loadPolicyFile, StructuredLogger, WebhookAlert, LOG_LEVEL };
