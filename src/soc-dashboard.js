'use strict';

/**
 * Agent Shield - Enterprise SOC Dashboard Backend
 *
 * Real-time attack visibility across all agents in an organization.
 * Aggregates threat data, provides drill-down by agent/category/time,
 * and supports alert routing to PagerDuty, Slack, and Microsoft Teams.
 *
 * @module soc-dashboard
 */

const { EventEmitter } = require('events');
const crypto = require('crypto');

// =========================================================================
// SOCDashboard - Aggregation and alerting engine
// =========================================================================

/**
 * Enterprise SOC dashboard backend.
 * Aggregates threat events from multiple agents and provides
 * real-time alerting and drill-down capabilities.
 */
class SOCDashboard extends EventEmitter {
  /**
   * @param {object} [options]
   * @param {number} [options.maxEvents=50000] - Max events retained.
   * @param {number} [options.alertCooldownMs=300000] - Min time between duplicate alerts (5 min).
   * @param {Array} [options.alertChannels] - Array of AlertChannel instances.
   */
  constructor(options = {}) {
    super();
    this.maxEvents = options.maxEvents || 50000;
    this.alertCooldownMs = options.alertCooldownMs || 300000;
    this._events = [];
    this._agents = new Map(); // agentId -> agent metadata
    this._alertChannels = options.alertChannels || [];
    this._lastAlerts = new Map(); // alertKey -> timestamp
    this._stats = {
      totalEvents: 0,
      totalThreats: 0,
      totalBlocked: 0,
      agentCount: 0,
    };
  }

  /**
   * Register an agent with the dashboard.
   * @param {string} agentId
   * @param {object} [metadata] - Agent metadata (name, environment, team, etc.)
   */
  registerAgent(agentId, metadata = {}) {
    this._agents.set(agentId, {
      id: agentId,
      name: metadata.name || agentId,
      environment: metadata.environment || 'production',
      team: metadata.team || 'default',
      registeredAt: Date.now(),
      lastActivity: Date.now(),
      eventCount: 0,
      threatCount: 0,
    });
    this._stats.agentCount = this._agents.size;
  }

  /**
   * Ingest a security event from an agent.
   * @param {object} event
   * @param {string} event.agentId - Source agent.
   * @param {string} event.type - Event type: 'scan', 'threat', 'block', 'anomaly'.
   * @param {string} [event.category] - Threat category if applicable.
   * @param {string} [event.severity] - Threat severity.
   * @param {string} [event.description] - Event description.
   * @param {boolean} [event.blocked] - Whether the threat was blocked.
   * @param {object} [event.metadata] - Additional data.
   */
  ingest(event) {
    const enriched = {
      id: crypto.randomBytes(8).toString('hex'),
      agentId: event.agentId,
      type: event.type || 'scan',
      category: event.category || null,
      severity: event.severity || null,
      description: event.description || '',
      blocked: event.blocked || false,
      metadata: event.metadata || {},
      timestamp: Date.now(),
    };

    this._events.push(enriched);
    this._stats.totalEvents++;

    if (enriched.type === 'threat' || enriched.severity) {
      this._stats.totalThreats++;
    }
    if (enriched.blocked) {
      this._stats.totalBlocked++;
    }

    // Update agent stats
    const agent = this._agents.get(enriched.agentId);
    if (agent) {
      agent.lastActivity = Date.now();
      agent.eventCount++;
      if (enriched.severity) agent.threatCount++;
    }

    // Rotate events
    if (this._events.length > this.maxEvents) {
      this._events = this._events.slice(-Math.floor(this.maxEvents * 0.75));
    }

    // Emit for real-time listeners
    this.emit('event', enriched);

    // Check alert conditions
    if (enriched.severity === 'critical') {
      this._sendAlert({
        level: 'critical',
        title: `Critical threat on ${enriched.agentId}`,
        message: enriched.description,
        event: enriched,
      });
    }

    return enriched;
  }

  // =======================================================================
  // Querying
  // =======================================================================

  /**
   * Get events with optional filters.
   * @param {object} [filters]
   * @param {string} [filters.agentId]
   * @param {string} [filters.type]
   * @param {string} [filters.category]
   * @param {string} [filters.severity]
   * @param {number} [filters.since] - Timestamp.
   * @param {number} [filters.limit=100]
   * @returns {Array}
   */
  query(filters = {}) {
    let results = this._events;

    if (filters.agentId) results = results.filter(e => e.agentId === filters.agentId);
    if (filters.type) results = results.filter(e => e.type === filters.type);
    if (filters.category) results = results.filter(e => e.category === filters.category);
    if (filters.severity) results = results.filter(e => e.severity === filters.severity);
    if (filters.since) results = results.filter(e => e.timestamp >= filters.since);

    const limit = filters.limit || 100;
    return results.slice(-limit);
  }

  /**
   * Get threat distribution by category.
   * @param {number} [sinceMs] - Time window in ms (e.g., 3600000 for last hour).
   * @returns {object} Category -> count mapping.
   */
  getThreatDistribution(sinceMs) {
    const cutoff = sinceMs ? Date.now() - sinceMs : 0;
    const dist = {};
    for (const e of this._events) {
      if (e.timestamp >= cutoff && e.category) {
        dist[e.category] = (dist[e.category] || 0) + 1;
      }
    }
    return dist;
  }

  /**
   * Get severity distribution.
   * @param {number} [sinceMs]
   * @returns {object}
   */
  getSeverityDistribution(sinceMs) {
    const cutoff = sinceMs ? Date.now() - sinceMs : 0;
    const dist = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const e of this._events) {
      if (e.timestamp >= cutoff && e.severity && dist[e.severity] !== undefined) {
        dist[e.severity]++;
      }
    }
    return dist;
  }

  /**
   * Get per-agent threat summary.
   * @returns {Array}
   */
  getAgentSummary() {
    const summaries = [];
    for (const [id, agent] of this._agents) {
      const recentThreats = this._events.filter(
        e => e.agentId === id && e.severity && e.timestamp > Date.now() - 3600000
      ).length;
      summaries.push({
        ...agent,
        recentThreats,
        status: recentThreats > 10 ? 'critical' : recentThreats > 3 ? 'elevated' : 'normal',
      });
    }
    return summaries.sort((a, b) => b.threatCount - a.threatCount);
  }

  /**
   * Get timeline data for charting (bucketed by interval).
   * @param {number} [intervalMs=60000] - Bucket size in ms (default: 1 minute).
   * @param {number} [windowMs=3600000] - Total window (default: 1 hour).
   * @returns {Array} Array of { timestamp, threats, blocked, scans }.
   */
  getTimeline(intervalMs = 60000, windowMs = 3600000) {
    const now = Date.now();
    const start = now - windowMs;
    const buckets = [];

    for (let t = start; t < now; t += intervalMs) {
      const bucketEnd = t + intervalMs;
      const events = this._events.filter(e => e.timestamp >= t && e.timestamp < bucketEnd);
      buckets.push({
        timestamp: t,
        threats: events.filter(e => e.severity).length,
        blocked: events.filter(e => e.blocked).length,
        scans: events.filter(e => e.type === 'scan').length,
      });
    }

    return buckets;
  }

  /**
   * Get dashboard summary.
   * @returns {object}
   */
  getSummary() {
    return {
      stats: { ...this._stats },
      agents: this.getAgentSummary(),
      threatDistribution: this.getThreatDistribution(3600000),
      severityDistribution: this.getSeverityDistribution(3600000),
      recentEvents: this._events.slice(-20),
    };
  }

  // =======================================================================
  // Alerting
  // =======================================================================

  /**
   * Add an alert channel.
   * @param {AlertChannel} channel
   */
  addAlertChannel(channel) {
    this._alertChannels.push(channel);
  }

  /** @private */
  _sendAlert(alert) {
    const key = `${alert.level}:${alert.event.agentId}:${alert.event.category}`;
    const lastSent = this._lastAlerts.get(key);

    // Cooldown to prevent alert storms
    if (lastSent && Date.now() - lastSent < this.alertCooldownMs) return;
    this._lastAlerts.set(key, Date.now());

    this.emit('alert', alert);
    for (const channel of this._alertChannels) {
      try { channel.send(alert); } catch (_) { /* channel error */ }
    }
  }
}

// =========================================================================
// Alert Channels
// =========================================================================

/**
 * Base alert channel. Extend for specific integrations.
 */
class AlertChannel {
  send(alert) { throw new Error('Not implemented'); }
}

/**
 * Slack webhook alert channel.
 */
class SlackAlertChannel extends AlertChannel {
  /**
   * @param {object} options
   * @param {string} options.webhookUrl - Slack webhook URL.
   * @param {string} [options.channel] - Override channel.
   */
  constructor(options = {}) {
    super();
    this.webhookUrl = options.webhookUrl;
    this.channel = options.channel;
  }

  send(alert) {
    const payload = {
      text: `[Agent Shield ${alert.level.toUpperCase()}] ${alert.title}`,
      blocks: [
        { type: 'header', text: { type: 'plain_text', text: `Agent Shield Alert: ${alert.title}` } },
        { type: 'section', text: { type: 'mrkdwn', text: alert.message } },
        { type: 'context', elements: [
          { type: 'mrkdwn', text: `*Agent:* ${alert.event.agentId} | *Severity:* ${alert.event.severity} | *Category:* ${alert.event.category}` }
        ]},
      ],
    };
    if (this.channel) payload.channel = this.channel;

    // In production, this would be: fetch(this.webhookUrl, { method: 'POST', body: JSON.stringify(payload) })
    // Stored for retrieval/testing
    this.lastPayload = payload;
    return payload;
  }
}

/**
 * PagerDuty alert channel.
 */
class PagerDutyAlertChannel extends AlertChannel {
  /**
   * @param {object} options
   * @param {string} options.routingKey - PagerDuty integration key.
   */
  constructor(options = {}) {
    super();
    this.routingKey = options.routingKey;
  }

  send(alert) {
    const payload = {
      routing_key: this.routingKey,
      event_action: alert.level === 'critical' ? 'trigger' : 'acknowledge',
      payload: {
        summary: `[Agent Shield] ${alert.title}`,
        severity: alert.level === 'critical' ? 'critical' : 'warning',
        source: alert.event.agentId,
        component: 'agent-shield',
        group: alert.event.category,
        custom_details: {
          description: alert.message,
          severity: alert.event.severity,
          category: alert.event.category,
          timestamp: new Date().toISOString(),
        },
      },
    };
    this.lastPayload = payload;
    return payload;
  }
}

/**
 * Microsoft Teams webhook alert channel.
 */
class TeamsAlertChannel extends AlertChannel {
  constructor(options = {}) {
    super();
    this.webhookUrl = options.webhookUrl;
  }

  send(alert) {
    const color = alert.level === 'critical' ? 'FF0000' : 'FFA500';
    const payload = {
      '@type': 'MessageCard',
      themeColor: color,
      summary: `Agent Shield: ${alert.title}`,
      sections: [{
        activityTitle: `Agent Shield Alert: ${alert.title}`,
        facts: [
          { name: 'Agent', value: alert.event.agentId },
          { name: 'Severity', value: alert.event.severity },
          { name: 'Category', value: alert.event.category },
        ],
        text: alert.message,
      }],
    };
    this.lastPayload = payload;
    return payload;
  }
}

module.exports = {
  SOCDashboard,
  AlertChannel,
  SlackAlertChannel,
  PagerDutyAlertChannel,
  TeamsAlertChannel,
};
