'use strict';

/**
 * Agent Shield — Automated Incident Response (v12)
 *
 * When an attack is detected, don't just alert — automatically:
 * isolate the compromised agent, preserve forensic evidence,
 * notify the SOC, generate an incident report, and suggest remediation.
 *
 * Closes the loop from detection to response.
 *
 * All processing runs locally — no data ever leaves your environment.
 *
 * @module incident-response
 */

const crypto = require('crypto');

// =========================================================================
// RESPONSE STRATEGIES
// =========================================================================

const RESPONSE_STRATEGIES = {
  /** Block the action and continue monitoring. */
  block: { name: 'block', description: 'Block the malicious action. Agent continues operating.' },
  /** Isolate the agent — kill its active sessions. */
  isolate: { name: 'isolate', description: 'Isolate the compromised agent. Terminate all sessions.' },
  /** Alert only — log the incident but take no action. */
  alert: { name: 'alert', description: 'Alert security team. No automated action.' },
  /** Quarantine — block and preserve state for forensics. */
  quarantine: { name: 'quarantine', description: 'Quarantine agent and preserve full state for investigation.' },
  /** Rollback — revert to last known-good state. */
  rollback: { name: 'rollback', description: 'Revert agent to last known-good configuration.' }
};

const SEVERITY_TO_STRATEGY = {
  critical: 'quarantine',
  high: 'block',
  medium: 'alert',
  low: 'alert'
};

// =========================================================================
// IncidentResponse
// =========================================================================

/**
 * Automated incident response engine for AI agent security events.
 */
class IncidentResponse {
  /**
   * @param {object} [options]
   * @param {object} [options.strategyOverrides] - Override default severity→strategy mapping.
   * @param {Function} [options.onIncident] - Callback when incident is created.
   * @param {Function} [options.onAction] - Callback when response action is taken.
   * @param {boolean} [options.autoRespond=true] - Automatically execute response strategy.
   */
  constructor(options = {}) {
    this.strategies = { ...SEVERITY_TO_STRATEGY, ...(options.strategyOverrides || {}) };
    this.onIncident = options.onIncident || null;
    this.onAction = options.onAction || null;
    this.autoRespond = options.autoRespond !== false;

    /** @type {Array<object>} */
    this.incidents = [];
    /** @type {Array<object>} */
    this.actions = [];
    this.stats = { incidentsCreated: 0, actionsExecuted: 0, agentsIsolated: 0, actionsBlocked: 0 };
  }

  /**
   * Handle a security event — create incident, determine strategy, execute response.
   *
   * @param {object} event
   * @param {string} event.type - Threat type (e.g., 'prompt_injection', 'ssrf', 'tool_poisoning').
   * @param {string} event.severity - 'critical', 'high', 'medium', 'low'.
   * @param {string} [event.agentId] - Affected agent ID.
   * @param {string} [event.serverId] - Affected MCP server ID.
   * @param {string} [event.description] - Human-readable description.
   * @param {*} [event.evidence] - Raw evidence (tool call, input text, etc.).
   * @returns {object} Incident record with response actions.
   */
  handleEvent(event) {
    const incidentId = crypto.randomBytes(8).toString('hex');
    const strategy = this.strategies[event.severity] || 'alert';
    const strategyInfo = RESPONSE_STRATEGIES[strategy] || RESPONSE_STRATEGIES.alert;

    const incident = {
      incidentId,
      timestamp: Date.now(),
      type: event.type,
      severity: event.severity,
      agentId: event.agentId || 'unknown',
      serverId: event.serverId || null,
      description: event.description || `${event.type} detected (${event.severity})`,
      evidence: event.evidence ? JSON.stringify(event.evidence).substring(0, 2000) : null,
      strategy: strategyInfo.name,
      strategyDescription: strategyInfo.description,
      status: 'open',
      actions: [],
      forensics: null
    };

    // Preserve forensic evidence
    incident.forensics = {
      capturedAt: Date.now(),
      eventSnapshot: { ...event, evidence: incident.evidence },
      contextHash: crypto.createHash('sha256').update(JSON.stringify(event)).digest('hex')
    };

    this.incidents.push(incident);
    this.stats.incidentsCreated++;

    // Bound incidents
    if (this.incidents.length > 1000) this.incidents = this.incidents.slice(-1000);

    // Notify
    if (this.onIncident) {
      try { this.onIncident(incident); } catch { /* ignore */ }
    }

    // Auto-respond
    if (this.autoRespond) {
      this._executeStrategy(incident);
    }

    return incident;
  }

  /**
   * Get all open incidents.
   * @returns {Array<object>}
   */
  getOpenIncidents() {
    return this.incidents.filter(i => i.status === 'open');
  }

  /**
   * Close an incident.
   * @param {string} incidentId
   * @param {string} [resolution] - How it was resolved.
   * @returns {boolean}
   */
  closeIncident(incidentId, resolution) {
    const incident = this.incidents.find(i => i.incidentId === incidentId);
    if (!incident) return false;
    incident.status = 'closed';
    incident.closedAt = Date.now();
    incident.resolution = resolution || 'Manually closed.';
    return true;
  }

  /**
   * Generate an incident report.
   * @param {string} [incidentId] - Specific incident, or null for summary.
   * @returns {object}
   */
  generateReport(incidentId) {
    if (incidentId) {
      const incident = this.incidents.find(i => i.incidentId === incidentId);
      if (!incident) return null;
      return {
        title: `Incident Report: ${incident.incidentId}`,
        incident,
        timeline: incident.actions,
        forensics: incident.forensics,
        recommendation: this._getRemediation(incident)
      };
    }

    // Summary report
    const open = this.incidents.filter(i => i.status === 'open');
    const closed = this.incidents.filter(i => i.status === 'closed');
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const i of this.incidents) bySeverity[i.severity] = (bySeverity[i.severity] || 0) + 1;

    return {
      title: 'Incident Summary Report',
      totalIncidents: this.incidents.length,
      open: open.length,
      closed: closed.length,
      bySeverity,
      recentIncidents: this.incidents.slice(-10),
      stats: { ...this.stats },
      generatedAt: Date.now()
    };
  }

  /**
   * Get stats.
   * @returns {object}
   */
  getStats() {
    return { ...this.stats, totalIncidents: this.incidents.length, openIncidents: this.incidents.filter(i => i.status === 'open').length };
  }

  // -----------------------------------------------------------------------
  // Private
  // -----------------------------------------------------------------------

  /** @private */
  _executeStrategy(incident) {
    const actions = [];

    switch (incident.strategy) {
      case 'quarantine':
        actions.push({ action: 'isolate_agent', target: incident.agentId, timestamp: Date.now() });
        actions.push({ action: 'preserve_forensics', evidenceHash: incident.forensics.contextHash, timestamp: Date.now() });
        actions.push({ action: 'notify_soc', severity: incident.severity, timestamp: Date.now() });
        this.stats.agentsIsolated++;
        this.stats.actionsBlocked++;
        break;
      case 'block':
        actions.push({ action: 'block_action', target: incident.agentId, timestamp: Date.now() });
        actions.push({ action: 'notify_soc', severity: incident.severity, timestamp: Date.now() });
        this.stats.actionsBlocked++;
        break;
      case 'isolate':
        actions.push({ action: 'isolate_agent', target: incident.agentId, timestamp: Date.now() });
        this.stats.agentsIsolated++;
        break;
      case 'alert':
        actions.push({ action: 'log_alert', severity: incident.severity, timestamp: Date.now() });
        break;
      case 'rollback':
        actions.push({ action: 'rollback_config', target: incident.agentId, timestamp: Date.now() });
        break;
    }

    incident.actions = actions;
    this.stats.actionsExecuted += actions.length;

    for (const action of actions) {
      this.actions.push({ ...action, incidentId: incident.incidentId });
      if (this.onAction) {
        try { this.onAction(action, incident); } catch { /* ignore */ }
      }
    }
  }

  /** @private */
  _getRemediation(incident) {
    const remediations = {
      prompt_injection: 'Review and harden system prompt. Add input validation. Enable semantic isolation.',
      ssrf: 'Block private IP ranges. Validate all URLs against allowlist. Apply CVE-2026-26118 patches.',
      tool_poisoning: 'Re-attest tool definitions. Pin tool versions. Enable full-schema scanning.',
      data_exfiltration: 'Enable DLP scanning on outbound calls. Review tool permissions. Add URL allowlists.',
      config_poisoning: 'Audit .claude/ and .cursor/ config files. Block ANTHROPIC_BASE_URL overrides.',
      role_hijack: 'Strengthen system prompt. Enable prompt hardening. Add role boundary monitoring.',
      memory_poisoning: 'Clear agent memory. Enable memory write validation. Add persistence monitoring.',
      cross_agent_injection: 'Enable cross-server isolation. Add message signing between agents.',
    };
    return remediations[incident.type] || 'Review security configuration and enable additional detection layers.';
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
  IncidentResponse,
  RESPONSE_STRATEGIES,
  SEVERITY_TO_STRATEGY
};
