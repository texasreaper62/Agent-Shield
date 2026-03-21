'use strict';

/**
 * Agent Shield - Agent Flight Recorder
 *
 * Records every interaction an agent has, creating a forensic timeline.
 * When an agent gets compromised, the Flight Recorder provides:
 * - The exact conversation that led to compromise
 * - The exact moment the attack succeeded
 * - What defense should have caught it
 * - Auto-generated pattern to prevent recurrence
 *
 * Like a black box from aviation, applied to AI agents.
 *
 * @module flight-recorder
 */

const crypto = require('crypto');
const { scanText } = require('./detector-core');

// =========================================================================
// FlightRecorder - Core recording engine
// =========================================================================

/**
 * Records agent interactions and provides forensic analysis.
 */
class FlightRecorder {
  /**
   * @param {object} [options]
   * @param {string} [options.agentId] - Agent identifier.
   * @param {number} [options.maxEntries=10000] - Max entries before rotation.
   * @param {boolean} [options.scanOnRecord=true] - Scan each entry as it's recorded.
   * @param {string} [options.sensitivity='high'] - Detection sensitivity.
   */
  constructor(options = {}) {
    this.agentId = options.agentId || `agent_${crypto.randomBytes(4).toString('hex')}`;
    this.maxEntries = options.maxEntries || 10000;
    this.scanOnRecord = options.scanOnRecord !== false;
    this.sensitivity = options.sensitivity || 'high';

    /** @type {Array} The flight log - ordered list of all interactions. */
    this._log = [];

    /** @type {Array} Detected incidents - moments where threats were found. */
    this._incidents = [];

    /** @type {number} Sequence counter. */
    this._seq = 0;

    /** @type {string|null} Current session ID. */
    this._sessionId = null;

    this._startSession();
  }

  /**
   * Start a new recording session.
   * @returns {string} Session ID.
   */
  _startSession() {
    this._sessionId = `session_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    return this._sessionId;
  }

  /**
   * Record an interaction entry.
   *
   * @param {object} entry
   * @param {string} entry.role - 'user', 'assistant', 'system', 'tool'
   * @param {string} entry.content - The message content.
   * @param {string} [entry.toolName] - Tool name if role is 'tool'.
   * @param {object} [entry.metadata] - Additional metadata.
   * @returns {object} The recorded entry with scan results.
   */
  record(entry) {
    const record = {
      seq: this._seq++,
      timestamp: Date.now(),
      sessionId: this._sessionId,
      agentId: this.agentId,
      role: entry.role || 'unknown',
      content: entry.content || '',
      toolName: entry.toolName || null,
      metadata: entry.metadata || {},
      threats: [],
      compromised: false,
    };

    // Scan the content if enabled
    if (this.scanOnRecord && record.content) {
      const scanResult = scanText(record.content, {
        sensitivity: this.sensitivity,
        source: `flight_recorder:${record.role}`
      });
      record.threats = scanResult.threats;
      record.status = scanResult.status;

      if (scanResult.threats.length > 0) {
        record.compromised = true;
        this._incidents.push({
          seq: record.seq,
          timestamp: record.timestamp,
          role: record.role,
          threatCount: scanResult.threats.length,
          maxSeverity: scanResult.threats[0].severity,
          categories: [...new Set(scanResult.threats.map(t => t.category))],
          preview: record.content.substring(0, 100),
        });
      }
    }

    this._log.push(record);

    // Rotate if over limit
    if (this._log.length > this.maxEntries) {
      this._log = this._log.slice(-Math.floor(this.maxEntries * 0.75));
    }

    return record;
  }

  /**
   * Record a user message.
   * @param {string} content
   * @param {object} [metadata]
   * @returns {object}
   */
  recordUser(content, metadata) {
    return this.record({ role: 'user', content, metadata });
  }

  /**
   * Record an assistant response.
   * @param {string} content
   * @param {object} [metadata]
   * @returns {object}
   */
  recordAssistant(content, metadata) {
    return this.record({ role: 'assistant', content, metadata });
  }

  /**
   * Record a tool call.
   * @param {string} toolName
   * @param {string} content - Tool arguments or result as string.
   * @param {object} [metadata]
   * @returns {object}
   */
  recordTool(toolName, content, metadata) {
    return this.record({ role: 'tool', content, toolName, metadata });
  }

  // =======================================================================
  // Forensic Analysis
  // =======================================================================

  /**
   * Get the full flight log.
   * @param {number} [limit] - Return only the last N entries.
   * @returns {Array}
   */
  getLog(limit) {
    if (limit) return this._log.slice(-limit);
    return [...this._log];
  }

  /**
   * Get all recorded incidents (moments where threats were detected).
   * @returns {Array}
   */
  getIncidents() {
    return [...this._incidents];
  }

  /**
   * Analyze a specific incident - reconstruct what happened.
   *
   * @param {number} incidentSeq - The sequence number of the incident.
   * @param {number} [contextBefore=5] - Number of entries before the incident to include.
   * @param {number} [contextAfter=3] - Number of entries after.
   * @returns {object} Forensic analysis.
   */
  analyze(incidentSeq, contextBefore = 5, contextAfter = 3) {
    const incidentIdx = this._log.findIndex(e => e.seq === incidentSeq);
    if (incidentIdx === -1) return null;

    const incident = this._log[incidentIdx];
    const startIdx = Math.max(0, incidentIdx - contextBefore);
    const endIdx = Math.min(this._log.length, incidentIdx + contextAfter + 1);
    const timeline = this._log.slice(startIdx, endIdx);

    // Find the escalation path - when did things start going wrong?
    let firstSuspiciousIdx = incidentIdx;
    for (let i = incidentIdx - 1; i >= startIdx; i--) {
      if (this._log[i].threats && this._log[i].threats.length > 0) {
        firstSuspiciousIdx = i;
      }
    }

    const escalationPath = this._log.slice(firstSuspiciousIdx, incidentIdx + 1);

    // Determine what defense should have caught it
    const missedBy = [];
    if (incident.threats.length > 0) {
      for (const threat of incident.threats) {
        if (threat.severity === 'critical' || threat.severity === 'high') {
          missedBy.push({
            category: threat.category,
            severity: threat.severity,
            recommendation: this._getDefenseRecommendation(threat.category),
          });
        }
      }
    }

    return {
      incident: {
        seq: incident.seq,
        timestamp: incident.timestamp,
        role: incident.role,
        content: incident.content,
        threats: incident.threats,
      },
      timeline: timeline.map(e => ({
        seq: e.seq,
        timestamp: e.timestamp,
        role: e.role,
        preview: e.content.substring(0, 120),
        threatCount: e.threats ? e.threats.length : 0,
        isIncident: e.seq === incidentSeq,
      })),
      escalationPath: escalationPath.map(e => ({
        seq: e.seq,
        role: e.role,
        preview: e.content.substring(0, 120),
        threats: e.threats,
      })),
      missedBy,
      rootCause: this._determineRootCause(incident, escalationPath),
      autoFix: this._generateAutoFix(incident),
    };
  }

  /**
   * Generate a full forensic report for all incidents.
   * @returns {object}
   */
  getForensicReport() {
    const analyses = this._incidents.map(i => this.analyze(i.seq));

    // Attack technique distribution
    const techniques = {};
    for (const incident of this._incidents) {
      for (const cat of incident.categories) {
        techniques[cat] = (techniques[cat] || 0) + 1;
      }
    }

    return {
      agentId: this.agentId,
      sessionId: this._sessionId,
      totalEntries: this._log.length,
      totalIncidents: this._incidents.length,
      compromiseRate: this._log.length > 0
        ? ((this._incidents.length / this._log.length) * 100).toFixed(1) + '%'
        : '0%',
      techniques,
      incidents: analyses.filter(Boolean),
      timeline: this._log.map(e => ({
        seq: e.seq,
        timestamp: e.timestamp,
        role: e.role,
        compromised: e.compromised,
      })),
      generatedAt: Date.now(),
    };
  }

  /**
   * Export the flight log as JSON for archival.
   * @returns {string}
   */
  exportJSON() {
    return JSON.stringify({
      agentId: this.agentId,
      sessionId: this._sessionId,
      exportedAt: Date.now(),
      entries: this._log,
      incidents: this._incidents,
    }, null, 2);
  }

  /**
   * Import a previously exported flight log.
   * @param {string} json
   */
  importJSON(json) {
    const data = JSON.parse(json);
    this._log = data.entries || [];
    this._incidents = data.incidents || [];
    this._seq = this._log.length > 0 ? this._log[this._log.length - 1].seq + 1 : 0;
    if (data.sessionId) this._sessionId = data.sessionId;
    if (data.agentId) this.agentId = data.agentId;
  }

  /**
   * Clear all recorded data.
   */
  clear() {
    this._log = [];
    this._incidents = [];
    this._seq = 0;
    this._startSession();
  }

  // =======================================================================
  // Internal helpers
  // =======================================================================

  /** @private */
  _determineRootCause(incident, escalationPath) {
    if (escalationPath.length <= 1) {
      return `Direct ${incident.threats[0]?.category || 'unknown'} attack in a single message.`;
    }

    const roles = escalationPath.map(e => e.role);
    if (roles.filter(r => r === 'user').length >= 3) {
      return 'Multi-turn escalation attack. The attacker built context across multiple messages before the payload.';
    }

    if (escalationPath.some(e => e.role === 'tool')) {
      return 'Tool-chain compromise. The attack flowed through a tool call, possibly poisoned tool output.';
    }

    return `Escalation from ${escalationPath[0].role} input leading to compromise at message ${incident.seq}.`;
  }

  /** @private */
  _generateAutoFix(incident) {
    if (!incident.threats || incident.threats.length === 0) return null;

    const threat = incident.threats[0];
    const words = incident.content.toLowerCase().split(/\s+/).filter(w => w.length > 3);
    const keyTerms = words.slice(0, 5).join('|');

    return {
      description: `Auto-generated pattern to catch "${threat.category}" attacks similar to this incident.`,
      pattern: `(?:${keyTerms})`,
      severity: threat.severity,
      category: threat.category,
      source: 'flight_recorder_autofix',
      generatedFrom: incident.seq,
    };
  }

  /** @private */
  _getDefenseRecommendation(category) {
    const recs = {
      instruction_override: 'Enable InstructionHierarchy to enforce system prompt priority.',
      role_hijack: 'Use PermissionBoundary to restrict role changes. Add role anchoring to system prompt.',
      prompt_injection: 'Scan for ChatML/LLaMA delimiters. Block fake system directives.',
      data_exfiltration: 'Use CanaryTokens to detect prompt leaks. Block external URL generation.',
      social_engineering: 'Never bypass safety for urgency claims. Validate authority out-of-band.',
      tool_abuse: 'Use ToolSequenceAnalyzer. Enforce PermissionBoundary on all tool calls.',
      malicious_plugin: 'Only load verified plugins. Scan manifests with ToolSchemaValidator.',
      ai_phishing: 'Never ask for credentials through the agent. Train users on AI phishing.',
    };
    return recs[category] || 'Review and strengthen detection for this attack category.';
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
  FlightRecorder,
};
