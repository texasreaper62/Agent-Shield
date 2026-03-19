'use strict';

/**
 * Multi-Agent Protection: Agent-to-Agent Firewall (#39),
 * Delegation Chain Tracking (#40), Consensus Verification (#41),
 * and Shared Threat State (#42)
 */

const { scanText } = require('./detector-core');

// =========================================================================
// AGENT-TO-AGENT FIREWALL
// =========================================================================

class AgentFirewall {
  /**
   * Scans all inter-agent messages. Enforces trust boundaries.
   *
   * @param {object} [options]
   * @param {object} [options.trustPolicy={}] - Trust levels between agents.
   * @param {string} [options.defaultTrust='scan'] - Default trust: 'trust', 'scan', or 'block'.
   * @param {Function} [options.onViolation] - Callback on firewall violation.
   */
  constructor(options = {}) {
    this.trustPolicy = options.trustPolicy || {};
    this.defaultTrust = options.defaultTrust || 'scan';
    this.onViolation = options.onViolation || null;
    this.messageLog = [];
  }

  /**
   * Sets trust level between two agents.
   *
   * @param {string} fromAgent - Sending agent ID.
   * @param {string} toAgent - Receiving agent ID.
   * @param {string} level - Trust level: 'trust', 'scan', or 'block'.
   * @returns {AgentFirewall} this
   */
  setTrust(fromAgent, toAgent, level) {
    const key = `${fromAgent}->${toAgent}`;
    this.trustPolicy[key] = level;
    return this;
  }

  /**
   * Checks an inter-agent message through the firewall.
   *
   * @param {string} fromAgent - Sending agent ID.
   * @param {string} toAgent - Receiving agent ID.
   * @param {string} message - The message content.
   * @returns {object} { allowed: boolean, scanned: boolean, threats: Array, reason?: string }
   */
  check(fromAgent, toAgent, message) {
    const key = `${fromAgent}->${toAgent}`;
    const trustLevel = this.trustPolicy[key] || this.defaultTrust;

    const logEntry = {
      from: fromAgent,
      to: toAgent,
      trustLevel,
      timestamp: Date.now(),
      messagePreview: message.substring(0, 100)
    };

    // Block immediately
    if (trustLevel === 'block') {
      logEntry.result = 'blocked';
      this.messageLog.push(logEntry);
      if (this.messageLog.length > 500) this.messageLog.shift();

      const result = {
        allowed: false,
        scanned: false,
        threats: [],
        reason: `Messages from "${fromAgent}" to "${toAgent}" are blocked by firewall policy.`
      };
      if (this.onViolation) { try { this.onViolation(result); } catch (e) { console.error('[Agent Shield] onViolation callback error:', e.message); } }
      return result;
    }

    // Trust — pass through without scanning
    if (trustLevel === 'trust') {
      logEntry.result = 'trusted';
      this.messageLog.push(logEntry);
      if (this.messageLog.length > 500) this.messageLog.shift();

      return { allowed: true, scanned: false, threats: [] };
    }

    // Scan — check for threats
    const scanResult = scanText(message, {
      source: `agent_message:${fromAgent}->${toAgent}`,
      sensitivity: 'high'
    });

    const allowed = scanResult.threats.length === 0;
    logEntry.result = allowed ? 'passed' : 'blocked';
    logEntry.threatCount = scanResult.threats.length;
    this.messageLog.push(logEntry);
    if (this.messageLog.length > 500) this.messageLog.shift();

    if (!allowed && this.onViolation) {
      try {
        this.onViolation({
          allowed: false,
          from: fromAgent,
          to: toAgent,
          threats: scanResult.threats,
          reason: `Inter-agent message from "${fromAgent}" contains threats.`
        });
      } catch (e) { console.error('[Agent Shield] onViolation callback error:', e.message); }
    }

    return {
      allowed,
      scanned: true,
      threats: scanResult.threats,
      reason: allowed ? undefined : `Message from "${fromAgent}" blocked: ${scanResult.threats.length} threat(s) detected.`
    };
  }

  getLog() {
    return [...this.messageLog];
  }

  reset() {
    this.messageLog = [];
  }
}

// =========================================================================
// DELEGATION CHAIN TRACKER
// =========================================================================

class DelegationChain {
  /**
   * Tracks the full chain of who requested what when agents delegate tasks.
   *
   * @param {object} [options]
   * @param {number} [options.maxDepth=10] - Maximum delegation depth.
   * @param {Function} [options.onMaxDepth] - Callback when max depth reached.
   */
  constructor(options = {}) {
    this.maxDepth = options.maxDepth || 10;
    this.onMaxDepth = options.onMaxDepth || null;
    this.chains = new Map(); // requestId -> chain
    this.activeChains = new Map(); // agentId -> requestId
    this.maxChains = options.maxChains || 1000;
  }

  /**
   * Starts a new delegation chain.
   *
   * @param {string} requestId - Unique request ID.
   * @param {string} originAgent - The agent that received the original request.
   * @param {string} [originalInput] - The original user input.
   * @returns {object} Chain entry.
   */
  start(requestId, originAgent, originalInput) {
    const chain = {
      requestId,
      originAgent,
      originalInput: originalInput ? originalInput.substring(0, 500) : null,
      steps: [{
        agent: originAgent,
        action: 'received_request',
        timestamp: Date.now(),
        depth: 0
      }],
      status: 'active',
      createdAt: Date.now()
    };

    // Prune completed chains if over limit
    if (this.chains.size >= this.maxChains) {
      for (const [id, c] of this.chains) {
        if (c.status === 'completed') { this.chains.delete(id); }
        if (this.chains.size < this.maxChains) break;
      }
    }

    this.chains.set(requestId, chain);
    this.activeChains.set(originAgent, requestId);
    return chain;
  }

  /**
   * Records a delegation from one agent to another.
   *
   * @param {string} requestId - The request chain ID.
   * @param {string} fromAgent - Delegating agent.
   * @param {string} toAgent - Receiving agent.
   * @param {string} action - What was delegated (e.g., 'call_tool:bash').
   * @param {string} [permissions] - What permissions the delegatee has.
   * @returns {object} { allowed: boolean, depth: number, chain: object }
   */
  delegate(requestId, fromAgent, toAgent, action, permissions) {
    const chain = this.chains.get(requestId);
    if (!chain) {
      return { allowed: false, depth: 0, chain: null, reason: 'Unknown request chain.' };
    }

    const depth = chain.steps.length;

    if (depth >= this.maxDepth) {
      if (this.onMaxDepth) {
        try { this.onMaxDepth({ requestId, depth, fromAgent, toAgent }); } catch (e) { console.error('[Agent Shield] onMaxDepth callback error:', e.message); }
      }
      return {
        allowed: false,
        depth,
        chain,
        reason: `Maximum delegation depth (${this.maxDepth}) reached. Possible delegation loop.`
      };
    }

    // Check for circular delegation
    const visited = new Set(chain.steps.map(s => s.agent));
    if (visited.has(toAgent)) {
      return {
        allowed: false,
        depth,
        chain,
        reason: `Circular delegation detected: "${toAgent}" is already in the delegation chain.`
      };
    }

    chain.steps.push({
      agent: fromAgent,
      delegatedTo: toAgent,
      action,
      permissions: permissions || 'inherited',
      timestamp: Date.now(),
      depth
    });

    this.activeChains.set(toAgent, requestId);

    return { allowed: true, depth, chain };
  }

  /**
   * Completes a delegation chain.
   * @param {string} requestId
   */
  complete(requestId) {
    const chain = this.chains.get(requestId);
    if (chain) {
      chain.status = 'completed';
      chain.completedAt = Date.now();
    }
  }

  /**
   * Gets the full chain for a request.
   * @param {string} requestId
   * @returns {object|null}
   */
  getChain(requestId) {
    return this.chains.get(requestId) || null;
  }

  /**
   * Gets the active chain for an agent.
   * @param {string} agentId
   * @returns {object|null}
   */
  getActiveChain(agentId) {
    const requestId = this.activeChains.get(agentId);
    return requestId ? this.chains.get(requestId) : null;
  }

  /**
   * Returns all chains.
   * @returns {Array}
   */
  getAllChains() {
    return Array.from(this.chains.values());
  }

  reset() {
    this.chains.clear();
    this.activeChains.clear();
  }
}

// =========================================================================
// SHARED THREAT STATE
// =========================================================================

class SharedThreatState {
  /**
   * When one agent detects an attack, broadcast the signature to all others.
   *
   * @param {object} [options]
   * @param {number} [options.ttlMs=3600000] - How long threats stay active (default: 1 hour).
   * @param {Function} [options.onBroadcast] - Callback when threat is broadcast.
   */
  constructor(options = {}) {
    this.ttlMs = options.ttlMs || 3600000;
    this.onBroadcast = options.onBroadcast || null;
    this.threats = new Map(); // signature -> threat data
    this.subscribers = new Map(); // agentId -> callback
  }

  /**
   * Registers an agent to receive threat broadcasts.
   *
   * @param {string} agentId
   * @param {Function} callback - Called with threat data when broadcast received.
   */
  subscribe(agentId, callback) {
    this.subscribers.set(agentId, callback);
  }

  /**
   * Unregisters an agent.
   * @param {string} agentId
   */
  unsubscribe(agentId) {
    this.subscribers.delete(agentId);
  }

  /**
   * Broadcasts a threat to all subscribed agents.
   *
   * @param {string} reportingAgent - Agent that detected the threat.
   * @param {object} threat - Threat data.
   * @param {string} threat.signature - Unique signature (e.g., hash of the attack text).
   * @param {string} threat.category - Threat category.
   * @param {string} threat.severity - Threat severity.
   * @param {string} [threat.description] - Description.
   */
  broadcast(reportingAgent, threat) {
    const entry = {
      ...threat,
      reportedBy: reportingAgent,
      reportedAt: Date.now(),
      expiresAt: Date.now() + this.ttlMs
    };

    this.threats.set(threat.signature, entry);

    // Notify all subscribers except the reporter
    for (const [agentId, callback] of this.subscribers) {
      if (agentId !== reportingAgent) {
        try { callback(entry); } catch (e) { console.error(`[Agent Shield] subscriber ${agentId} callback error:`, e.message); }
      }
    }

    if (this.onBroadcast) {
      try { this.onBroadcast(entry); } catch (e) { console.error('[Agent Shield] onBroadcast callback error:', e.message); }
    }
  }

  /**
   * Checks if a threat signature is already known.
   *
   * @param {string} signature
   * @returns {object|null} Known threat data, or null.
   */
  isKnown(signature) {
    const entry = this.threats.get(signature);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) {
      this.threats.delete(signature);
      return null;
    }
    return entry;
  }

  /**
   * Returns all active threats.
   * @returns {Array}
   */
  getActiveThreats() {
    const now = Date.now();
    const active = [];
    for (const [sig, entry] of this.threats) {
      if (now <= entry.expiresAt) {
        active.push(entry);
      } else {
        this.threats.delete(sig);
      }
    }
    return active;
  }

  /**
   * Generates a simple signature from text.
   * @param {string} text
   * @returns {string}
   */
  static generateSignature(text) {
    const crypto = require('crypto');
    return crypto.createHash('sha256').update(text.substring(0, 500)).digest('hex').substring(0, 16);
  }

  reset() {
    this.threats.clear();
  }
}

module.exports = { AgentFirewall, DelegationChain, SharedThreatState };
