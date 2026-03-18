'use strict';

/**
 * Agent Shield — Multi-Agent Trust
 *
 * - Message signing between agents (HMAC-based)
 * - Capability delegation tokens
 * - Blast radius containment
 */

const crypto = require('crypto');

// =========================================================================
// Message Signing Between Agents
// =========================================================================

class MessageSigner {
  constructor(options = {}) {
    this.algorithm = options.algorithm || 'sha256';
    this.keys = new Map(); // agentId -> secret
    this.verificationLog = [];
  }

  /**
   * Register an agent with a shared secret.
   */
  registerAgent(agentId, secret) {
    if (!secret || secret.length < 16) {
      throw new Error('Secret must be at least 16 characters');
    }
    this.keys.set(agentId, secret);
    return true;
  }

  /**
   * Generate a shared secret for an agent.
   */
  generateSecret(agentId) {
    const secret = crypto.randomBytes(32).toString('hex');
    this.keys.set(agentId, secret);
    return secret;
  }

  /**
   * Sign a message.
   * @param {string} fromAgent - Sender agent ID
   * @param {Object} message - Message payload
   * @returns {Object} Signed message envelope
   */
  sign(fromAgent, message) {
    const secret = this.keys.get(fromAgent);
    if (!secret) throw new Error(`Agent "${fromAgent}" not registered`);

    const payload = JSON.stringify(message);
    const timestamp = Date.now();
    const nonce = crypto.randomBytes(16).toString('hex');

    const signatureInput = `${fromAgent}:${timestamp}:${nonce}:${payload}`;
    const signature = crypto.createHmac(this.algorithm, secret).update(signatureInput).digest('hex');

    return {
      from: fromAgent,
      timestamp,
      nonce,
      payload: message,
      signature
    };
  }

  /**
   * Verify a signed message.
   * @param {Object} envelope - Signed message envelope
   * @param {number} maxAgeMs - Maximum age of message (default 5 min)
   * @returns {{ valid: boolean, reason?: string }}
   */
  verify(envelope, maxAgeMs = 300000) {
    const { from, timestamp, nonce, payload, signature } = envelope;

    // Check agent is registered
    const secret = this.keys.get(from);
    if (!secret) {
      this._logVerification(from, false, 'unknown_agent');
      return { valid: false, reason: 'Unknown agent' };
    }

    // Check timestamp freshness
    const age = Date.now() - timestamp;
    if (age > maxAgeMs) {
      this._logVerification(from, false, 'expired');
      return { valid: false, reason: `Message expired (${Math.round(age / 1000)}s old)` };
    }

    if (age < -5000) {
      this._logVerification(from, false, 'future_timestamp');
      return { valid: false, reason: 'Message has future timestamp' };
    }

    // Verify signature
    const signatureInput = `${from}:${timestamp}:${nonce}:${JSON.stringify(payload)}`;
    const expected = crypto.createHmac(this.algorithm, secret).update(signatureInput).digest('hex');

    if (!crypto.timingSafeEqual(Buffer.from(signature, 'hex'), Buffer.from(expected, 'hex'))) {
      this._logVerification(from, false, 'invalid_signature');
      return { valid: false, reason: 'Invalid signature' };
    }

    this._logVerification(from, true, 'ok');
    return { valid: true };
  }

  _logVerification(agent, valid, reason) {
    this.verificationLog.push({
      agent,
      valid,
      reason,
      timestamp: new Date().toISOString()
    });
    // Keep last 1000 entries
    while (this.verificationLog.length > 1000) this.verificationLog.shift();
  }

  getVerificationLog() { return this.verificationLog; }

  getStats() {
    const total = this.verificationLog.length;
    const valid = this.verificationLog.filter(l => l.valid).length;
    return {
      totalVerifications: total,
      valid,
      invalid: total - valid,
      registeredAgents: this.keys.size
    };
  }
}

// =========================================================================
// Capability Delegation Tokens
// =========================================================================

class CapabilityToken {
  constructor(data) {
    this.id = data.id || `cap_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    this.issuer = data.issuer;
    this.subject = data.subject;
    this.capabilities = data.capabilities || [];
    this.constraints = data.constraints || {};
    this.issuedAt = data.issuedAt || new Date().toISOString();
    this.expiresAt = data.expiresAt;
    this.maxUses = data.maxUses || Infinity;
    this.usedCount = data.usedCount || 0;
    this.revoked = data.revoked || false;
    this.parent = data.parent || null; // For delegation chains
  }

  isValid() {
    if (this.revoked) return false;
    if (this.expiresAt && new Date() > new Date(this.expiresAt)) return false;
    if (this.usedCount >= this.maxUses) return false;
    return true;
  }

  hasCapability(capability) {
    return this.capabilities.includes(capability) || this.capabilities.includes('*');
  }

  use() {
    this.usedCount++;
  }
}

class DelegationManager {
  constructor(options = {}) {
    this.tokens = new Map();
    this.maxChainDepth = options.maxChainDepth || 3;
    this.secret = options.secret || crypto.randomBytes(32).toString('hex');
    this.auditLog = [];
  }

  /**
   * Issue a new capability token.
   */
  issue(params) {
    const { issuer, subject, capabilities, constraints, ttlMs, maxUses, parent } = params;

    // Check chain depth
    if (parent) {
      const depth = this._getChainDepth(parent);
      if (depth >= this.maxChainDepth) {
        this._audit('issue_denied', issuer, `Chain depth ${depth} exceeds max ${this.maxChainDepth}`);
        return null;
      }

      // Delegated token can only have subset of parent capabilities
      const parentToken = this.tokens.get(parent);
      if (parentToken) {
        const invalid = capabilities.filter(c => !parentToken.hasCapability(c));
        if (invalid.length > 0) {
          this._audit('issue_denied', issuer, `Cannot delegate capabilities not held: ${invalid.join(', ')}`);
          return null;
        }
      }
    }

    const token = new CapabilityToken({
      issuer,
      subject,
      capabilities,
      constraints: constraints || {},
      expiresAt: ttlMs ? new Date(Date.now() + ttlMs).toISOString() : null,
      maxUses: maxUses || Infinity,
      parent
    });

    this.tokens.set(token.id, token);
    this._audit('issued', issuer, `Token ${token.id} for ${subject}: [${capabilities.join(', ')}]`);

    return {
      tokenId: token.id,
      expiresAt: token.expiresAt,
      capabilities: token.capabilities
    };
  }

  /**
   * Check if a token grants a specific capability.
   */
  check(tokenId, capability, context = {}) {
    const token = this.tokens.get(tokenId);
    if (!token) {
      this._audit('check_denied', 'unknown', `Token ${tokenId} not found`);
      return { allowed: false, reason: 'Token not found' };
    }

    if (!token.isValid()) {
      const reason = token.revoked ? 'Token revoked' : token.usedCount >= token.maxUses ? 'Max uses exceeded' : 'Token expired';
      this._audit('check_denied', token.subject, reason);
      return { allowed: false, reason };
    }

    if (!token.hasCapability(capability)) {
      this._audit('check_denied', token.subject, `Missing capability: ${capability}`);
      return { allowed: false, reason: `Capability "${capability}" not granted` };
    }

    // Check constraints
    if (token.constraints.allowedPaths && context.path) {
      const allowed = token.constraints.allowedPaths.some(p =>
        context.path.startsWith(p) || new RegExp(p).test(context.path)
      );
      if (!allowed) {
        this._audit('check_denied', token.subject, `Path ${context.path} not in allowed paths`);
        return { allowed: false, reason: 'Path not allowed by constraints' };
      }
    }

    token.use();
    this._audit('check_allowed', token.subject, `Used capability: ${capability}`);
    return { allowed: true, token: token.id, remaining: token.maxUses - token.usedCount };
  }

  /**
   * Revoke a token and all its children.
   */
  revoke(tokenId) {
    const token = this.tokens.get(tokenId);
    if (!token) return false;

    token.revoked = true;
    this._audit('revoked', token.issuer, `Token ${tokenId} revoked`);

    // Revoke all children
    for (const [id, t] of this.tokens) {
      if (t.parent === tokenId) {
        this.revoke(id);
      }
    }

    return true;
  }

  _getChainDepth(tokenId) {
    let depth = 0;
    let current = tokenId;
    while (current) {
      depth++;
      const token = this.tokens.get(current);
      current = token ? token.parent : null;
    }
    return depth;
  }

  _audit(action, agent, detail) {
    this.auditLog.push({ action, agent, detail, timestamp: new Date().toISOString() });
    while (this.auditLog.length > 1000) this.auditLog.shift();
  }

  getAuditLog() { return this.auditLog; }

  getActiveTokens() {
    const active = [];
    for (const [id, token] of this.tokens) {
      if (token.isValid()) {
        active.push({
          id,
          issuer: token.issuer,
          subject: token.subject,
          capabilities: token.capabilities,
          expiresAt: token.expiresAt,
          usedCount: token.usedCount,
          maxUses: token.maxUses === Infinity ? 'unlimited' : token.maxUses
        });
      }
    }
    return active;
  }
}

// =========================================================================
// Blast Radius Containment
// =========================================================================

class BlastRadiusContainer {
  constructor(options = {}) {
    this.zones = new Map();
    this.incidents = [];
    this.maxIncidents = options.maxIncidents || 500;
  }

  /**
   * Define a containment zone.
   */
  defineZone(zone) {
    this.zones.set(zone.name, {
      name: zone.name,
      description: zone.description || '',
      agents: new Set(zone.agents || []),
      allowedCapabilities: new Set(zone.allowedCapabilities || []),
      blockedCapabilities: new Set(zone.blockedCapabilities || []),
      canCommunicateWith: new Set(zone.canCommunicateWith || []),
      maxConcurrentActions: zone.maxConcurrentActions || 10,
      activeActions: 0,
      quarantined: false
    });
    return true;
  }

  /**
   * Check if an agent can perform an action.
   */
  checkAction(agentId, action, targetZone = null) {
    const zone = this._getAgentZone(agentId);
    if (!zone) {
      return { allowed: true, reason: 'Agent not in any zone (unrestricted)' };
    }

    if (zone.quarantined) {
      this._recordIncident(agentId, action, 'zone_quarantined');
      return { allowed: false, reason: `Zone "${zone.name}" is quarantined` };
    }

    if (zone.blockedCapabilities.has(action)) {
      this._recordIncident(agentId, action, 'blocked_capability');
      return { allowed: false, reason: `Action "${action}" is blocked in zone "${zone.name}"` };
    }

    if (zone.allowedCapabilities.size > 0 && !zone.allowedCapabilities.has(action)) {
      this._recordIncident(agentId, action, 'not_allowed');
      return { allowed: false, reason: `Action "${action}" not in allowed list for zone "${zone.name}"` };
    }

    if (zone.activeActions >= zone.maxConcurrentActions) {
      this._recordIncident(agentId, action, 'concurrent_limit');
      return { allowed: false, reason: `Zone "${zone.name}" has reached max concurrent actions` };
    }

    // Check cross-zone communication
    if (targetZone && !zone.canCommunicateWith.has(targetZone)) {
      this._recordIncident(agentId, action, 'cross_zone_blocked');
      return { allowed: false, reason: `Zone "${zone.name}" cannot communicate with zone "${targetZone}"` };
    }

    zone.activeActions++;
    return { allowed: true, zone: zone.name };
  }

  /**
   * Release an action slot.
   */
  releaseAction(agentId) {
    const zone = this._getAgentZone(agentId);
    if (zone && zone.activeActions > 0) zone.activeActions--;
  }

  /**
   * Quarantine a zone — block all actions.
   */
  quarantine(zoneName, reason) {
    const zone = this.zones.get(zoneName);
    if (!zone) return false;

    zone.quarantined = true;
    this._recordIncident('system', 'quarantine', `Zone ${zoneName}: ${reason}`);
    return true;
  }

  /**
   * Lift quarantine.
   */
  unquarantine(zoneName) {
    const zone = this.zones.get(zoneName);
    if (!zone) return false;

    zone.quarantined = false;
    this._recordIncident('system', 'unquarantine', `Zone ${zoneName} unquarantined`);
    return true;
  }

  _getAgentZone(agentId) {
    for (const [, zone] of this.zones) {
      if (zone.agents.has(agentId)) return zone;
    }
    return null;
  }

  _recordIncident(agent, action, type) {
    this.incidents.push({ agent, action, type, timestamp: new Date().toISOString() });
    while (this.incidents.length > this.maxIncidents) this.incidents.shift();
  }

  getZones() {
    const result = [];
    for (const [name, zone] of this.zones) {
      result.push({
        name,
        description: zone.description,
        agents: [...zone.agents],
        quarantined: zone.quarantined,
        activeActions: zone.activeActions,
        maxConcurrentActions: zone.maxConcurrentActions
      });
    }
    return result;
  }

  getIncidents() { return this.incidents; }
}

module.exports = {
  MessageSigner,
  CapabilityToken,
  DelegationManager,
  BlastRadiusContainer
};
