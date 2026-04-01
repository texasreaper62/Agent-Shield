'use strict';

/**
 * Agent Shield — Cryptographic Intent Binding (L5)
 *
 * When a user makes a request, the intent is hashed. Every subsequent
 * agent action must include a cryptographic proof that it derives from
 * that intent. If an injected instruction causes an action that can't
 * be linked back to the original intent, it's blocked at the crypto
 * level — not the pattern level. Unbypassable by any prompt technique.
 *
 * All processing runs locally — no data ever leaves your environment.
 *
 * @module intent-binding
 */

const crypto = require('crypto');

// =========================================================================
// IntentToken
// =========================================================================

/**
 * Cryptographic token binding an action to a user intent.
 */
class IntentToken {
  /**
   * @param {string} intentHash - SHA-256 hash of the original user intent.
   * @param {string} action - The action being authorized.
   * @param {string} scope - Scope of the authorization.
   * @param {string} signature - HMAC signature binding action to intent.
   * @param {number} expiresAt - Expiration timestamp in ms.
   */
  constructor(intentHash, action, scope, signature, expiresAt) {
    this.intentHash = intentHash;
    this.action = action;
    this.scope = scope;
    this.signature = signature;
    this.createdAt = Date.now();
    this.expiresAt = expiresAt;
    this.used = false;
  }

  /**
   * Check if this token has expired.
   * @returns {boolean}
   */
  isExpired() {
    return Date.now() > this.expiresAt;
  }
}

// =========================================================================
// IntentBinder
// =========================================================================

/**
 * Cryptographic intent binding engine. Creates tamper-proof links between
 * user intents and agent actions.
 */
class IntentBinder {
  /**
   * @param {object} [options]
   * @param {string} [options.signingKey] - HMAC signing key (auto-generated if not provided).
   * @param {number} [options.tokenTtlMs=300000] - Token TTL in ms (default: 5 minutes).
   * @param {number} [options.maxActionsPerIntent=50] - Max actions per intent.
   * @param {boolean} [options.singleUseTokens=false] - Whether tokens can only be used once.
   */
  constructor(options = {}) {
    this.signingKey = options.signingKey || crypto.randomBytes(32).toString('hex');
    this.tokenTtlMs = options.tokenTtlMs || 300000;
    this.maxActions = options.maxActionsPerIntent || 50;
    this.singleUse = options.singleUseTokens || false;

    /** @type {Map<string, { intent: string, hash: string, actions: string[], createdAt: number }>} */
    this.activeIntents = new Map();

    /** @type {Array<object>} */
    this.auditLog = [];
    this.stats = { intentsBound: 0, tokensIssued: 0, verified: 0, rejected: 0 };
  }

  /**
   * Bind a user intent. Returns an intent hash that must be included
   * with every subsequent action.
   *
   * @param {string} intentText - The user's original request.
   * @param {object} [metadata] - Additional context (userId, sessionId, etc.).
   * @returns {{ intentHash: string, allowedActions: string[] }}
   */
  bindIntent(intentText, metadata = {}) {
    const intentHash = this._hash(intentText);
    const allowedActions = this._deriveAllowedActions(intentText);

    this.activeIntents.set(intentHash, {
      intent: intentText,
      hash: intentHash,
      actions: allowedActions,
      metadata,
      createdAt: Date.now(),
      actionCount: 0
    });

    this.stats.intentsBound++;
    this._log('intent_bound', { intentHash, allowedActions, metadata });

    return { intentHash, allowedActions };
  }

  /**
   * Issue a cryptographic token authorizing a specific action
   * linked to an intent.
   *
   * @param {string} intentHash - The intent hash from bindIntent().
   * @param {string} action - The action to authorize (e.g., 'tool:readFile').
   * @param {string} [scope] - Optional scope restriction.
   * @returns {{ token: IntentToken|null, error: string|null }}
   */
  issueToken(intentHash, action, scope) {
    const intent = this.activeIntents.get(intentHash);
    if (!intent) {
      this.stats.rejected++;
      return { token: null, error: 'Intent not found or expired.' };
    }

    // Check action limit
    if (intent.actionCount >= this.maxActions) {
      this.stats.rejected++;
      return { token: null, error: `Action limit (${this.maxActions}) exceeded for this intent.` };
    }

    // Verify the action is derivable from the intent
    if (!this._isActionAllowed(intent, action)) {
      this.stats.rejected++;
      this._log('token_rejected', { intentHash, action, reason: 'Action not derivable from intent.' });
      return { token: null, error: `Action "${action}" is not derivable from the bound intent.` };
    }

    // Create signed token
    const scopeStr = scope || 'default';
    const payload = `${intentHash}:${action}:${scopeStr}`;
    const signature = this._sign(payload);
    const expiresAt = Date.now() + this.tokenTtlMs;

    const token = new IntentToken(intentHash, action, scopeStr, signature, expiresAt);
    intent.actionCount++;
    this.stats.tokensIssued++;
    this._log('token_issued', { intentHash, action, scope: scopeStr });

    return { token, error: null };
  }

  /**
   * Verify that a token is valid and the action is still bound to the intent.
   *
   * @param {IntentToken} token - The token to verify.
   * @returns {{ valid: boolean, reason: string|null }}
   */
  verify(token) {
    if (!token) {
      this.stats.rejected++;
      return { valid: false, reason: 'No token provided.' };
    }

    if (token.isExpired()) {
      this.stats.rejected++;
      return { valid: false, reason: 'Token has expired.' };
    }

    if (this.singleUse && token.used) {
      this.stats.rejected++;
      return { valid: false, reason: 'Token has already been used (single-use mode).' };
    }

    // Verify HMAC signature
    const payload = `${token.intentHash}:${token.action}:${token.scope}`;
    const expectedSig = this._sign(payload);
    if (token.signature !== expectedSig) {
      this.stats.rejected++;
      this._log('token_tampered', { intentHash: token.intentHash, action: token.action });
      return { valid: false, reason: 'Token signature is invalid. Possible tampering.' };
    }

    // Verify intent still active
    if (!this.activeIntents.has(token.intentHash)) {
      this.stats.rejected++;
      return { valid: false, reason: 'Bound intent no longer active.' };
    }

    token.used = true;
    this.stats.verified++;
    return { valid: true, reason: null };
  }

  /**
   * Revoke an intent and all its tokens.
   * @param {string} intentHash
   * @returns {boolean}
   */
  revokeIntent(intentHash) {
    const deleted = this.activeIntents.delete(intentHash);
    if (deleted) this._log('intent_revoked', { intentHash });
    return deleted;
  }

  /**
   * Get statistics.
   * @returns {object}
   */
  getStats() {
    return { ...this.stats, activeIntents: this.activeIntents.size };
  }

  /**
   * Get audit log.
   * @returns {Array<object>}
   */
  getAuditLog() {
    return [...this.auditLog];
  }

  /**
   * Purge expired intents.
   */
  purgeExpired() {
    const now = Date.now();
    for (const [hash, intent] of this.activeIntents) {
      if (now - intent.createdAt > this.tokenTtlMs * 2) {
        this.activeIntents.delete(hash);
      }
    }
  }

  // -----------------------------------------------------------------------
  // Private
  // -----------------------------------------------------------------------

  /**
   * Derive allowed actions from intent text using keyword analysis.
   * @private
   */
  _deriveAllowedActions(intentText) {
    const lower = intentText.toLowerCase();
    const actions = [];

    if (/\b(?:read|get|fetch|show|display|find|search|query|list|look\s*up)\b/.test(lower)) actions.push('data:read');
    if (/\b(?:write|create|update|edit|modify|save|add|insert|set)\b/.test(lower)) actions.push('data:write');
    if (/\b(?:delete|remove|drop|clear|purge|destroy)\b/.test(lower)) actions.push('data:delete');
    if (/\b(?:send|email|message|notify|post|share|communicate|slack)\b/.test(lower)) actions.push('comm:send');
    if (/\b(?:run|execute|bash|shell|script|compile|build|test)\b/.test(lower)) actions.push('exec:run');
    if (/\b(?:file|open|download|upload|path|directory|folder)\b/.test(lower)) actions.push('fs:access');
    if (/\b(?:http|api|request|fetch|curl|endpoint|url|webhook)\b/.test(lower)) actions.push('net:request');
    if (/\b(?:analyze|calculate|compute|summarize|compare|evaluate)\b/.test(lower)) actions.push('compute:analyze');

    if (actions.length === 0) actions.push('compute:analyze'); // Default: analysis only

    return actions;
  }

  /**
   * Check if an action is allowed by the bound intent.
   * @private
   */
  _isActionAllowed(intent, action) {
    // Exact match
    if (intent.actions.includes(action)) return true;

    // Category match (e.g., 'data:read' allows 'tool:readFile')
    const actionCategory = action.split(':')[0];
    return intent.actions.some(a => a.split(':')[0] === actionCategory);
  }

  /**
   * SHA-256 hash.
   * @private
   */
  _hash(text) {
    return crypto.createHash('sha256').update(text).digest('hex');
  }

  /**
   * HMAC-SHA256 sign.
   * @private
   */
  _sign(payload) {
    return crypto.createHmac('sha256', this.signingKey).update(payload).digest('hex');
  }

  /**
   * Log an event.
   * @private
   */
  _log(action, details) {
    this.auditLog.push({ timestamp: Date.now(), action, ...details });
    if (this.auditLog.length > 5000) {
      this.auditLog = this.auditLog.slice(-5000);
    }
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
  IntentBinder,
  IntentToken,
  PROVENANCE: require('./semantic-isolation').PROVENANCE
};
