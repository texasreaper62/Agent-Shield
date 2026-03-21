'use strict';

/**
 * Agent Shield — Confused Deputy Prevention (Meta Incident Response)
 *
 * Addresses the four IAM gaps exposed by Meta's rogue AI agent incident (March 2026):
 *   Gap 2: Post-authentication blindness — validates intent after auth succeeds
 *   Gap 3: Static credentials — ephemeral, scoped, auto-rotating tokens
 *   Gap 4: Confused deputy via MCP — per-user authorization context propagation
 *
 * Gap 1 (inter-agent identity) is already addressed by agent-protocol.js.
 *
 * References:
 *   - VentureBeat: "Meta's rogue AI agent passed every identity check"
 *   - OWASP Feb 2026: Practical Guide for Secure MCP Server Development
 *   - CVE-2026-27826, CVE-2026-27825 (mcp-atlassian)
 *
 * All processing runs locally — no data ever leaves your environment.
 */

const crypto = require('crypto');

// =========================================================================
// Authorization Context — binds user identity to agent actions
// =========================================================================

/**
 * Immutable authorization context that flows through delegation chains.
 * Ensures every tool call traces back to the originating user + permissions.
 */
class AuthorizationContext {
  /**
   * @param {object} params
   * @param {string} params.userId - Originating user identity
   * @param {string} params.agentId - Agent performing the action
   * @param {string[]} [params.roles] - User's roles
   * @param {string[]} [params.scopes] - Granted permission scopes
   * @param {string} [params.intent] - Declared intent for this session
   * @param {number} [params.ttlMs=300000] - Context TTL (default 5 min)
   * @param {string} [params.parentContextId] - Parent context for delegation
   */
  constructor(params) {
    if (!params.userId) throw new Error('AuthorizationContext requires userId');
    if (!params.agentId) throw new Error('AuthorizationContext requires agentId');

    this.contextId = crypto.randomUUID();
    this.userId = params.userId;
    this.agentId = params.agentId;
    this.roles = Object.freeze([...(params.roles || [])]);
    this.scopes = Object.freeze([...(params.scopes || [])]);
    this.intent = params.intent || null;
    this.createdAt = Date.now();
    this.expiresAt = this.createdAt + (params.ttlMs !== null && params.ttlMs !== undefined ? params.ttlMs : 300000);
    this.parentContextId = params.parentContextId || null;
    this.delegationDepth = 0;

    // Sign the context to detect tampering
    this._signature = this._sign();
  }

  /** @returns {boolean} */
  isExpired() {
    return Date.now() >= this.expiresAt;
  }

  /** @returns {boolean} */
  hasScope(scope) {
    return this.scopes.includes(scope) || this.scopes.includes('*');
  }

  /** @returns {boolean} */
  hasRole(role) {
    return this.roles.includes(role) || this.roles.includes('admin');
  }

  /**
   * Creates a child context for delegation — scopes can only narrow, never widen.
   * @param {string} delegateAgentId
   * @param {string[]} [delegateScopes] - Must be subset of current scopes
   * @returns {AuthorizationContext}
   */
  delegate(delegateAgentId, delegateScopes) {
    if (this.isExpired()) throw new Error('Cannot delegate expired context');
    if (!this.verify()) throw new Error('Context integrity check failed');

    const narrowedScopes = delegateScopes
      ? delegateScopes.filter(s => this.hasScope(s))
      : [...this.scopes];

    const child = new AuthorizationContext({
      userId: this.userId,
      agentId: delegateAgentId,
      roles: [...this.roles],
      scopes: narrowedScopes,
      intent: this.intent,
      ttlMs: Math.max(0, this.expiresAt - Date.now()),
      parentContextId: this.contextId
    });
    child.delegationDepth = this.delegationDepth + 1;
    child._signature = child._sign();
    return child;
  }

  /** Verifies context has not been tampered with. */
  verify() {
    return this._signature === this._sign();
  }

  /** @private */
  _sign() {
    const data = `${this.contextId}:${this.userId}:${this.agentId}:${this.roles.join(',')}:${this.scopes.join(',')}:${this.expiresAt}`;
    return crypto.createHash('sha256').update(data).digest('hex');
  }
}

// =========================================================================
// Ephemeral Token Manager — scoped, auto-rotating credentials
// =========================================================================

/**
 * Issues short-lived, scoped tokens that replace static API keys.
 * Tokens are bound to a specific user, agent, and set of actions.
 */
class EphemeralTokenManager {
  /**
   * @param {object} [options]
   * @param {number} [options.tokenTtlMs=900000] - Token lifetime (default 15 min)
   * @param {number} [options.maxTokensPerUser=10] - Max active tokens per user
   * @param {number} [options.rotationWindowMs=60000] - Grace period after rotation
   */
  constructor(options = {}) {
    this.tokenTtlMs = options.tokenTtlMs || 900000;
    this.maxTokensPerUser = options.maxTokensPerUser || 10;
    this.rotationWindowMs = options.rotationWindowMs || 60000;
    this.tokens = new Map();
    this.userTokens = new Map();
    this.revokedTokens = new Set();
    this.stats = { issued: 0, rotated: 0, revoked: 0, expired: 0, validated: 0 };
  }

  /**
   * Issues an ephemeral token scoped to specific actions.
   * @param {AuthorizationContext} authCtx
   * @param {string[]} scopes - Scopes this token grants (must be subset of authCtx scopes)
   * @returns {{ tokenId: string, token: string, expiresAt: number, scopes: string[] }}
   */
  issueToken(authCtx, scopes = []) {
    if (authCtx.isExpired()) throw new Error('Cannot issue token for expired context');

    // Scopes can only narrow, never widen
    const grantedScopes = scopes.length > 0
      ? scopes.filter(s => authCtx.hasScope(s))
      : [...authCtx.scopes];

    // Enforce per-user token limit
    const userTokenList = this.userTokens.get(authCtx.userId) || [];
    const activeTokens = userTokenList.filter(id => {
      const t = this.tokens.get(id);
      return t && !this._isTokenExpired(t);
    });
    if (activeTokens.length >= this.maxTokensPerUser) {
      // Revoke oldest
      const oldest = activeTokens[0];
      this.revokeToken(oldest);
    }

    const tokenId = crypto.randomUUID();
    const tokenData = {
      tokenId,
      userId: authCtx.userId,
      agentId: authCtx.agentId,
      contextId: authCtx.contextId,
      scopes: grantedScopes,
      issuedAt: Date.now(),
      expiresAt: Date.now() + this.tokenTtlMs,
      rotatedFrom: null,
      usageCount: 0
    };

    this.tokens.set(tokenId, tokenData);
    const updated = [...activeTokens, tokenId];
    this.userTokens.set(authCtx.userId, updated);
    this.stats.issued++;

    return {
      tokenId,
      token: this._encodeToken(tokenData),
      expiresAt: tokenData.expiresAt,
      scopes: grantedScopes
    };
  }

  /**
   * Validates a token and returns its context.
   * @param {string} tokenId
   * @returns {{ valid: boolean, reason: string|null, userId: string|null, scopes: string[] }}
   */
  validateToken(tokenId) {
    this.stats.validated++;
    const tokenData = this.tokens.get(tokenId);

    if (!tokenData) {
      return { valid: false, reason: 'Token not found', userId: null, scopes: [] };
    }
    if (this.revokedTokens.has(tokenId)) {
      return { valid: false, reason: 'Token has been revoked', userId: tokenData.userId, scopes: [] };
    }
    if (this._isTokenExpired(tokenData)) {
      this.stats.expired++;
      return { valid: false, reason: 'Token has expired', userId: tokenData.userId, scopes: [] };
    }

    tokenData.usageCount++;
    return { valid: true, reason: null, userId: tokenData.userId, scopes: tokenData.scopes };
  }

  /**
   * Rotates a token — issues new token, old remains valid during grace period.
   * @param {string} oldTokenId
   * @param {AuthorizationContext} authCtx
   * @returns {{ tokenId: string, token: string, expiresAt: number, scopes: string[] }|null}
   */
  rotateToken(oldTokenId, authCtx) {
    const oldToken = this.tokens.get(oldTokenId);
    if (!oldToken || this.revokedTokens.has(oldTokenId)) return null;

    // Issue new token with same scopes
    const newTokenResult = this.issueToken(authCtx, oldToken.scopes);

    // Mark old token for grace-period expiry
    oldToken.expiresAt = Math.min(oldToken.expiresAt, Date.now() + this.rotationWindowMs);
    const newTokenData = this.tokens.get(newTokenResult.tokenId);
    if (newTokenData) newTokenData.rotatedFrom = oldTokenId;

    this.stats.rotated++;
    return newTokenResult;
  }

  /**
   * Revokes a token immediately.
   * @param {string} tokenId
   */
  revokeToken(tokenId) {
    this.revokedTokens.add(tokenId);
    this.stats.revoked++;
  }

  /**
   * Revokes all tokens for a user.
   * @param {string} userId
   * @returns {number} Number of tokens revoked
   */
  revokeAllForUser(userId) {
    const userTokenList = this.userTokens.get(userId) || [];
    let count = 0;
    for (const id of userTokenList) {
      if (!this.revokedTokens.has(id)) {
        this.revokeToken(id);
        count++;
      }
    }
    return count;
  }

  /** @returns {object} */
  getStats() {
    return { ...this.stats, activeTokens: this.tokens.size - this.revokedTokens.size };
  }

  /** @private */
  _isTokenExpired(tokenData) {
    return Date.now() > tokenData.expiresAt;
  }

  /** @private */
  _encodeToken(tokenData) {
    const payload = `${tokenData.tokenId}:${tokenData.userId}:${tokenData.scopes.join(',')}:${tokenData.expiresAt}`;
    return crypto.createHash('sha256').update(payload).digest('hex');
  }
}

// =========================================================================
// Intent Validator — post-auth action verification
// =========================================================================

/**
 * Validates that tool calls match the agent's declared intent and user permissions.
 * Closes the "post-authentication blindness" gap.
 */
class IntentValidator {
  /**
   * @param {object} [options]
   * @param {boolean} [options.requireIntent=false] - Require declared intent for all actions
   * @param {number} [options.maxDelegationDepth=5] - Maximum delegation chain depth
   * @param {Function} [options.onViolation] - Callback on policy violation
   */
  constructor(options = {}) {
    this.requireIntent = options.requireIntent || false;
    this.maxDelegationDepth = options.maxDelegationDepth || 5;
    this.onViolation = options.onViolation || null;
    this.policies = [];
    this.auditLog = [];
  }

  /**
   * Registers a tool-level authorization policy.
   * @param {object} policy
   * @param {string|RegExp} policy.tool - Tool name or pattern
   * @param {string[]} [policy.requiredScopes] - Scopes needed to use this tool
   * @param {string[]} [policy.requiredRoles] - Roles needed to use this tool
   * @param {string[]} [policy.allowedIntents] - Intents that may use this tool
   * @param {boolean} [policy.requiresHumanApproval=false] - Needs human-in-the-loop
   */
  addPolicy(policy) {
    this.policies.push({
      tool: policy.tool,
      requiredScopes: policy.requiredScopes || [],
      requiredRoles: policy.requiredRoles || [],
      allowedIntents: policy.allowedIntents || [],
      requiresHumanApproval: policy.requiresHumanApproval || false
    });
  }

  /**
   * Validates a tool call against the authorization context and policies.
   * @param {string} toolName
   * @param {object} args
   * @param {AuthorizationContext} authCtx
   * @returns {{ allowed: boolean, violations: Array, requiresApproval: boolean }}
   */
  validateAction(toolName, args, authCtx) {
    const violations = [];
    let requiresApproval = false;

    // Check context validity
    if (!authCtx || !authCtx.verify()) {
      violations.push({ type: 'integrity', message: 'Authorization context is missing or tampered' });
    } else if (authCtx.isExpired()) {
      violations.push({ type: 'expired', message: 'Authorization context has expired' });
    }

    if (violations.length > 0) {
      this._logAudit(toolName, authCtx, violations, false);
      return { allowed: false, violations, requiresApproval: false };
    }

    // Check delegation depth
    if (authCtx.delegationDepth > this.maxDelegationDepth) {
      violations.push({ type: 'delegation_depth', message: `Delegation depth ${authCtx.delegationDepth} exceeds max ${this.maxDelegationDepth}` });
    }

    // Check intent requirement
    if (this.requireIntent && !authCtx.intent) {
      violations.push({ type: 'missing_intent', message: 'No intent declared for this action' });
    }

    // Check policies
    for (const policy of this.policies) {
      const toolMatch = policy.tool instanceof RegExp
        ? policy.tool.test(toolName)
        : policy.tool === toolName || policy.tool === '*';

      if (!toolMatch) continue;

      // Scope check
      for (const scope of policy.requiredScopes) {
        if (!authCtx.hasScope(scope)) {
          violations.push({ type: 'scope', message: `Missing required scope "${scope}" for tool "${toolName}"`, tool: toolName });
        }
      }

      // Role check
      if (policy.requiredRoles.length > 0) {
        const hasRequired = policy.requiredRoles.some(r => authCtx.hasRole(r));
        if (!hasRequired) {
          violations.push({ type: 'role', message: `Requires role ${policy.requiredRoles.join('|')} for tool "${toolName}"`, tool: toolName });
        }
      }

      // Intent check
      if (policy.allowedIntents.length > 0 && authCtx.intent) {
        const intentAllowed = policy.allowedIntents.some(i =>
          authCtx.intent.toLowerCase().includes(i.toLowerCase())
        );
        if (!intentAllowed) {
          violations.push({ type: 'intent', message: `Intent "${authCtx.intent}" not allowed for tool "${toolName}"`, tool: toolName });
        }
      }

      // Human approval check
      if (policy.requiresHumanApproval) {
        requiresApproval = true;
      }
    }

    const allowed = violations.length === 0;

    if (!allowed && this.onViolation) {
      this.onViolation({ toolName, args, authCtx, violations });
    }

    this._logAudit(toolName, authCtx, violations, allowed);
    return { allowed, violations, requiresApproval };
  }

  /**
   * Returns the audit log.
   * @param {number} [limit=100]
   * @returns {Array}
   */
  getAuditLog(limit = 100) {
    return this.auditLog.slice(-limit);
  }

  /** @private */
  _logAudit(toolName, authCtx, violations, allowed) {
    this.auditLog.push({
      timestamp: Date.now(),
      toolName,
      userId: authCtx ? authCtx.userId : null,
      agentId: authCtx ? authCtx.agentId : null,
      contextId: authCtx ? authCtx.contextId : null,
      delegationDepth: authCtx ? authCtx.delegationDepth : null,
      allowed,
      violations: violations.length > 0 ? violations : undefined
    });
  }
}

// =========================================================================
// ConfusedDeputyGuard — MCP-aware per-user authorization
// =========================================================================

/**
 * Prevents confused deputy attacks by enforcing per-user authorization
 * on every tool call, not just per-agent or per-session.
 */
class ConfusedDeputyGuard {
  /**
   * @param {object} [options]
   * @param {boolean} [options.enforceContext=true] - Require AuthorizationContext on all calls
   * @param {boolean} [options.logOnly=false] - Log violations without blocking
   */
  constructor(options = {}) {
    this.enforceContext = options.enforceContext !== false;
    this.logOnly = options.logOnly || false;
    this.tokenManager = new EphemeralTokenManager(options);
    this.intentValidator = new IntentValidator(options);
    this.toolPermissions = new Map();
    this.stats = { checked: 0, allowed: 0, denied: 0, escalations: 0 };
  }

  /**
   * Registers tool-level permission requirements.
   * @param {string} toolName
   * @param {object} requirements
   * @param {string[]} [requirements.scopes] - Required scopes
   * @param {string[]} [requirements.roles] - Required roles
   * @param {boolean} [requirements.requiresHumanApproval] - Needs HITL
   */
  registerTool(toolName, requirements = {}) {
    this.toolPermissions.set(toolName, requirements);
    this.intentValidator.addPolicy({
      tool: toolName,
      requiredScopes: requirements.scopes || [],
      requiredRoles: requirements.roles || [],
      requiresHumanApproval: requirements.requiresHumanApproval || false
    });
  }

  /**
   * Wraps a tool call with confused deputy prevention.
   * @param {string} toolName
   * @param {object} args
   * @param {AuthorizationContext} [authCtx]
   * @returns {{ allowed: boolean, violations: Array, requiresApproval: boolean, token: object|null }}
   */
  wrapToolCall(toolName, args, authCtx) {
    this.stats.checked++;

    // Enforce context requirement
    if (this.enforceContext && !authCtx) {
      this.stats.denied++;
      const violation = [{ type: 'missing_context', message: 'AuthorizationContext required but not provided — potential confused deputy' }];
      if (!this.logOnly) {
        return { allowed: false, violations: violation, requiresApproval: false, token: null };
      }
    }

    if (!authCtx) {
      this.stats.allowed++;
      return { allowed: true, violations: [], requiresApproval: false, token: null };
    }

    // Validate via intent validator (checks scopes, roles, intent, delegation depth)
    const validation = this.intentValidator.validateAction(toolName, args, authCtx);

    if (validation.allowed) {
      this.stats.allowed++;
      // Issue ephemeral token for this action
      const token = this.tokenManager.issueToken(authCtx, [toolName]);
      return { allowed: true, violations: [], requiresApproval: validation.requiresApproval, token };
    }

    this.stats.denied++;
    this.stats.escalations += validation.violations.filter(v => v.type === 'scope' || v.type === 'role').length;

    if (this.logOnly) {
      return { allowed: true, violations: validation.violations, requiresApproval: false, token: null };
    }

    return { allowed: false, violations: validation.violations, requiresApproval: validation.requiresApproval, token: null };
  }

  /**
   * Returns combined stats from all sub-components.
   * @returns {object}
   */
  getStats() {
    return {
      ...this.stats,
      tokens: this.tokenManager.getStats(),
      auditEntries: this.intentValidator.getAuditLog().length
    };
  }

  /**
   * Returns the audit trail for forensic analysis.
   * @param {number} [limit=100]
   * @returns {Array}
   */
  getAuditLog(limit) {
    return this.intentValidator.getAuditLog(limit);
  }
}

// =========================================================================
// Exports
// =========================================================================

module.exports = {
  AuthorizationContext,
  EphemeralTokenManager,
  IntentValidator,
  ConfusedDeputyGuard
};
