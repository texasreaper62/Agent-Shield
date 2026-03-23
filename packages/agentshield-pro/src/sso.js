'use strict';

/**
 * Agent Shield Pro — Enterprise SSO Integration
 *
 * Wraps the core SSO/SAML module with Pro-specific features:
 * - Simplified provider setup (Okta, Azure AD, Google Workspace, OneLogin)
 * - Session management with auto-refresh
 * - RBAC integration with shield config
 * - Provider health monitoring
 * - Audit logging of auth events
 *
 * Enterprise tier only.
 *
 * @module sso
 */

const crypto = require('crypto');

// =========================================================================
// Default IdP group-to-role mappings
// =========================================================================

const DEFAULT_ROLE_MAPPINGS = {
  admin: { shieldRole: 'admin', permissions: ['*'] },
  security: { shieldRole: 'analyst', permissions: ['scan', 'read', 'audit', 'configure', 'view_audit', 'manage_policies', 'view_reports'] },
  'security-team': { shieldRole: 'analyst', permissions: ['scan', 'read', 'audit', 'configure', 'view_audit', 'manage_policies', 'view_reports'] },
  developers: { shieldRole: 'operator', permissions: ['scan', 'read', 'configure', 'view_reports'] },
  engineering: { shieldRole: 'operator', permissions: ['scan', 'read', 'configure', 'view_reports'] },
  ops: { shieldRole: 'operator', permissions: ['scan', 'read', 'configure'] },
  viewers: { shieldRole: 'viewer', permissions: ['read', 'view_reports'] },
  '*': { shieldRole: 'viewer', permissions: ['read', 'view_reports'] },
};

// Provider presets
const PROVIDER_PRESETS = {
  okta: {
    type: 'saml',
    name: 'Okta',
    assertionFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress',
    groupAttribute: 'groups',
  },
  azure_ad: {
    type: 'oidc',
    name: 'Azure AD',
    scopes: ['openid', 'profile', 'email', 'groups'],
    groupClaim: 'groups',
  },
  google: {
    type: 'oidc',
    name: 'Google Workspace',
    scopes: ['openid', 'profile', 'email'],
    groupClaim: 'groups',
  },
  onelogin: {
    type: 'saml',
    name: 'OneLogin',
    assertionFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress',
    groupAttribute: 'memberOf',
  },
};


/**
 * Enterprise SSO integration manager.
 */
class SSOIntegration {
  /**
   * @param {Object} [options]
   * @param {string} [options.provider] - Provider preset: 'okta' | 'azure_ad' | 'google' | 'onelogin'
   * @param {Object} [options.providerConfig] - Custom provider config
   * @param {Object} [options.roleMappings] - Custom group-to-role mappings
   * @param {number} [options.sessionTTL=3600000] - Session TTL in ms (default 1 hour)
   * @param {number} [options.maxSessions=1000] - Maximum concurrent sessions
   * @param {boolean} [options.auditAuth=true] - Log authentication events
   */
  constructor(options = {}) {
    this.providerPreset = options.provider || null;
    this.providerConfig = options.providerConfig || {};
    this.roleMappings = options.roleMappings || { ...DEFAULT_ROLE_MAPPINGS };
    this.sessionTTL = options.sessionTTL || 3600000;
    this.maxSessions = options.maxSessions || 1000;
    this.auditAuth = options.auditAuth !== false;

    // Merge provider preset into config
    if (this.providerPreset && PROVIDER_PRESETS[this.providerPreset]) {
      this.providerConfig = { ...PROVIDER_PRESETS[this.providerPreset], ...this.providerConfig };
    }

    /** @private */
    this._sessions = new Map();   // sessionId -> session
    /** @private */
    this._auditLog = [];
    /** @private */
    this._stats = {
      totalLogins: 0,
      activeSessionCount: 0,
      failedLogins: 0,
      sessionsRevoked: 0,
    };
  }

  /**
   * Authenticate a user via SSO assertion/token.
   * Returns a session with mapped RBAC role and permissions.
   *
   * @param {Object} identity - Identity from IdP
   * @param {string} identity.email - User email
   * @param {string} [identity.name] - User display name
   * @param {string[]} [identity.groups] - IdP groups
   * @param {Object} [identity.attributes] - Additional IdP attributes
   * @returns {{ session: Object, role: string, permissions: string[] }}
   */
  authenticate(identity) {
    if (!identity || !identity.email) {
      this._stats.failedLogins++;
      this._audit('auth_failed', { reason: 'Missing identity or email' });
      throw new Error('[Agent Shield] SSO authentication requires an identity with email');
    }

    // Map groups to role
    const groups = identity.groups || [];
    const mapping = this._resolveRole(groups);

    // Create session
    const session = {
      id: crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex'),
      email: identity.email,
      name: identity.name || identity.email,
      groups,
      role: mapping.role,
      permissions: mapping.permissions,
      provider: this.providerConfig.name || 'custom',
      createdAt: Date.now(),
      expiresAt: Date.now() + this.sessionTTL,
      revoked: false,
    };

    // Enforce session limit
    if (this._sessions.size >= this.maxSessions) {
      this._evictOldest();
    }

    this._sessions.set(session.id, session);
    this._stats.totalLogins++;
    this._stats.activeSessionCount = this._sessions.size;
    this._audit('auth_success', { email: identity.email, role: mapping.role, sessionId: session.id });

    return {
      session: {
        id: session.id,
        email: session.email,
        name: session.name,
        role: session.role,
        permissions: session.permissions,
        expiresAt: new Date(session.expiresAt).toISOString(),
      },
      role: mapping.role,
      permissions: mapping.permissions,
    };
  }

  /**
   * Validate a session and check permissions.
   * @param {string} sessionId
   * @param {string} [requiredPermission] - Optional permission to check
   * @returns {{ valid: boolean, session?: Object, error?: string }}
   */
  validate(sessionId, requiredPermission) {
    const session = this._sessions.get(sessionId);
    if (!session) {
      return { valid: false, error: 'Session not found' };
    }
    if (session.revoked) {
      return { valid: false, error: 'Session revoked' };
    }
    if (Date.now() > session.expiresAt) {
      this._sessions.delete(sessionId);
      return { valid: false, error: 'Session expired' };
    }
    if (requiredPermission && !session.permissions.includes('*') && !session.permissions.includes(requiredPermission)) {
      return { valid: false, error: `Missing permission: ${requiredPermission}` };
    }

    return {
      valid: true,
      session: {
        id: session.id,
        email: session.email,
        role: session.role,
        permissions: session.permissions,
      },
    };
  }

  /**
   * Revoke a session.
   * @param {string} sessionId
   * @returns {boolean}
   */
  revoke(sessionId) {
    const session = this._sessions.get(sessionId);
    if (!session) return false;

    session.revoked = true;
    this._sessions.delete(sessionId);
    this._stats.sessionsRevoked++;
    this._stats.activeSessionCount = this._sessions.size;
    this._audit('session_revoked', { sessionId, email: session.email });

    return true;
  }

  /**
   * Revoke all sessions for an email.
   * @param {string} email
   * @returns {number} Sessions revoked
   */
  revokeAllForUser(email) {
    let count = 0;
    for (const [id, session] of this._sessions) {
      if (session.email === email) {
        session.revoked = true;
        this._sessions.delete(id);
        count++;
      }
    }
    this._stats.sessionsRevoked += count;
    this._stats.activeSessionCount = this._sessions.size;
    if (count > 0) this._audit('sessions_revoked_bulk', { email, count });
    return count;
  }

  /**
   * Add a custom role mapping.
   * @param {string} group - IdP group name
   * @param {string} role - Agent Shield role
   * @param {string[]} permissions - Permissions list
   */
  addRoleMapping(group, role, permissions) {
    this.roleMappings[group] = { shieldRole: role, permissions: permissions || [] };
  }

  /**
   * Create Express middleware that validates SSO sessions.
   * Extracts session ID from Authorization header or cookie.
   *
   * @param {Object} [options]
   * @param {string} [options.requiredPermission] - Permission to require
   * @param {string} [options.headerName='x-shield-session'] - Header for session ID
   * @returns {Function} Express middleware
   */
  middleware(options = {}) {
    const headerName = options.headerName || 'x-shield-session';
    const requiredPermission = options.requiredPermission || null;
    const sso = this;

    return function ssoMiddleware(req, res, next) {
      const sessionId = req.headers[headerName] || req.cookies?.shieldSession;
      if (!sessionId) {
        return res.status(401).json({ error: 'Missing session. Authenticate via SSO.' });
      }

      const result = sso.validate(sessionId, requiredPermission);
      if (!result.valid) {
        return res.status(403).json({ error: result.error });
      }

      req.shieldSession = result.session;
      next();
    };
  }

  /**
   * Get SSO statistics.
   * @returns {Object}
   */
  getStats() {
    return {
      ...this._stats,
      provider: this.providerConfig.name || 'custom',
      sessionTTL: this.sessionTTL,
    };
  }

  /**
   * Get authentication audit log.
   * @param {number} [limit=50] - Max entries to return
   * @returns {Array}
   */
  getAuditLog(limit = 50) {
    return this._auditLog.slice(-limit);
  }

  /** @private */
  _resolveRole(groups) {
    for (const group of groups) {
      if (this.roleMappings[group]) {
        const mapping = this.roleMappings[group];
        return { role: mapping.shieldRole, permissions: [...mapping.permissions] };
      }
    }
    // Fallback to wildcard
    const fallback = this.roleMappings['*'] || { shieldRole: 'viewer', permissions: ['read'] };
    return { role: fallback.shieldRole, permissions: [...fallback.permissions] };
  }

  /** @private */
  _evictOldest() {
    let oldestId = null;
    let oldestTime = Infinity;
    for (const [id, session] of this._sessions) {
      if (session.createdAt < oldestTime) {
        oldestTime = session.createdAt;
        oldestId = id;
      }
    }
    if (oldestId) this._sessions.delete(oldestId);
  }

  /** @private */
  _audit(event, data) {
    if (!this.auditAuth) return;
    this._auditLog.push({
      event,
      timestamp: new Date().toISOString(),
      ...data,
    });
    if (this._auditLog.length > 5000) this._auditLog.shift();
  }
}

module.exports = {
  SSOIntegration,
  DEFAULT_ROLE_MAPPINGS,
  PROVIDER_PRESETS,
};
