'use strict';

/**
 * Agent Shield — Enterprise Features
 *
 * - Multi-tenant support
 * - Role-based policies
 * - Debug mode with detailed traces
 * - Policy inheritance and overrides
 */

const { AgentShield } = require('./index');
const { loadPolicy } = require('./policy');

// =========================================================================
// Multi-Tenant Shield
// =========================================================================

/**
 * Multi-tenant Shield.
 *
 * SECURITY: Tenant IDs are treated as trust boundaries — scans, stats,
 * and policies are partitioned per `tenantId`. In production, callers
 * MUST configure `options.tenantVerifier` to prove that a supplied
 * tenantId was established by a trusted authentication mechanism
 * (JWT, session, mTLS, etc.). Without a verifier, a caller that can
 * invent tenant IDs can read/write any tenant's data.
 *
 * @example
 * const shield = new MultiTenantShield({
 *   tenantVerifier: (tenantId, ctx) => ctx && ctx.jwt && ctx.jwt.tenant === tenantId,
 *   strictAuth: true
 * });
 * shield.scan('tenant-42', userInput, { context: { jwt: decodedJwt } });
 */
class MultiTenantShield {
  constructor(options = {}) {
    this.tenants = new Map();
    this.defaultPolicy = options.defaultPolicy || { sensitivity: 'high', blockOnThreat: true };
    this.globalOverrides = options.globalOverrides || {};
    this.onTenantCreated = options.onTenantCreated || null;
    this.tenantVerifier = typeof options.tenantVerifier === 'function'
      ? options.tenantVerifier
      : null;
    this.strictAuth = options.strictAuth === true;

    if (!this.tenantVerifier) {
      if (this.strictAuth) {
        throw new Error(
          '[Agent Shield] MultiTenantShield: strictAuth is enabled but no options.tenantVerifier was provided. Supply a (tenantId, context) => boolean verifier.'
        );
      }
      console.warn('[Agent Shield] WARNING: MultiTenantShield has no tenantVerifier. Tenant IDs are trusted by default. Set options.tenantVerifier in production.');
    }
  }

  /**
   * Verify that a tenantId is authorized for the current caller.
   * @param {string} tenantId
   * @param {object} [context] - Request/auth context passed by the caller.
   * @returns {boolean}
   * @private
   */
  _verifyTenant(tenantId, context) {
    if (typeof tenantId !== 'string' || tenantId.length === 0) {
      throw new Error('[Agent Shield] MultiTenantShield: tenantId must be a non-empty string');
    }
    if (!this.tenantVerifier) {
      // Backward-compatible: permit by default, warning already logged at construction.
      return true;
    }
    let ok = false;
    try {
      ok = this.tenantVerifier(tenantId, context || {}) === true;
    } catch (err) {
      throw new Error(`[Agent Shield] MultiTenantShield: tenantVerifier threw while verifying tenant "${tenantId}": ${err.message}`);
    }
    if (!ok) {
      throw new Error(`[Agent Shield] MultiTenantShield: tenantVerifier rejected tenant "${tenantId}"`);
    }
    return true;
  }

  /**
   * Return a new MultiTenantShield that reuses this instance's tenant
   * registrations/stats but enforces the supplied tenant verifier. Useful
   * for adding auth to an existing shield without mutating global state.
   *
   * @param {(tenantId: string, context: object) => boolean} verifier
   * @param {object} [extraOptions]
   * @returns {MultiTenantShield}
   */
  withAuth(verifier, extraOptions = {}) {
    if (typeof verifier !== 'function') {
      throw new Error('[Agent Shield] MultiTenantShield.withAuth: verifier must be a function');
    }
    const next = new MultiTenantShield({
      defaultPolicy: this.defaultPolicy,
      globalOverrides: this.globalOverrides,
      onTenantCreated: this.onTenantCreated,
      tenantVerifier: verifier,
      strictAuth: extraOptions.strictAuth === true
    });
    // Share tenant registry so existing tenants remain accessible.
    next.tenants = this.tenants;
    return next;
  }

  /**
   * Register a tenant with its own policy.
   * @param {string} tenantId
   * @param {object} [policy]
   * @param {object} [context] - Auth context forwarded to the tenantVerifier.
   */
  registerTenant(tenantId, policy = {}, context) {
    this._verifyTenant(tenantId, context);
    const mergedPolicy = { ...this.defaultPolicy, ...policy, ...this.globalOverrides };
    const shield = new AgentShield(mergedPolicy);

    this.tenants.set(tenantId, {
      id: tenantId,
      policy: mergedPolicy,
      shield,
      stats: { scans: 0, threats: 0, blocked: 0 },
      createdAt: new Date().toISOString()
    });

    if (this.onTenantCreated) {
      this.onTenantCreated(tenantId, mergedPolicy);
    }

    return this;
  }

  /**
   * Get or auto-create a tenant shield.
   * @param {string} tenantId
   * @param {object} [context] - Auth context forwarded to the tenantVerifier.
   */
  getTenant(tenantId, context) {
    this._verifyTenant(tenantId, context);
    if (!this.tenants.has(tenantId)) {
      // Skip re-verification — we just verified above.
      const mergedPolicy = { ...this.defaultPolicy, ...this.globalOverrides };
      const shield = new AgentShield(mergedPolicy);
      this.tenants.set(tenantId, {
        id: tenantId,
        policy: mergedPolicy,
        shield,
        stats: { scans: 0, threats: 0, blocked: 0 },
        createdAt: new Date().toISOString()
      });
      if (this.onTenantCreated) {
        this.onTenantCreated(tenantId, mergedPolicy);
      }
    }
    return this.tenants.get(tenantId);
  }

  /**
   * Scan input for a specific tenant.
   * @param {string} tenantId
   * @param {string} text
   * @param {object} [options]
   * @param {object} [options.context] - Auth context forwarded to the tenantVerifier.
   */
  scan(tenantId, text, options = {}) {
    const tenant = this.getTenant(tenantId, options.context);
    tenant.stats.scans++;

    const result = tenant.shield.scan(text, options);

    if (result.threats.length > 0) {
      tenant.stats.threats += result.threats.length;
    }
    if (result.blocked) {
      tenant.stats.blocked++;
    }

    return { ...result, tenantId };
  }

  /**
   * Scan input for a specific tenant.
   */
  scanInput(tenantId, text, options = {}) {
    return this.scan(tenantId, text, options);
  }

  /**
   * Scan output for a specific tenant.
   */
  scanOutput(tenantId, text, options = {}) {
    const tenant = this.getTenant(tenantId, options.context);
    return tenant.shield.scanOutput(text);
  }

  /**
   * Update a tenant's policy.
   */
  updatePolicy(tenantId, policy, context) {
    const tenant = this.getTenant(tenantId, context);
    tenant.policy = { ...tenant.policy, ...policy, ...this.globalOverrides };
    tenant.shield = new AgentShield(tenant.policy);
    return tenant.policy;
  }

  /**
   * Get stats for a single tenant (auth-checked).
   */
  getStats(tenantId, context) {
    const tenant = this.getTenant(tenantId, context);
    return { ...tenant.stats, policy: tenant.policy };
  }

  /**
   * Get stats for all tenants. NOTE: this method bypasses per-tenant
   * auth — callers should gate access to it at the admin level.
   */
  getAllStats() {
    const stats = {};
    for (const [id, tenant] of this.tenants) {
      stats[id] = { ...tenant.stats, policy: tenant.policy };
    }
    return stats;
  }

  /**
   * Remove a tenant.
   */
  removeTenant(tenantId, context) {
    this._verifyTenant(tenantId, context);
    return this.tenants.delete(tenantId);
  }

  /**
   * Get tenant count.
   */
  get size() {
    return this.tenants.size;
  }
}

// =========================================================================
// Role-Based Policies
// =========================================================================

const DEFAULT_ROLES = {
  admin: {
    name: 'Administrator',
    sensitivity: 'medium',
    blockOnThreat: false,
    allowedTools: '*',
    blockedTools: [],
    bypassCircuitBreaker: true,
    canViewAuditTrail: true,
    canModifyPolicy: true
  },
  operator: {
    name: 'Operator',
    sensitivity: 'high',
    blockOnThreat: true,
    allowedTools: ['search', 'readFile', 'calculator'],
    blockedTools: ['bash', 'shell', 'exec'],
    bypassCircuitBreaker: false,
    canViewAuditTrail: true,
    canModifyPolicy: false
  },
  user: {
    name: 'Standard User',
    sensitivity: 'high',
    blockOnThreat: true,
    allowedTools: ['search', 'calculator'],
    blockedTools: ['bash', 'shell', 'exec', 'readFile', 'writeFile'],
    bypassCircuitBreaker: false,
    canViewAuditTrail: false,
    canModifyPolicy: false
  },
  restricted: {
    name: 'Restricted User',
    sensitivity: 'high',
    blockOnThreat: true,
    blockThreshold: 'low',
    allowedTools: [],
    blockedTools: '*',
    bypassCircuitBreaker: false,
    canViewAuditTrail: false,
    canModifyPolicy: false
  }
};

class RoleBasedPolicy {
  constructor(options = {}) {
    this.roles = { ...DEFAULT_ROLES, ...(options.customRoles || {}) };
    this.userRoles = new Map();
    this.shields = new Map();
  }

  /**
   * Assign a role to a user.
   */
  assignRole(userId, role) {
    if (!this.roles[role]) {
      throw new Error(`Unknown role: ${role}. Available: ${Object.keys(this.roles).join(', ')}`);
    }
    this.userRoles.set(userId, role);

    // Create a shield for this role if not exists
    if (!this.shields.has(role)) {
      const roleConfig = this.roles[role];
      this.shields.set(role, new AgentShield({
        sensitivity: roleConfig.sensitivity,
        blockOnThreat: roleConfig.blockOnThreat,
        blockThreshold: roleConfig.blockThreshold
      }));
    }

    return this;
  }

  /**
   * Get the effective policy for a user.
   */
  getPolicy(userId) {
    const role = this.userRoles.get(userId) || 'user';
    return { role, ...this.roles[role] };
  }

  /**
   * Scan input with the user's role-based policy.
   */
  scan(userId, text, options = {}) {
    const role = this.userRoles.get(userId) || 'user';

    // Reuse shield created in assignRole, or create lazily
    if (!this.shields.has(role)) {
      this.assignRole(userId, role);
    }

    const result = this.shields.get(role).scan(text, options);
    return { ...result, userId, role };
  }

  /**
   * Check if a user can use a specific tool.
   */
  checkToolAccess(userId, toolName) {
    const role = this.userRoles.get(userId) || 'user';
    const roleConfig = this.roles[role];

    if (roleConfig.blockedTools === '*') return { allowed: false, reason: 'All tools blocked for this role' };
    if (Array.isArray(roleConfig.blockedTools) && roleConfig.blockedTools.includes(toolName)) {
      return { allowed: false, reason: `Tool "${toolName}" is blocked for role "${role}"` };
    }

    if (roleConfig.allowedTools === '*') return { allowed: true };
    if (Array.isArray(roleConfig.allowedTools) && roleConfig.allowedTools.includes(toolName)) {
      return { allowed: true };
    }

    return { allowed: false, reason: `Tool "${toolName}" is not in the allowed list for role "${role}"` };
  }

  /**
   * Define a custom role.
   */
  defineRole(name, config) {
    this.roles[name] = { name: config.name || name, ...config };
    return this;
  }

  /**
   * Get all available roles.
   */
  getRoles() {
    return Object.entries(this.roles).map(([key, val]) => ({ key, ...val }));
  }
}

// =========================================================================
// Debug Mode
// =========================================================================

class DebugShield {
  constructor(options = {}) {
    this.shield = new AgentShield(options);
    this.traces = [];
    this.enabled = options.debug !== false;
    this.maxTraces = options.maxTraces || 1000;
    this.verbose = options.verbose || false;
  }

  /**
   * Scan with full debug trace.
   */
  scan(text, options = {}) {
    const startTime = this.enabled ? process.hrtime.bigint() : null;

    // Scan
    const result = this.shield.scan(text, options);

    // Only build trace if debug is enabled
    let trace = null;
    if (this.enabled) {
      const endTime = process.hrtime.bigint();
      const elapsedMs = Number(endTime - startTime) / 1e6;

      trace = {
        id: `trace_${Date.now()}_${Math.random().toString(36).slice(2, 8).padEnd(6, '0')}`,
        timestamp: new Date().toISOString(),
        input: text.substring(0, 500),
        inputLength: text.length,
        options,
        steps: [
          {
            step: 'input_received',
            time: 0,
            detail: { length: text.length, hasUnicode: /[^\x00-\x7F]/.test(text) }
          },
          {
            step: 'pattern_matching',
            time: elapsedMs,
            detail: {
              patternsChecked: this.shield.getPatterns().length,
              threatsFound: result.threats.length,
              threats: result.threats.map(t => ({
                severity: t.severity,
                category: t.category,
                description: t.description,
                confidence: t.confidence
              }))
            }
          },
          {
            step: 'decision',
            time: elapsedMs,
            detail: {
              status: result.status,
              blocked: result.blocked,
              threatCount: result.threats.length
            }
          }
        ],
        totalTimeMs: parseFloat(elapsedMs.toFixed(3)),
        result: {
          status: result.status,
          blocked: result.blocked,
          threatCount: result.threats.length
        }
      };

      this.traces.push(trace);
      while (this.traces.length > this.maxTraces) {
        this.traces.shift();
      }
    }

    if (this.verbose) {
      const ms = trace ? trace.totalTimeMs : 0;
      console.log(`[Agent Shield] DEBUG Scan: ${text.substring(0, 50)}... → ${result.status} (${ms.toFixed(1)}ms, ${result.threats.length} threats)`);
    }

    return { ...result, _trace: trace };
  }

  /**
   * Get all traces.
   */
  getTraces() {
    return this.traces;
  }

  /**
   * Get the last N traces.
   */
  getRecentTraces(n = 10) {
    return this.traces.slice(-n);
  }

  /**
   * Export traces as JSON.
   */
  exportTraces() {
    return JSON.stringify(this.traces, null, 2);
  }

  /**
   * Clear traces.
   */
  clearTraces() {
    this.traces = [];
  }

  /**
   * Get timing statistics across all traces.
   */
  getTimingStats() {
    if (this.traces.length === 0) return null;

    const times = this.traces.map(t => t.totalTimeMs);
    times.sort((a, b) => a - b);

    return {
      count: times.length,
      min: times[0],
      max: times[times.length - 1],
      avg: parseFloat((times.reduce((a, b) => a + b, 0) / times.length).toFixed(3)),
      median: times[Math.floor(times.length / 2)],
      p95: times[Math.min(Math.floor(times.length * 0.95), times.length - 1)],
      p99: times[Math.min(Math.floor(times.length * 0.99), times.length - 1)]
    };
  }
}

module.exports = {
  MultiTenantShield,
  RoleBasedPolicy,
  DebugShield,
  DEFAULT_ROLES
};
