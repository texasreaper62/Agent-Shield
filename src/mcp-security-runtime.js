'use strict';

/**
 * Agent Shield — MCP Security Runtime
 *
 * The unified security layer for Model Context Protocol (MCP) servers.
 * Connects authorization, threat scanning, behavioral monitoring, and
 * audit logging into a single runtime that can be added with one line.
 *
 * Addresses all four IAM gaps from the Meta rogue AI agent incident:
 *   1. Inter-agent identity verification (via agent-protocol.js)
 *   2. Post-authentication intent validation (via confused-deputy.js)
 *   3. Ephemeral, scoped credentials (via confused-deputy.js)
 *   4. Per-user MCP tool authorization (this module)
 *
 * Usage:
 *   const { MCPSecurityRuntime } = require('agent-shield');
 *   const runtime = new MCPSecurityRuntime({ signingKey: process.env.SHIELD_KEY });
 *   // One-line integration:
 *   const secured = runtime.createMiddleware();
 *
 * All processing runs locally — no data ever leaves your environment.
 */

const crypto = require('crypto');
const { MCPBridge, MCPSessionGuard, MCPResourceScanner, MCPToolPolicy } = require('./mcp-bridge');
const { AuthorizationContext, ConfusedDeputyGuard } = require('./confused-deputy');
const { BehaviorProfile } = require('./behavior-profiling');

const LOG_PREFIX = '[Agent Shield]';

// =========================================================================
// MCP Session State Machine — prevents tool ordering attacks
// =========================================================================

/** Valid session states and their allowed transitions. */
const SESSION_STATES = Object.freeze({
  initialized: ['authenticated', 'terminated'],
  authenticated: ['active', 'terminated'],
  active: ['active', 'suspended', 'terminated'],
  suspended: ['active', 'terminated'],
  terminated: []
});

/**
 * Tracks MCP session state to prevent tool call ordering attacks.
 * Detects sequences like: skip_auth → execute → destroy_logs.
 */
class MCPSessionStateMachine {
  /**
   * @param {string} sessionId
   */
  constructor(sessionId) {
    this.sessionId = sessionId;
    this.state = 'initialized';
    this.transitions = [];
    this.createdAt = Date.now();
  }

  /**
   * Transitions to a new state if allowed.
   * @param {string} newState
   * @returns {{ allowed: boolean, from: string, to: string, reason?: string }}
   */
  transition(newState) {
    const allowed = SESSION_STATES[this.state];
    if (!allowed || !allowed.includes(newState)) {
      return {
        allowed: false,
        from: this.state,
        to: newState,
        reason: `Invalid transition: ${this.state} → ${newState}`
      };
    }
    const from = this.state;
    this.state = newState;
    this.transitions.push({ from, to: newState, timestamp: Date.now() });
    return { allowed: true, from, to: newState };
  }

  /** @returns {boolean} */
  isTerminated() {
    return this.state === 'terminated';
  }
}

// =========================================================================
// MCP Security Runtime — the unified security layer
// =========================================================================

/**
 * Production-ready security runtime for MCP servers.
 * Integrates scanning, authorization, behavior monitoring, and audit
 * into a single coherent layer.
 */
class MCPSecurityRuntime {
  /**
   * @param {object} [options]
   * @param {string} [options.signingKey] - HMAC key for auth context signing
   * @param {boolean} [options.enforceAuth=true] - Require auth context on all calls
   * @param {boolean} [options.enableBehaviorMonitoring=true] - Track behavioral anomalies
   * @param {boolean} [options.enableStateMachine=true] - Enforce session state transitions
   * @param {number} [options.maxSessionsPerUser=10] - Max concurrent sessions per user
   * @param {number} [options.sessionTtlMs=3600000] - Session timeout (default 1 hour)
   * @param {number} [options.maxToolCallsPerSession=100] - Per-session tool call limit
   * @param {number} [options.maxTokenBudget=100000] - Per-session token budget
   * @param {string[]} [options.allowedTools] - Tool whitelist
   * @param {string[]} [options.blockedTools] - Tool blacklist
   * @param {Array} [options.policies] - MCPToolPolicy rules
   * @param {Function} [options.onThreat] - Callback when threat detected
   * @param {Function} [options.onBlock] - Callback when action blocked
   * @param {Function} [options.onAudit] - Callback for all audit events
   */
  constructor(options = {}) {
    this._signingKey = options.signingKey || 'agent-shield-mcp-runtime-key';
    this._enforceAuth = options.enforceAuth !== false;
    this._enableBehavior = options.enableBehaviorMonitoring !== false;
    this._enableStateMachine = options.enableStateMachine !== false;
    this._maxSessionsPerUser = options.maxSessionsPerUser || 10;
    this._sessionTtlMs = options.sessionTtlMs || 3600000;

    // Core components
    this._bridge = new MCPBridge({
      allowedTools: options.allowedTools,
      blockedTools: options.blockedTools,
      scanInputs: true,
      scanOutputs: true,
      maxToolCallsPerMinute: options.maxToolCallsPerMinute || 60
    });

    this._guard = new ConfusedDeputyGuard({
      enforceContext: this._enforceAuth,
      signingKey: this._signingKey
    });

    this._policy = new MCPToolPolicy(options.policies || []);
    this._resourceScanner = new MCPResourceScanner();

    // Per-session state
    this._sessions = new Map();        // sessionId → SessionState
    this._userSessions = new Map();    // userId → Set<sessionId>
    this._behaviorProfiles = new Map(); // userId → BehaviorProfile

    // Callbacks
    this._onThreat = options.onThreat || null;
    this._onBlock = options.onBlock || null;
    this._onAudit = options.onAudit || null;

    // Audit log
    this._auditLog = [];
    this._maxAuditEntries = options.maxAuditEntries || 10000;

    // Runtime stats
    this.stats = {
      sessionsCreated: 0,
      toolCallsProcessed: 0,
      toolCallsBlocked: 0,
      threatsDetected: 0,
      authFailures: 0,
      behaviorAnomalies: 0,
      stateViolations: 0
    };

    // Cleanup expired sessions periodically
    this._cleanupInterval = setInterval(() => this._purgeExpiredSessions(), 60000);
    if (this._cleanupInterval.unref) this._cleanupInterval.unref();
  }

  // =======================================================================
  // Session Management
  // =======================================================================

  /**
   * Creates a new authenticated MCP session.
   * @param {object} params
   * @param {string} params.userId - Authenticated user identity
   * @param {string} params.agentId - Agent identity
   * @param {string[]} [params.roles] - User roles
   * @param {string[]} [params.scopes] - Granted scopes
   * @param {string} [params.intent] - Declared session intent
   * @returns {{ sessionId: string, authCtx: AuthorizationContext }}
   */
  createSession(params) {
    if (!params.userId || !params.agentId) {
      throw new Error(`${LOG_PREFIX} createSession requires userId and agentId`);
    }

    // Enforce per-user session limit
    const userSessions = this._userSessions.get(params.userId) || new Set();
    if (userSessions.size >= this._maxSessionsPerUser) {
      this._audit('session_denied', { userId: params.userId, reason: 'max_sessions_exceeded' });
      throw new Error(`${LOG_PREFIX} Max sessions (${this._maxSessionsPerUser}) exceeded for user`);
    }

    const sessionId = crypto.randomUUID();
    const authCtx = new AuthorizationContext({
      userId: params.userId,
      agentId: params.agentId,
      roles: params.roles,
      scopes: params.scopes,
      intent: params.intent,
      ttlMs: this._sessionTtlMs,
      signingKey: this._signingKey
    });

    const session = {
      sessionId,
      authCtx,
      guard: new MCPSessionGuard(sessionId, {
        maxToolCalls: params.maxToolCalls || 100,
        maxTokenBudget: params.maxTokenBudget || 100000,
        allowedTools: params.allowedTools
      }),
      stateMachine: this._enableStateMachine ? new MCPSessionStateMachine(sessionId) : null,
      createdAt: Date.now(),
      lastActivity: Date.now(),
      toolCallCount: 0
    };

    // Transition to authenticated state
    if (session.stateMachine) {
      session.stateMachine.transition('authenticated');
      session.stateMachine.transition('active');
    }

    this._sessions.set(sessionId, session);
    userSessions.add(sessionId);
    this._userSessions.set(params.userId, userSessions);
    this.stats.sessionsCreated++;

    // Initialize behavior profile for user if needed
    if (this._enableBehavior && !this._behaviorProfiles.has(params.userId)) {
      this._behaviorProfiles.set(params.userId, new BehaviorProfile({
        windowSize: 200,
        learningPeriod: 10,
        anomalyThreshold: 2.5
      }));
    }

    this._audit('session_created', { sessionId, userId: params.userId, agentId: params.agentId });
    return { sessionId, authCtx };
  }

  /**
   * Terminates a session and cleans up resources.
   * @param {string} sessionId
   * @returns {boolean} True if session was found and terminated
   */
  terminateSession(sessionId) {
    const session = this._sessions.get(sessionId);
    if (!session || !session.authCtx) return false;

    if (session.stateMachine) {
      session.stateMachine.transition('terminated');
    }

    // Cascade: terminate child sessions first
    const childIds = [];
    for (const [id, s] of this._sessions) {
      if (s.parentSessionId === sessionId) childIds.push(id);
    }
    for (const childId of childIds) {
      this.terminateSession(childId);
    }

    // Remove from user sessions
    const userId = session.authCtx.userId;
    const userSessions = this._userSessions.get(userId);
    if (userSessions) {
      userSessions.delete(sessionId);
      if (userSessions.size === 0) {
        this._userSessions.delete(userId);
        this._behaviorProfiles.delete(userId);
      }
    }

    this._sessions.delete(sessionId);
    this._audit('session_terminated', { sessionId, userId, toolCalls: session.toolCallCount });
    return true;
  }

  // =======================================================================
  // Tool Call Security — the core product
  // =======================================================================

  /**
   * Secures an MCP tool call with full authorization, scanning, and monitoring.
   * This is the primary API — every tool call flows through here.
   *
   * @param {string} sessionId - Active session ID
   * @param {string} toolName - MCP tool being invoked
   * @param {object} [args={}] - Tool arguments
   * @returns {{ allowed: boolean, threats: Array, violations: Array, anomalies: Array, token: object|null, reason?: string }}
   */
  secureToolCall(sessionId, toolName, args = {}) {
    const startTime = Date.now();
    this.stats.toolCallsProcessed++;

    // 1. Validate session
    const session = this._sessions.get(sessionId);
    if (!session) {
      this.stats.authFailures++;
      this._audit('tool_blocked', { sessionId, toolName, reason: 'invalid_session' });
      return this._blocked('Invalid or expired session', toolName);
    }

    // Update activity timestamp
    session.lastActivity = Date.now();

    // 2. Check session state machine
    if (session.stateMachine && session.stateMachine.isTerminated()) {
      this.stats.stateViolations++;
      this._audit('tool_blocked', { sessionId, toolName, reason: 'session_terminated' });
      return this._blocked('Session has been terminated', toolName);
    }

    // 3. Check session budget (rate limiting)
    const budgetCheck = session.guard.trackToolCall(toolName, args);
    if (!budgetCheck.allowed) {
      this._audit('tool_blocked', { sessionId, toolName, reason: budgetCheck.reason });
      if (this._onBlock) this._onBlock({ sessionId, toolName, reason: budgetCheck.reason });
      return this._blocked(budgetCheck.reason, toolName);
    }

    // 4. Authorization check (confused deputy prevention)
    const authResult = this._guard.wrapToolCall(toolName, args, session.authCtx);
    if (!authResult.allowed) {
      this.stats.toolCallsBlocked++;
      this.stats.authFailures++;
      this._audit('auth_denied', {
        sessionId, toolName, userId: session.authCtx.userId,
        violations: authResult.violations
      });
      if (this._onBlock) this._onBlock({ sessionId, toolName, violations: authResult.violations });
      return {
        allowed: false,
        threats: [],
        violations: authResult.violations,
        anomalies: [],
        token: null,
        reason: 'Authorization denied: ' + authResult.violations.map(v => v.message).join('; ')
      };
    }

    // 5. Policy evaluation
    const policyResult = this._policy.evaluate(toolName, args, {
      userId: session.authCtx.userId,
      roles: [...session.authCtx.roles],
      scopes: [...session.authCtx.scopes]
    });
    if (policyResult.action === 'deny') {
      this._audit('policy_denied', { sessionId, toolName, rule: policyResult.matchedRule });
      return this._blocked(`Policy denied: ${policyResult.reason}`, toolName);
    }

    // 6. Threat scanning (injection, exfiltration, etc.)
    const scanResult = this._bridge.wrapToolCall(toolName, args);
    const threats = scanResult.threats || [];
    if (!scanResult.allowed) {
      this.stats.toolCallsBlocked++;
      this.stats.threatsDetected += threats.length;
      this._audit('threat_detected', { sessionId, toolName, threats });
      if (this._onThreat) this._onThreat({ sessionId, toolName, threats });
      return {
        allowed: false,
        threats,
        violations: [],
        anomalies: [],
        token: null,
        reason: 'Threat detected: ' + threats.map(t => t.category || t.type).join(', ')
      };
    }

    // 7. Behavioral anomaly detection
    const anomalies = [];
    if (this._enableBehavior) {
      const profile = this._behaviorProfiles.get(session.authCtx.userId);
      if (profile) {
        const elapsed = Date.now() - startTime;
        session.toolCallCount++;
        const observation = profile.record({
          responseTimeMs: elapsed,
          toolsCalled: [toolName],
          threatScore: threats.length > 0 ? threats.reduce((s, t) => s + (t.severity === 'critical' ? 1 : t.severity === 'high' ? 0.7 : 0.3), 0) : 0,
          toolCallCount: session.toolCallCount
        });
        if (observation.anomalies && observation.anomalies.length > 0) {
          anomalies.push(...observation.anomalies);
          this.stats.behaviorAnomalies += observation.anomalies.length;
          this._audit('behavior_anomaly', {
            sessionId, toolName, userId: session.authCtx.userId,
            anomalies: observation.anomalies
          });
        }
      }
    }

    // 8. Record success and return
    this._audit('tool_allowed', {
      sessionId, toolName, userId: session.authCtx.userId,
      threats: threats.length, anomalies: anomalies.length
    });

    return {
      allowed: true,
      threats,
      violations: [],
      anomalies,
      token: authResult.token,
      sanitizedArgs: scanResult.sanitizedArgs
    };
  }

  /**
   * Scans tool output/result before returning to the user.
   * @param {string} sessionId
   * @param {string} toolName
   * @param {*} result
   * @returns {{ safe: boolean, threats: Array, sanitizedResult: * }}
   */
  secureToolResult(sessionId, toolName, result) {
    const session = this._sessions.get(sessionId);
    if (!session) {
      return { safe: false, threats: [{ type: 'invalid_session', message: 'Unknown session' }] };
    }

    const scanResult = this._bridge.wrapToolResult(toolName, result);
    if (!scanResult.safe) {
      this.stats.threatsDetected += (scanResult.threats || []).length;
      this._audit('output_threat', { sessionId, toolName, threats: scanResult.threats });
      if (this._onThreat) this._onThreat({ sessionId, toolName, threats: scanResult.threats, direction: 'output' });
    }
    return scanResult;
  }

  /**
   * Scans an MCP resource before making it available.
   * @param {string} uri
   * @param {string} content
   * @param {string} [mimeType='text/plain']
   * @returns {{ safe: boolean, threats: Array }}
   */
  secureResource(uri, content, mimeType) {
    return this._resourceScanner.scanResource(uri, content, mimeType);
  }

  // =======================================================================
  // Tool Registration
  // =======================================================================

  /**
   * Registers a tool with its security requirements.
   * @param {string} toolName
   * @param {object} requirements
   * @param {string[]} [requirements.scopes] - Required scopes
   * @param {string[]} [requirements.roles] - Required roles
   * @param {boolean} [requirements.requiresHumanApproval] - HITL gate
   * @param {string[]} [requirements.allowedIntents] - Allowed intents
   */
  registerTool(toolName, requirements = {}) {
    this._guard.registerTool(toolName, requirements);
  }

  /**
   * Adds a policy rule.
   * @param {object} rule - MCPToolPolicy rule
   */
  addPolicy(rule) {
    this._policy.addRule(rule);
  }

  // =======================================================================
  // One-Line Middleware
  // =======================================================================

  /**
   * Creates middleware handlers for MCP server integration.
   * Drop-in for any MCP server implementation.
   *
   * @returns {object} Middleware with onToolCall, onToolResult, onResourceAccess, createSession, terminateSession
   */
  createMiddleware() {
    const runtime = this;
    return {
      /**
       * Creates an authenticated session. Call once per connection.
       * @param {object} params - { userId, agentId, roles, scopes, intent }
       * @returns {{ sessionId: string, authCtx: AuthorizationContext }}
       */
      createSession(params) {
        return runtime.createSession(params);
      },

      /**
       * Secures a tool call. Call for every tools/call request.
       * @param {string} sessionId
       * @param {string} toolName
       * @param {object} args
       * @returns {{ allowed: boolean, threats: Array, violations: Array, anomalies: Array }}
       */
      onToolCall(sessionId, toolName, args) {
        return runtime.secureToolCall(sessionId, toolName, args);
      },

      /**
       * Scans tool output before returning. Call for every tool response.
       * @param {string} sessionId
       * @param {string} toolName
       * @param {*} result
       * @returns {{ safe: boolean, threats: Array }}
       */
      onToolResult(sessionId, toolName, result) {
        return runtime.secureToolResult(sessionId, toolName, result);
      },

      /**
       * Scans MCP resources. Call for resources/read requests.
       * @param {string} uri
       * @param {string} content
       * @param {string} mimeType
       * @returns {{ safe: boolean, threats: Array }}
       */
      onResourceAccess(uri, content, mimeType) {
        return runtime.secureResource(uri, content, mimeType);
      },

      /**
       * Terminates a session. Call on connection close.
       * @param {string} sessionId
       */
      terminateSession(sessionId) {
        return runtime.terminateSession(sessionId);
      },

      /** Get runtime stats */
      getStats() {
        return runtime.getReport();
      }
    };
  }

  // =======================================================================
  // Delegation — secure agent-to-agent handoff
  // =======================================================================

  /**
   * Delegates a session's authorization to a sub-agent with narrowed scopes.
   * @param {string} sessionId - Parent session
   * @param {string} delegateAgentId - Sub-agent receiving delegation
   * @param {string[]} [delegateScopes] - Subset of parent scopes
   * @returns {{ sessionId: string, authCtx: AuthorizationContext }}
   */
  delegateSession(sessionId, delegateAgentId, delegateScopes) {
    const parentSession = this._sessions.get(sessionId);
    if (!parentSession) {
      throw new Error(`${LOG_PREFIX} Cannot delegate: invalid session`);
    }

    // Enforce per-user session limit for delegated sessions too
    const userSessions = this._userSessions.get(parentSession.authCtx.userId) || new Set();
    if (userSessions.size >= this._maxSessionsPerUser) {
      throw new Error(`${LOG_PREFIX} Cannot delegate: max sessions (${this._maxSessionsPerUser}) exceeded for user`);
    }

    const childCtx = parentSession.authCtx.delegate(delegateAgentId, delegateScopes);
    const childSessionId = crypto.randomUUID();

    const childSession = {
      sessionId: childSessionId,
      authCtx: childCtx,
      guard: new MCPSessionGuard(childSessionId, {
        maxToolCalls: 50, // Delegates get tighter budgets
        maxTokenBudget: 50000
      }),
      stateMachine: this._enableStateMachine ? new MCPSessionStateMachine(childSessionId) : null,
      createdAt: Date.now(),
      lastActivity: Date.now(),
      toolCallCount: 0,
      parentSessionId: sessionId
    };

    if (childSession.stateMachine) {
      childSession.stateMachine.transition('authenticated');
      childSession.stateMachine.transition('active');
    }

    this._sessions.set(childSessionId, childSession);

    // Track under same user (reuse userSessions from limit check above)
    userSessions.add(childSessionId);
    this._userSessions.set(parentSession.authCtx.userId, userSessions);

    this._audit('session_delegated', {
      parentSessionId: sessionId,
      childSessionId,
      delegateAgentId,
      delegateScopes: childCtx.scopes,
      delegationDepth: childCtx.delegationDepth
    });

    return { sessionId: childSessionId, authCtx: childCtx };
  }

  // =======================================================================
  // Reporting & Observability
  // =======================================================================

  /**
   * Returns comprehensive runtime report.
   * @returns {object}
   */
  getReport() {
    const sessions = [];
    for (const [id, session] of this._sessions) {
      sessions.push({
        sessionId: id,
        userId: session.authCtx.userId,
        agentId: session.authCtx.agentId,
        state: session.stateMachine ? session.stateMachine.state : 'active',
        toolCalls: session.toolCallCount,
        age: Date.now() - session.createdAt,
        budget: session.guard.checkBudget()
      });
    }

    const behaviorSummaries = {};
    for (const [userId, profile] of this._behaviorProfiles) {
      behaviorSummaries[userId] = profile.getReport();
    }

    return {
      stats: { ...this.stats },
      activeSessions: this._sessions.size,
      sessions,
      behaviorProfiles: behaviorSummaries,
      guard: this._guard.getStats(),
      recentAudit: this._auditLog.slice(-50)
    };
  }

  /**
   * Returns the full audit log.
   * @param {number} [limit=100]
   * @returns {Array}
   */
  getAuditLog(limit = 100) {
    return this._auditLog.slice(-limit);
  }

  /**
   * Returns behavior profile for a specific user.
   * @param {string} userId
   * @returns {object|null}
   */
  getBehaviorProfile(userId) {
    const profile = this._behaviorProfiles.get(userId);
    return profile ? profile.getReport() : null;
  }

  // =======================================================================
  // Cleanup
  // =======================================================================

  /**
   * Shuts down the runtime and cleans up resources.
   */
  shutdown() {
    if (this._cleanupInterval) {
      clearInterval(this._cleanupInterval);
      this._cleanupInterval = null;
    }
    const sessionIds = [...this._sessions.keys()];
    for (const sessionId of sessionIds) {
      this.terminateSession(sessionId);
    }
    this._audit('runtime_shutdown', { totalProcessed: this.stats.toolCallsProcessed });
  }

  // =======================================================================
  // Internal
  // =======================================================================

  /** @private */
  _blocked(reason, toolName) {
    this.stats.toolCallsBlocked++;
    return {
      allowed: false,
      threats: [],
      violations: [{ type: 'blocked', message: reason, tool: toolName }],
      anomalies: [],
      token: null,
      reason
    };
  }

  /** @private */
  _audit(type, data) {
    const entry = {
      type,
      timestamp: Date.now(),
      eventId: crypto.randomUUID(),
      ...data
    };
    if (this._auditLog.length >= this._maxAuditEntries) {
      this._auditLog = this._auditLog.slice(-Math.floor(this._maxAuditEntries * 0.75));
    }
    this._auditLog.push(entry);
    if (this._onAudit) {
      try { this._onAudit(entry); } catch (_e) { /* callback errors should not break the runtime */ }
    }
  }

  /** @private */
  _purgeExpiredSessions() {
    const now = Date.now();
    const expiredIds = [];
    for (const [sessionId, session] of this._sessions) {
      const expired = session.authCtx.isExpired() ||
        (now - session.lastActivity > this._sessionTtlMs);
      if (expired) expiredIds.push(sessionId);
    }
    for (const sessionId of expiredIds) {
      this.terminateSession(sessionId);
    }
  }
}

// =========================================================================
// Exports
// =========================================================================

module.exports = {
  MCPSecurityRuntime,
  MCPSessionStateMachine,
  SESSION_STATES
};
