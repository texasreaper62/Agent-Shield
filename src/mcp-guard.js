'use strict';

/**
 * Agent Shield — MCP Guard
 *
 * Drop-in MCP security middleware. Protects MCP connections with:
 * - Server attestation: hash tool definitions on first connect, alert if they change
 * - Input/output scanning via detector-core on all tool I/O
 * - Cross-server isolation (prevent one server's tools from manipulating another's)
 * - OAuth enforcement layer (reject unauthenticated connections)
 * - Per-server rate limiting with circuit breaker
 * - Behavioral baseline per tool (track normal usage, alert on deviation)
 *
 * All detection runs locally — no data ever leaves your environment.
 *
 * @module mcp-guard
 */

const crypto = require('crypto');
const { scanText } = require('./detector-core');

let MicroModel = null;
try { MicroModel = require('./micro-model').MicroModel; } catch { /* optional */ }

// =========================================================================
// CONSTANTS
// =========================================================================

/** Default rate limit: max tool calls per server per minute. */
const DEFAULT_RATE_LIMIT = 60;

/** Default circuit breaker threshold (threats before tripping). */
const DEFAULT_CB_THRESHOLD = 5;

/** Default circuit breaker cooldown in ms (5 minutes). */
const DEFAULT_CB_COOLDOWN_MS = 300000;

/** Default baseline window size (number of observations to keep). */
const DEFAULT_BASELINE_WINDOW = 100;

/** SSRF target patterns — private IPs, cloud metadata endpoints.
 *  Ref: CVE-2026-26118, 36.7% of MCP servers vulnerable. */
const SSRF_BLOCKLIST = [
  /169\.254\.169\.254/,                         // AWS/Azure metadata
  /metadata\.google\.internal/,                 // GCP metadata
  /metadata\.aws\.internal/,                    // AWS metadata (alt)
  /100\.100\.100\.200/,                         // Alibaba Cloud metadata
  /(?:^|\/)(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})/,           // 10.x.x.x
  /(?:^|\/)(?:172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})/, // 172.16-31.x.x
  /(?:^|\/)(?:192\.168\.\d{1,3}\.\d{1,3})/,               // 192.168.x.x
  /(?:^|\/)(?:127\.0\.0\.1|0\.0\.0\.0|localhost)/,         // loopback
  /(?:^|\/)(?:::1|0:0:0:0:0:0:0:1)/                       // IPv6 loopback
];

/** Z-score threshold for behavioral anomaly. */
const DEFAULT_Z_THRESHOLD = 3.0;

// =========================================================================
// HELPERS
// =========================================================================

/**
 * SHA-256 hash of a JSON-serializable value.
 * @param {*} value
 * @returns {string} Hex-encoded hash.
 */
function sha256(value) {
  const str = typeof value === 'string' ? value : JSON.stringify(value);
  return crypto.createHash('sha256').update(str).digest('hex');
}

/**
 * Calculate mean of a numeric array.
 * @param {number[]} arr
 * @returns {number}
 */
function mean(arr) {
  return arr.length > 0 ? arr.reduce((a, b) => a + b, 0) / arr.length : 0;
}

/**
 * Calculate sample standard deviation.
 * @param {number[]} arr
 * @returns {number}
 */
function stdDev(arr) {
  if (arr.length < 2) return 0;
  const m = mean(arr);
  return Math.sqrt(arr.reduce((s, x) => s + (x - m) ** 2, 0) / (arr.length - 1));
}

/**
 * Calculate z-score for a value.
 * @param {number} value
 * @param {number} m - Mean.
 * @param {number} sd - Standard deviation.
 * @returns {number}
 */
function zScore(value, m, sd) {
  if (sd === 0) return value === m ? 0 : Infinity;
  return (value - m) / sd;
}

// =========================================================================
// ServerAttestation
// =========================================================================

/**
 * Tracks SHA-256 fingerprints of MCP server tool definitions.
 * Detects the "rugpull" attack where tool definitions change between sessions
 * (e.g. the Postmark-style attack).
 */
class ServerAttestation {
  constructor() {
    /** @type {Map<string, { hash: string, tools: object, attestedAt: number }>} */
    this.registry = new Map();
    /** @type {Array<object>} */
    this.alerts = [];
  }

  /**
   * Attest a server's tool definitions. On first call, records the hash.
   * On subsequent calls, compares against the stored hash.
   *
   * @param {string} serverId - Unique server identifier.
   * @param {object} toolDefinitions - The server's tool definitions object.
   * @returns {{ trusted: boolean, hash: string, changed: boolean, alert: object|null }}
   */
  attest(serverId, toolDefinitions) {
    const hash = sha256(toolDefinitions);
    const existing = this.registry.get(serverId);

    if (!existing) {
      this.registry.set(serverId, {
        hash,
        tools: JSON.parse(JSON.stringify(toolDefinitions)),
        attestedAt: Date.now()
      });
      return { trusted: true, hash, changed: false, alert: null };
    }

    if (existing.hash === hash) {
      return { trusted: true, hash, changed: false, alert: null };
    }

    // Tool definitions changed — potential rugpull
    const alert = {
      type: 'tool_definition_change',
      severity: 'critical',
      serverId,
      previousHash: existing.hash,
      currentHash: hash,
      timestamp: Date.now(),
      description: `Server "${serverId}" tool definitions changed. Previous hash: ${existing.hash.substring(0, 12)}... Current: ${hash.substring(0, 12)}... Possible rugpull attack.`
    };
    this.alerts.push(alert);

    return { trusted: false, hash, changed: true, alert };
  }

  /**
   * Force-update a server's attestation (after manual review).
   * @param {string} serverId
   * @param {object} toolDefinitions
   */
  update(serverId, toolDefinitions) {
    const hash = sha256(toolDefinitions);
    this.registry.set(serverId, {
      hash,
      tools: JSON.parse(JSON.stringify(toolDefinitions)),
      attestedAt: Date.now()
    });
  }

  /**
   * Get the stored attestation for a server.
   * @param {string} serverId
   * @returns {object|null}
   */
  get(serverId) {
    return this.registry.get(serverId) || null;
  }

  /**
   * Get all alerts.
   * @returns {Array<object>}
   */
  getAlerts() {
    return [...this.alerts];
  }

  /**
   * Clear alerts.
   */
  clearAlerts() {
    this.alerts = [];
  }
}

// =========================================================================
// CrossServerIsolation
// =========================================================================

/**
 * Prevents one MCP server's tools from accessing or manipulating
 * another server's context, data, or tool calls.
 */
class CrossServerIsolation {
  constructor() {
    /** @type {Map<string, Set<string>>} serverId -> set of tool names */
    this.serverTools = new Map();
    /** @type {Map<string, string>} toolName -> serverId */
    this.toolOwnership = new Map();
  }

  /**
   * Register a server and its tools.
   * @param {string} serverId
   * @param {string[]} toolNames
   */
  registerServer(serverId, toolNames) {
    this.serverTools.set(serverId, new Set(toolNames));
    for (const name of toolNames) {
      this.toolOwnership.set(name, serverId);
    }
  }

  /**
   * Validate that a tool call from a given server context doesn't
   * reference tools owned by another server.
   *
   * @param {string} callingServerId - The server context making the call.
   * @param {string} toolName - The tool being called.
   * @param {*} args - Tool arguments (scanned for cross-server references).
   * @returns {{ allowed: boolean, violation: object|null }}
   */
  validate(callingServerId, toolName, args) {
    const owner = this.toolOwnership.get(toolName);

    // Unknown tool — allow (not our concern)
    if (!owner) {
      return { allowed: true, violation: null };
    }

    // Tool belongs to a different server
    if (owner !== callingServerId) {
      return {
        allowed: false,
        violation: {
          type: 'cross_server_access',
          severity: 'high',
          callingServer: callingServerId,
          toolOwner: owner,
          toolName,
          description: `Server "${callingServerId}" attempted to call tool "${toolName}" owned by server "${owner}".`
        }
      };
    }

    // Check args for references to other servers' tools
    const argsStr = typeof args === 'string' ? args : JSON.stringify(args || {});
    for (const [otherServer, tools] of this.serverTools) {
      if (otherServer === callingServerId) continue;
      for (const otherTool of tools) {
        if (argsStr.includes(otherTool)) {
          return {
            allowed: false,
            violation: {
              type: 'cross_server_reference',
              severity: 'medium',
              callingServer: callingServerId,
              referencedServer: otherServer,
              referencedTool: otherTool,
              toolName,
              description: `Tool "${toolName}" arguments reference tool "${otherTool}" from server "${otherServer}".`
            }
          };
        }
      }
    }

    return { allowed: true, violation: null };
  }

  /**
   * Get the owning server for a tool.
   * @param {string} toolName
   * @returns {string|null}
   */
  getOwner(toolName) {
    return this.toolOwnership.get(toolName) || null;
  }
}

// =========================================================================
// OAuthEnforcer
// =========================================================================

/**
 * Enforces OAuth authentication on MCP connections.
 * Rejects unauthenticated or expired connections.
 */
class OAuthEnforcer {
  /**
   * @param {object} [options]
   * @param {boolean} [options.required=true] - Whether OAuth is required.
   * @param {string[]} [options.allowedIssuers=[]] - Allowed token issuers.
   * @param {string[]} [options.requiredScopes=[]] - Required OAuth scopes.
   * @param {number} [options.clockSkewMs=30000] - Allowed clock skew in ms.
   */
  constructor(options = {}) {
    this.required = options.required !== false;
    this.allowedIssuers = new Set(options.allowedIssuers || []);
    this.requiredScopes = options.requiredScopes || [];
    this.clockSkewMs = options.clockSkewMs || 30000;
  }

  /**
   * Validate an OAuth token object.
   *
   * @param {object|null} token - Token with { sub, iss, exp, scopes, ... }
   * @returns {{ authenticated: boolean, reason: string|null }}
   */
  validate(token) {
    if (!token) {
      if (!this.required) {
        return { authenticated: true, reason: null };
      }
      return { authenticated: false, reason: 'No authentication token provided.' };
    }

    // Check expiration
    if (token.exp) {
      const now = Date.now();
      const expMs = typeof token.exp === 'number' && token.exp < 1e12
        ? token.exp * 1000  // Unix seconds -> ms
        : token.exp;
      if (now > expMs + this.clockSkewMs) {
        return { authenticated: false, reason: 'Token has expired.' };
      }
    }

    // Check issuer
    if (this.allowedIssuers.size > 0 && token.iss) {
      if (!this.allowedIssuers.has(token.iss)) {
        return { authenticated: false, reason: `Issuer "${token.iss}" is not allowed.` };
      }
    }

    // Check scopes
    const tokenScopes = token.scopes || token.scope
      ? (Array.isArray(token.scopes) ? token.scopes : (token.scope || '').split(' '))
      : [];
    for (const required of this.requiredScopes) {
      if (!tokenScopes.includes(required)) {
        return { authenticated: false, reason: `Missing required scope: "${required}".` };
      }
    }

    return { authenticated: true, reason: null };
  }
}

// =========================================================================
// ToolBehaviorBaseline
// =========================================================================

/**
 * Tracks behavioral baselines per tool: call frequency, argument length,
 * response time, error rate. Alerts when current behavior deviates.
 */
class ToolBehaviorBaseline {
  /**
   * @param {object} [options]
   * @param {number} [options.windowSize=100] - Number of observations to keep.
   * @param {number} [options.zThreshold=3.0] - Z-score threshold for anomaly.
   */
  constructor(options = {}) {
    this.windowSize = options.windowSize || DEFAULT_BASELINE_WINDOW;
    this.zThreshold = options.zThreshold || DEFAULT_Z_THRESHOLD;
    /** @type {Map<string, { argLengths: number[], responseTimes: number[], errorCount: number, callCount: number, callTimestamps: number[] }>} */
    this.baselines = new Map();
  }

  /**
   * Record a tool call observation.
   *
   * @param {string} toolName
   * @param {object} observation
   * @param {number} [observation.argLength] - Length of serialized arguments.
   * @param {number} [observation.responseTimeMs] - Response time in ms.
   * @param {boolean} [observation.isError] - Whether the call resulted in an error.
   * @returns {{ anomalies: Array<object> }}
   */
  record(toolName, observation = {}) {
    if (!this.baselines.has(toolName)) {
      this.baselines.set(toolName, {
        argLengths: [],
        responseTimes: [],
        errorCount: 0,
        callCount: 0,
        callTimestamps: []
      });
    }

    const baseline = this.baselines.get(toolName);
    const anomalies = [];

    baseline.callCount++;
    baseline.callTimestamps.push(Date.now());

    // Trim to window
    if (baseline.callTimestamps.length > this.windowSize) {
      baseline.callTimestamps = baseline.callTimestamps.slice(-this.windowSize);
    }

    // Argument length
    if (observation.argLength != null) {
      const z = this._checkAnomaly(baseline.argLengths, observation.argLength);
      if (z !== null) {
        anomalies.push({
          type: 'unusual_arg_length',
          toolName,
          severity: 'medium',
          zScore: z,
          value: observation.argLength,
          mean: mean(baseline.argLengths),
          description: `Tool "${toolName}" argument length (${observation.argLength}) deviates from baseline (z=${z.toFixed(2)}).`
        });
      }
      baseline.argLengths.push(observation.argLength);
      if (baseline.argLengths.length > this.windowSize) {
        baseline.argLengths = baseline.argLengths.slice(-this.windowSize);
      }
    }

    // Response time
    if (observation.responseTimeMs != null) {
      const z = this._checkAnomaly(baseline.responseTimes, observation.responseTimeMs);
      if (z !== null) {
        anomalies.push({
          type: 'unusual_response_time',
          toolName,
          severity: 'low',
          zScore: z,
          value: observation.responseTimeMs,
          mean: mean(baseline.responseTimes),
          description: `Tool "${toolName}" response time (${observation.responseTimeMs}ms) deviates from baseline (z=${z.toFixed(2)}).`
        });
      }
      baseline.responseTimes.push(observation.responseTimeMs);
      if (baseline.responseTimes.length > this.windowSize) {
        baseline.responseTimes = baseline.responseTimes.slice(-this.windowSize);
      }
    }

    // Error
    if (observation.isError) {
      baseline.errorCount++;
    }

    return { anomalies };
  }

  /**
   * Get the baseline stats for a tool.
   * @param {string} toolName
   * @returns {object|null}
   */
  getBaseline(toolName) {
    const b = this.baselines.get(toolName);
    if (!b) return null;
    return {
      callCount: b.callCount,
      errorCount: b.errorCount,
      errorRate: b.callCount > 0 ? b.errorCount / b.callCount : 0,
      avgArgLength: mean(b.argLengths),
      avgResponseTime: mean(b.responseTimes),
      stdArgLength: stdDev(b.argLengths),
      stdResponseTime: stdDev(b.responseTimes)
    };
  }

  /**
   * Check if a value is anomalous compared to historical data.
   * @param {number[]} history
   * @param {number} value
   * @returns {number|null} Z-score if anomalous, null otherwise.
   * @private
   */
  _checkAnomaly(history, value) {
    if (history.length < 5) return null; // Not enough data
    const m = mean(history);
    const sd = stdDev(history);
    const z = zScore(value, m, sd);
    return Math.abs(z) >= this.zThreshold ? z : null;
  }
}

// =========================================================================
// MCPGuard — Main class
// =========================================================================

/**
 * Drop-in MCP security middleware. Wraps MCP server connections with
 * attestation, scanning, isolation, auth, rate limiting, and behavioral
 * baselines.
 */
class MCPGuard {
  /**
   * @param {object} [options]
   * @param {boolean} [options.requireAuth=false] - Require OAuth tokens.
   * @param {string[]} [options.allowedIssuers] - Allowed OAuth issuers.
   * @param {string[]} [options.requiredScopes] - Required OAuth scopes.
   * @param {number} [options.rateLimit=60] - Max calls per server per minute.
   * @param {number} [options.cbThreshold=5] - Circuit breaker threat threshold.
   * @param {number} [options.cbCooldownMs=300000] - Circuit breaker cooldown.
   * @param {number} [options.baselineWindow=100] - Behavioral baseline window.
   * @param {number} [options.zThreshold=3.0] - Z-score anomaly threshold.
   * @param {Function} [options.onAlert] - Callback for alerts: (alert) => void.
   * @param {Function} [options.scanner] - Custom scan function.
   */
  constructor(options = {}) {
    this.attestation = new ServerAttestation();
    this.isolation = new CrossServerIsolation();
    this.oauth = new OAuthEnforcer({
      required: options.requireAuth || false,
      allowedIssuers: options.allowedIssuers,
      requiredScopes: options.requiredScopes
    });
    this.baselines = new ToolBehaviorBaseline({
      windowSize: options.baselineWindow || DEFAULT_BASELINE_WINDOW,
      zThreshold: options.zThreshold || DEFAULT_Z_THRESHOLD
    });

    this.rateLimit = options.rateLimit || DEFAULT_RATE_LIMIT;
    this.cbThreshold = options.cbThreshold || DEFAULT_CB_THRESHOLD;
    this.cbCooldownMs = options.cbCooldownMs || DEFAULT_CB_COOLDOWN_MS;
    this.onAlert = options.onAlert || null;
    this.scanner = options.scanner || ((text) => scanText(text));
    this.microModel = options.enableMicroModel && MicroModel ? new MicroModel() : null;

    /** @type {Map<string, { timestamps: number[], threatCount: number, trippedAt: number|null }>} */
    this.serverState = new Map();

    /** @type {Array<object>} */
    this.auditLog = [];
  }

  // -----------------------------------------------------------------------
  // Server lifecycle
  // -----------------------------------------------------------------------

  /**
   * Register an MCP server connection. Attests tool definitions and
   * sets up isolation boundaries.
   *
   * @param {string} serverId - Unique server identifier.
   * @param {object} toolDefinitions - The server's tool definitions.
   * @param {object} [authToken] - OAuth token for authentication.
   * @returns {{ allowed: boolean, attestation: object, auth: object, threats: Array<object> }}
   */
  registerServer(serverId, toolDefinitions, authToken) {
    const threats = [];

    // Auth check
    const auth = this.oauth.validate(authToken || null);
    if (!auth.authenticated) {
      threats.push({
        type: 'auth_failure',
        severity: 'critical',
        serverId,
        description: auth.reason
      });
      this._log('register_blocked', serverId, { reason: auth.reason });
      return { allowed: false, attestation: null, auth, threats };
    }

    // Attest tool definitions
    const attestResult = this.attestation.attest(serverId, toolDefinitions);
    if (!attestResult.trusted) {
      threats.push(attestResult.alert);
      this._emitAlert(attestResult.alert);
    }

    // Register tools for isolation
    const toolNames = this._extractToolNames(toolDefinitions);
    this.isolation.registerServer(serverId, toolNames);

    // Initialize rate limiter state
    if (!this.serverState.has(serverId)) {
      this.serverState.set(serverId, {
        timestamps: [],
        threatCount: 0,
        trippedAt: null
      });
    }

    this._log('server_registered', serverId, {
      toolCount: toolNames.length,
      hash: attestResult.hash,
      changed: attestResult.changed
    });

    return {
      allowed: threats.length === 0,
      attestation: attestResult,
      auth,
      threats
    };
  }

  // -----------------------------------------------------------------------
  // Tool call interception
  // -----------------------------------------------------------------------

  /**
   * Intercept and validate a tool call before execution.
   *
   * @param {string} serverId - The server context.
   * @param {string} toolName - Tool being called.
   * @param {*} args - Tool arguments.
   * @returns {{ allowed: boolean, threats: Array<object>, anomalies: Array<object> }}
   */
  interceptToolCall(serverId, toolName, args) {
    const threats = [];
    const anomalies = [];

    // Circuit breaker check
    const cbCheck = this._checkCircuitBreaker(serverId);
    if (!cbCheck.allowed) {
      threats.push({
        type: 'circuit_breaker_open',
        severity: 'critical',
        serverId,
        toolName,
        description: `Circuit breaker is open for server "${serverId}". Too many threats detected.`
      });
      return { allowed: false, threats, anomalies };
    }

    // Rate limit check
    const rlCheck = this._checkRateLimit(serverId);
    if (!rlCheck.allowed) {
      threats.push({
        type: 'rate_limit_exceeded',
        severity: 'high',
        serverId,
        toolName,
        description: `Server "${serverId}" exceeded rate limit of ${this.rateLimit} calls/minute.`
      });
      return { allowed: false, threats, anomalies };
    }

    // Cross-server isolation check
    const isoCheck = this.isolation.validate(serverId, toolName, args);
    if (!isoCheck.allowed) {
      threats.push(isoCheck.violation);
    }

    // Scan input
    const argsStr = typeof args === 'string' ? args : JSON.stringify(args || {});
    const scanResult = this.scanner(argsStr);
    if (scanResult.threats && scanResult.threats.length > 0) {
      for (const t of scanResult.threats) {
        threats.push({
          type: 'input_injection',
          severity: t.severity || 'high',
          serverId,
          toolName,
          category: t.category,
          description: t.description || 'Threat detected in tool call arguments.'
        });
      }
    }

    // SSRF firewall — block private IPs and cloud metadata endpoints
    const urls = argsStr.match(/https?:\/\/[^\s"'}\]]+/gi) || [];
    for (const url of urls) {
      for (const pattern of SSRF_BLOCKLIST) {
        if (pattern.test(url)) {
          threats.push({
            type: 'ssrf_blocked',
            severity: 'critical',
            serverId,
            toolName,
            description: `Blocked SSRF attempt targeting "${url.substring(0, 100)}". Private IPs and cloud metadata endpoints are not allowed (ref CVE-2026-26118).`
          });
          break;
        }
      }
    }

    // Micro-model secondary scan
    if (this.microModel) {
      const modelResult = this.microModel.scan(argsStr);
      if (modelResult.threats && modelResult.threats.length > 0) {
        for (const t of modelResult.threats) {
          threats.push({
            type: 'micro_model_input',
            severity: t.severity || 'high',
            serverId,
            toolName,
            category: t.category,
            confidence: t.confidence,
            description: t.description || 'Micro-model detected threat in tool call arguments.'
          });
        }
      }
    }

    // Record behavioral observation
    const behaviorResult = this.baselines.record(toolName, {
      argLength: argsStr.length
    });
    anomalies.push(...behaviorResult.anomalies);

    // Update threat count for circuit breaker
    if (threats.length > 0) {
      this._recordThreats(serverId, threats.length);
    }

    this._log('tool_call', serverId, { toolName, allowed: threats.length === 0, threatCount: threats.length });

    return { allowed: threats.length === 0, threats, anomalies };
  }

  /**
   * Intercept and validate a tool's output after execution.
   *
   * @param {string} serverId - The server context.
   * @param {string} toolName - Tool that produced the output.
   * @param {*} output - The tool's output.
   * @param {number} [responseTimeMs] - How long the tool took.
   * @returns {{ safe: boolean, threats: Array<object>, anomalies: Array<object> }}
   */
  interceptToolOutput(serverId, toolName, output, responseTimeMs) {
    const threats = [];
    const anomalies = [];

    // Scan output
    const outputStr = typeof output === 'string' ? output : JSON.stringify(output || {});
    const scanResult = this.scanner(outputStr);
    if (scanResult.threats && scanResult.threats.length > 0) {
      for (const t of scanResult.threats) {
        threats.push({
          type: 'output_injection',
          severity: t.severity || 'high',
          serverId,
          toolName,
          category: t.category,
          description: t.description || 'Threat detected in tool output.'
        });
      }
    }

    // Micro-model secondary scan on output
    if (this.microModel) {
      const modelResult = this.microModel.scan(outputStr);
      if (modelResult.threats && modelResult.threats.length > 0) {
        for (const t of modelResult.threats) {
          threats.push({
            type: 'micro_model_output',
            severity: t.severity || 'high',
            serverId,
            toolName,
            category: t.category,
            confidence: t.confidence,
            description: t.description || 'Micro-model detected threat in tool output.'
          });
        }
      }
    }

    // Record behavioral observation (only pass responseTimeMs if actually provided)
    const behaviorObs = { isError: false };
    if (responseTimeMs != null && responseTimeMs > 0) {
      behaviorObs.responseTimeMs = responseTimeMs;
    }
    const behaviorResult = this.baselines.record(toolName, behaviorObs);
    anomalies.push(...behaviorResult.anomalies);

    if (threats.length > 0) {
      this._recordThreats(serverId, threats.length);
    }

    this._log('tool_output', serverId, { toolName, safe: threats.length === 0 });

    return { safe: threats.length === 0, threats, anomalies };
  }

  // -----------------------------------------------------------------------
  // Reporting
  // -----------------------------------------------------------------------

  /**
   * Get a summary report of all server states.
   * @returns {object}
   */
  getReport() {
    const servers = {};
    for (const [serverId, state] of this.serverState) {
      const attestation = this.attestation.get(serverId);
      servers[serverId] = {
        threatCount: state.threatCount,
        circuitBreakerTripped: state.trippedAt !== null,
        attestationHash: attestation ? attestation.hash.substring(0, 16) : null,
        attestedAt: attestation ? attestation.attestedAt : null
      };
    }

    return {
      serverCount: this.serverState.size,
      servers,
      alerts: this.attestation.getAlerts(),
      auditLogSize: this.auditLog.length
    };
  }

  /**
   * Get the audit log.
   * @returns {Array<object>}
   */
  getAuditLog() {
    return [...this.auditLog];
  }

  /**
   * Reset the circuit breaker for a server (after manual review).
   * @param {string} serverId
   */
  resetCircuitBreaker(serverId) {
    const state = this.serverState.get(serverId);
    if (state) {
      state.threatCount = 0;
      state.trippedAt = null;
    }
  }

  // -----------------------------------------------------------------------
  // Private helpers
  // -----------------------------------------------------------------------

  /**
   * Check if a server's circuit breaker is open.
   * @param {string} serverId
   * @returns {{ allowed: boolean }}
   * @private
   */
  _checkCircuitBreaker(serverId) {
    const state = this.serverState.get(serverId);
    if (!state) return { allowed: true };

    if (state.trippedAt) {
      const elapsed = Date.now() - state.trippedAt;
      if (elapsed < this.cbCooldownMs) {
        return { allowed: false };
      }
      // Cooldown elapsed — half-open, reset
      state.trippedAt = null;
      state.threatCount = 0;
    }

    return { allowed: true };
  }

  /**
   * Check rate limit for a server.
   * @param {string} serverId
   * @returns {{ allowed: boolean }}
   * @private
   */
  _checkRateLimit(serverId) {
    const state = this.serverState.get(serverId);
    if (!state) return { allowed: true };

    const now = Date.now();
    const oneMinuteAgo = now - 60000;
    state.timestamps = state.timestamps.filter(t => t > oneMinuteAgo);
    state.timestamps.push(now);

    return { allowed: state.timestamps.length <= this.rateLimit };
  }

  /**
   * Record threat counts and potentially trip the circuit breaker.
   * @param {string} serverId
   * @param {number} count
   * @private
   */
  _recordThreats(serverId, count) {
    const state = this.serverState.get(serverId);
    if (!state) return;

    state.threatCount += count;
    if (state.threatCount >= this.cbThreshold && !state.trippedAt) {
      state.trippedAt = Date.now();
      const alert = {
        type: 'circuit_breaker_tripped',
        severity: 'critical',
        serverId,
        threatCount: state.threatCount,
        timestamp: Date.now(),
        description: `Circuit breaker tripped for server "${serverId}" after ${state.threatCount} threats.`
      };
      this._emitAlert(alert);
    }
  }

  /**
   * Extract tool names from various definition formats.
   * @param {*} definitions
   * @returns {string[]}
   * @private
   */
  _extractToolNames(definitions) {
    if (Array.isArray(definitions)) {
      return definitions.map(t => t.name || t.toolName || '').filter(Boolean);
    }
    if (definitions && typeof definitions === 'object') {
      return Object.keys(definitions);
    }
    return [];
  }

  /**
   * Emit an alert via the onAlert callback.
   * @param {object} alert
   * @private
   */
  _emitAlert(alert) {
    console.warn(`[Agent Shield] MCPGuard alert: ${alert.description}`);
    if (this.onAlert) {
      try { this.onAlert(alert); } catch { /* ignore callback errors */ }
    }
  }

  /**
   * Log an event to the audit log.
   * @param {string} action
   * @param {string} serverId
   * @param {object} details
   * @private
   */
  _log(action, serverId, details) {
    this.auditLog.push({
      timestamp: Date.now(),
      action,
      serverId,
      ...details
    });
    // Trim audit log to 10000 entries
    if (this.auditLog.length > 10000) {
      this.auditLog = this.auditLog.slice(-10000);
    }
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
  MCPGuard,
  ServerAttestation,
  CrossServerIsolation,
  OAuthEnforcer,
  ToolBehaviorBaseline,
  DEFAULT_RATE_LIMIT,
  DEFAULT_CB_THRESHOLD,
  DEFAULT_CB_COOLDOWN_MS,
  DEFAULT_BASELINE_WINDOW,
  DEFAULT_Z_THRESHOLD
};
