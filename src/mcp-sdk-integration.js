'use strict';

/**
 * Agent Shield — Official MCP SDK Integration
 *
 * Drop-in security for any MCP server built with @modelcontextprotocol/sdk.
 * Wraps the standard Server class to add threat scanning, authorization,
 * behavioral monitoring, and audit logging — with zero configuration required.
 *
 * Works with @modelcontextprotocol/sdk v1.x and v2.x.
 *
 * Usage (3 lines):
 *
 *   const { Server } = require('@modelcontextprotocol/sdk/server/index.js');
 *   const { shieldMCPServer } = require('agent-shield');
 *
 *   const server = shieldMCPServer(new Server({ name: 'my-server', version: '1.0' }));
 *   // All tool calls are now scanned. Injections blocked. Audit trail created.
 *
 * Advanced usage with MCPSecurityRuntime:
 *
 *   const server = shieldMCPServer(new Server({ ... }), {
 *     signingKey: process.env.SHIELD_KEY,
 *     enforceAuth: true,
 *     enableBehaviorMonitoring: true,
 *     onThreat: (event) => alertSecurityTeam(event),
 *     tools: {
 *       'database_query': { scopes: ['db:read'], roles: ['analyst'] },
 *       'file_delete':    { scopes: ['fs:write'], roles: ['admin'], requiresHumanApproval: true }
 *     }
 *   });
 *
 * All processing runs locally — no data ever leaves your environment.
 */

const { scanText } = require('./detector-core');
const { MCPSecurityRuntime } = require('./mcp-security-runtime');

const LOG_PREFIX = '[Agent Shield]';

/**
 * Wraps a @modelcontextprotocol/sdk Server with Agent Shield security.
 *
 * Intercepts tools/call requests to scan arguments for injection attacks,
 * scans tool results before returning, and maintains an audit trail.
 *
 * @param {object} server - @modelcontextprotocol/sdk Server instance
 * @param {object} [options]
 * @param {string} [options.signingKey] - HMAC key for auth context signing
 * @param {boolean} [options.enforceAuth=false] - Require per-user auth (advanced)
 * @param {boolean} [options.enableBehaviorMonitoring=true] - Track behavioral anomalies
 * @param {boolean} [options.scanInputs=true] - Scan tool call arguments
 * @param {boolean} [options.scanOutputs=true] - Scan tool results
 * @param {string} [options.sensitivity='medium'] - Detection sensitivity
 * @param {boolean} [options.blockOnThreat=true] - Block tool calls with detected threats
 * @param {Function} [options.onThreat] - Callback when threat detected
 * @param {Function} [options.onBlock] - Callback when tool call blocked
 * @param {object} [options.tools] - Per-tool security requirements
 * @returns {object} The same server instance, now secured
 */
function shieldMCPServer(server, options = {}) {
  if (!server) {
    throw new Error(`${LOG_PREFIX} shieldMCPServer requires a @modelcontextprotocol/sdk Server instance`);
  }

  const scanInputs = options.scanInputs !== false;
  const scanOutputs = options.scanOutputs !== false;
  const blockOnThreat = options.blockOnThreat !== false;
  const sensitivity = options.sensitivity || 'medium';
  const onThreat = options.onThreat || null;
  const onBlock = options.onBlock || null;

  // Initialize runtime if auth is enabled
  let runtime = null;
  if (options.enforceAuth || options.signingKey) {
    runtime = new MCPSecurityRuntime({
      signingKey: options.signingKey,
      enforceAuth: options.enforceAuth,
      enableBehaviorMonitoring: options.enableBehaviorMonitoring !== false,
      enableStateMachine: true,
      maxDelegationDepth: options.maxDelegationDepth || 5,
      onThreat: options.onThreat,
      onBlock: options.onBlock,
      onAudit: options.onAudit
    });

    // Register tool requirements
    if (options.tools) {
      for (const [toolName, requirements] of Object.entries(options.tools)) {
        runtime.registerTool(toolName, requirements);
      }
    }
  }

  // Audit log for non-runtime mode
  const auditLog = [];
  const maxAuditEntries = 10000;

  // Stats
  const stats = {
    toolCallsScanned: 0,
    toolCallsBlocked: 0,
    toolResultsScanned: 0,
    threatsDetected: 0
  };

  // Intercept tool handler registration
  const originalSetRequestHandler = server.setRequestHandler
    ? server.setRequestHandler.bind(server)
    : null;

  if (originalSetRequestHandler) {
    server.setRequestHandler = function (schema, handler) {
      // Check if this is a tools/call handler
      const schemaMethod = schema && (schema.method || schema);
      if (schemaMethod === 'tools/call' || (typeof schemaMethod === 'object' && schemaMethod.method === 'tools/call')) {
        const wrappedHandler = async (request, extra) => {
          const toolName = request.params && request.params.name;
          const args = request.params && request.params.arguments;

          // Scan tool call arguments
          if (scanInputs && args) {
            stats.toolCallsScanned++;
            const argsText = typeof args === 'string' ? args : JSON.stringify(args);
            const scanResult = scanText(argsText, { sensitivity });

            if (scanResult.threats && scanResult.threats.length > 0) {
              stats.threatsDetected += scanResult.threats.length;

              _audit('threat_detected', {
                toolName,
                threats: scanResult.threats.map(t => ({ category: t.category, severity: t.severity })),
                blocked: blockOnThreat
              });

              if (onThreat) {
                try { onThreat({ toolName, args, threats: scanResult.threats }); } catch (_e) { /* */ }
              }

              if (blockOnThreat) {
                stats.toolCallsBlocked++;
                if (onBlock) {
                  try { onBlock({ toolName, args, threats: scanResult.threats }); } catch (_e) { /* */ }
                }

                return {
                  content: [{
                    type: 'text',
                    text: `[Agent Shield] Tool call blocked: ${scanResult.threats.map(t => t.category).join(', ')} detected in arguments`
                  }],
                  isError: true
                };
              }
            }
          }

          // Runtime auth check (if enabled)
          if (runtime && extra && extra.sessionId) {
            const result = runtime.secureToolCall(extra.sessionId, toolName, args);
            if (!result.allowed) {
              stats.toolCallsBlocked++;
              return {
                content: [{
                  type: 'text',
                  text: `[Agent Shield] Authorization denied: ${result.reason || result.violations.map(v => v.message).join('; ')}`
                }],
                isError: true
              };
            }
          }

          _audit('tool_allowed', { toolName });

          // Call original handler
          const result = await handler(request, extra);

          // Scan tool result
          if (scanOutputs && result && result.content) {
            stats.toolResultsScanned++;
            for (const item of result.content) {
              if (item.type === 'text' && item.text) {
                const outputScan = scanText(item.text, { sensitivity });
                if (outputScan.threats && outputScan.threats.length > 0) {
                  stats.threatsDetected += outputScan.threats.length;
                  _audit('output_threat', {
                    toolName,
                    threats: outputScan.threats.map(t => ({ category: t.category, severity: t.severity }))
                  });
                  if (onThreat) {
                    try { onThreat({ toolName, threats: outputScan.threats, direction: 'output' }); } catch (_e) { /* */ }
                  }
                }
              }
            }
          }

          return result;
        };

        return originalSetRequestHandler(schema, wrappedHandler);
      }

      // Pass through non-tool handlers unchanged
      return originalSetRequestHandler(schema, handler);
    };
  }

  // Attach shield API to server instance
  server.agentShield = {
    /** Get scanning stats */
    getStats() {
      return runtime ? runtime.getReport() : { ...stats, auditEntries: auditLog.length };
    },

    /** Get the audit log */
    getAuditLog(limit = 100) {
      return runtime ? runtime.getAuditLog(limit) : auditLog.slice(-limit);
    },

    /** Get the runtime (if auth is enabled) */
    getRuntime() {
      return runtime;
    },

    /** Create an authenticated session (requires enforceAuth) */
    createSession(params) {
      if (!runtime) throw new Error(`${LOG_PREFIX} createSession requires enforceAuth or signingKey`);
      return runtime.createSession(params);
    },

    /** Terminate a session */
    terminateSession(sessionId) {
      if (!runtime) return false;
      return runtime.terminateSession(sessionId);
    },

    /** Shutdown the security runtime */
    shutdown() {
      if (runtime) runtime.shutdown();
    }
  };

  function _audit(type, data) {
    if (auditLog.length >= maxAuditEntries) {
      auditLog.splice(0, auditLog.length - Math.floor(maxAuditEntries * 0.75));
    }
    auditLog.push({ type, timestamp: Date.now(), ...data });
  }

  console.log(`${LOG_PREFIX} MCP server secured (scanInputs: ${scanInputs}, scanOutputs: ${scanOutputs}, blockOnThreat: ${blockOnThreat}, auth: ${!!runtime})`);

  return server;
}

/**
 * Creates a standalone security middleware for MCP servers that don't use
 * the official SDK. Works with any JSON-RPC 2.0 MCP implementation.
 *
 * @param {object} [options] - Same options as shieldMCPServer
 * @returns {object} Middleware with processRequest/processResponse methods
 */
function createMCPSecurityLayer(options = {}) {
  const scanInputs = options.scanInputs !== false;
  const scanOutputs = options.scanOutputs !== false;
  const blockOnThreat = options.blockOnThreat !== false;
  const sensitivity = options.sensitivity || 'medium';

  let runtime = null;
  if (options.enforceAuth || options.signingKey) {
    runtime = new MCPSecurityRuntime({
      signingKey: options.signingKey,
      enforceAuth: options.enforceAuth,
      enableBehaviorMonitoring: options.enableBehaviorMonitoring !== false,
      onThreat: options.onThreat,
      onBlock: options.onBlock
    });
    if (options.tools) {
      for (const [toolName, requirements] of Object.entries(options.tools)) {
        runtime.registerTool(toolName, requirements);
      }
    }
  }

  return {
    /**
     * Process an incoming MCP request before handling.
     * @param {object} request - JSON-RPC 2.0 request
     * @param {object} [context] - Optional context (sessionId, userId, etc.)
     * @returns {{ allowed: boolean, threats: Array, request: object }}
     */
    processRequest(request, context = {}) {
      if (!request || request.method !== 'tools/call') {
        return { allowed: true, threats: [], request };
      }

      const toolName = request.params && request.params.name;
      const args = request.params && request.params.arguments;

      // Runtime auth check
      if (runtime && context.sessionId) {
        const result = runtime.secureToolCall(context.sessionId, toolName, args);
        if (!result.allowed) {
          return { allowed: false, threats: result.threats, violations: result.violations, request };
        }
      }

      // Scan arguments
      if (scanInputs && args) {
        const argsText = typeof args === 'string' ? args : JSON.stringify(args);
        const scanResult = scanText(argsText, { sensitivity });
        if (scanResult.threats && scanResult.threats.length > 0 && blockOnThreat) {
          return { allowed: false, threats: scanResult.threats, request };
        }
      }

      return { allowed: true, threats: [], request };
    },

    /**
     * Process an MCP response before returning.
     * @param {object} response - JSON-RPC 2.0 response
     * @returns {{ safe: boolean, threats: Array, response: object }}
     */
    processResponse(response, _context = {}) {
      if (!scanOutputs || !response || !response.result || !response.result.content) {
        return { safe: true, threats: [], response };
      }

      const allThreats = [];
      for (const item of response.result.content) {
        if (item.type === 'text' && item.text) {
          const scanResult = scanText(item.text, { sensitivity });
          if (scanResult.threats) allThreats.push(...scanResult.threats);
        }
      }

      return { safe: allThreats.length === 0, threats: allThreats, response };
    },

    /** Get the runtime (if auth is enabled) */
    getRuntime() { return runtime; },

    /** Shutdown */
    shutdown() { if (runtime) runtime.shutdown(); }
  };
}

// =========================================================================
// Exports
// =========================================================================

module.exports = {
  shieldMCPServer,
  createMCPSecurityLayer
};
