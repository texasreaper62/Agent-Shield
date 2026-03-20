'use strict';

/**
 * Structured error codes for Agent Shield
 * Format: AS-{CATEGORY}-{NUMBER}
 *
 * Categories:
 *   DET  — Detection engine errors
 *   CFG  — Configuration errors
 *   PLG  — Plugin errors
 *   INT  — Integration errors
 *   POL  — Policy errors
 *   NET  — Network/distributed errors
 *   AUT  — Authentication/authorization errors
 */

const ERROR_CODES = {
  // Detection
  'AS-DET-001': { message: 'Detection engine not initialized', severity: 'critical' },
  'AS-DET-002': { message: 'Invalid input type — expected string', severity: 'high' },
  'AS-DET-003': { message: 'Pattern compilation failed', severity: 'high' },
  'AS-DET-004': { message: 'Scan timeout exceeded', severity: 'medium' },
  'AS-DET-005': { message: 'Input exceeds maximum length', severity: 'medium' },

  // Configuration
  'AS-CFG-001': { message: 'Invalid configuration object', severity: 'critical' },
  'AS-CFG-002': { message: 'Unknown configuration key', severity: 'low' },
  'AS-CFG-003': { message: 'Invalid threshold value — must be 0-1', severity: 'high' },
  'AS-CFG-004': { message: 'Preset not found', severity: 'medium' },

  // Plugin
  'AS-PLG-001': { message: 'Plugin failed to load', severity: 'high' },
  'AS-PLG-002': { message: 'Plugin version incompatible', severity: 'high' },
  'AS-PLG-003': { message: 'Plugin hook threw an error', severity: 'medium' },

  // Integration
  'AS-INT-001': { message: 'Framework adapter not found', severity: 'high' },
  'AS-INT-002': { message: 'Middleware setup failed', severity: 'critical' },
  'AS-INT-003': { message: 'Hook registration failed', severity: 'medium' },

  // Policy
  'AS-POL-001': { message: 'Policy parse error', severity: 'critical' },
  'AS-POL-002': { message: 'Policy rule conflict detected', severity: 'high' },
  'AS-POL-003': { message: 'Policy file not found', severity: 'high' },

  // Network/Distributed
  'AS-NET-001': { message: 'Distributed sync failed', severity: 'high' },
  'AS-NET-002': { message: 'Peer node unreachable', severity: 'medium' },

  // Auth
  'AS-AUT-001': { message: 'RBAC permission denied', severity: 'high' },
  'AS-AUT-002': { message: 'Tenant not found', severity: 'high' },
  'AS-AUT-003': { message: 'SSO token validation failed', severity: 'critical' },
};

/**
 * Create a structured AgentShield error
 * @param {string} code - Error code (e.g., 'AS-DET-001')
 * @param {Object} [details] - Additional context
 * @returns {Error}
 */
function createShieldError(code, details = {}) {
  const entry = ERROR_CODES[code];
  if (!entry) {
    const err = new Error(`Unknown error code: ${code}`);
    err.code = 'AS-CFG-002';
    return err;
  }
  const err = new Error(`[Agent Shield ${code}] ${entry.message}`);
  err.code = code;
  err.severity = entry.severity;
  err.details = details;
  err.timestamp = Date.now();
  return err;
}

/**
 * Emit a deprecation warning (once per code)
 * @param {string} feature - Deprecated feature name
 * @param {string} replacement - Suggested replacement
 * @param {string} removeVersion - Version when it will be removed
 */
const _warned = new Set();
function deprecationWarning(feature, replacement, removeVersion) {
  const key = `${feature}:${replacement}`;
  if (_warned.has(key)) return;
  _warned.add(key);
  const msg = `[Agent Shield] DEPRECATED: "${feature}" is deprecated and will be removed in v${removeVersion}. Use "${replacement}" instead.`;
  if (typeof process !== 'undefined' && process.emitWarning) {
    process.emitWarning(msg, 'DeprecationWarning');
  } else {
    console.warn(msg);
  }
}

module.exports = {
  ERROR_CODES,
  createShieldError,
  deprecationWarning,
};
