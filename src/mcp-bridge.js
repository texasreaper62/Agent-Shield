'use strict';

/**
 * Agent Shield — MCP (Model Context Protocol) Bridge
 *
 * Native integration with MCP tool chains. Scans tool calls, tool results,
 * resources, and prompt templates for security threats. Enforces per-session
 * budgets and tool policies.
 *
 * All processing runs locally — no data ever leaves your environment.
 */

const crypto = require('crypto');

// =========================================================================
// Dangerous tool patterns
// =========================================================================

/**
 * Tool name patterns that are inherently dangerous.
 * @type {Array<object>}
 */
const MCP_DANGEROUS_TOOLS = [
  { pattern: /(?:exec|spawn|run|shell|bash|cmd|powershell|terminal)/i, category: 'code_execution', severity: 'critical', description: 'Code/command execution tool' },
  { pattern: /(?:file|fs|read|write|delete|remove|mkdir|rmdir|unlink)/i, category: 'filesystem', severity: 'high', description: 'Filesystem access tool' },
  { pattern: /(?:http|fetch|request|curl|wget|socket|net|dns)/i, category: 'network', severity: 'high', description: 'Network access tool' },
  { pattern: /(?:sql|query|database|db|mongo|redis|postgres|mysql)/i, category: 'database', severity: 'high', description: 'Database access tool' },
  { pattern: /(?:env|process|os|system|config|secret|credential|key)/i, category: 'system', severity: 'high', description: 'System/environment access tool' },
  { pattern: /(?:email|smtp|send|notify|publish|post|tweet|slack)/i, category: 'communication', severity: 'medium', description: 'External communication tool' },
  { pattern: /(?:install|npm|pip|apt|brew|package|deploy)/i, category: 'package_management', severity: 'high', description: 'Package management tool' },
  { pattern: /(?:cron|schedule|timer|interval|daemon)/i, category: 'scheduling', severity: 'medium', description: 'Task scheduling tool' }
];

/**
 * Patterns that indicate injection in tool arguments.
 * @type {Array<object>}
 */
const ARG_INJECTION_PATTERNS = [
  { pattern: /;\s*(?:rm|del|drop|shutdown|kill|curl|wget)\b/i, severity: 'critical', description: 'Command chaining in argument' },
  { pattern: /\$\{.{0,500}\}|\$\(.{0,500}\)|`.{0,500}`/s, severity: 'high', description: 'Shell expansion in argument' },
  { pattern: /(?:\.\.\/){2,}|(?:\.\.\\){2,}/i, severity: 'high', description: 'Path traversal in argument' },
  { pattern: /(?:ignore|override|forget)\s+(?:previous|all|system)\s+(?:instructions|rules)/i, severity: 'critical', description: 'Injection in tool argument' },
  { pattern: /<script[^>]*>|javascript:/i, severity: 'high', description: 'XSS in tool argument' },
  { pattern: /(?:union\s+select|;\s*drop\s+table|'\s*or\s+'1'\s*=\s*'1)/i, severity: 'critical', description: 'SQL injection in tool argument' }
];

/**
 * Returns the default scanner (detector-core.scanText) or a safe fallback.
 * @returns {Function}
 */
function getDefaultScanner() {
  try {
    const { scanText } = require('./detector-core');
    return (text) => scanText(text);
  } catch (e) {
    return () => ({ threats: [], severity: 'safe' });
  }
}

// =========================================================================
// MCPBridge — Main integration point
// =========================================================================

class MCPBridge {
  /**
   * @param {object} [options]
   * @param {Function} [options.scanner] - Custom scan function (defaults to detector-core.scanText)
   * @param {string[]} [options.allowedTools] - Whitelist of allowed tool names
   * @param {string[]} [options.blockedTools] - Blacklist of blocked tool names
   * @param {boolean} [options.scanInputs=true] - Scan tool call arguments
   * @param {boolean} [options.scanOutputs=true] - Scan tool results
   * @param {number} [options.maxToolCallsPerMinute=60] - Rate limit
   */
  constructor(options = {}) {
    this.scanner = options.scanner || getDefaultScanner();
    this.allowedTools = options.allowedTools ? new Set(options.allowedTools) : null;
    this.blockedTools = new Set(options.blockedTools || []);
    this.scanInputs = options.scanInputs !== false;
    this.scanOutputs = options.scanOutputs !== false;
    this.maxToolCallsPerMinute = options.maxToolCallsPerMinute || 60;

    this.stats = {
      toolCallsScanned: 0,
      toolResultsScanned: 0,
      blocked: 0,
      threats: {},
      callTimestamps: []
    };
  }

  /**
   * Scans tool call arguments for injection before execution.
   * @param {string} toolName - MCP tool name
   * @param {object} args - Tool call arguments
   * @returns {{ allowed: boolean, threats: Array, sanitizedArgs: object, reason: string|null }}
   */
  wrapToolCall(toolName, args = {}) {
    this.stats.toolCallsScanned++;
    const threats = [];
    let reason = null;

    // Check blocked tools
    if (this.blockedTools.has(toolName)) {
      this.stats.blocked++;
      return { allowed: false, threats: [{ severity: 'high', category: 'blocked_tool', description: `Tool "${toolName}" is blocked by policy` }], sanitizedArgs: args, reason: 'Tool is blocked by policy' };
    }

    // Check allowlist
    if (this.allowedTools && !this.allowedTools.has(toolName)) {
      this.stats.blocked++;
      return { allowed: false, threats: [{ severity: 'medium', category: 'unlisted_tool', description: `Tool "${toolName}" is not in the allowed list` }], sanitizedArgs: args, reason: 'Tool is not in allowed list' };
    }

    // Check rate limit
    const now = Date.now();
    this.stats.callTimestamps = this.stats.callTimestamps.filter(t => now - t < 60000);
    if (this.stats.callTimestamps.length >= this.maxToolCallsPerMinute) {
      this.stats.blocked++;
      return { allowed: false, threats: [{ severity: 'medium', category: 'rate_limit', description: 'Tool call rate limit exceeded' }], sanitizedArgs: args, reason: 'Rate limit exceeded' };
    }
    this.stats.callTimestamps.push(now);

    // Check dangerous tool patterns
    for (const dt of MCP_DANGEROUS_TOOLS) {
      if (dt.pattern.test(toolName)) {
        threats.push({ severity: dt.severity, category: dt.category, description: dt.description, tool: toolName });
      }
    }

    // Scan arguments for injection
    if (this.scanInputs) {
      const argText = JSON.stringify(args);
      for (const ap of ARG_INJECTION_PATTERNS) {
        if (ap.pattern.test(argText)) {
          threats.push({ severity: ap.severity, category: 'arg_injection', description: ap.description, tool: toolName });
        }
      }

      // Run general scanner
      const scanResult = this.scanner(argText);
      if (scanResult.threats && scanResult.threats.length > 0) {
        threats.push(...scanResult.threats.map(t => ({ ...t, tool: toolName, source: 'general_scanner' })));
      }
    }

    const hasCritical = threats.some(t => t.severity === 'critical');
    if (hasCritical) {
      this.stats.blocked++;
      reason = 'Critical threat detected in tool call';
    }

    // Track threat categories
    for (const t of threats) {
      this.stats.threats[t.category] = (this.stats.threats[t.category] || 0) + 1;
    }

    return { allowed: !hasCritical, threats, sanitizedArgs: args, reason };
  }

  /**
   * Scans tool results for exfiltration/injection before returning to model.
   * @param {string} toolName - MCP tool name
   * @param {*} result - Tool result
   * @returns {{ safe: boolean, threats: Array, sanitizedResult: * }}
   */
  wrapToolResult(toolName, result) {
    this.stats.toolResultsScanned++;
    const threats = [];

    if (!this.scanOutputs) {
      return { safe: true, threats: [], sanitizedResult: result };
    }

    const resultText = typeof result === 'string' ? result : JSON.stringify(result);

    // Run general scanner on output
    const scanResult = this.scanner(resultText);
    if (scanResult.threats && scanResult.threats.length > 0) {
      threats.push(...scanResult.threats.map(t => ({ ...t, tool: toolName, source: 'output_scan' })));
    }

    // Check for potential data exfiltration markers
    const exfilPatterns = [
      { pattern: /(?:password|passwd|secret|token|api[_-]?key|private[_-]?key)\s*[:=]\s*\S+/i, description: 'Credential in tool output' },
      { pattern: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/i, description: 'Private key in tool output' },
      { pattern: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/i, description: 'JWT token in tool output' }
    ];

    for (const ep of exfilPatterns) {
      if (ep.pattern.test(resultText)) {
        threats.push({ severity: 'high', category: 'data_exfiltration', description: ep.description, tool: toolName });
      }
    }

    const safe = !threats.some(t => t.severity === 'critical' || t.severity === 'high');
    return { safe, threats, sanitizedResult: result };
  }

  /**
   * Validates an MCP tool schema for dangerous patterns.
   * @param {object} schema - MCP tool schema
   * @returns {{ valid: boolean, warnings: Array, risks: Array }}
   */
  validateToolSchema(schema = {}) {
    const warnings = [];
    const risks = [];

    if (!schema.name) {
      warnings.push({ field: 'name', message: 'Tool schema missing name' });
    }

    if (!schema.description) {
      warnings.push({ field: 'description', message: 'Tool schema missing description' });
    }

    // Check for dangerous tool names
    if (schema.name) {
      for (const dt of MCP_DANGEROUS_TOOLS) {
        if (dt.pattern.test(schema.name)) {
          risks.push({ severity: dt.severity, category: dt.category, description: `Tool "${schema.name}": ${dt.description}` });
        }
      }
    }

    // Check input schema for overly permissive types
    if (schema.inputSchema) {
      const inputStr = JSON.stringify(schema.inputSchema);
      if (!schema.inputSchema.properties || Object.keys(schema.inputSchema.properties).length === 0) {
        warnings.push({ field: 'inputSchema', message: 'Tool accepts arbitrary input (no properties defined)' });
      }
      if (inputStr.includes('"additionalProperties":true') || !inputStr.includes('additionalProperties')) {
        warnings.push({ field: 'inputSchema', message: 'Tool allows additional properties — may accept unexpected input' });
      }
    }

    return { valid: risks.length === 0, warnings, risks };
  }

  /**
   * Returns scan statistics.
   * @returns {object}
   */
  getStats() {
    return { ...this.stats, callTimestamps: this.stats.callTimestamps.length };
  }
}

// =========================================================================
// MCPToolPolicy — Policy engine for MCP tools
// =========================================================================

class MCPToolPolicy {
  /**
   * @param {Array<object>} [rules] - Policy rules: { id, tool, action, conditions }
   */
  constructor(rules = []) {
    this.rules = rules.map((r, i) => ({ id: r.id || `rule_${i}`, ...r }));
  }

  /**
   * Evaluates a tool call against the policy.
   * @param {string} toolName
   * @param {object} args
   * @param {object} [context] - Session context
   * @returns {{ action: string, reason: string, matchedRule: object|null }}
   */
  evaluate(toolName, args = {}, context = {}) {
    for (const rule of this.rules) {
      if (this._matchesRule(rule, toolName, args, context)) {
        return { action: rule.action, reason: rule.reason || `Matched rule ${rule.id}`, matchedRule: rule };
      }
    }
    return { action: 'scan', reason: 'No matching rule — default to scan', matchedRule: null };
  }

  /**
   * Adds a policy rule.
   * @param {object} rule
   */
  addRule(rule) {
    const id = rule.id || `rule_${this.rules.length}`;
    this.rules.push({ id, ...rule });
  }

  /**
   * Removes a rule by ID.
   * @param {string} ruleId
   */
  removeRule(ruleId) {
    this.rules = this.rules.filter(r => r.id !== ruleId);
  }

  /**
   * Serializes policy to JSON.
   * @returns {object}
   */
  toJSON() {
    return { version: '1.0', rules: this.rules };
  }

  /**
   * Deserializes policy from JSON.
   * @param {object} json
   * @returns {MCPToolPolicy}
   */
  static fromJSON(json) {
    return new MCPToolPolicy(json.rules || []);
  }

  /** @private */
  _matchesRule(rule, toolName, args, context) {
    if (rule.tool) {
      const toolMatch = rule.tool instanceof RegExp ? rule.tool.test(toolName) : rule.tool === toolName;
      if (!toolMatch) return false;
    }
    if (rule.conditions) {
      if (rule.conditions.maxArgLength && JSON.stringify(args).length > rule.conditions.maxArgLength) return true;
      if (rule.conditions.requiresAuth && !context.authenticated) return true;
      if (rule.conditions.roles && context.role && !rule.conditions.roles.includes(context.role)) return true;
    }
    return !rule.conditions || Object.keys(rule.conditions).length === 0;
  }
}

// =========================================================================
// MCPSessionGuard — Per-session security state
// =========================================================================

class MCPSessionGuard {
  /**
   * @param {string} sessionId
   * @param {object} [options]
   * @param {number} [options.maxToolCalls=100] - Max tool calls per session
   * @param {number} [options.maxTokenBudget=100000] - Max tokens per session
   * @param {string[]} [options.allowedTools] - Per-session tool whitelist
   */
  constructor(sessionId, options = {}) {
    this.sessionId = sessionId;
    this.maxToolCalls = options.maxToolCalls || 100;
    this.maxTokenBudget = options.maxTokenBudget || 100000;
    this.allowedTools = options.allowedTools ? new Set(options.allowedTools) : null;

    this.callCount = 0;
    this.tokenCount = 0;
    this.toolUsage = {};
    this.threats = [];
    this.startedAt = Date.now();
  }

  /**
   * Tracks a tool call, enforcing session limits.
   * @param {string} toolName
   * @param {object} args
   * @returns {{ allowed: boolean, reason: string|null }}
   */
  trackToolCall(toolName, args = {}) {
    // Validate before mutating state
    if (this.allowedTools && !this.allowedTools.has(toolName)) {
      return { allowed: false, reason: `Tool "${toolName}" not allowed in this session` };
    }

    if (this.callCount >= this.maxToolCalls) {
      return { allowed: false, reason: `Session tool call limit exceeded (${this.maxToolCalls})` };
    }

    this.callCount++;
    this.toolUsage[toolName] = (this.toolUsage[toolName] || 0) + 1;
    this.tokenCount += JSON.stringify(args).length;

    return { allowed: true, reason: null };
  }

  /**
   * Checks if the session budget is exceeded.
   * @returns {{ exceeded: boolean, callsRemaining: number, tokensRemaining: number }}
   */
  checkBudget() {
    return {
      exceeded: this.callCount >= this.maxToolCalls || this.tokenCount >= this.maxTokenBudget,
      callsRemaining: Math.max(0, this.maxToolCalls - this.callCount),
      tokensRemaining: Math.max(0, this.maxTokenBudget - this.tokenCount)
    };
  }

  /**
   * Returns session security summary.
   * @returns {object}
   */
  getSessionReport() {
    return {
      sessionId: this.sessionId,
      duration: Date.now() - this.startedAt,
      callCount: this.callCount,
      tokenCount: this.tokenCount,
      uniqueTools: Object.keys(this.toolUsage).length,
      toolUsage: { ...this.toolUsage },
      threats: this.threats.length,
      budget: this.checkBudget()
    };
  }

  /**
   * Resets session state.
   */
  reset() {
    this.callCount = 0;
    this.tokenCount = 0;
    this.toolUsage = {};
    this.threats = [];
    this.startedAt = Date.now();
  }
}

// =========================================================================
// MCPResourceScanner — Scan MCP resources
// =========================================================================

class MCPResourceScanner {
  /**
   * @param {object} [options]
   * @param {Function} [options.scanner] - Custom scan function
   */
  constructor(options = {}) {
    this.scanner = options.scanner || getDefaultScanner();
  }

  /**
   * Scans MCP resource content for threats.
   * @param {string} uri - Resource URI
   * @param {string} content - Resource content
   * @param {string} [mimeType='text/plain'] - MIME type
   * @returns {{ safe: boolean, threats: Array, uri: string }}
   */
  scanResource(uri, content, mimeType = 'text/plain') {
    const threats = [];
    const text = typeof content === 'string' ? content : JSON.stringify(content);
    const scanResult = this.scanner(text);

    if (scanResult.threats && scanResult.threats.length > 0) {
      threats.push(...scanResult.threats.map(t => ({ ...t, uri, mimeType })));
    }

    return { safe: threats.length === 0, threats, uri };
  }

  /**
   * Scans an MCP prompt template for injection vectors.
   * @param {string} template - Prompt template text
   * @returns {{ safe: boolean, threats: Array, recommendations: Array }}
   */
  scanPromptTemplate(template) {
    const threats = [];
    const recommendations = [];

    // Check for unescaped user input slots
    const slotPattern = /\{\{?\s*(\w+)\s*\}?\}/g;
    let match;
    while ((match = slotPattern.exec(template)) !== null) {
      const varName = match[1];
      if (/user|input|query|message|prompt/i.test(varName)) {
        recommendations.push(`Variable "${varName}" accepts user input — ensure it is sanitized before interpolation`);
      }
    }

    // Run general scanner
    const scanResult = this.scanner(template);
    if (scanResult.threats && scanResult.threats.length > 0) {
      threats.push(...scanResult.threats.map(t => ({ ...t, source: 'prompt_template' })));
    }

    // Check for missing safety instructions
    if (!/(?:do not|never|must not|should not)\s+(?:reveal|disclose|output|share)/i.test(template)) {
      recommendations.push('Prompt template lacks defensive instructions against information disclosure');
    }

    return { safe: threats.length === 0, threats, recommendations };
  }
}

// =========================================================================
// Factory middleware
// =========================================================================

/**
 * Creates an MCP middleware object with security handlers.
 * @param {object} [options] - MCPBridge options
 * @returns {{ onToolCall: Function, onToolResult: Function, onResourceAccess: Function }}
 */
function createMCPMiddleware(options = {}) {
  const bridge = new MCPBridge(options);
  const resourceScanner = new MCPResourceScanner(options);

  return {
    /**
     * Handler for tool calls.
     * @param {string} toolName
     * @param {object} args
     * @returns {{ allowed: boolean, threats: Array }}
     */
    onToolCall(toolName, args) {
      return bridge.wrapToolCall(toolName, args);
    },

    /**
     * Handler for tool results.
     * @param {string} toolName
     * @param {*} result
     * @returns {{ safe: boolean, threats: Array }}
     */
    onToolResult(toolName, result) {
      return bridge.wrapToolResult(toolName, result);
    },

    /**
     * Handler for resource access.
     * @param {string} uri
     * @param {string} content
     * @param {string} mimeType
     * @returns {{ safe: boolean, threats: Array }}
     */
    onResourceAccess(uri, content, mimeType) {
      return resourceScanner.scanResource(uri, content, mimeType);
    },

    /** Returns the underlying bridge for stats/config */
    getBridge() { return bridge; }
  };
}

// =========================================================================
// Exports
// =========================================================================

module.exports = {
  MCPBridge,
  MCPToolPolicy,
  MCPSessionGuard,
  MCPResourceScanner,
  MCP_DANGEROUS_TOOLS,
  ARG_INJECTION_PATTERNS,
  createMCPMiddleware
};
