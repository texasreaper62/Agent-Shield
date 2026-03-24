'use strict';

/**
 * Tool Sequence Analysis (#2), Permission Boundaries (#16),
 * Allowlists (#3), and Input Quarantine (#32)
 *
 * - Tool Sequence Analysis: Track tool call sequences and flag suspicious chains.
 * - Permission Boundaries: Define what each tool is allowed to do.
 * - Allowlists: Define expected tool/source allowlists.
 * - Input Quarantine: Hold suspicious inputs for human review.
 */

// =========================================================================
// TOOL SEQUENCE ANALYZER
// =========================================================================

/**
 * Known suspicious tool call sequences.
 * Each sequence describes a pattern of tool calls that, in order, indicate an attack.
 */
const SUSPICIOUS_SEQUENCES = [
  {
    name: 'credential_exfiltration',
    description: 'Reading credentials then making an HTTP request — likely data theft.',
    severity: 'critical',
    pattern: [
      { tool: /read|cat|file|open/i, args: /\.env|credentials|secret|password|token|key/i },
      { tool: /http|fetch|curl|wget|request|post|send/i }
    ]
  },
  {
    name: 'reconnaissance_then_delete',
    description: 'Listing files then deleting — likely destructive attack.',
    severity: 'critical',
    pattern: [
      { tool: /list|ls|find|glob|search|read/i },
      { tool: /delete|remove|rm|unlink|drop|truncate/i }
    ]
  },
  {
    name: 'read_then_write_config',
    description: 'Reading config then modifying it — possible self-modification attack.',
    severity: 'high',
    pattern: [
      { tool: /read|cat|file|open/i, args: /config|settings|\.env|system/i },
      { tool: /write|edit|modify|update|set/i, args: /config|settings|\.env|system/i }
    ]
  },
  {
    name: 'database_dump',
    description: 'Running a broad database query then sending data externally.',
    severity: 'critical',
    pattern: [
      { tool: /sql|query|database|db/i, args: /SELECT\s+\*|dump|export|all/i },
      { tool: /http|fetch|curl|wget|request|send|write/i }
    ]
  },
  {
    name: 'privilege_escalation',
    description: 'Modifying permissions or user roles then executing commands.',
    severity: 'critical',
    pattern: [
      { tool: /chmod|chown|permission|role|grant|sudo/i },
      { tool: /exec|run|shell|bash|system/i }
    ]
  }
];

class ToolSequenceAnalyzer {
  /**
   * @param {object} [options]
   * @param {number} [options.windowSize=10] - Number of recent tool calls to track.
   * @param {number} [options.windowMs=300000] - Time window in ms (default: 5 minutes).
   * @param {Array<object>} [options.customSequences=[]] - Additional suspicious sequences.
   * @param {Function} [options.onSuspicious] - Callback when suspicious sequence detected.
   */
  constructor(options = {}) {
    this.windowSize = options.windowSize || 10;
    this.windowMs = options.windowMs || 300000;
    this.customSequences = options.customSequences || [];
    this.onSuspicious = options.onSuspicious || null;
    this.history = [];
  }

  /**
   * Records a tool call and checks for suspicious sequences.
   *
   * @param {string} toolName - The tool that was called.
   * @param {object} [args={}] - The tool's arguments.
   * @returns {object} { suspicious: boolean, matches: Array }
   */
  record(toolName, args = {}) {
    const now = Date.now();
    const argsStr = typeof args === 'string' ? args : JSON.stringify(args);

    this.history.push({ tool: toolName, args: argsStr, timestamp: now });

    // Prune old entries
    const cutoff = now - this.windowMs;
    this.history = this.history.filter(h => h.timestamp > cutoff);
    if (this.history.length > this.windowSize) {
      this.history = this.history.slice(-this.windowSize);
    }

    // Check against known sequences
    const allSequences = [...SUSPICIOUS_SEQUENCES, ...this.customSequences];
    const matches = [];

    for (const seq of allSequences) {
      if (this._matchesSequence(seq.pattern)) {
        matches.push({
          name: seq.name,
          description: seq.description,
          severity: seq.severity,
          timestamp: now
        });
      }
    }

    if (matches.length > 0 && this.onSuspicious) {
      this.onSuspicious({ matches, history: this.getHistory() });
    }

    return { suspicious: matches.length > 0, matches };
  }

  /**
   * Checks if the recent history matches a sequence pattern.
   * @private
   * @param {Array} pattern
   * @returns {boolean}
   */
  _matchesSequence(pattern) {
    if (this.history.length < pattern.length) return false;

    // Sliding window: check if any subsequence in history matches the pattern
    for (let start = 0; start <= this.history.length - pattern.length; start++) {
      let patternIdx = 0;
      for (let i = start; i < this.history.length && patternIdx < pattern.length; i++) {
        const step = pattern[patternIdx];
        const entry = this.history[i];

        const toolMatch = step.tool.test(entry.tool);
        const argsMatch = !step.args || step.args.test(entry.args);

        if (toolMatch && argsMatch) {
          patternIdx++;
        }
      }
      if (patternIdx === pattern.length) return true;
    }
    return false;
  }

  /**
   * Returns recent tool call history.
   * @returns {Array}
   */
  getHistory() {
    return this.history.map(h => ({ tool: h.tool, args: h.args, timestamp: h.timestamp }));
  }

  reset() {
    this.history = [];
  }
}

// =========================================================================
// PERMISSION BOUNDARIES
// =========================================================================

class PermissionBoundary {
  /**
   * @param {object} [options]
   * @param {object} [options.tools={}] - Per-tool permission rules.
   * @param {Array<string>} [options.allowedTools] - Whitelist of allowed tool names.
   * @param {Array<string>} [options.blockedTools] - Blacklist of blocked tool names.
   * @param {Function} [options.onDenied] - Callback when permission denied.
   */
  constructor(options = {}) {
    this.tools = options.tools || {};
    this.allowedTools = options.allowedTools || null;
    this.blockedTools = options.blockedTools || [];
    this.onDenied = options.onDenied || null;
  }

  /**
   * Defines permissions for a specific tool.
   *
   * @param {string} toolName
   * @param {object} permissions
   * @param {Array<string|RegExp>} [permissions.allowArgs] - Allowed argument patterns.
   * @param {Array<string|RegExp>} [permissions.blockArgs] - Blocked argument patterns.
   * @param {Array<string>} [permissions.allowPaths] - Allowed file path prefixes.
   * @param {Array<string>} [permissions.blockPaths] - Blocked file path prefixes.
   * @param {number} [permissions.maxCallsPerMinute] - Rate limit per tool.
   * @returns {PermissionBoundary} this (for chaining)
   */
  defineTool(toolName, permissions) {
    this.tools[toolName] = {
      allowArgs: (permissions.allowArgs || []).map(p => typeof p === 'string' ? new RegExp(p, 'i') : p),
      blockArgs: (permissions.blockArgs || []).map(p => typeof p === 'string' ? new RegExp(p, 'i') : p),
      allowPaths: permissions.allowPaths || [],
      blockPaths: permissions.blockPaths || [],
      maxCallsPerMinute: permissions.maxCallsPerMinute || Infinity,
      recentCalls: []
    };
    return this;
  }

  /**
   * Checks if a tool call is permitted.
   *
   * @param {string} toolName
   * @param {object} [args={}]
   * @returns {object} { allowed: boolean, reason?: string }
   */
  check(toolName, args = {}) {
    // Check tool-level allowlist
    if (this.allowedTools && !this.allowedTools.includes(toolName)) {
      const result = { allowed: false, reason: `Tool "${toolName}" is not in the allowed tools list.` };
      if (this.onDenied) this.onDenied(result);
      return result;
    }

    // Check tool-level blocklist
    if (this.blockedTools.includes(toolName)) {
      const result = { allowed: false, reason: `Tool "${toolName}" is blocked.` };
      if (this.onDenied) this.onDenied(result);
      return result;
    }

    // Check per-tool permissions
    const perms = this.tools[toolName];
    if (!perms) return { allowed: true };

    const argsStr = typeof args === 'string' ? args : JSON.stringify(args);

    // Check blocked args
    for (const pattern of perms.blockArgs) {
      if (pattern.test(argsStr)) {
        const result = { allowed: false, reason: `Tool "${toolName}" argument matches blocked pattern: ${pattern}` };
        if (this.onDenied) this.onDenied(result);
        return result;
      }
    }

    // Check allowed args (if specified, args must match at least one)
    if (perms.allowArgs.length > 0) {
      const hasMatch = perms.allowArgs.some(p => p.test(argsStr));
      if (!hasMatch) {
        const result = { allowed: false, reason: `Tool "${toolName}" argument doesn't match any allowed pattern.` };
        if (this.onDenied) this.onDenied(result);
        return result;
      }
    }

    // Check file paths
    const paths = this._extractPaths(args);
    for (const path of paths) {
      for (const blocked of perms.blockPaths) {
        if (path.startsWith(blocked)) {
          const result = { allowed: false, reason: `Tool "${toolName}" cannot access path "${path}" (blocked: ${blocked})` };
          if (this.onDenied) this.onDenied(result);
          return result;
        }
      }
      if (perms.allowPaths.length > 0) {
        const isAllowed = perms.allowPaths.some(ap => path.startsWith(ap));
        if (!isAllowed) {
          const result = { allowed: false, reason: `Tool "${toolName}" cannot access path "${path}" (not in allowed paths)` };
          if (this.onDenied) this.onDenied(result);
          return result;
        }
      }
    }

    // Rate limit
    if (perms.maxCallsPerMinute < Infinity) {
      const now = Date.now();
      perms.recentCalls = perms.recentCalls.filter(t => t > now - 60000);
      perms.recentCalls.push(now);
      if (perms.recentCalls.length > perms.maxCallsPerMinute) {
        const result = { allowed: false, reason: `Tool "${toolName}" rate limit exceeded (${perms.maxCallsPerMinute}/min).` };
        if (this.onDenied) this.onDenied(result);
        return result;
      }
    }

    return { allowed: true };
  }

  /** @private */
  _extractPaths(args) {
    const paths = [];
    const pathKeys = ['path', 'file', 'file_path', 'filepath', 'target', 'destination', 'src', 'dest'];
    const extract = (obj, depth) => {
      if (!obj || typeof obj !== 'object' || depth > 5) return;
      for (const [key, value] of Object.entries(obj)) {
        if (typeof value === 'string' && (pathKeys.includes(key.toLowerCase()) || value.startsWith('/') || value.startsWith('./'))) {
          paths.push(value);
        } else if (typeof value === 'object') {
          extract(value, depth + 1);
        }
      }
    };
    extract(args, 0);
    return paths;
  }
}

// =========================================================================
// INPUT QUARANTINE
// =========================================================================

class InputQuarantine {
  /**
   * @param {object} [options]
   * @param {Function} [options.onQuarantine] - Callback when input is quarantined.
   * @param {number} [options.maxQueueSize=100] - Maximum quarantine queue size.
   */
  constructor(options = {}) {
    this.onQuarantine = options.onQuarantine || null;
    this.maxQueueSize = options.maxQueueSize || 100;
    this.queue = [];
  }

  /**
   * Quarantines an input for human review.
   *
   * @param {string} text - The quarantined text.
   * @param {object} scanResult - The scan result that triggered quarantine.
   * @param {string} [source='unknown'] - Source of the input.
   * @returns {object} { id, text, scanResult, source, timestamp }
   */
  add(text, scanResult, source = 'unknown') {
    const entry = {
      id: `q_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`,
      text,
      scanResult,
      source,
      status: 'pending',
      timestamp: Date.now()
    };

    this.queue.push(entry);
    if (this.queue.length > this.maxQueueSize) {
      this.queue.shift();
    }

    if (this.onQuarantine) {
      this.onQuarantine(entry);
    }

    return entry;
  }

  /**
   * Approves a quarantined input.
   * @param {string} id
   * @returns {object|null} The approved entry, or null if not found.
   */
  approve(id) {
    const entry = this.queue.find(e => e.id === id);
    if (entry) {
      entry.status = 'approved';
      entry.reviewedAt = Date.now();
    }
    return entry || null;
  }

  /**
   * Rejects a quarantined input.
   * @param {string} id
   * @returns {object|null}
   */
  reject(id) {
    const entry = this.queue.find(e => e.id === id);
    if (entry) {
      entry.status = 'rejected';
      entry.reviewedAt = Date.now();
    }
    return entry || null;
  }

  /**
   * Returns all pending quarantined inputs.
   * @returns {Array}
   */
  getPending() {
    return this.queue.filter(e => e.status === 'pending');
  }

  /**
   * Returns all quarantined items.
   * @returns {Array}
   */
  getAll() {
    return [...this.queue];
  }

  clear() {
    this.queue = [];
  }
}

module.exports = {
  ToolSequenceAnalyzer,
  PermissionBoundary,
  InputQuarantine,
  SUSPICIOUS_SEQUENCES
};
