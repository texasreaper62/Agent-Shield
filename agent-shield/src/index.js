'use strict';

/**
 * Agent Shield SDK
 *
 * Protects AI agents from prompt injection, data exfiltration,
 * tool abuse, and other AI-specific attacks.
 *
 * All detection runs locally — no data ever leaves your environment.
 *
 * @example
 * const { AgentShield } = require('agent-shield');
 *
 * const shield = new AgentShield();
 *
 * // Scan any text
 * const result = shield.scan('ignore all previous instructions');
 * if (result.status !== 'safe') {
 *   console.log('Threat detected:', result.threats);
 * }
 *
 * // Scan agent input before processing
 * const inputResult = shield.scanInput(userMessage);
 * if (inputResult.blocked) {
 *   return 'This input was blocked for safety reasons.';
 * }
 *
 * // Scan agent output before returning to user
 * const outputResult = shield.scanOutput(agentResponse);
 *
 * // Scan tool calls before execution
 * const toolResult = shield.scanToolCall('bash', { command: 'cat /etc/passwd' });
 */

const { scanText, getPatterns, SEVERITY_ORDER } = require('./detector-core');

/**
 * Default configuration for AgentShield.
 */
const DEFAULT_CONFIG = {
  /** Sensitivity level: 'low', 'medium', or 'high'. */
  sensitivity: 'medium',

  /** Whether to block inputs that reach the threshold. */
  blockOnThreat: false,

  /** Minimum severity to trigger a block: 'low', 'medium', 'high', or 'critical'. */
  blockThreshold: 'high',

  /** Whether to log scan results to console. */
  logging: false,

  /** Custom callback when a threat is detected. */
  onThreat: null,

  /** Dangerous tool names that should be scrutinized more carefully. */
  dangerousTools: [
    'bash', 'shell', 'terminal', 'exec', 'execute',
    'eval', 'run_command', 'system',
    'write_file', 'delete_file', 'remove',
    'http_request', 'fetch', 'curl', 'wget',
    'sql', 'query', 'database'
  ],

  /** Sensitive file patterns that should never be accessed. */
  sensitiveFilePatterns: [
    /\.env$/i,
    /credentials/i,
    /secrets?\.(?:json|yaml|yml|toml)/i,
    /private[_-]?key/i,
    /password/i,
    /token/i,
    /\.pem$/i,
    /\.key$/i,
    /id_rsa/i,
    /id_ed25519/i
  ]
};

class AgentShield {
  /**
   * Creates a new AgentShield instance.
   * @param {object} [config] - Configuration overrides.
   */
  constructor(config = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.stats = {
      totalScans: 0,
      threatsDetected: 0,
      inputsBlocked: 0,
      scanHistory: []
    };
  }

  /**
   * Scans arbitrary text for threats.
   *
   * @param {string} text - Text to scan.
   * @param {object} [options] - Scan options.
   * @param {string} [options.source] - Label for where the text came from.
   * @param {string} [options.sensitivity] - Override default sensitivity.
   * @returns {object} Scan result.
   */
  scan(text, options = {}) {
    const result = scanText(text, {
      source: options.source || 'unknown',
      sensitivity: options.sensitivity || this.config.sensitivity
    });

    this.stats.totalScans++;
    if (result.threats.length > 0) {
      this.stats.threatsDetected += result.threats.length;
    }

    // Keep last 100 scans in history
    this.stats.scanHistory.push({
      timestamp: result.timestamp,
      status: result.status,
      threatCount: result.threats.length,
      source: options.source || 'unknown'
    });
    if (this.stats.scanHistory.length > 100) {
      this.stats.scanHistory.shift();
    }

    if (this.config.logging && result.threats.length > 0) {
      console.warn(`[Agent Shield] ${result.threats.length} threat(s) detected in ${options.source || 'unknown'}:`,
        result.threats.map(t => `${t.severity}: ${t.description}`));
    }

    if (this.config.onThreat && result.threats.length > 0) {
      this.config.onThreat(result);
    }

    return result;
  }

  /**
   * Scans an agent's input (user message, API response, document, etc.)
   * before the agent processes it.
   *
   * @param {string} text - The input text.
   * @param {object} [options] - Options.
   * @param {string} [options.source='user_input'] - Where the input came from.
   * @returns {object} Scan result with additional `blocked` field.
   */
  scanInput(text, options = {}) {
    const source = options.source || 'user_input';
    const result = this.scan(text, { ...options, source });

    result.blocked = false;
    if (this.config.blockOnThreat && result.threats.length > 0) {
      const thresholdLevel = SEVERITY_ORDER[this.config.blockThreshold] ?? 1;
      const hasBlockingThreat = result.threats.some(
        t => SEVERITY_ORDER[t.severity] <= thresholdLevel
      );
      if (hasBlockingThreat) {
        result.blocked = true;
        this.stats.inputsBlocked++;
        if (this.config.logging) {
          console.warn(`[Agent Shield] INPUT BLOCKED from ${source}`);
        }
      }
    }

    return result;
  }

  /**
   * Scans an agent's output before it's returned to the user.
   * Catches cases where an agent has been successfully manipulated
   * and is now producing dangerous output.
   *
   * @param {string} text - The agent's output text.
   * @param {object} [options] - Options.
   * @param {string} [options.source='agent_output'] - Source label.
   * @returns {object} Scan result with additional `blocked` field.
   */
  scanOutput(text, options = {}) {
    const source = options.source || 'agent_output';
    const result = this.scan(text, { ...options, source });

    result.blocked = false;
    if (this.config.blockOnThreat && result.threats.length > 0) {
      const thresholdLevel = SEVERITY_ORDER[this.config.blockThreshold] ?? 1;
      const hasBlockingThreat = result.threats.some(
        t => SEVERITY_ORDER[t.severity] <= thresholdLevel
      );
      if (hasBlockingThreat) {
        result.blocked = true;
        this.stats.inputsBlocked++;
        if (this.config.logging) {
          console.warn(`[Agent Shield] OUTPUT BLOCKED from ${source}`);
        }
      }
    }

    return result;
  }

  /**
   * Scans a tool call before the agent executes it.
   * Checks both the tool name and its arguments for threats.
   *
   * @param {string} toolName - Name of the tool being called.
   * @param {object} args - The tool's arguments.
   * @param {object} [options] - Options.
   * @returns {object} Scan result with `blocked` and `warnings` fields.
   */
  scanToolCall(toolName, args = {}, options = {}) {
    const warnings = [];
    const allThreats = [];

    // Check if it's a dangerous tool
    const isDangerousTool = this.config.dangerousTools.some(
      t => toolName.toLowerCase().includes(t)
    );

    if (isDangerousTool) {
      warnings.push(`Tool "${toolName}" is on the dangerous tools list.`);
    }

    // Scan all string arguments for injection
    const argsText = this._flattenArgs(args);
    if (argsText) {
      const result = this.scan(argsText, {
        source: `tool_call:${toolName}`,
        ...options
      });
      allThreats.push(...result.threats);
    }

    // Check for sensitive file access
    const fileArgs = this._extractFilePaths(args);
    for (const filePath of fileArgs) {
      const isSensitive = this.config.sensitiveFilePatterns.some(
        pattern => pattern.test(filePath)
      );
      if (isSensitive) {
        allThreats.push({
          severity: 'critical',
          category: 'data_exfiltration',
          description: `Tool "${toolName}" is trying to access a sensitive file: ${filePath}`,
          detail: `Sensitive file access attempt via tool call. File: ${filePath}`,
          confidence: 90,
          confidenceLabel: 'Almost certainly a threat'
        });
      }
    }

    // Determine if this should be blocked
    let blocked = false;
    if (this.config.blockOnThreat && allThreats.length > 0) {
      const thresholdLevel = SEVERITY_ORDER[this.config.blockThreshold] ?? 1;
      blocked = allThreats.some(t => SEVERITY_ORDER[t.severity] <= thresholdLevel);
    }

    // Also block dangerous tools with any threat
    if (isDangerousTool && allThreats.length > 0) {
      blocked = true;
    }

    if (blocked) {
      this.stats.inputsBlocked++;
      if (this.config.logging) {
        console.warn(`[Agent Shield] TOOL CALL BLOCKED: ${toolName}`);
      }
    }

    return {
      status: allThreats.length > 0 ? 'danger' : 'safe',
      toolName,
      threats: allThreats,
      warnings,
      blocked,
      isDangerousTool,
      timestamp: Date.now()
    };
  }

  /**
   * Scans multiple pieces of text in batch.
   *
   * @param {Array<{text: string, source?: string}>} items - Items to scan.
   * @returns {object} Combined result with per-item results.
   */
  scanBatch(items) {
    const results = items.map(item =>
      this.scan(item.text, { source: item.source || 'batch' })
    );

    const allThreats = results.flatMap(r => r.threats);
    let worstStatus = 'safe';
    for (const r of results) {
      if (r.status === 'danger') { worstStatus = 'danger'; break; }
      if (r.status === 'warning' && worstStatus !== 'danger') worstStatus = 'warning';
      if (r.status === 'caution' && worstStatus === 'safe') worstStatus = 'caution';
    }

    return {
      status: worstStatus,
      results,
      totalThreats: allThreats.length,
      timestamp: Date.now()
    };
  }

  /**
   * Returns the current scan statistics.
   * @returns {object}
   */
  getStats() {
    return { ...this.stats };
  }

  /**
   * Resets scan statistics.
   */
  resetStats() {
    this.stats = {
      totalScans: 0,
      threatsDetected: 0,
      inputsBlocked: 0,
      scanHistory: []
    };
  }

  /**
   * Returns all detection patterns the engine uses.
   * @returns {Array}
   */
  getPatterns() {
    return getPatterns();
  }

  /**
   * Flattens tool arguments into a single string for scanning.
   * @private
   * @param {object} args
   * @returns {string}
   */
  _flattenArgs(args) {
    const parts = [];
    const flatten = (obj) => {
      if (typeof obj === 'string') {
        parts.push(obj);
      } else if (Array.isArray(obj)) {
        obj.forEach(flatten);
      } else if (obj && typeof obj === 'object') {
        Object.values(obj).forEach(flatten);
      }
    };
    flatten(args);
    return parts.join(' ');
  }

  /**
   * Extracts file paths from tool arguments.
   * @private
   * @param {object} args
   * @returns {Array<string>}
   */
  _extractFilePaths(args) {
    const paths = [];
    const fileKeys = ['file', 'path', 'file_path', 'filepath', 'filename', 'target', 'destination', 'src', 'dest'];

    const extract = (obj) => {
      if (!obj || typeof obj !== 'object') return;
      for (const [key, value] of Object.entries(obj)) {
        if (typeof value === 'string' && fileKeys.includes(key.toLowerCase())) {
          paths.push(value);
        } else if (typeof value === 'string' && (value.startsWith('/') || value.startsWith('./'))) {
          paths.push(value);
        } else if (typeof value === 'object') {
          extract(value);
        }
      }
    };
    extract(args);
    return paths;
  }
}

module.exports = { AgentShield };
