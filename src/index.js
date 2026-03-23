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
const { createShieldError } = require('./errors');

/**
 * Default configuration for AgentShield.
 */
const DEFAULT_CONFIG = {
  /** License tier: 'free', 'pro', or 'enterprise'. ML features require 'pro' or 'enterprise'. */
  tier: 'free',

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

  /** Maximum input size in bytes before truncation warning. */
  maxInputSize: 1_000_000,

  /** Maximum number of scan history entries to retain. */
  maxScanHistory: 100,

  /** Maximum recursion depth when flattening tool arguments. */
  maxArgDepth: 10,

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
    // Deep-merge arrays: append user items to defaults instead of replacing
    if (config.dangerousTools) {
      this.config.dangerousTools = [...new Set([...DEFAULT_CONFIG.dangerousTools, ...config.dangerousTools])];
    }
    if (config.sensitiveFilePatterns) {
      this.config.sensitiveFilePatterns = [...DEFAULT_CONFIG.sensitiveFilePatterns, ...config.sensitiveFilePatterns];
    }
    this.stats = {
      totalScans: 0,
      threatsDetected: 0,
      blocked: 0,
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
   * @throws {TypeError} If text is not a string.
   */
  scan(text, options = {}) {
    if (typeof text !== 'string') {
      throw createShieldError('AS-DET-002', { method: 'scan', received: typeof text });
    }
    if (text.length > this.config.maxInputSize) {
      console.warn('[Agent Shield] Input exceeds configured maxInputSize - consider scanning in chunks');
    }
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
    if (this.stats.scanHistory.length > this.config.maxScanHistory) {
      this.stats.scanHistory.shift();
    }

    if (this.config.logging && result.threats.length > 0) {
      console.warn(`[Agent Shield] ${result.threats.length} threat(s) detected in ${options.source || 'unknown'}:`,
        result.threats.map(t => `${t.severity}: ${t.description}`));
    }

    if (this.config.onThreat && result.threats.length > 0) {
      try {
        this.config.onThreat(result);
      } catch (err) {
        console.error('[Agent Shield] onThreat callback error:', err.message);
      }
    }

    return result;
  }

  /**
   * Checks if threats meet the blocking threshold.
   * @private
   * @param {Array} threats
   * @returns {boolean}
   */
  _shouldBlock(threats) {
    if (!this.config.blockOnThreat || threats.length === 0) return false;
    const thresholdLevel = SEVERITY_ORDER[this.config.blockThreshold] ?? 1;
    return threats.some(t => SEVERITY_ORDER[t.severity] <= thresholdLevel);
  }

  /**
   * Scans text, applies blocking logic, and tracks stats.
   * @private
   * @param {string} text
   * @param {string} defaultSource
   * @param {string} logLabel
   * @param {object} options
   * @returns {object}
   */
  _scanWithBlocking(text, defaultSource, logLabel, options = {}) {
    const source = options.source || defaultSource;
    const result = this.scan(text, { ...options, source });

    result.blocked = this._shouldBlock(result.threats);
    if (result.blocked) {
      this.stats.blocked++;
      if (this.config.logging) {
        console.warn(`[Agent Shield] ${logLabel} BLOCKED from ${source}`);
      }
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
   * @throws {TypeError} If text is not a string.
   */
  scanInput(text, options = {}) {
    if (typeof text !== 'string') {
      throw createShieldError('AS-DET-002', { method: 'scanInput', received: typeof text });
    }
    return this._scanWithBlocking(text, 'user_input', 'INPUT', options);
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
   * @throws {TypeError} If text is not a string.
   */
  scanOutput(text, options = {}) {
    if (typeof text !== 'string') {
      throw createShieldError('AS-DET-002', { method: 'scanOutput', received: typeof text });
    }
    return this._scanWithBlocking(text, 'agent_output', 'OUTPUT', options);
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
    if (typeof toolName !== 'string') {
      throw createShieldError('AS-DET-006', { method: 'scanToolCall', received: typeof toolName });
    }
    if (!toolName) {
      return { status: 'safe', toolName: '', threats: [], warnings: ['Empty tool name'], blocked: false, isDangerousTool: false, timestamp: Date.now() };
    }
    const warnings = [];
    const allThreats = [];

    // Check if it's a dangerous tool (exact match or word-boundary match)
    const lowerName = toolName.toLowerCase();
    const isDangerousTool = this.config.dangerousTools.some(
      t => lowerName === t || lowerName.startsWith(t + '_') || lowerName.endsWith('_' + t)
    );

    if (isDangerousTool) {
      warnings.push(`Tool "${toolName}" is on the dangerous tools list.`);
    }

    // Validate args type before processing
    if (args !== null && typeof args !== 'object') {
      args = {};
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
    let blocked = this._shouldBlock(allThreats);

    // Also block dangerous tools with any threat
    if (isDangerousTool && allThreats.length > 0) {
      blocked = true;
    }

    if (blocked) {
      this.stats.blocked++;
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
    if (!Array.isArray(items)) {
      throw createShieldError('AS-DET-007', { method: 'scanBatch', received: typeof items });
    }
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
      blocked: 0,
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
   * Create an ML-enhanced shield (Pro/Enterprise only).
   *
   * Returns an MLShield instance that combines pattern matching with
   * ONNX-based ML classification for higher detection accuracy.
   * Requires the agentshield-ml package to be installed.
   *
   * @param {Object} [options] - ML options (threshold, modelPath, etc.)
   * @returns {Object} MLShield instance — call .init() then .scan()
   * @throws {Error} If tier is 'free'
   */
  enableML(options = {}) {
    const tier = options.tier || this.config.tier || 'free';
    try {
      const { MLShield } = require('./ml-detector');
      return new MLShield(this, { ...options, tier });
    } catch (e) {
      throw new Error(`[Agent Shield] Failed to load ML module: ${e.message}`);
    }
  }

  /**
   * Flattens tool arguments into a single string for scanning.
   * @private
   * @param {object} args
   * @returns {string}
   */
  _flattenArgs(args, maxDepth) {
    if (maxDepth == null) maxDepth = this.config.maxArgDepth;
    const parts = [];
    const flatten = (obj, depth) => {
      if (depth > maxDepth) return;
      if (typeof obj === 'string') {
        parts.push(obj);
      } else if (Array.isArray(obj)) {
        obj.forEach(item => flatten(item, depth + 1));
      } else if (obj && typeof obj === 'object') {
        Object.values(obj).forEach(val => flatten(val, depth + 1));
      }
    };
    flatten(args, 0);
    return parts.join(' ');
  }

  /**
   * Extracts file paths from tool arguments.
   * @private
   * @param {object} args
   * @returns {Array<string>}
   */
  _extractFilePaths(args, maxDepth) {
    if (maxDepth == null) maxDepth = this.config.maxArgDepth;
    const paths = [];
    const fileKeys = [
      'file', 'path', 'file_path', 'filepath', 'filename', 'target',
      'destination', 'src', 'dest', 'source', 'dir', 'directory',
      'folder', 'location', 'output', 'input', 'module',
      'bucket', 'table', 'url', 'uri', 'endpoint'
    ];

    /** Normalize key to lowercase with separators removed for flexible matching. */
    const normalizeKey = (key) => key.toLowerCase().replace(/[-_]/g, '');
    const normalizedFileKeys = fileKeys.map(normalizeKey);

    const extract = (obj, depth) => {
      if (!obj || typeof obj !== 'object' || depth > maxDepth) return;
      for (const [key, value] of Object.entries(obj)) {
        if (typeof value === 'string') {
          // Match by key name (supports camelCase, snake_case, kebab-case)
          if (normalizedFileKeys.includes(normalizeKey(key))) {
            paths.push(value);
          // Match by path-like value patterns
          } else if (value.startsWith('/') || value.startsWith('./') || value.startsWith('../') || /^[A-Z]:\\/.test(value)) {
            paths.push(value);
          }
        } else if (typeof value === 'object') {
          extract(value, depth + 1);
        }
      }
    };
    extract(args, 0);
    return paths;
  }
}

module.exports = { AgentShield };
