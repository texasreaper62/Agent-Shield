'use strict';

/**
 * Agent Shield — MCP (Model Context Protocol) Server
 *
 * Exposes Agent Shield capabilities as MCP tools over JSON-RPC 2.0 on stdin/stdout.
 * Any MCP-capable AI agent (e.g. Claude) can use Agent Shield natively as a tool provider.
 *
 * All detection runs locally — no data ever leaves your environment.
 *
 * @example
 * // Start the server from CLI:
 * // node src/mcp-server.js
 * // node src/mcp-server.js --config ./agent-shield.json
 *
 * // Or programmatically:
 * const { MCPServer } = require('./mcp-server');
 * const server = new MCPServer({ sensitivity: 'high' });
 * server.start();
 */

const { AgentShield } = require('./index');
const { PIIRedactor } = require('./pii');
const { CanaryTokens } = require('./canary');
const { ShieldScoreCalculator } = require('./shield-score');
const { ThreatEncyclopedia, THREAT_ENCYCLOPEDIA } = require('./threat-encyclopedia');
const fs = require('fs');
const path = require('path');

// =========================================================================
// JSON-RPC 2.0 Error Codes
// =========================================================================

const JSON_RPC_ERRORS = {
  PARSE_ERROR: { code: -32700, message: 'Parse error' },
  INVALID_REQUEST: { code: -32600, message: 'Invalid Request' },
  METHOD_NOT_FOUND: { code: -32601, message: 'Method not found' },
  INVALID_PARAMS: { code: -32602, message: 'Invalid params' },
  INTERNAL_ERROR: { code: -32603, message: 'Internal error' }
};

// =========================================================================
// MCP Tool Definitions
// =========================================================================

const MCP_TOOLS = [
  {
    name: 'scan_text',
    description: 'Scan text for AI security threats including prompt injection, jailbreak attempts, data exfiltration, and 30+ other attack types. Returns threat details with severity and confidence scores.',
    inputSchema: {
      type: 'object',
      properties: {
        text: { type: 'string', description: 'The text to scan for threats' },
        sensitivity: { type: 'string', enum: ['low', 'medium', 'high'], description: 'Detection sensitivity level (default: medium)' },
        source: { type: 'string', description: 'Label describing where the text came from (e.g. "user_input", "api_response")' }
      },
      required: ['text']
    }
  },
  {
    name: 'scan_input',
    description: 'Scan user input before an AI agent processes it. Applies blocking logic when threats meet the configured threshold.',
    inputSchema: {
      type: 'object',
      properties: {
        text: { type: 'string', description: 'The user input text to scan' }
      },
      required: ['text']
    }
  },
  {
    name: 'scan_output',
    description: 'Scan agent output before returning it to the user. Detects compromised agent responses, leaked system prompts, and policy violations.',
    inputSchema: {
      type: 'object',
      properties: {
        text: { type: 'string', description: 'The agent output text to scan' }
      },
      required: ['text']
    }
  },
  {
    name: 'scan_tool_call',
    description: 'Validate a tool call before execution. Checks if the tool is dangerous and scans arguments for injection attacks and sensitive file access.',
    inputSchema: {
      type: 'object',
      properties: {
        toolName: { type: 'string', description: 'Name of the tool being called' },
        args: { type: 'object', description: 'The tool call arguments to validate' }
      },
      required: ['toolName']
    }
  },
  {
    name: 'redact_pii',
    description: 'Detect and redact personally identifiable information (PII) from text. Covers email, phone, SSN, credit card, IP address, and more.',
    inputSchema: {
      type: 'object',
      properties: {
        text: { type: 'string', description: 'The text to redact PII from' }
      },
      required: ['text']
    }
  },
  {
    name: 'check_canary',
    description: 'Check text for canary token leaks. Canary tokens are tripwire strings embedded in agent context; their presence in output indicates compromise.',
    inputSchema: {
      type: 'object',
      properties: {
        text: { type: 'string', description: 'The text to check for canary token leaks' },
        tokens: {
          type: 'array',
          items: { type: 'string' },
          description: 'List of canary token strings to check for'
        }
      },
      required: ['text', 'tokens']
    }
  },
  {
    name: 'shield_score',
    description: 'Calculate and return the current Agent Shield security score (0-100) with category breakdown, grade, and recommendations.',
    inputSchema: {
      type: 'object',
      properties: {},
      required: []
    }
  },
  {
    name: 'get_threats',
    description: 'Search the threat encyclopedia for information about AI security threats. Returns descriptions, examples, mitigations, and references.',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Search query — a threat name, ID (e.g. "T001"), category, or keyword' }
      },
      required: ['query']
    }
  }
];

// =========================================================================
// MCPToolHandler
// =========================================================================

/**
 * Wraps Agent Shield components to handle MCP tool calls.
 * Each method corresponds to one of the exposed MCP tools.
 */
class MCPToolHandler {
  /**
   * @param {object} [options] - Shield configuration options.
   */
  constructor(options = {}) {
    this.shield = new AgentShield(options);
    this.piiRedactor = new PIIRedactor(options.pii || {});
    this.canaryTokens = new CanaryTokens(options.canary || {});
    this.scoreCalculator = new ShieldScoreCalculator({
      sensitivity: options.sensitivity || 'high'
    });
    this.encyclopedia = new ThreatEncyclopedia();
  }

  /**
   * Scan text for AI security threats.
   * @param {object} params - { text, sensitivity?, source? }
   * @returns {object} Structured scan result.
   */
  scanText(params) {
    if (!params || !params.text) {
      throw new Error('Missing required parameter: text');
    }
    const result = this.shield.scan(params.text, {
      sensitivity: params.sensitivity,
      source: params.source || 'mcp_scan_text'
    });
    return {
      status: result.status,
      threatCount: result.threats.length,
      threats: result.threats,
      timestamp: result.timestamp
    };
  }

  /**
   * Scan user input before agent processing.
   * @param {object} params - { text }
   * @returns {object} Scan result with blocked field.
   */
  scanInput(params) {
    if (!params || !params.text) {
      throw new Error('Missing required parameter: text');
    }
    const result = this.shield.scanInput(params.text, {
      source: 'mcp_scan_input'
    });
    return {
      status: result.status,
      blocked: result.blocked,
      threatCount: result.threats.length,
      threats: result.threats,
      timestamp: result.timestamp
    };
  }

  /**
   * Scan agent output before returning to user.
   * @param {object} params - { text }
   * @returns {object} Scan result with blocked field.
   */
  scanOutput(params) {
    if (!params || !params.text) {
      throw new Error('Missing required parameter: text');
    }
    const result = this.shield.scanOutput(params.text, {
      source: 'mcp_scan_output'
    });
    return {
      status: result.status,
      blocked: result.blocked,
      threatCount: result.threats.length,
      threats: result.threats,
      timestamp: result.timestamp
    };
  }

  /**
   * Validate a tool call before execution.
   * @param {object} params - { toolName, args? }
   * @returns {object} Scan result with blocked, warnings, and isDangerousTool fields.
   */
  scanToolCall(params) {
    if (!params || !params.toolName) {
      throw new Error('Missing required parameter: toolName');
    }
    const result = this.shield.scanToolCall(
      params.toolName,
      params.args || {},
      { source: 'mcp_scan_tool_call' }
    );
    return {
      status: result.status,
      toolName: result.toolName,
      blocked: result.blocked,
      isDangerousTool: result.isDangerousTool,
      warnings: result.warnings,
      threatCount: result.threats.length,
      threats: result.threats,
      timestamp: result.timestamp
    };
  }

  /**
   * Redact PII from text.
   * @param {object} params - { text }
   * @returns {object} { redacted, findings, count }
   */
  redactPII(params) {
    if (!params || !params.text) {
      throw new Error('Missing required parameter: text');
    }
    return this.piiRedactor.redact(params.text);
  }

  /**
   * Check text for canary token leaks.
   * @param {object} params - { text, tokens }
   * @returns {object} { leaked, leaks }
   */
  checkCanary(params) {
    if (!params || !params.text) {
      throw new Error('Missing required parameter: text');
    }
    if (!params.tokens || !Array.isArray(params.tokens) || params.tokens.length === 0) {
      throw new Error('Missing required parameter: tokens (array of canary token strings)');
    }

    // Register the provided tokens, then check for leaks
    const registeredTokens = [];
    for (const token of params.tokens) {
      // Create a temporary entry for each token to check
      const id = `check_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
      this.canaryTokens.tokens.set(id, {
        token,
        label: 'mcp_check',
        createdAt: Date.now(),
        triggeredCount: 0
      });
      registeredTokens.push(id);
    }

    const result = this.canaryTokens.check(params.text, 'mcp_check_canary');

    // Clean up temporary tokens
    for (const id of registeredTokens) {
      this.canaryTokens.tokens.delete(id);
    }

    return {
      leaked: result.leaked,
      leaks: result.leaks
    };
  }

  /**
   * Calculate and return the shield security score.
   * @returns {object} Score breakdown with grade, categories, and recommendations.
   */
  getScore() {
    const result = this.scoreCalculator.calculate();
    return {
      score: result.score,
      grade: result.grade,
      label: result.label,
      categories: result.categories,
      recommendations: result.recommendations,
      elapsed: result.elapsed
    };
  }

  /**
   * Search the threat encyclopedia.
   * @param {object} params - { query }
   * @returns {object} Matching threat entries.
   */
  getThreats(params) {
    if (!params || !params.query) {
      throw new Error('Missing required parameter: query');
    }

    const query = params.query.trim();

    // Try direct lookup by ID or key first
    const direct = this.encyclopedia.get(query);
    if (direct) {
      return { results: [direct], count: 1 };
    }

    // Fall back to search
    const results = this.encyclopedia.search(query);
    return { results, count: results.length };
  }
}

// =========================================================================
// MCPServer
// =========================================================================

/**
 * MCP Server for Agent Shield.
 * Communicates via JSON-RPC 2.0 over stdin/stdout.
 */
class MCPServer {
  /**
   * Creates a new MCPServer instance.
   * @param {object} [options] - Shield configuration options passed to AgentShield.
   */
  constructor(options = {}) {
    this.options = options;
    this.handler = new MCPToolHandler(options);
    this.running = false;
    this._buffer = '';
    this._onData = null;

    /** @type {object} Server metadata returned in initialize response. */
    this.serverInfo = {
      name: 'agent-shield',
      version: '1.0.0'
    };

    /** @type {object} Server capabilities. */
    this.capabilities = {
      tools: {},
      resources: {}
    };
  }

  /**
   * Starts listening on stdin for JSON-RPC messages.
   * Responses are written to stdout.
   */
  start() {
    if (this.running) return;
    this.running = true;

    console.error('[Agent Shield] MCP server starting...');

    this._onData = (chunk) => {
      this._buffer += chunk.toString();
      if (this._buffer.length > 10 * 1024 * 1024) {
        console.error('[Agent Shield] MCP buffer exceeded 10MB, clearing');
        this._buffer = '';
        return;
      }
      this._processBuffer();
    };

    process.stdin.setEncoding('utf8');
    process.stdin.on('data', this._onData);
    process.stdin.resume();

    console.error('[Agent Shield] MCP server ready — listening on stdin');
  }

  /**
   * Stops the server and cleans up stdin listener.
   */
  stop() {
    if (!this.running) return;
    this.running = false;

    if (this._onData) {
      process.stdin.removeListener('data', this._onData);
      this._onData = null;
    }

    console.error('[Agent Shield] MCP server stopped');
  }

  /**
   * Process the internal buffer, extracting and handling complete JSON-RPC messages.
   * Messages are delimited by newlines.
   * @private
   */
  _processBuffer() {
    const lines = this._buffer.split('\n');
    // Keep the last incomplete line in the buffer
    this._buffer = lines.pop() || '';

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;

      try {
        const message = JSON.parse(trimmed);
        const response = this.handleMessage(message);
        if (response) {
          this._send(response);
        }
      } catch (err) {
        // JSON parse error
        this._send({
          jsonrpc: '2.0',
          id: null,
          error: { code: JSON_RPC_ERRORS.PARSE_ERROR.code, message: JSON_RPC_ERRORS.PARSE_ERROR.message }
        });
      }
    }
  }

  /**
   * Send a JSON-RPC response to stdout.
   * @private
   * @param {object} response - The JSON-RPC response object.
   */
  _send(response) {
    const json = JSON.stringify(response);
    process.stdout.write(json + '\n');
  }

  /**
   * Routes a JSON-RPC message to the appropriate handler.
   *
   * @param {object} message - Parsed JSON-RPC 2.0 request.
   * @returns {object|null} JSON-RPC response, or null for notifications.
   */
  handleMessage(message) {
    // Validate JSON-RPC 2.0 structure
    if (!message || message.jsonrpc !== '2.0') {
      return {
        jsonrpc: '2.0',
        id: message && message.id !== null && message.id !== undefined ? message.id : null,
        error: { code: JSON_RPC_ERRORS.INVALID_REQUEST.code, message: JSON_RPC_ERRORS.INVALID_REQUEST.message }
      };
    }

    const { id, method, params } = message;

    // Notifications (no id) don't get responses
    if ((id === null || id === undefined) && method !== 'initialize') {
      return null;
    }

    try {
      switch (method) {
        case 'initialize':
          return this._handleInitialize(id, params);
        case 'tools/list':
          return this._handleToolsList(id);
        case 'tools/call':
          return this._handleToolsCall(id, params);
        case 'resources/list':
          return this._handleResourcesList(id);
        case 'resources/read':
          return this._handleResourcesRead(id, params);
        default:
          return {
            jsonrpc: '2.0',
            id,
            error: { code: JSON_RPC_ERRORS.METHOD_NOT_FOUND.code, message: `Method not found: ${method}` }
          };
      }
    } catch (err) {
      console.error(`[Agent Shield] MCP error handling ${method}:`, err.message);
      return {
        jsonrpc: '2.0',
        id,
        error: { code: JSON_RPC_ERRORS.INTERNAL_ERROR.code, message: err.message }
      };
    }
  }

  /**
   * Handle the MCP initialize request.
   * @private
   * @param {number|string} id - Request ID.
   * @param {object} params - Client capabilities.
   * @returns {object} JSON-RPC response with server info and capabilities.
   */
  _handleInitialize(id, params) {
    console.error('[Agent Shield] MCP client connected:', params && params.clientInfo ? params.clientInfo.name : 'unknown');
    return {
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: '2024-11-05',
        serverInfo: this.serverInfo,
        capabilities: this.capabilities
      }
    };
  }

  /**
   * Handle tools/list — return all available MCP tools.
   * @private
   * @param {number|string} id - Request ID.
   * @returns {object} JSON-RPC response with tool list.
   */
  _handleToolsList(id) {
    return {
      jsonrpc: '2.0',
      id,
      result: {
        tools: MCP_TOOLS
      }
    };
  }

  /**
   * Handle tools/call — execute a tool and return the result.
   * @private
   * @param {number|string} id - Request ID.
   * @param {object} params - { name, arguments }
   * @returns {object} JSON-RPC response with tool result.
   */
  _handleToolsCall(id, params) {
    if (!params || !params.name) {
      return {
        jsonrpc: '2.0',
        id,
        error: { code: JSON_RPC_ERRORS.INVALID_PARAMS.code, message: 'Missing required parameter: name' }
      };
    }

    const toolName = params.name;
    const toolArgs = params.arguments || {};

    let result;
    let isError = false;

    try {
      switch (toolName) {
        case 'scan_text':
          result = this.handler.scanText(toolArgs);
          break;
        case 'scan_input':
          result = this.handler.scanInput(toolArgs);
          break;
        case 'scan_output':
          result = this.handler.scanOutput(toolArgs);
          break;
        case 'scan_tool_call':
          result = this.handler.scanToolCall(toolArgs);
          break;
        case 'redact_pii':
          result = this.handler.redactPII(toolArgs);
          break;
        case 'check_canary':
          result = this.handler.checkCanary(toolArgs);
          break;
        case 'shield_score':
          result = this.handler.getScore();
          break;
        case 'get_threats':
          result = this.handler.getThreats(toolArgs);
          break;
        default:
          return {
            jsonrpc: '2.0',
            id,
            error: { code: JSON_RPC_ERRORS.METHOD_NOT_FOUND.code, message: `Unknown tool: ${toolName}` }
          };
      }
    } catch (err) {
      result = { error: err.message };
      isError = true;
    }

    return {
      jsonrpc: '2.0',
      id,
      result: {
        content: [
          {
            type: 'text',
            text: JSON.stringify(result, null, 2)
          }
        ],
        isError
      }
    };
  }

  /**
   * Handle resources/list — expose threat encyclopedia entries as resources.
   * @private
   * @param {number|string} id - Request ID.
   * @returns {object} JSON-RPC response with resource list.
   */
  _handleResourcesList(id) {
    const resources = [];

    for (const [key, threat] of Object.entries(THREAT_ENCYCLOPEDIA)) {
      resources.push({
        uri: `threat://${threat.id}`,
        name: threat.name,
        description: threat.summary,
        mimeType: 'application/json'
      });
    }

    return {
      jsonrpc: '2.0',
      id,
      result: { resources }
    };
  }

  /**
   * Handle resources/read — read a specific threat resource by URI.
   * @private
   * @param {number|string} id - Request ID.
   * @param {object} params - { uri }
   * @returns {object} JSON-RPC response with resource contents.
   */
  _handleResourcesRead(id, params) {
    if (!params || !params.uri) {
      return {
        jsonrpc: '2.0',
        id,
        error: { code: JSON_RPC_ERRORS.INVALID_PARAMS.code, message: 'Missing required parameter: uri' }
      };
    }

    const uri = params.uri;

    // Extract threat ID from URI (e.g. "threat://T001" -> "T001")
    const match = uri.match(/^threat:\/\/(.+)$/);
    if (!match) {
      return {
        jsonrpc: '2.0',
        id,
        error: { code: JSON_RPC_ERRORS.INVALID_PARAMS.code, message: `Invalid resource URI: ${uri}` }
      };
    }

    const threatId = match[1];
    const threat = this.handler.encyclopedia.get(threatId);

    if (!threat) {
      return {
        jsonrpc: '2.0',
        id,
        error: { code: JSON_RPC_ERRORS.INVALID_PARAMS.code, message: `Threat not found: ${threatId}` }
      };
    }

    return {
      jsonrpc: '2.0',
      id,
      result: {
        contents: [
          {
            uri,
            mimeType: 'application/json',
            text: JSON.stringify(threat, null, 2)
          }
        ]
      }
    };
  }
}

// =========================================================================
// Standalone Entry Point
// =========================================================================

if (require.main === module) {
  let config = {};

  // Parse --config flag
  const configIndex = process.argv.indexOf('--config');
  if (configIndex !== -1 && process.argv[configIndex + 1]) {
    const configPath = path.resolve(process.argv[configIndex + 1]);
    try {
      const raw = fs.readFileSync(configPath, 'utf8');
      config = JSON.parse(raw);
      console.error(`[Agent Shield] Loaded config from ${configPath}`);
    } catch (err) {
      console.error(`[Agent Shield] Failed to load config from ${configPath}: ${err.message}`);
      process.exit(1);
    }
  }

  const server = new MCPServer(config);
  server.start();

  // Graceful shutdown
  process.on('SIGINT', () => {
    server.stop();
    process.exit(0);
  });
  process.on('SIGTERM', () => {
    server.stop();
    process.exit(0);
  });
}

module.exports = { MCPServer, MCPToolHandler };
