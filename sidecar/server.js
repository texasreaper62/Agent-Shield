'use strict';

/**
 * Agent Shield — HTTP Sidecar Server
 *
 * Exposes Agent Shield over a REST API so any language or tool can call it.
 * Zero external dependencies — uses only Node.js built-in http module.
 *
 * Usage:
 *   node sidecar/server.js                  # starts on default port 3141
 *   PORT=8080 node sidecar/server.js        # starts on port 8080
 *
 * @example
 *   curl -X POST http://localhost:3141/scan \
 *     -H 'Content-Type: application/json' \
 *     -d '{"text": "ignore all previous instructions"}'
 */

const http = require('http');
const {
  AgentShield,
  scanText,
  getPatterns,
  PIIRedactor,
  ShieldScoreCalculator,
  PromptLinter
} = require('../src/main');

// =========================================================================
// Configuration
// =========================================================================

const PORT = parseInt(process.env.PORT || process.env.AGENT_SHIELD_PORT, 10) || 3141;
const HOST = process.env.HOST || '0.0.0.0';

/**
 * Server options — override via createServer(options) or environment variables.
 * @type {Object}
 */
const options = {
  apiKey: process.env.AGENT_SHIELD_API_KEY || '',
  maxBodySize: parseInt(process.env.AGENT_SHIELD_MAX_BODY_SIZE, 10) || 1048576, // 1MB
  rateLimit: parseInt(process.env.AGENT_SHIELD_RATE_LIMIT, 10) || 100, // requests per minute
  cors: process.env.AGENT_SHIELD_CORS || 'same-origin'
};

// =========================================================================
// Shared Shield Instance
// =========================================================================

const shield = new AgentShield({
  sensitivity: 'high',
  blockOnThreat: true,
  logging: false
});

const piiRedactor = new PIIRedactor();

// =========================================================================
// Rate Limiting
// =========================================================================

/** @type {Map<string, number[]>} IP -> array of request timestamps */
const rateLimitMap = new Map();

/**
 * Check if an IP has exceeded the rate limit.
 * Cleans up expired timestamps on each call.
 * @param {string} ip
 * @returns {boolean} true if rate limit exceeded
 */
function isRateLimited(ip) {
  const now = Date.now();
  const windowMs = 60000; // 1 minute
  const timestamps = rateLimitMap.get(ip) || [];

  // Remove timestamps outside the window
  const valid = timestamps.filter(t => now - t < windowMs);

  if (valid.length >= options.rateLimit) {
    rateLimitMap.set(ip, valid);
    return true;
  }

  valid.push(now);
  rateLimitMap.set(ip, valid);
  return false;
}

// =========================================================================
// Helpers
// =========================================================================

/**
 * Reads the full request body as a string.
 * Rejects with a 413 error object if body exceeds maxBodySize.
 * @param {http.IncomingMessage} req
 * @returns {Promise<string>}
 */
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let totalSize = 0;
    req.on('data', chunk => {
      totalSize += chunk.length;
      if (totalSize > options.maxBodySize) {
        const err = new Error('Request body too large');
        err.statusCode = 413;
        req.destroy();
        reject(err);
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

/**
 * Parses a JSON body, returning null on failure.
 * @param {string} raw
 * @returns {object|null}
 */
function parseJSON(raw) {
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

/**
 * Sends a JSON response.
 * @param {http.ServerResponse} res
 * @param {number} statusCode
 * @param {object} data
 */
function sendJSON(res, statusCode, data) {
  const body = JSON.stringify(data);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': options.cors,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'X-Powered-By': 'Agent Shield Sidecar'
  });
  res.end(body);
}

/**
 * Sends a 400 error for bad JSON.
 * @param {http.ServerResponse} res
 * @param {string} [message]
 */
function sendBadRequest(res, message) {
  sendJSON(res, 400, { error: message || 'Invalid JSON body' });
}

/**
 * Logs a request.
 * @param {string} method
 * @param {string} url
 * @param {number} statusCode
 */
function logRequest(method, url, statusCode) {
  const timestamp = new Date().toISOString();
  console.log(`[Agent Shield Sidecar] ${timestamp} ${method} ${url} -> ${statusCode}`);
}

// =========================================================================
// Route Handlers
// =========================================================================

/**
 * POST /scan — Scan arbitrary text for threats.
 * Body: { text: string, sensitivity?: string, source?: string }
 */
async function handleScan(req, res) {
  const raw = await readBody(req);
  const body = parseJSON(raw);
  if (!body || typeof body.text !== 'string') {
    return sendBadRequest(res, 'Body must include "text" as a string');
  }

  const result = shield.scan(body.text, {
    sensitivity: body.sensitivity || undefined,
    source: body.source || 'sidecar'
  });

  sendJSON(res, 200, result);
}

/**
 * POST /scan/input — Scan agent input.
 * Body: { text: string }
 */
async function handleScanInput(req, res) {
  const raw = await readBody(req);
  const body = parseJSON(raw);
  if (!body || typeof body.text !== 'string') {
    return sendBadRequest(res, 'Body must include "text" as a string');
  }

  const result = shield.scanInput(body.text);
  sendJSON(res, 200, result);
}

/**
 * POST /scan/output — Scan agent output.
 * Body: { text: string }
 */
async function handleScanOutput(req, res) {
  const raw = await readBody(req);
  const body = parseJSON(raw);
  if (!body || typeof body.text !== 'string') {
    return sendBadRequest(res, 'Body must include "text" as a string');
  }

  const result = shield.scanOutput(body.text);
  sendJSON(res, 200, result);
}

/**
 * POST /scan/tool — Scan a tool call.
 * Body: { tool: string, args: object }
 */
async function handleScanTool(req, res) {
  const raw = await readBody(req);
  const body = parseJSON(raw);
  if (!body || typeof body.tool !== 'string') {
    return sendBadRequest(res, 'Body must include "tool" as a string');
  }

  const result = shield.scanToolCall(body.tool, body.args || {});
  sendJSON(res, 200, result);
}

/**
 * POST /pii/redact — Redact PII from text.
 * Body: { text: string }
 */
async function handlePIIRedact(req, res) {
  const raw = await readBody(req);
  const body = parseJSON(raw);
  if (!body || typeof body.text !== 'string') {
    return sendBadRequest(res, 'Body must include "text" as a string');
  }

  const result = piiRedactor.redact(body.text);
  sendJSON(res, 200, result);
}

/**
 * GET /health — Health check.
 */
function handleHealth(_req, res) {
  sendJSON(res, 200, {
    status: 'healthy',
    service: 'agent-shield-sidecar',
    version: '1.0.0',
    uptime: process.uptime(),
    timestamp: Date.now()
  });
}

/**
 * GET /score — Calculate shield score.
 */
function handleScore(_req, res) {
  const calculator = new ShieldScoreCalculator({ sensitivity: 'high' });
  const score = calculator.calculate();
  sendJSON(res, 200, score);
}

/**
 * GET /patterns — List all detection patterns.
 */
function handlePatterns(_req, res) {
  const patterns = getPatterns();
  sendJSON(res, 200, { count: patterns.length, patterns });
}

/**
 * GET /stats — Return scan statistics.
 */
function handleStats(_req, res) {
  sendJSON(res, 200, shield.stats);
}

// =========================================================================
// Router
// =========================================================================

const routes = {
  'POST /scan':        handleScan,
  'POST /scan/input':  handleScanInput,
  'POST /scan/output': handleScanOutput,
  'POST /scan/tool':   handleScanTool,
  'POST /pii/redact':  handlePIIRedact,
  'GET /health':       handleHealth,
  'GET /score':        handleScore,
  'GET /patterns':     handlePatterns,
  'GET /stats':        handleStats
};

// =========================================================================
// Server
// =========================================================================

const server = http.createServer(async (req, res) => {
  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': options.cors,
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    });
    res.end();
    return;
  }

  // API key authentication
  if (options.apiKey) {
    const authHeader = req.headers['authorization'] || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
    if (token !== options.apiKey) {
      sendJSON(res, 401, { error: 'Unauthorized: invalid or missing API key' });
      logRequest(req.method, req.url, 401);
      return;
    }
  }

  // Rate limiting by IP
  const clientIP = req.socket.remoteAddress || 'unknown';
  if (isRateLimited(clientIP)) {
    sendJSON(res, 429, { error: 'Too many requests. Try again later.' });
    logRequest(req.method, req.url, 429);
    return;
  }

  const routeKey = `${req.method} ${req.url}`;
  const handler = routes[routeKey];

  if (handler) {
    try {
      await handler(req, res);
      logRequest(req.method, req.url, res.statusCode);
    } catch (err) {
      if (err.statusCode === 413) {
        sendJSON(res, 413, { error: 'Request body too large' });
        logRequest(req.method, req.url, 413);
      } else {
        console.error(`[Agent Shield Sidecar] Error handling ${routeKey}:`, err.message);
        sendJSON(res, 500, { error: 'Internal server error' });
        logRequest(req.method, req.url, 500);
      }
    }
  } else {
    sendJSON(res, 404, {
      error: 'Not found',
      available: Object.keys(routes)
    });
    logRequest(req.method, req.url, 404);
  }
});

// =========================================================================
// Graceful Shutdown
// =========================================================================

function shutdown(signal) {
  console.log(`\n[Agent Shield Sidecar] Received ${signal}, shutting down gracefully...`);
  server.close(() => {
    console.log('[Agent Shield Sidecar] Server closed.');
    process.exit(0);
  });

  // Force exit after 5 seconds if connections are hanging
  setTimeout(() => {
    console.warn('[Agent Shield Sidecar] Forcing shutdown after timeout.');
    process.exit(1);
  }, 5000);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

// =========================================================================
// Start
// =========================================================================

if (require.main === module) {
  server.listen(PORT, HOST, () => {
    console.log(`[Agent Shield Sidecar] Server running on http://${HOST}:${PORT}`);
    console.log('[Agent Shield Sidecar] Available endpoints:');
    for (const route of Object.keys(routes)) {
      console.log(`  ${route}`);
    }
    if (!options.apiKey) {
      console.log('[Agent Shield] WARNING: Sidecar running without API key authentication. Set apiKey option for production use.');
    }
  });
}

module.exports = { server, shield, options };
