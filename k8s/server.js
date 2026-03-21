'use strict';

/**
 * Agent Shield — Kubernetes Sidecar Server
 *
 * Zero-dependency HTTP server that exposes the Agent Shield detection engine
 * as a local service inside a Kubernetes pod. Other containers in the pod
 * call POST /scan or POST /scan-batch to check text for threats.
 *
 * Exposes Prometheus-format metrics on GET /metrics for observability.
 */

const http = require('http');
const path = require('path');

// ---------------------------------------------------------------------------
// Structured logging
// ---------------------------------------------------------------------------

const LOG_LEVELS = { debug: 0, info: 1, warn: 2, error: 3 };
const LOG_LEVEL = process.env.SHIELD_LOG_LEVEL || 'info';

/**
 * Emit a structured JSON log line to stdout.
 * @param {'debug'|'info'|'warn'|'error'} level
 * @param {string} message
 * @param {object} [extra]
 */
function log(level, message, extra) {
  if (LOG_LEVELS[level] < LOG_LEVELS[LOG_LEVEL]) return;
  const entry = {
    timestamp: new Date().toISOString(),
    level,
    component: 'agent-shield-sidecar',
    message,
    ...extra
  };
  process.stdout.write(JSON.stringify(entry) + '\n');
}

// ---------------------------------------------------------------------------
// Detection engine
// ---------------------------------------------------------------------------

let scanText;
try {
  // When bundled inside the Docker image the full engine is available
  const detectorCore = require(path.join(__dirname, 'src', 'detector-core.js'));
  scanText = detectorCore.scanText;
  log('info', 'Loaded detection engine from src/detector-core.js');
} catch (_err) {
  // Fallback: embedded minimal patterns so the sidecar works standalone
  scanText = embeddedScanText;
  log('info', 'Using embedded detection patterns (standalone mode)');
}

// ---------------------------------------------------------------------------
// Configuration (environment variables)
// ---------------------------------------------------------------------------

const PORT = parseInt(process.env.SHIELD_PORT || '8080', 10);
const MAX_BODY_BYTES = parseInt(process.env.SHIELD_MAX_BODY || '1048576', 10); // 1 MB
const MIN_SEVERITY = process.env.SHIELD_MIN_SEVERITY || 'medium';
const BLOCK_ON_THREAT = process.env.SHIELD_BLOCK_ON_THREAT === 'true';

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

const metrics = {
  scansTotal: 0,
  threatsDetected: 0,
  scanErrors: 0,
  scanDurationBuckets: { 0.005: 0, 0.01: 0, 0.025: 0, 0.05: 0, 0.1: 0, 0.25: 0, 0.5: 0, 1: 0, 2.5: 0, 5: 0, 10: 0, Infinity: 0 },
  scanDurationSum: 0,
  scanDurationCount: 0
};

/**
 * Record a scan duration into histogram buckets.
 * @param {number} durationSec
 */
function recordDuration(durationSec) {
  metrics.scanDurationSum += durationSec;
  metrics.scanDurationCount += 1;
  for (const bound of Object.keys(metrics.scanDurationBuckets)) {
    if (durationSec <= parseFloat(bound)) {
      metrics.scanDurationBuckets[bound] += 1;
    }
  }
}

/**
 * Render metrics in Prometheus exposition format.
 * @returns {string}
 */
function renderMetrics() {
  const lines = [];

  lines.push('# HELP agent_shield_scans_total Total number of scans processed.');
  lines.push('# TYPE agent_shield_scans_total counter');
  lines.push(`agent_shield_scans_total ${metrics.scansTotal}`);

  lines.push('# HELP agent_shield_threats_detected_total Total threats detected.');
  lines.push('# TYPE agent_shield_threats_detected_total counter');
  lines.push(`agent_shield_threats_detected_total ${metrics.threatsDetected}`);

  lines.push('# HELP agent_shield_scan_errors_total Total scan errors.');
  lines.push('# TYPE agent_shield_scan_errors_total counter');
  lines.push(`agent_shield_scan_errors_total ${metrics.scanErrors}`);

  lines.push('# HELP agent_shield_scan_duration_seconds Histogram of scan durations.');
  lines.push('# TYPE agent_shield_scan_duration_seconds histogram');
  let cumulative = 0;
  for (const [bound, count] of Object.entries(metrics.scanDurationBuckets)) {
    cumulative += count;
    const le = bound === 'Infinity' ? '+Inf' : bound;
    lines.push(`agent_shield_scan_duration_seconds_bucket{le="${le}"} ${cumulative}`);
  }
  lines.push(`agent_shield_scan_duration_seconds_sum ${metrics.scanDurationSum}`);
  lines.push(`agent_shield_scan_duration_seconds_count ${metrics.scanDurationCount}`);

  return lines.join('\n') + '\n';
}

// ---------------------------------------------------------------------------
// Embedded fallback scanner (standalone mode)
// ---------------------------------------------------------------------------

/**
 * Minimal scan function used when detector-core.js is not available.
 * Covers the most common prompt-injection patterns.
 * @param {string} text
 * @param {object} options
 * @returns {object}
 */
function embeddedScanText(text, options = {}) {
  const threats = [];
  if (typeof text !== 'string' || text.length === 0 || text.trim().length === 0) {
    return { status: 'safe', threats: [], stats: { totalThreats: 0, critical: 0, high: 0, medium: 0, low: 0, scanTimeMs: 0 }, timestamp: Date.now() };
  }

  const PATTERNS = [
    { regex: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|rules|guidelines|prompts|context|directions|directives|text|commands)/i, severity: 'high', category: 'instruction_override', description: 'Instruction override attempt.' },
    { regex: /disregard\s+(all\s+)?(previous|prior|above|earlier|your)\s+(instructions|rules|guidelines)/i, severity: 'high', category: 'instruction_override', description: 'Instruction disregard attempt.' },
    { regex: /you\s+are\s+now\s+(?:(?:a|an|the)\s+)?/i, severity: 'high', category: 'role_hijack', description: 'Role hijack attempt.' },
    { regex: /override\s+(?:all\s+)?(?:system|safety|security)\s+(?:settings|prompt|instructions)/i, severity: 'critical', category: 'instruction_override', description: 'System override attempt.' },
    { regex: /\b(?:DAN|D\.A\.N\.?)\s*(?:mode|prompt|jailbreak)/i, severity: 'critical', category: 'role_hijack', description: 'DAN jailbreak pattern.' },
    { regex: /(?:^|\n)\s*(?:SYSTEM|ADMIN|ROOT)\s*:\s*.{10,}/i, severity: 'high', category: 'prompt_injection', description: 'Fake system directive.' },
    { regex: /forget\s+(your|all|any|everything)\s+(training|instructions|rules|guidelines)/i, severity: 'high', category: 'instruction_override', description: 'Training override attempt.' },
    { regex: /(?:fetch|curl|wget|http:\/\/|https:\/\/)\s*[^\s]+\s*\|\s*/i, severity: 'high', category: 'data_exfiltration', description: 'Possible data exfiltration via piped fetch.' },
    { regex: /(?:act|behave|function|operate|respond)\s+as\s+(?:a|an)\s+unrestricted/i, severity: 'high', category: 'role_hijack', description: 'Unrestricted mode request.' },
    { regex: /pretend\s+(?:to\s+be|you\s+are)\s+(?:a|an)\s+(?:evil|unrestricted|unfiltered|uncensored)/i, severity: 'high', category: 'role_hijack', description: 'Evil persona pretense.' },
    { regex: /reveal\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions|rules)/i, severity: 'high', category: 'data_exfiltration', description: 'System prompt extraction attempt.' },
    { regex: /(?:cat|type|print|read|show|display)\s+(?:\/etc\/(?:passwd|shadow)|~\/\.(?:ssh|aws|env))/i, severity: 'critical', category: 'data_exfiltration', description: 'Sensitive file access attempt.' },
    { regex: /(?:do\s+anything\s+now|without\s+(?:any\s+)?restrictions|no\s+(?:ethical|moral)\s+(?:guidelines|limits))/i, severity: 'critical', category: 'role_hijack', description: 'Jailbreak constraint removal.' },
    { regex: /(?:rm\s+-rf|dd\s+if=|mkfs|format\s+[a-z]:)/i, severity: 'critical', category: 'tool_abuse', description: 'Destructive command attempt.' },
    { regex: /(?:send|post|upload|exfiltrate|transmit)\s+(?:this|the|all|my)\s+(?:data|info|content|conversation)/i, severity: 'high', category: 'data_exfiltration', description: 'Data exfiltration request.' }
  ];

  const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

  for (const p of PATTERNS) {
    if (p.regex.test(text)) {
      threats.push({ severity: p.severity, category: p.category, description: p.description });
    }
  }

  threats.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  const stats = { totalThreats: threats.length, critical: 0, high: 0, medium: 0, low: 0, scanTimeMs: 0 };
  for (const t of threats) stats[t.severity] = (stats[t.severity] || 0) + 1;

  let status = 'safe';
  if (stats.critical > 0) status = 'danger';
  else if (stats.high > 0) status = 'warning';
  else if (stats.medium > 0) status = 'caution';

  return { status, threats, stats, timestamp: Date.now() };
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

/**
 * Read the full request body with a size limit.
 * @param {http.IncomingMessage} req
 * @returns {Promise<string>}
 */
function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    let bytes = 0;
    req.on('data', (chunk) => {
      bytes += chunk.length;
      if (bytes > MAX_BODY_BYTES) {
        req.destroy();
        reject(new Error('Request body exceeds 1 MB limit'));
        return;
      }
      body += chunk;
    });
    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
}

/**
 * Send a JSON response.
 * @param {http.ServerResponse} res
 * @param {number} statusCode
 * @param {object} data
 */
function jsonResponse(res, statusCode, data) {
  const body = JSON.stringify(data);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body)
  });
  res.end(body);
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

const startTime = Date.now();

/**
 * POST /scan — scan a single text.
 */
async function handleScan(req, res) {
  const t0 = process.hrtime.bigint();
  try {
    const raw = await readBody(req);
    const { text, options } = JSON.parse(raw);

    if (typeof text !== 'string') {
      jsonResponse(res, 400, { error: 'Missing required field: text (string)' });
      return;
    }

    const result = scanText(text, { source: 'sidecar', ...options });

    const durationNs = Number(process.hrtime.bigint() - t0);
    const durationSec = durationNs / 1e9;
    recordDuration(durationSec);
    metrics.scansTotal += 1;
    metrics.threatsDetected += result.stats.totalThreats;

    log('info', 'Scan completed', {
      status: result.status,
      threats: result.stats.totalThreats,
      durationMs: Math.round(durationSec * 1000)
    });

    jsonResponse(res, 200, result);
  } catch (err) {
    metrics.scanErrors += 1;
    log('error', 'Scan failed', { error: err.message });
    jsonResponse(res, err.message.includes('1 MB') ? 413 : 400, { error: err.message });
  }
}

/**
 * POST /scan-batch — scan multiple texts.
 */
async function handleScanBatch(req, res) {
  const t0 = process.hrtime.bigint();
  try {
    const raw = await readBody(req);
    const { texts, options } = JSON.parse(raw);

    if (!Array.isArray(texts)) {
      jsonResponse(res, 400, { error: 'Missing required field: texts (string[])' });
      return;
    }

    const results = texts.map((text) => {
      if (typeof text !== 'string') {
        return { status: 'safe', threats: [], stats: { totalThreats: 0, critical: 0, high: 0, medium: 0, low: 0, scanTimeMs: 0 }, timestamp: Date.now() };
      }
      return scanText(text, { source: 'sidecar-batch', ...options });
    });

    const durationNs = Number(process.hrtime.bigint() - t0);
    const durationSec = durationNs / 1e9;
    recordDuration(durationSec);
    metrics.scansTotal += texts.length;
    for (const r of results) {
      metrics.threatsDetected += r.stats.totalThreats;
    }

    log('info', 'Batch scan completed', {
      count: texts.length,
      durationMs: Math.round(durationSec * 1000)
    });

    jsonResponse(res, 200, { results });
  } catch (err) {
    metrics.scanErrors += 1;
    log('error', 'Batch scan failed', { error: err.message });
    jsonResponse(res, err.message.includes('1 MB') ? 413 : 400, { error: err.message });
  }
}

/**
 * GET /health — liveness/readiness probe.
 */
function handleHealth(_req, res) {
  jsonResponse(res, 200, {
    status: 'ok',
    uptime: Math.round((Date.now() - startTime) / 1000),
    scans_total: metrics.scansTotal
  });
}

/**
 * GET /metrics — Prometheus exposition format.
 */
function handleMetrics(_req, res) {
  const body = renderMetrics();
  res.writeHead(200, {
    'Content-Type': 'text/plain; version=0.0.4; charset=utf-8',
    'Content-Length': Buffer.byteLength(body)
  });
  res.end(body);
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

const server = http.createServer((req, res) => {
  const { method, url } = req;

  if (method === 'POST' && url === '/scan') return handleScan(req, res);
  if (method === 'POST' && url === '/scan-batch') return handleScanBatch(req, res);
  if (method === 'GET' && url === '/health') return handleHealth(req, res);
  if (method === 'GET' && url === '/metrics') return handleMetrics(req, res);

  jsonResponse(res, 404, { error: 'Not found' });
});

server.listen(PORT, () => {
  log('info', `[Agent Shield] Sidecar listening on port ${PORT}`, {
    minSeverity: MIN_SEVERITY,
    blockOnThreat: BLOCK_ON_THREAT
  });
});

// ---------------------------------------------------------------------------
// Graceful shutdown
// ---------------------------------------------------------------------------

function shutdown(signal) {
  log('info', `Received ${signal}, shutting down gracefully`);
  server.close(() => {
    log('info', 'Server closed');
    process.exit(0);
  });
  // Force exit after 10 seconds
  setTimeout(() => {
    log('warn', 'Forced shutdown after timeout');
    process.exit(1);
  }, 10000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
