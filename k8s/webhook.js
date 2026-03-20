'use strict';

/**
 * Agent Shield — Kubernetes Admission Webhook Server
 *
 * MutatingAdmissionWebhook that auto-injects the Agent Shield sidecar
 * container into pods labelled with agent-shield.io/inject: "true".
 *
 * Generates a JSON Patch to add:
 *   1. A shared emptyDir volume for config
 *   2. An init container that writes shield config
 *   3. The agent-shield sidecar container
 *
 * Serves TLS using certificates mounted from a Kubernetes Secret.
 */

const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const TLS_CERT_PATH = process.env.TLS_CERT_PATH || '/certs/tls.crt';
const TLS_KEY_PATH = process.env.TLS_KEY_PATH || '/certs/tls.key';
const PORT = parseInt(process.env.WEBHOOK_PORT || '8443', 10);
const HEALTH_PORT = parseInt(process.env.HEALTH_PORT || '8081', 10);
const SIDECAR_IMAGE = process.env.SIDECAR_IMAGE || 'agent-shield:1.0.0';
const SIDECAR_PORT = parseInt(process.env.SIDECAR_PORT || '8080', 10);
const LOG_LEVEL = process.env.SHIELD_LOG_LEVEL || 'info';

// ---------------------------------------------------------------------------
// Structured logging
// ---------------------------------------------------------------------------

const LOG_LEVELS = { debug: 0, info: 1, warn: 2, error: 3 };

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
    component: 'agent-shield-webhook',
    message,
    ...extra
  };
  process.stdout.write(JSON.stringify(entry) + '\n');
}

// ---------------------------------------------------------------------------
// Sidecar injection patch
// ---------------------------------------------------------------------------

/**
 * Build the JSON Patch operations to inject the Agent Shield sidecar.
 * @param {object} pod - The pod spec from the admission review.
 * @returns {object[]} JSON Patch operations.
 */
function buildPatch(pod) {
  const patches = [];
  const spec = pod.spec || {};

  // Ensure volumes array exists
  if (!spec.volumes || spec.volumes.length === 0) {
    patches.push({ op: 'add', path: '/spec/volumes', value: [] });
  }

  // Add shared config volume
  patches.push({
    op: 'add',
    path: '/spec/volumes/-',
    value: {
      name: 'agent-shield-config',
      emptyDir: {}
    }
  });

  // Ensure initContainers array exists
  if (!spec.initContainers || spec.initContainers.length === 0) {
    patches.push({ op: 'add', path: '/spec/initContainers', value: [] });
  }

  // Add init container that writes default config
  patches.push({
    op: 'add',
    path: '/spec/initContainers/-',
    value: {
      name: 'agent-shield-init',
      image: SIDECAR_IMAGE,
      command: ['sh', '-c', 'echo \'{"minSeverity":"medium","blockOnThreat":false}\' > /shield-config/config.json'],
      volumeMounts: [
        {
          name: 'agent-shield-config',
          mountPath: '/shield-config'
        }
      ],
      resources: {
        limits: { cpu: '50m', memory: '32Mi' },
        requests: { cpu: '10m', memory: '16Mi' }
      }
    }
  });

  // Ensure containers array exists (should always exist)
  if (!spec.containers || spec.containers.length === 0) {
    patches.push({ op: 'add', path: '/spec/containers', value: [] });
  }

  // Add sidecar container
  patches.push({
    op: 'add',
    path: '/spec/containers/-',
    value: {
      name: 'agent-shield',
      image: SIDECAR_IMAGE,
      ports: [
        { containerPort: SIDECAR_PORT, name: 'shield-http', protocol: 'TCP' }
      ],
      env: [
        { name: 'SHIELD_PORT', value: String(SIDECAR_PORT) },
        { name: 'SHIELD_LOG_LEVEL', value: 'info' }
      ],
      volumeMounts: [
        {
          name: 'agent-shield-config',
          mountPath: '/shield-config',
          readOnly: true
        }
      ],
      livenessProbe: {
        httpGet: { path: '/health', port: SIDECAR_PORT },
        initialDelaySeconds: 5,
        periodSeconds: 15
      },
      readinessProbe: {
        httpGet: { path: '/health', port: SIDECAR_PORT },
        initialDelaySeconds: 3,
        periodSeconds: 10
      },
      resources: {
        limits: { cpu: '200m', memory: '128Mi' },
        requests: { cpu: '50m', memory: '64Mi' }
      },
      securityContext: {
        runAsNonRoot: true,
        readOnlyRootFilesystem: true,
        allowPrivilegeEscalation: false
      }
    }
  });

  return patches;
}

// ---------------------------------------------------------------------------
// Admission review handler
// ---------------------------------------------------------------------------

/**
 * Process an AdmissionReview request and return the response.
 * @param {object} admissionReview - Parsed AdmissionReview JSON.
 * @returns {object} AdmissionReview response.
 */
function handleAdmissionReview(admissionReview) {
  const request = admissionReview.request;
  const uid = request.uid;

  // Default: allow without modification
  const response = {
    apiVersion: 'admission.k8s.io/v1',
    kind: 'AdmissionReview',
    response: {
      uid,
      allowed: true
    }
  };

  try {
    const pod = request.object;
    const labels = (pod.metadata && pod.metadata.labels) || {};
    const annotations = (pod.metadata && pod.metadata.annotations) || {};

    // Check for injection label or annotation
    const shouldInject =
      labels['agent-shield.io/inject'] === 'true' ||
      annotations['agent-shield.io/inject'] === 'true';

    if (!shouldInject) {
      log('debug', 'Skipping pod — no injection label', { uid });
      return response;
    }

    // Check if sidecar is already injected
    const containers = (pod.spec && pod.spec.containers) || [];
    const alreadyInjected = containers.some(c => c.name === 'agent-shield');
    if (alreadyInjected) {
      log('info', 'Sidecar already present, skipping', { uid });
      return response;
    }

    const patches = buildPatch(pod);
    const patchBase64 = Buffer.from(JSON.stringify(patches)).toString('base64');

    response.response.patchType = 'JSONPatch';
    response.response.patch = patchBase64;

    log('info', 'Injecting Agent Shield sidecar', {
      uid,
      namespace: request.namespace,
      patchOps: patches.length
    });
  } catch (err) {
    log('error', 'Failed to process admission review', { uid, error: err.message });
    // Still allow the pod — don't block on webhook errors
  }

  return response;
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

/**
 * Read the full request body.
 * @param {http.IncomingMessage} req
 * @returns {Promise<string>}
 */
function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    let bytes = 0;
    const limit = 5 * 1024 * 1024; // 5 MB
    req.on('data', (chunk) => {
      bytes += chunk.length;
      if (bytes > limit) {
        req.destroy();
        reject(new Error('Request body too large'));
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
// TLS Webhook Server
// ---------------------------------------------------------------------------

/**
 * Handle incoming requests to the webhook server.
 */
async function requestHandler(req, res) {
  const { method, url } = req;

  if (method === 'POST' && url === '/mutate') {
    try {
      const raw = await readBody(req);
      const admissionReview = JSON.parse(raw);
      const result = handleAdmissionReview(admissionReview);
      jsonResponse(res, 200, result);
    } catch (err) {
      log('error', 'Webhook request failed', { error: err.message });
      jsonResponse(res, 400, { error: err.message });
    }
    return;
  }

  if (method === 'GET' && url === '/health') {
    jsonResponse(res, 200, { status: 'ok' });
    return;
  }

  jsonResponse(res, 404, { error: 'Not found' });
}

// Start TLS server if certs are available, otherwise plain HTTP (for dev)
let server;
try {
  const tlsOptions = {
    cert: fs.readFileSync(TLS_CERT_PATH),
    key: fs.readFileSync(TLS_KEY_PATH)
  };
  server = https.createServer(tlsOptions, requestHandler);
  log('info', 'TLS certificates loaded');
} catch (_err) {
  log('warn', 'TLS certificates not found, starting in plain HTTP mode (development only)');
  server = http.createServer(requestHandler);
}

server.listen(PORT, () => {
  log('info', `[Agent Shield] Webhook server listening on port ${PORT}`, {
    sidecarImage: SIDECAR_IMAGE,
    sidecarPort: SIDECAR_PORT
  });
});

// Health endpoint on separate port (plain HTTP for kubelet probes)
const healthServer = http.createServer((_req, res) => {
  jsonResponse(res, 200, { status: 'ok' });
});

healthServer.listen(HEALTH_PORT, () => {
  log('info', `Health endpoint listening on port ${HEALTH_PORT}`);
});

// ---------------------------------------------------------------------------
// Graceful shutdown
// ---------------------------------------------------------------------------

function shutdown(signal) {
  log('info', `Received ${signal}, shutting down gracefully`);
  server.close(() => {
    healthServer.close(() => {
      log('info', 'Servers closed');
      process.exit(0);
    });
  });
  setTimeout(() => {
    log('warn', 'Forced shutdown after timeout');
    process.exit(1);
  }, 10000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
