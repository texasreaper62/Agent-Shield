'use strict';

/**
 * Agent Shield — GitHub App Server
 *
 * HTTP server that receives GitHub webhook events (pull_request, check_suite),
 * scans PR diffs for prompt injection threats, and reports results via
 * GitHub Check Runs and PR comments.
 *
 * Zero external dependencies. Uses Node.js built-in http and crypto modules.
 *
 * Environment variables:
 *   GITHUB_APP_ID         — GitHub App ID
 *   GITHUB_PRIVATE_KEY    — PEM-encoded RSA private key (or path to .pem file)
 *   GITHUB_WEBHOOK_SECRET — Webhook secret for signature verification
 *   PORT                  — Server port (default: 3000)
 *   MIN_SEVERITY          — Minimum severity to report (default: medium)
 */

const http = require('http');
const crypto = require('crypto');
const { GitHubClient } = require('./github-api');
const { PRScanner } = require('./scanner');

// =========================================================================
// CONFIGURATION
// =========================================================================

const PORT = parseInt(process.env.PORT, 10) || 3000;
const APP_ID = process.env.GITHUB_APP_ID || '';
const PRIVATE_KEY = process.env.GITHUB_PRIVATE_KEY || '';
const WEBHOOK_SECRET = process.env.GITHUB_WEBHOOK_SECRET || '';
const MIN_SEVERITY = process.env.MIN_SEVERITY || 'medium';

// =========================================================================
// HELPERS
// =========================================================================

/**
 * Read the full request body as a string.
 * @param {http.IncomingMessage} req
 * @returns {Promise<string>}
 */
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

/**
 * Verify GitHub webhook signature (HMAC SHA-256).
 * @param {string} payload - Raw request body
 * @param {string} signature - Value of X-Hub-Signature-256 header
 * @param {string} secret - Webhook secret
 * @returns {boolean}
 */
function verifySignature(payload, signature, secret) {
  if (!signature || !secret) return false;

  const expected = 'sha256=' + crypto
    .createHmac('sha256', secret)
    .update(payload, 'utf8')
    .digest('hex');

  try {
    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expected)
    );
  } catch {
    return false;
  }
}

/**
 * Send a JSON response.
 * @param {http.ServerResponse} res
 * @param {number} statusCode
 * @param {Object} data
 */
function sendJSON(res, statusCode, data) {
  const body = JSON.stringify(data);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body)
  });
  res.end(body);
}

// =========================================================================
// PR SCANNING LOGIC
// =========================================================================

/**
 * Scan a pull request for prompt injection threats.
 * Creates a Check Run and optionally a PR comment.
 * @param {Object} payload - Webhook event payload
 */
async function handlePullRequest(payload) {
  const pr = payload.pull_request;
  const repo = payload.repository;
  const installationId = payload.installation.id;
  const owner = repo.owner.login;
  const repoName = repo.name;
  const headSha = pr.head.sha;
  const pullNumber = pr.number;

  console.log(`[Agent Shield] Scanning PR #${pullNumber} on ${owner}/${repoName}`);

  const client = new GitHubClient(APP_ID, PRIVATE_KEY);
  const scanner = new PRScanner({ minSeverity: MIN_SEVERITY });

  // Get installation token
  const { token } = await client.getInstallationToken(installationId);

  // Create in-progress check run
  const checkRun = await client.createCheckRun(owner, repoName, {
    name: 'Agent Shield — Prompt Injection Scan',
    head_sha: headSha,
    status: 'in_progress',
    started_at: new Date().toISOString()
  }, token);

  try {
    // Fetch PR diff
    const diff = await client.getPullRequestDiff(owner, repoName, pullNumber, token);
    const diffEntries = client.parseDiff(diff);

    // Scan for threats
    const results = scanner.scanDiff(diffEntries);

    // GitHub limits annotations to 50 per API call
    const annotationBatches = [];
    for (let i = 0; i < results.annotations.length; i += 50) {
      annotationBatches.push(results.annotations.slice(i, i + 50));
    }

    const conclusion = results.summary.safe ? 'success' : 'failure';
    const title = results.summary.safe
      ? 'No threats detected'
      : `${results.summary.totalThreats} threat(s) found (max: ${results.summary.maxSeverity})`;

    // Update check run with first batch of annotations
    await client.updateCheckRun(owner, repoName, checkRun.id, {
      status: 'completed',
      conclusion,
      completed_at: new Date().toISOString(),
      output: {
        title,
        summary: scanner.formatSummary(results),
        annotations: annotationBatches[0] || []
      }
    }, token);

    // Send additional annotation batches if needed
    for (let i = 1; i < annotationBatches.length; i++) {
      await client.updateCheckRun(owner, repoName, checkRun.id, {
        output: {
          title,
          summary: scanner.formatSummary(results),
          annotations: annotationBatches[i]
        }
      }, token);
    }

    // Add PR comment if threats were found
    if (!results.summary.safe) {
      const comment = scanner.formatSummary(results);
      await client.addPRComment(owner, repoName, pullNumber, comment, token);
    }

    console.log(`[Agent Shield] PR #${pullNumber}: ${title}`);
  } catch (err) {
    console.error(`[Agent Shield] Error scanning PR #${pullNumber}:`, err.message);

    // Mark check run as failed with error
    await client.updateCheckRun(owner, repoName, checkRun.id, {
      status: 'completed',
      conclusion: 'failure',
      completed_at: new Date().toISOString(),
      output: {
        title: 'Scan Error',
        summary: `Agent Shield encountered an error while scanning: ${err.message}`
      }
    }, token).catch(() => {});
  }
}

/**
 * Handle check_suite.requested events.
 * Re-scans all open PRs associated with the check suite.
 * @param {Object} payload
 */
async function handleCheckSuite(payload) {
  const checkSuite = payload.check_suite;
  const repo = payload.repository;
  const installationId = payload.installation.id;
  const owner = repo.owner.login;
  const repoName = repo.name;

  console.log(`[Agent Shield] Check suite requested on ${owner}/${repoName}`);

  // Check suite contains associated pull requests
  const pullRequests = checkSuite.pull_requests || [];
  if (pullRequests.length === 0) {
    console.log('[Agent Shield] No associated PRs, skipping.');
    return;
  }

  for (const pr of pullRequests) {
    // Build a synthetic payload for handlePullRequest
    await handlePullRequest({
      pull_request: {
        number: pr.number,
        head: { sha: checkSuite.head_sha }
      },
      repository: payload.repository,
      installation: payload.installation
    });
  }
}

// =========================================================================
// HTTP SERVER
// =========================================================================

const server = http.createServer(async (req, res) => {
  // Health check
  if (req.method === 'GET' && req.url === '/health') {
    sendJSON(res, 200, {
      status: 'ok',
      app: 'agent-shield-github-app',
      timestamp: new Date().toISOString()
    });
    return;
  }

  // Webhook endpoint
  if (req.method === 'POST' && req.url === '/webhook') {
    try {
      const body = await readBody(req);

      // Verify webhook signature
      const signature = req.headers['x-hub-signature-256'] || '';
      if (WEBHOOK_SECRET && !verifySignature(body, signature, WEBHOOK_SECRET)) {
        console.log('[Agent Shield] Webhook signature verification failed');
        sendJSON(res, 401, { error: 'Invalid signature' });
        return;
      }

      const event = req.headers['x-github-event'] || '';
      const payload = JSON.parse(body);

      console.log(`[Agent Shield] Received event: ${event} (action: ${payload.action || 'n/a'})`);

      // Respond immediately — process asynchronously
      sendJSON(res, 200, { received: true, event });

      // Handle events
      if (event === 'pull_request' &&
          (payload.action === 'opened' || payload.action === 'synchronize')) {
        handlePullRequest(payload).catch(err => {
          console.error('[Agent Shield] PR handler error:', err.message);
        });
      } else if (event === 'check_suite' && payload.action === 'requested') {
        handleCheckSuite(payload).catch(err => {
          console.error('[Agent Shield] Check suite handler error:', err.message);
        });
      }
    } catch (err) {
      console.error('[Agent Shield] Webhook error:', err.message);
      sendJSON(res, 400, { error: 'Invalid request' });
    }
    return;
  }

  // 404 for everything else
  sendJSON(res, 404, { error: 'Not found' });
});

// Start server
server.listen(PORT, () => {
  console.log(`[Agent Shield] GitHub App server running on port ${PORT}`);
  console.log(`[Agent Shield] Webhook endpoint: POST /webhook`);
  console.log(`[Agent Shield] Health check:     GET  /health`);
  if (!APP_ID) console.warn('[Agent Shield] WARNING: GITHUB_APP_ID not set');
  if (!PRIVATE_KEY) console.warn('[Agent Shield] WARNING: GITHUB_PRIVATE_KEY not set');
  if (!WEBHOOK_SECRET) console.warn('[Agent Shield] WARNING: GITHUB_WEBHOOK_SECRET not set');
});

module.exports = { server, verifySignature, handlePullRequest, handleCheckSuite };
