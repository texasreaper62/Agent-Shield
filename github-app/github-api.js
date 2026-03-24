'use strict';

/**
 * Agent Shield — GitHub API Client
 *
 * Handles GitHub App authentication (JWT, installation tokens) and
 * API calls for PR diffs, check runs, and comments.
 *
 * Zero external dependencies. Uses Node.js built-in https and crypto.
 */

const https = require('https');
const crypto = require('crypto');

// =========================================================================
// HELPERS
// =========================================================================

/**
 * Base64url encode a buffer or string.
 * @param {Buffer|string} data
 * @returns {string}
 */
function base64url(data) {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
  return buf.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Make an HTTPS request. Returns a Promise.
 * @param {Object} options - https.request options
 * @param {string|Buffer|null} body - Request body
 * @returns {Promise<{statusCode: number, headers: Object, body: string}>}
 */
function httpsRequest(options, body) {
  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const responseBody = Buffer.concat(chunks).toString('utf8');
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: responseBody
        });
      });
    });

    req.on('error', reject);
    req.setTimeout(30000, () => {
      req.destroy(new Error('Request timeout'));
    });

    if (body) {
      req.write(body);
    }
    req.end();
  });
}

// =========================================================================
// GITHUB CLIENT CLASS
// =========================================================================

/**
 * GitHub API client for App authentication and REST calls.
 */
class GitHubClient {
  /**
   * @param {string} appId - GitHub App ID
   * @param {string} privateKey - PEM-encoded RSA private key
   */
  constructor(appId, privateKey) {
    this.appId = appId;
    this.privateKey = privateKey;
    this.apiHost = 'api.github.com';
    this.userAgent = 'AgentShield-GitHubApp/1.0';
  }

  /**
   * Generate a JSON Web Token for GitHub App authentication.
   * JWT is signed with RS256 and valid for 10 minutes.
   * @returns {string} Signed JWT
   */
  generateJWT() {
    const now = Math.floor(Date.now() / 1000);

    const header = {
      alg: 'RS256',
      typ: 'JWT'
    };

    const payload = {
      iat: now - 60,       // issued 60s ago to account for clock drift
      exp: now + (10 * 60), // expires in 10 minutes
      iss: this.appId
    };

    const segments = [
      base64url(JSON.stringify(header)),
      base64url(JSON.stringify(payload))
    ];

    const signingInput = segments.join('.');
    const sign = crypto.createSign('RSA-SHA256');
    sign.update(signingInput);
    const signature = sign.sign(this.privateKey);

    segments.push(base64url(signature));
    return segments.join('.');
  }

  /**
   * Exchange JWT for an installation access token.
   * @param {number|string} installationId
   * @returns {Promise<{token: string, expires_at: string}>}
   */
  async getInstallationToken(installationId) {
    const jwt = this.generateJWT();

    const response = await httpsRequest({
      hostname: this.apiHost,
      path: `/app/installations/${installationId}/access_tokens`,
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${jwt}`,
        'Accept': 'application/vnd.github+json',
        'User-Agent': this.userAgent,
        'X-GitHub-Api-Version': '2022-11-28'
      }
    }, '');

    if (response.statusCode !== 201) {
      throw new Error(`Failed to get installation token: ${response.statusCode} ${response.body}`);
    }

    return JSON.parse(response.body);
  }

  /**
   * Fetch a pull request diff.
   * @param {string} owner - Repository owner
   * @param {string} repo - Repository name
   * @param {number} pullNumber - PR number
   * @param {string} token - Installation access token
   * @returns {Promise<string>} Raw diff text
   */
  async getPullRequestDiff(owner, repo, pullNumber, token) {
    const response = await httpsRequest({
      hostname: this.apiHost,
      path: `/repos/${owner}/${repo}/pulls/${pullNumber}`,
      method: 'GET',
      headers: {
        'Authorization': `token ${token}`,
        'Accept': 'application/vnd.github.diff',
        'User-Agent': this.userAgent,
        'X-GitHub-Api-Version': '2022-11-28'
      }
    }, null);

    if (response.statusCode !== 200) {
      throw new Error(`Failed to get PR diff: ${response.statusCode} ${response.body}`);
    }

    return response.body;
  }

  /**
   * Create a check run on a commit.
   * @param {string} owner
   * @param {string} repo
   * @param {Object} data - Check run data (name, head_sha, status, etc.)
   * @param {string} token
   * @returns {Promise<Object>} Created check run
   */
  async createCheckRun(owner, repo, data, token) {
    const body = JSON.stringify(data);

    const response = await httpsRequest({
      hostname: this.apiHost,
      path: `/repos/${owner}/${repo}/check-runs`,
      method: 'POST',
      headers: {
        'Authorization': `token ${token}`,
        'Accept': 'application/vnd.github+json',
        'User-Agent': this.userAgent,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
        'X-GitHub-Api-Version': '2022-11-28'
      }
    }, body);

    if (response.statusCode !== 201) {
      throw new Error(`Failed to create check run: ${response.statusCode} ${response.body}`);
    }

    return JSON.parse(response.body);
  }

  /**
   * Update an existing check run.
   * @param {string} owner
   * @param {string} repo
   * @param {number} checkRunId
   * @param {Object} data - Update data (status, conclusion, output, etc.)
   * @param {string} token
   * @returns {Promise<Object>} Updated check run
   */
  async updateCheckRun(owner, repo, checkRunId, data, token) {
    const body = JSON.stringify(data);

    const response = await httpsRequest({
      hostname: this.apiHost,
      path: `/repos/${owner}/${repo}/check-runs/${checkRunId}`,
      method: 'PATCH',
      headers: {
        'Authorization': `token ${token}`,
        'Accept': 'application/vnd.github+json',
        'User-Agent': this.userAgent,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
        'X-GitHub-Api-Version': '2022-11-28'
      }
    }, body);

    if (response.statusCode !== 200) {
      throw new Error(`Failed to update check run: ${response.statusCode} ${response.body}`);
    }

    return JSON.parse(response.body);
  }

  /**
   * Add a comment to a pull request.
   * @param {string} owner
   * @param {string} repo
   * @param {number} pullNumber
   * @param {string} body - Comment body (markdown)
   * @param {string} token
   * @returns {Promise<Object>} Created comment
   */
  async addPRComment(owner, repo, pullNumber, body, token) {
    const reqBody = JSON.stringify({ body });

    const response = await httpsRequest({
      hostname: this.apiHost,
      path: `/repos/${owner}/${repo}/issues/${pullNumber}/comments`,
      method: 'POST',
      headers: {
        'Authorization': `token ${token}`,
        'Accept': 'application/vnd.github+json',
        'User-Agent': this.userAgent,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(reqBody),
        'X-GitHub-Api-Version': '2022-11-28'
      }
    }, reqBody);

    if (response.statusCode !== 201) {
      throw new Error(`Failed to add PR comment: ${response.statusCode} ${response.body}`);
    }

    return JSON.parse(response.body);
  }

  /**
   * Parse unified diff format into structured entries.
   * Only includes added lines (lines starting with +).
   * @param {string} diffText - Raw unified diff output
   * @returns {Array<{file: string, line: number, content: string}>}
   */
  parseDiff(diffText) {
    const entries = [];
    let currentFile = null;
    let lineNumber = 0;

    const lines = diffText.split('\n');

    for (const line of lines) {
      // Match diff file header: --- a/path or +++ b/path
      const fileMatch = line.match(/^\+\+\+\s+b\/(.+)/);
      if (fileMatch) {
        currentFile = fileMatch[1];
        continue;
      }

      // Match hunk header: @@ -oldStart,oldCount +newStart,newCount @@
      const hunkMatch = line.match(/^@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,\d+)?\s+@@/);
      if (hunkMatch) {
        lineNumber = parseInt(hunkMatch[1], 10);
        continue;
      }

      if (!currentFile) continue;

      // Added lines start with +
      if (line.startsWith('+') && !line.startsWith('+++')) {
        entries.push({
          file: currentFile,
          line: lineNumber,
          content: line.substring(1) // remove the leading +
        });
        lineNumber++;
      } else if (line.startsWith('-') && !line.startsWith('---')) {
        // Deleted lines — skip, don't increment new-file line number
        continue;
      } else if (!line.startsWith('\\')) {
        // Context line — increment line number
        lineNumber++;
      }
    }

    return entries;
  }
}

module.exports = { GitHubClient, base64url, httpsRequest };
