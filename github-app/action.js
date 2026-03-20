'use strict';

/**
 * Agent Shield — GitHub Action Entry Point
 *
 * Reads PR diff from the GitHub event payload, scans for prompt injection
 * threats, and reports results using GitHub Actions annotations.
 *
 * Zero external dependencies. Uses GitHub Actions toolkit patterns
 * (::error, ::warning, ::set-output) via stdout.
 */

const fs = require('fs');
const path = require('path');
const { PRScanner } = require('./scanner');
const { GitHubClient } = require('./github-api');

// =========================================================================
// GITHUB ACTIONS HELPERS
// =========================================================================

/**
 * Set an action output value.
 * @param {string} name
 * @param {string} value
 */
function setOutput(name, value) {
  const outputFile = process.env.GITHUB_OUTPUT;
  if (outputFile) {
    fs.appendFileSync(outputFile, `${name}=${value}\n`);
  } else {
    // Fallback for older runners
    console.log(`::set-output name=${name}::${value}`);
  }
}

/**
 * Log an error annotation.
 * @param {string} message
 * @param {Object} [properties]
 */
function logError(message, properties = {}) {
  const props = formatProperties(properties);
  console.log(`::error ${props}::${escapeData(message)}`);
}

/**
 * Log a warning annotation.
 * @param {string} message
 * @param {Object} [properties]
 */
function logWarning(message, properties = {}) {
  const props = formatProperties(properties);
  console.log(`::warning ${props}::${escapeData(message)}`);
}

/**
 * Format annotation properties string.
 * @param {Object} properties
 * @returns {string}
 */
function formatProperties(properties) {
  const parts = [];
  if (properties.file) parts.push(`file=${properties.file}`);
  if (properties.line) parts.push(`line=${properties.line}`);
  if (properties.col) parts.push(`col=${properties.col}`);
  if (properties.endLine) parts.push(`endLine=${properties.endLine}`);
  if (properties.title) parts.push(`title=${properties.title}`);
  return parts.join(',');
}

/**
 * Escape data for GitHub Actions commands.
 * @param {string} str
 * @returns {string}
 */
function escapeData(str) {
  return String(str)
    .replace(/%/g, '%25')
    .replace(/\r/g, '%0D')
    .replace(/\n/g, '%0A');
}

// =========================================================================
// MAIN
// =========================================================================

async function main() {
  console.log('[Agent Shield] Starting PR scan...');

  // Read configuration from inputs (environment variables)
  const minSeverity = process.env.INPUT_MIN_SEVERITY || process.env['INPUT_MIN-SEVERITY'] || 'medium';
  const categories = process.env.INPUT_CATEGORIES
    ? process.env.INPUT_CATEGORIES.split(',').map(c => c.trim()).filter(Boolean)
    : [];
  const githubToken = process.env.INPUT_GITHUB_TOKEN || process.env['INPUT_GITHUB-TOKEN'] || process.env.GITHUB_TOKEN || '';
  const blocking = (process.env.INPUT_BLOCKING || 'true') !== 'false';

  // Read event payload
  const eventPath = process.env.GITHUB_EVENT_PATH;
  if (!eventPath) {
    console.error('[Agent Shield] GITHUB_EVENT_PATH not set. Not running in GitHub Actions?');
    process.exit(1);
  }

  let event;
  try {
    event = JSON.parse(fs.readFileSync(eventPath, 'utf8'));
  } catch (err) {
    console.error(`[Agent Shield] Failed to read event payload: ${err.message}`);
    process.exit(1);
  }

  // Extract PR information
  const pr = event.pull_request;
  if (!pr) {
    console.log('[Agent Shield] No pull_request in event payload. Skipping.');
    setOutput('threat-count', '0');
    setOutput('severity', 'none');
    setOutput('safe', 'true');
    process.exit(0);
  }

  const prNumber = pr.number;
  const repo = process.env.GITHUB_REPOSITORY || '';
  const [owner, repoName] = repo.split('/');

  console.log(`[Agent Shield] Scanning PR #${prNumber} on ${repo}`);

  // Fetch PR diff
  let diffText = '';
  if (githubToken && owner && repoName) {
    try {
      const client = new GitHubClient('', '');
      diffText = await client.getPullRequestDiff(owner, repoName, prNumber, githubToken);
    } catch (err) {
      console.error(`[Agent Shield] Failed to fetch PR diff: ${err.message}`);
      // Try reading diff from event if API call fails
    }
  }

  if (!diffText) {
    console.log('[Agent Shield] No diff available. Scanning PR body and title only.');
    diffText = '';
    // Create a minimal diff from PR title and body
    const syntheticLines = [];
    if (pr.title) syntheticLines.push(pr.title);
    if (pr.body) syntheticLines.push(pr.body);
    diffText = syntheticLines.join('\n');
  }

  // Parse and scan
  const scanner = new PRScanner({ minSeverity, categories });
  let results;

  if (diffText.includes('diff --git')) {
    // Real diff format
    const client = new GitHubClient('', '');
    const entries = client.parseDiff(diffText);
    results = scanner.scanDiff(entries);
  } else {
    // Synthetic content — scan as single "file"
    results = scanner.scanFile('pull-request', diffText);
  }

  // Report results
  const { threats, summary } = results;

  // Emit annotations
  for (const threat of threats) {
    const isError = threat.severity === 'critical' || threat.severity === 'high';
    const props = {
      file: threat.file,
      line: threat.line,
      title: `[Agent Shield] ${threat.category} (${threat.severity})`
    };

    if (isError) {
      logError(threat.pattern || threat.detail, props);
    } else {
      logWarning(threat.pattern || threat.detail, props);
    }
  }

  // Set outputs
  setOutput('threat-count', String(summary.totalThreats));
  setOutput('severity', summary.maxSeverity);
  setOutput('safe', String(summary.safe));

  // Print summary
  console.log('');
  console.log(scanner.formatSummary(results));
  console.log('');

  if (summary.safe) {
    console.log('[Agent Shield] PR is clean. No threats detected.');
  } else {
    console.log(`[Agent Shield] Found ${summary.totalThreats} threat(s). Max severity: ${summary.maxSeverity}`);

    if (blocking) {
      console.log('[Agent Shield] Blocking mode enabled. Failing the check.');
      process.exit(1);
    }
  }
}

main().catch(err => {
  console.error(`[Agent Shield] Fatal error: ${err.message}`);
  process.exit(1);
});
