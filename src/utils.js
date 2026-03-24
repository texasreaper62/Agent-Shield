'use strict';

/**
 * Agent Shield — Shared Utilities
 *
 * Common helpers used across multiple modules to avoid duplication.
 */

/**
 * Calculate a letter grade from a numeric score (0-100).
 */
function getGrade(score) {
  if (score >= 95) return 'A+';
  if (score >= 90) return 'A';
  if (score >= 85) return 'A-';
  if (score >= 80) return 'B+';
  if (score >= 75) return 'B';
  if (score >= 70) return 'B-';
  if (score >= 65) return 'C+';
  if (score >= 60) return 'C';
  if (score >= 55) return 'C-';
  if (score >= 50) return 'D';
  return 'F';
}

/**
 * Get a human-readable grade label.
 */
function getGradeLabel(score) {
  if (score >= 95) return 'A+ — Excellent';
  if (score >= 90) return 'A — Strong';
  if (score >= 80) return 'B — Good';
  if (score >= 70) return 'C — Moderate';
  if (score >= 60) return 'D — Weak';
  return 'F — Critical gaps';
}

/**
 * Render a progress bar using block characters.
 */
function makeBar(filled, total, width) {
  const ratio = total > 0 ? filled / total : 0;
  const filledCount = Math.round(ratio * width);
  return '█'.repeat(filledCount) + '░'.repeat(width - filledCount);
}

/**
 * Truncate text to a maximum length with an optional suffix.
 */
function truncate(text, maxLength = 200, suffix = '') {
  if (!text || text.length <= maxLength) return text || '';
  return text.substring(0, maxLength) + suffix;
}

/**
 * Format a boxed console header.
 */
function formatHeader(title, width = 54) {
  const padded = title.length < width - 4
    ? ' '.repeat(Math.floor((width - 2 - title.length) / 2)) + title + ' '.repeat(Math.ceil((width - 2 - title.length) / 2))
    : title;
  return [
    '╔' + '═'.repeat(width) + '╗',
    '║' + padded + '║',
    '╚' + '═'.repeat(width) + '╝'
  ].join('\n');
}

/**
 * Generate a unique event ID.
 */
function generateId(prefix = 'evt') {
  return `${prefix}_${Date.now()}_${Math.random().toString(36).slice(2, 8).padEnd(6, '0')}`;
}

/**
 * Graceful shutdown helper with drain handling and timeout enforcement.
 * Runs cleanup functions with a hard deadline to prevent hanging.
 *
 * @param {object} [options]
 * @param {number} [options.timeoutMs=10000] - Maximum time to wait for cleanup before forced exit.
 * @param {Function[]} [options.cleanupFns] - Array of cleanup functions (sync or async).
 * @param {Function} [options.logger] - Log function (defaults to console.error).
 * @returns {{ shutdown: Function, onShutdown: Function }}
 */
function createGracefulShutdown(options = {}) {
  const timeoutMs = options.timeoutMs || 10000;
  const cleanupFns = options.cleanupFns || [];
  const logger = options.logger || console.error;
  let shuttingDown = false;

  /**
   * Register an additional cleanup function.
   * @param {Function} fn
   */
  function onShutdown(fn) {
    if (typeof fn === 'function') cleanupFns.push(fn);
  }

  /**
   * Execute shutdown sequence with timeout enforcement.
   * @param {string} [signal] - Signal that triggered shutdown.
   * @returns {Promise<void>}
   */
  async function shutdown(signal) {
    if (shuttingDown) return;
    shuttingDown = true;
    logger(`[Agent Shield] Shutdown initiated (${signal || 'manual'}), timeout: ${timeoutMs}ms`);

    const forceTimer = setTimeout(() => {
      logger('[Agent Shield] Shutdown timeout exceeded, forcing exit');
      process.exit(1);
    }, timeoutMs);
    // Do not keep process alive just for the force timer
    if (forceTimer.unref) forceTimer.unref();

    for (const fn of cleanupFns) {
      try {
        const result = fn();
        if (result && typeof result.then === 'function') {
          await result;
        }
      } catch (err) {
        logger(`[Agent Shield] Cleanup error: ${err.message}`);
      }
    }

    clearTimeout(forceTimer);
    logger('[Agent Shield] Shutdown complete');
  }

  return { shutdown, onShutdown };
}

/**
 * Load environment variables from a .env file into process.env.
 * Zero-dependency alternative to the dotenv package.
 * Does not overwrite existing env vars unless overwrite is true.
 *
 * @param {object} [options]
 * @param {string} [options.path] - Path to the .env file (defaults to cwd/.env).
 * @param {boolean} [options.overwrite=false] - Whether to overwrite existing vars.
 * @returns {{ loaded: number, errors: string[] }}
 */
function loadEnvFile(options = {}) {
  const fs = require('fs');
  const pathMod = require('path');
  const envPath = options.path || pathMod.resolve(process.cwd(), '.env');
  const overwrite = options.overwrite === true;
  const result = { loaded: 0, errors: [] };

  let content;
  try {
    content = fs.readFileSync(envPath, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') return result; // No .env file, not an error
    result.errors.push(`Failed to read ${envPath}: ${err.message}`);
    return result;
  }

  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    // Skip empty lines and comments
    if (!line || line.startsWith('#')) continue;

    const eqIndex = line.indexOf('=');
    if (eqIndex === -1) continue;

    const key = line.substring(0, eqIndex).trim();
    let value = line.substring(eqIndex + 1).trim();

    // Strip surrounding quotes (single or double)
    if ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }

    if (!key) continue;

    if (overwrite || process.env[key] === undefined) {
      process.env[key] = value;
      result.loaded++;
    }
  }

  return result;
}

module.exports = {
  getGrade,
  getGradeLabel,
  makeBar,
  truncate,
  formatHeader,
  generateId,
  createGracefulShutdown,
  loadEnvFile
};
