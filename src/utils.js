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

module.exports = {
  getGrade,
  getGradeLabel,
  makeBar,
  truncate,
  formatHeader,
  generateId
};
