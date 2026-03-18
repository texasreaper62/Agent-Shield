'use strict';

/**
 * Agent Shield — Integration Badges & GitHub Action Support
 *
 * Generate SVG badges for READMEs and CI/CD pipelines.
 */

// =========================================================================
// Badge Generator
// =========================================================================

class BadgeGenerator {
  /**
   * Generate a Shield Score badge in SVG.
   */
  static shieldScore(score) {
    const color = score >= 90 ? '22c55e' : score >= 70 ? 'eab308' : score >= 50 ? 'f97316' : 'ef4444';
    const grade = score >= 95 ? 'A+' : score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 50 ? 'D' : 'F';
    return BadgeGenerator.generateSVG('shield score', `${score} (${grade})`, color);
  }

  /**
   * Generate a protection status badge.
   */
  static protectionStatus(enabled = true) {
    return BadgeGenerator.generateSVG(
      'agent shield',
      enabled ? 'protected' : 'unprotected',
      enabled ? '3b82f6' : 'ef4444'
    );
  }

  /**
   * Generate a detection rate badge.
   */
  static detectionRate(rate) {
    const num = parseFloat(rate);
    const color = num >= 90 ? '22c55e' : num >= 70 ? 'eab308' : 'ef4444';
    return BadgeGenerator.generateSVG('detection rate', `${num}%`, color);
  }

  /**
   * Generate a scan count badge.
   */
  static scanCount(count) {
    return BadgeGenerator.generateSVG('scans', count.toLocaleString(), '06b6d4');
  }

  /**
   * Generate a compliance badge.
   */
  static compliance(framework, rate) {
    const num = parseFloat(rate);
    const color = num >= 80 ? '22c55e' : num >= 50 ? 'eab308' : 'ef4444';
    return BadgeGenerator.generateSVG(framework, `${num}%`, color);
  }

  /**
   * Generate a custom badge.
   */
  static custom(label, value, color = '3b82f6') {
    return BadgeGenerator.generateSVG(label, value, color);
  }

  /**
   * Generate Markdown badge links for README.
   */
  static markdownBadges(options = {}) {
    const lines = [];

    if (options.score !== undefined) {
      const color = options.score >= 90 ? 'brightgreen' : options.score >= 70 ? 'yellow' : options.score >= 50 ? 'orange' : 'red';
      lines.push(`![Shield Score](https://img.shields.io/badge/shield_score-${options.score}-${color}?style=flat-square&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0id2hpdGUiPjxwYXRoIGQ9Ik0xMiAyMnM4LTQgOC0xMFY1bC04LTMtOCAzdjdjMCA2IDggMTAgOCAxMHoiLz48L3N2Zz4=)`);
    }

    lines.push(`![Agent Shield](https://img.shields.io/badge/protected_by-agent_shield-blue?style=flat-square)`);

    if (options.detectionRate) {
      const color = parseFloat(options.detectionRate) >= 90 ? 'brightgreen' : 'yellow';
      lines.push(`![Detection Rate](https://img.shields.io/badge/detection_rate-${options.detectionRate}%25-${color}?style=flat-square)`);
    }

    return lines.join('\n');
  }

  /**
   * Core SVG badge generator.
   */
  static generateSVG(label, value, color) {
    const labelWidth = label.length * 7 + 12;
    const valueWidth = String(value).length * 7 + 12;
    const totalWidth = labelWidth + valueWidth;

    return `<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="20" role="img">
  <title>${label}: ${value}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r"><rect width="${totalWidth}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="${labelWidth}" height="20" fill="#555"/>
    <rect x="${labelWidth}" width="${valueWidth}" height="20" fill="#${color}"/>
    <rect width="${totalWidth}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="11">
    <text x="${labelWidth / 2}" y="14" fill="#010101" fill-opacity=".3">${label}</text>
    <text x="${labelWidth / 2}" y="13">${label}</text>
    <text x="${labelWidth + valueWidth / 2}" y="14" fill="#010101" fill-opacity=".3">${value}</text>
    <text x="${labelWidth + valueWidth / 2}" y="13">${value}</text>
  </g>
</svg>`;
  }
}

// =========================================================================
// GitHub Action Output
// =========================================================================

class GitHubActionReporter {
  constructor() {
    this.annotations = [];
  }

  /**
   * Report scan results as GitHub Action annotations.
   */
  reportScan(result, file = '', line = 0) {
    if (!result.threats || result.threats.length === 0) return;

    for (const threat of result.threats) {
      const level = threat.severity === 'critical' || threat.severity === 'high' ? 'error' : 'warning';
      const msg = `[Agent Shield] ${threat.description} (${threat.severity})`;

      // GitHub Actions annotation format
      if (file) {
        console.log(`::${level} file=${file},line=${line}::${msg}`);
      } else {
        console.log(`::${level}::${msg}`);
      }

      this.annotations.push({ level, file, line, message: msg });
    }
  }

  /**
   * Set GitHub Action output variables.
   */
  setOutputs(results) {
    const total = results.threats ? results.threats.length : 0;
    const blocked = results.blocked || false;
    const status = results.status || 'unknown';

    console.log(`::set-output name=threat_count::${total}`);
    console.log(`::set-output name=status::${status}`);
    console.log(`::set-output name=blocked::${blocked}`);
  }

  /**
   * Create a summary for GitHub Actions.
   */
  createSummary(shieldScore, scanResults) {
    const lines = [];
    lines.push('## Agent Shield Scan Results\n');
    lines.push(`| Metric | Value |`);
    lines.push(`|--------|-------|`);

    if (shieldScore) {
      lines.push(`| Shield Score | ${shieldScore.score}/100 (${shieldScore.grade}) |`);
    }

    if (scanResults) {
      lines.push(`| Status | ${scanResults.status} |`);
      lines.push(`| Threats | ${scanResults.threats ? scanResults.threats.length : 0} |`);
      lines.push(`| Blocked | ${scanResults.blocked ? 'Yes' : 'No'} |`);
    }

    lines.push('');
    return lines.join('\n');
  }
}

module.exports = {
  BadgeGenerator,
  GitHubActionReporter
};
