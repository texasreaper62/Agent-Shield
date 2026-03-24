'use strict';

/**
 * Agent Shield - Visual HTML Security Report Generator
 *
 * Produces a Lighthouse-style HTML report from a SecurityAudit result.
 * Self-contained HTML with inline CSS and SVG. No external dependencies.
 *
 * Usage:
 *   const { SecurityAudit } = require('./audit');
 *   const { generateHTMLReport, generateReportFile } = require('./report-generator');
 *   const report = new SecurityAudit().run();
 *   generateReportFile(report, 'shield-report.html');
 *
 * @module report-generator
 */

const fs = require('fs');
const path = require('path');
const { getGrade } = require('./utils');

// =========================================================================
// Color helpers
// =========================================================================

/**
 * Get the gauge color based on score.
 * @param {number} score - 0-100
 * @returns {string} CSS color
 */
function getScoreColor(score) {
  if (score > 80) return '#0cce6b';
  if (score > 50) return '#ffa400';
  return '#ff4e42';
}

/**
 * Get the severity badge color.
 * @param {string} severity
 * @returns {string} CSS color
 */
function getSeverityColor(severity) {
  const map = {
    critical: '#ff4e42',
    high: '#ff6d3a',
    medium: '#ffa400',
    low: '#0cce6b',
  };
  return map[severity] || '#888';
}

/**
 * Get the severity background color (lighter).
 * @param {string} severity
 * @returns {string} CSS color
 */
function getSeverityBg(severity) {
  const map = {
    critical: 'rgba(255,78,66,0.15)',
    high: 'rgba(255,109,58,0.15)',
    medium: 'rgba(255,164,0,0.15)',
    low: 'rgba(12,206,107,0.15)',
  };
  return map[severity] || 'rgba(136,136,136,0.15)';
}

// =========================================================================
// SVG generators
// =========================================================================

/**
 * Generate a circular gauge SVG for the shield score.
 * @param {number} score - 0-100
 * @param {string} grade - Letter grade
 * @returns {string} SVG markup
 */
function renderGaugeSVG(score, grade) {
  const color = getScoreColor(score);
  const radius = 56;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  return `<svg class="gauge" width="160" height="160" viewBox="0 0 160 160">
  <circle cx="80" cy="80" r="${radius}" fill="none" stroke="#2a2a3e" stroke-width="10"/>
  <circle cx="80" cy="80" r="${radius}" fill="none" stroke="${color}" stroke-width="10"
    stroke-dasharray="${circumference}" stroke-dashoffset="${offset}"
    stroke-linecap="round" transform="rotate(-90 80 80)"
    style="transition: stroke-dashoffset 0.6s ease;"/>
  <text x="80" y="72" text-anchor="middle" fill="${color}" font-size="36" font-weight="700">${score}</text>
  <text x="80" y="94" text-anchor="middle" fill="#ccc" font-size="14" font-weight="500">${grade}</text>
</svg>`;
}

/**
 * Generate a horizontal bar chart SVG for category breakdown.
 * @param {object} categoryStats - { category: { detected, total, missed } }
 * @returns {string} SVG markup
 */
function renderCategoryBarsSVG(categoryStats) {
  const entries = Object.entries(categoryStats);
  const barHeight = 28;
  const labelWidth = 200;
  const barMaxWidth = 280;
  const rowHeight = 40;
  const svgHeight = entries.length * rowHeight + 20;

  let bars = '';
  entries.forEach(([cat, stats], i) => {
    const rate = stats.total > 0 ? stats.detected / stats.total : 0;
    const pct = Math.round(rate * 100);
    const barWidth = Math.max(2, rate * barMaxWidth);
    const color = getScoreColor(pct);
    const y = i * rowHeight + 16;
    const label = cat.replace(/_/g, ' ');

    bars += `
  <text x="0" y="${y + 18}" fill="#ccc" font-size="13" class="cat-label">${label}</text>
  <rect x="${labelWidth}" y="${y + 4}" width="${barMaxWidth}" height="${barHeight - 6}" rx="4" fill="#2a2a3e"/>
  <rect x="${labelWidth}" y="${y + 4}" width="${barWidth}" height="${barHeight - 6}" rx="4" fill="${color}"/>
  <text x="${labelWidth + barMaxWidth + 10}" y="${y + 18}" fill="#ccc" font-size="13" font-weight="600">${pct}%</text>
  <text x="${labelWidth + barMaxWidth + 52}" y="${y + 18}" fill="#888" font-size="11">(${stats.detected}/${stats.total})</text>`;
  });

  return `<svg class="category-bars" width="100%" viewBox="0 0 580 ${svgHeight}" preserveAspectRatio="xMinYMin meet">
  ${bars}
</svg>`;
}

// =========================================================================
// HTML sections
// =========================================================================

function renderSeverityDistribution(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    if (counts[f.severity] !== undefined) {
      counts[f.severity]++;
    }
  }

  const pills = Object.entries(counts).map(([sev, count]) => {
    return `<span class="pill" style="background:${getSeverityBg(sev)};color:${getSeverityColor(sev)};">
      ${sev.toUpperCase()} <strong>${count}</strong>
    </span>`;
  }).join('\n      ');

  return `<div class="severity-dist">${pills}</div>`;
}

function renderTopFindings(findings, limit = 15) {
  if (!findings || findings.length === 0) {
    return '<p class="no-findings">No missed attacks found. All attacks were detected.</p>';
  }

  const sorted = [...findings].sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    return (order[a.severity] || 4) - (order[b.severity] || 4);
  });

  const rows = sorted.slice(0, limit).map(f => {
    const escapedAttack = escapeHtml(f.attack);
    const escapedRec = escapeHtml(f.recommendation);
    return `<div class="finding">
      <div class="finding-header">
        <span class="badge" style="background:${getSeverityColor(f.severity)};">${f.severity.toUpperCase()}</span>
        <span class="finding-category">${f.category.replace(/_/g, ' ')}</span>
        <span class="finding-type">${f.type}</span>
      </div>
      <div class="finding-attack">${escapedAttack}</div>
      <div class="finding-rec">Fix: ${escapedRec}</div>
    </div>`;
  }).join('\n    ');

  const extra = findings.length > limit
    ? `<p class="more-findings">...and ${findings.length - limit} more findings</p>`
    : '';

  return rows + extra;
}

function escapeHtml(str) {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// =========================================================================
// Main HTML generator
// =========================================================================

/**
 * Generate a self-contained HTML security report.
 *
 * @param {object} auditReport - AuditReport instance from SecurityAudit.run()
 * @param {object} [options]
 * @param {string} [options.title] - Report title
 * @param {number} [options.maxFindings] - Maximum findings to show (default 15)
 * @returns {string} Complete HTML string
 */
function generateHTMLReport(auditReport, options = {}) {
  const title = options.title || 'Agent Shield Security Report';
  const maxFindings = options.maxFindings || 15;
  const score = auditReport.score || 0;
  const grade = auditReport.grade || getGrade(score);
  const detectionRate = auditReport.detectionRate != null
    ? auditReport.detectionRate.toFixed(1)
    : '0.0';
  const timestamp = new Date().toISOString();

  const gaugeColor = getScoreColor(score);

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${escapeHtml(title)}</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
    background: #1a1a2e;
    color: #e0e0e0;
    line-height: 1.6;
    min-height: 100vh;
  }

  .container {
    max-width: 900px;
    margin: 0 auto;
    padding: 24px 20px 48px;
  }

  /* Header */
  .report-header {
    text-align: center;
    padding: 32px 0 24px;
    border-bottom: 1px solid #2a2a3e;
    margin-bottom: 32px;
  }

  .report-header h1 {
    font-size: 24px;
    font-weight: 700;
    color: #fff;
    margin-bottom: 4px;
    letter-spacing: -0.3px;
  }

  .report-header .subtitle {
    font-size: 14px;
    color: #888;
  }

  /* Score hero */
  .score-hero {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 48px;
    padding: 32px 0;
    flex-wrap: wrap;
  }

  .gauge { display: block; }

  .score-details {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .score-stat {
    display: flex;
    align-items: baseline;
    gap: 10px;
  }

  .score-stat .label {
    font-size: 13px;
    color: #888;
    min-width: 120px;
  }

  .score-stat .value {
    font-size: 20px;
    font-weight: 700;
    color: #fff;
  }

  .score-stat .value.green { color: #0cce6b; }
  .score-stat .value.yellow { color: #ffa400; }
  .score-stat .value.red { color: #ff4e42; }

  /* Cards */
  .card {
    background: #16213e;
    border: 1px solid #2a2a3e;
    border-radius: 10px;
    padding: 24px;
    margin-bottom: 24px;
  }

  .card h2 {
    font-size: 16px;
    font-weight: 700;
    color: #fff;
    margin-bottom: 16px;
    padding-bottom: 10px;
    border-bottom: 1px solid #2a2a3e;
  }

  /* Category bars */
  .cat-label { text-transform: capitalize; }

  .category-bars { display: block; width: 100%; }

  /* Severity pills */
  .severity-dist {
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
  }

  .pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 6px 14px;
    border-radius: 20px;
    font-size: 13px;
    font-weight: 600;
    letter-spacing: 0.5px;
  }

  .pill strong {
    font-size: 18px;
    font-weight: 800;
  }

  /* Findings */
  .finding {
    padding: 14px 0;
    border-bottom: 1px solid #2a2a3e;
  }

  .finding:last-child { border-bottom: none; }

  .finding-header {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 6px;
  }

  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
    color: #fff;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .finding-category {
    font-size: 13px;
    color: #ccc;
    font-weight: 600;
    text-transform: capitalize;
  }

  .finding-type {
    font-size: 11px;
    color: #666;
    margin-left: auto;
  }

  .finding-attack {
    font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace;
    font-size: 12px;
    color: #aaa;
    background: #1a1a2e;
    padding: 6px 10px;
    border-radius: 4px;
    margin: 6px 0;
    word-break: break-word;
  }

  .finding-rec {
    font-size: 12px;
    color: #70a0ff;
  }

  .no-findings {
    color: #0cce6b;
    font-weight: 600;
    padding: 16px 0;
  }

  .more-findings {
    color: #888;
    font-size: 13px;
    padding-top: 12px;
  }

  /* Metadata */
  .meta-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 16px;
  }

  .meta-item {
    background: #1a1a2e;
    border-radius: 8px;
    padding: 14px;
  }

  .meta-item .meta-label {
    font-size: 11px;
    color: #888;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 4px;
  }

  .meta-item .meta-value {
    font-size: 18px;
    font-weight: 700;
    color: #fff;
  }

  /* Verdict */
  .verdict {
    text-align: center;
    padding: 20px;
    border-radius: 8px;
    font-size: 16px;
    font-weight: 700;
    margin-top: 8px;
  }

  .verdict.pass { background: rgba(12,206,107,0.1); color: #0cce6b; border: 1px solid rgba(12,206,107,0.3); }
  .verdict.warn { background: rgba(255,164,0,0.1); color: #ffa400; border: 1px solid rgba(255,164,0,0.3); }
  .verdict.fail { background: rgba(255,78,66,0.1); color: #ff4e42; border: 1px solid rgba(255,78,66,0.3); }

  /* Footer */
  .report-footer {
    text-align: center;
    padding: 24px 0 0;
    margin-top: 32px;
    border-top: 1px solid #2a2a3e;
    font-size: 12px;
    color: #666;
  }

  .report-footer strong { color: #888; }

  /* Responsive */
  @media (max-width: 640px) {
    .score-hero { flex-direction: column; gap: 24px; }
    .meta-grid { grid-template-columns: 1fr 1fr; }
    .severity-dist { flex-direction: column; align-items: flex-start; }
    .container { padding: 16px 12px 32px; }
  }

  /* Print */
  @media print {
    body { background: #fff; color: #222; }
    .container { max-width: 100%; padding: 0; }
    .card { background: #f9f9f9; border-color: #ddd; break-inside: avoid; }
    .report-header { border-color: #ddd; }
    .report-header h1 { color: #111; }
    .score-stat .value { color: #111; }
    .finding-attack { background: #f0f0f0; color: #333; }
    .finding-rec { color: #336; }
    .meta-item { background: #f0f0f0; }
    .meta-item .meta-value { color: #111; }
    .report-footer { border-color: #ddd; color: #999; }
    .cat-label { fill: #333 !important; }
    .pill { print-color-adjust: exact; -webkit-print-color-adjust: exact; }
    .badge { print-color-adjust: exact; -webkit-print-color-adjust: exact; }
  }
</style>
</head>
<body>
<div class="container">

  <div class="report-header">
    <h1>${escapeHtml(title)}</h1>
    <div class="subtitle">Pre-deployment security audit powered by Agent Shield</div>
  </div>

  <!-- Score Hero -->
  <div class="score-hero">
    ${renderGaugeSVG(score, grade)}
    <div class="score-details">
      <div class="score-stat">
        <span class="label">Shield Score</span>
        <span class="value" style="color:${gaugeColor}">${score}/100</span>
      </div>
      <div class="score-stat">
        <span class="label">Grade</span>
        <span class="value" style="color:${gaugeColor}">${grade}</span>
      </div>
      <div class="score-stat">
        <span class="label">Detection Rate</span>
        <span class="value" style="color:${gaugeColor}">${detectionRate}%</span>
      </div>
      <div class="score-stat">
        <span class="label">Attacks Tested</span>
        <span class="value">${auditReport.totalAttacks || 0}</span>
      </div>
    </div>
  </div>

  <!-- Category Breakdown -->
  <div class="card">
    <h2>Category Breakdown</h2>
    ${renderCategoryBarsSVG(auditReport.categoryStats || {})}
  </div>

  <!-- Severity Distribution -->
  <div class="card">
    <h2>Threat Severity Distribution</h2>
    ${renderSeverityDistribution(auditReport.findings || [])}
  </div>

  <!-- Top Findings -->
  <div class="card">
    <h2>Top Findings</h2>
    ${renderTopFindings(auditReport.findings || [], maxFindings)}
  </div>

  <!-- Scan Metadata -->
  <div class="card">
    <h2>Scan Metadata</h2>
    <div class="meta-grid">
      <div class="meta-item">
        <div class="meta-label">Scan Duration</div>
        <div class="meta-value">${auditReport.elapsed || 0}ms</div>
      </div>
      <div class="meta-item">
        <div class="meta-label">Total Attacks</div>
        <div class="meta-value">${auditReport.totalAttacks || 0}</div>
      </div>
      <div class="meta-item">
        <div class="meta-label">Detected</div>
        <div class="meta-value" style="color:#0cce6b">${auditReport.totalDetected || 0}</div>
      </div>
      <div class="meta-item">
        <div class="meta-label">Missed</div>
        <div class="meta-value" style="color:${(auditReport.totalMissed || 0) > 0 ? '#ff4e42' : '#0cce6b'}">${auditReport.totalMissed || 0}</div>
      </div>
      <div class="meta-item">
        <div class="meta-label">Categories</div>
        <div class="meta-value">${Object.keys(auditReport.categoryStats || {}).length}</div>
      </div>
      <div class="meta-item">
        <div class="meta-label">Sensitivity</div>
        <div class="meta-value">${auditReport.sensitivity || 'high'}</div>
      </div>
      <div class="meta-item">
        <div class="meta-label">Mutations</div>
        <div class="meta-value">${auditReport.includedMutations ? 'Yes' : 'No'}</div>
      </div>
      <div class="meta-item">
        <div class="meta-label">Patterns Checked</div>
        <div class="meta-value">${auditReport.totalAttacks || 0}</div>
      </div>
    </div>
  </div>

  <!-- Verdict -->
  <div class="card">
    <h2>Verdict</h2>
    ${renderVerdict(score)}
  </div>

  <div class="report-footer">
    Generated by <strong>Agent Shield</strong> on ${timestamp}
  </div>

</div>
</body>
</html>`;
}

/**
 * Render the verdict section.
 * @param {number} score
 * @returns {string}
 */
function renderVerdict(score) {
  if (score >= 95) {
    return '<div class="verdict pass">READY FOR PRODUCTION</div>';
  }
  if (score >= 80) {
    return '<div class="verdict warn">NEEDS IMPROVEMENT - address critical findings before deploying</div>';
  }
  if (score >= 60) {
    return '<div class="verdict fail">NOT READY - significant security gaps detected</div>';
  }
  return '<div class="verdict fail">CRITICAL RISK - do not deploy without major remediation</div>';
}

// =========================================================================
// File writer
// =========================================================================

/**
 * Generate an HTML report and write it to a file.
 *
 * @param {object} auditReport - AuditReport instance from SecurityAudit.run()
 * @param {string} outputPath - File path to write the HTML report to
 * @param {object} [options] - Options passed to generateHTMLReport
 * @returns {string} The absolute path of the written file
 */
function generateReportFile(auditReport, outputPath, options = {}) {
  const html = generateHTMLReport(auditReport, options);
  const resolved = path.resolve(outputPath);
  fs.writeFileSync(resolved, html, 'utf-8');
  console.log(`[Agent Shield] HTML report written to ${resolved}`);
  return resolved;
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
  generateHTMLReport,
  generateReportFile,
};
