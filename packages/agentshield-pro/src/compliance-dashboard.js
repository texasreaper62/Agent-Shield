'use strict';

/**
 * Agent Shield Pro — Enterprise Compliance Dashboard
 *
 * Unified compliance posture view across all frameworks:
 * - OWASP LLM Top 10, EU AI Act, SOC 2, NIST AI RMF, HIPAA, GDPR
 * - Real-time compliance scoring
 * - Control gap analysis
 * - Remediation recommendations
 * - HTML export for stakeholder reporting
 *
 * Enterprise tier only.
 *
 * @module compliance-dashboard
 */

// =========================================================================
// Compliance Frameworks (extended for Enterprise)
// =========================================================================

const FRAMEWORKS = {
  owasp_llm: {
    name: 'OWASP LLM Top 10',
    version: '2025',
    controls: [
      { id: 'LLM01', name: 'Prompt Injection', check: 'injection_scanning', remediation: 'Enable detector-core with high sensitivity' },
      { id: 'LLM02', name: 'Insecure Output Handling', check: 'output_scanning', remediation: 'Enable output scanning in middleware' },
      { id: 'LLM03', name: 'Training Data Poisoning', check: 'data_validation', remediation: 'Validate training data with model-finetuning pipeline' },
      { id: 'LLM04', name: 'Model Denial of Service', check: 'rate_limiting', remediation: 'Enable circuit-breaker module' },
      { id: 'LLM05', name: 'Supply Chain Vulnerabilities', check: 'supply_chain', remediation: 'Enable supply-chain verification' },
      { id: 'LLM06', name: 'Sensitive Information Disclosure', check: 'pii_protection', remediation: 'Enable PII redaction module' },
      { id: 'LLM07', name: 'Insecure Plugin Design', check: 'tool_permissions', remediation: 'Enable tool-guard with allowlists' },
      { id: 'LLM08', name: 'Excessive Agency', check: 'permission_boundaries', remediation: 'Configure permission boundaries in tool-guard' },
      { id: 'LLM09', name: 'Overreliance', check: 'output_validation', remediation: 'Enable output watermarking and validation' },
      { id: 'LLM10', name: 'Model Theft', check: 'access_control', remediation: 'Enable canary tokens and access controls' },
    ],
  },

  eu_ai_act: {
    name: 'EU AI Act',
    version: '2024',
    controls: [
      { id: 'AIA-1', name: 'Risk Assessment', check: 'risk_assessment', remediation: 'Run shield-score benchmark and document results' },
      { id: 'AIA-2', name: 'Transparency', check: 'logging', remediation: 'Enable structured logging in policy module' },
      { id: 'AIA-3', name: 'Human Oversight', check: 'human_in_loop', remediation: 'Implement approval workflows for critical actions' },
      { id: 'AIA-4', name: 'Data Governance', check: 'pii_protection', remediation: 'Enable PII detection and DLP' },
      { id: 'AIA-5', name: 'Technical Documentation', check: 'documentation', remediation: 'Generate and maintain system documentation' },
      { id: 'AIA-6', name: 'Record Keeping', check: 'audit_trail', remediation: 'Enable audit trail with immutable logging' },
      { id: 'AIA-7', name: 'Accuracy & Robustness', check: 'accuracy_testing', remediation: 'Run adversarial self-training and red team' },
    ],
  },

  soc2: {
    name: 'SOC 2 (AI Controls)',
    version: '2024',
    controls: [
      { id: 'SOC2-CC6.1', name: 'Logical Access', check: 'access_control', remediation: 'Enable SSO integration and RBAC' },
      { id: 'SOC2-CC6.3', name: 'Authorization', check: 'permission_boundaries', remediation: 'Configure tool permission boundaries' },
      { id: 'SOC2-CC7.1', name: 'Detection', check: 'injection_scanning', remediation: 'Enable injection scanning at all entry points' },
      { id: 'SOC2-CC7.2', name: 'Monitoring', check: 'logging', remediation: 'Enable structured logging and alerting' },
      { id: 'SOC2-CC8.1', name: 'Change Management', check: 'supply_chain', remediation: 'Enable supply chain verification' },
      { id: 'SOC2-P3.1', name: 'Privacy Notice', check: 'pii_protection', remediation: 'Enable PII detection and redaction' },
    ],
  },

  nist_ai: {
    name: 'NIST AI RMF',
    version: '1.0',
    controls: [
      { id: 'GOVERN-1', name: 'AI Risk Culture', check: 'documentation', remediation: 'Document AI risk management procedures' },
      { id: 'MAP-1', name: 'Context Mapping', check: 'risk_assessment', remediation: 'Map AI system context with shield-score' },
      { id: 'MEASURE-1', name: 'Risk Measurement', check: 'accuracy_testing', remediation: 'Run benchmark suite and self-training' },
      { id: 'MANAGE-1', name: 'Risk Treatment', check: 'injection_scanning', remediation: 'Enable detection engine with adaptive thresholds' },
      { id: 'MANAGE-2', name: 'Incident Response', check: 'incident_response', remediation: 'Configure incident playbooks in compliance module' },
    ],
  },

  hipaa: {
    name: 'HIPAA (AI Processing)',
    version: '2024',
    controls: [
      { id: 'HIPAA-164.312a', name: 'Access Control', check: 'access_control', remediation: 'Enable SSO with identity mapping' },
      { id: 'HIPAA-164.312b', name: 'Audit Controls', check: 'audit_trail', remediation: 'Enable immutable audit logging' },
      { id: 'HIPAA-164.312c', name: 'Integrity', check: 'output_scanning', remediation: 'Enable output scanning and watermarking' },
      { id: 'HIPAA-164.312d', name: 'Authentication', check: 'sso_integration', remediation: 'Enable SSO/SAML integration' },
      { id: 'HIPAA-164.312e', name: 'Transmission Security', check: 'encryption', remediation: 'Enable agent protocol with HMAC signing' },
      { id: 'HIPAA-164.502', name: 'PHI Protection', check: 'pii_protection', remediation: 'Enable PII redaction in healthcare-agent preset' },
    ],
  },

  gdpr: {
    name: 'GDPR (AI Processing)',
    version: '2024',
    controls: [
      { id: 'GDPR-5.1f', name: 'Integrity & Confidentiality', check: 'encryption', remediation: 'Enable encrypted agent channels' },
      { id: 'GDPR-25', name: 'Data Protection by Design', check: 'pii_protection', remediation: 'Enable PII detection and redaction' },
      { id: 'GDPR-30', name: 'Records of Processing', check: 'audit_trail', remediation: 'Enable audit trail with structured logging' },
      { id: 'GDPR-32', name: 'Security of Processing', check: 'injection_scanning', remediation: 'Enable full detection engine' },
      { id: 'GDPR-33', name: 'Breach Notification', check: 'incident_response', remediation: 'Configure incident playbooks with notifications' },
      { id: 'GDPR-35', name: 'Impact Assessment', check: 'risk_assessment', remediation: 'Run shield-score and document DPIA' },
    ],
  },
};

// Maps check names to Agent Shield modules
const CHECK_MODULES = {
  injection_scanning: { module: 'detector-core', auto: true },
  output_scanning: { module: 'detector-core', auto: true },
  rate_limiting: { module: 'circuit-breaker', auto: true },
  pii_protection: { module: 'pii', auto: true },
  tool_permissions: { module: 'tool-guard', auto: true },
  permission_boundaries: { module: 'tool-guard', auto: true },
  logging: { module: 'policy', auto: true },
  supply_chain: { module: 'supply-chain', auto: true },
  access_control: { module: 'canary', auto: true },
  output_validation: { module: 'watermark', auto: true },
  audit_trail: { module: 'audit-immutable', auto: true },
  incident_response: { module: 'compliance', auto: true },
  accuracy_testing: { module: 'shield-score', auto: true },
  encryption: { module: 'agent-protocol', auto: true },
  sso_integration: { module: 'sso-saml', auto: true },
  data_validation: { module: null, auto: false },
  risk_assessment: { module: null, auto: false },
  human_in_loop: { module: null, auto: false },
  documentation: { module: null, auto: false },
};


/**
 * Enterprise compliance dashboard.
 * Provides unified compliance posture across all frameworks.
 */
class ComplianceDashboard {
  /**
   * @param {Object} [options]
   * @param {string[]} [options.frameworks] - Framework IDs to track (default: all)
   * @param {string[]} [options.enabledModules] - List of enabled Agent Shield modules
   * @param {Object} [options.orgInfo] - Organization info for reports
   * @param {string} [options.orgInfo.name] - Organization name
   * @param {string} [options.orgInfo.id] - Organization ID
   */
  constructor(options = {}) {
    this.frameworks = options.frameworks || Object.keys(FRAMEWORKS);
    this.enabledChecks = new Set(options.enabledModules || []);
    this.orgInfo = options.orgInfo || {};
    this._history = [];       // compliance score over time
    this._exceptions = [];    // documented exceptions/waivers
  }

  /**
   * Auto-detect enabled modules from a shield instance.
   * @param {Object} shield - An AgentShield instance
   * @param {Object} [config] - Shield config object
   */
  detectModules(shield, config) {
    // Always have core detection
    this.enabledChecks.add('injection_scanning');
    this.enabledChecks.add('output_scanning');

    if (config) {
      if (config.pii || config.enablePII) this.enabledChecks.add('pii_protection');
      if (config.dlp || config.enableDLP) this.enabledChecks.add('pii_protection');
      if (config.toolGuard) this.enabledChecks.add('tool_permissions');
      if (config.toolGuard) this.enabledChecks.add('permission_boundaries');
      if (config.logging || config.auditLog) this.enabledChecks.add('logging');
      if (config.auditLog) this.enabledChecks.add('audit_trail');
      if (config.circuitBreaker || config.rateLimit) this.enabledChecks.add('rate_limiting');
      if (config.supplyChain) this.enabledChecks.add('supply_chain');
      if (config.encryption || config.agentProtocol) this.enabledChecks.add('encryption');
      if (config.sso) this.enabledChecks.add('sso_integration');
      if (config.compliance) this.enabledChecks.add('incident_response');
    }

    // Check if shield has specific modules loaded
    if (shield) {
      if (typeof shield.scan === 'function') {
        this.enabledChecks.add('injection_scanning');
        this.enabledChecks.add('output_scanning');
      }
    }
  }

  /**
   * Enable a specific check.
   * @param {string} checkName
   */
  enableCheck(checkName) {
    this.enabledChecks.add(checkName);
  }

  /**
   * Generate compliance report for a specific framework.
   * @param {string} frameworkId
   * @returns {Object} Compliance report
   */
  generateReport(frameworkId) {
    const fw = FRAMEWORKS[frameworkId];
    if (!fw) throw new Error(`[Agent Shield] Unknown framework: ${frameworkId}`);

    const controls = fw.controls.map(ctrl => {
      const checkInfo = CHECK_MODULES[ctrl.check] || {};
      const enabled = this.enabledChecks.has(ctrl.check);
      const automatable = checkInfo.auto && checkInfo.module;
      const hasException = this._exceptions.some(e => e.controlId === ctrl.id && e.frameworkId === frameworkId);

      let status;
      if (enabled) {
        status = 'compliant';
      } else if (hasException) {
        status = 'exception';
      } else if (automatable) {
        status = 'available';
      } else {
        status = 'manual';
      }

      return {
        ...ctrl,
        status,
        module: checkInfo.module || null,
        automatable: !!automatable,
      };
    });

    const compliant = controls.filter(c => c.status === 'compliant').length;
    const exceptions = controls.filter(c => c.status === 'exception').length;
    const gaps = controls.filter(c => c.status === 'available' || c.status === 'manual');

    const report = {
      framework: fw.name,
      frameworkId,
      version: fw.version,
      generatedAt: new Date().toISOString(),
      org: this.orgInfo,
      summary: {
        total: controls.length,
        compliant,
        exceptions,
        gaps: gaps.length,
        score: Math.round((compliant / controls.length) * 100),
      },
      controls,
      gaps: gaps.map(g => ({
        id: g.id,
        name: g.name,
        status: g.status,
        remediation: g.remediation,
        module: g.module,
      })),
    };

    return report;
  }

  /**
   * Generate compliance posture across all configured frameworks.
   * @returns {Object} Full posture report
   */
  getPosture() {
    const reports = {};
    let totalControls = 0;
    let totalCompliant = 0;

    for (const fwId of this.frameworks) {
      const report = this.generateReport(fwId);
      reports[fwId] = report;
      totalControls += report.summary.total;
      totalCompliant += report.summary.compliant;
    }

    const overallScore = totalControls > 0 ? Math.round((totalCompliant / totalControls) * 100) : 0;

    const posture = {
      generatedAt: new Date().toISOString(),
      org: this.orgInfo,
      overallScore,
      frameworkCount: this.frameworks.length,
      totalControls,
      totalCompliant,
      totalGaps: totalControls - totalCompliant,
      frameworks: reports,
    };

    // Record in history
    this._history.push({
      timestamp: new Date().toISOString(),
      score: overallScore,
    });
    if (this._history.length > 100) this._history.shift();

    return posture;
  }

  /**
   * Document a compliance exception/waiver.
   * @param {Object} exception
   * @param {string} exception.frameworkId - Framework ID
   * @param {string} exception.controlId - Control ID
   * @param {string} exception.reason - Reason for exception
   * @param {string} [exception.approvedBy] - Who approved
   * @param {string} [exception.expiresAt] - Expiration date ISO string
   */
  addException(exception) {
    if (!exception.frameworkId || !exception.controlId || !exception.reason) {
      throw new Error('[Agent Shield] Exception requires frameworkId, controlId, and reason');
    }
    this._exceptions.push({
      ...exception,
      documentedAt: new Date().toISOString(),
    });
  }

  /**
   * Get compliance trend over time.
   * @returns {Array<{timestamp: string, score: number}>}
   */
  getTrend() {
    return [...this._history];
  }

  /**
   * Generate an HTML compliance report.
   * @param {Object} [options]
   * @param {string} [options.title] - Report title
   * @returns {string} HTML string
   */
  generateHTML(options = {}) {
    const posture = this.getPosture();
    const rawTitle = options.title || `Agent Shield Compliance Report - ${this.orgInfo.name || 'Organization'}`;
    const title = rawTitle.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

    const frameworkRows = Object.entries(posture.frameworks).map(([id, report]) => {
      const scoreColor = report.summary.score >= 80 ? '#22c55e' : report.summary.score >= 50 ? '#f59e0b' : '#ef4444';
      return `
        <tr>
          <td>${report.framework}</td>
          <td>${report.version}</td>
          <td><span style="color:${scoreColor};font-weight:bold">${report.summary.score}%</span></td>
          <td>${report.summary.compliant}/${report.summary.total}</td>
          <td>${report.summary.gaps}</td>
        </tr>`;
    }).join('');

    const gapDetails = Object.entries(posture.frameworks).map(([id, report]) => {
      if (report.gaps.length === 0) return '';
      const rows = report.gaps.map(g => `
        <tr>
          <td>${g.id}</td>
          <td>${g.name}</td>
          <td><span class="badge badge-${g.status}">${g.status}</span></td>
          <td>${g.remediation}</td>
        </tr>`).join('');
      return `
        <h3>${report.framework} — Gaps</h3>
        <table>
          <thead><tr><th>ID</th><th>Control</th><th>Status</th><th>Remediation</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>`;
    }).join('');

    const scoreColor = posture.overallScore >= 80 ? '#22c55e' : posture.overallScore >= 50 ? '#f59e0b' : '#ef4444';

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>${title}</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 960px; margin: 0 auto; padding: 2rem; background: #0f172a; color: #e2e8f0; }
  h1 { color: #f8fafc; border-bottom: 2px solid #334155; padding-bottom: 0.5rem; }
  h2 { color: #94a3b8; margin-top: 2rem; }
  h3 { color: #cbd5e1; }
  table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
  th { background: #1e293b; color: #94a3b8; text-align: left; padding: 0.75rem; font-size: 0.85rem; text-transform: uppercase; }
  td { padding: 0.75rem; border-bottom: 1px solid #1e293b; }
  tr:hover { background: #1e293b; }
  .score-circle { display: inline-block; width: 120px; height: 120px; border-radius: 50%; border: 8px solid ${scoreColor}; text-align: center; line-height: 104px; font-size: 2rem; font-weight: bold; color: ${scoreColor}; margin: 1rem; }
  .summary { display: flex; gap: 2rem; align-items: center; background: #1e293b; padding: 1.5rem; border-radius: 12px; margin: 1rem 0; }
  .summary-stats { flex: 1; }
  .summary-stats div { margin: 0.5rem 0; color: #94a3b8; }
  .summary-stats span { color: #f8fafc; font-weight: bold; }
  .badge { padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: 600; }
  .badge-available { background: #1e3a5f; color: #60a5fa; }
  .badge-manual { background: #3b1a1a; color: #f87171; }
  .badge-exception { background: #3b3a1a; color: #fbbf24; }
  .footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #334155; color: #64748b; font-size: 0.85rem; }
</style>
</head>
<body>
<h1>${title}</h1>
<p style="color:#64748b">Generated: ${posture.generatedAt}</p>

<div class="summary">
  <div class="score-circle">${posture.overallScore}%</div>
  <div class="summary-stats">
    <div>Frameworks: <span>${posture.frameworkCount}</span></div>
    <div>Total Controls: <span>${posture.totalControls}</span></div>
    <div>Compliant: <span>${posture.totalCompliant}</span></div>
    <div>Gaps: <span>${posture.totalGaps}</span></div>
  </div>
</div>

<h2>Framework Summary</h2>
<table>
  <thead><tr><th>Framework</th><th>Version</th><th>Score</th><th>Compliant</th><th>Gaps</th></tr></thead>
  <tbody>${frameworkRows}</tbody>
</table>

<h2>Gap Analysis & Remediation</h2>
${gapDetails || '<p style="color:#22c55e">No gaps found — full compliance across all frameworks.</p>'}

<div class="footer">
  <p>Agent Shield Pro — Enterprise Compliance Dashboard</p>
  <p>All detection runs locally. No data leaves your environment.</p>
</div>
</body>
</html>`;
  }

  /**
   * Format posture for terminal output.
   * @returns {string}
   */
  formatTerminal() {
    const posture = this.getPosture();
    const lines = [];

    lines.push('');
    lines.push('\x1b[1m╔══════════════════════════════════════════════════════════╗\x1b[0m');
    lines.push('\x1b[1m║       ENTERPRISE COMPLIANCE DASHBOARD                    ║\x1b[0m');
    lines.push('\x1b[1m╚══════════════════════════════════════════════════════════╝\x1b[0m');
    lines.push('');
    lines.push(`  Overall Score: \x1b[1m${posture.overallScore}%\x1b[0m  (${posture.totalCompliant}/${posture.totalControls} controls)`);
    lines.push('');

    for (const [fwId, report] of Object.entries(posture.frameworks)) {
      const scoreColor = report.summary.score >= 80 ? '\x1b[32m' : report.summary.score >= 50 ? '\x1b[33m' : '\x1b[31m';
      lines.push(`  ${scoreColor}${report.summary.score}%\x1b[0m  ${report.framework} v${report.version}  (${report.summary.compliant}/${report.summary.total})`);

      for (const ctrl of report.controls) {
        const icon = ctrl.status === 'compliant' ? '\x1b[32m✓\x1b[0m' :
          ctrl.status === 'exception' ? '\x1b[33m~\x1b[0m' :
            ctrl.status === 'available' ? '\x1b[33m○\x1b[0m' : '\x1b[31m✗\x1b[0m';
        lines.push(`       ${icon} ${ctrl.id.padEnd(16)} ${ctrl.name}`);
      }
      lines.push('');
    }

    lines.push('  Legend: \x1b[32m✓\x1b[0m Compliant  \x1b[33m○\x1b[0m Available  \x1b[33m~\x1b[0m Exception  \x1b[31m✗\x1b[0m Manual');
    lines.push('');

    return lines.join('\n');
  }
}

module.exports = {
  ComplianceDashboard,
  FRAMEWORKS,
  CHECK_MODULES,
};
