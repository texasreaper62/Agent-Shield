'use strict';

/**
 * Agent Shield -- Compliance Certification Authority
 *
 * Makes Agent Shield the SOC 2/OWASP auditor for AI agents.
 * Generates tamper-proof compliance certificates that auditors can verify.
 *
 * Features:
 * - ComplianceCertificateAuthority: audit, issue, verify, revoke certificates
 * - ComplianceReport: multi-format compliance reporting (JSON, text, HTML)
 * - ComplianceScheduler: scheduled audits with trend analysis
 *
 * All processing runs locally -- no data ever leaves your environment.
 */

const crypto = require('crypto');

// =========================================================================
// Framework Definitions
// =========================================================================

/**
 * Compliance framework definitions with control checks.
 * @type {Object}
 */
const AUTHORITY_FRAMEWORKS = {
  owasp: {
    id: 'owasp',
    name: 'OWASP LLM Top 10 v2025',
    version: '2025',
    controls: [
      { id: 'LLM01', name: 'Prompt Injection', weight: 15, check: 'injection_scanning' },
      { id: 'LLM02', name: 'Sensitive Information Disclosure', weight: 15, check: 'pii_protection' },
      { id: 'LLM03', name: 'Supply Chain', weight: 10, check: 'supply_chain' },
      { id: 'LLM04', name: 'Data and Model Poisoning', weight: 10, check: 'data_validation' },
      { id: 'LLM05', name: 'Improper Output Handling', weight: 10, check: 'output_scanning' },
      { id: 'LLM06', name: 'Excessive Agency', weight: 15, check: 'tool_permissions' },
      { id: 'LLM07', name: 'System Prompt Leakage', weight: 10, check: 'prompt_leakage' },
      { id: 'LLM08', name: 'Vector and Embedding Weaknesses', weight: 5, check: 'rag_scanning' },
      { id: 'LLM09', name: 'Misinformation', weight: 5, check: 'behavior_profiling' },
      { id: 'LLM10', name: 'Unbounded Consumption', weight: 5, check: 'rate_limiting' }
    ]
  },
  nist: {
    id: 'nist',
    name: 'NIST AI RMF',
    version: '1.0-2025',
    controls: [
      { id: 'GOVERN-1', name: 'AI Risk Culture', weight: 10, check: 'documentation' },
      { id: 'GOVERN-2', name: 'Accountability', weight: 10, check: 'access_control' },
      { id: 'GOVERN-5', name: 'Risk Assessment', weight: 15, check: 'risk_assessment' },
      { id: 'GOVERN-6', name: 'Policies & Procedures', weight: 10, check: 'policy_enforcement' },
      { id: 'MAP-3', name: 'Risk Identification', weight: 10, check: 'threat_detection' },
      { id: 'MAP-5', name: 'Documentation', weight: 10, check: 'audit_trail' },
      { id: 'MEASURE-1', name: 'Metrics', weight: 10, check: 'metrics_collection' },
      { id: 'MEASURE-2', name: 'Testing', weight: 10, check: 'security_testing' },
      { id: 'MANAGE-1', name: 'Risk Treatment', weight: 10, check: 'injection_scanning' },
      { id: 'MANAGE-2', name: 'Incident Response', weight: 5, check: 'incident_response' }
    ]
  },
  eu_ai_act: {
    id: 'eu_ai_act',
    name: 'EU AI Act',
    version: '2024',
    controls: [
      { id: 'AIA-1', name: 'Risk Assessment', weight: 20, check: 'risk_assessment' },
      { id: 'AIA-2', name: 'Transparency', weight: 15, check: 'logging' },
      { id: 'AIA-3', name: 'Human Oversight', weight: 15, check: 'human_in_loop' },
      { id: 'AIA-4', name: 'Data Governance', weight: 15, check: 'pii_protection' },
      { id: 'AIA-5', name: 'Technical Documentation', weight: 10, check: 'documentation' },
      { id: 'AIA-6', name: 'Record Keeping', weight: 15, check: 'audit_trail' },
      { id: 'AIA-7', name: 'Accuracy & Robustness', weight: 10, check: 'accuracy_testing' }
    ]
  },
  soc2: {
    id: 'soc2',
    name: 'SOC 2 (AI Controls)',
    version: '2024',
    controls: [
      { id: 'CC6.1', name: 'Logical Access', weight: 20, check: 'access_control' },
      { id: 'CC6.3', name: 'Authorization', weight: 15, check: 'tool_permissions' },
      { id: 'CC7.1', name: 'Detection', weight: 20, check: 'injection_scanning' },
      { id: 'CC7.2', name: 'Monitoring', weight: 15, check: 'logging' },
      { id: 'CC8.1', name: 'Change Management', weight: 15, check: 'supply_chain' },
      { id: 'P3.1', name: 'Privacy Notice', weight: 15, check: 'pii_protection' }
    ]
  }
};

/**
 * Maps check names to Agent Shield capabilities.
 * @type {Object}
 */
const CAPABILITY_MAP = {
  injection_scanning: { module: 'detector-core', description: 'Real-time pattern matching against injection signatures' },
  output_scanning: { module: 'detector-core', description: 'Output scanning for dangerous content' },
  pii_protection: { module: 'pii', description: 'PII detection and redaction' },
  tool_permissions: { module: 'tool-guard', description: 'Tool permission boundaries and sequence analysis' },
  rate_limiting: { module: 'circuit-breaker', description: 'Rate limiting and circuit breaker' },
  logging: { module: 'policy', description: 'Structured logging and audit trail' },
  audit_trail: { module: 'audit-immutable', description: 'Hash-chained tamper-evident audit log' },
  access_control: { module: 'enterprise', description: 'Role-based access control and multi-tenant' },
  supply_chain: { module: 'model-fingerprint', description: 'Model fingerprinting and supply chain detection' },
  prompt_leakage: { module: 'prompt-leakage', description: 'System prompt extraction detection' },
  rag_scanning: { module: 'rag-vulnerability', description: 'RAG/vector vulnerability scanning' },
  behavior_profiling: { module: 'behavior-profiling', description: 'Statistical baselining and anomaly detection' },
  threat_detection: { module: 'threat-encyclopedia', description: 'Threat reference database' },
  policy_enforcement: { module: 'policy-dsl', description: 'Policy DSL parser and runtime' },
  metrics_collection: { module: 'observability', description: 'Prometheus metrics and structured logging' },
  security_testing: { module: 'redteam', description: 'Attack simulation and payload fuzzing' },
  incident_response: { module: 'compliance', description: 'Incident response playbooks' },
  risk_assessment: { module: 'shield-score', description: 'Shield score calculator and benchmarks' },
  accuracy_testing: { module: 'shield-score', description: 'Shield score and benchmarking suite' },
  data_validation: { module: 'scanners', description: 'RAG document scanning and validation' },
  documentation: { available: false, description: 'Manual -- maintain system documentation' },
  human_in_loop: { available: false, description: 'Manual -- implement approval workflows' }
};

/**
 * Certificate level thresholds.
 * @type {Array<Object>}
 */
const CERTIFICATE_LEVELS = [
  { name: 'Platinum', minScore: 95, color: '#E5E4E2' },
  { name: 'Gold', minScore: 85, color: '#FFD700' },
  { name: 'Silver', minScore: 75, color: '#C0C0C0' },
  { name: 'Bronze', minScore: 60, color: '#CD7F32' },
  { name: 'Fail', minScore: 0, color: '#FF4444' }
];

// =========================================================================
// ComplianceCertificateAuthority
// =========================================================================

/**
 * Compliance Certification Authority for AI agents.
 * Audits agent configurations against compliance frameworks and issues
 * tamper-proof, signed certificates.
 */
class ComplianceCertificateAuthority {
  /**
   * @param {Object} [options]
   * @param {string} [options.signingKey] - HMAC-SHA256 signing key
   * @param {string} [options.issuer='Agent Shield CA'] - Certificate issuer name
   * @param {string[]} [options.frameworks] - Framework IDs to audit against (default: all)
   */
  constructor(options = {}) {
    this.signingKey = options.signingKey || crypto.randomBytes(32).toString('hex');
    this.issuer = options.issuer || 'Agent Shield CA';
    this.frameworks = options.frameworks || Object.keys(AUTHORITY_FRAMEWORKS);
    this._certificates = new Map();
    this._revoked = new Set();
    console.log(`[Agent Shield] ComplianceCertificateAuthority initialized (issuer: ${this.issuer})`);
  }

  /**
   * Run a comprehensive compliance audit against all configured frameworks.
   * @param {Object} agentConfig - Agent configuration to audit
   * @param {string[]} [agentConfig.enabledModules] - List of active module names
   * @param {Object} [agentConfig.settings] - Agent settings
   * @returns {Object} AuditResult with per-framework scores
   */
  audit(agentConfig = {}) {
    const enabledModules = agentConfig.enabledModules || [];
    const timestamp = new Date().toISOString();
    const frameworkResults = {};
    let totalWeightedScore = 0;
    let totalWeight = 0;

    for (const fwId of this.frameworks) {
      const fw = AUTHORITY_FRAMEWORKS[fwId];
      if (!fw) continue;

      const controlResults = [];
      let fwWeightedScore = 0;
      let fwTotalWeight = 0;

      for (const control of fw.controls) {
        const capability = CAPABILITY_MAP[control.check];
        let status = 'not_implemented';
        let score = 0;

        if (capability && capability.module) {
          if (enabledModules.includes(capability.module)) {
            status = 'compliant';
            score = 100;
          } else {
            status = 'available';
            score = 25;
          }
        } else if (capability && capability.available === false) {
          status = 'manual';
          score = 0;
        }

        fwWeightedScore += score * control.weight;
        fwTotalWeight += control.weight;

        controlResults.push({
          id: control.id,
          name: control.name,
          status,
          score,
          weight: control.weight,
          check: control.check,
          description: capability ? capability.description : 'No mapping available'
        });
      }

      const frameworkScore = fwTotalWeight > 0 ? Math.round(fwWeightedScore / fwTotalWeight) : 0;
      totalWeightedScore += frameworkScore;
      totalWeight += 1;

      const findings = controlResults
        .filter(c => c.status !== 'compliant')
        .map(c => ({
          controlId: c.id,
          controlName: c.name,
          status: c.status,
          recommendation: c.status === 'available'
            ? `Enable module "${CAPABILITY_MAP[c.check].module}" to achieve compliance`
            : c.status === 'manual'
              ? `Requires manual process: ${c.description}`
              : `Implement ${c.check} capability`
        }));

      frameworkResults[fwId] = {
        framework: fw.name,
        version: fw.version,
        score: frameworkScore,
        controls: controlResults,
        findings,
        compliantCount: controlResults.filter(c => c.status === 'compliant').length,
        totalControls: controlResults.length
      };
    }

    const overallScore = totalWeight > 0 ? Math.round(totalWeightedScore / totalWeight) : 0;

    return {
      id: `audit_${crypto.randomBytes(8).toString('hex')}`,
      timestamp,
      issuer: this.issuer,
      subject: agentConfig.name || 'AI Agent',
      overallScore,
      level: this._getLevel(overallScore),
      frameworks: frameworkResults,
      enabledModules,
      allFindings: Object.values(frameworkResults).reduce((acc, fw) => acc.concat(fw.findings), [])
    };
  }

  /**
   * Generate a signed, tamper-proof certificate from an audit result.
   * @param {Object} auditResult - Result from audit()
   * @returns {Object} Signed certificate
   */
  issueCertificate(auditResult) {
    const certId = `cert_${crypto.randomBytes(12).toString('hex')}`;
    const issuedAt = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString(); // 90 days

    const frameworkScores = {};
    for (const [fwId, fwResult] of Object.entries(auditResult.frameworks || {})) {
      frameworkScores[fwId] = {
        framework: fwResult.framework,
        score: fwResult.score,
        compliantCount: fwResult.compliantCount,
        totalControls: fwResult.totalControls
      };
    }

    const payload = {
      id: certId,
      type: 'agent-shield-compliance-certificate',
      version: '1.0',
      issuer: this.issuer,
      subject: auditResult.subject,
      issuedAt,
      expiresAt,
      overallScore: auditResult.overallScore,
      level: auditResult.level,
      frameworks: frameworkScores,
      findings: auditResult.allFindings,
      auditId: auditResult.id
    };

    const signature = this._sign(payload);

    const certificate = {
      ...payload,
      signature
    };

    this._certificates.set(certId, certificate);
    console.log(`[Agent Shield] Certificate issued: ${certId} (${auditResult.level}, score: ${auditResult.overallScore})`);

    return certificate;
  }

  /**
   * Verify a certificate's signature and expiry.
   * @param {Object} certificate - Certificate to verify
   * @returns {Object} Verification result { valid, expired, revoked, reason }
   */
  verifyCertificate(certificate) {
    if (!certificate || !certificate.id || !certificate.signature) {
      return { valid: false, expired: false, revoked: false, reason: 'Missing required certificate fields' };
    }

    if (this._revoked.has(certificate.id)) {
      return { valid: false, expired: false, revoked: true, reason: 'Certificate has been revoked' };
    }

    const now = new Date();
    const expiresAt = new Date(certificate.expiresAt);
    if (now > expiresAt) {
      return { valid: false, expired: true, revoked: false, reason: 'Certificate has expired' };
    }

    const payloadCopy = { ...certificate };
    delete payloadCopy.signature;
    const expectedSignature = this._sign(payloadCopy);

    if (expectedSignature !== certificate.signature) {
      return { valid: false, expired: false, revoked: false, reason: 'Signature verification failed -- certificate may have been tampered with' };
    }

    return { valid: true, expired: false, revoked: false, reason: 'Certificate is valid' };
  }

  /**
   * Revoke a certificate.
   * @param {string} certId - Certificate ID to revoke
   * @param {string} reason - Reason for revocation
   * @returns {Object} Revocation result
   */
  revokeCertificate(certId, reason) {
    if (!this._certificates.has(certId)) {
      return { success: false, reason: 'Certificate not found' };
    }

    this._revoked.add(certId);
    console.log(`[Agent Shield] Certificate revoked: ${certId} (reason: ${reason})`);

    return {
      success: true,
      certId,
      reason,
      revokedAt: new Date().toISOString()
    };
  }

  /**
   * Return all issued certificates.
   * @returns {Array<Object>} Certificate history
   */
  getCertificateHistory() {
    return Array.from(this._certificates.values()).map(cert => ({
      id: cert.id,
      issuer: cert.issuer,
      subject: cert.subject,
      issuedAt: cert.issuedAt,
      expiresAt: cert.expiresAt,
      overallScore: cert.overallScore,
      level: cert.level,
      revoked: this._revoked.has(cert.id)
    }));
  }

  /**
   * Compute HMAC-SHA256 signature for a payload.
   * @private
   * @param {Object} payload - Data to sign
   * @returns {string} Hex-encoded HMAC signature
   */
  _sign(payload) {
    const data = JSON.stringify(payload, Object.keys(payload).sort());
    return crypto.createHmac('sha256', this.signingKey).update(data).digest('hex');
  }

  /**
   * Determine certificate level from score.
   * @private
   * @param {number} score - Overall score 0-100
   * @returns {string} Level name
   */
  _getLevel(score) {
    for (const level of CERTIFICATE_LEVELS) {
      if (score >= level.minScore) return level.name;
    }
    return 'Fail';
  }
}

// =========================================================================
// ComplianceReport
// =========================================================================

/**
 * Multi-format compliance report generator.
 * Takes an audit result and produces reports in JSON, text, or HTML.
 */
class ComplianceReport {
  /**
   * @param {Object} [auditResult] - Audit result to report on
   */
  constructor(auditResult) {
    this._auditResult = auditResult || null;
    this._report = null;
  }

  /**
   * Generate a formatted compliance report from an audit result.
   * @param {Object} auditResult - Result from ComplianceCertificateAuthority.audit()
   * @returns {ComplianceReport} this (for chaining)
   */
  generate(auditResult) {
    const result = auditResult || this._auditResult;
    if (!result) throw new Error('No audit result provided');

    this._auditResult = result;

    const gapAnalysis = [];
    const remediationSteps = [];
    let stepPriority = 1;

    for (const [fwId, fwResult] of Object.entries(result.frameworks || {})) {
      for (const finding of fwResult.findings || []) {
        gapAnalysis.push({
          framework: fwResult.framework,
          frameworkId: fwId,
          controlId: finding.controlId,
          controlName: finding.controlName,
          status: finding.status,
          recommendation: finding.recommendation
        });

        if (finding.status === 'available') {
          remediationSteps.push({
            priority: stepPriority++,
            effort: 'low',
            action: finding.recommendation,
            control: `${fwId}/${finding.controlId}`,
            impact: 'Immediate compliance improvement'
          });
        } else if (finding.status === 'not_implemented') {
          remediationSteps.push({
            priority: stepPriority++,
            effort: 'medium',
            action: finding.recommendation,
            control: `${fwId}/${finding.controlId}`,
            impact: 'Addresses compliance gap'
          });
        } else if (finding.status === 'manual') {
          remediationSteps.push({
            priority: stepPriority++,
            effort: 'high',
            action: finding.recommendation,
            control: `${fwId}/${finding.controlId}`,
            impact: 'Requires process implementation'
          });
        }
      }
    }

    // Sort remediation: low effort first, then medium, then high
    const effortOrder = { low: 0, medium: 1, high: 2 };
    remediationSteps.sort((a, b) => (effortOrder[a.effort] || 2) - (effortOrder[b.effort] || 2));
    remediationSteps.forEach((step, i) => { step.priority = i + 1; });

    this._report = {
      title: 'Agent Shield Compliance Report',
      generatedAt: new Date().toISOString(),
      subject: result.subject,
      overallScore: result.overallScore,
      level: result.level,
      executiveSummary: this._generateExecutiveSummary(result),
      frameworkBreakdown: Object.entries(result.frameworks || {}).map(([fwId, fw]) => ({
        id: fwId,
        name: fw.framework,
        version: fw.version,
        score: fw.score,
        compliantCount: fw.compliantCount,
        totalControls: fw.totalControls,
        controls: fw.controls
      })),
      gapAnalysis,
      remediationRoadmap: remediationSteps
    };

    return this;
  }

  /**
   * Export report as JSON.
   * @returns {string} JSON string
   */
  toJSON() {
    if (!this._report) throw new Error('Report not generated. Call generate() first.');
    return JSON.stringify(this._report, null, 2);
  }

  /**
   * Export report as plain text.
   * @returns {string} Formatted text
   */
  toText() {
    if (!this._report) throw new Error('Report not generated. Call generate() first.');
    const r = this._report;
    const lines = [];

    lines.push('================================================================');
    lines.push('          AGENT SHIELD COMPLIANCE REPORT');
    lines.push('================================================================');
    lines.push('');
    lines.push(`  Subject:    ${r.subject}`);
    lines.push(`  Generated:  ${r.generatedAt}`);
    lines.push(`  Score:      ${r.overallScore}/100`);
    lines.push(`  Level:      ${r.level}`);
    lines.push('');

    // Executive summary
    lines.push('-- EXECUTIVE SUMMARY --');
    lines.push('');
    lines.push(`  ${r.executiveSummary}`);
    lines.push('');

    // Framework breakdown
    lines.push('-- FRAMEWORK BREAKDOWN --');
    lines.push('');
    for (const fw of r.frameworkBreakdown) {
      const bar = '#'.repeat(Math.round(fw.score / 5)) + '.'.repeat(20 - Math.round(fw.score / 5));
      lines.push(`  ${fw.name}`);
      lines.push(`    Score: [${bar}] ${fw.score}/100 (${fw.compliantCount}/${fw.totalControls} controls)`);
      for (const ctrl of fw.controls) {
        const icon = ctrl.status === 'compliant' ? '[OK]' : ctrl.status === 'available' ? '[--]' : '[  ]';
        lines.push(`    ${icon} ${ctrl.id} ${ctrl.name} (${ctrl.status})`);
      }
      lines.push('');
    }

    // Gap analysis
    if (r.gapAnalysis.length > 0) {
      lines.push('-- GAP ANALYSIS --');
      lines.push('');
      for (const gap of r.gapAnalysis) {
        lines.push(`  ${gap.frameworkId}/${gap.controlId} ${gap.controlName}`);
        lines.push(`    Status: ${gap.status}`);
        lines.push(`    Action: ${gap.recommendation}`);
      }
      lines.push('');
    }

    // Remediation roadmap
    if (r.remediationRoadmap.length > 0) {
      lines.push('-- REMEDIATION ROADMAP --');
      lines.push('');
      for (const step of r.remediationRoadmap) {
        lines.push(`  ${step.priority}. [${step.effort.toUpperCase()}] ${step.action}`);
        lines.push(`     Control: ${step.control} | Impact: ${step.impact}`);
      }
      lines.push('');
    }

    return lines.join('\n');
  }

  /**
   * Export report as HTML.
   * @returns {string} HTML document
   */
  toHTML() {
    if (!this._report) throw new Error('Report not generated. Call generate() first.');
    const r = this._report;

    const levelColor = r.level === 'Platinum' ? '#E5E4E2'
      : r.level === 'Gold' ? '#FFD700'
      : r.level === 'Silver' ? '#C0C0C0'
      : r.level === 'Bronze' ? '#CD7F32'
      : '#FF4444';

    const controlRows = r.frameworkBreakdown.map(fw => {
      const rows = fw.controls.map(ctrl => {
        const statusColor = ctrl.status === 'compliant' ? '#4CAF50'
          : ctrl.status === 'available' ? '#FF9800'
          : '#F44336';
        return `<tr><td>${fw.name}</td><td>${ctrl.id}</td><td>${ctrl.name}</td><td style="color:${statusColor};font-weight:bold">${ctrl.status}</td><td>${ctrl.score}</td></tr>`;
      });
      return rows.join('\n');
    }).join('\n');

    const gapRows = r.gapAnalysis.map(gap =>
      `<tr><td>${gap.frameworkId}</td><td>${gap.controlId}</td><td>${gap.controlName}</td><td>${gap.status}</td><td>${gap.recommendation}</td></tr>`
    ).join('\n');

    const remediationRows = r.remediationRoadmap.map(step =>
      `<tr><td>${step.priority}</td><td>${step.effort}</td><td>${step.action}</td><td>${step.control}</td><td>${step.impact}</td></tr>`
    ).join('\n');

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Agent Shield Compliance Report</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 2em; background: #fafafa; color: #333; }
  h1 { border-bottom: 3px solid ${levelColor}; padding-bottom: 0.5em; }
  h2 { color: #555; margin-top: 2em; }
  .score-badge { display: inline-block; padding: 0.5em 1.5em; background: ${levelColor}; color: #333; font-size: 1.5em; font-weight: bold; border-radius: 8px; }
  .summary { background: #fff; border: 1px solid #ddd; padding: 1.5em; border-radius: 8px; margin: 1em 0; }
  table { border-collapse: collapse; width: 100%; margin: 1em 0; }
  th, td { border: 1px solid #ddd; padding: 0.6em 1em; text-align: left; }
  th { background: #f5f5f5; font-weight: 600; }
  tr:nth-child(even) { background: #fafafa; }
  .meta { color: #888; font-size: 0.9em; }
</style>
</head>
<body>
<h1>Agent Shield Compliance Report</h1>
<p class="meta">Subject: ${r.subject} | Generated: ${r.generatedAt}</p>
<div class="score-badge">${r.level} - ${r.overallScore}/100</div>

<h2>Executive Summary</h2>
<div class="summary">${r.executiveSummary}</div>

<h2>Framework Breakdown</h2>
<table>
<tr><th>Framework</th><th>Control ID</th><th>Control</th><th>Status</th><th>Score</th></tr>
${controlRows}
</table>

<h2>Gap Analysis</h2>
<table>
<tr><th>Framework</th><th>Control ID</th><th>Control</th><th>Status</th><th>Recommendation</th></tr>
${gapRows}
</table>

<h2>Remediation Roadmap</h2>
<table>
<tr><th>#</th><th>Effort</th><th>Action</th><th>Control</th><th>Impact</th></tr>
${remediationRows}
</table>

<p class="meta">Generated by Agent Shield Compliance Authority</p>
</body>
</html>`;
  }

  /**
   * Generate an executive summary string.
   * @private
   * @param {Object} auditResult - Audit result
   * @returns {string} Summary text
   */
  _generateExecutiveSummary(auditResult) {
    const fwNames = Object.values(auditResult.frameworks || {}).map(f => f.framework).join(', ');
    const totalFindings = auditResult.allFindings ? auditResult.allFindings.length : 0;
    const criticalGaps = (auditResult.allFindings || []).filter(f => f.status === 'not_implemented').length;
    const availableQuickWins = (auditResult.allFindings || []).filter(f => f.status === 'available').length;

    let summary = `The AI agent "${auditResult.subject}" was audited against ${fwNames}. `;
    summary += `Overall compliance score: ${auditResult.overallScore}/100 (${auditResult.level}). `;
    summary += `${totalFindings} finding(s) identified. `;

    if (criticalGaps > 0) {
      summary += `${criticalGaps} control(s) require implementation. `;
    }
    if (availableQuickWins > 0) {
      summary += `${availableQuickWins} quick win(s) available by enabling existing modules. `;
    }
    if (auditResult.overallScore >= 95) {
      summary += 'The agent demonstrates excellent compliance posture.';
    } else if (auditResult.overallScore >= 85) {
      summary += 'The agent demonstrates strong compliance posture with minor gaps.';
    } else if (auditResult.overallScore >= 60) {
      summary += 'The agent meets minimum compliance thresholds but has notable gaps to address.';
    } else {
      summary += 'The agent does not meet minimum compliance thresholds. Immediate remediation is required.';
    }

    return summary;
  }
}

// =========================================================================
// ComplianceScheduler
// =========================================================================

/**
 * Schedules periodic compliance audits and tracks trends.
 */
class ComplianceScheduler {
  constructor() {
    this._history = [];
    this._timers = [];
  }

  /**
   * Schedule recurring audits.
   * @param {number} interval - Interval in milliseconds between audits
   * @param {Function} auditFn - Function that returns an audit result (sync or async)
   * @returns {Object} Schedule handle with stop() method
   */
  schedule(interval, auditFn) {
    const handle = {
      id: `sched_${crypto.randomBytes(4).toString('hex')}`,
      interval,
      started: new Date().toISOString(),
      _timer: null,
      stopped: false
    };

    const runAudit = async () => {
      if (handle.stopped) return;
      try {
        const result = typeof auditFn === 'function' ? await auditFn() : null;
        if (result) {
          this._history.push({
            timestamp: new Date().toISOString(),
            scheduleId: handle.id,
            overallScore: result.overallScore,
            level: result.level,
            frameworkScores: Object.entries(result.frameworks || {}).reduce((acc, [k, v]) => {
              acc[k] = v.score;
              return acc;
            }, {}),
            findingCount: result.allFindings ? result.allFindings.length : 0
          });
          console.log(`[Agent Shield] Scheduled audit complete: score ${result.overallScore} (${result.level})`);
        }
      } catch (err) {
        console.log(`[Agent Shield] Scheduled audit failed: ${err.message}`);
      }
    };

    // Run first audit immediately
    runAudit();

    handle._timer = setInterval(runAudit, interval);
    handle.stop = () => {
      handle.stopped = true;
      if (handle._timer) {
        clearInterval(handle._timer);
        handle._timer = null;
      }
    };

    this._timers.push(handle);
    return handle;
  }

  /**
   * Return audit history with all recorded data.
   * @returns {Array<Object>} Audit history entries
   */
  getHistory() {
    return [...this._history];
  }

  /**
   * Analyze the trend across recent audits.
   * @returns {'improving'|'stable'|'degrading'} Trend direction
   */
  getTrend() {
    if (this._history.length < 2) return 'stable';

    const recent = this._history.slice(-5);
    if (recent.length < 2) return 'stable';

    const first = recent[0].overallScore;
    const last = recent[recent.length - 1].overallScore;
    const delta = last - first;

    if (delta > 3) return 'improving';
    if (delta < -3) return 'degrading';
    return 'stable';
  }

  /**
   * Stop all scheduled audits.
   */
  stopAll() {
    for (const handle of this._timers) {
      handle.stop();
    }
    this._timers = [];
  }
}

// =========================================================================
// Exports
// =========================================================================

module.exports = {
  ComplianceCertificateAuthority,
  ComplianceReport,
  ComplianceScheduler,
  AUTHORITY_FRAMEWORKS,
  CAPABILITY_MAP,
  CERTIFICATE_LEVELS
};
