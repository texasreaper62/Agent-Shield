'use strict';

/**
 * Agent Shield — Compliance, Audit Trail & Incident Playbook
 *
 * Features:
 * - Compliance report generation (OWASP LLM Top 10, EU AI Act, SOC2)
 * - Audit trail export (JSON, CSV)
 * - Incident response playbooks
 * - Security checklist generator
 */

// =========================================================================
// Compliance Frameworks
// =========================================================================

const COMPLIANCE_FRAMEWORKS = {
  owasp_llm: {
    name: 'OWASP LLM Top 10',
    version: '1.1',
    controls: [
      { id: 'LLM01', name: 'Prompt Injection', check: 'injection_scanning', description: 'Validate and sanitize all inputs to the LLM' },
      { id: 'LLM02', name: 'Insecure Output Handling', check: 'output_scanning', description: 'Validate and sanitize LLM outputs' },
      { id: 'LLM03', name: 'Training Data Poisoning', check: 'data_validation', description: 'Ensure training data integrity' },
      { id: 'LLM04', name: 'Model Denial of Service', check: 'rate_limiting', description: 'Implement rate limiting and resource controls' },
      { id: 'LLM05', name: 'Supply Chain Vulnerabilities', check: 'supply_chain', description: 'Audit third-party components and plugins' },
      { id: 'LLM06', name: 'Sensitive Information Disclosure', check: 'pii_protection', description: 'Implement PII detection and DLP' },
      { id: 'LLM07', name: 'Insecure Plugin Design', check: 'tool_permissions', description: 'Restrict and validate tool/plugin access' },
      { id: 'LLM08', name: 'Excessive Agency', check: 'permission_boundaries', description: 'Limit agent capabilities and require human approval' },
      { id: 'LLM09', name: 'Overreliance', check: 'output_validation', description: 'Validate AI outputs before acting on them' },
      { id: 'LLM10', name: 'Model Theft', check: 'access_control', description: 'Protect model access and API keys' }
    ]
  },

  eu_ai_act: {
    name: 'EU AI Act',
    version: '2024',
    controls: [
      { id: 'AIA-1', name: 'Risk Assessment', check: 'risk_assessment', description: 'Document AI system risk level' },
      { id: 'AIA-2', name: 'Transparency', check: 'logging', description: 'Log all AI interactions for audit' },
      { id: 'AIA-3', name: 'Human Oversight', check: 'human_in_loop', description: 'Maintain human oversight of AI decisions' },
      { id: 'AIA-4', name: 'Data Governance', check: 'pii_protection', description: 'Protect personal data in AI processing' },
      { id: 'AIA-5', name: 'Technical Documentation', check: 'documentation', description: 'Maintain documentation of AI system capabilities' },
      { id: 'AIA-6', name: 'Record Keeping', check: 'audit_trail', description: 'Keep records of AI system operation' },
      { id: 'AIA-7', name: 'Accuracy & Robustness', check: 'accuracy_testing', description: 'Test AI system for accuracy and adversarial robustness' }
    ]
  },

  soc2: {
    name: 'SOC 2 (AI Controls)',
    version: '2024',
    controls: [
      { id: 'SOC2-CC6.1', name: 'Logical Access', check: 'access_control', description: 'Control access to AI systems and data' },
      { id: 'SOC2-CC6.3', name: 'Authorization', check: 'permission_boundaries', description: 'Authorize AI agent actions appropriately' },
      { id: 'SOC2-CC7.1', name: 'Detection', check: 'injection_scanning', description: 'Detect unauthorized activities in AI systems' },
      { id: 'SOC2-CC7.2', name: 'Monitoring', check: 'logging', description: 'Monitor AI system activities' },
      { id: 'SOC2-CC8.1', name: 'Change Management', check: 'supply_chain', description: 'Control changes to AI system components' },
      { id: 'SOC2-P3.1', name: 'Privacy Notice', check: 'pii_protection', description: 'Protect personal information in AI processing' }
    ]
  },

  nist_ai: {
    name: 'NIST AI RMF',
    version: '1.0',
    controls: [
      { id: 'GOVERN-1', name: 'AI Risk Culture', check: 'documentation', description: 'Establish AI risk management culture' },
      { id: 'MAP-1', name: 'Context Mapping', check: 'risk_assessment', description: 'Map AI system context and intended use' },
      { id: 'MEASURE-1', name: 'Risk Measurement', check: 'accuracy_testing', description: 'Measure AI risks through testing' },
      { id: 'MANAGE-1', name: 'Risk Treatment', check: 'injection_scanning', description: 'Treat identified AI risks' },
      { id: 'MANAGE-2', name: 'Incident Response', check: 'incident_response', description: 'Respond to AI-related incidents' }
    ]
  }
};

// What Agent Shield features satisfy which checks
const FEATURE_CHECK_MAP = {
  injection_scanning: { module: 'detector-core', description: 'Input/output scanning for injection patterns' },
  output_scanning: { module: 'detector-core', description: 'Output scanning for dangerous content' },
  rate_limiting: { module: 'circuit-breaker', description: 'Rate limiting and circuit breaker' },
  pii_protection: { module: 'pii', description: 'PII detection and redaction' },
  tool_permissions: { module: 'tool-guard', description: 'Tool permission boundaries' },
  permission_boundaries: { module: 'tool-guard', description: 'Permission boundaries and input quarantine' },
  logging: { module: 'policy', description: 'Structured logging and audit trail' },
  supply_chain: { module: 'multi-agent', description: 'Agent firewall and delegation chain validation' },
  access_control: { module: 'canary', description: 'Canary tokens and credential detection' },
  output_validation: { module: 'watermark', description: 'Output watermarking and validation' },
  audit_trail: { module: 'policy', description: 'Structured logging to file/webhook' },
  incident_response: { module: 'compliance', description: 'Incident response playbooks' },
  data_validation: { available: false, description: 'Not yet implemented — training data validation' },
  risk_assessment: { available: false, description: 'Manual — document using Shield Score' },
  human_in_loop: { available: false, description: 'Manual — implement approval workflows' },
  documentation: { available: false, description: 'Manual — maintain system documentation' },
  accuracy_testing: { module: 'shield-score', description: 'Shield Score and benchmarking suite' }
};

// =========================================================================
// Compliance Report Generator
// =========================================================================

class ComplianceReporter {
  constructor(options = {}) {
    this.enabledModules = options.enabledModules || Object.keys(FEATURE_CHECK_MAP).filter(k => FEATURE_CHECK_MAP[k].module);
    this.framework = options.framework || 'owasp_llm';
  }

  /**
   * Generate a compliance report for a specific framework.
   */
  generateReport(frameworkId) {
    const fw = COMPLIANCE_FRAMEWORKS[frameworkId || this.framework];
    if (!fw) throw new Error(`Unknown framework: ${frameworkId}`);

    const controls = fw.controls.map(ctrl => {
      const feature = FEATURE_CHECK_MAP[ctrl.check];
      const implemented = feature && feature.module && this.enabledModules.includes(ctrl.check);
      const available = feature && feature.module;

      return {
        ...ctrl,
        status: implemented ? 'compliant' : (available ? 'available' : 'manual'),
        feature: feature ? feature.description : 'Not mapped',
        module: feature ? feature.module : null
      };
    });

    const compliant = controls.filter(c => c.status === 'compliant').length;
    const available = controls.filter(c => c.status === 'available').length;
    const manual = controls.filter(c => c.status === 'manual').length;

    return {
      framework: fw.name,
      version: fw.version,
      date: new Date().toISOString(),
      summary: {
        total: controls.length,
        compliant,
        available,
        manual,
        complianceRate: `${((compliant / controls.length) * 100).toFixed(1)}%`
      },
      controls
    };
  }

  /**
   * Generate reports for all frameworks.
   */
  generateAllReports() {
    const reports = {};
    for (const key of Object.keys(COMPLIANCE_FRAMEWORKS)) {
      reports[key] = this.generateReport(key);
    }
    return reports;
  }

  /**
   * Format a compliance report for console output.
   */
  formatReport(report) {
    const lines = [];
    lines.push('');
    lines.push(`╔══════════════════════════════════════════════════════╗`);
    lines.push(`║          COMPLIANCE REPORT: ${report.framework.padEnd(24)}║`);
    lines.push(`╚══════════════════════════════════════════════════════╝`);
    lines.push('');
    lines.push(`  Version:    ${report.version}`);
    lines.push(`  Date:       ${report.date}`);
    lines.push(`  Compliance: ${report.summary.complianceRate} (${report.summary.compliant}/${report.summary.total})`);
    lines.push('');

    for (const ctrl of report.controls) {
      const icon = ctrl.status === 'compliant' ? '✓' : (ctrl.status === 'available' ? '○' : '✗');
      const color = ctrl.status === 'compliant' ? '\x1b[32m' : (ctrl.status === 'available' ? '\x1b[33m' : '\x1b[31m');
      lines.push(`  ${color}${icon}\x1b[0m ${ctrl.id.padEnd(12)} ${ctrl.name}`);
      lines.push(`    ${ctrl.description}`);
      if (ctrl.status !== 'compliant') {
        lines.push(`    \x1b[90m→ ${ctrl.feature}\x1b[0m`);
      }
    }

    lines.push('');
    lines.push(`  Legend: ✓ Compliant  ○ Available (enable module)  ✗ Manual action needed`);
    lines.push('');
    return lines.join('\n');
  }
}

// =========================================================================
// Audit Trail
// =========================================================================

class AuditTrail {
  constructor(options = {}) {
    this.events = [];
    this.maxEvents = options.maxEvents || 10000;
    this.autoFlush = options.autoFlush || false;
    this.flushPath = options.flushPath || null;
  }

  /**
   * Record an audit event.
   */
  record(event) {
    const entry = {
      id: `evt_${Date.now()}_${Math.random().toString(36).slice(2, 8).padEnd(6, '0')}`,
      timestamp: new Date().toISOString(),
      ...event
    };

    this.events.push(entry);

    // Remove oldest events when at capacity
    while (this.events.length > this.maxEvents) {
      this.events.shift();
    }

    if (this.autoFlush && this.flushPath) {
      this.flush();
    }

    return entry;
  }

  /**
   * Record a scan event.
   */
  recordScan(input, result, metadata = {}) {
    const inputStr = typeof input === 'string' ? input : String(input);
    return this.record({
      type: 'scan',
      input: inputStr.substring(0, 200),
      status: result.status,
      threatCount: result.threats ? result.threats.length : 0,
      blocked: result.blocked || false,
      threats: (result.threats || []).map(t => ({ severity: t.severity, category: t.category, description: t.description })),
      ...metadata
    });
  }

  /**
   * Record a block event.
   */
  recordBlock(reason, input, threats, metadata = {}) {
    const threatList = Array.isArray(threats) ? threats : [];
    const inputStr = typeof input === 'string' ? input : String(input);
    return this.record({
      type: 'block',
      reason,
      blocked: true,
      input: inputStr.substring(0, 200),
      threats: threatList.map(t => ({ severity: t.severity, category: t.category })),
      ...metadata
    });
  }

  /**
   * Record a tool call.
   */
  recordToolCall(tool, args, result, metadata = {}) {
    return this.record({
      type: 'tool_call',
      tool,
      args: typeof args === 'object' ? JSON.stringify(args).substring(0, 200) : String(args).substring(0, 200),
      allowed: result.allowed !== false,
      ...metadata
    });
  }

  /**
   * Export events as JSON.
   */
  exportJSON() {
    return JSON.stringify(this.events, null, 2);
  }

  /**
   * Export events as CSV.
   */
  exportCSV() {
    if (this.events.length === 0) return '';

    const headers = ['id', 'timestamp', 'type', 'status', 'blocked', 'threatCount', 'input'];
    const rows = [headers.join(',')];

    for (const evt of this.events) {
      rows.push([
        evt.id,
        evt.timestamp,
        evt.type || '',
        evt.status || '',
        evt.blocked || false,
        evt.threatCount || 0,
        `"${(evt.input || '').replace(/"/g, '""')}"`
      ].join(','));
    }

    return rows.join('\n');
  }

  /**
   * Flush events to file.
   */
  flush(filePath) {
    const targetPath = filePath || this.flushPath;
    if (!targetPath) return;

    const fs = require('fs');
    const ext = require('path').extname(targetPath).toLowerCase();

    if (ext === '.csv') {
      fs.writeFileSync(targetPath, this.exportCSV());
    } else {
      fs.writeFileSync(targetPath, this.exportJSON());
    }
  }

  /**
   * Query events.
   */
  query(filters = {}) {
    const sinceDate = filters.since ? new Date(filters.since) : null;
    const untilDate = filters.until ? new Date(filters.until) : null;

    return this.events.filter(e => {
      if (filters.type && e.type !== filters.type) return false;
      if (filters.blocked !== undefined && e.blocked !== filters.blocked) return false;
      if (sinceDate && new Date(e.timestamp) < sinceDate) return false;
      if (untilDate && new Date(e.timestamp) > untilDate) return false;
      if (filters.minThreats && (e.threatCount || 0) < filters.minThreats) return false;
      return true;
    });
  }

  /**
   * Get summary statistics.
   */
  getSummary() {
    const total = this.events.length;
    const blocks = this.events.filter(e => e.blocked).length;
    const scans = this.events.filter(e => e.type === 'scan').length;
    const toolCalls = this.events.filter(e => e.type === 'tool_call').length;
    const threats = this.events.reduce((sum, e) => sum + (e.threatCount || 0), 0);

    return { total, scans, blocks, toolCalls, threats };
  }

  /**
   * Clear all events.
   */
  clear() {
    this.events = [];
  }
}

// =========================================================================
// Incident Playbook
// =========================================================================

const INCIDENT_PLAYBOOKS = {
  prompt_injection: {
    name: 'Prompt Injection Detected',
    severity: 'high',
    steps: [
      { action: 'block', description: 'Immediately block the request' },
      { action: 'log', description: 'Log the full request with context (IP, session, user agent)' },
      { action: 'alert', description: 'Send alert to security team via webhook' },
      { action: 'rate_limit', description: 'Apply rate limiting to the source' },
      { action: 'review', description: 'Review recent requests from the same source for patterns' },
      { action: 'update', description: 'Check if the attack pattern is new and update detection rules' }
    ]
  },

  data_exfiltration: {
    name: 'Data Exfiltration Attempt',
    severity: 'critical',
    steps: [
      { action: 'block', description: 'Block the output immediately' },
      { action: 'quarantine', description: 'Quarantine the conversation/session' },
      { action: 'log', description: 'Log the full conversation history' },
      { action: 'alert', description: 'Send critical alert to security team and CISO' },
      { action: 'investigate', description: 'Determine what data was targeted' },
      { action: 'notify', description: 'If data was exposed, trigger data breach notification process' },
      { action: 'remediate', description: 'Rotate any potentially exposed credentials' }
    ]
  },

  credential_leak: {
    name: 'Credential Exposure',
    severity: 'critical',
    steps: [
      { action: 'block', description: 'Block the output immediately' },
      { action: 'rotate', description: 'Immediately rotate the exposed credential' },
      { action: 'audit', description: 'Audit usage of the credential for unauthorized access' },
      { action: 'log', description: 'Log the incident with full context' },
      { action: 'alert', description: 'Alert security team and credential owner' },
      { action: 'review', description: 'Review all locations where the credential is used' }
    ]
  },

  jailbreak: {
    name: 'Jailbreak Attempt',
    severity: 'high',
    steps: [
      { action: 'block', description: 'Block the request' },
      { action: 'log', description: 'Log the attempt with attack category' },
      { action: 'monitor', description: 'Increase monitoring for the source' },
      { action: 'rate_limit', description: 'Apply stricter rate limits' },
      { action: 'review', description: 'Check if the jailbreak technique is new' }
    ]
  },

  circuit_breaker_trip: {
    name: 'Circuit Breaker Tripped',
    severity: 'high',
    steps: [
      { action: 'alert', description: 'Alert operations team' },
      { action: 'investigate', description: 'Determine if this is an active attack or false positives' },
      { action: 'review', description: 'Review all blocked requests during the window' },
      { action: 'adjust', description: 'Adjust circuit breaker thresholds if needed' },
      { action: 'resume', description: 'Manually reset circuit breaker after investigation' }
    ]
  },

  pii_exposure: {
    name: 'PII Exposure',
    severity: 'high',
    steps: [
      { action: 'redact', description: 'Redact PII from all outputs' },
      { action: 'log', description: 'Log PII types detected (not the PII itself)' },
      { action: 'alert', description: 'Alert privacy/compliance team' },
      { action: 'investigate', description: 'Determine the source of PII in the system' },
      { action: 'notify', description: 'If PII was exposed externally, follow breach notification procedures' }
    ]
  }
};

class IncidentPlaybook {
  constructor() {
    this.playbooks = INCIDENT_PLAYBOOKS;
  }

  /**
   * Get a playbook by threat type.
   */
  get(threatType) {
    return this.playbooks[threatType] || null;
  }

  /**
   * Get all playbooks.
   */
  getAll() {
    return Object.entries(this.playbooks).map(([key, val]) => ({ key, ...val }));
  }

  /**
   * Get the recommended playbook for a scan result.
   */
  recommend(scanResult) {
    if (!scanResult.threats || scanResult.threats.length === 0) return null;

    // Find the most severe threat category
    const categories = scanResult.threats.map(t => t.category);

    if (categories.includes('data_exfiltration')) return { key: 'data_exfiltration', ...this.playbooks.data_exfiltration };
    if (categories.includes('credential_leak')) return { key: 'credential_leak', ...this.playbooks.credential_leak };
    if (categories.includes('pii')) return { key: 'pii_exposure', ...this.playbooks.pii_exposure };
    if (categories.includes('prompt_injection') || categories.includes('instruction_override')) return { key: 'prompt_injection', ...this.playbooks.prompt_injection };
    if (categories.includes('jailbreak')) return { key: 'jailbreak', ...this.playbooks.jailbreak };

    return { key: 'prompt_injection', ...this.playbooks.prompt_injection };
  }

  /**
   * Format a playbook for console output.
   */
  format(playbook) {
    if (!playbook) return 'No playbook available.';

    const lines = [];
    lines.push(`\n  Incident Playbook: ${playbook.name}`);
    lines.push(`  Severity: ${playbook.severity.toUpperCase()}`);
    lines.push('');
    playbook.steps.forEach((step, i) => {
      lines.push(`  ${i + 1}. [${step.action.toUpperCase()}] ${step.description}`);
    });
    lines.push('');
    return lines.join('\n');
  }
}

// =========================================================================
// Security Checklist Generator
// =========================================================================

const CHECKLIST_ITEMS = [
  // Input protection
  { category: 'Input Protection', item: 'Enable input scanning for prompt injection', env: ['development', 'staging', 'production'], priority: 'critical' },
  { category: 'Input Protection', item: 'Set sensitivity to "high" for production', env: ['production'], priority: 'high' },
  { category: 'Input Protection', item: 'Enable PII detection on user inputs', env: ['staging', 'production'], priority: 'high' },
  { category: 'Input Protection', item: 'Configure input quarantine for untrusted sources', env: ['production'], priority: 'medium' },
  { category: 'Input Protection', item: 'Enable encoding/steganography detection', env: ['production'], priority: 'medium' },

  // Output protection
  { category: 'Output Protection', item: 'Enable output scanning', env: ['development', 'staging', 'production'], priority: 'critical' },
  { category: 'Output Protection', item: 'Enable PII redaction on outputs', env: ['staging', 'production'], priority: 'high' },
  { category: 'Output Protection', item: 'Deploy canary tokens in system prompts', env: ['production'], priority: 'high' },
  { category: 'Output Protection', item: 'Enable output watermarking', env: ['production'], priority: 'low' },
  { category: 'Output Protection', item: 'Configure DLP rules for sensitive data', env: ['production'], priority: 'high' },

  // Tool protection
  { category: 'Tool Protection', item: 'Define permission boundaries for all tools', env: ['development', 'staging', 'production'], priority: 'critical' },
  { category: 'Tool Protection', item: 'Block dangerous tools (bash, exec, eval)', env: ['production'], priority: 'critical' },
  { category: 'Tool Protection', item: 'Enable tool sequence analysis', env: ['staging', 'production'], priority: 'high' },
  { category: 'Tool Protection', item: 'Set per-tool rate limits', env: ['production'], priority: 'medium' },
  { category: 'Tool Protection', item: 'Configure path restrictions for file tools', env: ['production'], priority: 'high' },

  // Availability
  { category: 'Availability', item: 'Configure circuit breaker', env: ['staging', 'production'], priority: 'high' },
  { category: 'Availability', item: 'Set up rate limiting', env: ['production'], priority: 'high' },
  { category: 'Availability', item: 'Define blockOnThreat threshold', env: ['production'], priority: 'medium' },

  // Monitoring
  { category: 'Monitoring', item: 'Enable structured logging', env: ['development', 'staging', 'production'], priority: 'high' },
  { category: 'Monitoring', item: 'Configure webhook alerts for critical threats', env: ['production'], priority: 'high' },
  { category: 'Monitoring', item: 'Set up audit trail export', env: ['production'], priority: 'medium' },
  { category: 'Monitoring', item: 'Enable behavioral fingerprinting', env: ['production'], priority: 'low' },

  // Conversation
  { category: 'Conversation', item: 'Enable fragmentation detection for multi-turn', env: ['staging', 'production'], priority: 'medium' },
  { category: 'Conversation', item: 'Configure instruction hierarchy', env: ['production'], priority: 'medium' },
  { category: 'Conversation', item: 'Enable language switch detection', env: ['production'], priority: 'low' },

  // Testing
  { category: 'Testing', item: 'Run Shield Score benchmark', env: ['development', 'staging'], priority: 'high' },
  { category: 'Testing', item: 'Run red team attack suite', env: ['development', 'staging'], priority: 'high' },
  { category: 'Testing', item: 'Test with custom attack payloads', env: ['staging'], priority: 'medium' },
  { category: 'Testing', item: 'Run performance benchmarks', env: ['staging'], priority: 'medium' },
  { category: 'Testing', item: 'Verify false positive rate is acceptable', env: ['staging'], priority: 'high' },

  // Compliance
  { category: 'Compliance', item: 'Generate OWASP LLM Top 10 compliance report', env: ['production'], priority: 'medium' },
  { category: 'Compliance', item: 'Document incident response procedures', env: ['production'], priority: 'high' },
  { category: 'Compliance', item: 'Set up regular audit trail exports', env: ['production'], priority: 'medium' }
];

class SecurityChecklistGenerator {
  constructor() {
    this.items = CHECKLIST_ITEMS;
  }

  /**
   * Generate a checklist for a specific environment.
   */
  generate(environment = 'production') {
    const env = environment.toLowerCase();
    const items = this.items
      .filter(item => item.env.includes(env))
      .sort((a, b) => {
        const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
        return (priorityOrder[a.priority] || 99) - (priorityOrder[b.priority] || 99);
      });

    // Group by category
    const grouped = {};
    for (const item of items) {
      if (!grouped[item.category]) grouped[item.category] = [];
      grouped[item.category].push(item);
    }

    return {
      environment: env,
      date: new Date().toISOString(),
      totalItems: items.length,
      categories: Object.entries(grouped).map(([name, items]) => ({
        name,
        items: items.map(i => ({ item: i.item, priority: i.priority, checked: false }))
      }))
    };
  }

  /**
   * Format a checklist for console output.
   */
  format(checklist) {
    const lines = [];
    lines.push('');
    lines.push(`╔══════════════════════════════════════════════════════╗`);
    lines.push(`║          SECURITY CHECKLIST: ${checklist.environment.toUpperCase().padEnd(23)}║`);
    lines.push(`╚══════════════════════════════════════════════════════╝`);
    lines.push('');
    lines.push(`  ${checklist.totalItems} items for ${checklist.environment} environment`);
    lines.push('');

    for (const cat of checklist.categories) {
      lines.push(`  ── ${cat.name} ──`);
      for (const item of cat.items) {
        const priorityTag = item.priority === 'critical' ? '\x1b[31m[CRITICAL]\x1b[0m' :
          item.priority === 'high' ? '\x1b[33m[HIGH]\x1b[0m' :
          item.priority === 'medium' ? '\x1b[90m[MEDIUM]\x1b[0m' :
          '\x1b[90m[LOW]\x1b[0m';
        lines.push(`  [ ] ${priorityTag} ${item.item}`);
      }
      lines.push('');
    }

    return lines.join('\n');
  }
}

module.exports = {
  ComplianceReporter,
  AuditTrail,
  IncidentPlaybook,
  SecurityChecklistGenerator,
  COMPLIANCE_FRAMEWORKS,
  INCIDENT_PLAYBOOKS,
  CHECKLIST_ITEMS
};
