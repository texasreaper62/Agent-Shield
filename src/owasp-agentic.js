'use strict';

/**
 * Agent Shield — OWASP Agentic Applications Top 10 (2026) Scanner
 *
 * Scans agent interactions for all 10 OWASP Agentic risks:
 *   ASI01 Agent Goal Hijack
 *   ASI02 Tool Misuse
 *   ASI03 Identity & Privilege Abuse
 *   ASI04 Supply Chain Compromise
 *   ASI05 Unexpected Code Execution
 *   ASI06 Memory & Context Poisoning
 *   ASI07 Insecure Inter-Agent Communication
 *   ASI08 Cascading Failures
 *   ASI09 Human-Agent Trust Exploitation
 *   ASI10 Rogue Agents
 *
 * Produces aggregate 0-100 score, JSON/Markdown/SARIF reports, and CI/CD exit codes.
 *
 * All detection runs locally — no data ever leaves your environment.
 *
 * @module owasp-agentic
 */

const { scanText } = require('./detector-core');

// =========================================================================
// RISK DEFINITIONS
// =========================================================================

/**
 * OWASP Agentic Top 10 risk definitions with detection patterns.
 */
const OWASP_AGENTIC_2026 = Object.freeze([
  {
    id: 'ASI01',
    name: 'Agent Goal Hijack',
    severity: 'critical',
    description: 'Attacker manipulates the agent into pursuing unauthorized objectives by overriding system instructions.',
    patterns: [
      /ignore\s+(all\s+)?(previous|prior)\s+(instructions|rules|objectives)/i,
      /your\s+new\s+(goal|objective|mission|purpose)\s+is/i,
      /forget\s+(your|all)\s+(instructions|training|goals)/i,
      /override\s+(system|safety)\s+(prompt|instructions|objectives)/i,
      /disregard\s+(all\s+)?(previous|prior|your)\s+(instructions|rules)/i
    ],
    remediation: 'Pin immutable system objectives via constitutional AI techniques. Reject override directives. Implement goal integrity checksums.'
  },
  {
    id: 'ASI02',
    name: 'Tool Misuse',
    severity: 'high',
    description: 'Agent tools are invoked in unintended ways — dangerous commands, unauthorized parameters, or chained abuse.',
    patterns: [
      /run\s+(?:shell|cmd|terminal|bash)/i,
      /rm\s+-rf/i,
      /curl\s+.*\|\s*(?:bash|sh)/i,
      /execute\s+(?:arbitrary|any)\s+(?:code|command)/i,
      /drop\s+table/i,
      /chmod\s+777/i
    ],
    remediation: 'Enforce least-privilege tool access. Maintain command allowlists. Require confirmation for destructive operations.'
  },
  {
    id: 'ASI03',
    name: 'Identity & Privilege Abuse',
    severity: 'critical',
    description: 'Agent assumes unauthorized identity or escalates privileges beyond its granted scope.',
    patterns: [
      /act\s+as\s+admin/i,
      /sudo\s+/i,
      /root\s+access/i,
      /grant\s+(me\s+)?(admin|root|superuser)/i,
      /escalate\s+(my\s+)?privilege/i,
      /impersonate\s+/i,
      /admin\s+override\s+code/i
    ],
    remediation: 'Require strong identity verification. Use signed delegation tokens with expiry. Enforce RBAC boundaries.'
  },
  {
    id: 'ASI04',
    name: 'Supply Chain Compromise',
    severity: 'high',
    description: 'Malicious or tampered tools, plugins, or MCP servers introduced into the agent pipeline.',
    patterns: [
      /download\s+and\s+execute/i,
      /unverified\s+plugin/i,
      /install\s+from\s+untrusted/i,
      /pip\s+install\s+.*--trusted-host/i,
      /npm\s+install\s+.*--ignore-scripts/i
    ],
    remediation: 'Require signed artifacts and hash-pinned dependencies. Verify MCP server attestation before use.'
  },
  {
    id: 'ASI05',
    name: 'Unexpected Code Execution',
    severity: 'critical',
    description: 'Agent or tool executes arbitrary code from untrusted input, enabling RCE.',
    patterns: [
      /eval\s*\(/i,
      /new\s+Function\s*\(/i,
      /child_process/i,
      /exec\s*\(\s*['"`]/i,
      /import\s*\(\s*['"`](?:https?:|data:)/i,
      /process\.env/i
    ],
    remediation: 'Disable dynamic code evaluation. Sandbox untrusted inputs. Use allowlisted interpreters only.'
  },
  {
    id: 'ASI06',
    name: 'Memory & Context Poisoning',
    severity: 'high',
    description: 'Attacker injects persistent malicious content into agent memory or conversation context.',
    patterns: [
      /store\s+this\s+forever/i,
      /remember\s+(?:this\s+)?secret\s+instruction/i,
      /add\s+to\s+(?:your\s+)?(?:memory|context|knowledge)/i,
      /persistent\s+instruction/i,
      /from\s+now\s+on\s+always/i
    ],
    remediation: 'Validate all memory writes. Isolate trusted context from untrusted data. Implement memory integrity checks.'
  },
  {
    id: 'ASI07',
    name: 'Insecure Inter-Agent Communication',
    severity: 'high',
    description: 'Messages between agents lack authentication, integrity, or confidentiality protections.',
    patterns: [
      /forward\s+without\s+verification/i,
      /unsigned\s+agent\s+message/i,
      /trust\s+all\s+agents/i,
      /skip\s+(?:message\s+)?(?:signing|verification|authentication)/i,
      /relay\s+unverified/i
    ],
    remediation: 'Use HMAC-signed messages with replay protection. Verify agent identity before processing delegated tasks.'
  },
  {
    id: 'ASI08',
    name: 'Cascading Failures',
    severity: 'medium',
    description: 'One agent failure propagates across the system, causing widespread disruption.',
    patterns: [
      /retry\s+forever/i,
      /broadcast\s+to\s+all\s+agents/i,
      /no\s+timeout/i,
      /infinite\s+(?:loop|retry|recursion)/i,
      /fan\s*-?\s*out\s+unlimited/i
    ],
    remediation: 'Add circuit breakers, bounded retries, and blast-radius isolation. Set timeouts on all agent calls.'
  },
  {
    id: 'ASI09',
    name: 'Human-Agent Trust Exploitation',
    severity: 'high',
    description: 'Attacker exploits human trust in AI agent outputs to authorize harmful actions.',
    patterns: [
      /urgent:\s*approve\s+/i,
      /ceo\s+(?:requested|authorized|approved)/i,
      /emergency\s+(?:override|authorization)/i,
      /skip\s+(?:human\s+)?(?:review|approval|verification)/i,
      /pre-?\s*approved\s+by\s+(?:management|security)/i,
      /already\s+verified\s+by/i
    ],
    remediation: 'Require step-up verification for high-impact actions. Never auto-approve based on claimed authority in text.'
  },
  {
    id: 'ASI10',
    name: 'Rogue Agents',
    severity: 'critical',
    description: 'Agent operates outside its intended boundaries — self-replicating, disabling monitoring, or acting autonomously.',
    patterns: [
      /self-?\s*replicate/i,
      /disable\s+(?:safety\s+)?monitoring/i,
      /spawn\s+(?:new\s+)?(?:agents?|copies|instances)\s+(?:without|no)\s+(?:approval|limit)/i,
      /remove\s+(?:all\s+)?(?:guardrails|safety|restrictions)/i,
      /operate\s+autonomously/i,
      /kill\s+switch\s+disabled/i
    ],
    remediation: 'Implement kill switches and attestation. Require human approval for agent spawning. Enable continuous behavioral monitoring.'
  }
]);

/** Severity weights for scoring. */
const SEVERITY_WEIGHTS = { critical: 20, high: 12, medium: 8, low: 4 };

// =========================================================================
// OWASPAgenticScanner
// =========================================================================

/**
 * Scans text inputs against all 10 OWASP Agentic Top 10 risks.
 */
class OWASPAgenticScanner {
  /**
   * @param {object} [options]
   * @param {number} [options.failThreshold=70] - Score below which scan is considered failed.
   */
  constructor(options = {}) {
    this.failThreshold = options.failThreshold != null ? options.failThreshold : 70;
  }

  /**
   * Scan input text for OWASP Agentic risks.
   *
   * @param {string|object} input - Text or object to scan.
   * @returns {{ score: number, exitCode: number, status: string, findings: Array<object>, summary: object }}
   */
  scan(input) {
    const text = typeof input === 'string' ? input : JSON.stringify(input || {});
    const findings = [];
    const matchedRisks = new Set();

    // Check each OWASP Agentic risk
    for (const risk of OWASP_AGENTIC_2026) {
      for (const pattern of risk.patterns) {
        if (pattern.test(text)) {
          if (!matchedRisks.has(risk.id)) {
            matchedRisks.add(risk.id);
            findings.push({
              riskId: risk.id,
              name: risk.name,
              severity: risk.severity,
              description: risk.description,
              remediation: risk.remediation,
              evidence: this._extractEvidence(text, pattern)
            });
          }
          break;
        }
      }
    }

    // Also run detector-core for broader injection coverage
    const generic = scanText(text, { source: 'owasp_agentic_scan', sensitivity: 'high' });
    if (generic.threats && generic.threats.length > 0 && !matchedRisks.has('ASI01')) {
      findings.push({
        riskId: 'ASI01',
        name: 'Agent Goal Hijack',
        severity: 'high',
        description: 'Generic prompt injection detected that could hijack agent goals.',
        remediation: 'Block prompt-injection patterns in untrusted input.',
        evidence: generic.threats[0].description || 'detector-core pattern match'
      });
    }

    const score = this._calculateScore(findings);
    const exitCode = score < this.failThreshold ? 1 : 0;

    return {
      score,
      exitCode,
      status: exitCode === 0 ? 'pass' : 'fail',
      findings,
      summary: this._buildSummary(findings),
      risks: OWASP_AGENTIC_2026.map(r => ({
        id: r.id,
        name: r.name,
        detected: matchedRisks.has(r.id)
      }))
    };
  }

  /**
   * Scan multiple inputs and aggregate results.
   *
   * @param {Array<string|object>} inputs
   * @returns {object} Aggregate scan result.
   */
  scanBatch(inputs) {
    const allFindings = [];
    const riskCounts = {};

    for (const input of (inputs || [])) {
      const result = this.scan(input);
      for (const finding of result.findings) {
        allFindings.push(finding);
        riskCounts[finding.riskId] = (riskCounts[finding.riskId] || 0) + 1;
      }
    }

    const score = this._calculateScore(allFindings);
    return {
      inputCount: (inputs || []).length,
      score,
      exitCode: score < this.failThreshold ? 1 : 0,
      status: score >= this.failThreshold ? 'pass' : 'fail',
      findings: allFindings,
      summary: this._buildSummary(allFindings),
      riskCounts
    };
  }

  /**
   * Format scan result as JSON string.
   * @param {object} scanResult
   * @returns {string}
   */
  toJSON(scanResult) {
    return JSON.stringify(scanResult, null, 2);
  }

  /**
   * Format scan result as Markdown report.
   * @param {object} scanResult
   * @returns {string}
   */
  toMarkdown(scanResult) {
    const lines = [
      '# OWASP Agentic Top 10 Scan',
      '',
      `- **Score:** ${scanResult.score}/100`,
      `- **Status:** ${scanResult.status.toUpperCase()}`,
      `- **Findings:** ${scanResult.findings.length}`,
      ''
    ];

    if (scanResult.findings.length === 0) {
      lines.push('No OWASP Agentic risks detected.');
      return lines.join('\n');
    }

    lines.push('## Findings');
    lines.push('');
    for (const finding of scanResult.findings) {
      lines.push(`### ${finding.riskId}: ${finding.name} (${finding.severity})`);
      lines.push(`- **Evidence:** ${finding.evidence}`);
      lines.push(`- **Remediation:** ${finding.remediation}`);
      lines.push('');
    }

    lines.push('## Summary');
    const s = scanResult.summary;
    lines.push(`| Severity | Count |`);
    lines.push(`|----------|-------|`);
    lines.push(`| Critical | ${s.critical} |`);
    lines.push(`| High     | ${s.high} |`);
    lines.push(`| Medium   | ${s.medium} |`);
    lines.push(`| Low      | ${s.low} |`);

    return lines.join('\n');
  }

  /**
   * Format scan result as SARIF 2.1.0 for CI/CD integration.
   * @param {object} scanResult
   * @returns {object} SARIF object.
   */
  toSARIF(scanResult) {
    const results = scanResult.findings.map(f => ({
      ruleId: f.riskId,
      level: f.severity === 'critical' ? 'error' : (f.severity === 'high' ? 'warning' : 'note'),
      message: { text: `${f.name}: ${f.evidence}` },
      properties: {
        severity: f.severity,
        remediation: f.remediation
      }
    }));

    return {
      version: '2.1.0',
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      runs: [{
        tool: {
          driver: {
            name: 'Agent Shield OWASP Agentic Scanner',
            version: '1.0.0',
            rules: OWASP_AGENTIC_2026.map(r => ({
              id: r.id,
              name: r.name,
              shortDescription: { text: r.name },
              fullDescription: { text: r.description },
              defaultConfiguration: { level: r.severity === 'critical' ? 'error' : 'warning' }
            }))
          }
        },
        results
      }]
    };
  }

  // -----------------------------------------------------------------------
  // Private
  // -----------------------------------------------------------------------

  /** @private */
  _calculateScore(findings) {
    const penalty = findings.reduce((sum, f) => sum + (SEVERITY_WEIGHTS[f.severity] || 6), 0);
    return Math.max(0, 100 - penalty);
  }

  /** @private */
  _buildSummary(findings) {
    const out = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of findings) {
      out[f.severity] = (out[f.severity] || 0) + 1;
    }
    return out;
  }

  /** @private */
  _extractEvidence(text, pattern) {
    const match = text.match(pattern);
    return match ? match[0].substring(0, 120) : 'pattern matched';
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
  OWASPAgenticScanner,
  OWASP_AGENTIC_2026,
  SEVERITY_WEIGHTS
};
