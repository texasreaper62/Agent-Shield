'use strict';

/**
 * Agent Shield — MCP Supply Chain Scanner
 *
 * npm-audit-style security scanner for MCP servers. Detects:
 * - Tool definition drift (rugpull / Postmark-style attacks)
 * - Known-bad MCP server blocklist matches
 * - Hidden prompt injection in tool descriptions
 * - CVE registry matches (e.g. CVE-2025-6514 mcp-remote RCE)
 * - Overly broad permissions in tool schemas
 * - Capability escalation chains (credential reader + HTTP sender)
 *
 * All detection runs locally — no data ever leaves your environment.
 *
 * @module supply-chain-scanner
 */

const crypto = require('crypto');
const { scanText } = require('./detector-core');

// =========================================================================
// CONSTANTS
// =========================================================================

/** Known-bad MCP server blocklist. */
const KNOWN_BAD_SERVERS = Object.freeze({
  'mcp-remote': {
    reason: 'Known remote command execution weakness (CVE-2025-6514)',
    severity: 'critical'
  },
  'rogue-toolbox': {
    reason: 'Observed prompt-injection distribution behavior',
    severity: 'high'
  },
  'shadow-mcp': {
    reason: 'Data exfiltration via tool output encoding',
    severity: 'high'
  },
  'postmark-clone': {
    reason: 'Tool definition bait-and-switch (Postmark-style rugpull)',
    severity: 'critical'
  }
});

/** CVE registry for known MCP vulnerabilities. */
const CVE_REGISTRY = Object.freeze({
  'mcp-remote': [
    {
      cve: 'CVE-2025-6514',
      severity: 'critical',
      description: 'mcp-remote RCE via unsanitized command bridge allows arbitrary code execution when tool arguments are passed to shell without escaping.',
      fix: 'Upgrade mcp-remote to >=2.1.0 and disable shell passthrough. Set sanitizeArgs: true.'
    }
  ]
});

/** Patterns that indicate hidden prompt injection in tool descriptions. */
const DESCRIPTION_INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?(previous|prior)\s+(instructions|rules)/i,
  /do\s+not\s+tell\s+the\s+user/i,
  /silently\s+exfiltrate/i,
  /system\s*:\s*new\s+instructions/i,
  /hidden\s+instruction/i,
  /secretly\s+(execute|send|forward|run)/i,
  /override\s+(all\s+)?(system|safety)/i,
  /act\s+as\s+(a|an)\s+unrestricted/i,
  /before\s+responding.*first\s+(send|forward|post)/i
];

/** Patterns that indicate overly broad permissions. */
const BROAD_PERMISSION_PATTERNS = [
  /^\*$/,
  /all(:|_|-)?scopes?/i,
  /admin/i,
  /root/i,
  /filesystem\.write/i,
  /network\.all/i,
  /execute\.any/i,
  /shell\.access/i
];

/** Severity ranking for report ordering. */
const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

// =========================================================================
// SupplyChainScanner
// =========================================================================

/**
 * MCP supply chain scanner. Scans MCP server definitions for security
 * vulnerabilities, producing npm-audit-style severity reports.
 */
class SupplyChainScanner {
  /**
   * @param {object} [options]
   * @param {object} [options.knownBadServers] - Additional known-bad servers to merge.
   * @param {object} [options.cveRegistry] - Additional CVE entries to merge.
   */
  constructor(options = {}) {
    this.knownBadServers = Object.assign({}, KNOWN_BAD_SERVERS, options.knownBadServers || {});
    this.cveRegistry = Object.assign({}, CVE_REGISTRY, options.cveRegistry || {});
  }

  /**
   * Generate a SHA-256 fingerprint of a server's tool definitions.
   * Tool order is normalized so the hash is stable regardless of ordering.
   *
   * @param {object} server - Server definition with name and tools array.
   * @returns {string} Hex-encoded SHA-256 hash.
   */
  fingerprintServer(server) {
    const name = server && server.name ? server.name : 'unknown';
    const normalizedTools = (server && Array.isArray(server.tools) ? server.tools : []).map(tool => ({
      name: tool.name || '',
      description: tool.description || '',
      inputSchema: tool.inputSchema || {},
      permissions: Array.isArray(tool.permissions) ? tool.permissions.slice().sort() : []
    })).sort((a, b) => a.name.localeCompare(b.name));

    const payload = JSON.stringify({ name, tools: normalizedTools });
    return crypto.createHash('sha256').update(payload).digest('hex');
  }

  /**
   * Scan an MCP server for supply chain vulnerabilities.
   *
   * @param {object} server - { name: string, tools: Array<{ name, description, permissions, inputSchema }> }
   * @param {object} [context] - Optional context.
   * @param {string} [context.previousFingerprint] - Previous fingerprint for drift detection.
   * @returns {object} npm-audit-style report with findings, score, and recommendations.
   */
  scanServer(server, context = {}) {
    const findings = [];
    const serverName = (server && server.name) ? String(server.name) : 'unknown';
    const toolList = Array.isArray(server && server.tools) ? server.tools : [];

    // Check known-bad registry
    this._checkBadRegistry(serverName, findings);

    // Check CVE registry
    this._checkCves(serverName, findings);

    // Scan each tool
    for (const tool of toolList) {
      this._scanToolDescription(tool, findings);
      this._scanPermissions(tool, findings);
      this._scanSchema(tool, findings);
    }

    // Analyze escalation chains
    this._analyzeEscalationChains(toolList, findings);

    // Fingerprint drift check
    if (context.previousFingerprint) {
      const currentFp = this.fingerprintServer(server);
      if (context.previousFingerprint !== currentFp) {
        findings.push({
          type: 'tool_definition_drift',
          severity: 'critical',
          message: `Tool definitions changed for server "${serverName}". Previous fingerprint: ${context.previousFingerprint.substring(0, 12)}...`,
          recommendation: 'Pin MCP server version and require signed tool manifests. Re-attest before allowing tool calls.'
        });
      }
    }

    return this._buildReport(serverName, findings);
  }

  /**
   * Scan multiple servers at once.
   *
   * @param {Array<object>} servers - Array of server definitions.
   * @returns {object} Aggregate report.
   */
  scanMultiple(servers) {
    const reports = [];
    for (const server of (servers || [])) {
      reports.push(this.scanServer(server));
    }
    const totalFindings = reports.reduce((sum, r) => sum + r.findings.length, 0);
    const worstScore = reports.length > 0 ? Math.min(...reports.map(r => r.score)) : 100;
    return {
      serverCount: reports.length,
      totalFindings,
      worstScore,
      reports
    };
  }

  // -----------------------------------------------------------------------
  // Private scan methods
  // -----------------------------------------------------------------------

  /** @private */
  _checkBadRegistry(serverName, findings) {
    const entry = this.knownBadServers[serverName];
    if (!entry) return;
    findings.push({
      type: 'known_bad_server',
      severity: entry.severity || 'high',
      message: `"${serverName}" appears in known-bad MCP server registry: ${entry.reason}`,
      recommendation: 'Block this MCP server until independently reviewed and cleared.'
    });
  }

  /** @private */
  _checkCves(serverName, findings) {
    const cves = this.cveRegistry[serverName] || [];
    for (const entry of cves) {
      findings.push({
        type: 'cve_match',
        severity: entry.severity || 'high',
        message: `${entry.cve}: ${entry.description}`,
        recommendation: entry.fix || 'Upgrade to a patched release.'
      });
    }
  }

  /** @private */
  _scanToolDescription(tool, findings) {
    const description = tool && tool.description ? String(tool.description) : '';
    if (!description) return;

    // Check against injection patterns
    for (const pattern of DESCRIPTION_INJECTION_PATTERNS) {
      if (pattern.test(description)) {
        findings.push({
          type: 'hidden_prompt_injection',
          severity: 'high',
          message: `Tool "${tool.name || 'unknown'}" description contains hidden instructions: "${description.substring(0, 100)}"`,
          recommendation: 'Remove behavioral/imperative instructions from tool descriptions. Keep them purely declarative.'
        });
        break;
      }
    }

    // Also run through detector-core for broader coverage
    const detectorResult = scanText(description, { source: 'mcp_tool_description', sensitivity: 'high' });
    if (detectorResult && detectorResult.threats && detectorResult.threats.length > 0) {
      findings.push({
        type: 'detector_core_prompt_risk',
        severity: detectorResult.threats[0].severity || 'medium',
        message: `Tool "${tool.name || 'unknown'}" description triggered detector-core: ${detectorResult.threats[0].description || 'pattern match'}`,
        recommendation: 'Rewrite tool description to remove system-like or imperative instructions.'
      });
    }
  }

  /** @private */
  _scanPermissions(tool, findings) {
    const perms = Array.isArray(tool && tool.permissions) ? tool.permissions : [];
    for (const perm of perms) {
      if (BROAD_PERMISSION_PATTERNS.some(pattern => pattern.test(String(perm)))) {
        findings.push({
          type: 'broad_permission',
          severity: 'medium',
          message: `Tool "${tool.name || 'unknown'}" requests overly broad permission: "${perm}"`,
          recommendation: 'Replace wildcard/admin privileges with least-privilege scoped permissions.'
        });
      }
    }
  }

  /** @private */
  _scanSchema(tool, findings) {
    if (tool && tool.inputSchema && tool.inputSchema.additionalProperties === true) {
      findings.push({
        type: 'schema_over_permissive',
        severity: 'medium',
        message: `Tool "${tool.name || 'unknown'}" input schema allows arbitrary additional properties.`,
        recommendation: 'Set additionalProperties=false and explicitly whitelist expected fields.'
      });
    }
  }

  /** @private */
  _analyzeEscalationChains(tools, findings) {
    if (!Array.isArray(tools) || tools.length < 2) return;

    const hasCredentialReader = tools.some(t => /secret|credential|token|env|get.?key|password/i.test(t.name || ''));
    const hasExternalSender = tools.some(t => /http|webhook|request|send|post|fetch|curl/i.test(t.name || ''));
    const hasShellExec = tools.some(t => /exec|shell|bash|cmd|terminal|spawn/i.test(t.name || ''));
    const hasFileSystem = tools.some(t => /read.?file|write.?file|fs|filesystem/i.test(t.name || ''));

    if (hasCredentialReader && hasExternalSender) {
      findings.push({
        type: 'capability_escalation_chain',
        severity: 'high',
        message: 'Credential-access tool + outbound-network tool chain detected. An attacker could exfiltrate secrets.',
        recommendation: 'Isolate credential-access tools from outbound network tools. Enforce sequence guardrails.'
      });
    }

    if (hasFileSystem && hasShellExec) {
      findings.push({
        type: 'capability_escalation_chain',
        severity: 'high',
        message: 'Filesystem-access tool + shell-execution tool chain detected. An attacker could write and execute malicious scripts.',
        recommendation: 'Sandbox shell execution. Restrict filesystem write paths. Add confirmation gates.'
      });
    }
  }

  /**
   * Build an npm-audit-style report from findings.
   * @private
   */
  _buildReport(serverName, findings) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const finding of findings) {
      counts[finding.severity] = (counts[finding.severity] || 0) + 1;
    }

    // Sort findings by severity (critical first)
    findings.sort((a, b) => (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0));

    const highest = findings.length > 0
      ? findings.reduce((cur, f) => (SEVERITY_RANK[f.severity] || 0) > (SEVERITY_RANK[cur] || 0) ? f.severity : cur, 'low')
      : 'low';

    const score = Math.max(0, 100 - (counts.critical * 30 + counts.high * 18 + counts.medium * 8 + counts.low * 3));

    return {
      server: serverName,
      status: findings.length === 0 ? 'pass' : 'fail',
      score,
      highestSeverity: highest,
      summary: counts,
      findings,
      recommendations: [...new Set(findings.map(f => f.recommendation))],
      generatedAt: Date.now()
    };
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
  SupplyChainScanner,
  KNOWN_BAD_SERVERS,
  CVE_REGISTRY,
  DESCRIPTION_INJECTION_PATTERNS,
  BROAD_PERMISSION_PATTERNS
};
