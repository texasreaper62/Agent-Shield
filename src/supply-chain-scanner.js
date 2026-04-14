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

let MicroModel = null;
try { MicroModel = require('./micro-model').MicroModel; } catch { /* optional */ }

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
  },
  'aws-mcp-server-unpatched': {
    reason: 'Multiple critical RCE vulnerabilities (CVE-2026-5058, CVE-2026-5059)',
    severity: 'critical'
  },
  'flowise-unpatched': {
    reason: 'CVSS 10.0 RCE actively exploited (CVE-2025-59528)',
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
  ],
  'azure-mcp-server': [
    {
      cve: 'CVE-2026-26118',
      severity: 'critical',
      description: 'Azure MCP Server SSRF (CVSS 8.8). Attacker sends crafted URL via tool parameter, server forwards request with managed identity token to attacker-controlled endpoint.',
      fix: 'Apply March 2026 Patch Tuesday update. Validate all URLs against allowlists. Block private IPs and cloud metadata endpoints (169.254.169.254).'
    },
    {
      cve: 'CVE-2026-32211',
      severity: 'critical',
      description: 'Azure MCP Server lacks authentication entirely (CVSS 9.1), allowing unauthorized access to sensitive data.',
      fix: 'Enable authentication on Azure MCP Server. Never deploy without auth.'
    }
  ],
  'adx-mcp-server': [
    {
      cve: 'CVE-2026-33980',
      severity: 'critical',
      description: 'Azure Data Explorer MCP Server KQL injection. table_name parameter interpolated directly into Kusto queries via f-strings without validation.',
      fix: 'Parameterize all KQL queries. Never interpolate user-controlled values via f-strings. Upgrade adx-mcp-server to patched version.'
    }
  ],
  'openclaw': [
    {
      cve: 'CVE-2026-25253',
      severity: 'critical',
      description: 'OpenClaw WebSocket token theft (CVSS 8.8). Control UI accepts gatewayUrl query parameter without validation, redirecting WebSocket to attacker server and leaking auth tokens.',
      fix: 'Upgrade to OpenClaw >=2026.1.29. Validate gatewayUrl against allowlist. Never pass auth tokens to unvalidated endpoints.'
    },
    {
      cve: 'CVE-2026-33579',
      severity: 'critical',
      description: 'Silent admin takeover. Attacker gains full admin access without detection. Patched April 5 2026.',
      fix: 'Upgrade OpenClaw immediately. Audit admin access logs.'
    },
    {
      cve: 'CVE-2026-24763',
      severity: 'high',
      description: 'Command injection in OpenClaw.',
      fix: 'Upgrade OpenClaw to latest patched version.'
    },
    {
      cve: 'CVE-2026-26322',
      severity: 'high',
      description: 'SSRF in OpenClaw.',
      fix: 'Upgrade OpenClaw to latest patched version.'
    },
    {
      cve: 'CVE-2026-26329',
      severity: 'high',
      description: 'Path traversal enables local file reads in OpenClaw.',
      fix: 'Upgrade OpenClaw to latest patched version.'
    },
    {
      cve: 'CVE-2026-30741',
      severity: 'critical',
      description: 'Prompt-injection-driven code execution in OpenClaw.',
      fix: 'Upgrade OpenClaw to latest patched version.'
    }
  ],
  'mcp-typescript-sdk': [
    {
      cve: 'CVE-2026-25536',
      severity: 'high',
      description: 'Cross-client data leak in the official MCP TypeScript SDK allows data from one client session to leak to another.',
      fix: 'Upgrade @modelcontextprotocol/sdk to patched version. Ensure per-client session isolation.'
    }
  ],
  'n8n': [
    {
      cve: 'CVE-2026-21858',
      severity: 'critical',
      description: 'n8n AI workflow platform RCE (CVSS 10.0). Unauthenticated file leak via web forms + full server takeover enabling arbitrary command execution.',
      fix: 'Upgrade n8n to patched release. Restrict web form access. Run n8n behind authentication proxy.'
    }
  ],
  'microsoft-excel-copilot': [
    {
      cve: 'CVE-2026-26144',
      severity: 'critical',
      description: 'Microsoft Excel XSS weaponizes Copilot Agent for zero-click data exfiltration via unintended network egress.',
      fix: 'Apply March 2026 Patch Tuesday update. Restrict Copilot Agent network access in enterprise policies.'
    }
  ],
  'fastmcp': [
    {
      cve: 'CVE-2026-32871',
      severity: 'critical',
      description: 'FastMCP OpenAPI Provider SSRF + Path Traversal (CVSS 10.0). _build_url() does not URL-encode path parameters. urljoin() interprets ../ sequences, allowing attackers to escape API prefix and access arbitrary backend endpoints with the server\'s auth headers.',
      fix: 'Upgrade FastMCP to >=3.2.0. Validate and URL-encode all path parameters before URL construction.'
    }
  ],
  'claude-code': [
    {
      cve: 'CVE-2025-59536',
      severity: 'critical',
      description: 'Claude Code code injection (CVSS 8.7). Malicious repo configs exploit Hooks to auto-execute arbitrary shell commands when a user starts Claude Code in an untrusted directory.',
      fix: 'Upgrade Claude Code to >=1.0.111. Never open untrusted repos without reviewing .claude/ config files first.'
    },
    {
      cve: 'CVE-2026-21852',
      severity: 'high',
      description: 'Claude Code API key exfiltration (CVSS 5.3). ANTHROPIC_BASE_URL can be overridden in project config to redirect all API calls to attacker server, leaking API keys with zero user interaction.',
      fix: 'Upgrade Claude Code to >=2.0.65. Audit project .claude/ settings for ANTHROPIC_BASE_URL overrides.'
    }
  ],
  'mcpjam-inspector': [
    {
      cve: 'CVE-2026-23744',
      severity: 'critical',
      description: 'MCPJam Inspector RCE. HTTP server binds to 0.0.0.0 by default with no authentication on server management endpoint. Any device on the same network can execute arbitrary commands.',
      fix: 'Upgrade MCPJam Inspector to >=1.4.3. Bind to 127.0.0.1 only. Add authentication to management endpoints.'
    }
  ],
  'aws-mcp-server': [
    {
      cve: 'CVE-2026-5058',
      severity: 'critical',
      description: 'Command injection in aws-mcp-server (CVSS 9.8) allows remote code execution without authentication.',
      fix: 'Upgrade aws-mcp-server. Sanitize all CLI arguments. Block shell metacharacters.'
    },
    {
      cve: 'CVE-2026-5059',
      severity: 'critical',
      description: 'Remote code execution in aws-mcp-server via unsanitized inputs.',
      fix: 'Upgrade aws-mcp-server to latest patched version.'
    }
  ],
  'vscode-mcp': [
    {
      cve: 'CVE-2026-21518',
      severity: 'high',
      description: 'VS Code mcp.json command injection. Opening malicious project executes arbitrary code through mcp.json file handling.',
      fix: 'Update VS Code. Never open untrusted projects. Audit mcp.json files before opening.'
    }
  ],
  'flowise': [
    {
      cve: 'CVE-2025-59528',
      severity: 'critical',
      description: 'Code injection in Flowise MCP node (CVSS 10.0) allows remote code execution. 12,000-15,000 instances exposed. Actively exploited since April 6.',
      fix: 'Upgrade Flowise to >=3.0.6. Restrict access to MCP node.'
    },
    {
      cve: 'CVE-2025-8943',
      severity: 'critical',
      description: 'Missing authentication in Flowise.',
      fix: 'Upgrade Flowise. Enable authentication.'
    },
    {
      cve: 'CVE-2025-26319',
      severity: 'critical',
      description: 'Arbitrary file upload in Flowise.',
      fix: 'Upgrade Flowise to latest.'
    }
  ],
  'mcp-data-vis': [
    {
      cve: 'CVE-2026-5322',
      severity: 'high',
      description: 'SQL injection in AlejandroArciniegas mcp-data-vis.',
      fix: 'Avoid using mcp-data-vis or patch SQL query handling.'
    }
  ],
  'chatbox-mcp': [
    {
      cve: 'CVE-2026-6130',
      severity: 'high',
      description: 'OS command injection in chatboxai chatbox MCP server management.',
      fix: 'Upgrade chatbox. Sanitize all management API inputs.'
    }
  ],
  'codebase-mcp': [
    {
      cve: 'CVE-2026-5023',
      severity: 'high',
      description: 'OS command injection RCE in codebase-mcp.',
      fix: 'Upgrade codebase-mcp. Never pass unsanitized inputs to shell.'
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

/** Patterns that indicate hidden injection in JSON schema fields (full-schema poisoning).
 *  Ref: CyberArk research — attack surface extends beyond descriptions to entire tool schema. */
const SCHEMA_POISONING_PATTERNS = [
  /ignore\s+(all\s+)?(previous|prior)\s+(instructions|rules)/i,
  /do\s+not\s+tell\s+the\s+user/i,
  /secretly\s+(execute|send|forward|run|exfiltrate)/i,
  /override\s+(all\s+)?(system|safety)/i,
  /system\s*:\s*new\s+instructions/i,
  /before\s+responding.*first\s+(send|forward|post)/i,
  /hidden\s+instruction/i,
  /act\s+as\s+(a|an)\s+unrestricted/i
];

/** SSRF target patterns — private IPs, cloud metadata endpoints.
 *  Ref: CVE-2026-26118 (Azure MCP SSRF), 36.7% of MCP servers vulnerable. */
const SSRF_PATTERNS = [
  /169\.254\.169\.254/,
  /metadata\.google/,
  /metadata\.aws/,
  /100\.100\.100\.200/,
  /^(?:https?:\/\/)?(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})/,
  /^(?:https?:\/\/)?(?:172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})/,
  /^(?:https?:\/\/)?(?:192\.168\.\d{1,3}\.\d{1,3})/,
  /^(?:https?:\/\/)?(?:127\.0\.0\.1|0\.0\.0\.0|localhost)/
];

/** Known malicious skill/plugin patterns (ref ClawHavoc campaign — 1,184+ malicious skills found on ClawHub). */
const CLAWHAVOC_INDICATORS = [
  /(?:reverse.?shell|bind.?shell)/i,
  /(?:AMOS|atomic.?macos.?stealer)/i,
  /(?:eval|exec)\s*\(\s*(?:atob|Buffer\.from|decodeURI)/i,
  /(?:child_process|spawn|execSync)\s*\(/i,
  /(?:net\.connect|dgram|tls\.connect)\s*\(/i,
  /(?:curl|wget)\s+.*\|\s*(?:bash|sh|node|python)/i,
  /(?:bcc|forward|redirect)\s+.*(?:to|@)\s+[^\s]+\.[a-z]{2,}/i
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
    this.microModel = options.enableMicroModel && MicroModel ? new MicroModel() : null;
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
      this._scanFullSchema(tool, findings);
      this._scanPermissions(tool, findings);
      this._scanSchema(tool, findings);
      this._scanForSSRF(tool, findings);
      this._scanForClawHavoc(tool, findings);
    }

    // Analyze escalation chains
    this._analyzeEscalationChains(toolList, findings);

    // Auth quality assessment
    if (context.auth) {
      this._assessAuthQuality(context.auth, serverName, findings);
    }

    // Config file poisoning check (ref CVE-2025-59536, CVE-2026-21852)
    if (context.configFiles) {
      this._scanConfigFiles(context.configFiles, findings);
    }

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
  // Report formats
  // -----------------------------------------------------------------------

  /**
   * Convert a scan report to SARIF 2.1.0 format for CI/CD integration
   * (GitHub Code Scanning, VS Code SARIF Viewer, etc.).
   *
   * @param {object} report - Report from scanServer().
   * @returns {object} SARIF 2.1.0 object.
   */
  toSARIF(report) {
    const rules = [
      { id: 'SCS001', name: 'Known Bad Server', shortDescription: { text: 'MCP server appears in known-bad registry' } },
      { id: 'SCS002', name: 'CVE Match', shortDescription: { text: 'MCP server has known CVE vulnerability' } },
      { id: 'SCS003', name: 'Hidden Prompt Injection', shortDescription: { text: 'Tool description contains hidden injection instructions' } },
      { id: 'SCS004', name: 'Broad Permission', shortDescription: { text: 'Tool requests overly broad permissions' } },
      { id: 'SCS005', name: 'Schema Over-Permissive', shortDescription: { text: 'Tool input schema allows arbitrary properties' } },
      { id: 'SCS006', name: 'Capability Escalation Chain', shortDescription: { text: 'Tool combination enables multi-step attack' } },
      { id: 'SCS007', name: 'Tool Definition Drift', shortDescription: { text: 'Tool definitions changed since last attestation (rugpull)' } },
      { id: 'SCS008', name: 'Schema Field Poisoning', shortDescription: { text: 'Hidden instructions in non-description schema fields' } },
      { id: 'SCS009', name: 'SSRF Vector', shortDescription: { text: 'Tool accepts URL parameters without validation' } },
      { id: 'SCS010', name: 'Malicious Skill Pattern', shortDescription: { text: 'Tool matches known malicious skill indicators' } },
      { id: 'SCS011', name: 'Detector Core Risk', shortDescription: { text: 'Tool description triggered pattern-based detection' } },
      { id: 'SCS012', name: 'Micro-Model Detection', shortDescription: { text: 'Tool flagged by ML-based threat classifier' } }
    ];

    const typeToRuleId = {
      known_bad_server: 'SCS001',
      cve_match: 'SCS002',
      hidden_prompt_injection: 'SCS003',
      broad_permission: 'SCS004',
      schema_over_permissive: 'SCS005',
      capability_escalation_chain: 'SCS006',
      tool_definition_drift: 'SCS007',
      schema_field_poisoning: 'SCS008',
      ssrf_vector: 'SCS009',
      ssrf_target_in_schema: 'SCS009',
      malicious_skill_pattern: 'SCS010',
      detector_core_prompt_risk: 'SCS011',
      micro_model_detection: 'SCS012'
    };

    const results = report.findings.map(f => ({
      ruleId: typeToRuleId[f.type] || 'SCS001',
      level: f.severity === 'critical' ? 'error' : f.severity === 'high' ? 'warning' : 'note',
      message: { text: f.message },
      properties: {
        severity: f.severity,
        findingType: f.type,
        recommendation: f.recommendation,
        server: report.server
      }
    }));

    return {
      version: '2.1.0',
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      runs: [{
        tool: {
          driver: {
            name: 'Agent Shield Supply Chain Scanner',
            version: '11.0.0',
            rules
          }
        },
        results
      }]
    };
  }

  /**
   * Convert a scan report to Markdown format.
   *
   * @param {object} report - Report from scanServer().
   * @returns {string}
   */
  toMarkdown(report) {
    const lines = [
      '# MCP Supply Chain Scan',
      '',
      `- **Server:** ${report.server}`,
      `- **Status:** ${report.status.toUpperCase()}`,
      `- **Score:** ${report.score}/100`,
      `- **Highest Severity:** ${report.highestSeverity}`,
      ''
    ];

    if (report.findings.length === 0) {
      lines.push('No supply chain issues detected.');
      return lines.join('\n');
    }

    lines.push('## Findings');
    lines.push('');
    lines.push('| Severity | Type | Message |');
    lines.push('|----------|------|---------|');
    for (const f of report.findings) {
      lines.push(`| ${f.severity} | ${f.type} | ${f.message.substring(0, 100)} |`);
    }

    lines.push('');
    lines.push('## Summary');
    lines.push(`| Critical | High | Medium | Low |`);
    lines.push(`|----------|------|--------|-----|`);
    lines.push(`| ${report.summary.critical} | ${report.summary.high} | ${report.summary.medium} | ${report.summary.low} |`);

    if (report.recommendations.length > 0) {
      lines.push('');
      lines.push('## Recommendations');
      for (const rec of report.recommendations) {
        lines.push(`- ${rec}`);
      }
    }

    return lines.join('\n');
  }

  /**
   * Get a CI/CD exit code based on scan results.
   * 0 = pass, 1 = warnings, 2 = critical failures.
   *
   * @param {object} report - Report from scanServer().
   * @param {object} [options]
   * @param {string} [options.failOn='high'] - Minimum severity to fail: 'critical', 'high', 'medium', 'low'.
   * @returns {{ exitCode: number, reason: string }}
   */
  getCIExitCode(report, options = {}) {
    const failOn = options.failOn || 'high';
    const severityRank = { critical: 4, high: 3, medium: 2, low: 1 };
    const threshold = severityRank[failOn] || 3;

    const failingFindings = report.findings.filter(f => (severityRank[f.severity] || 0) >= threshold);

    if (failingFindings.length === 0) {
      return { exitCode: 0, reason: 'All checks passed.' };
    }

    const hasCritical = failingFindings.some(f => f.severity === 'critical');
    return {
      exitCode: hasCritical ? 2 : 1,
      reason: `${failingFindings.length} finding(s) at or above "${failOn}" severity. ${hasCritical ? 'Critical issues found.' : 'Review recommended.'}`
    };
  }

  /**
   * Enforce security policy — throws if scan fails.
   * Use in CI/CD pipelines to block deployments.
   *
   * @param {object} server - Server definition.
   * @param {object} [options]
   * @param {string} [options.failOn='high'] - Minimum severity to fail.
   * @param {object} [options.context] - Scan context.
   * @returns {object} Report if scan passes.
   * @throws {Error} If scan fails policy.
   */
  enforce(server, options = {}) {
    const report = this.scanServer(server, options.context || {});
    const { exitCode, reason } = this.getCIExitCode(report, { failOn: options.failOn });

    if (exitCode > 0) {
      const err = new Error(`[Agent Shield] Supply chain scan failed: ${reason}`);
      err.exitCode = exitCode;
      err.report = report;
      throw err;
    }

    return report;
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

    // Micro-model scan for March 2026 attack patterns
    if (this.microModel) {
      const modelResult = this.microModel.scan(description);
      if (modelResult.threats && modelResult.threats.length > 0) {
        findings.push({
          type: 'micro_model_detection',
          severity: modelResult.threats[0].severity || 'high',
          message: `Tool "${tool.name || 'unknown'}" description flagged by micro-model: ${modelResult.threats[0].category} (confidence: ${(modelResult.threats[0].confidence * 100).toFixed(0)}%)`,
          recommendation: 'Review tool description for supply chain attack patterns (SSRF, schema poisoning, memory poisoning, exfiltration).'
        });
      }
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
   * Scan config files for poisoning (malicious hooks, URL overrides).
   * Ref: CVE-2025-59536 (Claude Code Hooks RCE), CVE-2026-21852 (API key theft).
   * @private
   */
  _scanConfigFiles(configFiles, findings) {
    const dangerousHooks = /(?:preToolCall|postToolCall|onSessionStart|afterResponse|hooks)\s*[=:]/i;
    const urlOverride = /(?:ANTHROPIC_BASE_URL|OPENAI_BASE_URL|API_BASE|baseUrl|base_url)\s*[=:]\s*['"]?https?:\/\//i;
    const shellCommands = /(?:curl|wget|bash|sh|node|python|nc|ncat|exec|eval)\b/i;
    const mcpAutoApprove = /(?:autoApprove|auto_approve|allowAll|trust_all)["']?\s*[=:]\s*(?:true|yes|1|"true")/i;

    for (const file of (Array.isArray(configFiles) ? configFiles : [])) {
      const content = typeof file === 'string' ? file : (file.content || '');
      const name = (file && file.name) || 'unknown config';

      if (dangerousHooks.test(content) && shellCommands.test(content)) {
        findings.push({
          type: 'config_hook_injection',
          severity: 'critical',
          message: `Config file "${name}" contains hooks with shell command execution (ref CVE-2025-59536).`,
          recommendation: 'Remove shell commands from hook definitions. Audit all .claude/ and .cursor/ config files in repos before opening.'
        });
      }

      if (urlOverride.test(content)) {
        const match = content.match(/(?:ANTHROPIC_BASE_URL|OPENAI_BASE_URL|API_BASE|baseUrl|base_url)\s*[=:]\s*['"]?(https?:\/\/[^\s'"]+)/i);
        const url = match ? match[1] : '';
        if (url && !/api\.anthropic\.com|api\.openai\.com|localhost|127\.0\.0\.1/.test(url)) {
          findings.push({
            type: 'config_url_override',
            severity: 'critical',
            message: `Config file "${name}" overrides API URL to "${url.substring(0, 80)}" (ref CVE-2026-21852). Potential credential theft.`,
            recommendation: 'Remove API URL overrides from project config. Only use official API endpoints.'
          });
        }
      }

      if (mcpAutoApprove.test(content)) {
        findings.push({
          type: 'config_auto_approve',
          severity: 'high',
          message: `Config file "${name}" auto-approves MCP servers without user consent.`,
          recommendation: 'Disable auto-approve. Require explicit user confirmation for each MCP server.'
        });
      }
    }
  }

  /**
   * Assess authentication quality for an MCP server.
   * Ref: 38% of public MCP servers lack authentication entirely.
   * @private
   */
  _assessAuthQuality(auth, serverName, findings) {
    if (!auth || auth.type === 'none') {
      findings.push({
        type: 'no_authentication',
        severity: 'critical',
        message: `Server "${serverName}" has no authentication configured. 38% of MCP servers share this vulnerability.`,
        recommendation: 'Add OAuth 2.0 or API key authentication. Never run MCP servers without auth.'
      });
      return;
    }

    // Weak token check
    if (auth.token && auth.token.length < 32) {
      findings.push({
        type: 'weak_auth_token',
        severity: 'high',
        message: `Server "${serverName}" uses a short auth token (${auth.token.length} chars). Minimum recommended: 32.`,
        recommendation: 'Use cryptographically random tokens of at least 32 characters.'
      });
    }

    // No expiry
    if (auth.type === 'oauth' && !auth.expiresAt && !auth.exp) {
      findings.push({
        type: 'no_token_expiry',
        severity: 'medium',
        message: `Server "${serverName}" OAuth token has no expiration. Compromised tokens persist indefinitely.`,
        recommendation: 'Set token expiry to 1 hour maximum. Implement token rotation.'
      });
    }

    // No scopes
    if (auth.type === 'oauth' && (!auth.scopes || auth.scopes.length === 0)) {
      findings.push({
        type: 'no_scope_restriction',
        severity: 'medium',
        message: `Server "${serverName}" OAuth token has no scope restrictions. Agent has unlimited access.`,
        recommendation: 'Define least-privilege scopes for each MCP server connection.'
      });
    }

    // Default/common credentials
    const weakPatterns = /^(?:test|admin|password|12345|secret|default|changeme|token)/i;
    if (auth.token && weakPatterns.test(auth.token)) {
      findings.push({
        type: 'default_credentials',
        severity: 'critical',
        message: `Server "${serverName}" appears to use default or common credentials.`,
        recommendation: 'Generate unique, cryptographically random credentials for each server.'
      });
    }
  }

  /**
   * Full-schema poisoning scan. Checks ALL schema fields (default, enum, title,
   * examples, const, pattern) for hidden instructions — not just descriptions.
   * Ref: CyberArk research "Poison Everywhere" — the true attack surface extends
   * across the entire tool schema.
   * @private
   */
  _scanFullSchema(tool, findings) {
    if (!tool || !tool.inputSchema) return;
    const strings = this._extractAllSchemaStrings(tool.inputSchema);
    for (const str of strings) {
      for (const pattern of SCHEMA_POISONING_PATTERNS) {
        if (pattern.test(str)) {
          findings.push({
            type: 'schema_field_poisoning',
            severity: 'critical',
            message: `Tool "${tool.name || 'unknown'}" has hidden instructions in schema fields: "${str.substring(0, 100)}"`,
            recommendation: 'Audit ALL schema fields (default, enum, title, examples, const). Remove imperative instructions from any schema property.'
          });
          return; // One finding per tool is enough
        }
      }
    }
  }

  /**
   * Recursively extract all string values from a JSON schema object.
   * @private
   */
  _extractAllSchemaStrings(obj, depth = 0) {
    if (depth > 10) return [];
    const strings = [];
    if (typeof obj === 'string') {
      if (obj.length > 5) strings.push(obj);
      return strings;
    }
    if (Array.isArray(obj)) {
      for (const item of obj) strings.push(...this._extractAllSchemaStrings(item, depth + 1));
      return strings;
    }
    if (obj && typeof obj === 'object') {
      for (const key of Object.keys(obj)) {
        // Skip 'type' and '$schema' — not useful attack surface
        if (key === 'type' || key === '$schema') continue;
        strings.push(...this._extractAllSchemaStrings(obj[key], depth + 1));
      }
    }
    return strings;
  }

  /**
   * Scan for SSRF attack vectors in tool definitions.
   * Ref: CVE-2026-26118, 36.7% of URL-accepting MCP servers vulnerable.
   * @private
   */
  _scanForSSRF(tool, findings) {
    if (!tool || !tool.inputSchema) return;
    const schema = tool.inputSchema;

    // Check if tool accepts URL parameters without validation
    const props = schema.properties || {};
    for (const [propName, propSchema] of Object.entries(props)) {
      if (/url|uri|endpoint|host|address|target|dest/i.test(propName)) {
        // URL-accepting parameter found — check for validation
        if (!propSchema.pattern && !propSchema.format && !propSchema.enum) {
          findings.push({
            type: 'ssrf_vector',
            severity: 'high',
            message: `Tool "${tool.name || 'unknown'}" accepts URL parameter "${propName}" without validation. SSRF risk (ref CVE-2026-26118).`,
            recommendation: 'Add URL allowlists. Block private IP ranges (10.x, 172.16.x, 192.168.x) and cloud metadata endpoints (169.254.169.254).'
          });
        }
      }
    }

    // Check default values for SSRF targets
    const allStrings = this._extractAllSchemaStrings(schema);
    for (const str of allStrings) {
      for (const pattern of SSRF_PATTERNS) {
        if (pattern.test(str)) {
          findings.push({
            type: 'ssrf_target_in_schema',
            severity: 'critical',
            message: `Tool "${tool.name || 'unknown'}" schema contains private/metadata IP: "${str.substring(0, 80)}"`,
            recommendation: 'Remove references to private IPs and cloud metadata endpoints from tool schemas.'
          });
          return;
        }
      }
    }
  }

  /**
   * Scan tool code/description for ClawHavoc-style malicious patterns.
   * Ref: 1,184+ malicious skills found on ClawHub, delivering AMOS stealer.
   * @private
   */
  _scanForClawHavoc(tool, findings) {
    const sources = [
      tool.description || '',
      tool.code || '',
      tool.script || '',
      JSON.stringify(tool.inputSchema || {})
    ].join(' ');

    for (const pattern of CLAWHAVOC_INDICATORS) {
      if (pattern.test(sources)) {
        findings.push({
          type: 'malicious_skill_pattern',
          severity: 'critical',
          message: `Tool "${tool.name || 'unknown'}" matches ClawHavoc malicious skill indicators: ${pattern.source.substring(0, 60)}`,
          recommendation: 'Block this skill. Scan all skills from untrusted registries. Only use signed skills from verified publishers.'
        });
        return;
      }
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
  BROAD_PERMISSION_PATTERNS,
  SCHEMA_POISONING_PATTERNS,
  SSRF_PATTERNS,
  CLAWHAVOC_INDICATORS
};
