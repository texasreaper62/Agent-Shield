'use strict';

/**
 * Agent Shield — Smart Configuration / Policy Engine (v12.0)
 *
 * Auto-configures Agent Shield based on deployment context. Provides presets
 * for common deployment scenarios (chatbot, coding agent, RAG pipeline,
 * MCP server, enterprise, paranoid) and generates complete configurations
 * with security recommendations.
 *
 * All processing runs locally — no data ever leaves your environment.
 *
 * @module smart-config
 */

// =========================================================================
// DEPLOYMENT PRESETS
// =========================================================================

/**
 * Predefined deployment presets with tuned security settings.
 * @type {Object<string, object>}
 */
const DEPLOYMENT_PRESETS = {
  chatbot: {
    name: 'Chatbot',
    description: 'Customer-facing conversational agent with moderate security',
    detection: {
      enablePatternScanner: true,
      enableMicroModel: true,
      enableIntentGraph: false,
      enableOWASP: false,
      sensitivity: 'medium',
      scanTimeout: 50
    },
    protection: {
      blockOnThreat: true,
      piiRedaction: true,
      canaryTokens: false,
      rateLimiting: true,
      rateLimit: { maxRequests: 60, windowMs: 60000 },
      circuitBreaker: { threshold: 10, resetMs: 30000 }
    },
    monitoring: {
      auditLog: true,
      metricsExport: false,
      alerting: false,
      shadowMode: false
    },
    compliance: {
      frameworks: ['gdpr'],
      dataRetention: '30d'
    }
  },

  coding_agent: {
    name: 'Coding Agent',
    description: 'AI coding assistant with tool execution capabilities',
    detection: {
      enablePatternScanner: true,
      enableMicroModel: true,
      enableIntentGraph: true,
      enableOWASP: true,
      sensitivity: 'high',
      scanTimeout: 100
    },
    protection: {
      blockOnThreat: true,
      piiRedaction: true,
      canaryTokens: true,
      rateLimiting: true,
      rateLimit: { maxRequests: 120, windowMs: 60000 },
      circuitBreaker: { threshold: 5, resetMs: 60000 },
      toolGuard: {
        enabled: true,
        blockedTools: ['exec', 'shell', 'eval'],
        requireApproval: ['writeFile', 'deleteFile', 'networkRequest'],
        maxChainDepth: 5
      }
    },
    monitoring: {
      auditLog: true,
      metricsExport: true,
      alerting: true,
      shadowMode: false
    },
    compliance: {
      frameworks: ['soc2'],
      dataRetention: '90d'
    }
  },

  rag_pipeline: {
    name: 'RAG Pipeline',
    description: 'Retrieval-augmented generation with document ingestion',
    detection: {
      enablePatternScanner: true,
      enableMicroModel: true,
      enableIntentGraph: true,
      enableOWASP: true,
      sensitivity: 'high',
      scanTimeout: 150,
      enableIPIA: true,
      enableDocumentScanner: true
    },
    protection: {
      blockOnThreat: true,
      piiRedaction: true,
      canaryTokens: true,
      rateLimiting: true,
      rateLimit: { maxRequests: 30, windowMs: 60000 },
      circuitBreaker: { threshold: 5, resetMs: 60000 },
      semanticIsolation: {
        enabled: true,
        trustLevels: { system: 'trusted', user: 'semi-trusted', rag_chunk: 'untrusted' }
      }
    },
    monitoring: {
      auditLog: true,
      metricsExport: true,
      alerting: true,
      shadowMode: false
    },
    compliance: {
      frameworks: ['soc2', 'gdpr'],
      dataRetention: '90d'
    }
  },

  mcp_server: {
    name: 'MCP Server',
    description: 'Model Context Protocol server with tool exposure',
    detection: {
      enablePatternScanner: true,
      enableMicroModel: true,
      enableIntentGraph: true,
      enableOWASP: true,
      sensitivity: 'high',
      scanTimeout: 100,
      enableSupplyChainScan: true
    },
    protection: {
      blockOnThreat: true,
      piiRedaction: true,
      canaryTokens: true,
      rateLimiting: true,
      rateLimit: { maxRequests: 100, windowMs: 60000 },
      circuitBreaker: { threshold: 3, resetMs: 120000 },
      mcpGuard: {
        enabled: true,
        attestation: true,
        ssrfFirewall: true,
        oauthEnforcement: true,
        crossServerIsolation: true,
        behaviorBaseline: true
      },
      intentBinding: { enabled: true },
      messageIntegrity: { enabled: true }
    },
    monitoring: {
      auditLog: true,
      metricsExport: true,
      alerting: true,
      shadowMode: false,
      driftMonitor: { enabled: true, windowSize: 100 }
    },
    compliance: {
      frameworks: ['soc2', 'owasp-agentic'],
      dataRetention: '180d'
    }
  },

  enterprise: {
    name: 'Enterprise',
    description: 'Enterprise deployment with full security, compliance, and monitoring',
    detection: {
      enablePatternScanner: true,
      enableMicroModel: true,
      enableIntentGraph: true,
      enableOWASP: true,
      sensitivity: 'high',
      scanTimeout: 200,
      enableIPIA: true,
      enableDocumentScanner: true,
      enableSupplyChainScan: true
    },
    protection: {
      blockOnThreat: true,
      piiRedaction: true,
      canaryTokens: true,
      rateLimiting: true,
      rateLimit: { maxRequests: 200, windowMs: 60000 },
      circuitBreaker: { threshold: 5, resetMs: 60000 },
      toolGuard: {
        enabled: true,
        blockedTools: ['exec', 'shell', 'eval'],
        requireApproval: [],
        maxChainDepth: 10
      },
      mcpGuard: {
        enabled: true,
        attestation: true,
        ssrfFirewall: true,
        oauthEnforcement: true,
        crossServerIsolation: true,
        behaviorBaseline: true
      },
      semanticIsolation: { enabled: true },
      intentBinding: { enabled: true },
      messageIntegrity: { enabled: true },
      multiTenant: { enabled: true },
      rbac: { enabled: true }
    },
    monitoring: {
      auditLog: true,
      metricsExport: true,
      alerting: true,
      shadowMode: false,
      driftMonitor: { enabled: true, windowSize: 200 },
      socIntegration: { enabled: true },
      immutableAudit: { enabled: true }
    },
    compliance: {
      frameworks: ['soc2', 'hipaa', 'gdpr', 'nist', 'owasp-agentic', 'eu-ai-act'],
      dataRetention: '365d',
      certificationLevel: 'gold'
    }
  },

  paranoid: {
    name: 'Paranoid',
    description: 'Maximum security — all detectors, all protections, strictest thresholds',
    detection: {
      enablePatternScanner: true,
      enableMicroModel: true,
      enableIntentGraph: true,
      enableOWASP: true,
      sensitivity: 'critical',
      scanTimeout: 500,
      enableIPIA: true,
      enableDocumentScanner: true,
      enableSupplyChainScan: true,
      enableBehaviorProfiling: true,
      enableHoneypot: true,
      enableSelfTraining: true,
      enableAttackSurface: true
    },
    protection: {
      blockOnThreat: true,
      piiRedaction: true,
      canaryTokens: true,
      rateLimiting: true,
      rateLimit: { maxRequests: 30, windowMs: 60000 },
      circuitBreaker: { threshold: 2, resetMs: 300000 },
      toolGuard: {
        enabled: true,
        blockedTools: ['exec', 'shell', 'eval', 'spawn', 'fork'],
        requireApproval: ['writeFile', 'deleteFile', 'networkRequest', 'databaseQuery'],
        maxChainDepth: 3
      },
      mcpGuard: {
        enabled: true,
        attestation: true,
        ssrfFirewall: true,
        oauthEnforcement: true,
        crossServerIsolation: true,
        behaviorBaseline: true
      },
      semanticIsolation: { enabled: true },
      intentBinding: { enabled: true },
      messageIntegrity: { enabled: true },
      promptHardening: { enabled: true, level: 4 },
      multiTenant: { enabled: true },
      rbac: { enabled: true }
    },
    monitoring: {
      auditLog: true,
      metricsExport: true,
      alerting: true,
      shadowMode: true,
      driftMonitor: { enabled: true, windowSize: 50 },
      socIntegration: { enabled: true },
      immutableAudit: { enabled: true },
      continuousSecurity: { enabled: true, intervalMs: 60000 }
    },
    compliance: {
      frameworks: ['soc2', 'hipaa', 'gdpr', 'nist', 'owasp-agentic', 'eu-ai-act'],
      dataRetention: '365d',
      certificationLevel: 'platinum'
    }
  }
};

// =========================================================================
// VALIDATION RULES
// =========================================================================

/**
 * Configuration validation rules.
 * @type {Array<{ check: function, message: string, severity: string }>}
 */
const VALIDATION_RULES = [
  {
    check: (cfg) => !cfg.detection?.enablePatternScanner && !cfg.detection?.enableMicroModel,
    message: 'No detection engine enabled — all threats will be missed',
    severity: 'critical'
  },
  {
    check: (cfg) => !cfg.protection?.blockOnThreat,
    message: 'Threat blocking is disabled — threats will be logged but not stopped',
    severity: 'high'
  },
  {
    check: (cfg) => !cfg.protection?.piiRedaction,
    message: 'PII redaction is disabled — personal data may leak to LLM providers',
    severity: 'high'
  },
  {
    check: (cfg) => !cfg.monitoring?.auditLog,
    message: 'Audit logging is disabled — no forensic trail for incidents',
    severity: 'medium'
  },
  {
    check: (cfg) => cfg.protection?.rateLimiting && !cfg.protection?.rateLimit?.maxRequests,
    message: 'Rate limiting enabled but no maxRequests set',
    severity: 'medium'
  },
  {
    check: (cfg) => cfg.protection?.mcpGuard?.enabled && !cfg.protection?.mcpGuard?.ssrfFirewall,
    message: 'MCP Guard enabled without SSRF firewall — CVE-2026-26118 risk',
    severity: 'high'
  },
  {
    check: (cfg) => cfg.protection?.mcpGuard?.enabled && !cfg.protection?.mcpGuard?.attestation,
    message: 'MCP Guard enabled without server attestation — tool rug-pull risk',
    severity: 'high'
  },
  {
    check: (cfg) => cfg.protection?.toolGuard?.enabled && (!cfg.protection?.toolGuard?.blockedTools || cfg.protection.toolGuard.blockedTools.length === 0),
    message: 'Tool guard enabled with empty blocklist — exec/shell/eval should be blocked',
    severity: 'medium'
  },
  {
    check: (cfg) => cfg.detection?.enableIPIA && !cfg.protection?.semanticIsolation?.enabled,
    message: 'IPIA detection enabled without semantic isolation — reduced effectiveness',
    severity: 'medium'
  },
  {
    check: (cfg) => !cfg.protection?.circuitBreaker,
    message: 'No circuit breaker configured — sustained attacks may overwhelm the system',
    severity: 'medium'
  },
  {
    check: (cfg) => cfg.detection?.scanTimeout && cfg.detection.scanTimeout > 300,
    message: 'Scan timeout exceeds 300ms — may impact user experience',
    severity: 'low'
  },
  {
    check: (cfg) => cfg.compliance?.frameworks?.includes('hipaa') && !cfg.monitoring?.immutableAudit?.enabled,
    message: 'HIPAA compliance requires immutable audit logging',
    severity: 'high'
  }
];

// =========================================================================
// SMART CONFIG CLASS
// =========================================================================

/**
 * Smart Configuration and Policy Engine.
 *
 * Analyzes deployment context and generates optimized security configurations.
 *
 * @example
 * const config = new SmartConfig();
 * const policy = config.generatePolicy('mcp_server');
 * const analysis = config.analyzeDeployment({
 *   tools: ['readFile', 'writeFile', 'exec'],
 *   model: 'claude-3-opus',
 *   mcpServers: ['filesystem', 'github']
 * });
 */
class SmartConfig {
  /**
   * @param {object} [options]
   * @param {Object<string, object>} [options.customPresets] - Additional presets to register
   */
  constructor(options = {}) {
    this.presets = { ...DEPLOYMENT_PRESETS };

    if (options.customPresets) {
      for (const [name, preset] of Object.entries(options.customPresets)) {
        this.presets[name] = preset;
      }
    }

    console.log(`[Agent Shield] SmartConfig initialized with ${Object.keys(this.presets).length} presets`);
  }

  /**
   * Analyze a deployment configuration and recommend security settings.
   * @param {object} deployment - Deployment context
   * @param {string[]} [deployment.tools] - Available tools
   * @param {string[]} [deployment.mcpServers] - Connected MCP servers
   * @param {string} [deployment.model] - LLM model name
   * @param {boolean} [deployment.hasRAG] - Whether RAG pipeline is present
   * @param {boolean} [deployment.isPublicFacing] - Whether agent faces external users
   * @param {string[]} [deployment.complianceNeeds] - Required compliance frameworks
   * @param {number} [deployment.expectedQPS] - Expected queries per second
   * @returns {{ recommendedPreset: string, reasons: string[], config: object, warnings: string[] }}
   */
  analyzeDeployment(deployment = {}) {
    const reasons = [];
    const warnings = [];
    let recommendedPreset = 'chatbot';
    let riskScore = 0;

    const tools = deployment.tools || [];
    const mcpServers = deployment.mcpServers || [];
    const complianceNeeds = deployment.complianceNeeds || [];

    // Analyze tool risk
    const dangerousTools = ['exec', 'shell', 'eval', 'spawn', 'fork', 'system'];
    const hasDangerousTools = tools.some(t => dangerousTools.includes(t.toLowerCase()));
    if (hasDangerousTools) {
      riskScore += 3;
      reasons.push('Dangerous tools detected (exec/shell/eval) — elevated protection required');
    }

    const fileTools = ['readFile', 'writeFile', 'deleteFile', 'listDir', 'mkdir'];
    const hasFileTools = tools.some(t => fileTools.includes(t));
    if (hasFileTools) {
      riskScore += 1;
      reasons.push('File system tools present — path traversal protection recommended');
    }

    const networkTools = ['fetch', 'httpRequest', 'networkRequest', 'curl'];
    const hasNetworkTools = tools.some(t => networkTools.includes(t));
    if (hasNetworkTools) {
      riskScore += 2;
      reasons.push('Network tools present — SSRF protection and domain allowlisting recommended');
    }

    // MCP servers
    if (mcpServers.length > 0) {
      riskScore += 2;
      reasons.push(`${mcpServers.length} MCP server(s) detected — MCP Guard recommended`);
      recommendedPreset = 'mcp_server';
    }

    // RAG pipeline
    if (deployment.hasRAG) {
      riskScore += 2;
      reasons.push('RAG pipeline detected — IPIA detection and semantic isolation recommended');
      if (recommendedPreset === 'chatbot') {
        recommendedPreset = 'rag_pipeline';
      }
    }

    // Public facing
    if (deployment.isPublicFacing) {
      riskScore += 1;
      reasons.push('Public-facing deployment — stricter rate limiting and PII redaction recommended');
    }

    // Compliance
    if (complianceNeeds.length > 0) {
      riskScore += 1;
      reasons.push(`Compliance requirements: ${complianceNeeds.join(', ')}`);
      if (complianceNeeds.includes('hipaa') || complianceNeeds.includes('soc2')) {
        recommendedPreset = 'enterprise';
      }
    }

    // Coding agent detection
    const codeTools = ['readFile', 'writeFile', 'exec', 'shell', 'runCode', 'compile'];
    const hasCodeTools = tools.filter(t => codeTools.includes(t)).length >= 2;
    if (hasCodeTools && recommendedPreset === 'chatbot') {
      recommendedPreset = 'coding_agent';
      reasons.push('Code execution tools detected — coding agent preset recommended');
    }

    // High risk override
    if (riskScore >= 7) {
      recommendedPreset = 'paranoid';
      reasons.push(`Risk score ${riskScore}/10 — paranoid preset recommended`);
    } else if (riskScore >= 5 && recommendedPreset !== 'enterprise') {
      recommendedPreset = 'enterprise';
      reasons.push(`Risk score ${riskScore}/10 — enterprise preset recommended`);
    }

    // QPS warnings
    if (deployment.expectedQPS && deployment.expectedQPS > 100) {
      warnings.push('High QPS expected — consider enabling worker scanner for non-blocking scans');
    }

    // Generate config from recommended preset
    const config = this.generatePolicy(recommendedPreset);

    // Apply deployment-specific overrides
    if (complianceNeeds.length > 0) {
      config.compliance = config.compliance || {};
      config.compliance.frameworks = [...new Set([...(config.compliance.frameworks || []), ...complianceNeeds])];
    }

    return {
      recommendedPreset,
      reasons,
      config,
      warnings,
      riskScore
    };
  }

  /**
   * Generate a complete security policy configuration from a preset.
   * @param {string} preset - Preset name
   * @returns {object} Complete security configuration
   */
  generatePolicy(preset) {
    const presetConfig = this.presets[preset];
    if (!presetConfig) {
      const available = Object.keys(this.presets).join(', ');
      throw new Error(`Unknown preset "${preset}". Available: ${available}`);
    }

    // Deep clone the preset config
    const config = JSON.parse(JSON.stringify(presetConfig));

    // Add metadata
    config._metadata = {
      preset,
      generatedAt: new Date().toISOString(),
      generatedBy: 'Agent Shield SmartConfig',
      version: '12.0'
    };

    return config;
  }

  /**
   * Validate a configuration for misconfigurations and security gaps.
   * @param {object} config - Configuration to validate
   * @returns {{ valid: boolean, issues: Array<{ message: string, severity: string }>, score: number }}
   */
  validateConfig(config) {
    if (!config || typeof config !== 'object') {
      return {
        valid: false,
        issues: [{ message: 'Configuration is empty or invalid', severity: 'critical' }],
        score: 0
      };
    }

    const issues = [];

    for (const rule of VALIDATION_RULES) {
      try {
        if (rule.check(config)) {
          issues.push({ message: rule.message, severity: rule.severity });
        }
      } catch (_e) {
        // Rule check failed — skip silently
      }
    }

    // Compute security score (0-100)
    const severityPenalty = { critical: 25, high: 15, medium: 8, low: 3 };
    let penalty = 0;
    for (const issue of issues) {
      penalty += severityPenalty[issue.severity] || 5;
    }
    const score = Math.max(0, 100 - penalty);

    const hasCritical = issues.some(i => i.severity === 'critical');
    const valid = !hasCritical && score >= 50;

    return { valid, issues, score };
  }

  /**
   * List all available preset names.
   * @returns {string[]}
   */
  listPresets() {
    return Object.keys(this.presets);
  }

  /**
   * Get a preset by name.
   * @param {string} name - Preset name
   * @returns {object|null}
   */
  getPreset(name) {
    return this.presets[name] || null;
  }

  /**
   * Register a custom preset.
   * @param {string} name - Preset name
   * @param {object} config - Preset configuration
   */
  registerPreset(name, config) {
    if (!name || typeof name !== 'string') {
      throw new Error('Preset name is required');
    }
    this.presets[name] = config;
    console.log(`[Agent Shield] Custom preset "${name}" registered`);
  }

  /**
   * Compare two presets and show differences.
   * @param {string} presetA - First preset name
   * @param {string} presetB - Second preset name
   * @returns {object} Comparison summary
   */
  comparePresets(presetA, presetB) {
    const a = this.presets[presetA];
    const b = this.presets[presetB];
    if (!a || !b) {
      throw new Error(`Preset not found: ${!a ? presetA : presetB}`);
    }

    const differences = [];

    const compare = (objA, objB, path = '') => {
      const allKeys = new Set([...Object.keys(objA || {}), ...Object.keys(objB || {})]);
      for (const key of allKeys) {
        const fullPath = path ? `${path}.${key}` : key;
        const va = objA?.[key];
        const vb = objB?.[key];

        if (va !== undefined && vb === undefined) {
          differences.push({ path: fullPath, inA: va, inB: undefined });
        } else if (va === undefined && vb !== undefined) {
          differences.push({ path: fullPath, inA: undefined, inB: vb });
        } else if (typeof va === 'object' && va !== null && typeof vb === 'object' && vb !== null && !Array.isArray(va)) {
          compare(va, vb, fullPath);
        } else if (JSON.stringify(va) !== JSON.stringify(vb)) {
          differences.push({ path: fullPath, inA: va, inB: vb });
        }
      }
    };

    compare(a, b);

    return {
      presetA,
      presetB,
      differences,
      differenceCount: differences.length
    };
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
  SmartConfig,
  DEPLOYMENT_PRESETS,
  VALIDATION_RULES
};
