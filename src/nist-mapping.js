'use strict';

/**
 * Agent Shield — NIST AI RMF Mapping & AI-BOM Generator
 *
 * Maps Agent Shield capabilities to the NIST AI Risk Management Framework
 * (2025 updates). Generates AI Bill of Materials (AI-BOM) for compliance.
 *
 * All processing runs locally — no data ever leaves your environment.
 */

// =========================================================================
// NIST AI RMF 2025 Framework
// =========================================================================

/**
 * NIST AI RMF functions, categories, and subcategories with Agent Shield mapping.
 * @type {object}
 */
const NIST_AI_RMF_2025 = {
  version: '1.0-2025',
  functions: {
    GOVERN: {
      name: 'Govern',
      description: 'Establish and maintain AI risk management culture, accountability, and policies.',
      categories: [
        { id: 'GOVERN-1', name: 'AI Risk Culture', description: 'Foster organizational culture for AI risk management', agentShieldMapping: ['compliance.js:ComplianceReporter'], automatable: false },
        { id: 'GOVERN-2', name: 'Accountability', description: 'Establish accountability structures for AI systems', agentShieldMapping: ['enterprise.js:RoleBasedPolicy', 'multi-agent-trust.js:CapabilityToken'], automatable: true },
        { id: 'GOVERN-3', name: 'Workforce', description: 'AI risk management workforce competencies', agentShieldMapping: [], automatable: false },
        { id: 'GOVERN-4', name: 'Stakeholder Engagement', description: 'Engage stakeholders in AI risk decisions', agentShieldMapping: [], automatable: false },
        { id: 'GOVERN-5', name: 'Risk Assessment', description: 'Continuous AI risk assessment processes', agentShieldMapping: ['shield-score.js:ShieldScoreCalculator', 'owasp-2025.js:OWASPCoverageMatrix'], automatable: true },
        { id: 'GOVERN-6', name: 'Policies & Procedures', description: 'AI governance policies and procedures', agentShieldMapping: ['policy.js:loadPolicy', 'policy-dsl.js:PolicyDSL'], automatable: true }
      ]
    },
    MAP: {
      name: 'Map',
      description: 'Identify and document AI system context, requirements, and risks.',
      categories: [
        { id: 'MAP-1', name: 'Context', description: 'Map AI system intended purpose and context of use', agentShieldMapping: ['compliance.js:ComplianceReporter'], automatable: false },
        { id: 'MAP-2', name: 'Requirements', description: 'Document AI system requirements and constraints', agentShieldMapping: ['owasp-2025.js:OWASPCoverageMatrix'], automatable: true },
        { id: 'MAP-3', name: 'Risks', description: 'Identify and characterize AI-specific risks', agentShieldMapping: ['threat-encyclopedia.js:ThreatEncyclopedia', 'redteam.js:AttackSimulator'], automatable: true },
        { id: 'MAP-4', name: 'Benefits', description: 'Document intended benefits relative to risks', agentShieldMapping: [], automatable: false },
        { id: 'MAP-5', name: 'Documentation', description: 'Maintain AI system documentation', agentShieldMapping: ['compliance.js:AuditTrail', 'audit-immutable.js:ImmutableAuditLog'], automatable: true }
      ]
    },
    MEASURE: {
      name: 'Measure',
      description: 'Assess, analyze, and monitor AI risks using quantitative and qualitative methods.',
      categories: [
        { id: 'MEASURE-1', name: 'Metrics', description: 'Define and track AI risk metrics', agentShieldMapping: ['shield-score.js:ShieldScoreCalculator', 'benchmark-harness.js:BenchmarkMetrics'], automatable: true },
        { id: 'MEASURE-2', name: 'Testing', description: 'Test AI systems for safety, security, and fairness', agentShieldMapping: ['redteam.js:AttackSimulator', 'fuzzer.js:FuzzingHarness', 'testing.js:TestSuiteGenerator'], automatable: true },
        { id: 'MEASURE-3', name: 'Monitoring', description: 'Continuously monitor AI system behavior', agentShieldMapping: ['behavior-profiling.js:BehaviorProfile', 'observability.js:MetricsCollector', 'circuit-breaker.js:CircuitBreaker'], automatable: true },
        { id: 'MEASURE-4', name: 'Feedback', description: 'Collect and integrate feedback on AI risk', agentShieldMapping: ['allowlist.js:FeedbackLoop', 'self-healing.js:SelfHealingEngine'], automatable: true }
      ]
    },
    MANAGE: {
      name: 'Manage',
      description: 'Allocate resources and implement plans to respond to AI risks.',
      categories: [
        { id: 'MANAGE-1', name: 'Risk Treatment', description: 'Treat identified AI risks with appropriate controls', agentShieldMapping: ['detector-core.js:scanText', 'middleware.js:wrapAgent', 'mcp-bridge.js:MCPBridge'], automatable: true },
        { id: 'MANAGE-2', name: 'Incident Response', description: 'Respond to AI-related security incidents', agentShieldMapping: ['compliance.js:IncidentPlaybook', 'circuit-breaker.js:CircuitBreaker'], automatable: true },
        { id: 'MANAGE-3', name: 'Communication', description: 'Communicate AI risks to stakeholders', agentShieldMapping: ['policy.js:WebhookAlert', 'audit-streaming.js:AuditStreamManager'], automatable: true },
        { id: 'MANAGE-4', name: 'Improvement', description: 'Continuously improve AI risk management', agentShieldMapping: ['self-healing.js:SelfHealingEngine', 'confidence-tuning.js:ConfidenceTuner'], automatable: true }
      ]
    }
  }
};

/**
 * NIST SP 800-53 controls relevant to AI systems.
 * @type {Array<object>}
 */
const SP800_53_AI_CONTROLS = [
  { id: 'AC-3', family: 'Access Control', name: 'Access Enforcement', description: 'Enforce approved authorizations for AI system access', agentShieldCoverage: 'enterprise.js:RoleBasedPolicy' },
  { id: 'AU-2', family: 'Audit', name: 'Event Logging', description: 'Log AI system security-relevant events', agentShieldCoverage: 'audit-immutable.js:ImmutableAuditLog' },
  { id: 'AU-6', family: 'Audit', name: 'Audit Review', description: 'Review and analyze AI system audit records', agentShieldCoverage: 'audit-streaming.js:AuditStreamManager' },
  { id: 'CA-7', family: 'Assessment', name: 'Continuous Monitoring', description: 'Continuously monitor AI system security', agentShieldCoverage: 'observability.js:MetricsCollector' },
  { id: 'CM-3', family: 'Configuration', name: 'Configuration Change Control', description: 'Control changes to AI system configuration', agentShieldCoverage: 'policy-dsl.js:PolicyDSL' },
  { id: 'IA-9', family: 'Identification', name: 'Service Identification', description: 'Identify and authenticate AI services', agentShieldCoverage: 'agent-protocol.js:AgentIdentity' },
  { id: 'IR-4', family: 'Incident Response', name: 'Incident Handling', description: 'Handle AI-related security incidents', agentShieldCoverage: 'compliance.js:IncidentPlaybook' },
  { id: 'RA-5', family: 'Risk Assessment', name: 'Vulnerability Monitoring', description: 'Monitor AI system vulnerabilities', agentShieldCoverage: 'shield-score.js:ShieldScoreCalculator' },
  { id: 'SA-11', family: 'Acquisition', name: 'Developer Testing', description: 'Test AI system security controls', agentShieldCoverage: 'testing.js:TestSuiteGenerator' },
  { id: 'SC-7', family: 'System Protection', name: 'Boundary Protection', description: 'Protect AI system communication boundaries', agentShieldCoverage: 'agent-protocol.js:SecureChannel' },
  { id: 'SI-3', family: 'System Integrity', name: 'Malicious Code Protection', description: 'Protect AI systems from malicious inputs', agentShieldCoverage: 'detector-core.js:scanText' },
  { id: 'SI-4', family: 'System Integrity', name: 'System Monitoring', description: 'Monitor AI system for anomalous behavior', agentShieldCoverage: 'behavior-profiling.js:BehaviorProfile' }
];

// =========================================================================
// NISTMapper
// =========================================================================

class NISTMapper {
  /**
   * @param {object} [options]
   * @param {string} [options.organizationName='Organization'] - Org name for reports
   * @param {string} [options.systemName='AI System'] - AI system name
   * @param {'low'|'medium'|'high'|'critical'} [options.riskLevel='medium'] - Risk level
   */
  constructor(options = {}) {
    this.organizationName = options.organizationName || 'Organization';
    this.systemName = options.systemName || 'AI System';
    this.riskLevel = options.riskLevel || 'medium';
  }

  /**
   * Returns which NIST categories Agent Shield covers and how.
   * @returns {object}
   */
  getCoverageMap() {
    const map = {};
    for (const [funcName, func] of Object.entries(NIST_AI_RMF_2025.functions)) {
      map[funcName] = func.categories.map(cat => ({
        id: cat.id,
        name: cat.name,
        covered: cat.agentShieldMapping.length > 0,
        automatable: cat.automatable,
        modules: cat.agentShieldMapping,
        coverageLevel: cat.agentShieldMapping.length > 1 ? 'strong' : cat.agentShieldMapping.length === 1 ? 'basic' : 'none'
      }));
    }
    return map;
  }

  /**
   * Returns percentage of NIST controls addressed.
   * @returns {{ percentage: number, covered: number, total: number, byFunction: object }}
   */
  getCoverageScore() {
    const byFunction = {};
    let covered = 0;
    let total = 0;

    for (const [funcName, func] of Object.entries(NIST_AI_RMF_2025.functions)) {
      const funcCovered = func.categories.filter(c => c.agentShieldMapping.length > 0).length;
      const funcTotal = func.categories.length;
      byFunction[funcName] = { covered: funcCovered, total: funcTotal, percentage: funcTotal > 0 ? Math.round((funcCovered / funcTotal) * 100) : 0 };
      covered += funcCovered;
      total += funcTotal;
    }

    return { percentage: total > 0 ? Math.round((covered / total) * 100) : 0, covered, total, byFunction };
  }

  /**
   * Returns uncovered or partially covered areas.
   * @returns {Array<object>}
   */
  getGaps() {
    const gaps = [];
    for (const [funcName, func] of Object.entries(NIST_AI_RMF_2025.functions)) {
      for (const cat of func.categories) {
        if (cat.agentShieldMapping.length === 0) {
          gaps.push({ function: funcName, id: cat.id, name: cat.name, description: cat.description, automatable: cat.automatable });
        }
      }
    }
    return gaps;
  }

  /**
   * Generates a NIST AI RMF profile document.
   * @param {string} [systemDescription=''] - Description of the AI system
   * @returns {object}
   */
  generateProfile(systemDescription = '') {
    return {
      framework: 'NIST AI RMF',
      version: NIST_AI_RMF_2025.version,
      generatedAt: new Date().toISOString(),
      organization: this.organizationName,
      system: { name: this.systemName, description: systemDescription, riskLevel: this.riskLevel },
      coverage: this.getCoverageScore(),
      coverageMap: this.getCoverageMap(),
      gaps: this.getGaps(),
      sp800_53_mapping: SP800_53_AI_CONTROLS.map(c => ({ ...c, covered: !!c.agentShieldCoverage }))
    };
  }

  /**
   * Generates a formatted report.
   * @param {'text'|'json'|'markdown'} [format='text']
   * @returns {string}
   */
  generateReport(format = 'text') {
    const profile = this.generateProfile();

    if (format === 'json') return JSON.stringify(profile, null, 2);

    if (format === 'markdown') {
      const lines = [
        '# NIST AI RMF Coverage Report',
        '',
        `**Organization:** ${this.organizationName}`,
        `**System:** ${this.systemName}`,
        `**Risk Level:** ${this.riskLevel}`,
        `**Coverage:** ${profile.coverage.percentage}%`,
        ''
      ];

      for (const [funcName, func] of Object.entries(NIST_AI_RMF_2025.functions)) {
        const funcScore = profile.coverage.byFunction[funcName];
        lines.push(`## ${func.name} (${funcScore.covered}/${funcScore.total})`);
        lines.push('');
        for (const cat of func.categories) {
          const icon = cat.agentShieldMapping.length > 0 ? 'x' : ' ';
          lines.push(`- [${icon}] **${cat.id}** ${cat.name}: ${cat.description}`);
        }
        lines.push('');
      }
      return lines.join('\n');
    }

    // text format
    const score = profile.coverage;
    const lines = [
      `=== NIST AI RMF Coverage Report ===`,
      `Organization: ${this.organizationName}`,
      `System: ${this.systemName} | Risk: ${this.riskLevel}`,
      `Coverage: ${score.percentage}% (${score.covered}/${score.total})`,
      ''
    ];
    for (const [funcName, func] of Object.entries(NIST_AI_RMF_2025.functions)) {
      const fs = score.byFunction[funcName];
      lines.push(`${func.name}: ${fs.percentage}% (${fs.covered}/${fs.total})`);
      for (const cat of func.categories) {
        const icon = cat.agentShieldMapping.length > 0 ? '●' : '○';
        lines.push(`  ${icon} ${cat.id} ${cat.name}`);
      }
    }
    return lines.join('\n');
  }
}

// =========================================================================
// AIBOMGenerator — AI Bill of Materials
// =========================================================================

class AIBOMGenerator {
  /**
   * @param {object} [options]
   * @param {'spdx'|'cyclonedx'|'custom'} [options.format='custom'] - Output format
   * @param {string} [options.organizationName] - Organization name
   * @param {string} [options.systemName] - System name
   */
  constructor(options = {}) {
    this.format = options.format || 'custom';
    this.organizationName = options.organizationName || 'Organization';
    this.systemName = options.systemName || 'AI System';
    this.components = [];
    this.models = [];
    this.datasets = [];
    this.services = [];
  }

  /**
   * Adds a generic component.
   * @param {object} component - { name, version, type, supplier, license, hash }
   */
  addComponent(component) {
    this.components.push({ ...component, addedAt: new Date().toISOString() });
  }

  /**
   * Adds an AI model.
   * @param {object} model - { name, provider, version, type, parameters, trainingData, license }
   */
  addModel(model) {
    this.models.push({ ...model, addedAt: new Date().toISOString() });
  }

  /**
   * Adds a dataset.
   * @param {object} dataset - { name, source, version, format, size, privacyLevel }
   */
  addDataset(dataset) {
    this.datasets.push({ ...dataset, addedAt: new Date().toISOString() });
  }

  /**
   * Adds an external service.
   * @param {object} service - { name, endpoint, provider, version, sla }
   */
  addService(service) {
    this.services.push({ ...service, addedAt: new Date().toISOString() });
  }

  /**
   * Generates the AI-BOM.
   * @returns {object}
   */
  generate() {
    if (this.format === 'spdx') return this.toSPDX();
    if (this.format === 'cyclonedx') return this.toCycloneDX();
    return this.toJSON();
  }

  /**
   * Validates completeness of the BOM.
   * @returns {{ valid: boolean, warnings: Array }}
   */
  validate() {
    const warnings = [];
    if (this.models.length === 0) warnings.push('No AI models documented');
    if (this.components.length === 0 && this.services.length === 0) warnings.push('No components or services documented');
    for (const m of this.models) {
      if (!m.version) warnings.push(`Model "${m.name}" missing version`);
      if (!m.license) warnings.push(`Model "${m.name}" missing license`);
    }
    for (const d of this.datasets) {
      if (!d.privacyLevel) warnings.push(`Dataset "${d.name}" missing privacy level`);
    }
    return { valid: warnings.length === 0, warnings };
  }

  /**
   * Custom JSON format.
   * @returns {object}
   */
  toJSON() {
    return {
      bomFormat: 'AgentShield-AI-BOM',
      specVersion: '1.0',
      generatedAt: new Date().toISOString(),
      system: { name: this.systemName, organization: this.organizationName },
      models: this.models,
      datasets: this.datasets,
      components: this.components,
      services: this.services,
      summary: { totalModels: this.models.length, totalDatasets: this.datasets.length, totalComponents: this.components.length, totalServices: this.services.length }
    };
  }

  /**
   * SPDX-compatible format.
   * @returns {object}
   */
  toSPDX() {
    return {
      spdxVersion: 'SPDX-2.3',
      dataLicense: 'CC0-1.0',
      SPDXID: 'SPDXRef-DOCUMENT',
      name: `AI-BOM-${this.systemName}`,
      documentNamespace: `https://spdx.org/spdxdocs/ai-bom-${Date.now()}`,
      creationInfo: { created: new Date().toISOString(), creators: [`Organization: ${this.organizationName}`, 'Tool: AgentShield'] },
      packages: [
        ...this.models.map((m, i) => ({
          SPDXID: `SPDXRef-Model-${i}`,
          name: m.name,
          versionInfo: m.version || 'unknown',
          supplier: m.provider || 'unknown',
          downloadLocation: 'NOASSERTION',
          licenseConcluded: m.license || 'NOASSERTION',
          primaryPackagePurpose: 'AI_MODEL'
        })),
        ...this.components.map((c, i) => ({
          SPDXID: `SPDXRef-Component-${i}`,
          name: c.name,
          versionInfo: c.version || 'unknown',
          supplier: c.supplier || 'unknown',
          downloadLocation: 'NOASSERTION',
          licenseConcluded: c.license || 'NOASSERTION',
          primaryPackagePurpose: 'LIBRARY'
        }))
      ]
    };
  }

  /**
   * CycloneDX-compatible format.
   * @returns {object}
   */
  toCycloneDX() {
    return {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      version: 1,
      metadata: {
        timestamp: new Date().toISOString(),
        tools: [{ vendor: 'AgentShield', name: 'AI-BOM Generator', version: '1.0' }],
        component: { type: 'application', name: this.systemName, version: '1.0' }
      },
      components: [
        ...this.models.map(m => ({
          type: 'machine-learning-model',
          name: m.name,
          version: m.version || 'unknown',
          supplier: { name: m.provider || 'unknown' },
          licenses: m.license ? [{ license: { id: m.license } }] : [],
          properties: [
            { name: 'ai:type', value: m.type || 'unknown' },
            { name: 'ai:parameters', value: String(m.parameters || 'unknown') }
          ]
        })),
        ...this.components.map(c => ({
          type: 'library',
          name: c.name,
          version: c.version || 'unknown',
          supplier: { name: c.supplier || 'unknown' },
          hashes: c.hash ? [{ alg: 'SHA-256', content: c.hash }] : []
        }))
      ]
    };
  }
}

// =========================================================================
// ComplianceChecker
// =========================================================================

class ComplianceChecker {
  /**
   * @param {NISTMapper} nistMapper
   */
  constructor(nistMapper) {
    this.mapper = nistMapper;
  }

  /**
   * Checks current state against a NIST profile.
   * @param {object} profile - Generated profile
   * @param {object} currentState - Current system state
   * @returns {{ compliant: boolean, gaps: Array, score: number }}
   */
  checkAgainstProfile(profile, currentState = {}) {
    const gaps = [];
    const activeModules = currentState.activeModules || [];

    for (const [funcName, categories] of Object.entries(profile.coverageMap)) {
      for (const cat of categories) {
        if (cat.covered && cat.modules.length > 0) {
          const moduleName = cat.modules[0].split(':')[0].replace('.js', '');
          if (!activeModules.includes(moduleName)) {
            gaps.push({ function: funcName, category: cat.id, name: cat.name, reason: 'Module available but not active' });
          }
        }
      }
    }

    const score = profile.coverage.percentage;
    return { compliant: gaps.length === 0 && score >= 80, gaps, score };
  }

  /**
   * Generates a prioritized action plan.
   * @returns {Array<object>}
   */
  generateActionPlan() {
    const gaps = this.mapper.getGaps();
    return gaps.map((gap, i) => ({
      priority: i + 1,
      action: `Address ${gap.id} — ${gap.name}`,
      description: gap.description,
      automatable: gap.automatable,
      effort: gap.automatable ? 'low' : 'high'
    }));
  }

  /**
   * Generates an audit artifact.
   * @param {'text'|'json'|'markdown'} [format='json']
   * @returns {string}
   */
  generateAuditArtifact(format = 'json') {
    const profile = this.mapper.generateProfile();
    const actionPlan = this.generateActionPlan();

    const artifact = {
      type: 'NIST AI RMF Audit Artifact',
      generatedAt: new Date().toISOString(),
      organization: this.mapper.organizationName,
      system: this.mapper.systemName,
      framework: 'NIST AI RMF 1.0 (2025)',
      riskLevel: this.mapper.riskLevel,
      coverageScore: profile.coverage,
      gaps: profile.gaps,
      actionPlan,
      sp800_53: profile.sp800_53_mapping
    };

    if (format === 'json') return JSON.stringify(artifact, null, 2);
    if (format === 'markdown') {
      return [
        '# NIST AI RMF Audit Artifact',
        `**Date:** ${artifact.generatedAt}`,
        `**Coverage:** ${artifact.coverageScore.percentage}%`,
        '',
        '## Action Plan',
        ...actionPlan.map(a => `${a.priority}. **${a.action}** — ${a.description} (effort: ${a.effort})`)
      ].join('\n');
    }
    return JSON.stringify(artifact, null, 2);
  }
}

// =========================================================================
// Exports
// =========================================================================

module.exports = {
  NIST_AI_RMF_2025,
  SP800_53_AI_CONTROLS,
  NISTMapper,
  AIBOMGenerator,
  ComplianceChecker
};
