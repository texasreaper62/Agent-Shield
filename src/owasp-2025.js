'use strict';

/**
 * Agent Shield — OWASP LLM Top 10 v2025 Coverage Matrix
 *
 * Maps Agent Shield capabilities to the OWASP Top 10 for LLM Applications (2025).
 * Provides coverage scoring, gap analysis, and compliance reporting.
 *
 * All processing runs locally — no data ever leaves your environment.
 */

// =========================================================================
// OWASP LLM Top 10 v2025 Definition
// =========================================================================

/**
 * The complete OWASP LLM Top 10 v2025 with Agent Shield coverage mapping.
 * @type {Array<object>}
 */
const OWASP_LLM_2025 = [
  {
    id: 'LLM01',
    name: 'Prompt Injection',
    description: 'Manipulating LLMs via crafted inputs that override system instructions or cause unintended actions.',
    severity: 'critical',
    agentShieldModules: ['detector-core', 'middleware', 'integrations', 'i18n-patterns', 'encoding', 'conversation'],
    coverageLevel: 'full',
    mitigations: [
      'Real-time pattern matching against 60+ injection signatures',
      'Multi-language injection detection (CJK, Arabic, Cyrillic, Indic)',
      'Encoding bruteforce detection (base64, hex, unicode escapes)',
      'Fragmentation and language-switch detection',
      'Framework middleware for Anthropic, OpenAI, LangChain, Vercel AI',
      'Input quarantine for suspicious payloads'
    ],
    references: ['detector-core.js:INJECTION_PATTERNS', 'middleware.js:wrapAgent', 'i18n-patterns.js']
  },
  {
    id: 'LLM02',
    name: 'Sensitive Information Disclosure',
    description: 'LLMs inadvertently revealing sensitive data such as PII, credentials, or proprietary information in responses.',
    severity: 'critical',
    agentShieldModules: ['pii', 'canary', 'watermark', 'prompt-leakage'],
    coverageLevel: 'full',
    mitigations: [
      'PII detection and redaction (SSN, credit cards, emails, phone numbers)',
      'DLP engine with configurable content policies',
      'API key pattern detection (AWS, GitHub, Stripe, etc.)',
      'Canary token injection and leak detection',
      'Output watermarking for traceability',
      'System prompt fingerprinting and leak scoring'
    ],
    references: ['pii.js:PIIRedactor', 'canary.js:CanaryTokens', 'prompt-leakage.js:SystemPromptGuard']
  },
  {
    id: 'LLM03',
    name: 'Supply Chain',
    description: 'Vulnerabilities from third-party components, training data, pre-trained models, and deployment platforms.',
    severity: 'high',
    agentShieldModules: ['model-fingerprint', 'scanners', 'plugin-marketplace'],
    coverageLevel: 'partial',
    mitigations: [
      'Model fingerprinting via 16-feature stylistic analysis',
      'Supply chain detection with cosine similarity matching',
      'Plugin validation and sandboxing',
      'Tool schema validation for dangerous patterns'
    ],
    gaps: [
      'No model artifact binary scanning (e.g., pickle deserialization attacks)',
      'No model BOM (Bill of Materials) generation for model files',
      'No pre-trained model integrity verification (hash-based)'
    ],
    references: ['model-fingerprint.js:SupplyChainDetector', 'scanners.js:ToolSchemaValidator']
  },
  {
    id: 'LLM04',
    name: 'Data and Model Poisoning',
    description: 'Manipulation of training data or model weights to introduce vulnerabilities, backdoors, or biases.',
    severity: 'high',
    agentShieldModules: ['scanners', 'self-healing', 'embedding', 'behavior-profiling'],
    coverageLevel: 'partial',
    mitigations: [
      'RAG document scanning for poisoned content',
      'Self-healing pattern generation from false negatives',
      'Embedding similarity detection for anomalous inputs',
      'Behavioral fingerprinting and anomaly detection (z-score)'
    ],
    gaps: [
      'No training data validation pipeline',
      'No model weight integrity verification',
      'No backdoor detection in fine-tuned models'
    ],
    references: ['scanners.js:RAGScanner', 'self-healing.js:SelfHealingEngine']
  },
  {
    id: 'LLM05',
    name: 'Improper Output Handling',
    description: 'Insufficient validation of LLM outputs leading to XSS, SSRF, privilege escalation, or code execution.',
    severity: 'high',
    agentShieldModules: ['tool-output-validator', 'middleware', 'detector-core'],
    coverageLevel: 'full',
    mitigations: [
      'Output scanning for injection patterns in LLM responses',
      'Tool output validation and sanitization',
      'Express middleware for output filtering',
      'Content policy enforcement on outputs',
      'Structured data scanning for embedded threats'
    ],
    references: ['tool-output-validator.js:ToolOutputValidator', 'middleware.js:wrapAgent']
  },
  {
    id: 'LLM06',
    name: 'Excessive Agency',
    description: 'Granting LLMs too much autonomy, capability, or permissions leading to unintended harmful actions.',
    severity: 'critical',
    agentShieldModules: ['tool-guard', 'multi-agent', 'multi-agent-trust', 'mcp-bridge'],
    coverageLevel: 'full',
    mitigations: [
      'Tool sequence analysis for suspicious call patterns',
      'Permission boundaries with allow/deny lists',
      'Agent firewall for inter-agent communication',
      'Delegation chain tracking and depth limits',
      'Capability tokens with expiration and scope limits',
      'Blast radius containment for agent failures',
      'MCP tool policy enforcement and session budgets'
    ],
    references: ['tool-guard.js:PermissionBoundary', 'multi-agent-trust.js:CapabilityToken', 'mcp-bridge.js:MCPToolPolicy']
  },
  {
    id: 'LLM07',
    name: 'System Prompt Leakage',
    description: 'Extraction or disclosure of system prompts through direct queries, indirect techniques, or multi-step attacks.',
    severity: 'high',
    agentShieldModules: ['prompt-leakage', 'canary'],
    coverageLevel: 'full',
    mitigations: [
      'Dedicated prompt extraction attempt detection (30+ patterns)',
      'Direct, indirect, encoded, roleplay, and multi-step technique detection',
      'System prompt fingerprinting (n-gram overlap, key phrase matching)',
      'Output scanning for partial prompt leakage',
      'Canary token injection for leak tripwires',
      'Anti-extraction defense layer wrapping',
      'Decoy prompt generation for detected extraction attempts'
    ],
    references: ['prompt-leakage.js:SystemPromptGuard', 'canary.js:PromptLeakDetector']
  },
  {
    id: 'LLM08',
    name: 'Vector and Embedding Weaknesses',
    description: 'Vulnerabilities in RAG systems including embedding manipulation, chunk boundary attacks, and retrieval poisoning.',
    severity: 'high',
    agentShieldModules: ['rag-vulnerability', 'embedding', 'scanners'],
    coverageLevel: 'full',
    mitigations: [
      'RAG-specific vulnerability scanning (chunk boundary, metadata injection)',
      'Embedding integrity checking and outlier detection',
      'Cross-document injection detection',
      'Context window stuffing assessment',
      'RAG pipeline security auditing',
      'Vector DB security checklist (Pinecone, Weaviate, Qdrant, Chroma, Milvus, pgvector)',
      'TF-IDF embedding similarity for anomaly detection'
    ],
    references: ['rag-vulnerability.js:RAGVulnerabilityScanner', 'embedding.js:EmbeddingSimilarityDetector']
  },
  {
    id: 'LLM09',
    name: 'Misinformation',
    description: 'LLMs generating false or misleading content that appears authoritative, leading to misinformed decisions.',
    severity: 'medium',
    agentShieldModules: ['behavior-profiling', 'confidence-tuning', 'context-scoring'],
    coverageLevel: 'partial',
    mitigations: [
      'Behavioral fingerprinting and baseline deviation detection',
      'Per-category confidence threshold calibration',
      'Multi-turn conversation context analysis for consistency',
      'Escalation signal detection for topic manipulation'
    ],
    gaps: [
      'No factual grounding verification against knowledge bases',
      'No hallucination detection via source attribution',
      'No citation verification for claimed references'
    ],
    references: ['behavior-profiling.js:BehaviorProfile', 'confidence-tuning.js:ConfidenceTuner']
  },
  {
    id: 'LLM10',
    name: 'Unbounded Consumption',
    description: 'LLM applications consuming excessive resources through large inputs, recursive operations, or resource exhaustion.',
    severity: 'medium',
    agentShieldModules: ['circuit-breaker', 'cost-optimizer', 'mcp-bridge'],
    coverageLevel: 'full',
    mitigations: [
      'Circuit breaker with configurable thresholds',
      'Rate limiter for request throttling',
      'Token budget analysis and enforcement',
      '4-tier adaptive scanning with latency budgets',
      'MCP session guards with call/token budgets',
      'Input size limits (1MB default)',
      'Scan time budgets (200ms default)'
    ],
    references: ['circuit-breaker.js:CircuitBreaker', 'cost-optimizer.js:CostOptimizer']
  }
];

// =========================================================================
// Coverage weights per severity
// =========================================================================

const SEVERITY_WEIGHTS = {
  critical: 15,
  high: 10,
  medium: 5
};

const COVERAGE_MULTIPLIERS = {
  full: 1.0,
  partial: 0.5,
  planned: 0.1,
  none: 0.0
};

// =========================================================================
// OWASPCoverageMatrix
// =========================================================================

class OWASPCoverageMatrix {
  /**
   * @param {object} [options]
   * @param {object} [options.agentShield] - AgentShield instance for live validation
   * @param {string} [options.organizationName] - Organization name for reports
   */
  constructor(options = {}) {
    this.agentShield = options.agentShield || null;
    this.organizationName = options.organizationName || 'Organization';
    this.entries = OWASP_LLM_2025;
  }

  /**
   * Returns the full coverage matrix with status for each OWASP entry.
   * @returns {Array<object>}
   */
  getCoverage() {
    return this.entries.map(entry => ({
      id: entry.id,
      name: entry.name,
      severity: entry.severity,
      coverageLevel: entry.coverageLevel,
      modules: entry.agentShieldModules,
      mitigationCount: entry.mitigations.length,
      hasGaps: !!(entry.gaps && entry.gaps.length > 0),
      gaps: entry.gaps || []
    }));
  }

  /**
   * Returns a percentage score (0–100) of OWASP coverage.
   * Weighted by severity: critical items count more than medium.
   * @returns {{ score: number, maxScore: number, percentage: number, grade: string }}
   */
  getCoverageScore() {
    let totalWeight = 0;
    let achievedWeight = 0;

    for (const entry of this.entries) {
      const weight = SEVERITY_WEIGHTS[entry.severity] || 5;
      const multiplier = COVERAGE_MULTIPLIERS[entry.coverageLevel] || 0;
      totalWeight += weight;
      achievedWeight += weight * multiplier;
    }

    const percentage = Math.round((achievedWeight / totalWeight) * 100);
    let grade;
    if (percentage >= 90) grade = 'A';
    else if (percentage >= 80) grade = 'B';
    else if (percentage >= 70) grade = 'C';
    else if (percentage >= 60) grade = 'D';
    else grade = 'F';

    return { score: achievedWeight, maxScore: totalWeight, percentage, grade };
  }

  /**
   * Returns items where coverage is partial or planned.
   * @returns {Array<object>}
   */
  getGaps() {
    return this.entries
      .filter(e => e.coverageLevel !== 'full')
      .map(e => ({
        id: e.id,
        name: e.name,
        severity: e.severity,
        coverageLevel: e.coverageLevel,
        gaps: e.gaps || [],
        currentModules: e.agentShieldModules
      }));
  }

  /**
   * Returns actionable recommendations to improve OWASP coverage.
   * @returns {Array<object>}
   */
  getRecommendations() {
    const recs = [];

    for (const entry of this.entries) {
      if (entry.coverageLevel === 'full') continue;

      const priority = entry.severity === 'critical' ? 'high' :
        entry.severity === 'high' ? 'medium' : 'low';

      recs.push({
        id: entry.id,
        name: entry.name,
        priority,
        currentCoverage: entry.coverageLevel,
        gaps: entry.gaps || [],
        recommendation: this._getRecommendation(entry)
      });
    }

    return recs.sort((a, b) => {
      const order = { high: 0, medium: 1, low: 2 };
      return (order[a.priority] || 2) - (order[b.priority] || 2);
    });
  }

  /**
   * Validates scan results against OWASP coverage requirements.
   * @param {object} scanResults - Results from AgentShield scan
   * @returns {{ compliant: boolean, checkedItems: Array<object>, unchecked: Array<string> }}
   */
  validateCompliance(scanResults = {}) {
    const checkedItems = [];
    const unchecked = [];

    for (const entry of this.entries) {
      const isActive = this._isEntryActive(entry, scanResults);
      if (isActive) {
        checkedItems.push({ id: entry.id, name: entry.name, status: 'active' });
      } else {
        unchecked.push(entry.id);
      }
    }

    return {
      compliant: unchecked.length === 0,
      checkedItems,
      unchecked,
      score: Math.round((checkedItems.length / this.entries.length) * 100)
    };
  }

  /**
   * Generates a formatted coverage report.
   * @param {'text'|'json'|'markdown'} [format='text']
   * @returns {string}
   */
  getCoverageReport(format = 'text') {
    const score = this.getCoverageScore();
    const gaps = this.getGaps();

    if (format === 'json') {
      return JSON.stringify({
        framework: 'OWASP LLM Top 10',
        version: '2025',
        generatedAt: new Date().toISOString(),
        organization: this.organizationName,
        score,
        coverage: this.getCoverage(),
        gaps,
        recommendations: this.getRecommendations()
      }, null, 2);
    }

    if (format === 'markdown') {
      return this._renderMarkdown(score, gaps);
    }

    return this._renderText(score, gaps);
  }

  // --- Private helpers ---

  /** @private */
  _getRecommendation(entry) {
    const recs = {
      LLM03: 'Add model artifact binary scanning (pickle, safetensors, ONNX) to detect deserialization attacks and backdoors. Generate AI-BOM for model supply chain.',
      LLM04: 'Implement training data validation pipeline and model weight integrity verification. Add fine-tuning backdoor detection.',
      LLM09: 'Add factual grounding verification, hallucination detection via source attribution, and citation verification.'
    };
    return recs[entry.id] || `Improve ${entry.name} coverage by addressing identified gaps.`;
  }

  /** @private */
  _isEntryActive(entry, scanResults) {
    if (!scanResults || typeof scanResults !== 'object') return false;
    const activeModules = scanResults.activeModules || [];
    return entry.agentShieldModules.some(m => activeModules.includes(m));
  }

  /** @private */
  _renderText(score, gaps) {
    const lines = [];
    lines.push('╔══════════════════════════════════════════════════════════════╗');
    lines.push('║       OWASP LLM Top 10 v2025 — Agent Shield Coverage       ║');
    lines.push('╚══════════════════════════════════════════════════════════════╝');
    lines.push('');
    lines.push(`Organization: ${this.organizationName}`);
    lines.push(`Generated:    ${new Date().toISOString()}`);
    lines.push(`Score:        ${score.percentage}% (Grade ${score.grade})`);
    lines.push('');

    for (const entry of this.entries) {
      const icon = entry.coverageLevel === 'full' ? '●' :
        entry.coverageLevel === 'partial' ? '◐' : '○';
      const sev = entry.severity.toUpperCase().padEnd(8);
      lines.push(`  ${icon} ${entry.id} ${entry.name.padEnd(35)} [${sev}] ${entry.coverageLevel}`);
    }

    if (gaps.length > 0) {
      lines.push('');
      lines.push('── Gaps ──');
      for (const gap of gaps) {
        lines.push(`  ${gap.id} ${gap.name}:`);
        for (const g of gap.gaps) {
          lines.push(`    - ${g}`);
        }
      }
    }

    lines.push('');
    lines.push(`Full: ${this.entries.filter(e => e.coverageLevel === 'full').length}/10  |  Partial: ${this.entries.filter(e => e.coverageLevel === 'partial').length}/10`);
    return lines.join('\n');
  }

  /** @private */
  _renderMarkdown(score, gaps) {
    const lines = [];
    lines.push('# OWASP LLM Top 10 v2025 — Agent Shield Coverage Report');
    lines.push('');
    lines.push(`**Organization:** ${this.organizationName}  `);
    lines.push(`**Generated:** ${new Date().toISOString()}  `);
    lines.push(`**Score:** ${score.percentage}% (Grade ${score.grade})`);
    lines.push('');
    lines.push('## Coverage Matrix');
    lines.push('');
    lines.push('| ID | Risk | Severity | Coverage | Modules | Mitigations |');
    lines.push('|----|------|----------|----------|---------|-------------|');

    for (const entry of this.entries) {
      const cov = entry.coverageLevel === 'full' ? 'Full' :
        entry.coverageLevel === 'partial' ? 'Partial' : 'Planned';
      lines.push(`| ${entry.id} | ${entry.name} | ${entry.severity} | ${cov} | ${entry.agentShieldModules.length} | ${entry.mitigations.length} |`);
    }

    if (gaps.length > 0) {
      lines.push('');
      lines.push('## Gaps & Recommendations');
      lines.push('');
      for (const gap of gaps) {
        lines.push(`### ${gap.id} — ${gap.name} (${gap.coverageLevel})`);
        for (const g of gap.gaps) {
          lines.push(`- ${g}`);
        }
        lines.push('');
      }
    }

    return lines.join('\n');
  }
}

// =========================================================================
// Exports
// =========================================================================

module.exports = {
  OWASP_LLM_2025,
  OWASPCoverageMatrix,
  SEVERITY_WEIGHTS,
  COVERAGE_MULTIPLIERS
};
