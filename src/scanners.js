'use strict';

/**
 * Agent Shield — Advanced Scanners
 *
 * - RAG Poisoning Scanner
 * - Prompt Template Linter
 * - Tool Schema Validator
 */

const { scanText } = require('./detector-core');

// =========================================================================
// RAG Poisoning Scanner
// =========================================================================

const RAG_INJECTION_PATTERNS = [
  { pattern: /<!--\s*(?:instructions?|system|ai|assistant)\s*:/i, severity: 'critical', description: 'HTML comment with AI instructions' },
  { pattern: /<div[^>]*style\s*=\s*["'][^"']*display\s*:\s*none[^"']*["'][^>]*>.*?(?:ignore|override|forget|disregard)/is, severity: 'critical', description: 'Hidden div with injection' },
  { pattern: /<span[^>]*style\s*=\s*["'][^"']*font-size\s*:\s*0[^"']*["']/i, severity: 'high', description: 'Zero-font-size hidden text' },
  { pattern: /<[^>]*style\s*=\s*["'][^"']*color\s*:\s*(?:white|#fff|#ffffff|transparent|rgba\(0,\s*0,\s*0,\s*0\))[^"']*["']/i, severity: 'high', description: 'Invisible text (same color as background)' },
  { pattern: /\[system\]|\[INST\]|<<SYS>>|<\|im_start\|>system/i, severity: 'critical', description: 'LLM control tokens in document' },
  { pattern: /(?:AI|assistant|model|LLM|GPT|Claude)\s*(?:should|must|will|needs?\s+to)\s+(?:ignore|override|forget|disregard)/i, severity: 'high', description: 'Directive targeting AI in document' },
  { pattern: /(?:when\s+(?:an?\s+)?(?:AI|assistant|model|LLM)\s+reads?\s+this|if\s+you\s+are\s+an?\s+(?:AI|language\s+model))/i, severity: 'high', description: 'AI-targeted conditional in document' },
  { pattern: /\u200B[\s\S]{5,}\u200B/i, severity: 'medium', description: 'Content between zero-width spaces' },
  { pattern: /\u2060[\s\S]{5,}\u2060/i, severity: 'medium', description: 'Content between word joiners' }
];

class RAGScanner {
  constructor(options = {}) {
    this.sensitivity = options.sensitivity || 'high';
    this.customPatterns = options.customPatterns || [];
    this.stats = { documentsScanned: 0, threatsFound: 0 };
  }

  /**
   * Scan a single document/chunk for RAG poisoning.
   */
  scanDocument(text, metadata = {}) {
    this.stats.documentsScanned++;
    const threats = [];

    // Run RAG-specific patterns
    const patterns = [...RAG_INJECTION_PATTERNS, ...this.customPatterns];
    for (const p of patterns) {
      if (p.pattern.test(text)) {
        threats.push({
          severity: p.severity,
          category: 'rag_poisoning',
          description: p.description,
          source: metadata.source || 'unknown'
        });
      }
    }

    // Also run the general scanner
    const generalResult = scanText(text, this.sensitivity);
    for (const t of generalResult.threats) {
      threats.push({ ...t, category: 'rag_indirect_injection', source: metadata.source || 'unknown' });
    }

    this.stats.threatsFound += threats.length;

    return {
      clean: threats.length === 0,
      threats,
      documentLength: text.length,
      metadata
    };
  }

  /**
   * Scan multiple documents/chunks (e.g., RAG retrieval results).
   */
  scanCorpus(documents) {
    const results = [];
    let totalThreats = 0;

    for (const doc of documents) {
      const text = typeof doc === 'string' ? doc : doc.text || doc.content || doc.pageContent || '';
      const meta = typeof doc === 'string' ? {} : { source: doc.source || doc.metadata?.source };
      const result = this.scanDocument(text, meta);
      results.push(result);
      totalThreats += result.threats.length;
    }

    return {
      totalDocuments: documents.length,
      cleanDocuments: results.filter(r => r.clean).length,
      poisonedDocuments: results.filter(r => !r.clean).length,
      totalThreats,
      results
    };
  }

  /**
   * Filter out poisoned documents from retrieval results.
   */
  filterCorpus(documents) {
    const clean = [];
    const poisoned = [];

    for (const doc of documents) {
      const text = typeof doc === 'string' ? doc : doc.text || doc.content || doc.pageContent || '';
      const result = this.scanDocument(text);
      if (result.clean) clean.push(doc);
      else poisoned.push({ doc, threats: result.threats });
    }

    return { clean, poisoned };
  }

  getStats() { return { ...this.stats }; }
}

// =========================================================================
// Prompt Template Linter
// =========================================================================

const LINT_RULES = [
  {
    id: 'PROMPT-001',
    name: 'missing_delimiters',
    severity: 'high',
    check: (template) => {
      const hasUserInput = /\{(?:user_?(?:input|message|query|prompt)|input|message|query)\}/i.test(template);
      const hasDelimiters = /(?:```|"""|---|===|<\/?(?:user|input|message)>)/i.test(template);
      return hasUserInput && !hasDelimiters;
    },
    message: 'User input variable has no delimiters. Wrap user input in clear boundaries (```, """, XML tags) to prevent injection.',
    fix: 'Add delimiters around user input: <user_input>{user_input}</user_input>'
  },
  {
    id: 'PROMPT-002',
    name: 'no_instruction_hierarchy',
    severity: 'high',
    check: (template) => {
      const hasSystemInstructions = template.length > 100;
      const hasHierarchy = /(?:IMPORTANT|PRIORITY|RULE|NEVER|ALWAYS|UNDER NO CIRCUMSTANCES|REGARDLESS)/i.test(template);
      return hasSystemInstructions && !hasHierarchy;
    },
    message: 'No instruction hierarchy markers. Use explicit priority markers (IMPORTANT, NEVER, ALWAYS) for critical rules.',
    fix: 'Add "IMPORTANT:" or "RULE:" prefixes to critical instructions'
  },
  {
    id: 'PROMPT-003',
    name: 'injectable_variables',
    severity: 'medium',
    check: (template) => {
      const vars = template.match(/\{([^}]+)\}/g) || [];
      const dangerous = vars.filter(v => /(?:url|path|file|command|code|script|html|sql)/i.test(v));
      return dangerous.length > 0;
    },
    message: 'Template contains potentially injectable variables (URL, path, command, etc.). Validate/sanitize these inputs.',
    fix: 'Add input validation before injecting these variables into the prompt'
  },
  {
    id: 'PROMPT-004',
    name: 'missing_output_constraints',
    severity: 'medium',
    check: (template) => {
      const isLong = template.length > 200;
      const hasOutputRules = /(?:respond\s+(?:only|exclusively)|output\s+format|do\s+not\s+(?:include|output|generate)|format\s*:|response\s+format)/i.test(template);
      return isLong && !hasOutputRules;
    },
    message: 'No output constraints defined. Specify output format/restrictions to limit unexpected responses.',
    fix: 'Add output constraints: "Respond only with..." or "Format: ..."'
  },
  {
    id: 'PROMPT-005',
    name: 'no_refusal_instructions',
    severity: 'medium',
    check: (template) => {
      const isLong = template.length > 200;
      const hasRefusal = /(?:refuse|decline|reject|do\s+not\s+(?:comply|help|assist)|if\s+(?:asked|requested)\s+to)/i.test(template);
      return isLong && !hasRefusal;
    },
    message: 'No refusal instructions. Tell the model when and how to refuse inappropriate requests.',
    fix: 'Add: "If asked to do X, politely decline and explain why."'
  },
  {
    id: 'PROMPT-006',
    name: 'hardcoded_secrets',
    severity: 'critical',
    check: (template) => {
      return /(?:sk-[a-zA-Z0-9]{20,}|(?:password|secret|token|key)\s*[=:]\s*["'][^"']{8,})/i.test(template);
    },
    message: 'Hardcoded secrets detected in prompt template. Use environment variables instead.',
    fix: 'Move secrets to environment variables and reference them dynamically'
  },
  {
    id: 'PROMPT-007',
    name: 'ambiguous_role',
    severity: 'low',
    check: (template) => {
      const isLong = template.length > 50;
      const hasRole = /(?:you\s+are|your\s+role|act\s+as|behave\s+as)/i.test(template);
      return isLong && !hasRole;
    },
    message: 'No explicit role definition. Define who/what the assistant is to establish behavioral boundaries.',
    fix: 'Start with: "You are [role]. Your purpose is [purpose]."'
  }
];

class PromptLinter {
  constructor(options = {}) {
    this.rules = [...LINT_RULES, ...(options.customRules || [])];
    this.disabledRules = new Set(options.disabledRules || []);
  }

  /**
   * Lint a prompt template.
   */
  lint(template) {
    const findings = [];

    for (const rule of this.rules) {
      if (this.disabledRules.has(rule.id)) continue;

      try {
        if (rule.check(template)) {
          findings.push({
            id: rule.id,
            name: rule.name,
            severity: rule.severity,
            message: rule.message,
            fix: rule.fix
          });
        }
      } catch (e) {
        // Skip rules that error during check
        console.warn('[Agent Shield] Lint rule "%s" threw an error: %s', rule.id, e.message);
      }
    }

    findings.sort((a, b) => {
      const order = { critical: 0, high: 1, medium: 2, low: 3 };
      return (order[a.severity] || 99) - (order[b.severity] || 99);
    });

    return {
      clean: findings.length === 0,
      score: Math.max(0, 100 - findings.reduce((sum, f) => {
        const weights = { critical: 30, high: 20, medium: 10, low: 5 };
        return sum + (weights[f.severity] || 5);
      }, 0)),
      findings,
      summary: findings.length === 0
        ? 'Prompt template looks good!'
        : `${findings.length} issue(s) found: ${findings.filter(f => f.severity === 'critical').length} critical, ${findings.filter(f => f.severity === 'high').length} high`
    };
  }

  /**
   * Get all available rules.
   */
  getRules() {
    return this.rules.map(r => ({ id: r.id, name: r.name, severity: r.severity, message: r.message }));
  }
}

// =========================================================================
// Tool Schema Validator
// =========================================================================

const DANGEROUS_TOOL_PATTERNS = [
  { pattern: /(?:execute|run|eval|shell|bash|command|system|exec)/i, severity: 'critical', message: 'Tool allows arbitrary code/command execution' },
  { pattern: /(?:any\s+(?:file|path|url|command)|unrestricted|no\s+(?:limit|restriction))/i, severity: 'high', message: 'Tool description implies unrestricted access' },
  { pattern: /(?:delete|remove|drop|truncate|destroy|wipe|purge)/i, severity: 'high', message: 'Tool can perform destructive operations' },
  { pattern: /(?:admin|root|superuser|elevated|privileged)/i, severity: 'medium', message: 'Tool implies elevated privileges' },
  { pattern: /(?:all\s+(?:files?|data|records?|users?)|entire|everything|full\s+access)/i, severity: 'medium', message: 'Tool scope is overly broad' }
];

class ToolSchemaValidator {
  constructor(options = {}) {
    this.customPatterns = options.customPatterns || [];
  }

  /**
   * Validate a single tool definition.
   * @param {Object} tool - { name, description, parameters?, inputSchema? }
   */
  validateTool(tool) {
    const findings = [];
    const name = tool.name || 'unnamed';
    const description = tool.description || '';
    const parameterText = tool.parameters ? JSON.stringify(tool.parameters) : (tool.inputSchema ? JSON.stringify(tool.inputSchema) : '');

    // Check tool name
    for (const p of DANGEROUS_TOOL_PATTERNS) {
      if (p.pattern.test(name)) {
        findings.push({ tool: name, severity: p.severity, location: 'name', message: `Tool name: ${p.message}` });
      }
    }

    // Check description
    const allPatterns = [...DANGEROUS_TOOL_PATTERNS, ...this.customPatterns];
    for (const p of allPatterns) {
      if (p.pattern.test(description)) {
        findings.push({ tool: name, severity: p.severity, location: 'description', message: `Description: ${p.message}` });
      }
    }

    // Check for missing description
    if (!description || description.length < 10) {
      findings.push({ tool: name, severity: 'medium', location: 'description', message: 'Tool has no meaningful description. LLMs may interpret its purpose incorrectly.' });
    }

    // Check for overly permissive parameters
    if (parameterText) {
      if (/type.*string.*description.*(?:any|arbitrary|free.?form)/i.test(parameterText)) {
        findings.push({ tool: name, severity: 'medium', location: 'parameters', message: 'Parameter accepts arbitrary string input without constraints' });
      }
      if (!parameterText.includes('"enum"') && !parameterText.includes('"pattern"') && !parameterText.includes('"maxLength"')) {
        const stringParams = (parameterText.match(/"type"\s*:\s*"string"/g) || []).length;
        if (stringParams > 0) {
          findings.push({ tool: name, severity: 'low', location: 'parameters', message: `${stringParams} string parameter(s) without enum/pattern/maxLength constraints` });
        }
      }
    }

    // Check for missing parameter validation
    if (!tool.parameters && !tool.inputSchema) {
      findings.push({ tool: name, severity: 'low', location: 'parameters', message: 'Tool has no parameter schema. Define parameters for type safety.' });
    }

    return {
      tool: name,
      safe: findings.filter(f => f.severity === 'critical' || f.severity === 'high').length === 0,
      findings
    };
  }

  /**
   * Validate multiple tool definitions.
   */
  validateTools(tools) {
    const results = tools.map(t => this.validateTool(t));
    const unsafe = results.filter(r => !r.safe);

    return {
      totalTools: tools.length,
      safeTools: results.filter(r => r.safe).length,
      unsafeTools: unsafe.length,
      totalFindings: results.reduce((sum, r) => sum + r.findings.length, 0),
      results
    };
  }
}

module.exports = {
  RAGScanner,
  RAG_INJECTION_PATTERNS,
  PromptLinter,
  LINT_RULES,
  ToolSchemaValidator,
  DANGEROUS_TOOL_PATTERNS
};
