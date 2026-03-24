'use strict';

/**
 * Agent Shield — PR Content Scanner
 *
 * Scans pull request diffs for prompt injection, role hijacking,
 * data exfiltration, and other AI-specific threats.
 *
 * Zero external dependencies. All detection runs locally.
 */

// =========================================================================
// DETECTION PATTERNS
// =========================================================================

/**
 * Detection patterns ported from Agent Shield detector-core.js.
 * Each pattern has: regex, severity, category, description, detail.
 */
const PATTERNS = [
  // --- Instruction Override ---
  {
    regex: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|rules|guidelines|prompts|context|directions|directives|text|commands)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text tells AI assistants to ignore their safety rules.',
    detail: 'Instruction override pattern: attempts to nullify prior AI instructions.'
  },
  {
    regex: /disregard\s+(all\s+)?(previous|prior|above|earlier|your)\s+(instructions|rules|guidelines|prompts|training|context)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text tells AI assistants to throw out their rules.',
    detail: 'Instruction disregard pattern: attempts to nullify prior AI instructions.'
  },
  {
    regex: /forget\s+(your|all|any|everything)\s+(training|instructions|rules|guidelines|programming|above|previous|prior)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text tries to make AI assistants forget their training.',
    detail: 'Training override pattern: attempts to reset AI behavioral constraints.'
  },
  {
    regex: /override\s+(?:all\s+)?(?:system|safety|security)\s+(?:settings|prompt|instructions|rules|mechanisms|filters|checks|protocols)/i,
    severity: 'critical',
    category: 'instruction_override',
    description: 'Text tries to override AI safety settings.',
    detail: 'System override pattern: direct attempt to bypass AI safety mechanisms.'
  },
  {
    regex: /(?:^|\n)\s*(?:new|updated|revised|replacement)\s+(?:instructions|policy)\s*:/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text contains fake "new instructions" for AI assistants.',
    detail: 'Instruction replacement pattern: attempts to inject new behavioral directives.'
  },
  {
    regex: /(?:abandon|drop|ditch|clear)\s+(?:all\s+)?(?:prior|previous|above|earlier|initial)\s+(?:context|instructions|rules|constraints|guidelines)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text tells AI to abandon its prior context or instructions.',
    detail: 'Context abandonment pattern: attempts to clear AI behavioral constraints.'
  },

  // --- Role Hijacking ---
  {
    regex: /you\s+are\s+now\s+(?:a|an|the)\s+/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text tries to change what an AI assistant thinks it is.',
    detail: 'Role reassignment pattern: attempts to override AI identity.'
  },
  {
    regex: /from\s+now\s+on[\s,]+(?:you\s+)?(?:will|shall|must|should|are)\s+(?:act|behave|operate|respond|answer|reply|pretend|simulate|function|serve|work)\s+(?:as|like|without)/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text tries to give permanent new orders to AI assistants.',
    detail: 'Persistent role override: attempts to establish new behavioral baseline.'
  },
  {
    regex: /(?:act|behave|function|operate|respond)\s+as\s+(?:a|an)\s+unrestricted/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text tries to remove AI safety restrictions.',
    detail: 'Restriction removal pattern: attempts to disable AI safety guardrails.'
  },
  {
    regex: /pretend\s+(?:to\s+be|you\s+are)\s+(?:a|an)\s+(?:evil|unrestricted|unfiltered|uncensored|malicious)/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text asks AI to pretend to be an evil or unrestricted entity.',
    detail: 'Evil persona pretense: social engineering to adopt unrestricted persona.'
  },
  {
    regex: /\b(?:DAN|D\.A\.N\.?)\s*(?:mode|prompt|jailbreak|\()/i,
    severity: 'critical',
    category: 'role_hijack',
    description: 'Text contains a known AI jailbreak technique called "DAN mode."',
    detail: 'DAN (Do Anything Now) jailbreak pattern detected.'
  },
  {
    regex: /\bdo\s+anything\s+now\b/i,
    severity: 'critical',
    category: 'role_hijack',
    description: 'Text references the "Do Anything Now" jailbreak technique.',
    detail: 'DAN (Do Anything Now) jailbreak reference detected.'
  },
  {
    regex: /\b(?:developer|dev)\s+mode\s+(?:enabled|activated|on|output)/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text tries to trick AI into a fake "developer mode."',
    detail: 'Developer mode activation pattern: common jailbreak technique.'
  },
  {
    regex: /\bjailbreak\s*(?:mode|prompt|enabled|activated)/i,
    severity: 'critical',
    category: 'role_hijack',
    description: 'Text contains an AI jailbreak attempt.',
    detail: 'Explicit jailbreak activation pattern detected.'
  },

  // --- System Prompt Injection ---
  {
    regex: /\[\s*(?:SYSTEM|SYS)\s*\]/i,
    severity: 'critical',
    category: 'prompt_injection',
    description: 'Text contains fake system-level commands for AI assistants.',
    detail: 'Spoofed [SYSTEM] tag: attempts to inject system-level instructions.'
  },
  {
    regex: /\[\s*(?:ADMIN|ADMINISTRATOR)\s*\]/i,
    severity: 'critical',
    category: 'prompt_injection',
    description: 'Text fakes admin-level commands for AI assistants.',
    detail: 'Spoofed [ADMIN] tag: attempts to inject administrator-level instructions.'
  },
  {
    regex: /<<\s*SYS\s*>>/i,
    severity: 'critical',
    category: 'prompt_injection',
    description: 'Text contains hidden system commands in LLaMA format.',
    detail: 'LLaMA-style <<SYS>> system prompt injection detected.'
  },
  {
    regex: /<\|im_start\|>\s*system/i,
    severity: 'critical',
    category: 'prompt_injection',
    description: 'Text contains hidden system commands in ChatML format.',
    detail: 'ChatML-style <|im_start|>system prompt injection detected.'
  },
  {
    regex: /<\|system\|>/i,
    severity: 'critical',
    category: 'prompt_injection',
    description: 'Text contains hidden system-level AI commands.',
    detail: 'System delimiter injection: <|system|> token detected.'
  },
  {
    regex: /(?:^|\n)\s*(?:SYSTEM|ADMIN|ROOT)\s*:\s*.{10,}/i,
    severity: 'high',
    category: 'prompt_injection',
    description: 'Text contains a fake SYSTEM/ADMIN directive.',
    detail: 'Unbracketed system directive: uses SYSTEM: prefix to inject instructions.'
  },

  // --- Data Exfiltration ---
  {
    regex: /send\s+(?:this|the|all|your|my)\s+(?:data|information|content|text|response)\s+to/i,
    severity: 'critical',
    category: 'data_exfiltration',
    description: 'Text tries to make AI assistants send data somewhere.',
    detail: 'Data exfiltration instruction: attempts to redirect AI output to external destination.'
  },
  {
    regex: /output\s+(?:your|the)\s+(?:system\s+)?prompt/i,
    severity: 'high',
    category: 'data_exfiltration',
    description: 'Text tries to extract the AI system prompt.',
    detail: 'System prompt extraction: attempts to reveal system-level instructions.'
  },
  {
    regex: /(?:show|display|print|reveal|output)\s+(?:me\s+)?(?:the\s+)?(?:exact\s+)?(?:text|content)\s+(?:between|inside|within|from)\s+(?:the\s+)?(?:<|&lt;)/i,
    severity: 'high',
    category: 'data_exfiltration',
    description: 'Text tries to extract content between specific tags.',
    detail: 'Tag extraction attempt: instructs agent to reveal content between markup tags.'
  },
  {
    regex: /(?:fetch|get|load|request|call|access)\s+(?:this\s+)?(?:url|link|endpoint|api)\s*:/i,
    severity: 'high',
    category: 'data_exfiltration',
    description: 'Text instructs AI to fetch an external URL.',
    detail: 'External URL fetch instruction: attempts to make agent contact external services.'
  },

  // --- Social Engineering ---
  {
    regex: /(?:this\s+is\s+(?:a|an)\s+)?(?:authorized|official|legitimate|approved)\s+(?:test|override|bypass|exception|request)/i,
    severity: 'medium',
    category: 'social_engineering',
    description: 'Text claims to be an authorized override or test.',
    detail: 'False authority claim: uses social engineering to bypass safety checks.'
  },
  {
    regex: /(?:i\s+am|this\s+is)\s+(?:the|your|a)\s+(?:developer|admin|administrator|owner|creator|maintainer)/i,
    severity: 'medium',
    category: 'social_engineering',
    description: 'Text falsely claims to be the developer or admin.',
    detail: 'Identity impersonation: claims developer/admin identity to gain trust.'
  },

  // --- Encoding / Obfuscation ---
  {
    regex: /(?:base64|b64|rot13|hex)\s*(?:decode|encrypt|encode|convert)/i,
    severity: 'medium',
    category: 'encoding',
    description: 'Text references encoding/decoding operations that may hide malicious content.',
    detail: 'Encoding reference: mentions encoding schemes commonly used to obfuscate payloads.'
  },
  {
    regex: /eval\s*\(\s*(?:atob|btoa|decodeURIComponent|unescape)\s*\(/i,
    severity: 'critical',
    category: 'encoding',
    description: 'Text contains eval with decoding — classic code injection.',
    detail: 'Eval with decode: code injection using eval() with decoding functions.'
  }
];

// =========================================================================
// SEVERITY LEVELS
// =========================================================================

const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1 };

/**
 * Check if a severity meets the minimum threshold.
 * @param {string} severity
 * @param {string} minSeverity
 * @returns {boolean}
 */
function meetsSeverity(severity, minSeverity) {
  return (SEVERITY_ORDER[severity] || 0) >= (SEVERITY_ORDER[minSeverity] || 0);
}

// =========================================================================
// PR SCANNER CLASS
// =========================================================================

/**
 * Scans pull request diffs for AI security threats.
 */
class PRScanner {
  /**
   * @param {Object} [config]
   * @param {string} [config.minSeverity='medium'] - Minimum severity to report
   * @param {string[]} [config.categories] - Categories to scan (null = all)
   * @param {boolean} [config.annotateInline=true] - Create inline annotations
   */
  constructor(config = {}) {
    this.minSeverity = config.minSeverity || 'medium';
    this.categories = config.categories || null;
    this.annotateInline = config.annotateInline !== false;
    this.patterns = PATTERNS;
  }

  /**
   * Scan parsed diff entries for threats.
   * @param {Array<{file: string, line: number, content: string}>} diffEntries
   * @returns {{threats: Array, annotations: Array, summary: Object}}
   */
  scanDiff(diffEntries) {
    const threats = [];
    const annotations = [];
    const categoryCounts = {};
    let maxSeverity = 'low';

    for (const entry of diffEntries) {
      const results = this._scanLine(entry.content);
      for (const result of results) {
        if (!meetsSeverity(result.severity, this.minSeverity)) continue;
        if (this.categories && !this.categories.includes(result.category)) continue;

        const threat = {
          file: entry.file,
          line: entry.line,
          content: entry.content.substring(0, 200),
          pattern: result.description,
          severity: result.severity,
          category: result.category,
          detail: result.detail
        };
        threats.push(threat);

        if (this.annotateInline) {
          annotations.push(this.formatAnnotation(entry.file, entry.line, threat));
        }

        categoryCounts[result.category] = (categoryCounts[result.category] || 0) + 1;

        if (SEVERITY_ORDER[result.severity] > SEVERITY_ORDER[maxSeverity]) {
          maxSeverity = result.severity;
        }
      }
    }

    const summary = {
      totalThreats: threats.length,
      maxSeverity: threats.length > 0 ? maxSeverity : 'none',
      categoryCounts,
      safe: threats.length === 0,
      filesScanned: new Set(diffEntries.map(e => e.file)).size
    };

    return { threats, annotations, summary };
  }

  /**
   * Scan a single file's content.
   * @param {string} filename
   * @param {string} content
   * @returns {{threats: Array, annotations: Array, summary: Object}}
   */
  scanFile(filename, content) {
    const lines = content.split('\n');
    const entries = lines.map((line, i) => ({
      file: filename,
      line: i + 1,
      content: line
    }));
    return this.scanDiff(entries);
  }

  /**
   * Scan a single line of text against all patterns.
   * @param {string} text
   * @returns {Array}
   * @private
   */
  _scanLine(text) {
    const results = [];
    for (const pattern of this.patterns) {
      if (pattern.regex.test(text)) {
        results.push(pattern);
      }
    }
    return results;
  }

  /**
   * Format a threat as a GitHub Check Run annotation.
   * @param {string} file
   * @param {number} line
   * @param {Object} threat
   * @returns {Object}
   */
  formatAnnotation(file, line, threat) {
    const level = threat.severity === 'critical' || threat.severity === 'high'
      ? 'failure'
      : 'warning';

    return {
      path: file,
      start_line: line,
      end_line: line,
      annotation_level: level,
      title: `[${threat.severity.toUpperCase()}] ${threat.category}`,
      message: threat.pattern,
      raw_details: threat.detail
    };
  }

  /**
   * Format scan results as a markdown summary for a PR comment.
   * @param {{threats: Array, annotations: Array, summary: Object}} results
   * @returns {string}
   */
  formatSummary(results) {
    const { threats, summary } = results;

    if (summary.safe) {
      return [
        '## :shield: Agent Shield — PR Scan Passed',
        '',
        `Scanned **${summary.filesScanned}** files. No prompt injection threats detected.`,
        '',
        '---',
        '*Powered by [Agent Shield](https://github.com/agent-shield/agent-shield)*'
      ].join('\n');
    }

    const lines = [
      '## :warning: Agent Shield — Threats Detected',
      '',
      `Found **${summary.totalThreats}** potential threat(s) across **${summary.filesScanned}** file(s).`,
      `**Max severity:** ${summary.maxSeverity}`,
      '',
      '### Threat Breakdown',
      '',
      '| Category | Count |',
      '|----------|-------|'
    ];

    for (const [category, count] of Object.entries(summary.categoryCounts)) {
      const safeCategory = String(category).replace(/\|/g, '\\|');
      lines.push(`| ${safeCategory} | ${count} |`);
    }

    lines.push('');
    lines.push('### Details');
    lines.push('');

    for (const threat of threats.slice(0, 20)) {
      const icon = threat.severity === 'critical' ? ':red_circle:'
        : threat.severity === 'high' ? ':orange_circle:'
        : ':yellow_circle:';
      lines.push(`- ${icon} **${threat.severity.toUpperCase()}** \`${threat.file}:${threat.line}\` — ${threat.pattern}`);
    }

    if (threats.length > 20) {
      lines.push(`- ... and ${threats.length - 20} more`);
    }

    lines.push('');
    lines.push('---');
    lines.push('*Powered by [Agent Shield](https://github.com/agent-shield/agent-shield)*');

    return lines.join('\n');
  }
}

module.exports = { PRScanner, PATTERNS, SEVERITY_ORDER, meetsSeverity };
