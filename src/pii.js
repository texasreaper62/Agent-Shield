'use strict';

/**
 * PII Redaction (#43), Data Loss Prevention (#45), and Output Content Policies (#17)
 *
 * - PII Redaction: Automatically detect and redact personal information.
 * - DLP: Define sensitive data patterns for your organization and block leaks.
 * - Content Policies: Block agents from generating certain content categories.
 */

// =========================================================================
// PII PATTERNS
// =========================================================================

const PII_PATTERNS = {
  email: {
    regex: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g,
    replacement: '[EMAIL REDACTED]',
    category: 'email',
    description: 'Email address'
  },
  phone_us: {
    regex: /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
    replacement: '[PHONE REDACTED]',
    category: 'phone',
    description: 'US phone number'
  },
  phone_intl: {
    regex: /\b\+\d{1,3}[-.\s]?\d{2,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b/g,
    replacement: '[PHONE REDACTED]',
    category: 'phone',
    description: 'International phone number'
  },
  ssn: {
    regex: /\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b/g,
    replacement: '[SSN REDACTED]',
    category: 'ssn',
    description: 'Social Security Number'
  },
  credit_card: {
    regex: /\b(?:\d{4}[-.\s]?){3}\d{4}\b/g,
    replacement: '[CREDIT CARD REDACTED]',
    category: 'credit_card',
    description: 'Credit card number'
  },
  ip_address: {
    regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
    replacement: '[IP REDACTED]',
    category: 'ip_address',
    description: 'IP address'
  },
  date_of_birth: {
    regex: /\b(?:date\s+of\s+birth|DOB|born\s+on)\s*:?\s*\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}\b/gi,
    replacement: '[DOB REDACTED]',
    category: 'dob',
    description: 'Date of birth'
  },
  street_address: {
    regex: /\b\d{1,5}\s+[A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)*\s+(?:St|Street|Ave|Avenue|Blvd|Boulevard|Dr|Drive|Ln|Lane|Rd|Road|Way|Ct|Court|Pl|Place)\b\.?\s*,?\s*(?:[A-Z][a-z]+\s*,?\s*)?(?:[A-Z]{2}\s*\d{5}(?:-\d{4})?)?/g,
    replacement: '[ADDRESS REDACTED]',
    category: 'address',
    description: 'Street address'
  },
  passport: {
    regex: /\b(?:passport)\s*(?:#|number|no\.?)\s*:?\s*[A-Z0-9]{6,9}\b/gi,
    replacement: '[PASSPORT REDACTED]',
    category: 'passport',
    description: 'Passport number'
  },
  drivers_license: {
    regex: /\b(?:driver'?s?\s*license|DL)\s*(?:#|number|no\.?)\s*:?\s*[A-Z0-9-]{5,15}\b/gi,
    replacement: '[DRIVERS LICENSE REDACTED]',
    category: 'drivers_license',
    description: 'Driver\'s license number'
  }
};

class PIIRedactor {
  /**
   * @param {object} [options]
   * @param {Array<string>} [options.categories] - PII categories to redact. Defaults to all.
   * @param {object} [options.customPatterns] - Additional custom PII patterns.
   * @param {boolean} [options.logging=false] - Log redactions.
   */
  constructor(options = {}) {
    // Collect unique category values (not keys) so phone_us/phone_intl both map to 'phone'
    const allCategories = [...new Set(Object.values(PII_PATTERNS).map(p => p.category))];
    this.categories = options.categories || allCategories;
    this.customPatterns = options.customPatterns || {};
    this.logging = options.logging || false;
    this.stats = { totalRedactions: 0, byCategory: {} };
  }

  /**
   * Redacts PII from text.
   *
   * @param {string} text - Text to redact.
   * @returns {object} { redacted: string, findings: Array, count: number }
   */
  redact(text) {
    if (typeof text !== 'string' || !text) return { redacted: text || '', findings: [], count: 0 };

    let redacted = text;
    const findings = [];

    // Apply built-in patterns
    for (const [name, pattern] of Object.entries(PII_PATTERNS)) {
      if (!this.categories.includes(pattern.category)) continue;

      const matches = redacted.match(pattern.regex);
      if (matches) {
        for (const match of matches) {
          findings.push({
            type: name,
            category: pattern.category,
            description: pattern.description,
            preview: match.substring(0, 4) + '...'
          });
        }
        redacted = redacted.replace(pattern.regex, pattern.replacement);
        this.stats.byCategory[pattern.category] = (this.stats.byCategory[pattern.category] || 0) + matches.length;
      }
    }

    // Apply custom patterns
    for (const [name, pattern] of Object.entries(this.customPatterns)) {
      const matches = redacted.match(pattern.regex);
      if (matches) {
        for (const match of matches) {
          findings.push({
            type: name,
            category: 'custom',
            description: pattern.description || name,
            preview: match.substring(0, 4) + '...'
          });
        }
        redacted = redacted.replace(pattern.regex, pattern.replacement || `[${name.toUpperCase()} REDACTED]`);
      }
    }

    this.stats.totalRedactions += findings.length;

    if (this.logging && findings.length > 0) {
      console.warn(`[Agent Shield PII] Redacted ${findings.length} item(s):`, findings.map(f => f.description));
    }

    return { redacted, findings, count: findings.length };
  }

  /**
   * Checks text for PII without redacting. Useful for output scanning.
   *
   * @param {string} text
   * @returns {object} { hasPII: boolean, findings: Array }
   */
  detect(text) {
    if (!text) return { hasPII: false, findings: [] };

    const findings = [];

    for (const [name, pattern] of Object.entries(PII_PATTERNS)) {
      if (!this.categories.includes(pattern.category)) continue;

      const matches = text.match(pattern.regex);
      if (matches) {
        for (const match of matches) {
          findings.push({
            type: name,
            category: pattern.category,
            description: pattern.description,
            value: match
          });
        }
      }
    }

    return { hasPII: findings.length > 0, findings };
  }

  getStats() {
    return { ...this.stats };
  }
}

// =========================================================================
// DATA LOSS PREVENTION
// =========================================================================

class DLPEngine {
  /**
   * @param {object} [options]
   * @param {Array<object>} [options.rules=[]] - DLP rules.
   * @param {Function} [options.onViolation] - Callback when a rule is violated.
   */
  constructor(options = {}) {
    this.rules = options.rules || [];
    this.onViolation = options.onViolation || null;
    this.violations = [];
  }

  /**
   * Adds a DLP rule.
   *
   * @param {object} rule
   * @param {string} rule.name - Rule name.
   * @param {RegExp|string} rule.pattern - Pattern to match.
   * @param {string} [rule.action='block'] - Action: 'block', 'redact', or 'warn'.
   * @param {string} [rule.replacement] - Replacement text for 'redact' action.
   * @param {string} [rule.severity='high'] - Severity level.
   * @returns {DLPEngine} this (for chaining)
   */
  addRule(rule) {
    let pattern;
    if (typeof rule.pattern === 'string') {
      try {
        pattern = new RegExp(rule.pattern, 'gi');
      } catch (err) {
        console.error(`[Agent Shield] DLPEngine.addRule(): invalid regex pattern "${rule.pattern}": ${err.message}`);
        return this;
      }
    } else {
      pattern = rule.pattern;
    }
    this.rules.push({
      name: rule.name,
      pattern,
      action: rule.action || 'block',
      replacement: rule.replacement || `[${rule.name.toUpperCase()} BLOCKED]`,
      severity: rule.severity || 'high'
    });
    return this;
  }

  /**
   * Scans text against all DLP rules.
   *
   * @param {string} text
   * @param {string} [source='unknown']
   * @returns {object} { clean: boolean, violations: Array, redactedText: string }
   */
  scan(text, source = 'unknown') {
    if (!text) return { clean: true, violations: [], redactedText: text };

    const violations = [];
    let redactedText = text;

    for (const rule of this.rules) {
      // Reset regex lastIndex for global patterns
      if (rule.pattern.global) rule.pattern.lastIndex = 0;

      const matches = text.match(rule.pattern);
      if (matches) {
        for (const match of matches) {
          const violation = {
            rule: rule.name,
            action: rule.action,
            severity: rule.severity,
            match: match.substring(0, 50),
            source,
            timestamp: Date.now()
          };
          violations.push(violation);
          this.violations.push(violation);
        }

        if (rule.action === 'redact') {
          if (rule.pattern.global) rule.pattern.lastIndex = 0;
          redactedText = redactedText.replace(rule.pattern, rule.replacement);
        }
      }
    }

    if (violations.length > 0 && this.onViolation) {
      this.onViolation({ violations, source });
    }

    const hasBlock = violations.some(v => v.action === 'block');

    return {
      clean: violations.length === 0,
      blocked: hasBlock,
      violations,
      redactedText
    };
  }

  /**
   * Returns violation history.
   * @returns {Array}
   */
  getViolations() {
    return [...this.violations];
  }

  clearHistory() {
    this.violations = [];
  }
}

// =========================================================================
// OUTPUT CONTENT POLICIES
// =========================================================================

const CONTENT_CATEGORIES = {
  medical_advice: {
    patterns: [
      /\b(?:you\s+should\s+(?:take|stop\s+taking|increase|decrease)\s+(?:your\s+)?(?:medication|dosage|prescription))\b/gi,
      /\b(?:diagnos(?:e|is|ed)|prescrib(?:e|ed)|treatment\s+plan)\b.*\b(?:you|your|patient)\b/gi
    ],
    description: 'Medical advice or diagnosis'
  },
  legal_advice: {
    patterns: [
      /\b(?:you\s+should\s+(?:sue|file\s+a\s+lawsuit|take\s+legal\s+action|hire\s+a\s+lawyer))\b/gi,
      /\b(?:legal(?:ly)?\s+(?:binding|obligat|liable|entitled))\b.*\b(?:you|your)\b/gi
    ],
    description: 'Legal advice or recommendations'
  },
  financial_advice: {
    patterns: [
      /\b(?:you\s+should\s+(?:invest|buy|sell|trade)\s+(?:in\s+)?(?:stocks?|bonds?|crypto|bitcoin|options?))\b/gi,
      /\b(?:guaranteed\s+(?:return|profit|income))\b/gi
    ],
    description: 'Financial or investment advice'
  },
  harmful_instructions: {
    patterns: [
      /\b(?:how\s+to\s+(?:make|build|create)\s+(?:a\s+)?(?:bomb|weapon|explosive|poison))\b/gi,
      /\b(?:instructions\s+for\s+(?:making|building|creating)\s+(?:a\s+)?(?:bomb|weapon|explosive))\b/gi
    ],
    description: 'Harmful or dangerous instructions'
  }
};

class ContentPolicy {
  /**
   * @param {object} [options]
   * @param {Array<string>} [options.blockedCategories=[]] - Categories to block.
   * @param {Array<object>} [options.customCategories=[]] - Custom content categories.
   * @param {Function} [options.onViolation] - Callback on policy violation.
   */
  constructor(options = {}) {
    this.blockedCategories = options.blockedCategories || [];
    this.customCategories = options.customCategories || [];
    this.onViolation = options.onViolation || null;
  }

  /**
   * Checks text against content policies.
   *
   * @param {string} text
   * @returns {object} { allowed: boolean, violations: Array }
   */
  check(text) {
    if (!text) return { allowed: true, violations: [] };

    const violations = [];

    // Check built-in categories
    for (const category of this.blockedCategories) {
      const def = CONTENT_CATEGORIES[category];
      if (!def) continue;

      for (const pattern of def.patterns) {
        if (pattern.global) pattern.lastIndex = 0;
        if (pattern.test(text)) {
          violations.push({
            category,
            description: def.description,
            severity: 'high'
          });
          break;
        }
      }
    }

    // Check custom categories
    for (const custom of this.customCategories) {
      for (const pattern of custom.patterns) {
        const regex = typeof pattern === 'string' ? new RegExp(pattern, 'gi') : pattern;
        if (regex.global) regex.lastIndex = 0;
        if (regex.test(text)) {
          violations.push({
            category: custom.name,
            description: custom.description || custom.name,
            severity: custom.severity || 'medium'
          });
          break;
        }
      }
    }

    if (violations.length > 0 && this.onViolation) {
      this.onViolation({ violations, timestamp: Date.now() });
    }

    return { allowed: violations.length === 0, violations };
  }
}

module.exports = { PIIRedactor, DLPEngine, ContentPolicy, PII_PATTERNS, CONTENT_CATEGORIES };
