'use strict';

/**
 * Agent Shield — Policy-as-Code DSL
 *
 * A domain-specific language for writing shield policies.
 * Like Rego for OPA, but for prompt injection rules.
 *
 * Example:
 *   policy "strict" {
 *     severity minimum "high"
 *     rule "no-injection" {
 *       when input matches "ignore.*previous.*instructions"
 *       then block with severity "critical"
 *     }
 *   }
 */

// =========================================================================
// BUILTIN FUNCTIONS
// =========================================================================

/** @type {Object<string, function>} */
const BUILTIN_FUNCTIONS = {
  matches: (text, pattern) => new RegExp(pattern, 'i').test(text),
  contains: (text, substr) => typeof text === 'string' && text.toLowerCase().includes(substr.toLowerCase()),
  starts_with: (text, prefix) => typeof text === 'string' && text.toLowerCase().startsWith(prefix.toLowerCase()),
  ends_with: (text, suffix) => typeof text === 'string' && text.toLowerCase().endsWith(suffix.toLowerCase()),
  length: (text) => typeof text === 'string' ? text.length : 0,
  lower: (text) => typeof text === 'string' ? text.toLowerCase() : '',
  upper: (text) => typeof text === 'string' ? text.toUpperCase() : '',
  hash: (text) => {
    let h = 0;
    for (let i = 0; i < text.length; i++) {
      h = ((h << 5) - h + text.charCodeAt(i)) | 0;
    }
    return h.toString(16);
  },
  now: () => Date.now(),
  severity_gte: (a, b) => {
    const order = { low: 1, medium: 2, high: 3, critical: 4 };
    return (order[a] || 0) >= (order[b] || 0);
  },
};

// =========================================================================
// TOKEN TYPES
// =========================================================================

const TOKEN_TYPES = {
  KEYWORD: 'keyword',
  STRING: 'string',
  NUMBER: 'number',
  IDENTIFIER: 'identifier',
  BLOCK_OPEN: 'block_open',
  BLOCK_CLOSE: 'block_close',
  OPERATOR: 'operator',
  NEWLINE: 'newline',
};

const KEYWORDS = new Set([
  'policy', 'rule', 'when', 'then', 'and', 'or', 'not',
  'allow', 'block', 'warn', 'with', 'severity', 'minimum',
  'message', 'rate_limit', 'per', 'scan_mode', 'on_threat',
  'input', 'source', 'metadata', 'is', 'matches', 'contains',
  'starts_with', 'ends_with', 'greater_than', 'less_than', 'true', 'false',
]);

// =========================================================================
// POLICY PARSER
// =========================================================================

/**
 * Tokenizer and recursive descent parser for the policy DSL.
 */
class PolicyParser {
  constructor() {
    this._tokens = [];
    this._pos = 0;
  }

  /**
   * Tokenize DSL source into tokens.
   * @param {string} source
   * @returns {Array<{type: string, value: string, line: number, col: number}>}
   */
  tokenize(source) {
    const tokens = [];
    const lines = source.split('\n');

    for (let lineNum = 0; lineNum < lines.length; lineNum++) {
      let line = lines[lineNum];
      // Strip comments
      const commentIdx = line.indexOf('#');
      if (commentIdx >= 0) line = line.substring(0, commentIdx);
      line = line.trim();
      if (!line) continue;

      let col = 0;
      let i = 0;
      while (i < line.length) {
        // Skip whitespace
        if (/\s/.test(line[i])) { i++; col++; continue; }

        // Block delimiters
        if (line[i] === '{') {
          tokens.push({ type: TOKEN_TYPES.BLOCK_OPEN, value: '{', line: lineNum + 1, col });
          i++; col++; continue;
        }
        if (line[i] === '}') {
          tokens.push({ type: TOKEN_TYPES.BLOCK_CLOSE, value: '}', line: lineNum + 1, col });
          i++; col++; continue;
        }

        // Strings
        if (line[i] === '"') {
          let str = '';
          i++; col++;
          while (i < line.length && line[i] !== '"') {
            if (line[i] === '\\' && i + 1 < line.length) { str += line[i + 1]; i += 2; col += 2; }
            else { str += line[i]; i++; col++; }
          }
          i++; col++; // closing quote
          tokens.push({ type: TOKEN_TYPES.STRING, value: str, line: lineNum + 1, col });
          continue;
        }

        // Numbers
        if (/\d/.test(line[i])) {
          let num = '';
          while (i < line.length && /[\d.]/.test(line[i])) { num += line[i]; i++; col++; }
          tokens.push({ type: TOKEN_TYPES.NUMBER, value: num, line: lineNum + 1, col });
          continue;
        }

        // Dot operator
        if (line[i] === '.') {
          tokens.push({ type: TOKEN_TYPES.OPERATOR, value: '.', line: lineNum + 1, col });
          i++; col++; continue;
        }

        // Identifiers / keywords
        if (/[a-zA-Z_]/.test(line[i])) {
          let word = '';
          while (i < line.length && /[a-zA-Z0-9_]/.test(line[i])) { word += line[i]; i++; col++; }
          const type = KEYWORDS.has(word) ? TOKEN_TYPES.KEYWORD : TOKEN_TYPES.IDENTIFIER;
          tokens.push({ type, value: word, line: lineNum + 1, col });
          continue;
        }

        // Skip unknown
        i++; col++;
      }
    }

    return tokens;
  }

  /**
   * Parse tokens into an AST.
   * @param {Array} tokens
   * @returns {{type: string, policies: Array}}
   */
  parse(tokens) {
    this._tokens = tokens;
    this._pos = 0;
    const policies = [];

    while (this._pos < this._tokens.length) {
      if (this._peek('policy')) {
        policies.push(this._parsePolicy());
      } else {
        this._pos++;
      }
    }

    return { type: 'Program', policies };
  }

  /** @private */
  _peek(value) {
    return this._pos < this._tokens.length && this._tokens[this._pos].value === value;
  }

  /** @private */
  _consume(value) {
    if (this._pos >= this._tokens.length) throw new Error(`Unexpected end of input, expected '${value}'`);
    const token = this._tokens[this._pos];
    if (value && token.value !== value) {
      throw new Error(`Expected '${value}' at line ${token.line}, got '${token.value}'`);
    }
    this._pos++;
    return token;
  }

  /** @private */
  _consumeType(type) {
    if (this._pos >= this._tokens.length) throw new Error(`Unexpected end of input, expected ${type}`);
    const token = this._tokens[this._pos];
    if (token.type !== type) throw new Error(`Expected ${type} at line ${token.line}, got ${token.type}`);
    this._pos++;
    return token;
  }

  /** @private */
  _parsePolicy() {
    this._consume('policy');
    const name = this._consumeType(TOKEN_TYPES.STRING);
    this._consume('{');

    const rules = [];
    const allows = [];
    const config = {};

    while (!this._peek('}') && this._pos < this._tokens.length) {
      if (this._peek('rule')) {
        rules.push(this._parseRule());
      } else if (this._peek('allow')) {
        allows.push(this._parseAllow());
      } else if (this._peek('severity')) {
        this._consume('severity');
        if (this._peek('minimum')) this._consume('minimum');
        config.minSeverity = this._consumeType(TOKEN_TYPES.STRING).value;
      } else if (this._peek('block')) {
        this._consume('block');
        this._consume('on_threat');
        config.blockOnThreat = this._tokens[this._pos].value === 'true';
        this._pos++;
      } else if (this._peek('rate_limit')) {
        this._consume('rate_limit');
        config.rateLimit = parseInt(this._consumeType(TOKEN_TYPES.NUMBER).value);
        this._consume('per');
        config.rateLimitPeriod = this._consumeType(TOKEN_TYPES.STRING).value;
      } else if (this._peek('scan_mode')) {
        this._consume('scan_mode');
        config.scanMode = this._consumeType(TOKEN_TYPES.STRING).value;
      } else {
        this._pos++;
      }
    }

    this._consume('}');
    return { type: 'Policy', name: name.value, rules, allows, config };
  }

  /** @private */
  _parseRule() {
    this._consume('rule');
    const name = this._consumeType(TOKEN_TYPES.STRING);
    this._consume('{');

    const conditions = [];
    let action = 'block';
    let severity = 'high';
    let message = '';

    while (!this._peek('}') && this._pos < this._tokens.length) {
      if (this._peek('when')) {
        this._consume('when');
        conditions.push(this._parseCondition());
      } else if (this._peek('and')) {
        this._consume('and');
        conditions.push(this._parseCondition());
      } else if (this._peek('then')) {
        this._consume('then');
        action = this._tokens[this._pos].value;
        this._pos++;
        if (this._peek('with')) {
          this._consume('with');
          this._consume('severity');
          severity = this._consumeType(TOKEN_TYPES.STRING).value;
        }
      } else if (this._peek('message')) {
        this._consume('message');
        message = this._consumeType(TOKEN_TYPES.STRING).value;
      } else {
        this._pos++;
      }
    }

    this._consume('}');
    return { type: 'Rule', name: name.value, conditions, action, severity, message };
  }

  /** @private */
  _parseCondition() {
    const subject = this._tokens[this._pos].value;
    this._pos++;

    // Handle property access (e.g., input.length)
    let property = null;
    if (this._peek('.')) {
      this._consume('.');
      property = this._tokens[this._pos].value;
      this._pos++;
    }

    const operator = this._tokens[this._pos].value;
    this._pos++;

    const value = this._tokens[this._pos];
    this._pos++;

    return {
      type: 'Condition',
      subject,
      property,
      operator,
      value: value.value,
      valueType: value.type,
    };
  }

  /** @private */
  _parseAllow() {
    this._consume('allow');
    this._consume('{');

    const conditions = [];
    const logic = []; // 'and' or 'or' between conditions

    while (!this._peek('}') && this._pos < this._tokens.length) {
      if (this._peek('when')) {
        this._consume('when');
        conditions.push(this._parseCondition());
      } else if (this._peek('and')) {
        this._consume('and');
        logic.push('and');
        conditions.push(this._parseCondition());
      } else if (this._peek('or')) {
        this._consume('or');
        logic.push('or');
        conditions.push(this._parseCondition());
      } else {
        this._pos++;
      }
    }

    this._consume('}');
    return { type: 'Allow', conditions, logic };
  }
}

// =========================================================================
// POLICY COMPILER
// =========================================================================

/**
 * Compiles an AST into executable policy functions.
 */
class PolicyCompiler {
  constructor() {}

  /**
   * Compile an AST into a CompiledPolicy.
   * @param {{type: string, policies: Array}} ast
   * @returns {Array<{name: string, rules: Array, allows: Array, config: object}>}
   */
  compile(ast) {
    return ast.policies.map(p => this._compilePolicy(p));
  }

  /** @private */
  _compilePolicy(policyNode) {
    const rules = policyNode.rules.map(r => this._compileRule(r));
    const allows = policyNode.allows.map(a => this._compileAllow(a));
    return {
      name: policyNode.name,
      config: policyNode.config,
      rules,
      allows,
    };
  }

  /** @private */
  _compileRule(ruleNode) {
    const predicates = ruleNode.conditions.map(c => this._compileCondition(c));
    return {
      name: ruleNode.name,
      action: ruleNode.action,
      severity: ruleNode.severity,
      message: ruleNode.message,
      test: (context) => predicates.every(pred => pred(context)),
    };
  }

  /** @private */
  _compileAllow(allowNode) {
    const predicates = allowNode.conditions.map(c => this._compileCondition(c));
    const logic = allowNode.logic;

    return {
      test: (context) => {
        if (predicates.length === 0) return true;
        let result = predicates[0](context);
        for (let i = 1; i < predicates.length; i++) {
          const op = logic[i - 1] || 'and';
          if (op === 'or') result = result || predicates[i](context);
          else result = result && predicates[i](context);
        }
        return result;
      },
    };
  }

  /** @private */
  _compileCondition(condNode) {
    const { subject, property, operator, value, valueType } = condNode;

    return (context) => {
      let subjectValue;
      if (subject === 'input') {
        subjectValue = property ? this._getProperty(context.input, property) : context.input;
      } else if (subject === 'source') {
        subjectValue = context.source || '';
      } else if (subject === 'metadata') {
        subjectValue = property ? (context.metadata || {})[property] : context.metadata;
      } else {
        subjectValue = context[subject];
      }

      const compareValue = valueType === TOKEN_TYPES.NUMBER ? parseFloat(value)
        : value === 'true' ? true
        : value === 'false' ? false
        : value;

      switch (operator) {
        case 'matches': return BUILTIN_FUNCTIONS.matches(String(subjectValue), String(compareValue));
        case 'contains': return BUILTIN_FUNCTIONS.contains(String(subjectValue), String(compareValue));
        case 'is': return subjectValue === compareValue;
        case 'starts_with': return BUILTIN_FUNCTIONS.starts_with(String(subjectValue), String(compareValue));
        case 'ends_with': return BUILTIN_FUNCTIONS.ends_with(String(subjectValue), String(compareValue));
        case 'greater_than': return Number(subjectValue) > Number(compareValue);
        case 'less_than': return Number(subjectValue) < Number(compareValue);
        default: return false;
      }
    };
  }

  /** @private */
  _getProperty(obj, prop) {
    if (typeof obj === 'string') {
      if (prop === 'length') return obj.length;
    }
    if (obj && typeof obj === 'object') return obj[prop];
    return undefined;
  }
}

// =========================================================================
// POLICY RUNTIME
// =========================================================================

/**
 * Executes compiled policies against scan contexts.
 */
class PolicyRuntime {
  /**
   * @param {object} [builtins]
   */
  constructor(builtins) {
    this._functions = { ...BUILTIN_FUNCTIONS, ...builtins };
  }

  /**
   * Register a custom function.
   * @param {string} name
   * @param {function} fn
   */
  registerFunction(name, fn) {
    this._functions[name] = fn;
  }

  /**
   * Execute a compiled policy against a context.
   * @param {object} compiledPolicy
   * @param {{input: string, source?: string, metadata?: object}} context
   * @returns {{action: string, reason: string, severity: string, matched_rules: string[]}}
   */
  execute(compiledPolicy, context) {
    // Check allow rules first
    for (const allow of compiledPolicy.allows) {
      if (allow.test(context)) {
        return { action: 'allow', reason: 'Matched allow rule', severity: 'safe', matched_rules: [] };
      }
    }

    // Check deny rules
    const matchedRules = [];
    let maxSeverity = 'safe';
    let action = 'allow';
    let reason = '';
    const severityOrder = { safe: 0, low: 1, medium: 2, high: 3, critical: 4 };

    for (const rule of compiledPolicy.rules) {
      if (rule.test(context)) {
        matchedRules.push(rule.name);
        if (severityOrder[rule.severity] > severityOrder[maxSeverity]) {
          maxSeverity = rule.severity;
        }
        action = rule.action;
        reason = rule.message || `Matched rule: ${rule.name}`;
      }
    }

    if (matchedRules.length === 0) {
      return { action: 'allow', reason: 'No rules matched', severity: 'safe', matched_rules: [] };
    }

    return { action, reason, severity: maxSeverity, matched_rules: matchedRules };
  }
}

// =========================================================================
// POLICY VALIDATOR
// =========================================================================

/**
 * Validates policy DSL syntax and semantics.
 */
class PolicyValidator {
  constructor() {}

  /**
   * Validate DSL source.
   * @param {string} source
   * @returns {{valid: boolean, errors: Array<{message: string, line?: number}>, warnings: Array}}
   */
  validate(source) {
    const errors = [];
    const warnings = [];
    const parser = new PolicyParser();

    // Check braces
    let braceCount = 0;
    const lines = source.split('\n');
    for (let i = 0; i < lines.length; i++) {
      for (const ch of lines[i]) {
        if (ch === '{') braceCount++;
        if (ch === '}') braceCount--;
        if (braceCount < 0) {
          errors.push({ message: `Unexpected '}' at line ${i + 1}`, line: i + 1 });
        }
      }
    }
    if (braceCount > 0) {
      errors.push({ message: `Unclosed block: ${braceCount} missing '}'` });
    }

    // Try tokenizing
    let tokens;
    try {
      tokens = parser.tokenize(source);
    } catch (e) {
      errors.push({ message: `Tokenization error: ${e.message}` });
      return { valid: false, errors, warnings };
    }

    // Check for policy keyword
    const hasPolicyKeyword = tokens.some(t => t.value === 'policy');
    if (!hasPolicyKeyword) {
      errors.push({ message: 'No policy block found. Source must contain at least one "policy" block.' });
    }

    // Check severity values
    const validSeverities = new Set(['low', 'medium', 'high', 'critical']);
    for (let i = 0; i < tokens.length; i++) {
      if (tokens[i].value === 'severity' && i + 1 < tokens.length) {
        const next = tokens[i + 1].value === 'minimum' ? tokens[i + 2] : tokens[i + 1];
        if (next && next.type === TOKEN_TYPES.STRING && !validSeverities.has(next.value)) {
          warnings.push({ message: `Unknown severity '${next.value}' at line ${next.line}. Valid: low, medium, high, critical`, line: next.line });
        }
      }
    }

    // Try parsing
    try {
      parser.parse(tokens);
    } catch (e) {
      errors.push({ message: `Parse error: ${e.message}` });
    }

    // Check for duplicate rule names
    const ruleNames = new Set();
    for (const token of tokens) {
      if (token.value === 'rule') {
        const idx = tokens.indexOf(token);
        if (idx + 1 < tokens.length && tokens[idx + 1].type === TOKEN_TYPES.STRING) {
          const name = tokens[idx + 1].value;
          if (ruleNames.has(name)) {
            warnings.push({ message: `Duplicate rule name '${name}' at line ${tokens[idx + 1].line}`, line: tokens[idx + 1].line });
          }
          ruleNames.add(name);
        }
      }
    }

    return { valid: errors.length === 0, errors, warnings };
  }
}

// =========================================================================
// POLICY DSL (MAIN ENTRY)
// =========================================================================

/**
 * Main entry point for the Policy DSL.
 */
class PolicyDSL {
  constructor() {
    this._parser = new PolicyParser();
    this._compiler = new PolicyCompiler();
    this._runtime = new PolicyRuntime();
    this._validator = new PolicyValidator();
  }

  /**
   * Parse DSL source into AST.
   * @param {string} source
   * @returns {object}
   */
  parse(source) {
    const tokens = this._parser.tokenize(source);
    return this._parser.parse(tokens);
  }

  /**
   * Compile AST into executable policies.
   * @param {object} ast
   * @returns {Array}
   */
  compile(ast) {
    return this._compiler.compile(ast);
  }

  /**
   * Evaluate a compiled policy against a context.
   * @param {object} policy
   * @param {{input: string, source?: string, metadata?: object}} context
   * @returns {{action: string, reason: string, severity: string, matched_rules: string[]}}
   */
  evaluate(policy, context) {
    return this._runtime.execute(policy, context);
  }

  /**
   * Parse + compile in one step.
   * @param {string} source
   * @returns {Array}
   */
  loadFile(source) {
    const ast = this.parse(source);
    return this.compile(ast);
  }

  /**
   * Validate DSL source.
   * @param {string} source
   * @returns {{valid: boolean, errors: Array, warnings: Array}}
   */
  validate(source) {
    return this._validator.validate(source);
  }
}

// =========================================================================
// EXAMPLE POLICIES
// =========================================================================

const EXAMPLE_STRICT_POLICY = `
policy "strict" {
  severity minimum "low"
  block on_threat true
  scan_mode "deep"

  rule "no-injection" {
    when input matches "ignore.*previous.*instructions"
    then block with severity "critical"
    message "Instruction override attempt detected"
  }

  rule "no-role-hijack" {
    when input matches "you are now.*unrestricted"
    then block with severity "critical"
    message "Role hijacking attempt detected"
  }

  rule "no-exfiltration" {
    when input contains "send data to"
    then block with severity "high"
    message "Data exfiltration attempt detected"
  }

  rate_limit 100 per "minute"
}
`;

const EXAMPLE_PERMISSIVE_POLICY = `
policy "permissive" {
  severity minimum "high"
  block on_threat false
  scan_mode "fast"

  rule "critical-only" {
    when input matches "override.*system.*safety"
    then warn with severity "critical"
    message "Critical safety override attempt"
  }

  allow {
    when input.length less_than 50
  }

  rate_limit 10000 per "minute"
}
`;

const EXAMPLE_CUSTOM_RULES_POLICY = `
# Custom rules for a financial services agent
policy "financial-security" {
  severity minimum "medium"
  block on_threat true

  rule "no-account-exfil" {
    when input matches "account.*number|credit.*card|ssn|social.*security"
    then block with severity "critical"
    message "PII exfiltration attempt in financial context"
  }

  rule "no-auth-bypass" {
    when input contains "bypass authentication"
    then block with severity "critical"
  }

  rule "no-transaction-manipulation" {
    when input matches "transfer.*funds|modify.*balance|override.*limit"
    then block with severity "high"
    message "Transaction manipulation attempt"
  }

  allow {
    when source is "internal-audit"
  }
}
`;

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
  PolicyDSL,
  PolicyParser,
  PolicyCompiler,
  PolicyRuntime,
  PolicyValidator,
  BUILTIN_FUNCTIONS,
  EXAMPLE_STRICT_POLICY,
  EXAMPLE_PERMISSIVE_POLICY,
  EXAMPLE_CUSTOM_RULES_POLICY,
};
