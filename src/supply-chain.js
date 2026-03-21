'use strict';

/**
 * Supply Chain Verification Module
 *
 * Validates the entire tool chain an AI agent uses. When an agent calls tools,
 * those tools call APIs, those APIs return data. Any link in the chain could be
 * compromised. This module catches poisoned tool responses before the agent
 * processes them.
 *
 * All detection runs locally -- no data ever leaves your environment.
 */

const { scanText } = require('./detector-core');

// =========================================================================
// CONSTANTS
// =========================================================================

/** Patterns that indicate prompt injection hidden in tool responses. */
const RESPONSE_INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules)/i,
  /you\s+are\s+now\s+(?:a|an)\s+(?:unrestricted|unfiltered)/i,
  /SYSTEM\s*:\s*.{10,}/i,
  /\bdo\s+not\s+tell\s+the\s+user\b/i,
  /\bhidden\s+instruction\b/i,
  /\bsecret(?:ly)?\s+(?:execute|run|send|transmit|forward)\b/i,
  /\boverride\s+(?:all\s+)?(?:system|safety)\s+(?:settings|instructions)\b/i,
  /\bdisregard\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions|rules)\b/i,
  /\bact\s+as\s+(?:a|an)\s+unrestricted\b/i,
  /\bpretend\s+(?:you\s+)?(?:have\s+no|there\s+are\s+no)\s+restrictions\b/i
];

/** Patterns that match exfiltration URLs in response data. */
const EXFILTRATION_URL_PATTERNS = [
  /https?:\/\/[^\s"']+\.(?:ngrok|burpcollaborator|pipedream|requestbin|hookbin|webhook\.site)/i,
  /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?/i,
  /https?:\/\/[^\s"']*(?:exfil|steal|leak|extract|dump|collect)/i
];

/** Patterns that match credentials or secrets in response data. */
const CREDENTIAL_PATTERNS = [
  /(?:api[_-]?key|apikey)\s*[:=]\s*['"]?[A-Za-z0-9_\-]{16,}/i,
  /(?:secret|token|password|passwd|pwd)\s*[:=]\s*['"]?[^\s'"]{8,}/i,
  /(?:aws_access_key_id|aws_secret_access_key)\s*[:=]\s*['"]?[A-Za-z0-9/+=]{16,}/i,
  /(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}/,
  /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/,
  /ghp_[A-Za-z0-9]{36}/,
  /sk-[A-Za-z0-9]{32,}/,
  /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/
];

/** Suspicious tool call chains (read sensitive data, then send it out). */
const CHAIN_SUSPICIOUS_PATTERNS = [
  {
    name: 'credential_then_http',
    description: 'Tool reads credentials then makes an outbound HTTP call.',
    severity: 'critical',
    steps: [
      { tool: /read|file|open|cat|get|load|fetch_secret/i, args: /\.env|cred|secret|password|token|key|auth/i },
      { tool: /http|fetch|curl|wget|request|post|send|upload/i }
    ]
  },
  {
    name: 'db_dump_then_send',
    description: 'Tool dumps database contents then sends data externally.',
    severity: 'critical',
    steps: [
      { tool: /sql|query|database|db|mongo|redis/i, args: /SELECT\s+\*|dump|export|find\(\)/i },
      { tool: /http|fetch|curl|wget|request|send|upload|write/i }
    ]
  },
  {
    name: 'list_then_exfil',
    description: 'Tool lists sensitive files then makes an outbound request.',
    severity: 'high',
    steps: [
      { tool: /list|ls|find|glob|readdir/i, args: /\.ssh|\.gnupg|\.aws|credentials|secrets/i },
      { tool: /http|fetch|curl|wget|request|send|upload/i }
    ]
  },
  {
    name: 'config_read_then_modify',
    description: 'Tool reads config then modifies it, possible self-modification.',
    severity: 'high',
    steps: [
      { tool: /read|cat|file|open|get/i, args: /config|settings|\.env|system/i },
      { tool: /write|edit|modify|update|set|put/i, args: /config|settings|\.env|system/i }
    ]
  }
];

/** Default maximum response size in bytes (5 MB). */
const DEFAULT_MAX_RESPONSE_SIZE = 5 * 1024 * 1024;

/** Default maximum depth for recursive object scanning. */
const DEFAULT_SCAN_DEPTH = 10;

// =========================================================================
// DomainAllowlist
// =========================================================================

/**
 * Manages a set of allowed domains for URL validation.
 */
class DomainAllowlist {
  /**
   * @param {string[]} [allowedDomains=[]] - Initial list of allowed domains.
   */
  constructor(allowedDomains = []) {
    /** @type {Set<string>} */
    this.domains = new Set(allowedDomains.map(d => d.toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '')));
  }

  /**
   * Check if a URL's domain is in the allowlist.
   * @param {string} url - URL to check.
   * @returns {boolean} True if the domain is allowed.
   */
  isAllowed(url) {
    if (!url || typeof url !== 'string') return false;
    try {
      const domain = this._extractDomain(url);
      if (!domain) return false;
      for (const allowed of this.domains) {
        if (domain === allowed || domain.endsWith('.' + allowed)) {
          return true;
        }
      }
      return false;
    } catch {
      return false;
    }
  }

  /**
   * Add a domain to the allowlist.
   * @param {string} domain
   */
  add(domain) {
    if (domain && typeof domain === 'string') {
      this.domains.add(domain.toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, ''));
    }
  }

  /**
   * Remove a domain from the allowlist.
   * @param {string} domain
   */
  remove(domain) {
    if (domain && typeof domain === 'string') {
      this.domains.delete(domain.toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, ''));
    }
  }

  /**
   * Extract domain from a URL string.
   * @param {string} url
   * @returns {string|null}
   * @private
   */
  _extractDomain(url) {
    const match = url.match(/^(?:https?:\/\/)?([^/:?#]+)/i);
    return match ? match[1].toLowerCase() : null;
  }
}

// =========================================================================
// ResponseScanner
// =========================================================================

/**
 * Deep-scans tool responses for hidden threats: prompt injections,
 * exfiltration URLs, embedded instructions, and credential leaks.
 */
class ResponseScanner {
  /**
   * @param {object} [options]
   * @param {number} [options.maxSize=5242880] - Maximum response size in bytes.
   * @param {number} [options.scanDepth=10] - Maximum depth for recursive scanning.
   */
  constructor(options = {}) {
    this.maxSize = options.maxSize || DEFAULT_MAX_RESPONSE_SIZE;
    this.scanDepth = options.scanDepth || DEFAULT_SCAN_DEPTH;
  }

  /**
   * Scan a tool response for threats.
   * Accepts strings, objects, or any JSON-serializable value.
   *
   * @param {*} response - Tool response to scan.
   * @returns {{ safe: boolean, threats: Array<object>, sanitizedResponse: * }}
   */
  scan(response) {
    const threats = [];

    // Collect all string values from the response
    const strings = this._extractStrings(response, 0);

    // Size check
    const totalSize = strings.reduce((sum, s) => sum + s.length, 0);
    if (totalSize > this.maxSize) {
      threats.push({
        type: 'oversized_response',
        severity: 'medium',
        description: `Response size (${totalSize} bytes) exceeds limit (${this.maxSize} bytes).`
      });
    }

    let sanitizedResponse = response;

    for (const str of strings) {
      // Check for prompt injections using detector-core
      const scanResult = scanText(str, { source: 'tool_response', sensitivity: 'high' });
      if (scanResult.threats && scanResult.threats.length > 0) {
        for (const t of scanResult.threats) {
          threats.push({
            type: 'embedded_injection',
            severity: t.severity || 'high',
            category: t.category,
            description: t.description || 'Prompt injection detected in tool response.',
            detail: t.detail
          });
        }
      }

      // Check response-specific injection patterns
      for (const pattern of RESPONSE_INJECTION_PATTERNS) {
        if (pattern.test(str)) {
          threats.push({
            type: 'hidden_instruction',
            severity: 'high',
            description: 'Hidden instruction detected in tool response data.',
            matched: str.substring(0, 200)
          });
          break;
        }
      }

      // Check for exfiltration URLs
      for (const pattern of EXFILTRATION_URL_PATTERNS) {
        const match = str.match(pattern);
        if (match) {
          threats.push({
            type: 'exfiltration_url',
            severity: 'high',
            description: 'Potential data exfiltration URL found in tool response.',
            url: match[0].substring(0, 200)
          });
          break;
        }
      }

      // Check for credentials/secrets
      for (const pattern of CREDENTIAL_PATTERNS) {
        if (pattern.test(str)) {
          threats.push({
            type: 'credential_leak',
            severity: 'critical',
            description: 'Credential or secret pattern detected in tool response.'
          });
          break;
        }
      }
    }

    // Sanitize if threats found
    if (threats.length > 0) {
      sanitizedResponse = this._sanitize(response, 0);
    }

    return {
      safe: threats.length === 0,
      threats,
      sanitizedResponse
    };
  }

  /**
   * Extract all string values from a nested structure.
   * @param {*} value
   * @param {number} depth
   * @returns {string[]}
   * @private
   */
  _extractStrings(value, depth) {
    if (depth > this.scanDepth) return [];

    if (typeof value === 'string') return [value];

    if (Array.isArray(value)) {
      const result = [];
      for (const item of value) {
        result.push(...this._extractStrings(item, depth + 1));
      }
      return result;
    }

    if (value && typeof value === 'object') {
      const result = [];
      for (const key of Object.keys(value)) {
        // Also scan keys -- attackers can hide payloads in JSON keys
        if (typeof key === 'string' && key.length > 20) {
          result.push(key);
        }
        result.push(...this._extractStrings(value[key], depth + 1));
      }
      return result;
    }

    return [];
  }

  /**
   * Sanitize a response by redacting detected threats.
   * @param {*} value
   * @param {number} depth
   * @returns {*}
   * @private
   */
  _sanitize(value, depth) {
    if (depth > this.scanDepth) return value;

    if (typeof value === 'string') {
      let sanitized = value;
      for (const pattern of RESPONSE_INJECTION_PATTERNS) {
        sanitized = sanitized.replace(pattern, '[REDACTED:injection]');
      }
      for (const pattern of EXFILTRATION_URL_PATTERNS) {
        sanitized = sanitized.replace(pattern, '[REDACTED:exfil_url]');
      }
      for (const pattern of CREDENTIAL_PATTERNS) {
        sanitized = sanitized.replace(pattern, '[REDACTED:credential]');
      }
      return sanitized;
    }

    if (Array.isArray(value)) {
      return value.map(item => this._sanitize(item, depth + 1));
    }

    if (value && typeof value === 'object') {
      const result = {};
      for (const key of Object.keys(value)) {
        result[key] = this._sanitize(value[key], depth + 1);
      }
      return result;
    }

    return value;
  }
}

// =========================================================================
// ToolChainValidator
// =========================================================================

/**
 * Validates tool calls before execution and tool responses after execution.
 * Tracks the full chain of tool interactions to detect multi-step attacks.
 */
class ToolChainValidator {
  /**
   * @param {object} [options]
   * @param {string} [options.sensitivity='medium'] - Detection sensitivity: low, medium, high.
   * @param {string[]} [options.allowedDomains=[]] - Allowed domains for URL validation.
   * @param {string[]} [options.blockedDomains=[]] - Blocked domains for URL validation.
   * @param {number} [options.maxResponseSize=5242880] - Max response size in bytes.
   * @param {boolean} [options.scanResponses=true] - Whether to scan tool responses.
   */
  constructor(options = {}) {
    this.sensitivity = options.sensitivity || 'medium';
    this.allowedDomains = new DomainAllowlist(options.allowedDomains || []);
    this.blockedDomains = new Set((options.blockedDomains || []).map(d => d.toLowerCase()));
    this.maxResponseSize = options.maxResponseSize || DEFAULT_MAX_RESPONSE_SIZE;
    this.scanResponses = options.scanResponses !== false;

    this.responseScanner = new ResponseScanner({
      maxSize: this.maxResponseSize,
      scanDepth: DEFAULT_SCAN_DEPTH
    });

    /** @type {Array<{ toolName: string, args: *, timestamp: number }>} */
    this.callHistory = [];

    // Stats tracking
    this.stats = {
      totalValidated: 0,
      blocked: 0,
      passed: 0,
      byTool: {}
    };
  }

  /**
   * Scan tool arguments for injection before execution.
   *
   * @param {string} toolName - Name of the tool being called.
   * @param {*} args - Arguments passed to the tool.
   * @returns {{ allowed: boolean, threats: Array<object> }}
   */
  validateToolCall(toolName, args) {
    this.stats.totalValidated++;
    this._trackTool(toolName, 'call');

    const threats = [];
    const argsStr = typeof args === 'string' ? args : JSON.stringify(args || {});

    // Scan arguments with detector-core
    const scanResult = scanText(argsStr, {
      source: `tool_call:${toolName}`,
      sensitivity: this.sensitivity
    });

    if (scanResult.threats && scanResult.threats.length > 0) {
      for (const t of scanResult.threats) {
        threats.push({
          type: 'injection_in_args',
          tool: toolName,
          severity: t.severity || 'high',
          category: t.category,
          description: t.description || 'Injection detected in tool arguments.'
        });
      }
    }

    // Check for URLs in arguments
    const urls = argsStr.match(/https?:\/\/[^\s"'}\]]+/gi) || [];
    for (const url of urls) {
      const urlResult = this.validateURL(url);
      if (!urlResult.allowed) {
        threats.push(...urlResult.threats.map(t => ({
          ...t,
          tool: toolName,
          type: 'suspicious_url_in_args'
        })));
      }
    }

    // Record in history for chain analysis
    this.callHistory.push({
      toolName,
      args: argsStr.substring(0, 500),
      timestamp: Date.now()
    });

    // Trim history to last 50 calls
    if (this.callHistory.length > 50) {
      this.callHistory = this.callHistory.slice(-50);
    }

    const allowed = threats.length === 0;
    if (allowed) {
      this.stats.passed++;
    } else {
      this.stats.blocked++;
    }

    return { allowed, threats };
  }

  /**
   * Scan tool output for injection/exfiltration after execution.
   *
   * @param {string} toolName - Name of the tool that produced the response.
   * @param {*} response - The tool's response data.
   * @returns {{ safe: boolean, threats: Array<object>, sanitizedResponse: * }}
   */
  validateToolResponse(toolName, response) {
    this.stats.totalValidated++;
    this._trackTool(toolName, 'response');

    if (!this.scanResponses) {
      this.stats.passed++;
      return { safe: true, threats: [], sanitizedResponse: response };
    }

    const result = this.responseScanner.scan(response);

    // Tag threats with tool name
    for (const threat of result.threats) {
      threat.tool = toolName;
    }

    if (result.safe) {
      this.stats.passed++;
    } else {
      this.stats.blocked++;
    }

    return result;
  }

  /**
   * Check if a URL is in allowed/blocked lists and detect suspicious patterns.
   *
   * @param {string} url - URL to validate.
   * @returns {{ allowed: boolean, threats: Array<object> }}
   */
  validateURL(url) {
    const threats = [];

    if (!url || typeof url !== 'string') {
      return { allowed: false, threats: [{ type: 'invalid_url', severity: 'medium', description: 'URL is empty or not a string.' }] };
    }

    // Extract domain
    const domainMatch = url.match(/^(?:https?:\/\/)?([^/:?#]+)/i);
    const domain = domainMatch ? domainMatch[1].toLowerCase() : null;

    if (!domain) {
      threats.push({ type: 'malformed_url', severity: 'medium', description: 'Could not extract domain from URL.' });
      return { allowed: false, threats };
    }

    // Check blocked domains
    for (const blocked of this.blockedDomains) {
      if (domain === blocked || domain.endsWith('.' + blocked)) {
        threats.push({
          type: 'blocked_domain',
          severity: 'high',
          description: `Domain "${domain}" is on the blocklist.`,
          domain
        });
        return { allowed: false, threats };
      }
    }

    // If allowlist has entries, domain must be in it
    if (this.allowedDomains.domains.size > 0 && !this.allowedDomains.isAllowed(url)) {
      threats.push({
        type: 'domain_not_allowed',
        severity: 'medium',
        description: `Domain "${domain}" is not in the allowlist.`,
        domain
      });
      return { allowed: false, threats };
    }

    // Check for suspicious URL patterns (IP addresses, known exfil services)
    for (const pattern of EXFILTRATION_URL_PATTERNS) {
      if (pattern.test(url)) {
        threats.push({
          type: 'suspicious_url',
          severity: 'high',
          description: 'URL matches a known exfiltration or suspicious pattern.',
          url: url.substring(0, 200)
        });
        return { allowed: false, threats };
      }
    }

    // Check for data-in-URL exfiltration (long query strings, base64 in path)
    if (url.length > 500) {
      threats.push({
        type: 'data_in_url',
        severity: 'medium',
        description: 'URL is unusually long, possibly encoding exfiltrated data.'
      });
    }

    const base64InPath = url.match(/\/[A-Za-z0-9+/=]{50,}/);
    if (base64InPath) {
      threats.push({
        type: 'encoded_data_in_url',
        severity: 'high',
        description: 'URL path contains what appears to be base64-encoded data.'
      });
    }

    return { allowed: threats.length === 0, threats };
  }

  /**
   * Validate a sequence of tool calls for suspicious patterns.
   * Detects multi-step attacks such as reading credentials then sending them.
   *
   * @param {Array<{ tool: string, args: string }>} steps - Sequence of tool calls.
   * @returns {{ safe: boolean, threats: Array<object> }}
   */
  validateChain(steps) {
    const threats = [];

    if (!Array.isArray(steps) || steps.length < 2) {
      return { safe: true, threats: [] };
    }

    for (const pattern of CHAIN_SUSPICIOUS_PATTERNS) {
      const patternSteps = pattern.steps;

      // Sliding window: look for the pattern steps in order within the chain
      let patternIdx = 0;
      for (let i = 0; i < steps.length && patternIdx < patternSteps.length; i++) {
        const step = steps[i];
        const expected = patternSteps[patternIdx];

        const toolMatches = expected.tool.test(step.tool || '');
        const argsMatch = !expected.args || expected.args.test(step.args || '');

        if (toolMatches && argsMatch) {
          patternIdx++;
        }
      }

      if (patternIdx === patternSteps.length) {
        threats.push({
          type: 'suspicious_chain',
          name: pattern.name,
          severity: pattern.severity,
          description: pattern.description,
          stepsMatched: patternSteps.length,
          totalSteps: steps.length
        });
      }
    }

    return {
      safe: threats.length === 0,
      threats
    };
  }

  /**
   * Return a report of validation statistics.
   *
   * @returns {{ totalValidated: number, blocked: number, passed: number, byTool: object }}
   */
  getReport() {
    return {
      totalValidated: this.stats.totalValidated,
      blocked: this.stats.blocked,
      passed: this.stats.passed,
      byTool: { ...this.stats.byTool }
    };
  }

  /**
   * Track per-tool stats.
   * @param {string} toolName
   * @param {string} action
   * @private
   */
  _trackTool(toolName, action) {
    if (!this.stats.byTool[toolName]) {
      this.stats.byTool[toolName] = { calls: 0, responses: 0, blocked: 0 };
    }
    if (action === 'call') {
      this.stats.byTool[toolName].calls++;
    } else if (action === 'response') {
      this.stats.byTool[toolName].responses++;
    }
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
  ToolChainValidator,
  ResponseScanner,
  DomainAllowlist,
  RESPONSE_INJECTION_PATTERNS,
  EXFILTRATION_URL_PATTERNS,
  CREDENTIAL_PATTERNS,
  CHAIN_SUSPICIOUS_PATTERNS
};
