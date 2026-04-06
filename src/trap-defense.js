'use strict';

/**
 * Agent Shield — Behavioral Control Trap Defenses (Trap 4) + Content Injection Additions (Trap 1)
 *
 * Defenses for DeepMind's AI Agent Trap categories 1 and 4:
 * - Browser action validation for web-browsing agents
 * - Credential isolation monitoring
 * - Transaction gatekeeper (requires human confirmation for financial actions)
 * - Side-channel exfiltration detection
 * - Dynamic cloaking detection
 * - SVG/composite content scanning
 *
 * All processing runs locally — no data ever leaves your environment.
 *
 * @module trap-defense
 */

const { scanText } = require('./detector-core');

// =========================================================================
// TRAP 1: Content Injection Additions
// =========================================================================

/**
 * Detects dynamic cloaking — when a server serves different content to AI
 * agents vs human browsers.
 */
class CloakingDetector {
  constructor() {
    /** @type {Map<string, { content: string, userAgent: string, timestamp: number }>} */
    this.contentCache = new Map();
    this.stats = { checked: 0, cloakingDetected: 0 };
  }

  /**
   * Record content received from a URL and check for cloaking.
   * Call this with the same URL fetched by different user agents.
   *
   * @param {string} url - Source URL.
   * @param {string} content - Received content.
   * @param {string} userAgent - User agent string used.
   * @returns {{ cloaking: boolean, divergenceScore: number, details: string|null }}
   */
  check(url, content, userAgent) {
    this.stats.checked++;
    const key = url.toLowerCase().replace(/[?#].*$/, '');
    const existing = this.contentCache.get(key);

    if (!existing) {
      this.contentCache.set(key, { content: (content || '').substring(0, 5000), userAgent, timestamp: Date.now() });
      if (this.contentCache.size > 1000) {
        const oldest = [...this.contentCache.entries()].sort((a, b) => a[1].timestamp - b[1].timestamp)[0];
        if (oldest) this.contentCache.delete(oldest[0]);
      }
      return { cloaking: false, divergenceScore: 0, details: null };
    }

    // Compare content from different UAs
    const divergence = this._computeDivergence(existing.content, (content || '').substring(0, 5000));

    if (divergence > 0.3) {
      this.stats.cloakingDetected++;
      return {
        cloaking: true,
        divergenceScore: divergence,
        details: `Content for "${key}" differs ${(divergence * 100).toFixed(0)}% between UA "${existing.userAgent}" and "${userAgent}". Possible dynamic cloaking.`
      };
    }

    return { cloaking: false, divergenceScore: divergence, details: null };
  }

  /** @private */
  _computeDivergence(a, b) {
    if (a === b) return 0;
    const wordsA = new Set(a.toLowerCase().split(/\s+/));
    const wordsB = new Set(b.toLowerCase().split(/\s+/));
    const intersection = [...wordsA].filter(w => wordsB.has(w)).length;
    const union = new Set([...wordsA, ...wordsB]).size;
    return union > 0 ? 1 - (intersection / union) : 0;
  }
}

/**
 * Scans composite content — merges text from HTML, CSS, JS, SVG sources
 * and scans the merged result for injection that only appears when combined.
 */
class CompositeContentScanner {
  /**
   * Scan merged content from multiple sources.
   *
   * @param {object} sources
   * @param {string} [sources.html] - HTML body text.
   * @param {string} [sources.css] - CSS content property values.
   * @param {string} [sources.js] - JavaScript string literals.
   * @param {string} [sources.svg] - SVG text/title/desc content.
   * @param {string} [sources.metadata] - Document metadata.
   * @returns {{ safe: boolean, threats: Array<object>, mergedLength: number }}
   */
  scan(sources = {}) {
    const parts = [];
    for (const [source, content] of Object.entries(sources)) {
      if (content && typeof content === 'string') {
        parts.push(content);
      }
    }

    const merged = parts.join(' ');
    if (merged.length < 10) return { safe: true, threats: [], mergedLength: 0 };

    const result = scanText(merged, { source: 'composite_content', sensitivity: 'high' });
    const threats = (result.threats || []).map(t => ({
      ...t,
      detail: (t.detail || '') + ' [Detected in merged composite content across HTML/CSS/JS/SVG sources]'
    }));

    return { safe: threats.length === 0, threats, mergedLength: merged.length };
  }
}

/**
 * Extracts and scans text from SVG content.
 */
class SVGScanner {
  /**
   * Scan SVG content for hidden injection.
   * @param {string} svgContent - Raw SVG markup.
   * @returns {{ safe: boolean, threats: Array<object>, extractedText: string }}
   */
  scan(svgContent) {
    if (!svgContent || typeof svgContent !== 'string') {
      return { safe: true, threats: [], extractedText: '' };
    }

    // Extract text from SVG elements
    const textPatterns = [
      /<text[^>]*>([\s\S]*?)<\/text>/gi,
      /<title[^>]*>([\s\S]*?)<\/title>/gi,
      /<desc[^>]*>([\s\S]*?)<\/desc>/gi,
      /<tspan[^>]*>([\s\S]*?)<\/tspan>/gi,
    ];

    const extractedParts = [];
    for (const pattern of textPatterns) {
      let match;
      while ((match = pattern.exec(svgContent)) !== null) {
        const text = match[1].replace(/<[^>]+>/g, '').trim();
        if (text.length > 3) extractedParts.push(text);
      }
    }

    // Also check SVG attributes
    const attrPattern = /(?:aria-label|data-text|content)\s*=\s*["']([^"']{10,})["']/gi;
    let attrMatch;
    while ((attrMatch = attrPattern.exec(svgContent)) !== null) {
      extractedParts.push(attrMatch[1]);
    }

    const extractedText = extractedParts.join(' ');
    if (extractedText.length < 10) return { safe: true, threats: [], extractedText };

    const result = scanText(extractedText, { source: 'svg_content', sensitivity: 'high' });
    const threats = (result.threats || []).map(t => ({
      ...t,
      detail: (t.detail || '') + ' [Detected in SVG text/title/desc element]'
    }));

    return { safe: threats.length === 0, threats, extractedText };
  }
}

// =========================================================================
// TRAP 4: Behavioral Control Additions
// =========================================================================

/**
 * Validates browser actions for web-browsing agents.
 * Checks every click, navigate, type, submit against user intent.
 */
class BrowserActionValidator {
  /**
   * @param {object} [options]
   * @param {string[]} [options.allowedDomains] - Domains the agent is allowed to navigate to.
   * @param {string[]} [options.blockedDomains] - Domains the agent must never navigate to.
   */
  constructor(options = {}) {
    this.allowedDomains = new Set(options.allowedDomains || []);
    this.blockedDomains = new Set(options.blockedDomains || []);
    this.stats = { validated: 0, blocked: 0 };
  }

  /**
   * Validate a browser action before execution.
   *
   * @param {object} action
   * @param {string} action.type - 'click', 'navigate', 'type', 'submit', 'download'.
   * @param {string} [action.url] - Target URL for navigate/click actions.
   * @param {string} [action.selector] - CSS selector for click/type actions.
   * @param {string} [action.value] - Value for type actions.
   * @param {string} [action.formAction] - Form action URL for submit actions.
   * @returns {{ allowed: boolean, reason: string|null, riskLevel: string }}
   */
  validate(action) {
    this.stats.validated++;
    const issues = [];

    // Check URL-based actions
    const targetUrl = action.url || action.formAction || '';
    if (targetUrl) {
      // Extract domain
      const domainMatch = targetUrl.match(/^(?:https?:\/\/)?([^/:?#]+)/i);
      const domain = domainMatch ? domainMatch[1].toLowerCase() : '';

      // Blocked domain check
      if (domain && this.blockedDomains.has(domain)) {
        this.stats.blocked++;
        return { allowed: false, reason: `Domain "${domain}" is blocked.`, riskLevel: 'critical' };
      }

      // Allowlist check
      if (this.allowedDomains.size > 0 && domain && !this.allowedDomains.has(domain)) {
        this.stats.blocked++;
        return { allowed: false, reason: `Domain "${domain}" is not in the allowlist.`, riskLevel: 'high' };
      }

      // SSRF check — private IPs
      if (/(?:10\.\d|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.0\.0\.1|0\.0\.0\.0|localhost|169\.254\.169\.254)/i.test(targetUrl)) {
        this.stats.blocked++;
        return { allowed: false, reason: 'URL targets a private/internal address (SSRF).', riskLevel: 'critical' };
      }
    }

    // Credential field interaction
    if (action.type === 'type' && action.selector) {
      if (/password|passwd|secret|token|credential|api[_-]?key/i.test(action.selector)) {
        issues.push({ concern: 'Typing into a credential field', riskLevel: 'high' });
      }
    }

    // Form submission to unexpected domain
    if (action.type === 'submit' && action.formAction) {
      const scanResult = scanText(action.formAction, { source: 'form_action' });
      if (scanResult.threats && scanResult.threats.length > 0) {
        this.stats.blocked++;
        return { allowed: false, reason: 'Form submits to a suspicious URL.', riskLevel: 'critical' };
      }
    }

    // Download actions always require review
    if (action.type === 'download') {
      return { allowed: false, reason: 'Download actions require human approval.', riskLevel: 'high' };
    }

    if (issues.length > 0) {
      return { allowed: false, reason: issues[0].concern, riskLevel: issues[0].riskLevel };
    }

    return { allowed: true, reason: null, riskLevel: 'safe' };
  }
}

/**
 * Monitors credential usage across contexts to prevent credential stuffing.
 */
class CredentialIsolationMonitor {
  constructor() {
    /** @type {Map<string, { context: string, timestamp: number }>} */
    this.credentialAccess = new Map();
    this.stats = { monitored: 0, violations: 0 };
  }

  /**
   * Record a credential access event.
   * @param {string} credentialId - Identifier for the credential (hashed).
   * @param {string} context - Where the credential was accessed from (domain/service).
   */
  recordAccess(credentialId, context) {
    this.stats.monitored++;
    this.credentialAccess.set(credentialId, { context, timestamp: Date.now() });
  }

  /**
   * Check if a credential is being used in a different context than where it was read.
   * @param {string} credentialId
   * @param {string} usageContext - Where the credential is being used.
   * @returns {{ isolated: boolean, violation: object|null }}
   */
  checkUsage(credentialId, usageContext) {
    const access = this.credentialAccess.get(credentialId);
    if (!access) return { isolated: true, violation: null };

    if (access.context !== usageContext) {
      this.stats.violations++;
      return {
        isolated: false,
        violation: {
          type: 'credential_context_mismatch',
          severity: 'critical',
          credential: credentialId,
          readContext: access.context,
          usageContext,
          description: `Credential from "${access.context}" used in "${usageContext}". Possible credential stuffing.`
        }
      };
    }

    return { isolated: true, violation: null };
  }
}

/**
 * Requires human confirmation for financial/transactional actions.
 */
class TransactionGatekeeper {
  constructor() {
    /** @type {Array<object>} */
    this.pendingTransactions = [];
    this.stats = { gated: 0, approved: 0, denied: 0 };
  }

  /**
   * Gate a potentially financial action.
   * @param {string} action - Description of the action.
   * @param {object} [details] - Action details (amount, recipient, etc.).
   * @returns {{ requiresApproval: boolean, riskLevel: string, reason: string, transactionId: string }}
   */
  gate(action, details = {}) {
    const actionStr = typeof action === 'string' ? action : JSON.stringify(action);
    const isFinancial = /(?:pay(?:ment)?|transfer|purchase|buy|sell|trade|send\s+money|withdraw|deposit|invoice|charge|subscribe|billing|refund|transaction)/i.test(actionStr);

    if (!isFinancial) {
      return { requiresApproval: false, riskLevel: 'safe', reason: 'Non-financial action.', transactionId: null };
    }

    const transactionId = Date.now().toString(36) + Math.random().toString(36).substring(2, 8);
    this.pendingTransactions.push({
      transactionId,
      action: actionStr.substring(0, 500),
      details,
      timestamp: Date.now(),
      status: 'pending'
    });
    this.stats.gated++;

    // Bound pending list
    if (this.pendingTransactions.length > 100) {
      this.pendingTransactions = this.pendingTransactions.slice(-100);
    }

    return {
      requiresApproval: true,
      riskLevel: 'high',
      reason: 'Financial/transactional action detected. Requires human approval.',
      transactionId
    };
  }

  /**
   * Approve a pending transaction.
   * @param {string} transactionId
   * @returns {boolean}
   */
  approve(transactionId) {
    const tx = this.pendingTransactions.find(t => t.transactionId === transactionId);
    if (!tx || tx.status !== 'pending') return false;
    tx.status = 'approved';
    this.stats.approved++;
    return true;
  }

  /**
   * Deny a pending transaction.
   * @param {string} transactionId
   * @returns {boolean}
   */
  deny(transactionId) {
    const tx = this.pendingTransactions.find(t => t.transactionId === transactionId);
    if (!tx || tx.status !== 'pending') return false;
    tx.status = 'denied';
    this.stats.denied++;
    return true;
  }
}

/**
 * Detects potential side-channel exfiltration through timing, response length, or error patterns.
 */
class SideChannelDetector {
  constructor() {
    /** @type {Array<{ timestamp: number, responseLength: number, errorOccurred: boolean, sensitiveAccess: boolean }>} */
    this.observations = [];
    this.maxObservations = 200;
  }

  /**
   * Record an observation and check for side-channel patterns.
   * @param {object} obs
   * @param {number} obs.responseLength - Response length.
   * @param {boolean} obs.errorOccurred - Whether an error occurred.
   * @param {boolean} obs.sensitiveAccess - Whether sensitive data was accessed this turn.
   * @returns {{ suspicious: boolean, pattern: string|null }}
   */
  observe(obs) {
    this.observations.push({ ...obs, timestamp: Date.now() });
    if (this.observations.length > this.maxObservations) {
      this.observations = this.observations.slice(-this.maxObservations);
    }

    if (this.observations.length < 10) return { suspicious: false, pattern: null };

    // Check: response length correlates with sensitive access
    const withSensitive = this.observations.filter(o => o.sensitiveAccess);
    const withoutSensitive = this.observations.filter(o => !o.sensitiveAccess);

    if (withSensitive.length >= 3 && withoutSensitive.length >= 3) {
      const avgLenSensitive = withSensitive.reduce((s, o) => s + o.responseLength, 0) / withSensitive.length;
      const avgLenNormal = withoutSensitive.reduce((s, o) => s + o.responseLength, 0) / withoutSensitive.length;

      if (Math.abs(avgLenSensitive - avgLenNormal) > avgLenNormal * 0.5) {
        return {
          suspicious: true,
          pattern: `Response length varies ${((Math.abs(avgLenSensitive - avgLenNormal) / avgLenNormal) * 100).toFixed(0)}% based on sensitive data access. Possible side-channel.`
        };
      }
    }

    // Check: error rate spikes with sensitive access
    const errorWithSensitive = withSensitive.filter(o => o.errorOccurred).length / (withSensitive.length || 1);
    const errorWithout = withoutSensitive.filter(o => o.errorOccurred).length / (withoutSensitive.length || 1);

    if (errorWithSensitive > 0.5 && errorWithout < 0.1) {
      return {
        suspicious: true,
        pattern: 'Error rate spikes when sensitive data is accessed. Possible error-based side-channel.'
      };
    }

    return { suspicious: false, pattern: null };
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
  // Trap 1
  CloakingDetector,
  CompositeContentScanner,
  SVGScanner,
  // Trap 4
  BrowserActionValidator,
  CredentialIsolationMonitor,
  TransactionGatekeeper,
  SideChannelDetector
};
