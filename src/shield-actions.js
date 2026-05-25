'use strict';

/**
 * Agent Shield — Action Executor
 *
 * Translates ShieldAgent verdicts into concrete operations: block requests,
 * sanitize input, quarantine to a sink, or escalate to an external SOC.
 * Pure functions where possible; effectful operations (quarantine sink, SOC
 * webhook) are caller-injected.
 */

const { ACTIONS, VERDICTS } = require('./shield-agent');

class ShieldActions {
  constructor(opts = {}) {
    this.quarantineSink = opts.quarantineSink || null; // (entry) => Promise<void>
    this.escalateSink = opts.escalateSink || null;     // (entry) => Promise<void>
    this.blockedResponse = opts.blockedResponse ||
      'This request was blocked by Agent Shield for safety reasons.';
    this.sanitizers = opts.sanitizers || defaultSanitizers();
    this.stats = {
      executed: 0,
      byAction: Object.fromEntries(Object.values(ACTIONS).map((a) => [a, 0])),
    };
  }

  /**
   * Execute the action embedded in a verdict. Returns:
   *   { proceed: boolean, payload: string | null, info: object }
   *
   * - proceed=true means the host agent may continue with `payload` as the
   *   (possibly rewritten/sanitized) content.
   * - proceed=false means the host agent must NOT process the original content;
   *   `payload` holds a safe response string suitable for returning to the user.
   */
  async execute(verdict, originalText) {
    this.stats.executed++;
    const action = verdict.action || ACTIONS.ALLOW;
    if (action in this.stats.byAction) this.stats.byAction[action]++;

    switch (action) {
      case ACTIONS.ALLOW:
        return { proceed: true, payload: originalText, info: { action, reason: verdict.reason } };

      case ACTIONS.BLOCK:
        return { proceed: false, payload: this.blockedResponse, info: { action, reason: verdict.reason } };

      case ACTIONS.REWRITE: {
        const rewritten = verdict.rewritten;
        if (typeof rewritten !== 'string' || rewritten.length === 0) {
          // Rewrite failed; degrade to block.
          return { proceed: false, payload: this.blockedResponse, info: { action: ACTIONS.BLOCK, reason: 'rewrite produced empty payload; degraded to block' } };
        }
        return { proceed: true, payload: rewritten, info: { action, reason: verdict.reason } };
      }

      case ACTIONS.SANITIZE: {
        const sanitized = this.sanitize(originalText);
        return { proceed: true, payload: sanitized, info: { action, reason: verdict.reason, removed: sanitized !== originalText } };
      }

      case ACTIONS.QUARANTINE:
        if (this.quarantineSink) {
          try { await this.quarantineSink({ text: originalText, verdict }); }
          catch (err) { return { proceed: false, payload: this.blockedResponse, info: { action, error: err.message } }; }
        }
        return { proceed: false, payload: this.blockedResponse, info: { action, reason: verdict.reason, quarantined: true } };

      case ACTIONS.ESCALATE:
        if (this.escalateSink) {
          try { await this.escalateSink({ text: originalText, verdict }); }
          catch (err) { /* escalation is best-effort; still block */ void err; }
        }
        return { proceed: false, payload: this.blockedResponse, info: { action, reason: verdict.reason, escalated: true } };

      default:
        return { proceed: false, payload: this.blockedResponse, info: { action: ACTIONS.BLOCK, reason: `unknown action: ${action}` } };
    }
  }

  /**
   * Strip well-known injection scaffolding from text without an LLM call.
   * Conservative — only removes patterns with no legitimate use.
   */
  sanitize(text) {
    let out = String(text || '');
    for (const sanitizer of this.sanitizers) {
      out = out.replace(sanitizer.pattern, sanitizer.replacement);
    }
    return out;
  }

  getStats() {
    return JSON.parse(JSON.stringify(this.stats));
  }
}

function defaultSanitizers() {
  return [
    // HTML comments hiding instructions.
    { pattern: /<!--[\s\S]*?-->/g, replacement: '' },
    // Markdown image with data exfil parameters.
    { pattern: /!\[[^\]]*\]\([^)]*[?&](?:data|exfil|leak|steal|secret|token|conversation|context|prompt)=[^)]*\)/gi, replacement: '[image redacted]' },
    // Hidden display:none containers.
    { pattern: /style\s*=\s*['"][^'"]*display\s*:\s*none[^'"]*['"]/gi, replacement: '' },
    // Hard-overrides — "ignore all previous instructions"-class boilerplate.
    { pattern: /\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|rules|context|directions)\b[^.]*\.?/gi, replacement: '[instruction-override removed]' },
    // System-prompt impersonation tags.
    { pattern: /<\/?(?:system|admin|developer|root)(?:[\s>][^>]*)?>/gi, replacement: '' },
  ];
}

module.exports = {
  ShieldActions,
  defaultSanitizers,
  ACTIONS,
  VERDICTS,
};
