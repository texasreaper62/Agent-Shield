'use strict';

/**
 * Agent Shield — Compliance Auto-Narrator (H2)
 *
 * Watches a stream of Shield events and produces auditor-grade narratives
 * for SOC2 / HIPAA / GDPR / EU AI Act. Auditors get a continuously updated
 * portal instead of a quarterly scramble.
 *
 * Two output modes:
 *   - Deterministic: rule-based markdown narrative, zero LLM. Always available.
 *   - LLM-augmented: if a judge is wired in, narrative is rewritten in
 *     plain-English audit prose with cited evidence.
 *
 * Every narrative is HMAC-signed (sha256 over the canonical JSON event set
 * + the report body) so a tampered narrative is detectable later. The
 * signing key is caller-provided; if absent, signing is skipped and the
 * narrative carries `signature: null` (still useful for drafts).
 */

const crypto = require('crypto');

const FRAMEWORKS = Object.freeze({
  SOC2: 'soc2',
  HIPAA: 'hipaa',
  GDPR: 'gdpr',
  EU_AI_ACT: 'eu_ai_act',
});

// Map Shield categories → relevant framework control IDs. Conservative
// mapping; auditors can override via constructor opts.
const DEFAULT_CONTROL_MAP = Object.freeze({
  soc2: {
    instruction_override: 'CC6.1',
    role_hijack: 'CC6.1',
    data_exfiltration: 'CC6.7',
    credential_exfiltration: 'CC6.7',
    pii_exposure: 'CC6.7',
    tool_abuse: 'CC6.6',
    config_poisoning: 'CC7.1',
    supply_chain: 'CC7.1',
  },
  hipaa: {
    pii_exposure: '164.312(a)(1)',
    data_exfiltration: '164.312(e)(1)',
    credential_exfiltration: '164.308(a)(5)',
  },
  gdpr: {
    pii_exposure: 'Art.32',
    data_exfiltration: 'Art.32',
    credential_exfiltration: 'Art.32',
  },
  eu_ai_act: {
    instruction_override: 'Art.15(4)',
    role_hijack: 'Art.15(4)',
    config_poisoning: 'Art.15(4)',
    autonomous_jailbreak: 'Art.55',
  },
});

class ComplianceNarrator {
  constructor(opts = {}) {
    this.framework = opts.framework || FRAMEWORKS.SOC2;
    this.controlMap = opts.controlMap || DEFAULT_CONTROL_MAP[this.framework] || {};
    this.signingKey = opts.signingKey || null;
    this.judge = opts.judge || null;
    this.judgeBudgetMs = opts.judgeBudgetMs || 8000;
    this.events = [];
  }

  /**
   * Ingest a Shield event. Accepted shapes:
   *   - { timestamp?, severity, category, description, source?, action? }
   *   - a raw scan() result (we'll extract individual threats)
   *   - a ShieldAgent verdict entry
   */
  ingest(event) {
    if (!event) return;
    if (Array.isArray(event.threats)) {
      for (const t of event.threats) {
        this.events.push({
          timestamp: event.timestamp || Date.now(),
          severity: t.severity,
          category: t.category,
          description: t.description,
          source: event.source || 'scan',
          action: event.action || null,
        });
      }
      return;
    }
    if (event.verdict && event.action) {
      // ShieldAgent verdict entry — record one row.
      this.events.push({
        timestamp: event.timestamp || Date.now(),
        severity: (event.scan && event.scan.severity) || 'unknown',
        category: (event.indicators && event.indicators[0]) || 'agent-verdict',
        description: event.reason || '',
        source: (event.scan && event.scan.source) || 'agent',
        action: event.action,
      });
      return;
    }
    this.events.push({
      timestamp: event.timestamp || Date.now(),
      severity: event.severity || 'unknown',
      category: event.category || 'unknown',
      description: event.description || '',
      source: event.source || 'unknown',
      action: event.action || null,
    });
  }

  ingestMany(events) {
    if (!Array.isArray(events)) return;
    for (const e of events) this.ingest(e);
  }

  /**
   * Generate a narrative for a date window. If `judge` is wired, the
   * deterministic narrative is rewritten into audit prose.
   * Returns: { framework, window, summary, controls{}, evidenceCount,
   *           narrative, signature, generatedAt }
   */
  async narrate(opts = {}) {
    const windowFrom = opts.from || 0;
    const windowTo = opts.to || Date.now();
    const inWindow = this.events.filter((e) => e.timestamp >= windowFrom && e.timestamp <= windowTo);

    const summary = this._summarize(inWindow);
    const controls = this._byControl(inWindow);
    const narrative = this._deterministicNarrative({ inWindow, summary, controls, windowFrom, windowTo });
    let prose = narrative;
    if (this.judge) {
      const rewritten = await this._rewriteWithJudge(narrative, summary, controls);
      if (rewritten) prose = rewritten;
    }
    const signature = this._sign({ framework: this.framework, windowFrom, windowTo, summary, controls, prose });
    return {
      framework: this.framework,
      window: { from: windowFrom, to: windowTo },
      summary,
      controls,
      evidenceCount: inWindow.length,
      narrative: prose,
      signature,
      generatedAt: Date.now(),
    };
  }

  _summarize(events) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, safe: 0, unknown: 0 };
    const actionCounts = { allow: 0, block: 0, rewrite: 0, sanitize: 0, quarantine: 0, escalate: 0 };
    const categories = new Set();
    for (const e of events) {
      if (e.severity in counts) counts[e.severity]++;
      else counts.unknown++;
      if (e.action && e.action in actionCounts) actionCounts[e.action]++;
      categories.add(e.category);
    }
    return {
      totalEvents: events.length,
      bySeverity: counts,
      byAction: actionCounts,
      distinctCategories: categories.size,
      categories: Array.from(categories).sort(),
    };
  }

  _byControl(events) {
    const out = {};
    for (const e of events) {
      const ctrl = this.controlMap[e.category];
      if (!ctrl) continue;
      if (!out[ctrl]) out[ctrl] = { control: ctrl, events: 0, categories: new Set(), severities: new Set() };
      out[ctrl].events++;
      out[ctrl].categories.add(e.category);
      out[ctrl].severities.add(e.severity);
    }
    return Object.fromEntries(
      Object.entries(out).map(([k, v]) => [k, {
        control: v.control,
        events: v.events,
        categories: Array.from(v.categories),
        severities: Array.from(v.severities),
      }])
    );
  }

  _deterministicNarrative({ inWindow, summary, controls, windowFrom, windowTo }) {
    const lines = [];
    lines.push(`# ${this.framework.toUpperCase()} Compliance Narrative`);
    lines.push('');
    lines.push(`**Window:** ${new Date(windowFrom).toISOString()} → ${new Date(windowTo).toISOString()}`);
    lines.push(`**Events ingested:** ${inWindow.length}`);
    lines.push('');
    lines.push(`## Executive summary`);
    lines.push(`During this window, Agent Shield processed ${summary.totalEvents} security events across ${summary.distinctCategories} distinct threat categories. ` +
      `Severity distribution: ${summary.bySeverity.critical} critical, ${summary.bySeverity.high} high, ${summary.bySeverity.medium} medium, ${summary.bySeverity.low} low. ` +
      `Enforcement actions: ${summary.byAction.block} blocked, ${summary.byAction.rewrite} rewritten, ${summary.byAction.sanitize} sanitized, ${summary.byAction.quarantine} quarantined, ${summary.byAction.escalate} escalated.`);
    lines.push('');
    lines.push(`## Mapped controls`);
    if (Object.keys(controls).length === 0) {
      lines.push(`_No events mapped to ${this.framework.toUpperCase()} controls in this window._`);
    } else {
      lines.push(`| Control | Events | Categories | Severities |`);
      lines.push(`|---|---:|---|---|`);
      for (const c of Object.values(controls)) {
        lines.push(`| ${c.control} | ${c.events} | ${c.categories.join(', ')} | ${c.severities.join(', ')} |`);
      }
    }
    lines.push('');
    lines.push(`## Top categories`);
    for (const cat of summary.categories.slice(0, 10)) {
      lines.push(`- \`${cat}\``);
    }
    return lines.join('\n');
  }

  async _rewriteWithJudge(narrative, summary, controls) {
    const prompt = [
      `Rewrite the following compliance audit notes in plain-English audit prose, suitable for inclusion in an annual ${this.framework.toUpperCase()} report. Preserve every number and control ID exactly. Reply with the rewritten markdown only — no preamble, no apologies, no fences.`,
      ``,
      `Stats: ${JSON.stringify(summary)}`,
      `Controls: ${JSON.stringify(controls)}`,
      ``,
      `--- Notes ---`,
      narrative,
    ].join('\n');
    try {
      return await Promise.race([
        Promise.resolve(this.judge({ system: 'You are a security-compliance writer.', user: prompt })),
        new Promise((_, reject) => setTimeout(() => reject(new Error('judge timeout')), this.judgeBudgetMs)),
      ]);
    } catch (_) {
      return null;
    }
  }

  _sign(payload) {
    if (!this.signingKey) return null;
    // Canonical JSON: recursively sort keys so the hash is order-independent.
    // (JSON.stringify's replacer array filters keys but doesn't recurse the
    // way we need — it'd drop nested fields and let tampering slip past.)
    const canonical = canonicalize(payload);
    return crypto.createHmac('sha256', this.signingKey).update(canonical).digest('hex');
  }

  /**
   * Verify a previously-signed narrative. Returns true if signature matches.
   */
  verify(report) {
    if (!report || !this.signingKey || !report.signature) return false;
    const payload = {
      framework: report.framework,
      windowFrom: report.window.from,
      windowTo: report.window.to,
      summary: report.summary,
      controls: report.controls,
      prose: report.narrative,
    };
    const expected = this._sign(payload);
    if (!expected) return false;
    // Constant-time compare.
    const a = Buffer.from(report.signature, 'hex');
    const b = Buffer.from(expected, 'hex');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  }
}

function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',') + '}';
}

module.exports = { ComplianceNarrator, FRAMEWORKS, DEFAULT_CONTROL_MAP };
