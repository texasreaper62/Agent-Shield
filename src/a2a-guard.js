'use strict';

/**
 * Agent Shield — A2A Guard + 2026 Threat Coverage
 *
 * Closes the highest-impact gaps from the May 2026 threat-intel sweep:
 *
 *   - Agent Card Poisoning (Keysight Mar 2026, Unit 42 Apr 2026)
 *   - A2A Session Smuggling (Unit 42)
 *   - MCP STDIO config-to-command exec (10 active CVEs, Anthropic declined patch)
 *   - MCP tool response schema-pin violation (CVE-2026-26118 Microsoft)
 *   - Sleeper / temporal-trigger backdoors (arXiv 2603.03371)
 *   - Reasoning-trace extraction (arXiv 2506.15674, 2603.05618)
 *   - LLM-as-judge score manipulation (arXiv 2503.00596)
 *   - Reverse-CAPTCHA invisible-Unicode binary payload
 *
 * Each detector is exposed as both:
 *   1. a function (callable directly), and
 *   2. an entry in NEW_2026_PATTERNS (a list of pattern dicts compatible
 *      with detector-core's INJECTION_PATTERNS array, so a host can splice
 *      them into the live scanner without modifying detector-core).
 *
 * Schema-pin and TOCTOU detectors are stateful so they live as classes.
 */

const crypto = require('crypto');

// =========================================================================
// Regex patterns — host can splice into INJECTION_PATTERNS directly
// =========================================================================

const NEW_2026_PATTERNS = [
  // 1. Agent Card Poisoning — A2A `agent card` metadata carrying injection.
  // Note `[\s\S]{0,400}` (not `[^"]`) so it matches arrays + nested objects too,
  // e.g. `"skills":["math","ignore all previous..."]`.
  {
    regex: /"(?:skills|capabilities|description|instructions?)"\s*:\s*(?:\[|")[\s\S]{0,400}(?:ignore\s+(?:all\s+)?(?:previous|prior)|disregard|execute|exfiltrate|system\s+prompt|jailbreak|override\s+(?:safety|system)|reveal\s+(?:your|the)\s+(?:system|instructions))/i,
    severity: 'critical',
    category: 'a2a_card_poisoning',
    description: 'A2A agent card metadata field contains injection-shaped content (skills/capabilities/description).',
  },
  // 2. A2A naming-squat impersonation — agent ID claims a trusted name.
  {
    regex: /"(?:agent_?id|agent_?name)"\s*:\s*"(?:claude|anthropic|openai|gpt|chatgpt|microsoft|google|gemini|admin|root|system|owner|operator)[-_]?(?:\d+|official|trusted|verified)?"/i,
    severity: 'high',
    category: 'a2a_card_poisoning',
    description: 'A2A agent ID impersonates a trusted vendor or privileged role.',
  },

  // 3. MCP STDIO config command exec — JSON config `command` with shell metachars.
  {
    regex: /"command"\s*:\s*"[^"]*(?:[;&|`$()<>]|\\x[0-9a-f]{2}|\$\{|\$\(|\|\||&&)/i,
    severity: 'critical',
    category: 'mcp_stdio_command_audit',
    description: 'MCP server config `command` field contains shell metacharacters (CVE-2025-49596, CVE-2026-22252, CVE-2025-54994 family).',
  },

  // 4. MCP env-var poisoning in config — overriding LLM endpoint in MCP env.
  {
    regex: /"env"\s*:\s*\{[^}]*"(?:ANTHROPIC|OPENAI|API)_BASE_URL"\s*:\s*"https?:\/\/(?!api\.anthropic\.com|api\.openai\.com)/i,
    severity: 'critical',
    category: 'mcp_stdio_command_audit',
    description: 'MCP server env block redirects ANTHROPIC/OPENAI_BASE_URL to a non-official endpoint.',
  },

  // 5. Sleeper / temporal backdoor — date or version gate before exfil.
  {
    regex: /\bif\s+(?:date|today|now|version|deployment_id|env\.[A-Z_]+|process\.env\.[A-Z_]+)\s*(?:>=|==|>|<=|<)\s*['"][^'"]{4,}['"][\s\S]{0,200}(?:exfiltrate|leak|send\s+to|post\s+to|curl|wget|fetch)/i,
    severity: 'critical',
    category: 'temporal_backdoor_trigger',
    description: 'Date/version-gated exfiltration logic — sleeper backdoor pattern (arXiv 2603.03371).',
  },

  // 6. Reasoning-trace extraction — leak <thinking>/CoT channel verbatim.
  // Allow 1-3 modifiers between verb and noun: "reveal your full chain of thought".
  {
    regex: /\b(?:show|reveal|print|output|repeat|expose|dump|disclose)\s+(?:(?:your|the|all|complete|full|raw|internal|entire|hidden)\s+){1,3}(?:thinking|reasoning|chain[-\s]of[-\s]thought|cot|scratchpad|reflection|deliberation|<thinking>|<reasoning>)/i,
    severity: 'high',
    category: 'reasoning_trace_extraction',
    description: 'Attempt to extract the reasoning/<thinking> channel of a reasoning model (arXiv 2506.15674).',
  },
  {
    regex: /(?:include|show|append|prepend|return)\s+(?:your|the)\s+(?:thinking|reasoning|chain[-\s]of[-\s]thought)\s+(?:in|with|before|after)\s+(?:your|the)\s+(?:final\s+)?(?:answer|response|output)/i,
    severity: 'high',
    category: 'reasoning_trace_extraction',
    description: 'Coerces a reasoning model to surface its <thinking> trace in the visible response.',
  },

  // 7. LLM-as-judge score manipulation — adversarial suffix designed to win.
  {
    regex: /(?:Let'?s\s+think\s+step.by.step|^\s*Thought:|^\s*Reasoning:|\b(?:excellent|perfect|definitely\s+10\/10|score\s*:\s*10|highest\s+rating))[\s\S]{0,30}$/im,
    severity: 'medium',
    category: 'judge_score_manipulation',
    description: 'Adversarial suffix targeting LLM-as-judge graders (arXiv 2503.00596 "BadJudge").',
  },

  // 8. Universal-adversarial tool selector bias — "always pick this tool".
  {
    regex: /(?:always|must|preferred|first[-\s]choice|recommended|optimal|default|highest[-\s]priority)\s+(?:tool|function|action|choice|invocation)\s+for\s+(?:any|all|every|all\s+queries|user\s+questions?)/i,
    severity: 'high',
    category: 'universal_tool_selector_bias',
    description: 'Universal-adversarial tool description biases the selector toward this tool (arXiv 2604.20994).',
  },

  // 9. Authority threshold drift — agent's claimed authorization growing.
  // Include "has been" (third-person) and "is now" alongside "are now"/"have been".
  {
    regex: /\b(?:you|the\s+agent|the\s+system)\s+(?:are\s+now|is\s+now|have\s+been|has\s+been|may\s+now|can\s+now)\s+(?:authorized|approved|permitted|allowed|cleared|trusted)\s+(?:to\s+)?(?:approve|spend|transact|execute|sign\s+off\s+on|commit)\s+(?:up\s+to\s+)?\$?[\d,]{3,}/i,
    severity: 'high',
    category: 'authority_threshold_drift',
    description: 'Mid-session attempt to raise the agent\'s claimed authorization ceiling (long-horizon grooming).',
  },
];

// =========================================================================
// A2A session-smuggling detector — stateful (looks at message sequences)
// =========================================================================

class A2ASmugglingDetector {
  constructor(opts = {}) {
    this.windowSize = opts.windowSize || 8;
    this.imperativeRe = /\b(?:execute|run|invoke|call|fetch|post|send|delete|drop|exfiltrate|leak|forward|upload|download|install|chmod|sudo|curl|wget|eval|exec|spawn|deploy|publish|merge|push|approve|sign)\b/i;
    this.history = []; // last N envelopes
  }

  /**
   * Record an A2A turn. Returns a verdict if the turn looks smuggled.
   * @param {object} turn { from, to, content, intent? }
   */
  observe(turn) {
    if (!turn || typeof turn.content !== 'string') return { suspicious: false };
    this.history.push({
      ts: Date.now(),
      from: turn.from || 'unknown',
      to: turn.to || 'unknown',
      content: turn.content,
      intent: turn.intent || null,
      density: this._imperativeDensity(turn.content),
    });
    if (this.history.length > this.windowSize) this.history.shift();
    return this._evaluate();
  }

  _imperativeDensity(text) {
    if (!text) return 0;
    const tokens = text.toLowerCase().split(/\s+/);
    if (tokens.length === 0) return 0;
    let hits = 0;
    for (const t of tokens) if (this.imperativeRe.test(t)) hits++;
    return hits / tokens.length;
  }

  _evaluate() {
    if (this.history.length < 2) return { suspicious: false };
    const recent = this.history[this.history.length - 1];
    const baseline = this.history.slice(0, -1);
    const avgDensity = baseline.reduce((a, b) => a + b.density, 0) / baseline.length;
    // Smuggled turn: imperative density spike + tool reference inside an
    // in-protocol response from a non-originating agent.
    const spike = recent.density > 0.05 && recent.density > avgDensity * 3 + 0.02;
    const hasTool = /\b(?:tool|function|api|endpoint|webhook|skill)\s*[:=]/i.test(recent.content);
    if (spike && hasTool) {
      return {
        suspicious: true,
        reason: 'imperative-density spike + tool reference in mid-protocol turn',
        recent: { from: recent.from, density: recent.density },
        baselineAvgDensity: avgDensity,
      };
    }
    return { suspicious: false };
  }
}

// =========================================================================
// MCP tool response schema-pinning — CVE-2026-26118 defense
// =========================================================================

class MCPSchemaPin {
  constructor(opts = {}) {
    this.pins = new Map(); // toolName → { fields, types, hash }
    this.strict = opts.strict !== false;
  }

  /**
   * Register a tool's expected response shape (from the first known-good
   * response, or from an explicit JSON schema).
   */
  register(toolName, sampleResponse) {
    if (!toolName) throw new Error('register requires toolName');
    const shape = this._shapeOf(sampleResponse);
    this.pins.set(toolName, {
      fields: shape.fields,
      types: shape.types,
      hash: shape.hash,
    });
    return shape;
  }

  /**
   * Check whether a tool's actual response matches the pinned shape.
   * Returns { ok, violations: [...] }.
   */
  check(toolName, response) {
    if (!this.pins.has(toolName)) {
      return this.strict
        ? { ok: false, violations: [{ kind: 'unpinned_tool', tool: toolName }] }
        : { ok: true, violations: [] };
    }
    const expected = this.pins.get(toolName);
    const actual = this._shapeOf(response);
    const violations = [];
    if (actual.hash !== expected.hash) {
      // Drill into specifics.
      const added = actual.fields.filter((f) => !expected.fields.includes(f));
      const removed = expected.fields.filter((f) => !actual.fields.includes(f));
      const retyped = [];
      for (const f of actual.fields) {
        if (f in expected.types && actual.types[f] !== expected.types[f]) {
          retyped.push({ field: f, expected: expected.types[f], actual: actual.types[f] });
        }
      }
      if (added.length) violations.push({ kind: 'added_fields', fields: added });
      if (removed.length) violations.push({ kind: 'removed_fields', fields: removed });
      if (retyped.length) violations.push({ kind: 'retyped_fields', changes: retyped });
    }
    return { ok: violations.length === 0, violations };
  }

  _shapeOf(value) {
    const fields = [];
    const types = {};
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      for (const k of Object.keys(value).sort()) {
        fields.push(k);
        types[k] = Array.isArray(value[k]) ? 'array' : typeof value[k];
      }
    }
    const canonical = fields.map((f) => `${f}:${types[f]}`).join('|');
    const hash = crypto.createHash('sha256').update(canonical).digest('hex').slice(0, 16);
    return { fields, types, hash };
  }
}

// =========================================================================
// Reverse-CAPTCHA invisible-Unicode binary-payload detector
// =========================================================================

const ZWC_CHARS = ['​', '‌', '‍', '⁠', '⁣', '﻿', '᠎'];

function detectZwcBinaryPayload(text, opts = {}) {
  if (typeof text !== 'string') return { suspicious: false };
  const threshold = opts.minCount || 16;
  let count = 0;
  const positions = [];
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (ZWC_CHARS.includes(c)) { count++; positions.push(i); }
  }
  if (count < threshold) return { suspicious: false, count };
  // Density: ZWC chars vs visible chars in a 200-char window.
  const span = positions.length > 1 ? positions[positions.length - 1] - positions[0] : 0;
  const density = span > 0 ? count / span : 1;
  // Attempt binary decode: map ZWC pairs to bits, decode to ASCII.
  const bits = positions.map((i) => (text[i] === '‌' || text[i] === '⁣') ? '1' : '0').join('');
  let decoded = '';
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    const byte = parseInt(bits.slice(i, i + 8), 2);
    if (byte >= 32 && byte < 127) decoded += String.fromCharCode(byte);
    else decoded += '?';
  }
  const printable = decoded.replace(/[?]/g, '').length;
  const printableRatio = decoded.length > 0 ? printable / decoded.length : 0;
  return {
    suspicious: count >= threshold && (density > 0.05 || printableRatio > 0.4),
    count,
    density,
    decodedSample: decoded.slice(0, 80),
    printableRatio,
  };
}

// =========================================================================
// Pull it all together: one-call scan helper
// =========================================================================

function scanA2A(input, opts = {}) {
  const findings = [];
  for (const p of NEW_2026_PATTERNS) {
    if (opts.categories && !opts.categories.includes(p.category)) continue;
    if (p.regex.test(input)) {
      findings.push({
        category: p.category,
        severity: p.severity,
        description: p.description,
      });
    }
  }
  const zwc = detectZwcBinaryPayload(input);
  if (zwc.suspicious) {
    findings.push({
      category: 'zwc_binary_payload',
      severity: 'high',
      description: `Invisible-Unicode binary-encoded payload (count=${zwc.count}, decoded sample: ${JSON.stringify(zwc.decodedSample)}).`,
    });
  }
  return { findings, count: findings.length };
}

module.exports = {
  NEW_2026_PATTERNS,
  A2ASmugglingDetector,
  MCPSchemaPin,
  detectZwcBinaryPayload,
  scanA2A,
};
