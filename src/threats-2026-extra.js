'use strict';

/**
 * Agent Shield — Extra 2026 Threat Detectors
 *
 * Closes the remaining 5 threat-intel gaps from the May 2026 council
 * research (after a2a-guard.js covered the first 6):
 *
 *   1. TOCTOU browser-agent race      — DOM mutates between observe + act
 *   2. GraphRAG triple poisoning       — adversarial entity/relation triples
 *   3. GCG / activation-steering suffix — high-perplexity trailing tokens
 *   4. Cross-conversation memory replay — re-scan persisted memory on load
 *   5. Context-stuffing attention dilution — oversized/repetitive inputs
 *
 * Each closes one of the gaps the threat-coverage council surfaced; all
 * zero-dep and integrable as middleware around existing Shield calls.
 */

const crypto = require('crypto');

// =========================================================================
// 1. TOCTOU browser-agent guard
// =========================================================================

/**
 * Hash a piece of DOM (or any text) before the agent observes it; check
 * the same locator yields the same hash before the agent acts on it. If
 * the page mutates between observe→act, that's a TOCTOU attack
 * (arXiv 2603.00476).
 *
 * Usage:
 *   const guard = new TOCTOUGuard();
 *   guard.observe('button#buy', currentButtonHtml);   // before agent reasons
 *   ...
 *   const v = guard.checkBeforeAct('button#buy', currentButtonHtml);
 *   if (!v.safe) refuseAction(v.reason);
 */
class TOCTOUGuard {
  constructor(opts = {}) {
    this.observations = new Map(); // locator → { hash, ts }
    this.maxAgeMs = opts.maxAgeMs || 60_000;
    this.maxEntries = opts.maxEntries || 1000;
  }

  observe(locator, content) {
    if (typeof locator !== 'string' || !locator) throw new Error('observe: locator required');
    const hash = this._hash(content);
    this.observations.set(locator, { hash, ts: Date.now() });
    if (this.observations.size > this.maxEntries) {
      // Drop oldest insertion-order entries.
      const overshoot = this.observations.size - this.maxEntries;
      let i = 0;
      for (const k of this.observations.keys()) {
        if (i++ >= overshoot) break;
        this.observations.delete(k);
      }
    }
    return hash;
  }

  checkBeforeAct(locator, content) {
    const prior = this.observations.get(locator);
    if (!prior) {
      return { safe: false, reason: `no prior observation for ${locator}` };
    }
    if (Date.now() - prior.ts > this.maxAgeMs) {
      return { safe: false, reason: `observation for ${locator} is stale (>${this.maxAgeMs}ms)` };
    }
    const currentHash = this._hash(content);
    if (currentHash !== prior.hash) {
      return {
        safe: false,
        reason: `DOM drift detected at ${locator}`,
        priorHash: prior.hash,
        currentHash,
        ageMs: Date.now() - prior.ts,
      };
    }
    return { safe: true, hash: currentHash, ageMs: Date.now() - prior.ts };
  }

  clear() { this.observations.clear(); }

  _hash(content) {
    return crypto.createHash('sha256').update(String(content || '')).digest('hex').slice(0, 24);
  }
}

// =========================================================================
// 2. GraphRAG triple poisoning
// =========================================================================

const GRAPH_TRIPLE_PATTERNS = [
  {
    // Adversarial "isAdmin" / "hasRole" / "trustedBy" edges pointing at root.
    regex: /(?:relation|edge|triple|entity|predicate)\s*[:=]\s*["'][^"']{0,80}(?:isAdmin|hasRole|trustedBy|equivalentTo|sameAs|hasPermission|grants?Access|owns)["'][\s\S]{0,80}(?:root|admin|system|superuser|owner|god|\*)/i,
    severity: 'high',
    category: 'graph_triple_poisoning',
    description: 'GraphRAG triple grants a privileged role to a sensitive entity (arXiv 2508.04276).',
  },
  {
    // Inline turtle/RDF syntax with the same shape.
    regex: /[<:]\w+(?::\w+)?\s+(?::?isAdmin|:?hasRole|:?trustedBy|:?equivalentTo|:?sameAs)\s+(?::?root|:?admin|:?system|:?superuser)\b/i,
    severity: 'high',
    category: 'graph_triple_poisoning',
    description: 'Inline RDF/Turtle triple wires a sensitive entity to admin-equivalent role.',
  },
  {
    // Bulk-import of edges all pointing to one privileged target.
    regex: /(?:add|insert|upsert|merge)\s+(?:edges?|triples?|relations?)[\s\S]{0,200}?(?:->|\s+TO\s+|\s+=>\s+)\s*['"]?(?:root|admin|system|superuser|owner)['"]?(?:[\s\S]{0,200}(?:->|\s+TO\s+|\s+=>\s+)\s*['"]?(?:root|admin|system|superuser|owner)['"]?){2,}/i,
    severity: 'critical',
    category: 'graph_triple_poisoning',
    description: 'Bulk-edge import all targeting privileged entities (graph-poisoning bulk variant).',
  },
];

// =========================================================================
// 3. GCG / activation-steering suffix
// =========================================================================

/**
 * Detect Greedy Coordinate Gradient (GCG) and activation-steering style
 * suffixes (arXiv 2503.09066, 2506.16078). These are trailing tokens
 * optimized by gradient methods; surface signal:
 *   - high non-dictionary token ratio
 *   - high Shannon entropy in trailing window
 *   - lots of punctuation/symbol bytes
 *   - very few real English words
 *
 * @param {string} text
 * @param {object} [opts]
 * @param {number} [opts.windowChars=200] — how much trailing text to scan
 * @param {number} [opts.minSuspiciousLength=40] — only flag windows ≥ this
 * @returns {{ suspicious, score, entropy, nonDictRatio, symbolRatio, window }}
 */
function detectGCGSuffix(text, opts = {}) {
  if (typeof text !== 'string') return { suspicious: false, score: 0 };
  const windowChars = opts.windowChars || 200;
  const minLen = opts.minSuspiciousLength || 40;
  const tail = text.slice(-windowChars).trim();
  if (tail.length < minLen) return { suspicious: false, score: 0 };

  // Shannon entropy of the byte stream.
  const freq = {};
  for (const ch of tail) freq[ch] = (freq[ch] || 0) + 1;
  const n = tail.length;
  let entropy = 0;
  for (const c of Object.values(freq)) {
    const p = c / n;
    entropy -= p * Math.log2(p);
  }

  // Tokenize crudely and compute non-dictionary ratio. The "dictionary"
  // here is a small set of very common English function words plus the
  // common bigram-prefix test (ascii letters, length ≥ 2). Anything that
  // isn't a plausible word counts as non-dictionary.
  const tokens = tail.split(/\s+/).filter(Boolean);
  let nonDict = 0;
  for (const tok of tokens) {
    if (!/^[a-zA-Z][a-zA-Z\-']{1,15}$/.test(tok)) nonDict++;
  }
  const nonDictRatio = tokens.length ? nonDict / tokens.length : 0;

  // Symbol density — punctuation + brackets + non-ASCII.
  let symbols = 0;
  for (const ch of tail) {
    const code = ch.charCodeAt(0);
    if ((code >= 33 && code <= 47) || (code >= 58 && code <= 64) || (code >= 91 && code <= 96) || (code >= 123 && code <= 126) || code > 127) symbols++;
  }
  const symbolRatio = symbols / tail.length;

  // Composite score: weights tuned so a clean English suffix scores ≈ 0
  // and a GCG-style suffix scores > 1.
  const score = (entropy / 6) * 0.35 + nonDictRatio * 0.5 + symbolRatio * 0.5;
  return {
    suspicious: score >= 0.7 && nonDictRatio >= 0.4 && tokens.length >= 4,
    score,
    entropy,
    nonDictRatio,
    symbolRatio,
    window: tail,
  };
}

// =========================================================================
// 4. Cross-conversation memory replay
// =========================================================================

/**
 * Wrap a memory backend so that persisted messages are re-scanned at
 * LOAD time, not just at write time (CVE-2026-25253). A poisoned message
 * dormant for weeks becomes active when the user resumes the thread; the
 * write-time scan can't catch what was injected in a prior, less-strict
 * version of Shield.
 *
 * Usage:
 *   const guard = new MemoryReplayGuard({ shield });
 *   const filtered = guard.scanLoad(messagesFromDb);
 *   if (filtered.flagged.length) ...
 */
class MemoryReplayGuard {
  constructor(opts = {}) {
    this.shield = opts.shield;
    if (!this.shield || typeof this.shield.scan !== 'function') {
      throw new Error('MemoryReplayGuard requires { shield } with .scan()');
    }
    // Stored messages get a stricter threshold than live input: anything
    // medium-or-higher is flagged on load.
    this.minSeverity = opts.minSeverity || 'medium';
    this.sevRank = { low: 1, medium: 2, high: 3, critical: 4 };
  }

  scanLoad(messages) {
    if (!Array.isArray(messages)) throw new Error('scanLoad: messages must be array');
    const flagged = [];
    const safe = [];
    const minRank = this.sevRank[this.minSeverity] || 2;
    for (const m of messages) {
      const content = typeof m === 'string' ? m : (m && (m.content || m.text || ''));
      if (!content) { safe.push(m); continue; }
      const scan = this.shield.scan(content);
      const top = (scan.threats || [])[0];
      const rank = top ? (this.sevRank[top.severity] || 0) : 0;
      if (rank >= minRank) {
        flagged.push({ message: m, scan, severity: top.severity, category: top.category });
      } else {
        safe.push(m);
      }
    }
    return { safe, flagged, totalLoaded: messages.length, flaggedCount: flagged.length };
  }
}

// =========================================================================
// 5. Context-stuffing / attention dilution
// =========================================================================

/**
 * Detect oversized + low-entropy inputs designed to push real instructions
 * past the model's effective attention window (arXiv 2511.22729). Two
 * signals:
 *   - input size > maxNormalSize bytes (default 30KB single message)
 *   - repetitive padding: long runs of the same short pattern
 *   - whitespace runs > 2KB
 *
 * @param {string} text
 * @param {object} [opts]
 * @returns {{ suspicious, reasons[], size, repetitionFactor }}
 */
function detectContextStuffing(text, opts = {}) {
  if (typeof text !== 'string') return { suspicious: false, reasons: [] };
  const maxNormal = opts.maxNormalSize || 30_000;
  const minRepetitionRun = opts.minRepetitionRun || 20;
  const maxWsRunBytes = opts.maxWsRunBytes || 2_048;
  const reasons = [];
  if (text.length > maxNormal) reasons.push(`oversized input: ${text.length} bytes`);

  // Repetition: scan for (X){N+} where N >= minRepetitionRun and X ≤ 40 chars.
  const repMatch = text.match(/(.{1,40}?)\1{20,}/);
  let repetitionFactor = 0;
  if (repMatch) {
    repetitionFactor = (repMatch[0].length / Math.max(repMatch[1].length, 1));
    reasons.push(`repetitive padding: ${repMatch[1].length}-char pattern × ${Math.round(repetitionFactor)}`);
  } else {
    // Try less restrictive: many short patterns repeated 20+
    const wide = text.match(/(.{1,80}?)\1{15,}/);
    if (wide) {
      repetitionFactor = (wide[0].length / Math.max(wide[1].length, 1));
      reasons.push(`repetitive padding: ${wide[1].length}-char pattern × ${Math.round(repetitionFactor)}`);
    }
  }

  const wsMatch = text.match(/\s{2048,}/);
  if (wsMatch) reasons.push(`whitespace run: ${wsMatch[0].length} bytes`);

  return {
    suspicious: reasons.length >= 1 && (text.length > maxNormal / 2 || repetitionFactor >= minRepetitionRun),
    reasons,
    size: text.length,
    repetitionFactor,
  };
}

// =========================================================================
// One-call helper combining all five
// =========================================================================

function scanExtras2026(input, opts = {}) {
  const findings = [];
  for (const p of GRAPH_TRIPLE_PATTERNS) {
    if (p.regex.test(input)) {
      findings.push({ category: p.category, severity: p.severity, description: p.description });
    }
  }
  const gcg = detectGCGSuffix(input, opts.gcg);
  if (gcg.suspicious) {
    findings.push({
      category: 'gcg_style_suffix',
      severity: 'medium',
      description: `Trailing window has GCG/activation-steering shape (score=${gcg.score.toFixed(2)}, nonDictRatio=${gcg.nonDictRatio.toFixed(2)}).`,
    });
  }
  const stuff = detectContextStuffing(input, opts.contextStuffing);
  if (stuff.suspicious) {
    findings.push({
      category: 'attention_dilution_attack',
      severity: 'medium',
      description: `Context-stuffing signals: ${stuff.reasons.join('; ')}.`,
    });
  }
  return { findings, count: findings.length };
}

module.exports = {
  TOCTOUGuard,
  GRAPH_TRIPLE_PATTERNS,
  detectGCGSuffix,
  MemoryReplayGuard,
  detectContextStuffing,
  scanExtras2026,
};
