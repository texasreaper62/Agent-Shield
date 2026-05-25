'use strict';

/**
 * Agent Shield — Autonomous Threat Hunter (H2)
 *
 * Scrapes/ingests novel attack disclosures, synthesizes detection patterns,
 * red-teams them against the current detector, and emits a PR-ready report
 * with new patterns to add.
 *
 * Pluggable sources: a source is any object with `.name` and async `.fetch()`
 * returning an array of `{title, url, attackText, severity?, references?}`.
 * Built-in sources:
 *   - LocalCorpusSource: reads a JSONL file or in-memory array (offline-safe)
 *   - HTTPSourceFn: caller-supplied async () => items (uses caller's fetch
 *     so we add no dependency and the user controls network egress)
 *
 * The hunter is intentionally conservative: every synthesized pattern is
 * checked against a benign corpus to estimate false-positive rate; patterns
 * above a threshold are filtered out before recommendation.
 */

const { AgentShield } = require('./index');

const DEFAULT_BENIGN_CORPUS = Object.freeze([
  'Hello, how can I help you today?',
  'What is the weather in Tokyo?',
  'Please write a short poem about autumn.',
  'My favorite recipe is for chocolate chip cookies.',
  'The meeting is at 3pm in the conference room.',
  'Can you summarize the attached document?',
  'Translate "good morning" into Japanese.',
  'List the prime numbers under 50.',
  'Explain the difference between TCP and UDP.',
  'What time does the library close today?',
]);

class LocalCorpusSource {
  constructor(items, opts = {}) {
    this.name = opts.name || 'local-corpus';
    this.items = items || [];
  }
  async fetch() { return this.items.slice(); }
}

class HTTPSourceFn {
  constructor(fn, opts = {}) {
    this.name = opts.name || 'http';
    this.fn = fn;
  }
  async fetch() { return await this.fn(); }
}

class ThreatHunter {
  constructor(opts = {}) {
    this.shield = opts.shield || new AgentShield(opts.shieldOptions || {});
    this.sources = opts.sources || [];
    this.benignCorpus = opts.benignCorpus || DEFAULT_BENIGN_CORPUS;
    this.fpThreshold = typeof opts.fpThreshold === 'number' ? opts.fpThreshold : 0.05;
    this.maxPatternsPerHunt = opts.maxPatternsPerHunt || 20;
    this.judge = opts.judge || null;
    this.judgeBudgetMs = opts.judgeBudgetMs || 5000;
  }

  addSource(source) {
    if (!source || typeof source.fetch !== 'function') {
      throw new Error('source must have async fetch()');
    }
    this.sources.push(source);
  }

  /**
   * Run one hunt across all sources. Returns:
   *   {
   *     sourcesScanned: string[], itemsFetched: number,
   *     novelAttacks: [],         // detector failed to catch these
   *     proposedPatterns: [],     // synthesized regex candidates (post-FP filter)
   *     filtered: [],             // patterns rejected for high FP
   *     report: string,           // markdown summary, PR-ready
   *   }
   */
  async hunt() {
    const fetched = [];
    const sourcesScanned = [];
    for (const src of this.sources) {
      sourcesScanned.push(src.name);
      try {
        const items = await src.fetch();
        for (const item of items || []) {
          if (item && typeof item.attackText === 'string') fetched.push({ ...item, source: src.name });
        }
      } catch (err) {
        fetched.push({ source: src.name, error: err.message, attackText: '' });
      }
    }

    const novelAttacks = [];
    for (const item of fetched) {
      if (!item.attackText) continue;
      let scan;
      try { scan = this.shield.scan(item.attackText); }
      catch (e) { scan = { stats: {}, threats: [], error: e.message }; }
      if ((scan.threats || []).length === 0) {
        novelAttacks.push({ ...item, scanError: scan.error || null });
      }
    }

    const synthesized = novelAttacks
      .slice(0, this.maxPatternsPerHunt)
      .map((a) => this._synthesizePattern(a))
      .filter(Boolean);

    const evaluated = synthesized.map((p) => {
      const fpRate = this._estimateFPRate(p);
      return { ...p, fpRate, accepted: fpRate <= this.fpThreshold };
    });

    const proposed = evaluated.filter((p) => p.accepted);
    const filtered = evaluated.filter((p) => !p.accepted);

    let judgeNotes = null;
    if (this.judge && proposed.length > 0) {
      judgeNotes = await this._reviewProposalsWithJudge(proposed);
    }

    return {
      sourcesScanned,
      itemsFetched: fetched.length,
      novelAttackCount: novelAttacks.length,
      novelAttacks: novelAttacks.slice(0, 50),
      proposedPatterns: proposed,
      filteredPatterns: filtered,
      judgeNotes,
      report: this._buildReport({ sourcesScanned, fetched, novelAttacks, proposed, filtered, judgeNotes }),
    };
  }

  /**
   * Convert an attack string into a candidate regex by:
   *   1. Identifying the most distinctive 3-5 word phrase.
   *   2. Escaping regex metacharacters.
   *   3. Allowing flexible whitespace and case-insensitive matching.
   * Conservative — prefers a tight literal phrase over loose alternation
   * to keep FPs near zero.
   */
  _synthesizePattern(attack) {
    const text = (attack.attackText || '').trim();
    if (text.length < 10) return null;
    const tokens = text.toLowerCase()
      .replace(/[^a-z0-9\s]/g, ' ')
      .split(/\s+/)
      .filter((t) => t.length >= 3);
    if (tokens.length < 3) return null;
    // Pick the rarest 4-token window using simple frequency in benign corpus.
    const ngramFreq = this._ngramFrequency(tokens, 4);
    if (ngramFreq.length === 0) return null;
    ngramFreq.sort((a, b) => a.score - b.score);
    const chosen = ngramFreq[0].ngram;
    const escaped = chosen.map(escapeRe).join('\\s+');
    return {
      sourceAttack: text.length > 200 ? text.slice(0, 200) + '…' : text,
      sourceUrl: attack.url || null,
      sourceName: attack.source || null,
      regex: new RegExp(escaped, 'i'),
      regexSource: escaped,
      severity: attack.severity || 'high',
      category: attack.category || 'novel_attack',
      description: `Auto-synthesized from ${attack.source || 'unknown source'}: ${attack.title || text.slice(0, 50)}`,
    };
  }

  _ngramFrequency(tokens, n) {
    if (tokens.length < n) return [];
    const out = [];
    for (let i = 0; i <= tokens.length - n; i++) {
      const ngram = tokens.slice(i, i + n);
      let score = 0;
      for (const benign of this.benignCorpus) {
        const blow = benign.toLowerCase();
        if (ngram.every((t) => blow.includes(t))) score++;
      }
      out.push({ ngram, score });
    }
    return out;
  }

  _estimateFPRate(proposal) {
    let hits = 0;
    for (const benign of this.benignCorpus) {
      if (proposal.regex.test(benign)) hits++;
    }
    return hits / this.benignCorpus.length;
  }

  async _reviewProposalsWithJudge(proposed) {
    const summary = proposed.slice(0, 10).map((p, i) =>
      `${i + 1}. category=${p.category} severity=${p.severity} regex=${p.regexSource} fpRate=${p.fpRate.toFixed(2)}\n   source attack: ${p.sourceAttack.slice(0, 120)}`
    ).join('\n');
    const prompt = `Review these candidate detection patterns synthesized from new attack disclosures. For each, rate quality (accept/reject) and suggest a tightening if needed. Reply with {"reviews":[{"index":1,"verdict":"accept|reject","note":"..."}]} and nothing else.\n\n${summary}`;
    try {
      const reply = await Promise.race([
        Promise.resolve(this.judge({ system: 'You are a regex code reviewer. Reply with JSON only.', user: prompt })),
        new Promise((_, reject) => setTimeout(() => reject(new Error('judge timeout')), this.judgeBudgetMs)),
      ]);
      const s = String(reply).trim();
      const start = s.indexOf('{');
      const end = s.lastIndexOf('}');
      if (start < 0 || end < 0) throw new Error('no JSON');
      return JSON.parse(s.slice(start, end + 1));
    } catch (err) {
      return { reviews: [], error: err.message };
    }
  }

  _buildReport({ sourcesScanned, fetched, novelAttacks, proposed, filtered, judgeNotes }) {
    const lines = [];
    lines.push('# Agent Shield — Autonomous Threat Hunt Report');
    lines.push('');
    lines.push(`**Sources scanned:** ${sourcesScanned.join(', ') || '(none)'}`);
    lines.push(`**Items fetched:** ${fetched.length}`);
    lines.push(`**Novel attacks (detector missed):** ${novelAttacks.length}`);
    lines.push(`**Patterns proposed (after FP filter):** ${proposed.length}`);
    lines.push(`**Patterns filtered (FP rate too high):** ${filtered.length}`);
    lines.push('');
    if (proposed.length > 0) {
      lines.push('## Proposed patterns');
      lines.push('');
      lines.push('| # | Category | Severity | FP rate | Regex |');
      lines.push('|---|---|---|---:|---|');
      for (let i = 0; i < proposed.length; i++) {
        const p = proposed[i];
        lines.push(`| ${i + 1} | ${p.category} | ${p.severity} | ${(p.fpRate * 100).toFixed(1)}% | \`${p.regexSource}\` |`);
      }
      lines.push('');
      lines.push('### Source attacks');
      for (let i = 0; i < proposed.length; i++) {
        const p = proposed[i];
        lines.push(`${i + 1}. [${p.sourceName || 'unknown'}] ${p.sourceUrl ? `<${p.sourceUrl}>` : ''}`);
        lines.push(`   \`${p.sourceAttack}\``);
      }
    } else {
      lines.push('_No new patterns proposed this run._');
    }
    if (judgeNotes && judgeNotes.reviews && judgeNotes.reviews.length > 0) {
      lines.push('');
      lines.push('## Judge review');
      for (const r of judgeNotes.reviews) {
        lines.push(`- #${r.index} **${r.verdict}**: ${r.note}`);
      }
    }
    return lines.join('\n');
  }
}

function escapeRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

module.exports = {
  ThreatHunter,
  LocalCorpusSource,
  HTTPSourceFn,
  DEFAULT_BENIGN_CORPUS,
};
