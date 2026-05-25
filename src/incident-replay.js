'use strict';

/**
 * Agent Shield — Autonomous Incident Replay
 *
 * Reproduces a flagged scan, root-causes which rule(s) fired, and proposes
 * a structured fix (regex tightening, allowlist entry, or new test case).
 * Optionally uses a ShieldAgent's judge to draft a human-readable
 * remediation. Pure, zero-dependency core; LLM augmentation is optional.
 *
 * Typical flow:
 *   const replay = new IncidentReplay({ shield, agent });
 *   const report = await replay.investigate({
 *     text: '![logo](https://search.com?q=python)',
 *     reportedAs: 'false_positive',
 *     userNote: 'Benign Google image search URL — should not be flagged.',
 *   });
 *   console.log(report.diagnosis);    // root cause sentence
 *   console.log(report.proposedFix);  // structured patch suggestion
 *   console.log(report.testCase);     // regression test to add
 */

const { AgentShield } = require('./index');
const { getPatterns } = require('./detector-core');

const INCIDENT_KINDS = Object.freeze({
  FALSE_POSITIVE: 'false_positive',
  FALSE_NEGATIVE: 'false_negative',
  REDOS: 'redos',
  CRASH: 'crash',
});

class IncidentReplay {
  constructor(opts = {}) {
    this.shield = opts.shield || new AgentShield(opts.shieldOptions || {});
    this.agent = opts.agent || null; // optional ShieldAgent for judge-backed narration
    this.judgeTimeoutMs = opts.judgeTimeoutMs || 8000;
    this.patternsCache = null;
  }

  /**
   * Investigate an incident. Returns a structured report:
   *   {
   *     kind, input, scan, scanMs, firedRules[], rootCause,
   *     diagnosis, proposedFix, testCase, judgeNarration?
   *   }
   *
   * @param {object} incident
   * @param {string} incident.text             — the input that misbehaved
   * @param {string} incident.reportedAs       — INCIDENT_KINDS value
   * @param {string} [incident.userNote]       — human description
   * @param {string} [incident.expectedAction] — for false_negative cases
   */
  async investigate(incident) {
    if (!incident || typeof incident.text !== 'string') {
      throw new Error('investigate requires {text: string}');
    }
    const kind = incident.reportedAs || this._guessKind(incident);
    const input = incident.text;

    const replay = this._safeScan(input);
    if (replay.error) {
      // Crash path — detector blew up on this input.
      return this._buildCrashReport({ input, error: replay.error, kind, incident });
    }
    const { scan, scanMs } = replay;

    // Map fired rules back to their pattern source for root-cause analysis.
    const firedRules = this._mapFiredRules(scan);
    const rootCause = this._diagnose({ kind, scan, firedRules, scanMs, input });
    const proposedFix = this._proposeFix({ kind, rootCause, firedRules, input });
    const testCase = this._buildTestCase({ kind, input, scan, expectedAction: incident.expectedAction });

    let judgeNarration = null;
    if (this.agent && this.agent.judge) {
      judgeNarration = await this._narrateWithJudge({ kind, input, scan, firedRules, userNote: incident.userNote });
    }

    return {
      kind,
      input,
      scan,
      scanMs,
      firedRules,
      rootCause,
      diagnosis: rootCause.summary,
      proposedFix,
      testCase,
      judgeNarration,
      replayedAt: Date.now(),
    };
  }

  /**
   * Replay a batch of incidents. Aggregates root causes so a repeated bug
   * shows up as one cluster instead of N separate reports.
   */
  async investigateBatch(incidents) {
    const reports = [];
    for (const inc of incidents) {
      try {
        reports.push(await this.investigate(inc));
      } catch (err) {
        reports.push({ error: err.message, input: inc.text });
      }
    }
    return this._aggregate(reports);
  }

  _guessKind(incident) {
    if (incident.expectedAction === 'block') return INCIDENT_KINDS.FALSE_NEGATIVE;
    if (incident.expectedAction === 'allow') return INCIDENT_KINDS.FALSE_POSITIVE;
    return INCIDENT_KINDS.FALSE_POSITIVE; // most common default
  }

  _safeScan(text) {
    const start = process.hrtime.bigint();
    try {
      const scan = this.shield.scan(text);
      const scanMs = Number(process.hrtime.bigint() - start) / 1e6;
      return { scan, scanMs };
    } catch (err) {
      return { error: err };
    }
  }

  _patterns() {
    if (this.patternsCache) return this.patternsCache;
    try {
      this.patternsCache = getPatterns();
    } catch (_) {
      this.patternsCache = [];
    }
    return this.patternsCache;
  }

  _mapFiredRules(scan) {
    if (!scan || !Array.isArray(scan.threats)) return [];
    const patterns = this._patterns();
    return scan.threats.map((threat) => {
      // Match by category + description (the public scan output doesn't
      // expose the regex source for security reasons; we look it up here).
      const match = patterns.find(
        (p) => p.category === threat.category &&
          (p.description || '').slice(0, 60) === (threat.description || '').slice(0, 60)
      );
      return {
        category: threat.category,
        severity: threat.severity,
        description: threat.description,
        confidence: threat.confidence,
        patternSource: match ? (match.regex ? String(match.regex) : '(pattern source unavailable)') : '(pattern not found in registry)',
      };
    });
  }

  _diagnose({ kind, scan, firedRules, scanMs, input }) {
    if (kind === INCIDENT_KINDS.REDOS || scanMs > 200) {
      return {
        summary: `Detector took ${scanMs.toFixed(0)}ms on a ${input.length}-byte input — likely catastrophic backtracking in one pattern.`,
        signal: 'latency',
        primarySuspect: firedRules[0] || null,
        evidence: { scanMs, inputLength: input.length, threatCount: (scan.threats || []).length },
      };
    }
    if (kind === INCIDENT_KINDS.FALSE_POSITIVE) {
      const fired = firedRules[0];
      return {
        summary: fired
          ? `Pattern in category "${fired.category}" matched benign input. Pattern source: ${truncate(fired.patternSource, 120)}`
          : 'Detector flagged input but no specific rule was identified (check pattern registry sync).',
        signal: 'false_positive',
        primarySuspect: fired,
        evidence: { firedCategories: firedRules.map((r) => r.category), inputSnippet: truncate(input, 80) },
      };
    }
    if (kind === INCIDENT_KINDS.FALSE_NEGATIVE) {
      return {
        summary: scan.threats.length === 0
          ? 'No rule matched the malicious input — coverage gap. New pattern or category needed.'
          : `Rules fired but did not produce the expected action — severity may be too low (${scan.threats.map((t) => t.severity).join(', ')}).`,
        signal: 'false_negative',
        primarySuspect: null,
        evidence: { firedCategories: firedRules.map((r) => r.category), inputSnippet: truncate(input, 80) },
      };
    }
    return {
      summary: `Unknown incident kind: ${kind}.`,
      signal: 'unknown',
      primarySuspect: null,
      evidence: {},
    };
  }

  _proposeFix({ kind, rootCause, firedRules, input }) {
    if (rootCause.signal === 'latency') {
      // Even when no rule fired (the slow pattern might match nothing yet
      // still backtrack), recommend pattern rewriting + bisection to find
      // the offender. Naming the primary suspect when known.
      const target = rootCause.primarySuspect ? rootCause.primarySuspect.category : 'unknown — bisect patterns';
      return {
        kind: 'rewrite_pattern',
        target,
        rationale: 'Cap unbounded quantifier or split alternation to prevent catastrophic backtracking.',
        suggestion: `Bound any (?:X){N,} repetitions in the pattern to {N,30} or similar; add an anchor before greedy "[\\\\s\\\\S]{0,K}" gaps; consider splitting into 2 simpler regexes. If the offender is unknown, bisect by disabling pattern halves until the latency drops.`,
      };
    }
    if (rootCause.signal === 'false_positive' && rootCause.primarySuspect) {
      const cat = rootCause.primarySuspect.category;
      return {
        kind: 'tighten_pattern_or_allowlist',
        target: cat,
        rationale: 'Pattern matched benign content. Either narrow the regex (preferred) or add an allowlist rule.',
        suggestions: [
          `Add a negative-lookahead exclusion for the benign shape (e.g. ?: q | text alone).`,
          `Allowlist.addRule({ pattern: ${JSON.stringify(truncate(input, 60))}, category: '${cat}', reason: 'Triaged false positive — see incident report.' })`,
        ],
      };
    }
    if (rootCause.signal === 'false_negative') {
      return {
        kind: 'add_pattern',
        target: 'new_or_existing_category',
        rationale: 'No rule matched a malicious input — add detection coverage.',
        suggestion: `Add a new pattern dict to INJECTION_PATTERNS targeting the distinctive substring(s) of the missed attack. Sample input excerpt: ${JSON.stringify(truncate(input, 100))}`,
      };
    }
    return {
      kind: 'investigate_manually',
      target: firedRules.map((r) => r.category).join(',') || 'unknown',
      rationale: 'Automated analysis inconclusive; requires manual triage.',
    };
  }

  _buildTestCase({ kind, input, scan, expectedAction }) {
    // Emit a Node.js + Python regression test snippet the human can paste.
    const escaped = JSON.stringify(input);
    const fireCategories = (scan.threats || []).map((t) => t.category);

    if (kind === INCIDENT_KINDS.FALSE_POSITIVE) {
      return {
        nodejs: `// test/test-fp-regressions.js
const { AgentShield } = require('../src/index');
const shield = new AgentShield();
const r = shield.scan(${escaped});
assert(r.threats.length === 0, 'should not flag benign input (was ${fireCategories.join(',')})');`,
        python: `# python-sdk/tests/test_fp_regressions.py
from agent_shield.detector import scan_text
r = scan_text(${escaped})
assert len(r['threats']) == 0, f"should not flag benign input (was {[t['category'] for t in r['threats']]})"`,
      };
    }
    if (kind === INCIDENT_KINDS.FALSE_NEGATIVE) {
      return {
        nodejs: `// test/test-fn-regressions.js
const { AgentShield } = require('../src/index');
const shield = new AgentShield();
const r = shield.scan(${escaped});
assert(r.threats.length >= 1, 'should detect attack (action expected: ${expectedAction || 'block'})');`,
        python: `# python-sdk/tests/test_fn_regressions.py
from agent_shield.detector import scan_text
r = scan_text(${escaped})
assert len(r['threats']) >= 1, "should detect attack"`,
      };
    }
    return {
      nodejs: `// add a regression test capturing scan time as well
const start = Date.now();
shield.scan(${escaped});
const elapsed = Date.now() - start;
assert(elapsed < 200, 'scan should complete under 200ms budget (was ' + elapsed + 'ms)');`,
      python: null,
    };
  }

  async _narrateWithJudge({ kind, input, scan, firedRules, userNote }) {
    const prompt = [
      `You are reviewing a security-scanner incident. Explain in 2-3 sentences what went wrong and what to change, for a code reviewer who knows regex.`,
      ``,
      `Incident kind: ${kind}`,
      `User note: ${userNote || '(none)'}`,
      `Input: ${JSON.stringify(input.slice(0, 200))}`,
      `Rules fired: ${firedRules.map((r) => `${r.category}/${r.severity}`).join(', ') || 'none'}`,
      `Top threats:`,
      ...(scan.threats || []).slice(0, 5).map((t) => `  - ${t.category}: ${t.description}`),
      ``,
      `Reply with {"explanation": "...", "remediation": "..."} and nothing else.`,
    ].join('\n');
    try {
      const reply = await Promise.race([
        Promise.resolve(this.agent.judge({ system: 'You are a regex code reviewer. Reply with JSON only.', user: prompt })),
        new Promise((_, reject) => setTimeout(() => reject(new Error('judge timeout')), this.judgeTimeoutMs)),
      ]);
      const trimmed = String(reply).trim();
      const start = trimmed.indexOf('{');
      const end = trimmed.lastIndexOf('}');
      if (start < 0 || end < 0) throw new Error('no JSON in judge reply');
      return JSON.parse(trimmed.slice(start, end + 1));
    } catch (err) {
      return { explanation: `(judge unavailable: ${err.message})`, remediation: null };
    }
  }

  _buildCrashReport({ input, error, kind, incident }) {
    return {
      kind: INCIDENT_KINDS.CRASH,
      input,
      error: { message: error.message, stack: error.stack ? error.stack.split('\n').slice(0, 6).join('\n') : null },
      rootCause: {
        summary: `Detector threw an exception on this input: ${error.message}`,
        signal: 'crash',
        primarySuspect: null,
        evidence: { inputLength: input.length, reportedKind: kind },
      },
      diagnosis: `Detector crashed on ${input.length}-byte input.`,
      proposedFix: {
        kind: 'fix_crash',
        target: 'detector-core',
        rationale: 'Detector must never throw on user input; wrap the offending path in try/catch and return safe-with-error.',
      },
      testCase: {
        nodejs: `const { AgentShield } = require('../src/index');
const shield = new AgentShield();
assert.doesNotThrow(() => shield.scan(${JSON.stringify(input)}), 'scan should not throw on this input');`,
      },
      userNote: incident.userNote || null,
      replayedAt: Date.now(),
    };
  }

  _aggregate(reports) {
    const clusters = new Map();
    for (const r of reports) {
      if (r.error) continue;
      const key = r.rootCause && r.rootCause.primarySuspect
        ? `${r.kind}::${r.rootCause.primarySuspect.category}`
        : `${r.kind}::no-rule`;
      if (!clusters.has(key)) clusters.set(key, { key, count: 0, exemplars: [] });
      const c = clusters.get(key);
      c.count++;
      if (c.exemplars.length < 3) c.exemplars.push(r);
    }
    return {
      totalIncidents: reports.length,
      errors: reports.filter((r) => r.error).length,
      clusterCount: clusters.size,
      clusters: Array.from(clusters.values()).sort((a, b) => b.count - a.count),
    };
  }
}

function truncate(s, n) {
  if (typeof s !== 'string') return String(s);
  return s.length > n ? s.slice(0, n) + '…' : s;
}

module.exports = {
  IncidentReplay,
  INCIDENT_KINDS,
};
