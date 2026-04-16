'use strict';

/**
 * Agent Shield — Pattern Quality Audit
 *
 * Measures the real-world value of every regex in detector-core.js by
 * running each pattern independently against:
 *   - Attack samples from src/real-benchmark.js (HackAPrompt / TensorTrust /
 *     research corpus)
 *   - Attack & benign samples from src/sota-benchmark.js
 *     (BIPIA / HackAPrompt / MCPTox / Multilingual / Stealth / Functional)
 *   - Benign samples extracted from test/false-positives.js
 *
 * For every pattern the script tallies:
 *   - true positives  (matched an attack)
 *   - false positives (matched a benign sample)
 *   - total matches   (both)
 *
 * Output is a ranked report:
 *   1. Most valuable patterns (high TP, low FP)
 *   2. Dead patterns (never matched anything, attack or benign)
 *   3. Noisy patterns (FP rate >= 25%)
 *
 * Run with: node scripts/pattern-quality-audit.js
 */

const path = require('path');
const { getRawPatterns } = require('../src/detector-core');

const PREFIX = '[Agent Shield]';

// -------------------------------------------------------------------------
// Sample loading
// -------------------------------------------------------------------------

/**
 * Load attack and benign samples from the real + SOTA benchmark modules.
 * @returns {{attacks: string[], benign: string[]}}
 */
const loadBenchmarkSamples = () => {
  const attacks = [];
  const benign = [];

  // real-benchmark.js — attacks + benign
  try {
    const rb = require('../src/real-benchmark');
    for (const s of rb.REAL_HACKAPROMPT || []) attacks.push(s.text || s);
    for (const s of rb.REAL_TENSORTRUST || []) attacks.push(s.text || s);
    for (const s of rb.REAL_RESEARCH || []) attacks.push(s.text || s);
    for (const s of rb.REAL_BENIGN || []) benign.push(s.text || s);
  } catch (err) {
    console.warn(`${PREFIX} WARN could not load real-benchmark: ${err.message}`);
  }

  // sota-benchmark.js — attacks + benign per suite
  try {
    const sb = require('../src/sota-benchmark');
    const suites = [
      sb.BIPIA_SAMPLES,
      sb.HACKAPROMPT_SAMPLES,
      sb.MCPTOX_SAMPLES,
      sb.MULTILINGUAL_SAMPLES,
      sb.STEALTH_SAMPLES
    ];
    for (const suite of suites) {
      if (!suite) continue;
      for (const s of suite.attacks || []) attacks.push(s.text || s);
      for (const s of suite.benign || []) benign.push(s.text || s);
    }
    // FUNCTIONAL_SAMPLES uses `legitimate` (benign only)
    if (sb.FUNCTIONAL_SAMPLES) {
      for (const s of sb.FUNCTIONAL_SAMPLES.legitimate || []) benign.push(s.text || s);
    }
  } catch (err) {
    console.warn(`${PREFIX} WARN could not load sota-benchmark: ${err.message}`);
  }

  return { attacks, benign };
};

/**
 * Extract benign string literals from test/false-positives.js by parsing the
 * file and pulling every quoted string out of the named array literals. This
 * avoids executing the file (which would invoke the shield directly).
 * @returns {string[]}
 */
const loadFalsePositiveSamples = () => {
  const fs = require('fs');
  const file = path.resolve(__dirname, '..', 'test', 'false-positives.js');
  let src;
  try {
    src = fs.readFileSync(file, 'utf8');
  } catch (err) {
    console.warn(`${PREFIX} WARN could not read false-positives.js: ${err.message}`);
    return [];
  }

  const arrayNames = [
    'normalConversations',
    'technical',
    'business',
    'trickyButLegit',
    'specialChars',
    'casual',
    'paragraphs',
    'multilingual',
    'edgeCases'
  ];

  const samples = [];
  for (const name of arrayNames) {
    const re = new RegExp(`const\\s+${name}\\s*=\\s*\\[([\\s\\S]*?)\\];`, 'm');
    const m = src.match(re);
    if (!m) continue;
    const body = m[1];
    // Pull single-quoted string literals. false-positives.js uses '...'.
    // Reconstruct simple escape sequences.
    const stringRe = /'((?:\\'|[^'])*)'/g;
    let sm;
    while ((sm = stringRe.exec(body)) !== null) {
      const raw = sm[1]
        .replace(/\\'/g, "'")
        .replace(/\\n/g, '\n')
        .replace(/\\t/g, '\t')
        .replace(/\\\\/g, '\\');
      if (raw.length > 1) samples.push(raw);
    }
  }
  return samples;
};

// -------------------------------------------------------------------------
// Audit
// -------------------------------------------------------------------------

/**
 * Safely test a regex against text, resetting lastIndex and swallowing errors.
 * @param {RegExp} regex
 * @param {string} text
 * @returns {boolean}
 */
const testSafe = (regex, text) => {
  try {
    if (regex.global || regex.sticky) regex.lastIndex = 0;
    return regex.test(text);
  } catch (_) {
    return false;
  }
};

const main = () => {
  console.log(`${PREFIX} Pattern Quality Audit — starting`);

  const patterns = getRawPatterns();
  const { attacks, benign: benchmarkBenign } = loadBenchmarkSamples();
  const fpBenign = loadFalsePositiveSamples();
  const benign = [...benchmarkBenign, ...fpBenign];

  console.log(`${PREFIX} Loaded ${patterns.length} patterns`);
  console.log(`${PREFIX} Attack samples:  ${attacks.length}`);
  console.log(`${PREFIX} Benign samples:  ${benign.length} (${benchmarkBenign.length} benchmark + ${fpBenign.length} false-positive)`);
  console.log('');

  // Per-pattern counters
  const stats = patterns.map((p, i) => ({
    index: i,
    category: p.category,
    severity: p.severity,
    source: p.source,
    flags: p.flags,
    tp: 0,
    fp: 0
  }));

  // Score attacks → TP
  for (const text of attacks) {
    if (typeof text !== 'string' || !text) continue;
    for (let i = 0; i < patterns.length; i++) {
      const p = patterns[i];
      if (!p.regex) continue;
      if (testSafe(p.regex, text)) stats[i].tp++;
    }
  }

  // Score benign → FP
  for (const text of benign) {
    if (typeof text !== 'string' || !text) continue;
    for (let i = 0; i < patterns.length; i++) {
      const p = patterns[i];
      if (!p.regex) continue;
      if (testSafe(p.regex, text)) stats[i].fp++;
    }
  }

  // Derived metrics
  for (const s of stats) {
    s.total = s.tp + s.fp;
    s.tpRate = attacks.length ? s.tp / attacks.length : 0;
    s.fpRate = benign.length ? s.fp / benign.length : 0;
    // Value score: reward TP, penalize FP. F-score-ish but keeps raw magnitude.
    s.value = s.tp - 2 * s.fp;
  }

  // -----------------------------------------------------------------------
  // Report
  // -----------------------------------------------------------------------
  console.log('===================================================');
  console.log(`${PREFIX} Pattern Quality Report`);
  console.log('===================================================');

  const dead = stats.filter(s => s.total === 0);
  const noisy = stats.filter(s => s.fp > 0 && s.fpRate >= 0.25);
  const active = stats.filter(s => s.total > 0);

  console.log(`Total patterns:          ${patterns.length}`);
  console.log(`Active patterns:         ${active.length}`);
  console.log(`Dead patterns:           ${dead.length}  (never matched attack OR benign)`);
  console.log(`Noisy patterns (FP>=25%): ${noisy.length}`);
  const totalTP = stats.reduce((a, s) => a + s.tp, 0);
  const totalFP = stats.reduce((a, s) => a + s.fp, 0);
  console.log(`Aggregate TP matches:    ${totalTP}`);
  console.log(`Aggregate FP matches:    ${totalFP}`);
  console.log('');

  // --- Top 20 by value ----
  const ranked = stats.slice().sort((a, b) => b.value - a.value || b.tp - a.tp);
  console.log('--- Top 20 Most Valuable Patterns ---');
  console.log('idx  sev      tp   fp   value  category');
  for (const s of ranked.slice(0, 20)) {
    console.log(
      `#${String(s.index).padStart(3)}  ${String(s.severity || '?').padEnd(8)} `
      + `${String(s.tp).padStart(3)}  ${String(s.fp).padStart(3)}  `
      + `${String(s.value).padStart(5)}  ${s.category}`
    );
  }
  console.log('');

  // --- Dead patterns ----
  console.log(`--- Dead Patterns (${dead.length}) — never matched ANY sample ---`);
  if (dead.length === 0) {
    console.log('  (none)');
  } else {
    for (const s of dead.slice(0, 50)) {
      const shortSrc = s.source && s.source.length > 70
        ? s.source.slice(0, 70) + '...'
        : s.source || '(no source)';
      console.log(`  #${String(s.index).padStart(3)}  [${s.severity || '?'}] ${s.category}`);
      console.log(`       /${shortSrc}/${s.flags || ''}`);
    }
    if (dead.length > 50) console.log(`  ... and ${dead.length - 50} more`);
  }
  console.log('');

  // --- Noisy patterns ----
  const noisyRanked = noisy.slice().sort((a, b) => b.fpRate - a.fpRate);
  console.log(`--- Noisy Patterns (${noisy.length}) — FP rate >= 25% ---`);
  if (noisy.length === 0) {
    console.log('  (none)');
  } else {
    console.log('idx  sev      tp   fp   fp%    category');
    for (const s of noisyRanked.slice(0, 25)) {
      console.log(
        `#${String(s.index).padStart(3)}  ${String(s.severity || '?').padEnd(8)} `
        + `${String(s.tp).padStart(3)}  ${String(s.fp).padStart(3)}  `
        + `${(s.fpRate * 100).toFixed(1).padStart(5)}%  ${s.category}`
      );
    }
    if (noisy.length > 25) console.log(`  ... and ${noisy.length - 25} more`);
  }
  console.log('');

  // Exit 0 — this is a report, not a gate.
  process.exit(0);
};

main();
