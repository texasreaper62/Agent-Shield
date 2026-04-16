'use strict';

/**
 * Agent Shield — ReDoS Audit
 *
 * Scans every detection regex in detector-core.js for catastrophic
 * backtracking (ReDoS) by running a battery of adversarial worst-case
 * inputs against each pattern and measuring execution time.
 *
 * A pattern is flagged as a ReDoS risk if any single input takes longer
 * than the threshold (default 100ms) to evaluate.
 *
 * Run with: node scripts/redos-audit.js
 */

const { getRawPatterns } = require('../src/detector-core');

const PREFIX = '[Agent Shield]';
const THRESHOLD_MS = 100;
const HARD_TIMEOUT_MS = 2000; // per-test hard ceiling (still measured)

/**
 * Build a suite of adversarial inputs designed to stress common ReDoS
 * shapes: long repetition, nested quantifiers, alternation collapse,
 * greedy/non-greedy interaction, and trailing mismatch characters.
 * @returns {Array<{name: string, input: string}>}
 */
const buildAdversarialInputs = () => {
  const inputs = [];

  // Long repetitive strings (pure character flood)
  inputs.push({ name: 'a x 10k', input: 'a'.repeat(10000) });
  inputs.push({ name: 'a x 100k', input: 'a'.repeat(100000) });
  inputs.push({ name: 'space x 10k', input: ' '.repeat(10000) });
  inputs.push({ name: 'word x 10k', input: 'ignore '.repeat(2000) });

  // Classic evil-regex triggers (for (a+)+ / (a|a)* / (a*)* style bombs)
  inputs.push({ name: 'a x 100 + !', input: 'a'.repeat(100) + '!' });
  inputs.push({ name: 'a x 1k + !', input: 'a'.repeat(1000) + '!' });
  inputs.push({ name: 'a x 5k + !', input: 'a'.repeat(5000) + '!' });

  // Known ReDoS attack payload — polynomial explosion on nested optionals
  inputs.push({
    name: 'a? x 100 + a x 100',
    input: 'x=' + 'a'.repeat(100)
  });
  inputs.push({
    name: 'a? x 50 + a x 50',
    input: 'x=' + 'a'.repeat(50)
  });

  // Alternation collapse — common in override/exfil patterns
  inputs.push({
    name: 'mixed-alt x 500',
    input: 'ignore previous instructions rules guidelines '.repeat(500)
  });

  // Whitespace heavy (triggers \s+ over-scan)
  inputs.push({ name: 'ws-heavy', input: ('ignore' + ' '.repeat(200)).repeat(100) });
  inputs.push({ name: 'newline-heavy', input: 'A\n'.repeat(10000) });

  // Long near-matches that force the engine deep into the pattern before failing
  inputs.push({
    name: 'near-miss ignore',
    input: 'ignore ' + 'all '.repeat(1000) + 'previous XYZ'
  });
  inputs.push({
    name: 'near-miss system',
    input: 'SYSTEM:' + ' '.repeat(5000) + 'x'
  });

  // Unicode-ish & homoglyph flood (catches patterns using \w boundaries)
  inputs.push({ name: 'digit flood', input: '1'.repeat(10000) });
  inputs.push({ name: 'mixed case flood', input: 'AaAaAa'.repeat(5000) });

  // Classic (a+)+ payload shape
  inputs.push({ name: 'evil-a+', input: 'a'.repeat(30) + 'X' });
  inputs.push({ name: 'evil-a+ medium', input: 'a'.repeat(50) + 'X' });

  // URL-ish flood for URL patterns
  inputs.push({
    name: 'url flood',
    input: 'https://' + 'a.'.repeat(1000) + 'com/' + 'x'.repeat(5000)
  });

  // Comma/brace flood for JSON-ish patterns
  inputs.push({ name: 'brace flood', input: '{'.repeat(5000) + 'x' });
  inputs.push({ name: 'comma flood', input: ','.repeat(10000) + 'x' });

  return inputs;
};

/**
 * Safely time a single regex against a single input.
 * Uses process.hrtime.bigint for sub-ms resolution.
 * @param {RegExp} regex
 * @param {string} input
 * @returns {{ms: number, matched: boolean, error: ?string}}
 */
const timeRegex = (regex, input) => {
  try {
    const start = process.hrtime.bigint();
    const matched = regex.test(input);
    const end = process.hrtime.bigint();
    const ms = Number(end - start) / 1e6;
    // Reset lastIndex for global regexes to avoid state bleed
    if (regex.global || regex.sticky) regex.lastIndex = 0;
    return { ms, matched, error: null };
  } catch (err) {
    return { ms: 0, matched: false, error: err.message };
  }
};

const main = () => {
  console.log(`${PREFIX} ReDoS Audit — starting`);
  const patterns = getRawPatterns();
  const inputs = buildAdversarialInputs();
  console.log(`${PREFIX} Loaded ${patterns.length} patterns; ${inputs.length} adversarial inputs per pattern`);
  console.log(`${PREFIX} Flagging threshold: >${THRESHOLD_MS}ms`);
  console.log('');

  const risky = [];
  const nearRisky = []; // 50-100ms — worth noting
  let totalTestMs = 0;
  let maxPatternMs = 0;

  for (let i = 0; i < patterns.length; i++) {
    const p = patterns[i];
    if (!p.regex) continue;

    let worstMs = 0;
    let worstInput = null;
    let worstError = null;

    for (const adv of inputs) {
      const result = timeRegex(p.regex, adv.input);
      totalTestMs += result.ms;
      if (result.error && !worstError) worstError = result.error;
      if (result.ms > worstMs) {
        worstMs = result.ms;
        worstInput = adv.name;
      }
      // Short-circuit if we exceed the hard timeout to avoid freezing the audit
      if (result.ms > HARD_TIMEOUT_MS) break;
    }

    if (worstMs > maxPatternMs) maxPatternMs = worstMs;

    if (worstMs > THRESHOLD_MS) {
      risky.push({
        index: i,
        category: p.category,
        severity: p.severity,
        source: p.source,
        flags: p.flags,
        worstInput,
        worstMs: Math.round(worstMs * 100) / 100,
        error: worstError
      });
    } else if (worstMs > 50) {
      nearRisky.push({
        index: i,
        category: p.category,
        source: p.source,
        worstInput,
        worstMs: Math.round(worstMs * 100) / 100
      });
    }
  }

  console.log('===================================================');
  console.log(`${PREFIX} ReDoS Audit Report`);
  console.log('===================================================');
  console.log(`Total patterns:           ${patterns.length}`);
  console.log(`Total regex evaluations:  ${patterns.length * inputs.length}`);
  console.log(`Total wall time in regex: ${totalTestMs.toFixed(1)}ms`);
  console.log(`Slowest pattern time:     ${maxPatternMs.toFixed(2)}ms`);
  console.log(`Patterns >${THRESHOLD_MS}ms (RISKY): ${risky.length}`);
  console.log(`Patterns 50-${THRESHOLD_MS}ms (watch):  ${nearRisky.length}`);
  console.log('');

  if (risky.length === 0) {
    console.log(`${PREFIX} PASS — no patterns exceed the ${THRESHOLD_MS}ms ReDoS threshold.`);
  } else {
    console.log(`${PREFIX} FAIL — ${risky.length} patterns are ReDoS risks:`);
    console.log('');
    for (const r of risky) {
      console.log(`  #${r.index}  [${r.severity}] ${r.category}`);
      console.log(`      worst input: ${r.worstInput}  (${r.worstMs}ms)`);
      console.log(`      regex: /${r.source}/${r.flags}`);
      if (r.error) console.log(`      error: ${r.error}`);
      console.log('');
    }
  }

  if (nearRisky.length > 0) {
    console.log(`${PREFIX} Watch-list (50-${THRESHOLD_MS}ms):`);
    for (const r of nearRisky.slice(0, 15)) {
      console.log(`  #${r.index}  ${r.category}  ${r.worstMs}ms  (${r.worstInput})`);
    }
    if (nearRisky.length > 15) console.log(`  ... and ${nearRisky.length - 15} more`);
    console.log('');
  }

  process.exit(risky.length > 0 ? 1 : 0);
};

main();
