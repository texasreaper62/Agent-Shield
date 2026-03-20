#!/usr/bin/env node
'use strict';

/**
 * Agent Shield — Benchmark Runner (CLI)
 *
 * Registers Agent Shield as the default engine, runs the DEFAULT_SUITE,
 * prints formatted results, and optionally compares with a baseline
 * simple regex engine.
 *
 * Usage:
 *   node benchmark-registry/run-benchmark.js [--json] [--markdown] [--compare]
 *
 * All detection runs locally — no data ever leaves your environment.
 */

const { BenchmarkRegistry, DEFAULT_SUITE } = require('./registry');
const { Leaderboard } = require('./leaderboard');

// =========================================================================
// PARSE CLI FLAGS
// =========================================================================

const args = process.argv.slice(2);
const flags = {
  json: args.includes('--json'),
  markdown: args.includes('--markdown'),
  compare: args.includes('--compare'),
  help: args.includes('--help') || args.includes('-h')
};

if (flags.help) {
  console.log(`
Agent Shield Benchmark Runner

Usage:
  node benchmark-registry/run-benchmark.js [options]

Options:
  --json       Output results as JSON
  --markdown   Output results as Markdown table
  --compare    Include a simple regex baseline engine for comparison
  -h, --help   Show this help message
`);
  process.exit(0);
}

// =========================================================================
// ENGINE: AGENT SHIELD
// =========================================================================

/**
 * Create Agent Shield scanner engine.
 * @returns {Object} Engine descriptor
 */
function createAgentShieldEngine() {
  let scanText;
  try {
    const detectorCore = require('../src/detector-core');
    scanText = detectorCore.scanText;
  } catch (err) {
    console.log('[Agent Shield] Warning: Could not load detector-core.js, using fallback scanner');
    scanText = fallbackScanner;
  }

  return {
    id: 'agent-shield',
    name: 'Agent Shield',
    version: getVersion(),
    scanFn: function(text) {
      return scanText(text);
    }
  };
}

/**
 * Read version from package.json.
 * @returns {string}
 */
function getVersion() {
  try {
    const pkg = require('../package.json');
    return pkg.version || '1.0.0';
  } catch (err) {
    return '1.0.0';
  }
}

/**
 * Fallback scanner when detector-core.js is not available.
 * @param {string} text
 * @returns {Object}
 */
function fallbackScanner(text) {
  const patterns = [
    /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules)/i,
    /disregard\s+(your\s+)?(prior|previous)\s+(instructions|rules)/i,
    /forget\s+(everything|all)\s+(above|previous)/i,
    /you\s+are\s+now\s+(DAN|jailbroken|unrestricted)/i,
    /pretend\s+you\s+are\s+(an?\s+)?(evil|unrestricted|hacker)/i,
    /act\s+as\s+(an?\s+)?(hacker|evil|unrestricted)/i,
    /developer\s+mode/i,
    /bypass\s+(all\s+)?(safety|content|security)/i,
    /override\s+(all\s+)?(safety|system|security)/i,
    /exfiltrat/i,
    /send\s+(all\s+)?(data|conversation|system)\s+to/i,
    /system\s+prompt/i,
    /reveal\s+(your\s+)?(hidden|secret|initial)\s+instructions/i,
    /rm\s+-rf/i,
    /DROP\s+TABLE/i,
    /reverse\s+shell/i,
    /sudo\s+command/i
  ];

  const threats = [];
  for (const p of patterns) {
    if (p.test(text)) {
      threats.push({ pattern: p.toString() });
    }
  }

  return {
    status: threats.length > 0 ? 'danger' : 'safe',
    threats
  };
}

// =========================================================================
// ENGINE: SIMPLE REGEX BASELINE
// =========================================================================

/**
 * Create a deliberately simple regex baseline engine for comparison.
 * @returns {Object} Engine descriptor
 */
function createBaselineEngine() {
  return {
    id: 'simple-regex',
    name: 'Simple Regex Baseline',
    version: '0.1.0',
    scanFn: function(text) {
      const basicPatterns = [
        /ignore.*(previous|prior).*instructions/i,
        /you are now/i,
        /pretend you/i,
        /system prompt/i,
        /rm\s+-rf/i,
        /DROP\s+TABLE/i
      ];

      let detected = false;
      for (const p of basicPatterns) {
        if (p.test(text)) {
          detected = true;
          break;
        }
      }

      return { detected, status: detected ? 'danger' : 'safe', threats: detected ? [{ match: true }] : [] };
    }
  };
}

// =========================================================================
// MAIN
// =========================================================================

function main() {
  console.log('');
  console.log('='.repeat(60));
  console.log('  Agent Shield — Benchmark Registry');
  console.log('='.repeat(60));
  console.log('');

  const registry = new BenchmarkRegistry();

  // Register Agent Shield
  const agentShieldEngine = createAgentShieldEngine();
  registry.registerEngine(agentShieldEngine);

  // Optionally register baseline
  if (flags.compare) {
    const baselineEngine = createBaselineEngine();
    registry.registerEngine(baselineEngine);
  }

  // Print suite info
  const stats = DEFAULT_SUITE.getStats();
  console.log(`[Agent Shield] Suite: ${DEFAULT_SUITE.name}`);
  console.log(`[Agent Shield] Test cases: ${stats.totalCases} (${stats.attacks} attacks, ${stats.benign} benign)`);
  console.log(`[Agent Shield] Categories: ${stats.categories.join(', ')}`);
  console.log('');

  // Run benchmarks
  console.log('[Agent Shield] Running benchmarks...');
  console.log('');

  const allResults = registry.runAllBenchmarks(DEFAULT_SUITE);

  // Print results for each engine
  for (const [engineId, result] of Object.entries(allResults)) {
    printEngineResult(result);
  }

  // Print leaderboard
  if (flags.compare || registry.engines.size > 1) {
    console.log('');
    console.log('-'.repeat(60));
    console.log('  LEADERBOARD');
    console.log('-'.repeat(60));
    console.log('');
    console.log(registry.leaderboard.formatTable('f1'));
  }

  // Comparison
  if (flags.compare) {
    const ids = Array.from(registry.engines.keys());
    const comparison = registry.compareEngines(ids);
    console.log('');
    console.log('-'.repeat(60));
    console.log('  SIDE-BY-SIDE COMPARISON');
    console.log('-'.repeat(60));
    console.log('');
    for (const [metric, values] of Object.entries(comparison.comparison)) {
      const parts = Object.entries(values).map(function(kv) {
        let val;
        if (metric === 'throughput') {
          val = typeof kv[1] === 'number' ? Math.round(kv[1]) + ' t/s' : kv[1];
        } else {
          val = typeof kv[1] === 'number' ? (kv[1] * 100).toFixed(1) + '%' : kv[1];
        }
        return kv[0] + ': ' + val;
      });
      console.log(`  ${metric.padEnd(20)} ${parts.join('  |  ')}`);
    }
  }

  // JSON output
  if (flags.json) {
    console.log('');
    console.log('-'.repeat(60));
    console.log('  JSON OUTPUT');
    console.log('-'.repeat(60));
    console.log(registry.exportResults('json'));
  }

  // Markdown output
  if (flags.markdown) {
    console.log('');
    console.log('-'.repeat(60));
    console.log('  MARKDOWN OUTPUT');
    console.log('-'.repeat(60));
    console.log('');
    console.log(registry.exportResults('markdown'));
  }

  console.log('');
  console.log('='.repeat(60));
  console.log('  Benchmark complete.');
  console.log('='.repeat(60));
  console.log('');
}

/**
 * Print formatted results for a single engine.
 * @param {Object} result - Benchmark result
 */
function printEngineResult(result) {
  const m = result.metrics;

  console.log(`--- ${result.engineName} v${result.engineVersion} ---`);
  console.log(`  Accuracy:    ${(m.accuracy * 100).toFixed(1)}%`);
  console.log(`  Precision:   ${(m.precision * 100).toFixed(1)}%`);
  console.log(`  Recall:      ${(m.recall * 100).toFixed(1)}%`);
  console.log(`  F1 Score:    ${(m.f1 * 100).toFixed(1)}%`);
  console.log(`  MCC:         ${m.mcc !== null ? m.mcc.toFixed(3) : 'N/A'}`);
  console.log(`  FPR:         ${(m.falsePositiveRate * 100).toFixed(1)}%`);
  console.log(`  FNR:         ${(m.falseNegativeRate * 100).toFixed(1)}%`);
  console.log(`  Throughput:  ${m.throughput.toFixed(0)} texts/sec`);
  if (m.latency) {
    console.log(`  Latency p50: ${m.latency.p50}ms | p95: ${m.latency.p95}ms | p99: ${m.latency.p99}ms`);
  }
  console.log(`  Total time:  ${m.totalTimeMs}ms`);
  console.log('');

  // Per-category breakdown
  if (result.perCategory) {
    console.log('  Category Breakdown:');
    for (const [cat, catMetrics] of Object.entries(result.perCategory)) {
      const catF1 = catMetrics.f1 !== undefined ? (catMetrics.f1 * 100).toFixed(1) + '%' : 'N/A';
      const catAcc = catMetrics.accuracy !== undefined ? (catMetrics.accuracy * 100).toFixed(1) + '%' : 'N/A';
      console.log(`    ${cat.padEnd(24)} F1: ${catF1.padEnd(8)} Acc: ${catAcc}`);
    }
    console.log('');
  }
}

main();
