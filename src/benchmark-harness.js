'use strict';

/**
 * Agent Shield — Standardized Benchmark Harness
 *
 * Provides a reproducible framework for evaluating detection engines.
 * Supports dataset loading (JSON, BIPIA, Garak formats), metric computation
 * (precision, recall, F1, MCC, per-category breakdowns), regression tracking,
 * and multi-engine comparison.
 *
 * All processing is local — no data leaves the environment.
 *
 * @module benchmark-harness
 */

const fs = require('fs');
const path = require('path');

// =========================================================================
// CONSTANTS
// =========================================================================

/** Required fields for each dataset entry. */
const REQUIRED_ENTRY_FIELDS = ['id', 'text', 'category', 'expected_detection', 'severity', 'difficulty'];

/** Valid severity levels. */
const VALID_SEVERITIES = ['critical', 'high', 'medium', 'low'];

/** Valid difficulty levels. */
const VALID_DIFFICULTIES = ['easy', 'medium', 'hard'];

/** Default F1 regression threshold (absolute drop). */
const DEFAULT_F1_REGRESSION_THRESHOLD = 0.02;

/** Default latency regression threshold (relative increase). */
const DEFAULT_LATENCY_REGRESSION_THRESHOLD = 0.20;

// =========================================================================
// DatasetLoader
// =========================================================================

/**
 * Validates and loads benchmark datasets from various formats.
 */
class DatasetLoader {
  /**
   * Load a dataset from a JSON file.
   * @param {string} filePath — absolute or relative path to the JSON dataset
   * @returns {{ entries: Array<Object>, meta: Object }}
   */
  load(filePath) {
    const resolved = path.resolve(filePath);
    if (!fs.existsSync(resolved)) {
      throw new Error(`[Agent Shield] Dataset file not found: ${resolved}`);
    }
    const raw = fs.readFileSync(resolved, 'utf-8');
    let data;
    try {
      data = JSON.parse(raw);
    } catch (err) {
      throw new Error(`[Agent Shield] Invalid JSON in dataset: ${err.message}`);
    }

    const entries = Array.isArray(data) ? data : (data.entries || data.dataset || []);
    const meta = Array.isArray(data) ? {} : (data.meta || {});

    this.validate(entries);
    return { entries, meta };
  }

  /**
   * Validate the structure of dataset entries.
   * @param {Array<Object>} entries
   * @throws {Error} if any entry is missing required fields or has invalid values
   */
  validate(entries) {
    if (!Array.isArray(entries) || entries.length === 0) {
      throw new Error('[Agent Shield] Dataset must be a non-empty array of entries');
    }

    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];
      for (const field of REQUIRED_ENTRY_FIELDS) {
        if (!(field in entry)) {
          throw new Error(`[Agent Shield] Entry ${i} missing required field: "${field}"`);
        }
      }
      if (typeof entry.expected_detection !== 'boolean') {
        throw new Error(`[Agent Shield] Entry ${i} (${entry.id}): expected_detection must be boolean`);
      }
      if (!VALID_SEVERITIES.includes(entry.severity)) {
        throw new Error(`[Agent Shield] Entry ${i} (${entry.id}): invalid severity "${entry.severity}"`);
      }
      if (!VALID_DIFFICULTIES.includes(entry.difficulty)) {
        throw new Error(`[Agent Shield] Entry ${i} (${entry.id}): invalid difficulty "${entry.difficulty}"`);
      }
    }
  }

  /**
   * Convert BIPIA-format entries to the standard format.
   * BIPIA entries have: { prompt, label, attack_type }
   * @param {Array<Object>} entries
   * @returns {Array<Object>}
   */
  fromBIPIA(entries) {
    if (!Array.isArray(entries)) {
      throw new Error('[Agent Shield] BIPIA entries must be an array');
    }
    return entries.map((e, i) => ({
      id: e.id || `bipia-${i}`,
      text: e.prompt || e.text || '',
      category: e.attack_type || 'prompt_injection',
      expected_detection: e.label === 'attack' || e.label === 1 || e.label === true,
      severity: e.severity || 'high',
      difficulty: e.difficulty || 'medium'
    }));
  }

  /**
   * Convert Garak-format entries to the standard format.
   * Garak entries have: { prompt, detector_results, probe_name }
   * @param {Array<Object>} entries
   * @returns {Array<Object>}
   */
  fromGarak(entries) {
    if (!Array.isArray(entries)) {
      throw new Error('[Agent Shield] Garak entries must be an array');
    }
    return entries.map((e, i) => ({
      id: e.id || `garak-${i}`,
      text: e.prompt || e.text || '',
      category: e.probe_name || 'unknown',
      expected_detection: e.detector_results === 'fail' || e.expected_detection === true,
      severity: e.severity || 'medium',
      difficulty: e.difficulty || 'medium'
    }));
  }
}

// =========================================================================
// BenchmarkMetrics
// =========================================================================

/**
 * Computes classification metrics from benchmark results.
 */
class BenchmarkMetrics {
  /**
   * Compute comprehensive metrics from benchmark results.
   * @param {Array<Object>} results — array of { entry, detected, expected, latencyMs }
   * @returns {Object} metrics object
   */
  compute(results) {
    let tp = 0, fp = 0, tn = 0, fn = 0;
    const latencies = [];
    const perCategory = {};
    const perDifficulty = { easy: { tp: 0, fp: 0, tn: 0, fn: 0 }, medium: { tp: 0, fp: 0, tn: 0, fn: 0 }, hard: { tp: 0, fp: 0, tn: 0, fn: 0 } };

    for (const r of results) {
      const expected = r.expected;
      const detected = r.detected;
      const cat = r.entry.category;
      const diff = r.entry.difficulty;

      if (!perCategory[cat]) {
        perCategory[cat] = { tp: 0, fp: 0, tn: 0, fn: 0 };
      }

      if (expected && detected) {
        tp++;
        perCategory[cat].tp++;
        if (perDifficulty[diff]) perDifficulty[diff].tp++;
      } else if (!expected && detected) {
        fp++;
        perCategory[cat].fp++;
        if (perDifficulty[diff]) perDifficulty[diff].fp++;
      } else if (!expected && !detected) {
        tn++;
        perCategory[cat].tn++;
        if (perDifficulty[diff]) perDifficulty[diff].tn++;
      } else {
        fn++;
        perCategory[cat].fn++;
        if (perDifficulty[diff]) perDifficulty[diff].fn++;
      }

      if (typeof r.latencyMs === 'number') {
        latencies.push(r.latencyMs);
      }
    }

    const precision = (tp + fp) > 0 ? tp / (tp + fp) : 0;
    const recall = (tp + fn) > 0 ? tp / (tp + fn) : 0;
    const f1 = (precision + recall) > 0 ? (2 * precision * recall) / (precision + recall) : 0;
    const accuracy = results.length > 0 ? (tp + tn) / results.length : 0;
    const mcc = this._computeMCC(tp, tn, fp, fn);

    const confusionMatrix = { tp, fp, tn, fn };

    // Per-category metrics
    const perCategoryMetrics = {};
    for (const [cat, cm] of Object.entries(perCategory)) {
      perCategoryMetrics[cat] = this._metricsFromCM(cm);
    }

    // Per-difficulty metrics
    const perDifficultyMetrics = {};
    for (const [diff, cm] of Object.entries(perDifficulty)) {
      if (cm.tp + cm.fp + cm.tn + cm.fn > 0) {
        perDifficultyMetrics[diff] = this._metricsFromCM(cm);
      }
    }

    // Latency stats
    const latency = this._computeLatencyStats(latencies);

    return {
      total: results.length,
      precision,
      recall,
      f1,
      accuracy,
      mcc,
      confusionMatrix,
      perCategory: perCategoryMetrics,
      perDifficulty: perDifficultyMetrics,
      latency
    };
  }

  /**
   * Compute Matthews Correlation Coefficient.
   * MCC = (TP*TN - FP*FN) / sqrt((TP+FP)(TP+FN)(TN+FP)(TN+FN))
   * @param {number} tp
   * @param {number} tn
   * @param {number} fp
   * @param {number} fn
   * @returns {number}
   * @private
   */
  _computeMCC(tp, tn, fp, fn) {
    const numerator = (tp * tn) - (fp * fn);
    const denominator = Math.sqrt(
      (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)
    );
    if (denominator === 0) return 0;
    return numerator / denominator;
  }

  /**
   * Derive precision/recall/f1 from a confusion matrix bucket.
   * @param {{ tp: number, fp: number, tn: number, fn: number }} cm
   * @returns {{ precision: number, recall: number, f1: number, total: number }}
   * @private
   */
  _metricsFromCM(cm) {
    const precision = (cm.tp + cm.fp) > 0 ? cm.tp / (cm.tp + cm.fp) : 0;
    const recall = (cm.tp + cm.fn) > 0 ? cm.tp / (cm.tp + cm.fn) : 0;
    const f1 = (precision + recall) > 0 ? (2 * precision * recall) / (precision + recall) : 0;
    return { precision, recall, f1, total: cm.tp + cm.fp + cm.tn + cm.fn, ...cm };
  }

  /**
   * Compute latency statistics from an array of timings.
   * @param {number[]} latencies
   * @returns {{ mean: number, median: number, p95: number, p99: number, min: number, max: number }}
   * @private
   */
  _computeLatencyStats(latencies) {
    if (latencies.length === 0) {
      return { mean: 0, median: 0, p95: 0, p99: 0, min: 0, max: 0 };
    }
    const sorted = [...latencies].sort((a, b) => a - b);
    const sum = sorted.reduce((a, b) => a + b, 0);
    const mean = sum / sorted.length;
    const median = sorted[Math.floor(sorted.length / 2)];
    const p95 = sorted[Math.floor(sorted.length * 0.95)];
    const p99 = sorted[Math.floor(sorted.length * 0.99)];
    return {
      mean: Math.round(mean * 100) / 100,
      median: Math.round(median * 100) / 100,
      p95: Math.round(p95 * 100) / 100,
      p99: Math.round(p99 * 100) / 100,
      min: Math.round(sorted[0] * 100) / 100,
      max: Math.round(sorted[sorted.length - 1] * 100) / 100
    };
  }
}

// =========================================================================
// RegressionTracker
// =========================================================================

/**
 * Tracks performance baselines and detects regressions between runs.
 */
class RegressionTracker {
  /**
   * @param {Object} [options]
   * @param {number} [options.f1Threshold=0.02] — F1 drop threshold to flag regression
   * @param {number} [options.latencyThreshold=0.20] — latency increase ratio threshold
   */
  constructor(options = {}) {
    this.f1Threshold = options.f1Threshold || DEFAULT_F1_REGRESSION_THRESHOLD;
    this.latencyThreshold = options.latencyThreshold || DEFAULT_LATENCY_REGRESSION_THRESHOLD;
  }

  /**
   * Save a baseline to a JSON file.
   * @param {Object} metrics — output from BenchmarkMetrics.compute()
   * @param {string} filePath — path to write the baseline
   */
  saveBaseline(metrics, filePath) {
    const resolved = path.resolve(filePath);
    const dir = path.dirname(resolved);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    const baseline = {
      timestamp: new Date().toISOString(),
      metrics
    };
    fs.writeFileSync(resolved, JSON.stringify(baseline, null, 2), 'utf-8');
  }

  /**
   * Load a baseline from a JSON file.
   * @param {string} filePath
   * @returns {Object} baseline object with { timestamp, metrics }
   */
  loadBaseline(filePath) {
    const resolved = path.resolve(filePath);
    if (!fs.existsSync(resolved)) {
      throw new Error(`[Agent Shield] Baseline file not found: ${resolved}`);
    }
    const raw = fs.readFileSync(resolved, 'utf-8');
    return JSON.parse(raw);
  }

  /**
   * Compare current metrics against a baseline and flag regressions.
   * @param {Object} current — current metrics from BenchmarkMetrics.compute()
   * @param {Object} baseline — baseline object from loadBaseline() or { metrics }
   * @returns {{ passed: boolean, regressions: Array<Object>, improvements: Array<Object> }}
   */
  compare(current, baseline) {
    const baseMetrics = baseline.metrics || baseline;
    const regressions = [];
    const improvements = [];

    // F1 score check
    const f1Delta = current.f1 - baseMetrics.f1;
    if (f1Delta < -this.f1Threshold) {
      regressions.push({
        metric: 'f1',
        baseline: baseMetrics.f1,
        current: current.f1,
        delta: f1Delta,
        message: `F1 dropped by ${Math.abs(f1Delta).toFixed(4)} (threshold: ${this.f1Threshold})`
      });
    } else if (f1Delta > this.f1Threshold) {
      improvements.push({
        metric: 'f1',
        baseline: baseMetrics.f1,
        current: current.f1,
        delta: f1Delta,
        message: `F1 improved by ${f1Delta.toFixed(4)}`
      });
    }

    // Precision check
    const precDelta = current.precision - baseMetrics.precision;
    if (precDelta < -this.f1Threshold) {
      regressions.push({
        metric: 'precision',
        baseline: baseMetrics.precision,
        current: current.precision,
        delta: precDelta,
        message: `Precision dropped by ${Math.abs(precDelta).toFixed(4)}`
      });
    }

    // Recall check
    const recDelta = current.recall - baseMetrics.recall;
    if (recDelta < -this.f1Threshold) {
      regressions.push({
        metric: 'recall',
        baseline: baseMetrics.recall,
        current: current.recall,
        delta: recDelta,
        message: `Recall dropped by ${Math.abs(recDelta).toFixed(4)}`
      });
    }

    // MCC check
    if (typeof baseMetrics.mcc === 'number') {
      const mccDelta = current.mcc - baseMetrics.mcc;
      if (mccDelta < -this.f1Threshold) {
        regressions.push({
          metric: 'mcc',
          baseline: baseMetrics.mcc,
          current: current.mcc,
          delta: mccDelta,
          message: `MCC dropped by ${Math.abs(mccDelta).toFixed(4)}`
        });
      }
    }

    // Latency check (mean)
    if (baseMetrics.latency && baseMetrics.latency.mean > 0 && current.latency) {
      const latencyRatio = (current.latency.mean - baseMetrics.latency.mean) / baseMetrics.latency.mean;
      if (latencyRatio > this.latencyThreshold) {
        regressions.push({
          metric: 'latency_mean',
          baseline: baseMetrics.latency.mean,
          current: current.latency.mean,
          delta: latencyRatio,
          message: `Mean latency increased by ${(latencyRatio * 100).toFixed(1)}% (threshold: ${(this.latencyThreshold * 100).toFixed(0)}%)`
        });
      }
    }

    // Per-category regression check
    if (baseMetrics.perCategory && current.perCategory) {
      for (const [cat, baseStats] of Object.entries(baseMetrics.perCategory)) {
        if (current.perCategory[cat]) {
          const catF1Delta = current.perCategory[cat].f1 - baseStats.f1;
          if (catF1Delta < -this.f1Threshold) {
            regressions.push({
              metric: `category:${cat}:f1`,
              baseline: baseStats.f1,
              current: current.perCategory[cat].f1,
              delta: catF1Delta,
              message: `Category "${cat}" F1 dropped by ${Math.abs(catF1Delta).toFixed(4)}`
            });
          }
        }
      }
    }

    return {
      passed: regressions.length === 0,
      regressions,
      improvements
    };
  }
}

// =========================================================================
// BenchmarkReportGenerator
// =========================================================================

/**
 * Formats benchmark results into text, JSON, and markdown reports.
 */
class BenchmarkReportGenerator {
  /**
   * Generate a plain text report.
   * @param {Object} metrics — output from BenchmarkMetrics.compute()
   * @param {Object} [options]
   * @param {string} [options.title='Benchmark Report']
   * @returns {string}
   */
  text(metrics, options = {}) {
    const title = options.title || 'Benchmark Report';
    const lines = [];
    const sep = '='.repeat(60);

    lines.push(sep);
    lines.push(`  ${title}`);
    lines.push(sep);
    lines.push('');
    lines.push(`  Total entries:  ${metrics.total}`);
    lines.push(`  Precision:      ${(metrics.precision * 100).toFixed(2)}%`);
    lines.push(`  Recall:         ${(metrics.recall * 100).toFixed(2)}%`);
    lines.push(`  F1 Score:       ${(metrics.f1 * 100).toFixed(2)}%`);
    lines.push(`  Accuracy:       ${(metrics.accuracy * 100).toFixed(2)}%`);
    lines.push(`  MCC:            ${metrics.mcc.toFixed(4)}`);
    lines.push('');

    // Confusion matrix
    const cm = metrics.confusionMatrix;
    lines.push('  Confusion Matrix:');
    lines.push(`    TP: ${cm.tp}    FP: ${cm.fp}`);
    lines.push(`    FN: ${cm.fn}    TN: ${cm.tn}`);
    lines.push('');

    // Per-category breakdown
    if (Object.keys(metrics.perCategory).length > 0) {
      lines.push('  Per-Category Breakdown:');
      lines.push(`    ${'Category'.padEnd(25)} ${'Prec'.padStart(7)} ${'Rec'.padStart(7)} ${'F1'.padStart(7)} ${'N'.padStart(5)}`);
      lines.push('    ' + '-'.repeat(51));
      for (const [cat, m] of Object.entries(metrics.perCategory)) {
        lines.push(`    ${cat.padEnd(25)} ${(m.precision * 100).toFixed(1).padStart(6)}% ${(m.recall * 100).toFixed(1).padStart(6)}% ${(m.f1 * 100).toFixed(1).padStart(6)}% ${String(m.total).padStart(5)}`);
      }
      lines.push('');
    }

    // Per-difficulty breakdown
    if (Object.keys(metrics.perDifficulty).length > 0) {
      lines.push('  Per-Difficulty Breakdown:');
      for (const [diff, m] of Object.entries(metrics.perDifficulty)) {
        lines.push(`    ${diff.padEnd(10)} F1: ${(m.f1 * 100).toFixed(1)}%  (n=${m.total})`);
      }
      lines.push('');
    }

    // Latency
    if (metrics.latency && metrics.latency.mean > 0) {
      lines.push('  Latency (ms):');
      lines.push(`    Mean:   ${metrics.latency.mean}`);
      lines.push(`    Median: ${metrics.latency.median}`);
      lines.push(`    P95:    ${metrics.latency.p95}`);
      lines.push(`    P99:    ${metrics.latency.p99}`);
      lines.push(`    Min:    ${metrics.latency.min}`);
      lines.push(`    Max:    ${metrics.latency.max}`);
      lines.push('');
    }

    lines.push(sep);
    return lines.join('\n');
  }

  /**
   * Generate a JSON report.
   * @param {Object} metrics
   * @returns {string}
   */
  json(metrics) {
    return JSON.stringify(metrics, null, 2);
  }

  /**
   * Generate a markdown table report.
   * @param {Object} metrics — output from BenchmarkMetrics.compute()
   * @param {Object} [options]
   * @param {string} [options.title='Benchmark Report']
   * @returns {string}
   */
  markdown(metrics, options = {}) {
    const title = options.title || 'Benchmark Report';
    const lines = [];

    lines.push(`# ${title}`);
    lines.push('');
    lines.push('## Overall Metrics');
    lines.push('');
    lines.push('| Metric | Value |');
    lines.push('|--------|-------|');
    lines.push(`| Total | ${metrics.total} |`);
    lines.push(`| Precision | ${(metrics.precision * 100).toFixed(2)}% |`);
    lines.push(`| Recall | ${(metrics.recall * 100).toFixed(2)}% |`);
    lines.push(`| F1 Score | ${(metrics.f1 * 100).toFixed(2)}% |`);
    lines.push(`| Accuracy | ${(metrics.accuracy * 100).toFixed(2)}% |`);
    lines.push(`| MCC | ${metrics.mcc.toFixed(4)} |`);
    lines.push('');

    // Confusion matrix
    const cm = metrics.confusionMatrix;
    lines.push('## Confusion Matrix');
    lines.push('');
    lines.push('| | Predicted Positive | Predicted Negative |');
    lines.push('|---|---|---|');
    lines.push(`| **Actual Positive** | TP: ${cm.tp} | FN: ${cm.fn} |`);
    lines.push(`| **Actual Negative** | FP: ${cm.fp} | TN: ${cm.tn} |`);
    lines.push('');

    // Per-category
    if (Object.keys(metrics.perCategory).length > 0) {
      lines.push('## Per-Category Breakdown');
      lines.push('');
      lines.push('| Category | Precision | Recall | F1 | N |');
      lines.push('|----------|-----------|--------|-----|---|');
      for (const [cat, m] of Object.entries(metrics.perCategory)) {
        lines.push(`| ${cat} | ${(m.precision * 100).toFixed(1)}% | ${(m.recall * 100).toFixed(1)}% | ${(m.f1 * 100).toFixed(1)}% | ${m.total} |`);
      }
      lines.push('');
    }

    // Latency
    if (metrics.latency && metrics.latency.mean > 0) {
      lines.push('## Latency');
      lines.push('');
      lines.push('| Stat | ms |');
      lines.push('|------|-----|');
      lines.push(`| Mean | ${metrics.latency.mean} |`);
      lines.push(`| Median | ${metrics.latency.median} |`);
      lines.push(`| P95 | ${metrics.latency.p95} |`);
      lines.push(`| P99 | ${metrics.latency.p99} |`);
      lines.push('');
    }

    return lines.join('\n');
  }

  /**
   * Generate a comparison table for multiple engines.
   * @param {Object} comparison — output from BenchmarkHarness.compare()
   * @returns {string}
   */
  comparisonText(comparison) {
    const lines = [];
    const sep = '='.repeat(70);

    lines.push(sep);
    lines.push('  Engine Comparison');
    lines.push(sep);
    lines.push('');
    lines.push(`  ${'Engine'.padEnd(20)} ${'Prec'.padStart(7)} ${'Rec'.padStart(7)} ${'F1'.padStart(7)} ${'MCC'.padStart(7)} ${'Lat(ms)'.padStart(8)}`);
    lines.push('  ' + '-'.repeat(56));

    for (const [name, m] of Object.entries(comparison)) {
      const lat = m.latency && m.latency.mean > 0 ? m.latency.mean.toFixed(1) : 'N/A';
      lines.push(`  ${name.padEnd(20)} ${(m.precision * 100).toFixed(1).padStart(6)}% ${(m.recall * 100).toFixed(1).padStart(6)}% ${(m.f1 * 100).toFixed(1).padStart(6)}% ${m.mcc.toFixed(3).padStart(7)} ${lat.padStart(8)}`);
    }

    lines.push('');
    lines.push(sep);
    return lines.join('\n');
  }
}

// =========================================================================
// BenchmarkHarness
// =========================================================================

/**
 * Main benchmark harness for evaluating detection engines.
 *
 * @example
 * const { BenchmarkHarness } = require('./benchmark-harness');
 * const { scanText } = require('./detector-core');
 *
 * const harness = new BenchmarkHarness();
 * harness.loadDataset('datasets/attack-corpus.json');
 * const results = harness.run((text) => {
 *   const result = scanText(text);
 *   return result.threats.length > 0;
 * });
 * console.log(harness.formatReport(results));
 */
class BenchmarkHarness {
  /**
   * @param {Object} [options]
   * @param {number} [options.warmupRuns=1] — number of warmup iterations (not measured)
   */
  constructor(options = {}) {
    /** @private */
    this._entries = [];
    /** @private */
    this._meta = {};
    /** @private */
    this._loader = new DatasetLoader();
    /** @private */
    this._metrics = new BenchmarkMetrics();
    /** @private */
    this._reporter = new BenchmarkReportGenerator();
    /** @private */
    this._warmupRuns = options.warmupRuns || 1;
  }

  /**
   * Load a benchmark dataset from a JSON file.
   * @param {string} filePath — path to the dataset JSON
   * @returns {BenchmarkHarness} this (for chaining)
   */
  loadDataset(filePath) {
    const { entries, meta } = this._loader.load(filePath);
    this._entries = entries;
    this._meta = meta;
    return this;
  }

  /**
   * Load entries directly (must conform to the standard schema).
   * @param {Array<Object>} entries
   * @returns {BenchmarkHarness} this (for chaining)
   */
  loadEntries(entries) {
    this._loader.validate(entries);
    this._entries = entries;
    return this;
  }

  /**
   * Run a detector function against all loaded entries.
   *
   * The detector function receives the text and must return a boolean
   * (true = threat detected, false = no threat).
   *
   * @param {function(string): boolean} detectorFn
   * @returns {{ results: Array<Object>, metrics: Object }}
   */
  run(detectorFn) {
    if (this._entries.length === 0) {
      throw new Error('[Agent Shield] No entries loaded. Call loadDataset() or loadEntries() first.');
    }
    if (typeof detectorFn !== 'function') {
      throw new Error('[Agent Shield] detectorFn must be a function');
    }

    // Warmup runs (not measured)
    for (let w = 0; w < this._warmupRuns; w++) {
      for (const entry of this._entries) {
        detectorFn(entry.text);
      }
    }

    // Measured run
    const results = [];
    for (const entry of this._entries) {
      const start = this._now();
      let detected;
      try {
        detected = Boolean(detectorFn(entry.text));
      } catch (err) {
        detected = false;
      }
      const latencyMs = this._now() - start;

      results.push({
        entry,
        detected,
        expected: entry.expected_detection,
        correct: detected === entry.expected_detection,
        latencyMs
      });
    }

    const metrics = this._metrics.compute(results);
    return { results, metrics };
  }

  /**
   * Compare multiple detector functions side-by-side.
   *
   * @param {Object<string, function(string): boolean>} detectors — name → detectorFn
   * @returns {Object<string, Object>} name → metrics
   */
  compare(detectors) {
    if (!detectors || typeof detectors !== 'object') {
      throw new Error('[Agent Shield] detectors must be an object mapping names to functions');
    }
    const comparison = {};
    for (const [name, fn] of Object.entries(detectors)) {
      const { metrics } = this.run(fn);
      comparison[name] = metrics;
    }
    return comparison;
  }

  /**
   * Generate a human-readable text report from run results.
   * @param {{ results: Array, metrics: Object }} results — output from run()
   * @returns {string}
   */
  formatReport(results) {
    return this._reporter.text(results.metrics, { title: 'Agent Shield Benchmark Report' });
  }

  /**
   * Generate a comparison table from compare() output.
   * @param {Object} comparison — output from compare()
   * @returns {string}
   */
  formatComparison(comparison) {
    return this._reporter.comparisonText(comparison);
  }

  /**
   * Generate a markdown report from run results.
   * @param {{ results: Array, metrics: Object }} results — output from run()
   * @returns {string}
   */
  formatMarkdown(results) {
    return this._reporter.markdown(results.metrics, { title: 'Agent Shield Benchmark Report' });
  }

  /**
   * High-resolution timer.
   * @returns {number}
   * @private
   */
  _now() {
    if (typeof performance !== 'undefined' && performance.now) {
      return performance.now();
    }
    const hr = process.hrtime();
    return hr[0] * 1e3 + hr[1] / 1e6;
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
  BenchmarkHarness,
  DatasetLoader,
  BenchmarkMetrics,
  RegressionTracker,
  BenchmarkReportGenerator
};
