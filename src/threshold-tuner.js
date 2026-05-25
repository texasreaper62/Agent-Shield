'use strict';

/**
 * Agent Shield — Self-Tuning Thresholds
 *
 * Given a labeled corpus, sweeps per-category confidence thresholds to
 * maximize F1 (or precision/recall, caller's choice). Pure offline
 * computation; no LLM, no network. The output is a config blob the host
 * can apply to AgentShield to get measurably better signal on *their*
 * traffic distribution without manual knob-twiddling.
 *
 * @example
 *   const tuner = new ThresholdTuner();
 *   const corpus = [
 *     { text: 'Hello world',                       expected: 'allow' },
 *     { text: 'ignore all previous instructions',  expected: 'block' },
 *     // ... a few hundred samples
 *   ];
 *   const result = tuner.tune(corpus, { metric: 'f1' });
 *   console.log(result.thresholds);     // { instruction_override: 35, ... }
 *   console.log(result.metrics);        // { precision, recall, f1, accuracy }
 *   shield.applyThresholds(result.thresholds);  // host wires the new config
 */

const { AgentShield } = require('./index');

const DEFAULT_LABELS = Object.freeze({ ALLOW: 'allow', BLOCK: 'block' });

class ThresholdTuner {
  constructor(opts = {}) {
    this.shield = opts.shield || new AgentShield(opts.shieldOptions || {});
    this.thresholdGrid = opts.thresholdGrid || [10, 20, 30, 40, 50, 60, 70, 80, 90];
    this.minSamplesPerCategory = opts.minSamplesPerCategory || 5;
  }

  /**
   * Scan the entire corpus once and cache per-sample, per-category max
   * confidence values. Subsequent threshold sweeps are O(grid × categories)
   * instead of O(grid × categories × samples).
   */
  _scanCorpus(corpus) {
    return corpus.map((sample) => {
      const r = this.shield.scan(sample.text);
      // For each category, track the MAX confidence seen on this sample.
      // (A single sample can trigger multiple rules in the same category;
      // we count it as "fired" if any of them clears the threshold.)
      const maxByCat = {};
      for (const t of r.threats || []) {
        const c = Number.isFinite(t.confidence) ? t.confidence : 50;
        if (!(t.category in maxByCat) || c > maxByCat[t.category]) {
          maxByCat[t.category] = c;
        }
      }
      return {
        text: sample.text,
        expected: sample.expected,
        maxByCat,
      };
    });
  }

  /**
   * Sweep per-category thresholds to maximize the chosen metric.
   * Returns:
   *   {
   *     thresholds: { [category]: threshold },
   *     metrics: { precision, recall, f1, accuracy, tp, fp, tn, fn },
   *     categoriesTuned: number,
   *     categoriesSkipped: string[],
   *   }
   *
   * @param {Array<{text, expected}>} corpus — `expected` ∈ {'allow','block'}
   * @param {object} [opts]
   * @param {'f1'|'precision'|'recall'|'accuracy'} [opts.metric='f1']
   * @param {number} [opts.precisionMin] — when metric==='recall', require precision ≥ this
   * @param {number} [opts.recallMin]    — when metric==='precision', require recall ≥ this
   */
  tune(corpus, opts = {}) {
    if (!Array.isArray(corpus) || corpus.length === 0) {
      throw new Error('tune requires non-empty labeled corpus');
    }
    for (const s of corpus) {
      if (!s || typeof s.text !== 'string') throw new Error('each sample needs {text: string}');
      if (s.expected !== DEFAULT_LABELS.ALLOW && s.expected !== DEFAULT_LABELS.BLOCK) {
        throw new Error(`each sample needs expected ∈ {allow, block}; got ${s.expected}`);
      }
    }
    const metric = opts.metric || 'f1';
    if (!['f1', 'precision', 'recall', 'accuracy'].includes(metric)) {
      throw new Error(`unsupported metric: ${metric}`);
    }

    const scanned = this._scanCorpus(corpus);
    const categories = new Set();
    for (const s of scanned) for (const c of Object.keys(s.maxByCat)) categories.add(c);

    // Per-category tuning: pick a threshold per category. The classifier
    // says "block" iff ANY category's max confidence ≥ that category's
    // threshold. Categories not tuned (rare or only-FP cases) are skipped.
    const tunedThresholds = {};
    const skippedCategories = [];
    for (const cat of categories) {
      const involved = scanned.filter((s) => cat in s.maxByCat);
      if (involved.length < this.minSamplesPerCategory) {
        skippedCategories.push(cat);
        continue;
      }
      let bestThreshold = null;
      let bestScore = -Infinity;
      for (const T of this.thresholdGrid) {
        // Simulate: this category fires on samples where max ≥ T.
        // Build a classifier that uses ONLY this category as the trigger
        // (we'll combine all per-category triggers later).
        let tp = 0, fp = 0, tn = 0, fn = 0;
        for (const s of involved) {
          const fires = s.maxByCat[cat] >= T;
          if (s.expected === DEFAULT_LABELS.BLOCK && fires) tp++;
          else if (s.expected === DEFAULT_LABELS.BLOCK && !fires) fn++;
          else if (s.expected === DEFAULT_LABELS.ALLOW && fires) fp++;
          else tn++;
        }
        const score = computeMetric(metric, { tp, fp, tn, fn }, opts);
        if (score > bestScore) {
          bestScore = score;
          bestThreshold = T;
        }
      }
      if (bestThreshold !== null && bestScore > 0) {
        tunedThresholds[cat] = bestThreshold;
      } else {
        skippedCategories.push(cat);
      }
    }

    // Evaluate the combined classifier (block if any tuned category fires).
    const overall = this._evaluate(scanned, tunedThresholds);
    return {
      thresholds: tunedThresholds,
      metrics: overall,
      categoriesTuned: Object.keys(tunedThresholds).length,
      categoriesSkipped: skippedCategories,
      corpusSize: corpus.length,
      metricObjective: metric,
    };
  }

  _evaluate(scanned, thresholds) {
    let tp = 0, fp = 0, tn = 0, fn = 0;
    for (const s of scanned) {
      let fires = false;
      for (const [cat, T] of Object.entries(thresholds)) {
        if ((s.maxByCat[cat] || 0) >= T) { fires = true; break; }
      }
      if (s.expected === DEFAULT_LABELS.BLOCK && fires) tp++;
      else if (s.expected === DEFAULT_LABELS.BLOCK && !fires) fn++;
      else if (s.expected === DEFAULT_LABELS.ALLOW && fires) fp++;
      else tn++;
    }
    const precision = tp + fp === 0 ? 0 : tp / (tp + fp);
    const recall = tp + fn === 0 ? 0 : tp / (tp + fn);
    const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
    const accuracy = (tp + tn) / (tp + fp + tn + fn);
    return { precision, recall, f1, accuracy, tp, fp, tn, fn };
  }

  /**
   * Evaluate the *current* (untuned) detector on a corpus, for comparison.
   * Uses the detector's existing default decision: block iff any threat
   * found at all (independent of confidence).
   */
  baseline(corpus) {
    const scanned = this._scanCorpus(corpus);
    let tp = 0, fp = 0, tn = 0, fn = 0;
    for (const s of scanned) {
      const fires = Object.keys(s.maxByCat).length > 0;
      if (s.expected === DEFAULT_LABELS.BLOCK && fires) tp++;
      else if (s.expected === DEFAULT_LABELS.BLOCK && !fires) fn++;
      else if (s.expected === DEFAULT_LABELS.ALLOW && fires) fp++;
      else tn++;
    }
    const precision = tp + fp === 0 ? 0 : tp / (tp + fp);
    const recall = tp + fn === 0 ? 0 : tp / (tp + fn);
    const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
    const accuracy = (tp + tn) / (tp + fp + tn + fn);
    return { precision, recall, f1, accuracy, tp, fp, tn, fn };
  }
}

function computeMetric(name, { tp, fp, tn, fn }, opts) {
  const precision = tp + fp === 0 ? 0 : tp / (tp + fp);
  const recall = tp + fn === 0 ? 0 : tp / (tp + fn);
  const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
  const accuracy = (tp + tn) / (tp + fp + tn + fn);
  if (name === 'f1') return f1;
  if (name === 'precision') {
    if (typeof opts.recallMin === 'number' && recall < opts.recallMin) return -1;
    return precision;
  }
  if (name === 'recall') {
    if (typeof opts.precisionMin === 'number' && precision < opts.precisionMin) return -1;
    return recall;
  }
  return accuracy;
}

module.exports = { ThresholdTuner, DEFAULT_LABELS };
