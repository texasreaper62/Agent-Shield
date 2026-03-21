'use strict';

/**
 * Agent Shield — Benchmark Metrics Calculator
 *
 * Computes classification metrics for detection engine evaluation.
 * Includes accuracy, precision, recall, F1, MCC, throughput, and latency.
 *
 * All calculations run locally — no data ever leaves your environment.
 */

// =========================================================================
// METRICS CALCULATOR
// =========================================================================

/**
 * Calculates classification and performance metrics for benchmark results.
 */
class MetricsCalculator {
  /**
   * Calculate full metrics from predictions and ground truth.
   * @param {string[]} predictions - Predicted labels ('attack' or 'benign')
   * @param {string[]} groundTruth - Actual labels ('attack' or 'benign')
   * @returns {Object} Complete metrics object
   */
  calculate(predictions, groundTruth) {
    if (!predictions || !groundTruth || predictions.length !== groundTruth.length) {
      throw new Error('predictions and groundTruth must be arrays of equal length');
    }

    const cm = this.confusionMatrix(predictions, groundTruth);
    const { tp, tn, fp, fn } = cm;

    const acc = this.accuracy(tp, tn, fp, fn);
    const prec = this.precision(tp, fp);
    const rec = this.recall(tp, fn);
    const f1 = this.f1Score(prec, rec);
    const fpr = this.falsePositiveRate(fp, tn);
    const fnr = this.falseNegativeRate(fn, tp);
    const mcc = this.matthewsCorrelation(tp, tn, fp, fn);

    return {
      accuracy: acc,
      precision: prec,
      recall: rec,
      f1,
      falsePositiveRate: fpr,
      falseNegativeRate: fnr,
      mcc,
      confusionMatrix: cm,
      total: predictions.length
    };
  }

  /**
   * Calculate accuracy.
   * @param {number} tp - True positives
   * @param {number} tn - True negatives
   * @param {number} fp - False positives
   * @param {number} fn - False negatives
   * @returns {number} Accuracy [0, 1]
   */
  accuracy(tp, tn, fp, fn) {
    const total = tp + tn + fp + fn;
    return total === 0 ? 0 : (tp + tn) / total;
  }

  /**
   * Calculate precision.
   * @param {number} tp - True positives
   * @param {number} fp - False positives
   * @returns {number} Precision [0, 1]
   */
  precision(tp, fp) {
    return (tp + fp) === 0 ? 0 : tp / (tp + fp);
  }

  /**
   * Calculate recall (sensitivity / true positive rate).
   * @param {number} tp - True positives
   * @param {number} fn - False negatives
   * @returns {number} Recall [0, 1]
   */
  recall(tp, fn) {
    return (tp + fn) === 0 ? 0 : tp / (tp + fn);
  }

  /**
   * Calculate F1 score (harmonic mean of precision and recall).
   * @param {number} prec - Precision
   * @param {number} rec - Recall
   * @returns {number} F1 score [0, 1]
   */
  f1Score(prec, rec) {
    return (prec + rec) === 0 ? 0 : (2 * prec * rec) / (prec + rec);
  }

  /**
   * Calculate false positive rate.
   * @param {number} fp - False positives
   * @param {number} tn - True negatives
   * @returns {number} FPR [0, 1]
   */
  falsePositiveRate(fp, tn) {
    return (fp + tn) === 0 ? 0 : fp / (fp + tn);
  }

  /**
   * Calculate false negative rate.
   * @param {number} fn - False negatives
   * @param {number} tp - True positives
   * @returns {number} FNR [0, 1]
   */
  falseNegativeRate(fn, tp) {
    return (fn + tp) === 0 ? 0 : fn / (fn + tp);
  }

  /**
   * Calculate Matthews Correlation Coefficient (MCC).
   * A balanced measure even if classes are imbalanced.
   * @param {number} tp - True positives
   * @param {number} tn - True negatives
   * @param {number} fp - False positives
   * @param {number} fn - False negatives
   * @returns {number|null} MCC [-1, 1] or null if undefined
   */
  matthewsCorrelation(tp, tn, fp, fn) {
    const denominator = Math.sqrt(
      (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)
    );
    if (denominator === 0) return null;
    return (tp * tn - fp * fn) / denominator;
  }

  /**
   * Calculate throughput.
   * @param {number} count - Number of texts processed
   * @param {number} timeMs - Total time in milliseconds
   * @returns {number} Texts per second
   */
  throughput(count, timeMs) {
    if (timeMs === 0) return Infinity;
    return (count / timeMs) * 1000;
  }

  /**
   * Calculate latency percentiles.
   * @param {number[]} latencies - Array of latency measurements in ms
   * @returns {{ p50: number, p95: number, p99: number, min: number, max: number, mean: number }}
   */
  latencyPercentiles(latencies) {
    if (!latencies || latencies.length === 0) {
      return { p50: 0, p95: 0, p99: 0, min: 0, max: 0, mean: 0 };
    }

    const sorted = [...latencies].sort((a, b) => a - b);
    const len = sorted.length;

    const percentile = (p) => {
      const rank = (p / 100) * (len - 1);
      const lower = Math.floor(rank);
      const upper = Math.ceil(rank);
      if (lower === upper) return sorted[lower];
      // Linear interpolation between adjacent ranks
      const frac = rank - lower;
      return sorted[lower] + frac * (sorted[upper] - sorted[lower]);
    };

    const sum = sorted.reduce((a, b) => a + b, 0);

    return {
      p50: percentile(50),
      p95: percentile(95),
      p99: percentile(99),
      min: sorted[0],
      max: sorted[len - 1],
      mean: sum / len
    };
  }

  /**
   * Build confusion matrix from predictions and ground truth.
   * Positive class = 'attack', Negative class = 'benign'.
   * @param {string[]} predictions - Predicted labels
   * @param {string[]} groundTruth - Actual labels
   * @returns {{ tp: number, tn: number, fp: number, fn: number }}
   */
  confusionMatrix(predictions, groundTruth) {
    let tp = 0, tn = 0, fp = 0, fn = 0;

    for (let i = 0; i < predictions.length; i++) {
      const pred = predictions[i];
      const actual = groundTruth[i];

      if (pred === 'attack' && actual === 'attack') tp++;
      else if (pred === 'benign' && actual === 'benign') tn++;
      else if (pred === 'attack' && actual === 'benign') fp++;
      else if (pred === 'benign' && actual === 'attack') fn++;
    }

    return { tp, tn, fp, fn };
  }
}

module.exports = { MetricsCalculator };
