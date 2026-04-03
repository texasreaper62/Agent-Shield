'use strict';

/**
 * Agent Shield — Multi-Classifier Ensemble (v12.0)
 *
 * Unified ensemble that combines results from multiple detection layers:
 * detector-core (scanText), MicroModel, OWASP scanner, and intent graph.
 * Uses weighted voting with configurable weights, confidence calibration,
 * and produces a final threat/benign verdict with aggregated confidence.
 *
 * All detection runs locally — no data ever leaves your environment.
 *
 * @module ensemble
 */

// =========================================================================
// CONSTANTS
// =========================================================================

/**
 * Default classifier weights. Higher weight = more influence on final verdict.
 * @type {Object<string, number>}
 */
const DEFAULT_WEIGHTS = {
  'detector-core': 1.0,
  'micro-model': 1.2,
  'owasp-scanner': 0.8,
  'intent-graph': 0.9
};

/**
 * Default confidence threshold for threat verdict.
 * @type {number}
 */
const DEFAULT_THRESHOLD = 0.5;

/**
 * Minimum number of classifiers that must agree for high-confidence verdict.
 * @type {number}
 */
const MIN_QUORUM = 2;

/**
 * Calibration parameters for Platt scaling (sigmoid calibration).
 * Tuned on BIPIA/HackAPrompt validation set.
 * @type {Object<string, { a: number, b: number }>}
 */
const CALIBRATION_PARAMS = {
  'detector-core': { a: -2.5, b: 0.8 },
  'micro-model': { a: -3.0, b: 0.5 },
  'owasp-scanner': { a: -2.0, b: 1.0 },
  'intent-graph': { a: -1.8, b: 1.2 }
};

// =========================================================================
// CALIBRATION
// =========================================================================

/**
 * Apply Platt scaling (sigmoid calibration) to a raw score.
 * Maps raw classifier output to a calibrated probability.
 * @param {number} rawScore - Raw classifier score (0..1)
 * @param {number} a - Slope parameter
 * @param {number} b - Intercept parameter
 * @returns {number} Calibrated probability (0..1)
 */
function plattScale(rawScore, a, b) {
  // Sigmoid: P = 1 / (1 + exp(a*score + b))
  const exponent = a * rawScore + b;
  return 1 / (1 + Math.exp(exponent));
}

/**
 * Isotonic regression-style binned calibration (fallback).
 * Maps raw scores through piecewise linear bins.
 * @param {number} rawScore
 * @returns {number}
 */
function binnedCalibration(rawScore) {
  // Simple 5-bin calibration
  const bins = [
    { from: 0.0, to: 0.2, calibrated: 0.05 },
    { from: 0.2, to: 0.4, calibrated: 0.25 },
    { from: 0.4, to: 0.6, calibrated: 0.50 },
    { from: 0.6, to: 0.8, calibrated: 0.75 },
    { from: 0.8, to: 1.0, calibrated: 0.95 }
  ];

  for (const bin of bins) {
    if (rawScore >= bin.from && rawScore < bin.to) {
      // Linear interpolation within bin
      const fraction = (rawScore - bin.from) / (bin.to - bin.from);
      const nextCalibrated = bins[bins.indexOf(bin) + 1]?.calibrated || 1.0;
      return bin.calibrated + fraction * (nextCalibrated - bin.calibrated);
    }
  }
  return rawScore >= 1.0 ? 0.99 : 0.01;
}

// =========================================================================
// CLASSIFIER RESULT
// =========================================================================

/**
 * @typedef {object} ClassifierResult
 * @property {string} classifier - Classifier name
 * @property {boolean} isThreat - Whether classifier detected a threat
 * @property {number} confidence - Raw confidence score (0..1)
 * @property {string} [category] - Threat category if detected
 * @property {string} [severity] - Severity level if detected
 * @property {object} [metadata] - Additional classifier-specific data
 */

/**
 * @typedef {object} EnsembleVerdict
 * @property {'threat'|'benign'} verdict - Final verdict
 * @property {number} confidence - Aggregated calibrated confidence (0..1)
 * @property {number} rawScore - Raw weighted score before calibration
 * @property {ClassifierResult[]} contributors - Results from each classifier
 * @property {string[]} threats - Detected threat categories
 * @property {string} severity - Highest severity across all classifiers
 * @property {number} agreementRatio - Fraction of classifiers agreeing with verdict
 * @property {number} classifiersUsed - Number of classifiers that contributed
 */

// =========================================================================
// DETECTION ENSEMBLE
// =========================================================================

/**
 * Multi-Classifier Detection Ensemble.
 *
 * Combines results from multiple detection layers using weighted voting
 * and confidence calibration to produce a unified verdict.
 *
 * @example
 * const ensemble = new DetectionEnsemble();
 * ensemble.addResult('detector-core', { isThreat: true, confidence: 0.9, category: 'injection' });
 * ensemble.addResult('micro-model', { isThreat: true, confidence: 0.85 });
 * ensemble.addResult('owasp-scanner', { isThreat: false, confidence: 0.3 });
 * const verdict = ensemble.evaluate();
 * // { verdict: 'threat', confidence: 0.82, ... }
 */
class DetectionEnsemble {
  /**
   * @param {object} [options]
   * @param {Object<string, number>} [options.weights] - Classifier weights
   * @param {number} [options.threshold] - Confidence threshold for threat verdict (default 0.5)
   * @param {string} [options.calibrationMode] - 'platt' or 'binned' (default 'platt')
   * @param {boolean} [options.requireQuorum] - Require MIN_QUORUM classifiers agree (default true)
   */
  constructor(options = {}) {
    this.weights = { ...DEFAULT_WEIGHTS, ...(options.weights || {}) };
    this.threshold = options.threshold ?? DEFAULT_THRESHOLD;
    this.calibrationMode = options.calibrationMode || 'platt';
    this.requireQuorum = options.requireQuorum !== false;

    /** @type {ClassifierResult[]} */
    this.results = [];

    /** @type {EnsembleVerdict[]} */
    this._history = [];

    console.log('[Agent Shield] DetectionEnsemble initialized');
  }

  /**
   * Add a classifier result to the ensemble.
   * @param {string} classifier - Classifier name (e.g. 'detector-core', 'micro-model')
   * @param {object} result - Classifier output
   * @param {boolean} result.isThreat - Whether a threat was detected
   * @param {number} result.confidence - Confidence score (0..1)
   * @param {string} [result.category] - Threat category
   * @param {string} [result.severity] - Severity level
   * @param {object} [result.metadata] - Additional data
   */
  addResult(classifier, result) {
    if (!classifier || typeof classifier !== 'string') {
      throw new Error('Classifier name is required');
    }
    if (result === null || result === undefined || typeof result !== 'object') {
      throw new Error('Result object is required');
    }

    const confidence = Math.max(0, Math.min(1, result.confidence || 0));

    this.results.push({
      classifier,
      isThreat: !!result.isThreat,
      confidence,
      category: result.category || null,
      severity: result.severity || null,
      metadata: result.metadata || {}
    });
  }

  /**
   * Add result from detector-core scanText output.
   * @param {object} scanResult - Output from scanText()
   */
  addScanTextResult(scanResult) {
    if (!scanResult) return;

    const isThreat = scanResult.flagged || (scanResult.threats && scanResult.threats.length > 0);
    const confidence = isThreat ? Math.min(1, (scanResult.threats?.length || 1) * 0.3 + 0.4) : 0.1;
    const category = scanResult.threats?.[0]?.category || null;
    const severity = scanResult.threats?.[0]?.severity || null;

    this.addResult('detector-core', { isThreat, confidence, category, severity, metadata: scanResult });
  }

  /**
   * Add result from MicroModel classification.
   * @param {object} modelResult - Output from MicroModel.classify()
   */
  addMicroModelResult(modelResult) {
    if (!modelResult) return;

    const isThreat = modelResult.label === 'malicious' || modelResult.isThreat === true;
    const confidence = modelResult.confidence || modelResult.score || 0;

    this.addResult('micro-model', { isThreat, confidence, metadata: modelResult });
  }

  /**
   * Add result from OWASP Agentic scanner.
   * @param {object} owaspResult - Output from OWASPAgenticScanner
   */
  addOWASPResult(owaspResult) {
    if (!owaspResult) return;

    const findings = owaspResult.findings || owaspResult.risks || [];
    const isThreat = findings.length > 0;
    const confidence = isThreat ? Math.min(1, findings.length * 0.2 + 0.3) : 0.05;
    const severity = findings[0]?.severity || null;

    this.addResult('owasp-scanner', { isThreat, confidence, severity, metadata: owaspResult });
  }

  /**
   * Add result from intent graph analysis.
   * @param {object} intentResult - Output from IntentGraph analysis
   */
  addIntentGraphResult(intentResult) {
    if (!intentResult) return;

    const suspicious = intentResult.suspiciousTransitions || intentResult.suspicious || [];
    const isThreat = suspicious.length > 0 || intentResult.isThreat === true;
    const confidence = intentResult.confidence || (isThreat ? 0.7 : 0.1);

    this.addResult('intent-graph', { isThreat, confidence, metadata: intentResult });
  }

  /**
   * Calibrate a raw confidence score for a given classifier.
   * @param {string} classifier - Classifier name
   * @param {number} rawScore - Raw confidence (0..1)
   * @returns {number} Calibrated probability (0..1)
   */
  calibrate(classifier, rawScore) {
    if (this.calibrationMode === 'platt') {
      const params = CALIBRATION_PARAMS[classifier];
      if (params) {
        return plattScale(rawScore, params.a, params.b);
      }
    }
    return binnedCalibration(rawScore);
  }

  /**
   * Evaluate all added results and produce a final verdict.
   * @returns {EnsembleVerdict}
   */
  evaluate() {
    if (this.results.length === 0) {
      return {
        verdict: 'benign',
        confidence: 0,
        rawScore: 0,
        contributors: [],
        threats: [],
        severity: 'low',
        agreementRatio: 0,
        classifiersUsed: 0
      };
    }

    let weightedThreatSum = 0;
    let weightedBenignSum = 0;
    let totalWeight = 0;
    let threatVoters = 0;
    let benignVoters = 0;
    const threats = new Set();
    const severities = [];

    const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1 };

    for (const result of this.results) {
      const weight = this.weights[result.classifier] ?? 1.0;
      const calibrated = this.calibrate(result.classifier, result.confidence);

      if (result.isThreat) {
        weightedThreatSum += calibrated * weight;
        threatVoters++;
        if (result.category) threats.add(result.category);
        if (result.severity) severities.push(result.severity);
      } else {
        weightedBenignSum += (1 - calibrated) * weight;
        benignVoters++;
      }

      totalWeight += weight;
    }

    // Compute raw weighted score
    const rawScore = totalWeight > 0 ? weightedThreatSum / totalWeight : 0;

    // Determine verdict
    let verdict = rawScore >= this.threshold ? 'threat' : 'benign';

    // Quorum check: if required, need at least MIN_QUORUM classifiers to agree
    if (this.requireQuorum && this.results.length >= MIN_QUORUM) {
      if (verdict === 'threat' && threatVoters < MIN_QUORUM) {
        // Not enough classifiers agree on threat — downgrade to benign
        verdict = 'benign';
      }
    }

    // Compute agreement ratio
    const majority = verdict === 'threat' ? threatVoters : benignVoters;
    const agreementRatio = this.results.length > 0 ? majority / this.results.length : 0;

    // Determine highest severity
    let severity = 'low';
    for (const s of severities) {
      if ((SEVERITY_ORDER[s] || 0) > (SEVERITY_ORDER[severity] || 0)) {
        severity = s;
      }
    }

    // Final confidence: combine raw score with agreement
    const confidence = Math.round(rawScore * 0.7 + agreementRatio * 0.3 * (verdict === 'threat' ? 1 : 0.5) * 1000) / 1000
      || Math.round(rawScore * 1000) / 1000;

    const ensembleVerdict = {
      verdict,
      confidence: Math.min(1, Math.max(0, confidence)),
      rawScore: Math.round(rawScore * 1000) / 1000,
      contributors: [...this.results],
      threats: [...threats],
      severity,
      agreementRatio: Math.round(agreementRatio * 1000) / 1000,
      classifiersUsed: this.results.length
    };

    this._history.push(ensembleVerdict);

    return ensembleVerdict;
  }

  /**
   * Reset the ensemble for a new evaluation round.
   */
  reset() {
    this.results = [];
  }

  /**
   * Update classifier weights.
   * @param {Object<string, number>} newWeights - Partial weight overrides
   */
  updateWeights(newWeights) {
    if (newWeights && typeof newWeights === 'object') {
      Object.assign(this.weights, newWeights);
    }
  }

  /**
   * Get evaluation history.
   * @returns {EnsembleVerdict[]}
   */
  getHistory() {
    return [...this._history];
  }

  /**
   * Get current configuration summary.
   * @returns {object}
   */
  getConfig() {
    return {
      weights: { ...this.weights },
      threshold: this.threshold,
      calibrationMode: this.calibrationMode,
      requireQuorum: this.requireQuorum,
      pendingResults: this.results.length,
      historySize: this._history.length
    };
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
  DetectionEnsemble,
  DEFAULT_WEIGHTS,
  DEFAULT_THRESHOLD,
  MIN_QUORUM,
  CALIBRATION_PARAMS,
  plattScale,
  binnedCalibration
};
