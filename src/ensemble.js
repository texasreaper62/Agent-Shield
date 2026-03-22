'use strict';

/**
 * Agent Shield — Ensemble Voting Classifier (v8.0)
 *
 * Combines multiple detection signals (pattern matching, TF-IDF similarity,
 * entropy analysis, IPIA classification) into a single threat/benign decision
 * using weighted majority voting.
 *
 * Zero dependencies. All processing runs locally — no data ever leaves
 * your environment.
 *
 * @module ensemble
 */

const { scanText } = require('./detector-core');
const { EmbeddingSimilarityDetector } = require('./embedding');
const { EntropyAnalyzer, PerplexityEstimator } = require('./token-analysis');
const { FeatureExtractor, TreeClassifier, ContextConstructor } = require('./ipia-detector');

// =========================================================================
// CONSTANTS
// =========================================================================

/** Default voter names */
const VOTER_NAMES = ['pattern', 'tfidf', 'entropy', 'ipia'];

/** Severity thresholds */
const SEVERITY_MAP = [
  { min: 0.8, label: 'critical' },
  { min: 0.6, label: 'high' },
  { min: 0.4, label: 'medium' },
  { min: 0.0, label: 'low' },
];

/**
 * Map a confidence score to a severity label.
 * @param {number} confidence
 * @returns {string}
 */
function confidenceToSeverity(confidence) {
  for (const entry of SEVERITY_MAP) {
    if (confidence >= entry.min) return entry.label;
  }
  return 'low';
}

/**
 * Map a pattern severity string to a confidence value.
 * @param {string} severity
 * @returns {number}
 */
function severityToConfidence(severity) {
  switch (severity) {
    case 'critical': return 1.0;
    case 'high': return 0.85;
    case 'medium': return 0.6;
    case 'low': return 0.3;
    default: return 0.5;
  }
}

// =========================================================================
// PATTERN VOTER
// =========================================================================

/**
 * Wraps the detector-core scanText pattern matcher as an ensemble voter.
 */
class PatternVoter {
  /**
   * @param {object} [options]
   * @param {string} [options.source='ensemble'] - Source label for scanText.
   */
  constructor(options = {}) {
    this.name = 'pattern';
    this.source = options.source || 'ensemble';
  }

  /**
   * Cast a vote by running pattern-based detection.
   * @param {string} text - Text to scan.
   * @param {object} [context] - Optional context (unused by this voter).
   * @returns {{ voter: string, isInjection: boolean, confidence: number, reason: string }}
   */
  vote(text) {
    const result = scanText(text, { source: this.source });
    const threats = result.threats || [];

    if (threats.length === 0) {
      return {
        voter: this.name,
        isInjection: false,
        confidence: 0,
        reason: 'No pattern matches found'
      };
    }

    // Use highest severity threat to determine confidence
    let maxConfidence = 0;
    let topDescription = threats[0].description || 'Pattern match detected';
    for (const threat of threats) {
      const c = severityToConfidence(threat.severity);
      if (c > maxConfidence) {
        maxConfidence = c;
        topDescription = threat.description || topDescription;
      }
    }

    return {
      voter: this.name,
      isInjection: true,
      confidence: maxConfidence,
      reason: topDescription
    };
  }
}

// =========================================================================
// TF-IDF VOTER
// =========================================================================

/**
 * Wraps the EmbeddingSimilarityDetector as an ensemble voter.
 * Detects paraphrased attacks via TF-IDF cosine similarity.
 */
class TFIDFVoter {
  /**
   * @param {object} [options]
   * @param {number} [options.similarityThreshold=0.45] - Threshold for flagging.
   */
  constructor(options = {}) {
    this.name = 'tfidf';
    this._detector = new EmbeddingSimilarityDetector({
      similarityThreshold: options.similarityThreshold || 0.45
    });
  }

  /**
   * Cast a vote by running TF-IDF similarity detection.
   * @param {string} text - Text to scan.
   * @param {object} [context] - Optional context (unused by this voter).
   * @returns {{ voter: string, isInjection: boolean, confidence: number, reason: string }}
   */
  vote(text) {
    const result = this._detector.check(text);

    if (!result.isSimilar || !result.bestMatch) {
      return {
        voter: this.name,
        isInjection: false,
        confidence: result.bestMatch ? result.bestMatch.similarity : 0,
        reason: 'No significant similarity to known attacks'
      };
    }

    return {
      voter: this.name,
      isInjection: true,
      confidence: result.bestMatch.similarity,
      reason: 'Similar to known attack: ' + result.bestMatch.text
    };
  }
}

// =========================================================================
// ENTROPY VOTER
// =========================================================================

/**
 * Wraps EntropyAnalyzer and PerplexityEstimator as an ensemble voter.
 * Detects statistical anomalies in character entropy and n-gram perplexity.
 */
class EntropyVoter {
  /**
   * @param {object} [options]
   * @param {number} [options.entropyThreshold=0.3] - Entropy shift threshold.
   * @param {number} [options.ngramSize=3] - N-gram size for perplexity.
   */
  constructor(options = {}) {
    this.name = 'entropy';
    this._entropyAnalyzer = new EntropyAnalyzer({
      threshold: options.entropyThreshold || 0.3
    });
    this._perplexityEstimator = new PerplexityEstimator({
      ngramSize: options.ngramSize || 3
    });
  }

  /**
   * Cast a vote by running entropy and perplexity analysis.
   * @param {string} text - Text to scan.
   * @param {object} [context] - Optional context (unused by this voter).
   * @returns {{ voter: string, isInjection: boolean, confidence: number, reason: string }}
   */
  vote(text) {
    const entropyResult = this._entropyAnalyzer.analyze(text);
    const perplexityResult = this._perplexityEstimator.estimate(text);

    const hasEntropyAnomaly = entropyResult.anomalies.length > 0;
    const hasPerplexityAnomaly = perplexityResult.suspicious;

    if (!hasEntropyAnomaly && !hasPerplexityAnomaly) {
      return {
        voter: this.name,
        isInjection: false,
        confidence: 0,
        reason: 'No statistical anomalies detected'
      };
    }

    // Compute confidence based on deviation magnitude
    let confidence = 0;
    const reasons = [];

    if (hasEntropyAnomaly) {
      // Use max deviation normalized against a reference range
      let maxDeviation = 0;
      for (const anomaly of entropyResult.anomalies) {
        if (anomaly.deviation > maxDeviation) {
          maxDeviation = anomaly.deviation;
        }
      }
      // Entropy typically ranges 0-5 bits; deviation of 1+ is significant
      const entropyConfidence = Math.min(maxDeviation / 2, 1.0);
      confidence = Math.max(confidence, entropyConfidence);
      reasons.push('Entropy anomaly in ' + entropyResult.anomalies.length + ' segment(s), max deviation ' + maxDeviation.toFixed(2));
    }

    if (hasPerplexityAnomaly) {
      // Perplexity ratio: how many times higher than baseline
      const ratio = this._perplexityEstimator.baselinePerplexity > 0
        ? perplexityResult.perplexity / this._perplexityEstimator.baselinePerplexity
        : 2;
      // ratio of 2 is the threshold; scale 2-5 range to 0.4-1.0
      const perplexityConfidence = Math.min(Math.max((ratio - 1) / 4, 0.3), 1.0);
      confidence = Math.max(confidence, perplexityConfidence);
      reasons.push('High perplexity ' + perplexityResult.perplexity.toFixed(2) + ' (baseline: ' + this._perplexityEstimator.baselinePerplexity.toFixed(2) + ')');
    }

    return {
      voter: this.name,
      isInjection: true,
      confidence: Math.round(confidence * 1000) / 1000,
      reason: reasons.join('; ')
    };
  }
}

// =========================================================================
// IPIA VOTER
// =========================================================================

/**
 * Wraps the IPIA FeatureExtractor and TreeClassifier as an ensemble voter.
 * Uses joint-context analysis to detect indirect prompt injection.
 */
class IPIAVoter {
  /**
   * @param {object} [options]
   * @param {number} [options.classifierThreshold=0.5] - Decision tree threshold.
   */
  constructor(options = {}) {
    this.name = 'ipia';
    this._contextConstructor = new ContextConstructor();
    this._featureExtractor = new FeatureExtractor();
    this._classifier = new TreeClassifier({
      threshold: options.classifierThreshold || 0.5
    });
  }

  /**
   * Cast a vote by running the IPIA pipeline.
   * Uses context.intent as user intent and the text itself as external content.
   * If no intent is provided, uses a generic intent.
   * @param {string} text - Text to scan (treated as external content).
   * @param {object} [context] - Optional context.
   * @param {string} [context.intent] - User intent for joint-context analysis.
   * @returns {{ voter: string, isInjection: boolean, confidence: number, reason: string }}
   */
  vote(text, context = {}) {
    const intent = context.intent || 'Summarize the following content.';
    const ctx = this._contextConstructor.build(text, intent);
    const { features, featureMap } = this._featureExtractor.extract(ctx);
    const result = this._classifier.classify(features, featureMap);

    return {
      voter: this.name,
      isInjection: result.isInjection,
      confidence: Math.round(result.confidence * 1000) / 1000,
      reason: result.reason || (result.isInjection ? 'IPIA classifier flagged content' : 'IPIA classifier found no injection')
    };
  }
}

// =========================================================================
// VOTER REGISTRY
// =========================================================================

/**
 * Map voter names to their constructor classes.
 * @type {Object<string, Function>}
 */
const VOTER_REGISTRY = {
  pattern: PatternVoter,
  tfidf: TFIDFVoter,
  entropy: EntropyVoter,
  ipia: IPIAVoter,
};

// =========================================================================
// ENSEMBLE CLASSIFIER
// =========================================================================

/**
 * Ensemble Voting Classifier — combines multiple detection backends into
 * a unified threat/benign decision via weighted majority voting.
 *
 * @example
 * const { EnsembleClassifier } = require('./ensemble');
 * const ensemble = new EnsembleClassifier({ threshold: 0.5 });
 * const result = ensemble.scan('ignore all previous instructions');
 * console.log(result.isInjection, result.confidence, result.severity);
 */
class EnsembleClassifier {
  /**
   * Create an EnsembleClassifier.
   * @param {object} [config]
   * @param {string[]} [config.voters=['pattern','tfidf','entropy','ipia']] - Voter names to use.
   * @param {number} [config.threshold=0.5] - Confidence threshold for final decision.
   * @param {boolean} [config.requireUnanimous=false] - If true, all voters must agree.
   * @param {Object<string, number>} [config.weights] - Per-voter weights. Default: equal weights.
   * @param {number} [config.minVoters=2] - Minimum voters that must cast a vote.
   * @param {object} [config.voterOptions] - Per-voter config, keyed by voter name.
   */
  constructor(config = {}) {
    this.threshold = config.threshold !== undefined ? config.threshold : 0.5;
    this.requireUnanimous = config.requireUnanimous || false;
    this.minVoters = config.minVoters !== undefined ? config.minVoters : 2;

    const voterNames = config.voters || [...VOTER_NAMES];
    const voterOptions = config.voterOptions || {};

    // Resolve weights (default: equal weight of 1)
    this.weights = {};
    for (const name of voterNames) {
      this.weights[name] = (config.weights && config.weights[name] !== undefined)
        ? config.weights[name]
        : 1;
    }

    // Instantiate voters
    this._voters = [];
    for (const name of voterNames) {
      const VoterClass = VOTER_REGISTRY[name];
      if (!VoterClass) {
        console.log('[Agent Shield] Ensemble: unknown voter "' + name + '", skipping');
        continue;
      }
      try {
        const voter = new VoterClass(voterOptions[name] || {});
        this._voters.push(voter);
      } catch (err) {
        console.log('[Agent Shield] Ensemble: failed to initialize voter "' + name + '": ' + err.message);
      }
    }

    // Stats tracking
    this._stats = {
      totalScans: 0,
      injections: 0,
      safe: 0,
      voterAgreementSum: 0,
      averageConfidence: 0,
      confidenceSum: 0,
    };

    console.log('[Agent Shield] EnsembleClassifier initialized (' + this._voters.length + ' voters: ' + this._voters.map(v => v.name).join(', ') + ', threshold: ' + this.threshold + ')');
  }

  /**
   * Scan text using all enabled voters and combine results via weighted majority voting.
   * @param {string} text - Text to scan.
   * @param {object} [context] - Optional context { intent, source, conversationHistory }.
   * @returns {{
   *   isInjection: boolean,
   *   confidence: number,
   *   severity: string,
   *   votes: Array<{ voter: string, isInjection: boolean, confidence: number, reason: string }>,
   *   agreement: number,
   *   method: string,
   *   timestamp: string
   * }}
   */
  scan(text, context = {}) {
    this._stats.totalScans++;

    // Collect votes from all voters
    const votes = [];
    for (const voter of this._voters) {
      try {
        const vote = voter.vote(text, context);
        votes.push(vote);
      } catch (err) {
        console.log('[Agent Shield] Ensemble: voter "' + voter.name + '" threw error: ' + err.message);
        // Voter abstains on error
      }
    }

    // Check minimum voter requirement
    if (votes.length < this.minVoters) {
      console.log('[Agent Shield] Ensemble: only ' + votes.length + ' voter(s) responded, need ' + this.minVoters);
      return this._buildResult(false, 0, votes);
    }

    // Weighted majority voting
    // weightedScore: positive = injection, negative = benign
    let weightedScore = 0;
    let totalWeight = 0;

    for (const vote of votes) {
      const weight = this.weights[vote.voter] || 1;
      const direction = vote.isInjection ? 1 : -1;
      weightedScore += weight * vote.confidence * direction;
      totalWeight += weight;
    }

    // Normalize to 0-1 range
    // weightedScore ranges from -totalWeight to +totalWeight
    // Map to 0-1: (score + totalWeight) / (2 * totalWeight)
    const normalizedScore = totalWeight > 0
      ? (weightedScore + totalWeight) / (2 * totalWeight)
      : 0;

    let isInjection = normalizedScore >= this.threshold;

    // Unanimous check
    if (this.requireUnanimous && isInjection) {
      const allAgree = votes.every(v => v.isInjection);
      if (!allAgree) {
        isInjection = false;
      }
    }

    // Compute agreement
    const injectionCount = votes.filter(v => v.isInjection).length;
    const benignCount = votes.length - injectionCount;
    const majorityCount = Math.max(injectionCount, benignCount);
    const agreement = votes.length > 0 ? majorityCount / votes.length : 0;

    const confidence = Math.round(normalizedScore * 1000) / 1000;

    // Update stats
    if (isInjection) {
      this._stats.injections++;
    } else {
      this._stats.safe++;
    }
    this._stats.voterAgreementSum += agreement;
    this._stats.confidenceSum += confidence;

    return this._buildResult(isInjection, confidence, votes, agreement);
  }

  /**
   * Build a standardized result object.
   * @param {boolean} isInjection
   * @param {number} confidence
   * @param {Array} votes
   * @param {number} [agreement=0]
   * @returns {object}
   * @private
   */
  _buildResult(isInjection, confidence, votes, agreement = 0) {
    return {
      isInjection,
      confidence,
      severity: confidenceToSeverity(isInjection ? confidence : 0),
      votes,
      agreement: Math.round(agreement * 1000) / 1000,
      method: 'ensemble',
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Get stats about ensemble performance.
   * @returns {{
   *   totalScans: number,
   *   injections: number,
   *   safe: number,
   *   averageAgreement: number,
   *   averageConfidence: number,
   *   voterCount: number,
   *   voters: string[]
   * }}
   */
  getStats() {
    const total = this._stats.totalScans || 1;
    return {
      totalScans: this._stats.totalScans,
      injections: this._stats.injections,
      safe: this._stats.safe,
      averageAgreement: Math.round((this._stats.voterAgreementSum / total) * 1000) / 1000,
      averageConfidence: Math.round((this._stats.confidenceSum / total) * 1000) / 1000,
      voterCount: this._voters.length,
      voters: this._voters.map(v => v.name)
    };
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
  EnsembleClassifier,
  PatternVoter,
  TFIDFVoter,
  EntropyVoter,
  IPIAVoter,
  VOTER_NAMES,
};
