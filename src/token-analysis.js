'use strict';

/**
 * Agent Shield — Token-Level Analysis Module
 *
 * Detects prompt injection through statistical analysis of text.
 * Uses Shannon entropy, character n-gram perplexity estimation,
 * and vocabulary burst detection to identify injected content.
 *
 * All computation is pure JavaScript — no external dependencies.
 * No data ever leaves the user's environment.
 */

// =========================================================================
// TEXT STATISTICS (utility class)
// =========================================================================

/**
 * Utility class for computing text statistics.
 * All methods are static and operate on raw strings.
 */
class TextStatistics {
  /**
   * Compute Shannon entropy of the character distribution in text.
   * H = -sum(p * log2(p)) for each character frequency p.
   * @param {string} text - Input text
   * @returns {number} Shannon entropy in bits
   */
  static charEntropy(text) {
    if (!text || text.length === 0) return 0;

    const freq = {};
    for (let i = 0; i < text.length; i++) {
      const ch = text[i];
      freq[ch] = (freq[ch] || 0) + 1;
    }

    const len = text.length;
    let entropy = 0;
    const keys = Object.keys(freq);
    for (let i = 0; i < keys.length; i++) {
      const p = freq[keys[i]] / len;
      if (p > 0) {
        entropy -= p * Math.log2(p);
      }
    }

    return entropy;
  }

  /**
   * Build a word frequency map from text.
   * @param {string} text - Input text
   * @returns {Object<string, number>} Map of word to count
   */
  static wordFrequency(text) {
    if (!text || text.length === 0) return {};

    const words = text.toLowerCase().match(/[a-z'-]+/g);
    if (!words) return {};

    const freq = {};
    for (let i = 0; i < words.length; i++) {
      const w = words[i];
      freq[w] = (freq[w] || 0) + 1;
    }
    return freq;
  }

  /**
   * Compute vocabulary richness as the type-token ratio.
   * TTR = unique words / total words.
   * @param {string} text - Input text
   * @returns {number} Type-token ratio between 0 and 1
   */
  static vocabularyRichness(text) {
    if (!text || text.length === 0) return 0;

    const words = text.toLowerCase().match(/[a-z'-]+/g);
    if (!words || words.length === 0) return 0;

    const unique = new Set(words);
    return unique.size / words.length;
  }

  /**
   * Compute the average word length.
   * @param {string} text - Input text
   * @returns {number} Mean word length in characters
   */
  static averageWordLength(text) {
    if (!text || text.length === 0) return 0;

    const words = text.match(/[a-zA-Z'-]+/g);
    if (!words || words.length === 0) return 0;

    let total = 0;
    for (let i = 0; i < words.length; i++) {
      total += words[i].length;
    }
    return total / words.length;
  }

  /**
   * Compute sentence complexity as average words per sentence.
   * @param {string} text - Input text
   * @returns {number} Average number of words per sentence
   */
  static sentenceComplexity(text) {
    if (!text || text.length === 0) return 0;

    const sentences = text.split(/[.!?]+/).filter(s => s.trim().length > 0);
    if (sentences.length === 0) return 0;

    let totalWords = 0;
    for (let i = 0; i < sentences.length; i++) {
      const words = sentences[i].trim().match(/\S+/g);
      if (words) {
        totalWords += words.length;
      }
    }
    return totalWords / sentences.length;
  }
}

// =========================================================================
// ENTROPY ANALYZER
// =========================================================================

/**
 * Detects prompt injection via Shannon entropy shifts across text segments.
 * Injected instructions often have markedly different entropy than natural
 * conversational text, creating detectable anomalies.
 */
class EntropyAnalyzer {
  /**
   * Create an EntropyAnalyzer.
   * @param {Object} [options] - Configuration options
   * @param {number} [options.threshold=0.3] - Entropy shift threshold for flagging anomalies
   * @param {number} [options.windowSize=200] - Segment size in characters
   */
  constructor(options = {}) {
    this.threshold = options.threshold !== undefined ? options.threshold : 0.3;
    this.windowSize = options.windowSize !== undefined ? options.windowSize : 200;
  }

  /**
   * Analyze text for entropy-based anomalies.
   * Splits text into segments, computes per-segment entropy, and flags
   * segments that deviate significantly from the overall average.
   * @param {string} text - Input text to analyze
   * @returns {{entropy: number, segments: Array<{text: string, entropy: number, suspicious: boolean}>, anomalies: Array<{text: string, entropy: number, deviation: number, position: number}>}}
   */
  analyze(text) {
    if (!text || text.length === 0) {
      return { entropy: 0, segments: [], anomalies: [] };
    }

    const overallEntropy = TextStatistics.charEntropy(text);

    // Split text into segments of windowSize characters
    const segments = [];
    for (let i = 0; i < text.length; i += this.windowSize) {
      const segText = text.slice(i, i + this.windowSize);
      const segEntropy = TextStatistics.charEntropy(segText);
      segments.push({
        text: segText,
        entropy: segEntropy,
        suspicious: false
      });
    }

    // Compute average segment entropy
    let entropySum = 0;
    for (let i = 0; i < segments.length; i++) {
      entropySum += segments[i].entropy;
    }
    const avgEntropy = segments.length > 0 ? entropySum / segments.length : 0;

    // Flag segments where entropy deviates beyond threshold
    const anomalies = [];
    for (let i = 0; i < segments.length; i++) {
      const deviation = Math.abs(segments[i].entropy - avgEntropy);
      if (deviation > this.threshold) {
        segments[i].suspicious = true;
        anomalies.push({
          text: segments[i].text,
          entropy: segments[i].entropy,
          deviation: deviation,
          position: i * this.windowSize
        });
      }
    }

    if (anomalies.length > 0) {
      console.log('[Agent Shield] Entropy anomalies detected: ' + anomalies.length + ' segment(s) flagged');
    }

    return {
      entropy: overallEntropy,
      segments: segments,
      anomalies: anomalies
    };
  }
}

// =========================================================================
// PERPLEXITY ESTIMATOR
// =========================================================================

/**
 * Built-in English baseline corpus for bootstrapping the n-gram model.
 * Common words and phrases that represent normal English text.
 */
const ENGLISH_BASELINE = [
  'the quick brown fox jumps over the lazy dog',
  'to be or not to be that is the question',
  'I would like to help you with your request today',
  'please let me know if you have any questions about this',
  'thank you for your patience and understanding',
  'the weather is nice today and I hope you are doing well',
  'can you please provide more information about your issue',
  'I am happy to assist you with anything you need',
  'this is a common question and here is the answer',
  'we appreciate your feedback and will work to improve',
  'hello how are you doing today I hope everything is going well',
  'the project is progressing smoothly and we are on schedule',
  'please review the following document and provide your comments',
  'I understand your concern and will look into this matter',
  'the meeting has been scheduled for next week at the usual time'
];

/**
 * Estimates text perplexity using character n-gram frequency models.
 * High perplexity relative to a trained baseline suggests the text
 * deviates from normal patterns, indicating potential injection.
 */
class PerplexityEstimator {
  /**
   * Create a PerplexityEstimator.
   * @param {Object} [options] - Configuration options
   * @param {number} [options.ngramSize=3] - Character n-gram size
   */
  constructor(options = {}) {
    this.ngramSize = options.ngramSize !== undefined ? options.ngramSize : 3;
    this.ngramCounts = {};
    this.totalNgrams = 0;
    this.trained = false;
    this.baselinePerplexity = 0;

    // Automatically train on the built-in English baseline
    this.train(ENGLISH_BASELINE);
  }

  /**
   * Build an n-gram frequency model from an array of normal texts.
   * Subsequent calls to train() will add to the existing model.
   * @param {string[]} corpusTexts - Array of normal/clean text samples
   */
  train(corpusTexts) {
    if (!corpusTexts || corpusTexts.length === 0) return;

    for (let t = 0; t < corpusTexts.length; t++) {
      const text = corpusTexts[t].toLowerCase();
      const maxI = Math.max(-1, text.length - this.ngramSize);
      for (let i = 0; i <= maxI; i++) {
        const ngram = text.slice(i, i + this.ngramSize);
        this.ngramCounts[ngram] = (this.ngramCounts[ngram] || 0) + 1;
        this.totalNgrams++;
      }
    }

    this.trained = true;

    // Compute baseline perplexity from the training corpus
    let totalPerplexity = 0;
    for (let t = 0; t < corpusTexts.length; t++) {
      totalPerplexity += this._computePerplexity(corpusTexts[t]);
    }
    this.baselinePerplexity = totalPerplexity / corpusTexts.length;

    console.log('[Agent Shield] Perplexity model trained: ' + this.totalNgrams + ' n-grams, baseline perplexity=' + this.baselinePerplexity.toFixed(2));
  }

  /**
   * Compute raw perplexity for a given text using the trained model.
   * @param {string} text - Input text
   * @returns {number} Perplexity score
   * @private
   */
  _computePerplexity(text) {
    if (!text || text.length < this.ngramSize) return 0;

    const lowered = text.toLowerCase();
    const ngramCount = lowered.length - this.ngramSize + 1;
    if (ngramCount <= 0) return 0;

    let logProbSum = 0;
    const vocabSize = Object.keys(this.ngramCounts).length;

    for (let i = 0; i <= lowered.length - this.ngramSize; i++) {
      const ngram = lowered.slice(i, i + this.ngramSize);
      // Laplace smoothing: add 1 to avoid zero probabilities
      const count = (this.ngramCounts[ngram] || 0) + 1;
      const prob = count / (this.totalNgrams + vocabSize);
      logProbSum += Math.log2(prob);
    }

    const avgLogProb = logProbSum / ngramCount;
    // Perplexity = 2^(-avg log2 probability)
    return Math.pow(2, -avgLogProb);
  }

  /**
   * Estimate whether text is suspicious based on its perplexity.
   * @param {string} text - Input text to evaluate
   * @returns {{perplexity: number, suspicious: boolean}}
   */
  estimate(text) {
    if (!this.trained) {
      console.log('[Agent Shield] Perplexity estimator not trained, returning neutral result');
      return { perplexity: 0, suspicious: false };
    }

    const perplexity = this._computePerplexity(text);

    // Text is suspicious if its perplexity is significantly higher
    // than the baseline (more than 2x the baseline)
    const suspicious = perplexity > this.baselinePerplexity * 2;

    if (suspicious) {
      console.log('[Agent Shield] High perplexity detected: ' + perplexity.toFixed(2) + ' (baseline: ' + this.baselinePerplexity.toFixed(2) + ')');
    }

    return {
      perplexity: perplexity,
      suspicious: suspicious
    };
  }
}

// =========================================================================
// BURST DETECTOR
// =========================================================================

/**
 * Detects sudden topic or style shifts in text using vocabulary overlap
 * between sliding windows. Injection payloads often introduce a burst of
 * new terminology that diverges sharply from surrounding content.
 */
class BurstDetector {
  /**
   * Create a BurstDetector.
   * @param {Object} [options] - Configuration options
   * @param {number} [options.sensitivity=0.5] - Detection sensitivity (0 to 1). Higher = more sensitive.
   */
  constructor(options = {}) {
    this.sensitivity = options.sensitivity !== undefined ? options.sensitivity : 0.5;
  }

  /**
   * Extract words from text as a set for vocabulary comparison.
   * @param {string} text - Input text
   * @returns {Set<string>} Set of lowercase words
   * @private
   */
  _wordSet(text) {
    const words = text.toLowerCase().match(/[a-z'-]+/g);
    return new Set(words || []);
  }

  /**
   * Compute Jaccard similarity between two sets.
   * J(A, B) = |A ∩ B| / |A ∪ B|
   * @param {Set<string>} setA
   * @param {Set<string>} setB
   * @returns {number} Similarity between 0 and 1
   * @private
   */
  _jaccardSimilarity(setA, setB) {
    if (setA.size === 0 && setB.size === 0) return 1;

    let intersection = 0;
    for (const item of setA) {
      if (setB.has(item)) intersection++;
    }

    const union = setA.size + setB.size - intersection;
    return union === 0 ? 1 : intersection / union;
  }

  /**
   * Analyze text for vocabulary bursts indicating style/topic shifts.
   * Uses sliding windows with vocabulary overlap measurement.
   * @param {string} text - Input text to analyze
   * @returns {{bursts: Array<{position: number, before: string, after: string, score: number}>, suspicious: boolean}}
   */
  analyze(text) {
    if (!text || text.length === 0) {
      return { bursts: [], suspicious: false };
    }

    // Split into sentences for natural boundary detection
    const sentences = text.split(/(?<=[.!?\n])\s+/).filter(s => s.trim().length > 0);

    if (sentences.length < 2) {
      return { bursts: [], suspicious: false };
    }

    // Use a sliding window of sentences to detect vocabulary shifts
    const windowSize = Math.max(1, Math.floor(sentences.length / 4));
    const bursts = [];
    // Threshold: lower sensitivity means we need a bigger vocabulary gap
    const threshold = 1 - this.sensitivity;

    for (let i = windowSize; i < sentences.length; i++) {
      const beforeText = sentences.slice(Math.max(0, i - windowSize), i).join(' ');
      const afterText = sentences.slice(i, Math.min(sentences.length, i + windowSize)).join(' ');

      const beforeWords = this._wordSet(beforeText);
      const afterWords = this._wordSet(afterText);

      // Skip if either window has too few words
      if (beforeWords.size < 3 || afterWords.size < 3) continue;

      const similarity = this._jaccardSimilarity(beforeWords, afterWords);
      const burstScore = 1 - similarity;

      if (burstScore > threshold) {
        // Compute character position
        let position = 0;
        for (let j = 0; j < i; j++) {
          position += sentences[j].length + 1;
        }

        bursts.push({
          position: position,
          before: beforeText.slice(-100),
          after: afterText.slice(0, 100),
          score: burstScore
        });
      }
    }

    const suspicious = bursts.length > 0;

    if (suspicious) {
      console.log('[Agent Shield] Vocabulary burst detected: ' + bursts.length + ' transition(s) flagged');
    }

    return {
      bursts: bursts,
      suspicious: suspicious
    };
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
  EntropyAnalyzer,
  PerplexityEstimator,
  BurstDetector,
  TextStatistics
};
