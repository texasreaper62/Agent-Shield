'use strict';

/**
 * Agent Shield Pro — Enterprise Custom Model Training
 *
 * Wraps the core model-finetuning module with Pro-specific features:
 * - One-call training from scan history
 * - Automatic dataset management
 * - Model versioning and rollback
 * - A/B testing between models
 * - Training metrics and reporting
 *
 * Enterprise tier only.
 *
 * @module model-training
 */

// =========================================================================
// Tokenizer & Feature Extraction (self-contained, no external deps)
// =========================================================================

/**
 * Tokenize text into lowercase word tokens.
 * @param {string} text
 * @returns {string[]}
 */
function tokenize(text) {
  return text.toLowerCase().replace(/[^a-z0-9\s]/g, ' ').split(/\s+/).filter(t => t.length > 1);
}

/**
 * Build vocabulary from a corpus of texts.
 * @param {string[]} texts
 * @param {number} [maxTerms=200]
 * @returns {string[]}
 */
function buildVocabulary(texts, maxTerms = 200) {
  const df = {};
  for (const text of texts) {
    const unique = new Set(tokenize(text));
    for (const term of unique) {
      df[term] = (df[term] || 0) + 1;
    }
  }

  // Filter: must appear in at least 2 docs, not in >80% of docs
  const n = texts.length;
  const filtered = Object.entries(df)
    .filter(([, count]) => count >= 2 && count <= n * 0.8)
    .sort((a, b) => b[1] - a[1])
    .map(([term]) => term);

  return filtered.slice(0, maxTerms);
}

/**
 * Extract TF-IDF feature vector for text against a vocabulary.
 * @param {string} text
 * @param {string[]} vocabulary
 * @returns {number[]}
 */
function extractFeatures(text, vocabulary) {
  const tokens = tokenize(text);
  const tf = {};
  for (const t of tokens) tf[t] = (tf[t] || 0) + 1;
  const total = tokens.length || 1;

  const features = new Array(vocabulary.length + 1).fill(0);
  for (let i = 0; i < vocabulary.length; i++) {
    if (tf[vocabulary[i]]) {
      features[i] = tf[vocabulary[i]] / total;
    }
  }
  features[vocabulary.length] = 1; // bias
  return features;
}

function sigmoid(z) {
  if (z > 500) return 1;
  if (z < -500) return 0;
  return 1 / (1 + Math.exp(-z));
}

function dot(a, b) {
  let sum = 0;
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) sum += a[i] * b[i];
  return sum;
}


// =========================================================================
// TrainedModel
// =========================================================================

/**
 * A trained binary classifier (logistic regression on TF-IDF features).
 */
class TrainedModel {
  /**
   * @param {number[]} weights
   * @param {string[]} vocabulary
   * @param {Object} metadata
   */
  constructor(weights, vocabulary, metadata = {}) {
    this.weights = weights;
    this.vocabulary = vocabulary;
    this.metadata = metadata;
    this.createdAt = new Date().toISOString();
  }

  /**
   * Predict whether text is an attack.
   * @param {string} text
   * @returns {{ label: string, confidence: number }}
   */
  predict(text) {
    const features = extractFeatures(text, this.vocabulary);
    const z = dot(features, this.weights);
    const prob = sigmoid(z);
    return {
      label: prob >= 0.5 ? 'attack' : 'benign',
      confidence: prob >= 0.5 ? prob : 1 - prob,
    };
  }

  /**
   * Batch predict.
   * @param {string[]} texts
   * @returns {Array<{label: string, confidence: number}>}
   */
  predictBatch(texts) {
    return texts.map(t => this.predict(t));
  }

  /**
   * Export model to JSON.
   * @returns {Object}
   */
  export() {
    return {
      type: 'agent-shield-trained-model',
      version: '1.0',
      weights: this.weights,
      vocabulary: this.vocabulary,
      metadata: this.metadata,
      createdAt: this.createdAt,
    };
  }

  /**
   * Load model from JSON.
   * @param {Object} json
   * @returns {TrainedModel}
   */
  static load(json) {
    if (!json || json.type !== 'agent-shield-trained-model') {
      throw new Error('[Agent Shield] Invalid model format');
    }
    const model = new TrainedModel(json.weights, json.vocabulary, json.metadata);
    model.createdAt = json.createdAt;
    return model;
  }
}


// =========================================================================
// ModelTrainingPipeline
// =========================================================================

/**
 * Enterprise model training pipeline.
 * Train org-specific detection models from scan history.
 */
class ModelTrainingPipeline {
  /**
   * @param {Object} [options]
   * @param {number} [options.epochs=50] - Training epochs
   * @param {number} [options.learningRate=0.1] - Learning rate
   * @param {number} [options.vocabSize=200] - Max vocabulary terms
   * @param {number} [options.testSplit=0.2] - Fraction held out for evaluation
   * @param {number} [options.maxModels=10] - Max model versions to retain
   */
  constructor(options = {}) {
    this.epochs = options.epochs || 50;
    this.learningRate = options.learningRate || 0.1;
    this.vocabSize = options.vocabSize || 200;
    this.testSplit = options.testSplit || 0.2;
    this.maxModels = options.maxModels || 10;

    /** @private */
    this._samples = [];
    /** @private */
    this._models = [];   // version history
    /** @private */
    this._activeModel = null;
    /** @private */
    this._stats = {
      totalSamples: 0,
      trainingRuns: 0,
      lastTrainedAt: null,
    };
  }

  /**
   * Add a training sample.
   * @param {string} text
   * @param {string} label - 'attack' or 'benign'
   * @param {Object} [metadata]
   */
  addSample(text, label, metadata) {
    if (!text || typeof text !== 'string') return;
    if (label !== 'attack' && label !== 'benign') return;
    this._samples.push({ text, label, metadata: metadata || {} });
    this._stats.totalSamples = this._samples.length;
  }

  /**
   * Import samples from Agent Shield scan results.
   * @param {Array} scanResults - Array of { text, status, threats }
   */
  addFromScanHistory(scanResults) {
    if (!Array.isArray(scanResults)) return;
    for (const result of scanResults) {
      if (!result.text) continue;
      const label = (result.threats && result.threats.length > 0) ? 'attack' : 'benign';
      this.addSample(result.text, label, { source: 'scan_history' });
    }
  }

  /**
   * Train a model on collected samples.
   * Uses logistic regression with gradient descent on TF-IDF features.
   *
   * @returns {{ model: TrainedModel, metrics: Object }}
   */
  train() {
    if (this._samples.length < 10) {
      throw new Error(`[Agent Shield] Need at least 10 samples to train (have ${this._samples.length})`);
    }

    // Fisher-Yates shuffle and split
    const shuffled = [...this._samples];
    for (let i = shuffled.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
    }
    const splitIdx = Math.floor(shuffled.length * (1 - this.testSplit));
    const trainSet = shuffled.slice(0, splitIdx);
    const testSet = shuffled.slice(splitIdx);

    // Build vocabulary from training set
    const vocabulary = buildVocabulary(trainSet.map(s => s.text), this.vocabSize);
    const featureDim = vocabulary.length + 1; // +1 for bias

    // Extract features
    const trainFeatures = trainSet.map(s => extractFeatures(s.text, vocabulary));
    const trainLabels = trainSet.map(s => s.label === 'attack' ? 1 : 0);

    // Initialize weights
    const weights = new Array(featureDim).fill(0);

    // Gradient descent
    for (let epoch = 0; epoch < this.epochs; epoch++) {
      for (let i = 0; i < trainFeatures.length; i++) {
        const features = trainFeatures[i];
        const label = trainLabels[i];
        const prediction = sigmoid(dot(features, weights));
        const error = prediction - label;

        for (let j = 0; j < featureDim; j++) {
          weights[j] -= this.learningRate * error * features[j];
        }
      }
    }

    // Create model
    const model = new TrainedModel(weights, vocabulary, {
      epochs: this.epochs,
      learningRate: this.learningRate,
      trainSamples: trainSet.length,
      testSamples: testSet.length,
    });

    // Evaluate on test set
    const metrics = this._evaluate(model, testSet);

    // Store as version
    this._models.push({
      version: this._models.length + 1,
      model,
      metrics,
      trainedAt: new Date().toISOString(),
    });

    // Trim old versions
    while (this._models.length > this.maxModels) {
      this._models.shift();
    }

    this._activeModel = model;
    this._stats.trainingRuns++;
    this._stats.lastTrainedAt = new Date().toISOString();

    return { model, metrics };
  }

  /**
   * Predict using the active model.
   * @param {string} text
   * @returns {{ label: string, confidence: number } | null}
   */
  predict(text) {
    if (!this._activeModel) return null;
    return this._activeModel.predict(text);
  }

  /**
   * Compare two model versions (A/B test).
   * @param {number} versionA
   * @param {number} versionB
   * @param {Array<{text: string, label: string}>} testData
   * @returns {{ versionA: Object, versionB: Object, winner: number }}
   */
  compareModels(versionA, versionB, testData) {
    const modelA = this._models.find(m => m.version === versionA);
    const modelB = this._models.find(m => m.version === versionB);

    if (!modelA || !modelB) {
      throw new Error(`[Agent Shield] Model version not found`);
    }

    const metricsA = this._evaluate(modelA.model, testData);
    const metricsB = this._evaluate(modelB.model, testData);

    return {
      versionA: { version: versionA, ...metricsA },
      versionB: { version: versionB, ...metricsB },
      winner: metricsA.f1 >= metricsB.f1 ? versionA : versionB,
    };
  }

  /**
   * Set the active model to a specific version.
   * @param {number} version
   */
  setActiveVersion(version) {
    const entry = this._models.find(m => m.version === version);
    if (!entry) throw new Error(`[Agent Shield] Model version ${version} not found`);
    this._activeModel = entry.model;
  }

  /**
   * Get all model versions.
   * @returns {Array<{version: number, metrics: Object, trainedAt: string}>}
   */
  getVersions() {
    return this._models.map(m => ({
      version: m.version,
      metrics: m.metrics,
      trainedAt: m.trainedAt,
      isActive: m.model === this._activeModel,
    }));
  }

  /**
   * Export the active model.
   * @returns {Object|null}
   */
  exportModel() {
    if (!this._activeModel) return null;
    return this._activeModel.export();
  }

  /**
   * Import and activate a model.
   * @param {Object} json
   */
  importModel(json) {
    const model = TrainedModel.load(json);
    this._activeModel = model;
    this._models.push({
      version: this._models.length + 1,
      model,
      metrics: { imported: true },
      trainedAt: model.createdAt,
    });
  }

  /**
   * Get pipeline statistics.
   * @returns {Object}
   */
  getStats() {
    return {
      ...this._stats,
      modelVersions: this._models.length,
      hasActiveModel: !!this._activeModel,
    };
  }

  /** @private */
  _evaluate(model, testSet) {
    let tp = 0, fp = 0, tn = 0, fn = 0;

    for (const sample of testSet) {
      const pred = model.predict(sample.text);
      const actual = sample.label === 'attack';
      const predicted = pred.label === 'attack';

      if (predicted && actual) tp++;
      else if (predicted && !actual) fp++;
      else if (!predicted && !actual) tn++;
      else fn++;
    }

    const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
    const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
    const f1 = precision + recall > 0 ? 2 * (precision * recall) / (precision + recall) : 0;
    const accuracy = testSet.length > 0 ? (tp + tn) / testSet.length : 0;

    return {
      accuracy: Math.round(accuracy * 1000) / 1000,
      precision: Math.round(precision * 1000) / 1000,
      recall: Math.round(recall * 1000) / 1000,
      f1: Math.round(f1 * 1000) / 1000,
      confusion: { tp, fp, tn, fn },
      testSamples: testSet.length,
    };
  }
}

module.exports = {
  ModelTrainingPipeline,
  TrainedModel,
  tokenize,
  buildVocabulary,
  extractFeatures,
};
