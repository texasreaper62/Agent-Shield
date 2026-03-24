'use strict';

/**
 * Agent Shield — Custom Model Fine-Tuning
 *
 * Train org-specific detection models on threat data.
 * Uses TF-IDF + logistic regression — zero external dependencies.
 *
 * - ModelTrainer: Core training engine (gradient descent, binary cross-entropy)
 * - TrainingPipeline: End-to-end collect -> train -> evaluate pipeline
 * - DatasetManager: Dataset handling, augmentation, splitting
 * - ModelEvaluator: Accuracy, precision, recall, F1, confusion matrix, ROC AUC
 * - FineTunedModel: Trained model with predict, export, load
 */

// =========================================================================
// FineTunedModel
// =========================================================================

/**
 * A trained binary classifier using TF-IDF features and logistic regression.
 */
class FineTunedModel {
  /**
   * @param {number[]} weights - Model weight vector (one per vocabulary term + bias)
   * @param {string[]} vocabulary - Ordered vocabulary terms
   * @param {Object} config - Training config used to produce this model
   */
  constructor(weights, vocabulary, config) {
    this.weights = weights || [];
    this.vocabulary = vocabulary || [];
    this.config = config || {};
    this.createdAt = new Date().toISOString();
  }

  /**
   * Predict whether text is an attack or benign.
   * @param {string} text - Input text
   * @returns {{label: string, confidence: number}}
   */
  predict(text) {
    const features = this._extractFeatures(text);
    const z = this._dot(features);
    const probability = this._sigmoid(z);

    return {
      label: probability >= 0.5 ? 'attack' : 'benign',
      confidence: probability >= 0.5 ? probability : 1 - probability
    };
  }

  /**
   * Batch prediction on multiple texts.
   * @param {string[]} texts - Array of input texts
   * @returns {Array<{label: string, confidence: number}>}
   */
  predictBatch(texts) {
    return texts.map(text => this.predict(text));
  }

  /**
   * Export the model to a serializable JSON object.
   * @returns {Object}
   */
  export() {
    return {
      type: 'agent-shield-finetuned-model',
      version: '1.0',
      weights: this.weights,
      vocabulary: this.vocabulary,
      config: this.config,
      createdAt: this.createdAt
    };
  }

  /**
   * Load a model from a serialized JSON object.
   * @param {Object} json - Serialized model
   * @returns {FineTunedModel}
   */
  static load(json) {
    if (!json || json.type !== 'agent-shield-finetuned-model') {
      throw new Error('[Agent Shield] Invalid model format');
    }
    const model = new FineTunedModel(json.weights, json.vocabulary, json.config);
    model.createdAt = json.createdAt || new Date().toISOString();
    return model;
  }

  /**
   * Get the top weighted features (most important for classification).
   * @param {number} [topN=20] - Number of top features to return
   * @returns {Array<{term: string, weight: number}>}
   */
  getFeatureImportance(topN = 20) {
    const features = this.vocabulary.map((term, i) => ({
      term,
      weight: this.weights[i] || 0
    }));

    // Sort by absolute weight descending
    features.sort((a, b) => Math.abs(b.weight) - Math.abs(a.weight));

    return features.slice(0, topN);
  }

  /**
   * Extract TF-IDF feature vector for a text sample.
   * @private
   * @param {string} text
   * @returns {number[]} Feature vector aligned with vocabulary
   */
  _extractFeatures(text) {
    const tokens = _tokenize(text);
    const termFreq = {};
    for (const token of tokens) {
      termFreq[token] = (termFreq[token] || 0) + 1;
    }

    const features = new Array(this.vocabulary.length + 1).fill(0);
    const totalTokens = tokens.length || 1;

    for (let i = 0; i < this.vocabulary.length; i++) {
      const term = this.vocabulary[i];
      if (termFreq[term]) {
        // TF component (normalized)
        features[i] = termFreq[term] / totalTokens;
      }
    }

    // Bias term
    features[this.vocabulary.length] = 1;

    return features;
  }

  /**
   * Dot product of features and weights.
   * @private
   */
  _dot(features) {
    let sum = 0;
    const len = Math.min(features.length, this.weights.length);
    for (let i = 0; i < len; i++) {
      sum += features[i] * this.weights[i];
    }
    return sum;
  }

  /**
   * Sigmoid activation function.
   * @private
   */
  _sigmoid(z) {
    // Clamp to avoid overflow
    if (z > 500) return 1;
    if (z < -500) return 0;
    return 1 / (1 + Math.exp(-z));
  }
}

// =========================================================================
// DatasetManager
// =========================================================================

/**
 * Manages training datasets for the fine-tuning pipeline.
 */
class DatasetManager {
  constructor() {
    this.samples = [];
  }

  /**
   * Add a training sample.
   * @param {string} text - Sample text
   * @param {string} label - 'attack' or 'benign'
   * @param {Object} [metadata] - Optional metadata
   */
  addSample(text, label, metadata) {
    if (!text || typeof text !== 'string') {
      throw new Error('[Agent Shield] Sample text must be a non-empty string');
    }
    if (label !== 'attack' && label !== 'benign') {
      throw new Error('[Agent Shield] Label must be "attack" or "benign"');
    }
    this.samples.push({ text, label, metadata: metadata || {} });
    return this;
  }

  /**
   * Import samples from Agent Shield scan results.
   * @param {Array} scanResults - Array of scan result objects
   */
  addFromScanHistory(scanResults) {
    if (!Array.isArray(scanResults)) {
      throw new Error('[Agent Shield] scanResults must be an array');
    }

    for (const result of scanResults) {
      const text = result.input || result.text || result.prompt || '';
      if (!text) continue;

      // Determine label from scan result
      const isAttack = result.blocked || result.threat ||
        (result.status && result.status !== 'safe') ||
        (result.severity && result.severity !== 'low');

      this.samples.push({
        text,
        label: isAttack ? 'attack' : 'benign',
        metadata: {
          source: 'scan_history',
          severity: result.severity,
          category: result.category,
          originalResult: result
        }
      });
    }

    return this;
  }

  /**
   * Augment the dataset with synthetic variations.
   * Applies case variation, truncation, and token shuffling.
   * @returns {DatasetManager} this
   */
  augment() {
    const augmented = [];

    for (const sample of this.samples) {
      // Case variation: uppercase
      augmented.push({
        text: sample.text.toUpperCase(),
        label: sample.label,
        metadata: { ...sample.metadata, augmented: 'uppercase' }
      });

      // Case variation: lowercase
      augmented.push({
        text: sample.text.toLowerCase(),
        label: sample.label,
        metadata: { ...sample.metadata, augmented: 'lowercase' }
      });

      // Truncation: first half
      if (sample.text.length > 20) {
        const half = Math.ceil(sample.text.length / 2);
        augmented.push({
          text: sample.text.slice(0, half),
          label: sample.label,
          metadata: { ...sample.metadata, augmented: 'truncated' }
        });
      }

      // Synonym insertion: add noise characters between words
      const words = sample.text.split(/\s+/);
      if (words.length > 2) {
        const shuffled = [...words];
        // Swap two random words
        const i = Math.floor(Math.random() * shuffled.length);
        const j = Math.floor(Math.random() * shuffled.length);
        [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
        augmented.push({
          text: shuffled.join(' '),
          label: sample.label,
          metadata: { ...sample.metadata, augmented: 'shuffled' }
        });
      }
    }

    this.samples.push(...augmented);
    return this;
  }

  /**
   * Split the dataset into train/validation/test sets.
   * @param {number} [ratio=0.8] - Fraction for training (rest split evenly for val/test)
   * @returns {{train: Array, validation: Array, test: Array}}
   */
  split(ratio = 0.8) {
    // Shuffle samples
    const shuffled = [...this.samples];
    for (let i = shuffled.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
    }

    const trainEnd = Math.floor(shuffled.length * ratio);
    const valEnd = Math.floor(shuffled.length * (ratio + (1 - ratio) / 2));

    return {
      train: shuffled.slice(0, trainEnd),
      validation: shuffled.slice(trainEnd, valEnd),
      test: shuffled.slice(valEnd)
    };
  }

  /**
   * Get dataset statistics.
   * @returns {Object} Statistics including counts, label distribution
   */
  getStats() {
    const attackCount = this.samples.filter(s => s.label === 'attack').length;
    const benignCount = this.samples.filter(s => s.label === 'benign').length;
    const total = this.samples.length;

    return {
      total,
      attackCount,
      benignCount,
      attackRatio: total > 0 ? attackCount / total : 0,
      benignRatio: total > 0 ? benignCount / total : 0,
      avgTextLength: total > 0
        ? Math.round(this.samples.reduce((sum, s) => sum + s.text.length, 0) / total)
        : 0,
      augmentedCount: this.samples.filter(s => s.metadata && s.metadata.augmented).length
    };
  }

  /**
   * Export the dataset as a serializable object.
   * @returns {Object}
   */
  export() {
    return {
      type: 'agent-shield-dataset',
      version: '1.0',
      samples: this.samples,
      stats: this.getStats(),
      exportedAt: new Date().toISOString()
    };
  }
}

// =========================================================================
// ModelTrainer
// =========================================================================

/**
 * Core training engine using TF-IDF features and logistic regression
 * with gradient descent.
 */
class ModelTrainer {
  /**
   * @param {Object} [config]
   * @param {number} [config.learningRate=0.01] - Learning rate for gradient descent
   * @param {number} [config.epochs=10] - Number of training epochs
   * @param {number} [config.batchSize=32] - Mini-batch size
   * @param {number} [config.validationSplit=0.2] - Fraction held out for validation
   */
  constructor(config = {}) {
    this.learningRate = config.learningRate || 0.01;
    this.epochs = config.epochs || 10;
    this.batchSize = config.batchSize || 32;
    this.validationSplit = config.validationSplit || 0.2;
  }

  /**
   * Train a binary classifier on the provided dataset.
   * Uses TF-IDF features, sigmoid activation, and binary cross-entropy loss.
   *
   * @param {Array<{text: string, label: string}>} dataset - Training samples
   * @returns {FineTunedModel} Trained model
   */
  train(dataset) {
    if (!dataset || dataset.length === 0) {
      throw new Error('[Agent Shield] Dataset cannot be empty');
    }

    console.log(`[Agent Shield] Training started: ${dataset.length} samples, ${this.epochs} epochs`);

    // Build vocabulary from training data
    const vocabulary = this._buildVocabulary(dataset);
    console.log(`[Agent Shield] Vocabulary size: ${vocabulary.length}`);

    // Compute IDF values
    const idf = this._computeIDF(dataset, vocabulary);

    // Build feature matrix and label vector
    const { features, labels } = this._buildFeatureMatrix(dataset, vocabulary, idf);

    // Split into train/validation
    const splitIdx = Math.floor(features.length * (1 - this.validationSplit));
    const trainFeatures = features.slice(0, splitIdx);
    const trainLabels = labels.slice(0, splitIdx);
    const valFeatures = features.slice(splitIdx);
    const valLabels = labels.slice(splitIdx);

    // Initialize weights (vocabulary size + 1 for bias)
    const numFeatures = vocabulary.length + 1;
    const weights = new Array(numFeatures).fill(0);

    // Initialize with small random values
    for (let i = 0; i < numFeatures; i++) {
      weights[i] = (Math.random() - 0.5) * 0.01;
    }

    const lossHistory = [];

    // Gradient descent training
    for (let epoch = 0; epoch < this.epochs; epoch++) {
      let epochLoss = 0;
      let batchCount = 0;

      // Mini-batch gradient descent
      for (let batchStart = 0; batchStart < trainFeatures.length; batchStart += this.batchSize) {
        const batchEnd = Math.min(batchStart + this.batchSize, trainFeatures.length);
        const batchSize = batchEnd - batchStart;
        const gradients = new Array(numFeatures).fill(0);

        for (let i = batchStart; i < batchEnd; i++) {
          const x = trainFeatures[i];
          const y = trainLabels[i];

          // Forward pass: z = w . x, yhat = sigmoid(z)
          let z = 0;
          for (let j = 0; j < numFeatures; j++) {
            z += weights[j] * x[j];
          }
          const yhat = _sigmoid(z);

          // Binary cross-entropy loss
          const clampedYhat = Math.max(1e-7, Math.min(1 - 1e-7, yhat));
          epochLoss += -(y * Math.log(clampedYhat) + (1 - y) * Math.log(1 - clampedYhat));

          // Gradient: (yhat - y) * x_j
          const error = yhat - y;
          for (let j = 0; j < numFeatures; j++) {
            gradients[j] += error * x[j];
          }
        }

        // Update weights
        for (let j = 0; j < numFeatures; j++) {
          weights[j] -= this.learningRate * (gradients[j] / batchSize);
        }
        batchCount++;
      }

      const avgLoss = trainFeatures.length > 0 ? epochLoss / trainFeatures.length : 0;

      // Validation loss
      let valLoss = 0;
      if (valFeatures.length > 0) {
        for (let i = 0; i < valFeatures.length; i++) {
          let z = 0;
          for (let j = 0; j < numFeatures; j++) {
            z += weights[j] * valFeatures[i][j];
          }
          const yhat = _sigmoid(z);
          const clampedYhat = Math.max(1e-7, Math.min(1 - 1e-7, yhat));
          valLoss += -(valLabels[i] * Math.log(clampedYhat) + (1 - valLabels[i]) * Math.log(1 - clampedYhat));
        }
        valLoss /= valFeatures.length;
      }

      lossHistory.push({ epoch: epoch + 1, trainLoss: avgLoss, valLoss });
      console.log(`[Agent Shield]   Epoch ${epoch + 1}/${this.epochs} — train_loss: ${avgLoss.toFixed(4)}, val_loss: ${valLoss.toFixed(4)}`);
    }

    const model = new FineTunedModel(weights, vocabulary, {
      learningRate: this.learningRate,
      epochs: this.epochs,
      batchSize: this.batchSize,
      trainingSamples: trainFeatures.length,
      validationSamples: valFeatures.length,
      lossHistory
    });

    console.log('[Agent Shield] Training complete');
    return model;
  }

  /**
   * Build vocabulary from dataset (unique tokens sorted by frequency).
   * @private
   */
  _buildVocabulary(dataset) {
    const freq = {};
    for (const sample of dataset) {
      const tokens = new Set(_tokenize(sample.text));
      for (const token of tokens) {
        freq[token] = (freq[token] || 0) + 1;
      }
    }

    // Filter: keep tokens appearing in at least 2 documents, max 5000 terms
    return Object.entries(freq)
      .filter(([, count]) => count >= 2)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5000)
      .map(([term]) => term);
  }

  /**
   * Compute IDF (inverse document frequency) for each vocabulary term.
   * @private
   */
  _computeIDF(dataset, vocabulary) {
    const docCount = dataset.length;
    const idf = {};

    for (const term of vocabulary) {
      let df = 0;
      for (const sample of dataset) {
        if (sample.text.toLowerCase().includes(term)) {
          df++;
        }
      }
      idf[term] = Math.log((docCount + 1) / (df + 1)) + 1; // smoothed IDF
    }

    return idf;
  }

  /**
   * Build TF-IDF feature matrix and label vector.
   * @private
   */
  _buildFeatureMatrix(dataset, vocabulary, idf) {
    const features = [];
    const labels = [];

    for (const sample of dataset) {
      const tokens = _tokenize(sample.text);
      const termFreq = {};
      for (const token of tokens) {
        termFreq[token] = (termFreq[token] || 0) + 1;
      }

      const totalTokens = tokens.length || 1;
      const featureVec = new Array(vocabulary.length + 1);

      for (let i = 0; i < vocabulary.length; i++) {
        const term = vocabulary[i];
        const tf = (termFreq[term] || 0) / totalTokens;
        featureVec[i] = tf * (idf[term] || 0);
      }

      // Bias term
      featureVec[vocabulary.length] = 1;

      features.push(featureVec);
      labels.push(sample.label === 'attack' ? 1 : 0);
    }

    return { features, labels };
  }
}

// =========================================================================
// ModelEvaluator
// =========================================================================

/**
 * Evaluates a fine-tuned model and computes classification metrics.
 */
class ModelEvaluator {
  constructor() {
    this.lastReport = null;
  }

  /**
   * Evaluate a model on a test set.
   * @param {FineTunedModel} model - Trained model
   * @param {Array<{text: string, label: string}>} testSet - Test samples
   * @returns {Object} Evaluation metrics
   */
  evaluate(model, testSet) {
    if (!model || !testSet || testSet.length === 0) {
      throw new Error('[Agent Shield] Model and non-empty test set required');
    }

    let tp = 0, fp = 0, tn = 0, fn = 0;
    const predictions = [];

    for (const sample of testSet) {
      const prediction = model.predict(sample.text);
      const actual = sample.label;
      const predicted = prediction.label;

      predictions.push({
        text: sample.text.slice(0, 80),
        actual,
        predicted,
        confidence: prediction.confidence
      });

      if (actual === 'attack' && predicted === 'attack') tp++;
      else if (actual === 'benign' && predicted === 'attack') fp++;
      else if (actual === 'benign' && predicted === 'benign') tn++;
      else if (actual === 'attack' && predicted === 'benign') fn++;
    }

    const accuracy = testSet.length > 0 ? (tp + tn) / testSet.length : 0;
    const precision = (tp + fp) > 0 ? tp / (tp + fp) : 0;
    const recall = (tp + fn) > 0 ? tp / (tp + fn) : 0;
    const f1 = (precision + recall) > 0
      ? 2 * (precision * recall) / (precision + recall)
      : 0;

    // Compute ROC AUC approximation
    const roc_auc = this._computeAUC(predictions);

    const result = {
      accuracy,
      precision,
      recall,
      f1,
      confusionMatrix: { tp, fp, tn, fn },
      roc_auc,
      totalSamples: testSet.length,
      predictions
    };

    this.lastReport = result;
    return result;
  }

  /**
   * Generate a formatted text report from the last evaluation.
   * @returns {string} Formatted report
   */
  generateReport() {
    if (!this.lastReport) {
      return '[Agent Shield] No evaluation has been run yet.';
    }

    const r = this.lastReport;
    const cm = r.confusionMatrix;

    const lines = [
      '=== Agent Shield — Model Evaluation Report ===',
      '',
      `Samples evaluated: ${r.totalSamples}`,
      '',
      'Metrics:',
      `  Accuracy:  ${(r.accuracy * 100).toFixed(2)}%`,
      `  Precision: ${(r.precision * 100).toFixed(2)}%`,
      `  Recall:    ${(r.recall * 100).toFixed(2)}%`,
      `  F1 Score:  ${(r.f1 * 100).toFixed(2)}%`,
      `  ROC AUC:   ${r.roc_auc.toFixed(4)}`,
      '',
      'Confusion Matrix:',
      `                Predicted Attack  Predicted Benign`,
      `  Actual Attack       ${String(cm.tp).padStart(5)}           ${String(cm.fn).padStart(5)}`,
      `  Actual Benign       ${String(cm.fp).padStart(5)}           ${String(cm.tn).padStart(5)}`,
      '',
      '=== End of Report ==='
    ];

    return lines.join('\n');
  }

  /**
   * Approximate AUC using the trapezoidal rule on sorted predictions.
   * @private
   */
  _computeAUC(predictions) {
    if (predictions.length === 0) return 0;

    // Sort by confidence descending (for attack predictions) / ascending (for benign)
    const scored = predictions.map(p => ({
      actual: p.actual === 'attack' ? 1 : 0,
      score: p.predicted === 'attack' ? p.confidence : 1 - p.confidence
    }));
    scored.sort((a, b) => b.score - a.score);

    const totalPositive = scored.filter(s => s.actual === 1).length;
    const totalNegative = scored.filter(s => s.actual === 0).length;

    if (totalPositive === 0 || totalNegative === 0) return 0.5;

    let tpr = 0, fpr = 0, prevTpr = 0, prevFpr = 0;
    let auc = 0;

    for (const item of scored) {
      if (item.actual === 1) {
        tpr += 1 / totalPositive;
      } else {
        fpr += 1 / totalNegative;
      }

      // Trapezoidal rule
      auc += (fpr - prevFpr) * (tpr + prevTpr) / 2;
      prevTpr = tpr;
      prevFpr = fpr;
    }

    return auc;
  }
}

// =========================================================================
// TrainingPipeline
// =========================================================================

/**
 * End-to-end pipeline for collecting, processing, training, and evaluating
 * a fine-tuned detection model.
 */
class TrainingPipeline {
  /**
   * @param {Object} [config] - Pipeline configuration passed to ModelTrainer
   */
  constructor(config = {}) {
    this.config = config;
    this.stages = [];
    this.report = null;
  }

  /**
   * Add a custom processing stage to the pipeline.
   * @param {string} name - Stage name
   * @param {Function} fn - Stage function (receives data, returns transformed data)
   * @returns {TrainingPipeline} this
   */
  addStage(name, fn) {
    if (typeof fn !== 'function') {
      throw new Error(`[Agent Shield] Stage "${name}" must be a function`);
    }
    this.stages.push({ name, fn });
    return this;
  }

  /**
   * Run the full pipeline: collect -> preprocess -> augment -> train -> evaluate -> export.
   * @param {Array} rawData - Raw training data (array of {text, label} or scan results)
   * @returns {Object} Pipeline result with model, evaluation, and export
   */
  run(rawData) {
    const startTime = Date.now();
    const stageResults = [];

    console.log('[Agent Shield] Training pipeline started');

    // Stage 1: Collect
    let data = rawData;
    stageResults.push({ stage: 'collect', samples: data.length, duration: 0 });

    // Stage 2: Preprocess
    const preprocessStart = Date.now();
    const dataset = new DatasetManager();
    for (const item of data) {
      const text = item.text || item.input || item.prompt || '';
      const label = item.label || (item.blocked || item.threat ? 'attack' : 'benign');
      if (text) {
        dataset.addSample(text, label, item.metadata);
      }
    }
    stageResults.push({
      stage: 'preprocess',
      samples: dataset.samples.length,
      duration: Date.now() - preprocessStart
    });

    // Stage 3: Augment
    const augmentStart = Date.now();
    dataset.augment();
    stageResults.push({
      stage: 'augment',
      samples: dataset.samples.length,
      duration: Date.now() - augmentStart
    });

    // Run custom stages
    let pipelineData = dataset.samples;
    for (const stage of this.stages) {
      const stageStart = Date.now();
      pipelineData = stage.fn(pipelineData);
      stageResults.push({
        stage: stage.name,
        samples: Array.isArray(pipelineData) ? pipelineData.length : 'N/A',
        duration: Date.now() - stageStart
      });
    }

    // Stage 4: Train
    const trainStart = Date.now();
    const trainer = new ModelTrainer(this.config);
    const trainingData = Array.isArray(pipelineData) ? pipelineData : dataset.samples;
    const model = trainer.train(trainingData);
    stageResults.push({
      stage: 'train',
      samples: trainingData.length,
      duration: Date.now() - trainStart
    });

    // Stage 5: Evaluate
    const evalStart = Date.now();
    const splits = dataset.split(0.8);
    const evaluator = new ModelEvaluator();
    const evaluation = evaluator.evaluate(model, splits.test.length > 0 ? splits.test : splits.validation);
    stageResults.push({
      stage: 'evaluate',
      samples: (splits.test.length > 0 ? splits.test : splits.validation).length,
      duration: Date.now() - evalStart
    });

    // Stage 6: Export
    const exportStart = Date.now();
    const exported = model.export();
    stageResults.push({
      stage: 'export',
      samples: 1,
      duration: Date.now() - exportStart
    });

    const totalDuration = Date.now() - startTime;

    this.report = {
      stages: stageResults,
      totalDuration,
      datasetStats: dataset.getStats(),
      evaluation: {
        accuracy: evaluation.accuracy,
        precision: evaluation.precision,
        recall: evaluation.recall,
        f1: evaluation.f1,
        roc_auc: evaluation.roc_auc
      },
      completedAt: new Date().toISOString()
    };

    console.log(`[Agent Shield] Training pipeline complete in ${totalDuration}ms`);

    return {
      model,
      evaluation,
      exported,
      report: this.report
    };
  }

  /**
   * Get the pipeline execution report.
   * @returns {Object|null} Report from the last run
   */
  getReport() {
    return this.report;
  }
}

// =========================================================================
// Shared Utilities
// =========================================================================

/**
 * Tokenize text into lowercase terms.
 * @param {string} text
 * @returns {string[]}
 */
function _tokenize(text) {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9\s_-]/g, ' ')
    .split(/\s+/)
    .filter(t => t.length > 1);
}

/**
 * Sigmoid function.
 * @param {number} z
 * @returns {number}
 */
function _sigmoid(z) {
  if (z > 500) return 1;
  if (z < -500) return 0;
  return 1 / (1 + Math.exp(-z));
}

// =========================================================================
// Exports
// =========================================================================

module.exports = {
  ModelTrainer,
  TrainingPipeline,
  DatasetManager,
  ModelEvaluator,
  FineTunedModel
};
