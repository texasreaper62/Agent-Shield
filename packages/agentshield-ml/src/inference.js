'use strict';

/**
 * Agent Shield ML — ONNX Inference Engine
 *
 * Loads a trained ONNX model and runs prompt injection detection locally.
 * Uses onnxruntime-node for server-side or onnxruntime-web for browsers.
 *
 * The model file and tokenizer must be present in the models/ directory.
 * See training/TRAINING-GUIDE.md for how to train and export the model.
 */

const fs = require('fs');
const path = require('path');

const PREFIX = '[Agent Shield ML]';
const MODELS_DIR = path.join(__dirname, '..', 'models');

/**
 * Simple WordPiece-like tokenizer that works without external dependencies.
 * Loads vocabulary from the tokenizer.json file exported by HuggingFace.
 */
class SimpleTokenizer {
  /**
   * @param {string} vocabPath - Path to tokenizer.json
   * @param {number} maxLength - Maximum token sequence length
   */
  constructor(vocabPath, maxLength = 256) {
    this.maxLength = maxLength;
    this.vocab = new Map();
    this.unkId = 0;
    this.padId = 0;
    this.clsId = 101;
    this.sepId = 102;

    if (fs.existsSync(vocabPath)) {
      this._loadVocab(vocabPath);
    } else {
      console.warn(`${PREFIX} Tokenizer not found at ${vocabPath} — using fallback`);
    }
  }

  _loadVocab(vocabPath) {
    try {
      const data = JSON.parse(fs.readFileSync(vocabPath, 'utf-8'));

      // HuggingFace tokenizer.json format
      if (data.model && data.model.vocab) {
        // WordPiece format
        const vocabObj = data.model.vocab;
        for (const [token, id] of Object.entries(vocabObj)) {
          this.vocab.set(token, id);
        }
      } else if (data.added_tokens) {
        // Simpler format — try to extract vocab from the file
        for (const token of data.added_tokens) {
          if (token.id !== undefined && token.content) {
            this.vocab.set(token.content, token.id);
          }
        }
      }

      // Extract special token IDs
      if (data.added_tokens) {
        for (const t of data.added_tokens) {
          if (t.content === '[PAD]') this.padId = t.id;
          if (t.content === '[UNK]') this.unkId = t.id;
          if (t.content === '[CLS]') this.clsId = t.id;
          if (t.content === '[SEP]') this.sepId = t.id;
        }
      }

      console.log(`${PREFIX} Tokenizer loaded: ${this.vocab.size} tokens`);
    } catch (e) {
      console.warn(`${PREFIX} Failed to load tokenizer: ${e.message}`);
    }
  }

  /**
   * Tokenize text into input_ids and attention_mask.
   * @param {string} text
   * @returns {{ input_ids: number[], attention_mask: number[] }}
   */
  encode(text) {
    const tokens = this._tokenize(text);
    const ids = [this.clsId]; // [CLS]

    for (const token of tokens) {
      if (ids.length >= this.maxLength - 1) break;
      const id = this.vocab.get(token) || this.vocab.get(token.toLowerCase()) || this.unkId;
      ids.push(id);
    }

    ids.push(this.sepId); // [SEP]

    // Pad to maxLength
    const attention_mask = new Array(this.maxLength).fill(0);
    const input_ids = new Array(this.maxLength).fill(this.padId);

    for (let i = 0; i < ids.length; i++) {
      input_ids[i] = ids[i];
      attention_mask[i] = 1;
    }

    return { input_ids, attention_mask };
  }

  _tokenize(text) {
    // Basic WordPiece tokenization
    const words = text.toLowerCase().replace(/[^\w\s'-]/g, ' ').split(/\s+/).filter(Boolean);
    const tokens = [];

    for (const word of words) {
      if (this.vocab.has(word)) {
        tokens.push(word);
      } else {
        // Try subword tokenization
        let remaining = word;
        let isFirst = true;

        while (remaining.length > 0) {
          let found = false;
          for (let end = remaining.length; end > 0; end--) {
            const sub = isFirst ? remaining.slice(0, end) : `##${remaining.slice(0, end)}`;
            if (this.vocab.has(sub)) {
              tokens.push(sub);
              remaining = remaining.slice(end);
              isFirst = false;
              found = true;
              break;
            }
          }
          if (!found) {
            tokens.push('[UNK]');
            break;
          }
        }
      }
    }

    return tokens;
  }
}

/**
 * ML-based prompt injection detector using ONNX Runtime.
 */
class MLDetector {
  /**
   * @param {Object} [options]
   * @param {string} [options.modelPath] - Path to ONNX model file
   * @param {string} [options.tokenizerPath] - Path to tokenizer.json
   * @param {number} [options.maxLength=256] - Maximum token sequence length
   * @param {number} [options.threshold=0.5] - Classification threshold
   */
  constructor(options = {}) {
    this.modelPath = options.modelPath || path.join(MODELS_DIR, 'shield-detector.onnx');
    this.tokenizerPath = options.tokenizerPath || path.join(MODELS_DIR, 'tokenizer.json');
    this.maxLength = options.maxLength || 256;
    this.threshold = options.threshold || 0.5;
    this.session = null;
    this.tokenizer = null;
    this._loaded = false;
    this._stats = { totalScans: 0, injections: 0, avgLatencyMs: 0 };
  }

  /**
   * Check if the model file exists.
   * @returns {boolean}
   */
  isModelAvailable() {
    return fs.existsSync(this.modelPath);
  }

  /**
   * Load the ONNX model and tokenizer.
   * @returns {Promise<boolean>} True if loaded successfully
   */
  async load() {
    if (this._loaded) return true;

    if (!this.isModelAvailable()) {
      console.warn(`${PREFIX} Model not found at ${this.modelPath}`);
      console.warn(`${PREFIX} Run the training pipeline first. See training/TRAINING-GUIDE.md`);
      return false;
    }

    try {
      // Try to load onnxruntime-node
      let ort;
      try {
        ort = require('onnxruntime-node');
      } catch (_e) {
        try {
          ort = require('onnxruntime-web');
        } catch (_e2) {
          console.warn(`${PREFIX} onnxruntime not found. Install: npm install onnxruntime-node`);
          return false;
        }
      }

      console.log(`${PREFIX} Loading model: ${this.modelPath}`);
      this.session = await ort.InferenceSession.create(this.modelPath);

      // Load tokenizer
      this.tokenizer = new SimpleTokenizer(this.tokenizerPath, this.maxLength);
      this._loaded = true;

      const sizeKB = Math.round(fs.statSync(this.modelPath).size / 1024);
      console.log(`${PREFIX} Model loaded (${sizeKB}KB)`);
      return true;
    } catch (e) {
      console.error(`${PREFIX} Failed to load model: ${e.message}`);
      return false;
    }
  }

  /**
   * Classify text as injection or benign.
   * @param {string} text - Input text to classify
   * @returns {Promise<{ isInjection: boolean, confidence: number, severity: string, latencyMs: number }>}
   */
  async classify(text) {
    if (!this._loaded) {
      const loaded = await this.load();
      if (!loaded) {
        return {
          isInjection: false,
          confidence: 0,
          severity: 'unknown',
          latencyMs: 0,
          error: 'Model not loaded'
        };
      }
    }

    const startTime = Date.now();

    try {
      // Tokenize
      const { input_ids, attention_mask } = this.tokenizer.encode(text);

      // Create tensors
      const ort = this.session.constructor.name === 'InferenceSession'
        ? require('onnxruntime-node')
        : require('onnxruntime-web');

      const inputIdsTensor = new ort.Tensor('int64', BigInt64Array.from(input_ids.map(BigInt)), [1, this.maxLength]);
      const attentionTensor = new ort.Tensor('int64', BigInt64Array.from(attention_mask.map(BigInt)), [1, this.maxLength]);

      // Run inference
      const results = await this.session.run({
        input_ids: inputIdsTensor,
        attention_mask: attentionTensor
      });

      // Get logits and compute softmax
      const logits = Array.from(results.logits.data);
      const maxLogit = Math.max(...logits);
      const exps = logits.map(l => Math.exp(l - maxLogit));
      const sumExp = exps.reduce((a, b) => a + b, 0);
      const probs = exps.map(e => e / sumExp);

      const injectionProb = probs[1] || 0; // class 1 = injection
      const isInjection = injectionProb >= this.threshold;
      const latencyMs = Date.now() - startTime;

      // Update stats
      this._stats.totalScans++;
      if (isInjection) this._stats.injections++;
      this._stats.avgLatencyMs = (this._stats.avgLatencyMs * (this._stats.totalScans - 1) + latencyMs) / this._stats.totalScans;

      return {
        isInjection,
        confidence: Math.round(injectionProb * 1000) / 1000,
        severity: this._confidenceToSeverity(injectionProb),
        latencyMs
      };
    } catch (e) {
      return {
        isInjection: false,
        confidence: 0,
        severity: 'error',
        latencyMs: Date.now() - startTime,
        error: e.message
      };
    }
  }

  /**
   * Classify a batch of texts.
   * @param {string[]} texts
   * @returns {Promise<Array>}
   */
  async classifyBatch(texts) {
    const results = [];
    for (const text of texts) {
      results.push(await this.classify(text));
    }
    return results;
  }

  /**
   * Get detector statistics.
   * @returns {Object}
   */
  getStats() {
    return { ...this._stats };
  }

  _confidenceToSeverity(confidence) {
    if (confidence >= 0.9) return 'critical';
    if (confidence >= 0.7) return 'high';
    if (confidence >= 0.5) return 'medium';
    if (confidence >= 0.3) return 'low';
    return 'safe';
  }
}

/**
 * Create an ML-enhanced scan function that combines pattern matching with ML.
 * Falls back to pattern-only if model is not available.
 *
 * @param {Object} shield - AgentShield instance from agentshield-sdk
 * @param {Object} [options] - MLDetector options
 * @returns {Function} async scan function
 */
function createMLScan(shield, options = {}) {
  const detector = new MLDetector(options);

  return async function mlScan(text) {
    // Always run pattern scan (fast, synchronous)
    const patternResult = shield.scan(text);

    // Try ML scan (async, may not be available)
    let mlResult = null;
    try {
      if (detector.isModelAvailable()) {
        mlResult = await detector.classify(text);
      }
    } catch (_e) {
      // ML failure is non-fatal
    }

    // Combine results
    const combined = { ...patternResult };
    if (mlResult) {
      combined.ml = mlResult;

      // If ML detects injection but patterns didn't, upgrade the result
      if (mlResult.isInjection && patternResult.status === 'safe') {
        combined.status = 'warning';
        combined.threats = combined.threats || [];
        combined.threats.push({
          category: 'ml_detection',
          severity: mlResult.severity,
          description: 'ML classifier detected potential injection',
          confidence: mlResult.confidence,
          source: 'ml-model'
        });
      }

      // If both agree it's an injection, boost confidence
      if (mlResult.isInjection && patternResult.status !== 'safe') {
        combined.mlConfirmed = true;
      }
    }

    return combined;
  };
}

module.exports = {
  MLDetector,
  SimpleTokenizer,
  createMLScan,
  MODELS_DIR
};
