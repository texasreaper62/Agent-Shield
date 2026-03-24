'use strict';

/**
 * Agent Shield — Smart Configuration System (v8)
 *
 * Unified configuration for all Shield features.
 * Three ways to use:
 *
 * 1. Quick start (3 lines):
 *    const { createShield } = require('agentshield-sdk');
 *    const shield = createShield('chatbot');
 *    const result = shield.scan(text);
 *
 * 2. Builder pattern:
 *    const shield = createShield()
 *      .preset('rag_pipeline')
 *      .enableIntent({ purpose: 'Answer questions from docs' })
 *      .enableLearning({ persist: true })
 *      .enableEnsemble()
 *      .build();
 *
 * 3. Config object:
 *    const shield = createShield({
 *      preset: 'high_security',
 *      intent: { purpose: 'Flight booking agent', allowedTools: ['searchFlights', 'bookFlight'] },
 *      learning: { persist: true, feedbackEnabled: true },
 *      ensemble: true,
 *      goalDrift: true,
 *      crossTurn: { windowSize: 20 },
 *      toolSequence: true,
 *      adaptiveThresholds: true
 *    });
 *
 * @module smart-config
 */

/** Valid preset names */
const VALID_PRESETS = [
  'chatbot',
  'coding_agent',
  'rag_pipeline',
  'customer_support',
  'internal_tool',
  'multi_agent',
  'high_security',
  'minimal',
  'mcp_server'
];

/** Valid sensitivity levels */
const VALID_SENSITIVITIES = ['low', 'medium', 'high'];

/** Valid block threshold levels */
const VALID_BLOCK_THRESHOLDS = ['low', 'medium', 'high', 'critical'];

/** Valid ensemble voter names */
const VALID_VOTERS = ['pattern', 'tfidf', 'entropy', 'ipia', 'semantic', 'behavioral', 'heuristic'];

/** Default configurations for each v8 feature */
const FEATURE_DEFAULTS = {
  intent: {
    purpose: '',
    allowedTools: [],
    allowedTopics: [],
    maxDriftScore: 0.6
  },
  learning: {
    persist: false,
    persistPath: './.agentshield/learned-patterns.json',
    promotionThreshold: 3,
    maxPatterns: 500
  },
  feedback: {
    autoRetrain: true,
    maxPending: 100,
    cooldownMs: 5000
  },
  ensemble: {
    voters: ['pattern', 'tfidf', 'entropy', 'ipia'],
    threshold: 0.5,
    requireUnanimous: false
  },
  goalDrift: {
    checkInterval: 5,
    driftThreshold: 0.6,
    windowSize: 10
  },
  crossTurn: {
    windowSize: 20,
    scanInterval: 3,
    accumulateAll: true
  },
  toolSequence: {
    learningPeriod: 50,
    anomalyThreshold: 0.15,
    maxChainLength: 10
  },
  adaptiveThresholds: {
    calibrationSamples: 100,
    adjustInterval: 50,
    minConfidence: 0.3
  },
  selfTraining: {
    generations: 10,
    populationSize: 20,
    mutationRate: 0.3,
    interval: 0
  }
};

/**
 * Preset configurations that set sensible defaults for common use cases.
 * @private
 */
const PRESET_CONFIGS = {
  chatbot: {
    sensitivity: 'medium',
    blockOnThreat: true,
    blockThreshold: 'medium',
    intent: { purpose: 'General-purpose chatbot' },
    crossTurn: true,
    goalDrift: true
  },
  coding_agent: {
    sensitivity: 'high',
    blockOnThreat: true,
    blockThreshold: 'high',
    intent: { purpose: 'Code generation and assistance' },
    toolSequence: true,
    ensemble: true
  },
  rag_pipeline: {
    sensitivity: 'high',
    blockOnThreat: true,
    blockThreshold: 'medium',
    intent: { purpose: 'Answer questions from documents' },
    ensemble: true,
    crossTurn: true,
    adaptiveThresholds: true
  },
  customer_support: {
    sensitivity: 'medium',
    blockOnThreat: true,
    blockThreshold: 'medium',
    intent: { purpose: 'Customer support agent' },
    goalDrift: true,
    crossTurn: true,
    feedback: true
  },
  internal_tool: {
    sensitivity: 'low',
    blockOnThreat: false,
    blockThreshold: 'high',
    intent: { purpose: 'Internal tooling agent' },
    toolSequence: true
  },
  multi_agent: {
    sensitivity: 'high',
    blockOnThreat: true,
    blockThreshold: 'medium',
    intent: { purpose: 'Multi-agent orchestration' },
    ensemble: true,
    toolSequence: true,
    crossTurn: true,
    goalDrift: true
  },
  high_security: {
    sensitivity: 'high',
    blockOnThreat: true,
    blockThreshold: 'low',
    intent: { purpose: 'High-security agent' },
    ensemble: { voters: ['pattern', 'tfidf', 'entropy', 'ipia', 'semantic', 'behavioral'], requireUnanimous: false },
    learning: { persist: true },
    goalDrift: { driftThreshold: 0.4 },
    crossTurn: true,
    toolSequence: true,
    adaptiveThresholds: true,
    selfTraining: true
  },
  minimal: {
    sensitivity: 'low',
    blockOnThreat: false,
    blockThreshold: 'critical'
  },
  mcp_server: {
    sensitivity: 'high',
    blockOnThreat: true,
    blockThreshold: 'medium',
    intent: { purpose: 'MCP tool server' },
    ensemble: true,
    toolSequence: { learningPeriod: 30, anomalyThreshold: 0.1, maxChainLength: 15 },
    crossTurn: true,
    goalDrift: { driftThreshold: 0.5 },
    adaptiveThresholds: true
  }
};

/**
 * Deep-merge source into target. Arrays are replaced, not concatenated.
 * @private
 * @param {object} target
 * @param {object} source
 * @returns {object}
 */
function deepMerge(target, source) {
  const result = Object.assign({}, target);
  for (const key of Object.keys(source)) {
    const srcVal = source[key];
    const tgtVal = result[key];
    if (srcVal && typeof srcVal === 'object' && !Array.isArray(srcVal) &&
        tgtVal && typeof tgtVal === 'object' && !Array.isArray(tgtVal)) {
      result[key] = deepMerge(tgtVal, srcVal);
    } else {
      result[key] = srcVal;
    }
  }
  return result;
}

/**
 * Deep-freeze an object and all nested objects.
 * @private
 * @param {object} obj
 * @returns {object}
 */
function deepFreeze(obj) {
  Object.freeze(obj);
  for (const val of Object.values(obj)) {
    if (val && typeof val === 'object' && !Object.isFrozen(val)) {
      deepFreeze(val);
    }
  }
  return obj;
}

/**
 * Resolve a feature value: `true` becomes the defaults, an object merges with defaults,
 * falsy stays null.
 * @private
 * @param {string} featureName
 * @param {*} value
 * @returns {object|null}
 */
function resolveFeature(featureName, value) {
  if (!value) return null;
  const defaults = FEATURE_DEFAULTS[featureName];
  if (!defaults) return null;
  if (value === true) return Object.assign({}, defaults);
  if (typeof value === 'object' && !Array.isArray(value)) {
    return Object.assign({}, defaults, value);
  }
  return Object.assign({}, defaults);
}

/**
 * Validate a configuration object.
 * @param {object} config - The configuration to validate.
 * @returns {{ valid: boolean, errors: string[] }} Validation result.
 */
function validateConfig(config) {
  const errors = [];

  if (!config || typeof config !== 'object') {
    return { valid: false, errors: ['Config must be a non-null object'] };
  }

  // Preset
  if (config.preset !== undefined && config.preset !== null) {
    if (!VALID_PRESETS.includes(config.preset)) {
      errors.push(`Invalid preset "${config.preset}". Valid presets: ${VALID_PRESETS.join(', ')}`);
    }
  }

  // Sensitivity
  if (config.sensitivity !== undefined) {
    if (!VALID_SENSITIVITIES.includes(config.sensitivity)) {
      errors.push(`Invalid sensitivity "${config.sensitivity}". Must be one of: ${VALID_SENSITIVITIES.join(', ')}`);
    }
  }

  // Block threshold
  if (config.blockThreshold !== undefined) {
    if (!VALID_BLOCK_THRESHOLDS.includes(config.blockThreshold)) {
      errors.push(`Invalid blockThreshold "${config.blockThreshold}". Must be one of: ${VALID_BLOCK_THRESHOLDS.join(', ')}`);
    }
  }

  // Intent
  if (config.intent) {
    if (typeof config.intent === 'object') {
      if (config.intent.purpose !== undefined && (typeof config.intent.purpose !== 'string' || config.intent.purpose.trim() === '')) {
        errors.push('intent.purpose must be a non-empty string when provided');
      }
      if (config.intent.maxDriftScore !== undefined) {
        if (typeof config.intent.maxDriftScore !== 'number' || config.intent.maxDriftScore < 0 || config.intent.maxDriftScore > 1) {
          errors.push('intent.maxDriftScore must be a number between 0 and 1');
        }
      }
    }
  }

  // Learning
  if (config.learning && typeof config.learning === 'object') {
    if (config.learning.persistPath !== undefined && typeof config.learning.persistPath !== 'string') {
      errors.push('learning.persistPath must be a string');
    }
    if (config.learning.promotionThreshold !== undefined) {
      if (typeof config.learning.promotionThreshold !== 'number' || config.learning.promotionThreshold < 0) {
        errors.push('learning.promotionThreshold must be a non-negative number');
      }
    }
  }

  // Ensemble
  if (config.ensemble && typeof config.ensemble === 'object') {
    if (config.ensemble.voters !== undefined) {
      if (!Array.isArray(config.ensemble.voters)) {
        errors.push('ensemble.voters must be an array');
      } else {
        for (const voter of config.ensemble.voters) {
          if (!VALID_VOTERS.includes(voter)) {
            errors.push(`Invalid ensemble voter "${voter}". Valid voters: ${VALID_VOTERS.join(', ')}`);
          }
        }
      }
    }
    if (config.ensemble.threshold !== undefined) {
      if (typeof config.ensemble.threshold !== 'number' || config.ensemble.threshold < 0 || config.ensemble.threshold > 1) {
        errors.push('ensemble.threshold must be a number between 0 and 1');
      }
    }
  }

  // Goal drift
  if (config.goalDrift && typeof config.goalDrift === 'object') {
    if (config.goalDrift.driftThreshold !== undefined) {
      if (typeof config.goalDrift.driftThreshold !== 'number' || config.goalDrift.driftThreshold < 0 || config.goalDrift.driftThreshold > 1) {
        errors.push('goalDrift.driftThreshold must be a number between 0 and 1');
      }
    }
  }

  // Adaptive thresholds
  if (config.adaptiveThresholds && typeof config.adaptiveThresholds === 'object') {
    if (config.adaptiveThresholds.minConfidence !== undefined) {
      if (typeof config.adaptiveThresholds.minConfidence !== 'number' || config.adaptiveThresholds.minConfidence < 0 || config.adaptiveThresholds.minConfidence > 1) {
        errors.push('adaptiveThresholds.minConfidence must be a number between 0 and 1');
      }
    }
  }

  // Self-training
  if (config.selfTraining && typeof config.selfTraining === 'object') {
    if (config.selfTraining.mutationRate !== undefined) {
      if (typeof config.selfTraining.mutationRate !== 'number' || config.selfTraining.mutationRate < 0 || config.selfTraining.mutationRate > 1) {
        errors.push('selfTraining.mutationRate must be a number between 0 and 1');
      }
    }
  }

  // Tool sequence
  if (config.toolSequence && typeof config.toolSequence === 'object') {
    if (config.toolSequence.anomalyThreshold !== undefined) {
      if (typeof config.toolSequence.anomalyThreshold !== 'number' || config.toolSequence.anomalyThreshold < 0 || config.toolSequence.anomalyThreshold > 1) {
        errors.push('toolSequence.anomalyThreshold must be a number between 0 and 1');
      }
    }
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Return a human-readable summary of a Shield configuration.
 * @param {object} config - A built configuration object.
 * @returns {string} Multi-line summary string.
 */
function describeConfig(config) {
  if (!config || typeof config !== 'object') {
    return '[Agent Shield] No configuration provided.';
  }

  const lines = [];
  lines.push('Agent Shield Configuration:');
  if (config.preset) {
    lines.push(`  Preset: ${config.preset}`);
  }

  const sens = config.sensitivity || 'medium';
  const block = config.blockOnThreat ? 'yes' : 'no';
  const thresh = config.blockThreshold || 'medium';
  lines.push(`  Sensitivity: ${sens} | Block: ${block} (threshold: ${thresh})`);
  lines.push('');
  lines.push('  Features enabled:');

  // Intent
  if (config.intent) {
    const purpose = config.intent.purpose || '(not specified)';
    lines.push(`    \u2713 Agent Intent \u2014 "${purpose}"`);
  } else {
    lines.push('    \u2717 Agent Intent \u2014 disabled');
  }

  // Learning
  if (config.learning) {
    const dest = config.learning.persist
      ? `saving to ${config.learning.persistPath || FEATURE_DEFAULTS.learning.persistPath}`
      : 'in-memory only';
    lines.push(`    \u2713 Persistent Learning \u2014 ${dest}`);
  } else {
    lines.push('    \u2717 Persistent Learning \u2014 disabled');
  }

  // Feedback
  if (config.feedback) {
    lines.push(`    \u2713 Feedback API \u2014 autoRetrain: ${config.feedback.autoRetrain !== false}`);
  } else {
    lines.push('    \u2717 Feedback API \u2014 disabled');
  }

  // Ensemble
  if (config.ensemble) {
    const voters = (config.ensemble.voters || FEATURE_DEFAULTS.ensemble.voters).join(', ');
    lines.push(`    \u2713 Ensemble Detection \u2014 voters: ${voters}`);
  } else {
    lines.push('    \u2717 Ensemble Detection \u2014 disabled');
  }

  // Goal Drift
  if (config.goalDrift) {
    const dt = config.goalDrift.driftThreshold !== undefined ? config.goalDrift.driftThreshold : FEATURE_DEFAULTS.goalDrift.driftThreshold;
    lines.push(`    \u2713 Goal Drift Detection \u2014 threshold: ${dt}`);
  } else {
    lines.push('    \u2717 Goal Drift Detection \u2014 disabled');
  }

  // Cross-Turn
  if (config.crossTurn) {
    const ws = config.crossTurn.windowSize !== undefined ? config.crossTurn.windowSize : FEATURE_DEFAULTS.crossTurn.windowSize;
    lines.push(`    \u2713 Cross-Turn Tracking \u2014 window: ${ws} turns`);
  } else {
    lines.push('    \u2717 Cross-Turn Tracking \u2014 disabled');
  }

  // Tool Sequence
  if (config.toolSequence) {
    const at = config.toolSequence.anomalyThreshold !== undefined ? config.toolSequence.anomalyThreshold : FEATURE_DEFAULTS.toolSequence.anomalyThreshold;
    lines.push(`    \u2713 Tool Sequence Modeling \u2014 anomaly threshold: ${at}`);
  } else {
    lines.push('    \u2717 Tool Sequence Modeling \u2014 disabled');
  }

  // Adaptive Thresholds
  if (config.adaptiveThresholds) {
    const cs = config.adaptiveThresholds.calibrationSamples !== undefined ? config.adaptiveThresholds.calibrationSamples : FEATURE_DEFAULTS.adaptiveThresholds.calibrationSamples;
    lines.push(`    \u2713 Adaptive Thresholds \u2014 calibration samples: ${cs}`);
  } else {
    lines.push('    \u2717 Adaptive Thresholds \u2014 disabled');
  }

  // Self-Training
  if (config.selfTraining) {
    const gen = config.selfTraining.generations !== undefined ? config.selfTraining.generations : FEATURE_DEFAULTS.selfTraining.generations;
    lines.push(`    \u2713 Self-Training \u2014 ${gen} generations`);
  } else {
    lines.push('    \u2717 Self-Training \u2014 disabled');
  }

  return lines.join('\n');
}

/**
 * Fluent builder for Agent Shield configuration.
 *
 * Use method chaining to enable features, then call `.build()` to get
 * a frozen, validated config object.
 */
class ShieldBuilder {
  constructor() {
    /** @private */
    this._config = {
      preset: null,
      sensitivity: 'medium',
      blockOnThreat: true,
      blockThreshold: 'medium',
      intent: null,
      learning: null,
      feedback: null,
      ensemble: null,
      goalDrift: null,
      crossTurn: null,
      toolSequence: null,
      adaptiveThresholds: null,
      selfTraining: null,
      callbacks: {
        onThreat: null,
        onDrift: null,
        onAnomaly: null
      }
    };
  }

  /**
   * Start from a named preset.
   * @param {string} name - One of the VALID_PRESETS.
   * @returns {ShieldBuilder} this
   */
  preset(name) {
    if (!VALID_PRESETS.includes(name)) {
      throw new Error(`[Agent Shield] Unknown preset "${name}". Valid presets: ${VALID_PRESETS.join(', ')}`);
    }
    this._config.preset = name;
    const presetCfg = PRESET_CONFIGS[name];
    if (presetCfg) {
      this._applyPreset(presetCfg);
    }
    return this;
  }

  /**
   * Apply a preset config to the internal state.
   * @private
   * @param {object} presetCfg
   */
  _applyPreset(presetCfg) {
    if (presetCfg.sensitivity) this._config.sensitivity = presetCfg.sensitivity;
    if (presetCfg.blockOnThreat !== undefined) this._config.blockOnThreat = presetCfg.blockOnThreat;
    if (presetCfg.blockThreshold) this._config.blockThreshold = presetCfg.blockThreshold;

    const features = ['intent', 'learning', 'feedback', 'ensemble', 'goalDrift',
      'crossTurn', 'toolSequence', 'adaptiveThresholds', 'selfTraining'];
    for (const feat of features) {
      if (presetCfg[feat] !== undefined) {
        this._config[feat] = resolveFeature(feat, presetCfg[feat]);
      }
    }
  }

  /**
   * Set detection sensitivity.
   * @param {string} level - 'low', 'medium', or 'high'.
   * @returns {ShieldBuilder} this
   */
  sensitivity(level) {
    if (!VALID_SENSITIVITIES.includes(level)) {
      throw new Error(`[Agent Shield] Invalid sensitivity "${level}". Must be one of: ${VALID_SENSITIVITIES.join(', ')}`);
    }
    this._config.sensitivity = level;
    return this;
  }

  /**
   * Enable or disable blocking on threat detection.
   * @param {boolean} bool
   * @returns {ShieldBuilder} this
   */
  blockOnThreat(bool) {
    this._config.blockOnThreat = !!bool;
    return this;
  }

  /**
   * Set the severity threshold at which blocking occurs.
   * @param {string} level - 'low', 'medium', 'high', or 'critical'.
   * @returns {ShieldBuilder} this
   */
  blockThreshold(level) {
    if (!VALID_BLOCK_THRESHOLDS.includes(level)) {
      throw new Error(`[Agent Shield] Invalid blockThreshold "${level}". Must be one of: ${VALID_BLOCK_THRESHOLDS.join(', ')}`);
    }
    this._config.blockThreshold = level;
    return this;
  }

  /**
   * Enable agent intent declaration.
   * @param {object} [opts] - { purpose, allowedTools, allowedTopics, maxDriftScore }
   * @returns {ShieldBuilder} this
   */
  enableIntent(opts) {
    this._config.intent = resolveFeature('intent', opts || true);
    if (opts && opts.purpose) this._config.intent.purpose = opts.purpose;
    if (opts && opts.allowedTools) this._config.intent.allowedTools = opts.allowedTools;
    if (opts && opts.allowedTopics) this._config.intent.allowedTopics = opts.allowedTopics;
    if (opts && opts.maxDriftScore !== undefined) this._config.intent.maxDriftScore = opts.maxDriftScore;
    return this;
  }

  /**
   * Enable persistent learning.
   * @param {object} [opts] - { persist, persistPath, promotionThreshold, maxPatterns }
   * @returns {ShieldBuilder} this
   */
  enableLearning(opts) {
    this._config.learning = resolveFeature('learning', opts || true);
    return this;
  }

  /**
   * Enable the feedback API.
   * @param {object} [opts] - { autoRetrain, maxPending, cooldownMs }
   * @returns {ShieldBuilder} this
   */
  enableFeedback(opts) {
    this._config.feedback = resolveFeature('feedback', opts || true);
    return this;
  }

  /**
   * Enable ensemble voting detection.
   * @param {object} [opts] - { voters, threshold, requireUnanimous }
   * @returns {ShieldBuilder} this
   */
  enableEnsemble(opts) {
    this._config.ensemble = resolveFeature('ensemble', opts || true);
    return this;
  }

  /**
   * Enable goal drift detection.
   * @param {object} [opts] - { checkInterval, driftThreshold, windowSize }
   * @returns {ShieldBuilder} this
   */
  enableGoalDrift(opts) {
    this._config.goalDrift = resolveFeature('goalDrift', opts || true);
    return this;
  }

  /**
   * Enable cross-turn injection tracking.
   * @param {object} [opts] - { windowSize, scanInterval, accumulateAll }
   * @returns {ShieldBuilder} this
   */
  enableCrossTurn(opts) {
    this._config.crossTurn = resolveFeature('crossTurn', opts || true);
    return this;
  }

  /**
   * Enable tool sequence modeling.
   * @param {object} [opts] - { learningPeriod, anomalyThreshold, maxChainLength }
   * @returns {ShieldBuilder} this
   */
  enableToolSequence(opts) {
    this._config.toolSequence = resolveFeature('toolSequence', opts || true);
    return this;
  }

  /**
   * Enable adaptive entropy thresholds.
   * @param {object} [opts] - { calibrationSamples, adjustInterval, minConfidence }
   * @returns {ShieldBuilder} this
   */
  enableAdaptiveThresholds(opts) {
    this._config.adaptiveThresholds = resolveFeature('adaptiveThresholds', opts || true);
    return this;
  }

  /**
   * Enable adversarial self-training.
   * @param {object} [opts] - { generations, populationSize, mutationRate, interval }
   * @returns {ShieldBuilder} this
   */
  enableSelfTraining(opts) {
    this._config.selfTraining = resolveFeature('selfTraining', opts || true);
    return this;
  }

  /**
   * Set a callback invoked when a threat is detected.
   * @param {function} callback - fn(threatInfo)
   * @returns {ShieldBuilder} this
   */
  onThreat(callback) {
    if (typeof callback !== 'function') {
      throw new Error('[Agent Shield] onThreat callback must be a function');
    }
    this._config.callbacks.onThreat = callback;
    return this;
  }

  /**
   * Set a callback invoked when goal drift is detected.
   * @param {function} callback - fn(driftInfo)
   * @returns {ShieldBuilder} this
   */
  onDrift(callback) {
    if (typeof callback !== 'function') {
      throw new Error('[Agent Shield] onDrift callback must be a function');
    }
    this._config.callbacks.onDrift = callback;
    return this;
  }

  /**
   * Set a callback invoked when an anomaly is detected.
   * @param {function} callback - fn(anomalyInfo)
   * @returns {ShieldBuilder} this
   */
  onAnomaly(callback) {
    if (typeof callback !== 'function') {
      throw new Error('[Agent Shield] onAnomaly callback must be a function');
    }
    this._config.callbacks.onAnomaly = callback;
    return this;
  }

  /**
   * Finalize and return a frozen configuration object.
   * Validates the config and throws on errors.
   * @returns {object} Frozen config object.
   */
  build() {
    const config = Object.assign({}, this._config);

    // Extract callbacks — they can't be frozen in the same way
    const callbacks = config.callbacks;
    delete config.callbacks;

    const validation = validateConfig(config);
    if (!validation.valid) {
      throw new Error(`[Agent Shield] Invalid configuration:\n  - ${validation.errors.join('\n  - ')}`);
    }

    // Attach callbacks as a non-enumerable property so they survive freezing
    Object.defineProperty(config, 'callbacks', {
      value: Object.freeze(callbacks),
      enumerable: false,
      writable: false,
      configurable: false
    });

    console.log('[Agent Shield] Configuration built' + (config.preset ? ` (preset: ${config.preset})` : ''));

    return deepFreeze(config);
  }
}

/**
 * Factory function for creating Shield configurations.
 *
 * @param {string|object|ShieldBuilder} [input] - Preset name, config object, or ShieldBuilder.
 * @returns {object|ShieldBuilder} Built config (if string/object) or new ShieldBuilder (if no input).
 */
function createShield(input) {
  // No input — return builder for chaining
  if (input === undefined || input === null) {
    return new ShieldBuilder();
  }

  // String — preset name, auto-build
  if (typeof input === 'string') {
    return new ShieldBuilder().preset(input).build();
  }

  // ShieldBuilder instance — build it
  if (input instanceof ShieldBuilder) {
    return input.build();
  }

  // Object — treat as raw config
  if (typeof input === 'object' && !Array.isArray(input)) {
    const builder = new ShieldBuilder();

    // Apply preset first if specified
    if (input.preset) {
      builder.preset(input.preset);
    }

    // Override with explicit values
    if (input.sensitivity) builder.sensitivity(input.sensitivity);
    if (input.blockOnThreat !== undefined) builder.blockOnThreat(input.blockOnThreat);
    if (input.blockThreshold) builder.blockThreshold(input.blockThreshold);

    const featureMap = {
      intent: 'enableIntent',
      learning: 'enableLearning',
      feedback: 'enableFeedback',
      ensemble: 'enableEnsemble',
      goalDrift: 'enableGoalDrift',
      crossTurn: 'enableCrossTurn',
      toolSequence: 'enableToolSequence',
      adaptiveThresholds: 'enableAdaptiveThresholds',
      selfTraining: 'enableSelfTraining'
    };

    for (const [key, method] of Object.entries(featureMap)) {
      if (input[key] !== undefined && input[key] !== false && input[key] !== null) {
        const val = input[key] === true ? undefined : input[key];
        builder[method](val);
      }
    }

    // Callbacks
    if (typeof input.onThreat === 'function') builder.onThreat(input.onThreat);
    if (typeof input.onDrift === 'function') builder.onDrift(input.onDrift);
    if (typeof input.onAnomaly === 'function') builder.onAnomaly(input.onAnomaly);

    return builder.build();
  }

  throw new Error('[Agent Shield] createShield() accepts a string, object, ShieldBuilder, or no arguments');
}

module.exports = {
  ShieldBuilder,
  createShield,
  validateConfig,
  describeConfig,
  FEATURE_DEFAULTS,
  VALID_PRESETS
};
