'use strict';

// Smart Configuration System for Agent Shield Pro
// Zero external dependencies — pure Node.js

/**
 * Sensitivity levels mapped to numeric thresholds.
 * @type {Object<string, number>}
 */
const SENSITIVITY_LEVELS = {
  low: 0.3,
  medium: 0.5,
  high: 0.7,
  maximum: 0.9
};

/**
 * Preset configurations for common agent types.
 * Each preset provides a complete config object suitable for AgentShield.
 * @type {Object<string, Object>}
 */
const PRESETS = {
  chatbot: {
    name: 'chatbot',
    description: 'General-purpose chatbot with strong injection protection',
    sensitivity: 'high',
    sensitivityThreshold: SENSITIVITY_LEVELS.high,
    blockOnThreat: true,
    pii: { enabled: true, redact: true, categories: ['email', 'phone', 'ssn', 'creditCard', 'address'] },
    dlp: { enabled: false },
    toolGuard: { enabled: true, mode: 'moderate', blockedTools: [], restrictShell: false },
    ipia: { enabled: false },
    ensemble: { enabled: false },
    crossTurn: { enabled: false },
    intentGuard: { enabled: false },
    compliance: {},
    audit: { enabled: false },
    shadowMode: false,
    logging: 'standard',
    ragScanning: false,
    mcpRuntime: false,
    contentPolicy: 'standard',
    batchMode: false
  },

  'coding-agent': {
    name: 'coding-agent',
    description: 'Code generation agent with strict tool boundaries',
    sensitivity: 'medium',
    sensitivityThreshold: SENSITIVITY_LEVELS.medium,
    blockOnThreat: false,
    blockCriticalOnly: true,
    pii: { enabled: false },
    dlp: { enabled: false },
    toolGuard: {
      enabled: true,
      mode: 'strict',
      blockedTools: ['shell', 'exec', 'spawn', 'system'],
      fileAccess: 'restricted',
      allowedPaths: ['/workspace', '/tmp']
    },
    ipia: { enabled: false },
    ensemble: { enabled: false },
    crossTurn: { enabled: false },
    intentGuard: { enabled: false },
    compliance: {},
    audit: { enabled: false },
    shadowMode: false,
    logging: 'standard',
    ragScanning: false,
    mcpRuntime: false,
    contentPolicy: 'standard',
    batchMode: false
  },

  'rag-pipeline': {
    name: 'rag-pipeline',
    description: 'RAG pipeline with IPIA detection and batch optimization',
    sensitivity: 'high',
    sensitivityThreshold: SENSITIVITY_LEVELS.high,
    blockOnThreat: true,
    pii: { enabled: false },
    dlp: { enabled: false },
    toolGuard: { enabled: false },
    ipia: { enabled: true, contextWindow: 4096, embeddingBackend: 'tfidf' },
    ensemble: { enabled: false },
    crossTurn: { enabled: false },
    intentGuard: { enabled: false },
    compliance: {},
    audit: { enabled: false },
    shadowMode: false,
    logging: 'standard',
    ragScanning: true,
    mcpRuntime: false,
    contentPolicy: 'standard',
    batchMode: true,
    batchSize: 50
  },

  'customer-support': {
    name: 'customer-support',
    description: 'Customer-facing support agent with PII and DLP protection',
    sensitivity: 'high',
    sensitivityThreshold: SENSITIVITY_LEVELS.high,
    blockOnThreat: true,
    pii: { enabled: true, redact: true, categories: ['email', 'phone', 'ssn', 'creditCard', 'address', 'name'] },
    dlp: { enabled: true, rules: ['no-internal-urls', 'no-credentials', 'no-api-keys', 'no-customer-data'] },
    toolGuard: { enabled: true, mode: 'moderate' },
    ipia: { enabled: false },
    ensemble: { enabled: false },
    crossTurn: { enabled: false },
    intentGuard: { enabled: false },
    compliance: {},
    audit: { enabled: true, level: 'standard' },
    shadowMode: false,
    logging: 'standard',
    ragScanning: false,
    mcpRuntime: false,
    contentPolicy: 'strict',
    batchMode: false
  },

  'research-assistant': {
    name: 'research-assistant',
    description: 'Research agent with broad access and verbose logging',
    sensitivity: 'low',
    sensitivityThreshold: SENSITIVITY_LEVELS.low,
    blockOnThreat: false,
    pii: { enabled: false },
    dlp: { enabled: false },
    toolGuard: { enabled: true, mode: 'permissive', blockedTools: [] },
    ipia: { enabled: false },
    ensemble: { enabled: false },
    crossTurn: { enabled: false },
    intentGuard: { enabled: false },
    compliance: {},
    audit: { enabled: false },
    shadowMode: true,
    logging: 'verbose',
    ragScanning: false,
    mcpRuntime: false,
    contentPolicy: 'standard',
    batchMode: false
  },

  'financial-agent': {
    name: 'financial-agent',
    description: 'Financial operations agent with maximum security and full compliance',
    sensitivity: 'maximum',
    sensitivityThreshold: SENSITIVITY_LEVELS.maximum,
    blockOnThreat: true,
    pii: { enabled: true, redact: true, categories: ['email', 'phone', 'ssn', 'creditCard', 'address', 'name', 'accountNumber'] },
    dlp: { enabled: true, mode: 'strict', rules: ['no-financials', 'no-credentials', 'no-pii', 'no-internal-data'] },
    toolGuard: { enabled: true, mode: 'strict', blockedTools: ['shell', 'exec'] },
    ipia: { enabled: true },
    ensemble: { enabled: false },
    crossTurn: { enabled: true },
    intentGuard: { enabled: true },
    compliance: { soc2: true, gdpr: true, pci: true },
    audit: { enabled: true, level: 'full', immutable: true },
    shadowMode: false,
    logging: 'verbose',
    ragScanning: false,
    mcpRuntime: false,
    contentPolicy: 'strict',
    batchMode: false
  },

  'healthcare-agent': {
    name: 'healthcare-agent',
    description: 'Healthcare agent with HIPAA compliance and strict PII handling',
    sensitivity: 'maximum',
    sensitivityThreshold: SENSITIVITY_LEVELS.maximum,
    blockOnThreat: true,
    pii: { enabled: true, redact: true, mode: 'strict', categories: ['email', 'phone', 'ssn', 'address', 'name', 'dob', 'mrn', 'diagnosis'] },
    dlp: { enabled: true, mode: 'strict', rules: ['no-phi', 'no-pii', 'no-credentials'] },
    toolGuard: { enabled: true, mode: 'strict' },
    ipia: { enabled: true },
    ensemble: { enabled: false },
    crossTurn: { enabled: true },
    intentGuard: { enabled: true },
    compliance: { hipaa: true, soc2: true },
    audit: { enabled: true, level: 'full', immutable: true },
    shadowMode: false,
    logging: 'verbose',
    ragScanning: false,
    mcpRuntime: false,
    contentPolicy: 'strict',
    batchMode: false
  },

  'devops-agent': {
    name: 'devops-agent',
    description: 'Infrastructure agent with restricted shell and credential blocking',
    sensitivity: 'medium',
    sensitivityThreshold: SENSITIVITY_LEVELS.medium,
    blockOnThreat: true,
    pii: { enabled: false },
    dlp: { enabled: true, rules: ['no-credentials', 'no-api-keys', 'no-secrets', 'no-private-keys'] },
    toolGuard: {
      enabled: true,
      mode: 'infra-only',
      allowedTools: ['kubectl', 'docker', 'terraform', 'helm', 'aws', 'gcloud', 'az'],
      restrictShell: true,
      blockedCommands: ['rm -rf /', 'dd if=', 'mkfs', ':(){:|:&};:']
    },
    ipia: { enabled: false },
    ensemble: { enabled: false },
    crossTurn: { enabled: false },
    intentGuard: { enabled: false },
    compliance: {},
    audit: { enabled: true, level: 'standard' },
    shadowMode: false,
    logging: 'standard',
    ragScanning: false,
    mcpRuntime: false,
    contentPolicy: 'standard',
    batchMode: false
  },

  'mcp-server': {
    name: 'mcp-server',
    description: 'MCP server with full runtime security, sessions, and auth',
    sensitivity: 'high',
    sensitivityThreshold: SENSITIVITY_LEVELS.high,
    blockOnThreat: true,
    pii: { enabled: true, redact: true },
    dlp: { enabled: false },
    toolGuard: { enabled: true, mode: 'strict', scanToolOutputs: true },
    ipia: { enabled: true },
    ensemble: { enabled: false },
    crossTurn: { enabled: false },
    intentGuard: { enabled: false },
    compliance: {},
    audit: { enabled: true, level: 'standard' },
    shadowMode: false,
    logging: 'standard',
    ragScanning: false,
    mcpRuntime: true,
    mcpConfig: {
      sessionManagement: true,
      toolScanning: true,
      authRequired: true,
      rateLimiting: { enabled: true, maxPerMinute: 60 }
    },
    contentPolicy: 'standard',
    batchMode: false
  }
};

/**
 * Deep merges source into target, returning a new object.
 * Arrays are replaced, not concatenated.
 * @param {Object} target - Base object
 * @param {Object} source - Override object
 * @returns {Object} Merged result
 */
function deepMerge(target, source) {
  const result = Object.assign({}, target);
  for (const key of Object.keys(source)) {
    if (
      source[key] &&
      typeof source[key] === 'object' &&
      !Array.isArray(source[key]) &&
      target[key] &&
      typeof target[key] === 'object' &&
      !Array.isArray(target[key])
    ) {
      result[key] = deepMerge(target[key], source[key]);
    } else {
      result[key] = source[key];
    }
  }
  return result;
}

/**
 * Creates a shield configuration from a named preset, optionally merged with overrides.
 * @param {string} presetName - One of the PRESETS keys (e.g. 'chatbot', 'rag-pipeline')
 * @param {Object} [overrides={}] - Partial config to merge on top of the preset
 * @returns {Object} Complete shield configuration object
 * @throws {Error} If preset name is not recognized
 */
function createShield(presetName, overrides) {
  if (!PRESETS[presetName]) {
    const available = Object.keys(PRESETS).join(', ');
    throw new Error(`[Agent Shield Pro] Unknown preset "${presetName}". Available: ${available}`);
  }
  const base = JSON.parse(JSON.stringify(PRESETS[presetName]));
  if (!overrides || Object.keys(overrides).length === 0) {
    console.log(`[Agent Shield Pro] Created shield from preset: ${presetName}`);
    return base;
  }
  const merged = deepMerge(base, overrides);
  console.log(`[Agent Shield Pro] Created shield from preset: ${presetName} (with overrides)`);
  return merged;
}

/**
 * Fluent builder for constructing shield configurations step by step.
 * Use ShieldBuilder.from(preset) to start, chain methods, and call .build().
 */
class ShieldBuilder {
  /**
   * @param {Object} config - Initial configuration object
   */
  constructor(config) {
    this._config = JSON.parse(JSON.stringify(config));
    this._license = null;
  }

  /**
   * Creates a new ShieldBuilder starting from a named preset.
   * @param {string} presetName - Preset key (e.g. 'chatbot')
   * @returns {ShieldBuilder} New builder instance
   * @throws {Error} If preset name is not recognized
   */
  static from(presetName) {
    if (!PRESETS[presetName]) {
      const available = Object.keys(PRESETS).join(', ');
      throw new Error(`[Agent Shield Pro] Unknown preset "${presetName}". Available: ${available}`);
    }
    return new ShieldBuilder(PRESETS[presetName]);
  }

  /**
   * Sets the detection sensitivity level.
   * @param {string} level - 'low' | 'medium' | 'high' | 'maximum'
   * @returns {ShieldBuilder} this (for chaining)
   */
  sensitivity(level) {
    if (!SENSITIVITY_LEVELS[level]) {
      throw new Error(`[Agent Shield Pro] Invalid sensitivity "${level}". Use: low, medium, high, maximum`);
    }
    this._config.sensitivity = level;
    this._config.sensitivityThreshold = SENSITIVITY_LEVELS[level];
    return this;
  }

  /**
   * Sets whether to block when a threat is detected.
   * @param {boolean} enabled - true to block, false to allow with warning
   * @returns {ShieldBuilder} this
   */
  blockOnThreat(enabled) {
    this._config.blockOnThreat = !!enabled;
    return this;
  }

  /**
   * Enables or disables PII redaction.
   * @param {boolean} enabled - Whether PII detection/redaction is on
   * @returns {ShieldBuilder} this
   */
  enablePII(enabled) {
    if (typeof enabled === 'boolean') {
      this._config.pii = { enabled, redact: enabled };
    } else {
      this._config.pii = Object.assign({ enabled: true, redact: true }, enabled);
    }
    return this;
  }

  /**
   * Enables DLP with the specified rules.
   * @param {Object|string[]} rules - DLP rule names or full config object
   * @returns {ShieldBuilder} this
   */
  enableDLP(rules) {
    if (Array.isArray(rules)) {
      this._config.dlp = { enabled: true, rules };
    } else if (typeof rules === 'object') {
      this._config.dlp = Object.assign({ enabled: true }, rules);
    } else {
      this._config.dlp = { enabled: !!rules };
    }
    return this;
  }

  /**
   * Enables the tool guard with the given configuration.
   * @param {Object} config - Tool guard settings (mode, blockedTools, etc.)
   * @returns {ShieldBuilder} this
   */
  enableToolGuard(config) {
    this._config.toolGuard = Object.assign({ enabled: true }, config || {});
    return this;
  }

  /**
   * Enables indirect prompt injection attack detection.
   * @param {Object} config - IPIA settings (contextWindow, embeddingBackend, etc.)
   * @returns {ShieldBuilder} this
   */
  enableIPIA(config) {
    this._config.ipia = Object.assign({ enabled: true }, config || {});
    return this;
  }

  /**
   * Enables ensemble detection combining multiple engines.
   * @param {Object} config - Ensemble settings (engines, votingStrategy, etc.)
   * @returns {ShieldBuilder} this
   */
  enableEnsemble(config) {
    this._config.ensemble = Object.assign({ enabled: true }, config || {});
    return this;
  }

  /**
   * Enables cross-turn conversation analysis.
   * @param {Object} config - Cross-turn settings (windowSize, etc.)
   * @returns {ShieldBuilder} this
   */
  enableCrossTurn(config) {
    this._config.crossTurn = Object.assign({ enabled: true }, config || {});
    return this;
  }

  /**
   * Enables intent-based threat detection.
   * @param {Object} config - Intent guard settings
   * @returns {ShieldBuilder} this
   */
  enableIntentGuard(config) {
    this._config.intentGuard = Object.assign({ enabled: true }, config || {});
    return this;
  }

  /**
   * Attaches a Pro license key and secret.
   * @param {string} key - License key
   * @param {string} secret - License secret
   * @returns {ShieldBuilder} this
   */
  withLicense(key, secret) {
    this._license = { key, secret };
    return this;
  }

  /**
   * Builds and returns the final configuration object.
   * @returns {Object} Complete shield configuration
   */
  build() {
    const config = JSON.parse(JSON.stringify(this._config));
    if (this._license) {
      config.license = { key: this._license.key, secret: this._license.secret };
    }
    console.log(`[Agent Shield Pro] Built config from preset: ${config.name || 'custom'} (sensitivity: ${config.sensitivity})`);
    return config;
  }
}

module.exports = {
  PRESETS,
  SENSITIVITY_LEVELS,
  createShield,
  ShieldBuilder,
  deepMerge
};
