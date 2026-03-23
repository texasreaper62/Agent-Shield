'use strict';

/**
 * Agent Shield Pro — Main Entry Point
 *
 * Enhances the free agentshield-sdk with:
 * - Ensemble ML classifier (4-voter weighted system)
 * - Agent intent declaration + goal drift detection
 * - Tool sequence modeling (Markov chains)
 * - Persistent learning (survives restarts)
 * - Cross-turn injection tracking
 * - Adversarial self-training (12 mutation strategies)
 * - Smart config with 9 presets
 * - TUI dashboard for terminal management
 * - Lighthouse-style HTML reports
 *
 * Requires: npm install agentshield-sdk (peer dependency)
 */

const { license, LicenseManager, generateLicenseKey, validateLicenseKey, TIER_FEATURES, TIER_ORDER } = require('./license');

// Lazy-load modules to keep startup fast
function safeRequire(path) {
  try { return require(path); } catch (_e) { return {}; }
}

// Pro modules — loaded on demand
let _ensemble, _agentIntent, _persistentLearning, _crossTurn, _selfTraining, _smartConfig, _tui;
let _threatIntel, _complianceDashboard, _sso, _modelTraining;

function getEnsemble() {
  if (!_ensemble) _ensemble = safeRequire('./ensemble');
  return _ensemble;
}
function getAgentIntent() {
  if (!_agentIntent) _agentIntent = safeRequire('./agent-intent');
  return _agentIntent;
}
function getPersistentLearning() {
  if (!_persistentLearning) _persistentLearning = safeRequire('./persistent-learning');
  return _persistentLearning;
}
function getCrossTurn() {
  if (!_crossTurn) _crossTurn = safeRequire('./cross-turn');
  return _crossTurn;
}
function getSelfTraining() {
  if (!_selfTraining) _selfTraining = safeRequire('./self-training');
  return _selfTraining;
}
function getSmartConfig() {
  if (!_smartConfig) _smartConfig = safeRequire('./smart-config');
  return _smartConfig;
}
function getTui() {
  if (!_tui) _tui = safeRequire('./tui-dashboard');
  return _tui;
}

// Enterprise modules
function getThreatIntel() {
  if (!_threatIntel) _threatIntel = safeRequire('./threat-intel');
  return _threatIntel;
}
function getComplianceDashboard() {
  if (!_complianceDashboard) _complianceDashboard = safeRequire('./compliance-dashboard');
  return _complianceDashboard;
}
function getSSO() {
  if (!_sso) _sso = safeRequire('./sso');
  return _sso;
}
function getModelTraining() {
  if (!_modelTraining) _modelTraining = safeRequire('./model-training');
  return _modelTraining;
}

/**
 * Create a Pro-enhanced shield instance with smart defaults.
 *
 * @param {string|Object} configOrPreset - Preset name ('chatbot', 'coding-agent', etc.) or config object
 * @param {Object} [options] - Additional options
 * @param {string} [options.licenseKey] - License key (or set AGENT_SHIELD_LICENSE_KEY env var)
 * @param {string} [options.signingSecret] - Signing secret (or set AGENT_SHIELD_SECRET env var)
 * @returns {Object} Enhanced shield instance with pro features
 */
function createProShield(configOrPreset, options = {}) {
  const licenseKey = options.licenseKey || process.env.AGENT_SHIELD_LICENSE_KEY;
  const signingSecret = options.signingSecret || process.env.AGENT_SHIELD_SECRET;

  // Activate license if provided
  if (licenseKey && signingSecret) {
    const result = license.activate(licenseKey, signingSecret);
    if (!result.activated) {
      console.warn(`[Agent Shield Pro] License activation failed: ${result.error}`);
    }
  }

  // Build config from preset or direct config
  const smartConfig = getSmartConfig();
  let config;
  if (typeof configOrPreset === 'string' && smartConfig.createShield) {
    config = smartConfig.createShield(configOrPreset);
  } else if (typeof configOrPreset === 'object') {
    config = configOrPreset;
  } else {
    config = {};
  }

  // Try to load the free SDK
  let AgentShield;
  try {
    const sdk = require('agentshield-sdk');
    AgentShield = sdk.AgentShield || sdk.default;
  } catch (_e) {
    // Fallback: try relative path (for monorepo development)
    try {
      const sdk = require('../../src/index');
      AgentShield = sdk;
    } catch (_e2) {
      throw new Error('[Agent Shield Pro] agentshield-sdk is required. Run: npm install agentshield-sdk');
    }
  }

  const shield = new AgentShield(config);

  // Attach pro modules
  const proFeatures = {};

  // Ensemble classifier
  const ensemble = getEnsemble();
  if (ensemble.EnsembleClassifier) {
    proFeatures.ensemble = new ensemble.EnsembleClassifier(config.ensemble || {});
    proFeatures.ensembleScan = (text) => {
      license.requireFeature('ensemble', 'Ensemble classifier');
      return proFeatures.ensemble.classify(text);
    };
  }

  // Agent intent + goal drift
  const intent = getAgentIntent();
  if (intent.AgentIntentGuard) {
    proFeatures.intentGuard = new intent.AgentIntentGuard(config.intent || {});
    proFeatures.declareIntent = (agentId, purposeDeclaration) => {
      license.requireFeature('agent-intent', 'Agent intent declaration');
      return proFeatures.intentGuard.declare(agentId, purposeDeclaration);
    };
    proFeatures.checkDrift = (agentId, currentContext) => {
      license.requireFeature('goal-drift', 'Goal drift detection');
      return proFeatures.intentGuard.checkDrift(agentId, currentContext);
    };
  }

  // Tool sequence modeling
  if (intent.ToolSequenceModel) {
    proFeatures.toolSequence = new intent.ToolSequenceModel(config.toolSequence || {});
    proFeatures.recordToolCall = (agentId, toolName) => {
      license.requireFeature('tool-sequence', 'Tool sequence modeling');
      return proFeatures.toolSequence.record(agentId, toolName);
    };
  }

  // Persistent learning
  const learning = getPersistentLearning();
  if (learning.PersistentLearner) {
    proFeatures.learner = new learning.PersistentLearner(config.learning || {});
    proFeatures.reportFalsePositive = (scanId, details) => {
      license.requireFeature('persistent-learning', 'Persistent learning');
      return proFeatures.learner.reportFP(scanId, details);
    };
    proFeatures.reportFalseNegative = (text, details) => {
      license.requireFeature('persistent-learning', 'Persistent learning');
      return proFeatures.learner.reportFN(text, details);
    };
  }

  // Cross-turn tracking
  const crossTurn = getCrossTurn();
  if (crossTurn.CrossTurnTracker) {
    proFeatures.crossTurn = new crossTurn.CrossTurnTracker(config.crossTurn || {});
    proFeatures.scanConversation = (sessionId, messages) => {
      license.requireFeature('cross-turn', 'Cross-turn tracking');
      return proFeatures.crossTurn.scan(sessionId, messages);
    };
  }

  // Self-training
  const selfTraining = getSelfTraining();
  if (selfTraining.SelfTrainer) {
    proFeatures.trainer = new selfTraining.SelfTrainer(config.selfTraining || {});
    proFeatures.runTrainingCycle = () => {
      license.requireFeature('self-training', 'Adversarial self-training');
      return proFeatures.trainer.runCycle(shield);
    };
  }

  // Enterprise: Threat intelligence feed
  const threatIntel = getThreatIntel();
  if (threatIntel.ThreatIntelFeed) {
    proFeatures.threatFeed = new threatIntel.ThreatIntelFeed({
      orgId: license.orgId || config.orgId,
      ...config.threatIntel,
    });
    proFeatures.getThreatFeed = () => {
      license.requireFeature('threat-intel-feed', 'Threat intelligence feed');
      return proFeatures.threatFeed;
    };
    proFeatures.checkThreatFeed = (text) => {
      license.requireFeature('threat-intel-feed', 'Threat intelligence feed');
      return proFeatures.threatFeed.check(text);
    };
    proFeatures.submitThreat = (report) => {
      license.requireFeature('threat-intel-feed', 'Threat intelligence feed');
      return proFeatures.threatFeed.submit(report);
    };
  }

  // Enterprise: Compliance dashboard
  const complianceDash = getComplianceDashboard();
  if (complianceDash.ComplianceDashboard) {
    proFeatures.complianceDashboard = new complianceDash.ComplianceDashboard({
      orgInfo: { name: license._license?.orgName, id: license.orgId },
      ...config.compliance,
    });
    // Auto-detect modules from config
    proFeatures.complianceDashboard.detectModules(shield, config);
    proFeatures.getCompliancePosture = () => {
      license.requireFeature('compliance-dashboard', 'Compliance dashboard');
      return proFeatures.complianceDashboard.getPosture();
    };
    proFeatures.getComplianceReport = (frameworkId) => {
      license.requireFeature('compliance-dashboard', 'Compliance dashboard');
      return proFeatures.complianceDashboard.generateReport(frameworkId);
    };
    proFeatures.getComplianceHTML = (htmlOptions) => {
      license.requireFeature('compliance-dashboard', 'Compliance dashboard');
      return proFeatures.complianceDashboard.generateHTML(htmlOptions);
    };
  }

  // Enterprise: SSO integration
  const sso = getSSO();
  if (sso.SSOIntegration) {
    proFeatures.sso = new sso.SSOIntegration(config.sso || {});
    proFeatures.ssoAuthenticate = (identity) => {
      license.requireFeature('sso-integration', 'SSO integration');
      return proFeatures.sso.authenticate(identity);
    };
    proFeatures.ssoValidate = (sessionId, permission) => {
      license.requireFeature('sso-integration', 'SSO integration');
      return proFeatures.sso.validate(sessionId, permission);
    };
    proFeatures.ssoMiddleware = (middlewareOptions) => {
      license.requireFeature('sso-integration', 'SSO integration');
      return proFeatures.sso.middleware(middlewareOptions);
    };
  }

  // Enterprise: Custom model training
  const modelTraining = getModelTraining();
  if (modelTraining.ModelTrainingPipeline) {
    proFeatures.training = new modelTraining.ModelTrainingPipeline(config.training || {});
    proFeatures.trainModel = () => {
      license.requireFeature('custom-model-training', 'Custom model training');
      return proFeatures.training.train();
    };
    proFeatures.addTrainingSample = (text, label, metadata) => {
      license.requireFeature('custom-model-training', 'Custom model training');
      return proFeatures.training.addSample(text, label, metadata);
    };
    proFeatures.predictWithModel = (text) => {
      license.requireFeature('custom-model-training', 'Custom model training');
      return proFeatures.training.predict(text);
    };
  }

  // Combine into enhanced shield
  const proShield = Object.create(shield);
  Object.assign(proShield, proFeatures);

  // Enhanced scan that runs ensemble if licensed
  const originalScan = shield.scan.bind(shield);
  proShield.scan = function(text, options) {
    const baseResult = originalScan(text, options);

    // If ensemble is available and licensed, add ensemble vote
    if (proFeatures.ensemble && license.hasFeature('ensemble')) {
      try {
        const ensembleResult = proFeatures.ensemble.classify(text);
        baseResult.ensemble = ensembleResult;
        // Upgrade severity if ensemble disagrees and has higher confidence
        if (ensembleResult.isInjection && baseResult.status === 'safe') {
          baseResult.status = 'warning';
          baseResult.threats = baseResult.threats || [];
          baseResult.threats.push({
            category: 'ensemble_detection',
            severity: ensembleResult.severity || 'medium',
            description: ensembleResult.reason || 'Ensemble classifier detected potential injection',
            confidence: ensembleResult.confidence,
            source: 'ensemble'
          });
        }
      } catch (_e) {
        // Ensemble failure is non-fatal
      }
    }

    return baseResult;
  };

  // License info
  proShield.license = license;
  proShield.getLicenseStatus = () => license.getStatus();

  return proShield;
}

module.exports = {
  // Main API
  createProShield,

  // License management
  license,
  LicenseManager,
  generateLicenseKey,
  validateLicenseKey,
  TIER_FEATURES,
  TIER_ORDER,

  // Module access (for advanced users)
  getEnsemble,
  getAgentIntent,
  getPersistentLearning,
  getCrossTurn,
  getSelfTraining,
  getSmartConfig,
  getTui,

  // Enterprise modules
  getThreatIntel,
  getComplianceDashboard,
  getSSO,
  getModelTraining
};
