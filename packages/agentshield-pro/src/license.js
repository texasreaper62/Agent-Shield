'use strict';

/**
 * Agent Shield Pro — License Key System
 *
 * HMAC-SHA256 signed license keys with:
 * - Tier validation (pro/team/enterprise)
 * - Expiration dates
 * - Org ID binding
 * - Feature entitlements
 * - Offline validation (no cloud calls)
 *
 * Key format: AS-{tier}-{base64 payload}.{hmac signature}
 */

const crypto = require('crypto');

/** @type {string} */
const LICENSE_PREFIX = 'AS';

/** @type {Object<string, string[]>} */
const TIER_FEATURES = {
  pro: [
    'ensemble', 'persistent-learning', 'smart-config',
    'cross-turn', 'self-training', 'html-report',
    'pre-deploy-audit', 'cli-pentest'
  ],
  team: [
    'ensemble', 'persistent-learning', 'smart-config',
    'cross-turn', 'self-training', 'html-report',
    'pre-deploy-audit', 'cli-pentest',
    'agent-intent', 'goal-drift', 'tool-sequence',
    'tui-dashboard', 'priority-support'
  ],
  enterprise: [
    'ensemble', 'persistent-learning', 'smart-config',
    'cross-turn', 'self-training', 'html-report',
    'pre-deploy-audit', 'cli-pentest',
    'agent-intent', 'goal-drift', 'tool-sequence',
    'tui-dashboard', 'priority-support',
    'threat-intel-feed', 'compliance-dashboard',
    'custom-model-training', 'sso-integration',
    'dedicated-support', 'sla'
  ]
};

const TIER_ORDER = { pro: 1, team: 2, enterprise: 3 };

/**
 * Generate a license key.
 * @param {Object} options
 * @param {string} options.tier - 'pro' | 'team' | 'enterprise'
 * @param {string} options.orgId - Organization identifier
 * @param {string} options.orgName - Organization display name
 * @param {string} options.signingSecret - HMAC secret (keep private)
 * @param {number} [options.expiresInDays=365] - Days until expiration
 * @param {number} [options.seats=1] - Number of licensed seats
 * @param {string[]} [options.extraFeatures=[]] - Additional feature flags
 * @returns {{ key: string, payload: Object }}
 */
function generateLicenseKey(options = {}) {
  const {
    tier,
    orgId,
    orgName,
    signingSecret,
    expiresInDays = 365,
    seats = 1,
    extraFeatures = []
  } = options;

  if (!tier || !TIER_FEATURES[tier]) {
    throw new Error(`[Agent Shield] Invalid tier: ${tier}. Must be one of: ${Object.keys(TIER_FEATURES).join(', ')}`);
  }
  if (!orgId || typeof orgId !== 'string') {
    throw new Error('[Agent Shield] orgId is required');
  }
  if (!signingSecret || typeof signingSecret !== 'string') {
    throw new Error('[Agent Shield] signingSecret is required');
  }

  const now = Date.now();
  const payload = {
    v: 1,
    tier,
    orgId,
    orgName: orgName || orgId,
    seats,
    features: [...new Set([...TIER_FEATURES[tier], ...extraFeatures])],
    issuedAt: now,
    expiresAt: now + (expiresInDays * 24 * 60 * 60 * 1000),
    keyId: crypto.randomUUID()
  };

  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto
    .createHmac('sha256', signingSecret)
    .update(payloadB64)
    .digest('hex');

  const key = `${LICENSE_PREFIX}-${tier.toUpperCase()}-${payloadB64}.${signature}`;

  return { key, payload };
}

/**
 * Validate a license key.
 * @param {string} key - The license key string
 * @param {string} signingSecret - The HMAC secret used to sign
 * @returns {{ valid: boolean, payload?: Object, error?: string, tier?: string, features?: string[] }}
 */
function validateLicenseKey(key, signingSecret) {
  if (!key || typeof key !== 'string') {
    return { valid: false, error: 'Missing or invalid license key' };
  }
  if (!signingSecret || typeof signingSecret !== 'string') {
    return { valid: false, error: 'Missing signing secret' };
  }

  // Parse key format: AS-TIER-{base64payload}.{signature}
  const dotIndex = key.lastIndexOf('.');
  if (dotIndex === -1) {
    return { valid: false, error: 'Invalid key format: missing signature' };
  }

  const prefix = key.substring(0, dotIndex);
  const signature = key.substring(dotIndex + 1);

  // Extract payload (skip AS-TIER- prefix)
  const parts = prefix.split('-');
  if (parts.length < 3 || parts[0] !== LICENSE_PREFIX) {
    return { valid: false, error: 'Invalid key format: missing AS prefix' };
  }

  const payloadB64 = parts.slice(2).join('-');

  // Verify HMAC signature
  const expectedSig = crypto
    .createHmac('sha256', signingSecret)
    .update(payloadB64)
    .digest('hex');

  // Timing-safe comparison
  if (signature.length !== expectedSig.length) {
    return { valid: false, error: 'Invalid signature' };
  }
  const sigBuffer = Buffer.from(signature, 'hex');
  const expectedBuffer = Buffer.from(expectedSig, 'hex');
  if (sigBuffer.length !== expectedBuffer.length || !crypto.timingSafeEqual(sigBuffer, expectedBuffer)) {
    return { valid: false, error: 'Invalid signature' };
  }

  // Decode payload
  let payload;
  try {
    payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf-8'));
  } catch (_e) {
    return { valid: false, error: 'Corrupted payload' };
  }

  // Check expiration
  if (payload.expiresAt && Date.now() > payload.expiresAt) {
    return { valid: false, error: 'License expired', payload };
  }

  // Check required fields
  if (!payload.tier || !payload.orgId || !payload.features) {
    return { valid: false, error: 'Incomplete license payload' };
  }

  // Verify prefix tier matches payload tier
  const prefixTier = parts[1];
  if (prefixTier && prefixTier.toLowerCase() !== payload.tier) {
    return { valid: false, error: 'Key prefix does not match payload tier (possible tampering)' };
  }

  return {
    valid: true,
    payload,
    tier: payload.tier,
    features: payload.features
  };
}

/**
 * License manager — singleton that holds the active license and gates features.
 */
class LicenseManager {
  constructor() {
    /** @type {Object|null} */
    this._license = null;
    /** @type {string|null} */
    this._key = null;
    /** @type {Set<string>} */
    this._features = new Set();
    /** @type {string|null} */
    this._tier = null;
  }

  /**
   * Activate a license key.
   * @param {string} key - License key
   * @param {string} signingSecret - HMAC secret
   * @returns {{ activated: boolean, tier?: string, features?: string[], error?: string }}
   */
  activate(key, signingSecret) {
    const result = validateLicenseKey(key, signingSecret);
    if (!result.valid) {
      return { activated: false, error: result.error };
    }

    this._license = result.payload;
    this._key = key;
    this._tier = result.tier;
    this._features = new Set(result.features);

    return {
      activated: true,
      tier: this._tier,
      features: Array.from(this._features),
      orgId: result.payload.orgId,
      orgName: result.payload.orgName,
      expiresAt: new Date(result.payload.expiresAt).toISOString()
    };
  }

  /**
   * Deactivate current license.
   */
  deactivate() {
    this._license = null;
    this._key = null;
    this._features = new Set();
    this._tier = null;
  }

  /**
   * Check if a specific feature is licensed.
   * @param {string} feature - Feature name
   * @returns {boolean}
   */
  hasFeature(feature) {
    return this._features.has(feature);
  }

  /**
   * Check if current tier meets minimum requirement.
   * @param {string} minTier - Minimum tier required
   * @returns {boolean}
   */
  hasTier(minTier) {
    if (!this._tier) return false;
    return (TIER_ORDER[this._tier] || 0) >= (TIER_ORDER[minTier] || 0);
  }

  /**
   * Require a feature — throws if not licensed.
   * @param {string} feature - Feature name
   * @param {string} [context] - Context for error message
   */
  requireFeature(feature, context) {
    if (!this.hasFeature(feature)) {
      const msg = context
        ? `[Agent Shield Pro] ${context} requires the '${feature}' feature. Upgrade at https://agentshield.dev/pricing`
        : `[Agent Shield Pro] Feature '${feature}' requires a Pro license. Upgrade at https://agentshield.dev/pricing`;
      throw new Error(msg);
    }
  }

  /**
   * Get license status.
   * @returns {Object}
   */
  getStatus() {
    if (!this._license) {
      return { licensed: false, tier: 'community', features: [] };
    }
    return {
      licensed: true,
      tier: this._tier,
      orgId: this._license.orgId,
      orgName: this._license.orgName,
      seats: this._license.seats,
      features: Array.from(this._features),
      expiresAt: new Date(this._license.expiresAt).toISOString(),
      daysRemaining: Math.max(0, Math.ceil((this._license.expiresAt - Date.now()) / (24 * 60 * 60 * 1000)))
    };
  }

  /** @returns {boolean} */
  get isLicensed() {
    return this._license !== null;
  }

  /** @returns {string|null} */
  get tier() {
    return this._tier;
  }

  /** @returns {string|null} */
  get orgId() {
    return this._license ? this._license.orgId : null;
  }
}

// Singleton instance
const license = new LicenseManager();

module.exports = {
  generateLicenseKey,
  validateLicenseKey,
  LicenseManager,
  license,
  TIER_FEATURES,
  TIER_ORDER,
  LICENSE_PREFIX
};
