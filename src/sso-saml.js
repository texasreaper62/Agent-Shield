'use strict';

/**
 * Agent Shield — SSO/SAML Integration
 *
 * Ties RBAC to enterprise identity providers. Supports SAML, OIDC, and LDAP
 * provider types. All processing is local — no external calls are made.
 *
 * - SSOManager: Main SSO orchestration
 * - SAMLParser: SAML assertion parsing and validation (simulated)
 * - OIDCHandler: OpenID Connect flow handling
 * - IdentityMapper: Maps IdP identities to Agent Shield RBAC roles
 * - SSOSession: Session management with TTL and permissions
 */

const crypto = require('crypto');

// =========================================================================
// SSOSession
// =========================================================================

/**
 * Represents an authenticated SSO session.
 */
class SSOSession {
  /**
   * @param {object} identity - The user identity from the IdP.
   * @param {string} role - The mapped Agent Shield RBAC role.
   * @param {string[]} permissions - List of granted permissions.
   * @param {number} ttl - Session time-to-live in milliseconds.
   */
  constructor(identity, role, permissions, ttl) {
    this.id = crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex');
    this.identity = identity;
    this.role = role;
    this.permissions = permissions || [];
    this.ttl = ttl || 3600000;
    this.createdAt = Date.now();
    this.expiresAt = this.createdAt + this.ttl;
    this.revoked = false;
  }

  /**
   * Check whether the session is still valid (not expired, not revoked).
   * @returns {boolean}
   */
  isValid() {
    if (this.revoked) return false;
    return Date.now() < this.expiresAt;
  }

  /**
   * Check whether the session has a specific permission.
   * @param {string} permission - Permission string to check.
   * @returns {boolean}
   */
  hasPermission(permission) {
    if (!this.isValid()) return false;
    return this.permissions.includes('*') || this.permissions.includes(permission);
  }

  /**
   * Serializable representation of the session.
   * @returns {object}
   */
  toJSON() {
    return {
      id: this.id,
      identity: this.identity,
      role: this.role,
      permissions: this.permissions,
      createdAt: new Date(this.createdAt).toISOString(),
      expiresAt: new Date(this.expiresAt).toISOString(),
      revoked: this.revoked,
      valid: this.isValid()
    };
  }
}

// =========================================================================
// IdentityMapper
// =========================================================================

/**
 * Default group-to-role mappings for common IdP groups.
 */
const DEFAULT_MAPPINGS = [
  { idpGroup: 'admins', shieldRole: 'admin', permissions: ['*'] },
  { idpGroup: 'security', shieldRole: 'analyst', permissions: ['scan', 'read', 'audit', 'configure', 'view_audit', 'manage_policies', 'view_reports'] },
  { idpGroup: 'developers', shieldRole: 'operator', permissions: ['scan', 'read', 'configure', 'view_reports'] },
  { idpGroup: '*', shieldRole: 'viewer', permissions: ['read', 'view_reports'] }
];

/**
 * Maps IdP identities (groups/attributes) to Agent Shield RBAC roles.
 */
class IdentityMapper {
  /**
   * @param {Array<{idpGroup: string, shieldRole: string, permissions: string[]}>} [mappingRules]
   */
  constructor(mappingRules) {
    this.rules = mappingRules ? [...mappingRules] : [...DEFAULT_MAPPINGS];
  }

  /**
   * Add a mapping rule.
   * @param {{idpGroup: string, shieldRole: string, permissions: string[]}} rule
   */
  addRule(rule) {
    if (!rule || !rule.idpGroup || !rule.shieldRole) {
      throw new Error('[Agent Shield] Mapping rule must have idpGroup and shieldRole');
    }
    // Insert before the wildcard rule if one exists
    const wildcardIdx = this.rules.findIndex(r => r.idpGroup === '*');
    if (wildcardIdx >= 0) {
      this.rules.splice(wildcardIdx, 0, rule);
    } else {
      this.rules.push(rule);
    }
    return this;
  }

  /**
   * Map an identity to a role and permissions based on the identity's groups.
   * @param {object} identity - Identity object with a groups array.
   * @returns {{role: string, permissions: string[]}}
   */
  mapIdentity(identity) {
    const groups = identity.groups || [];
    let matchedRole = null;
    let matchedPermissions = [];

    for (const rule of this.rules) {
      if (rule.idpGroup === '*' || groups.includes(rule.idpGroup)) {
        matchedRole = rule.shieldRole;
        matchedPermissions = [...(rule.permissions || [])];
        break;
      }
    }

    // Fallback to viewer if no rule matched
    if (!matchedRole) {
      matchedRole = 'viewer';
      matchedPermissions = ['view_reports'];
    }

    return { role: matchedRole, permissions: matchedPermissions };
  }
}

// =========================================================================
// SAMLParser
// =========================================================================

/**
 * Simulated SAML assertion parser. Extracts identity attributes from
 * SAML-like XML strings without requiring real XML crypto libraries.
 */
class SAMLParser {
  /**
   * Parse a SAML assertion XML string and extract identity attributes.
   * @param {string} xml - SAML assertion XML string.
   * @returns {object} Parsed assertion with issuer, subject, attributes, conditions.
   */
  parseAssertion(xml) {
    if (!xml || typeof xml !== 'string') {
      throw new Error('[Agent Shield] SAML assertion must be a non-empty string');
    }

    const assertion = {
      issuer: this._extractTag(xml, 'Issuer'),
      subject: {
        nameId: this._extractTag(xml, 'NameID'),
        format: this._extractAttribute(xml, 'NameID', 'Format')
      },
      conditions: {
        notBefore: this._extractAttribute(xml, 'Conditions', 'NotBefore'),
        notOnOrAfter: this._extractAttribute(xml, 'Conditions', 'NotOnOrAfter'),
        audience: this._extractTag(xml, 'Audience')
      },
      attributes: this.extractAttributes({ xml }),
      raw: xml
    };

    return assertion;
  }

  /**
   * Validate a parsed SAML assertion against a provider configuration.
   * Checks issuer, audience, time validity, subject, and XML signature.
   * @param {object} assertion - Parsed assertion from parseAssertion.
   * @param {object} provider - Provider config with {issuer, audience, certificate}.
   * @returns {{valid: boolean, errors: string[], signatureVerified: boolean}}
   */
  validateAssertion(assertion, provider) {
    const errors = [];
    let signatureVerified = false;

    // Check issuer
    if (assertion.issuer && provider.metadata && provider.metadata.issuer) {
      if (assertion.issuer !== provider.metadata.issuer) {
        errors.push(`Issuer mismatch: expected "${provider.metadata.issuer}", got "${assertion.issuer}"`);
      }
    }

    // Check audience
    if (assertion.conditions && assertion.conditions.audience && provider.metadata && provider.metadata.audience) {
      if (assertion.conditions.audience !== provider.metadata.audience) {
        errors.push(`Audience mismatch: expected "${provider.metadata.audience}", got "${assertion.conditions.audience}"`);
      }
    }

    // Check time validity
    const now = new Date();
    if (assertion.conditions && assertion.conditions.notBefore) {
      const notBefore = new Date(assertion.conditions.notBefore);
      if (now < notBefore) {
        errors.push(`Assertion not yet valid (notBefore: ${assertion.conditions.notBefore})`);
      }
    }
    if (assertion.conditions && assertion.conditions.notOnOrAfter) {
      const notOnOrAfter = new Date(assertion.conditions.notOnOrAfter);
      if (now >= notOnOrAfter) {
        errors.push(`Assertion expired (notOnOrAfter: ${assertion.conditions.notOnOrAfter})`);
      }
    }

    // Check subject
    if (!assertion.subject || !assertion.subject.nameId) {
      errors.push('Missing subject NameID');
    }

    // Verify XML signature if certificate is provided
    if (provider.metadata && provider.metadata.certificate) {
      const sigResult = this.verifySignature(assertion.raw, provider.metadata.certificate);
      signatureVerified = sigResult.valid;
      if (!sigResult.valid) {
        errors.push(`Signature verification failed: ${sigResult.error}`);
      }
    } else {
      errors.push('No IdP certificate provided — cannot verify assertion signature. This is a security risk.');
    }

    return { valid: errors.length === 0, errors, signatureVerified };
  }

  /**
   * Verify the XML digital signature on a SAML assertion.
   * Uses Node.js crypto to validate RSA-SHA256 or RSA-SHA1 signatures
   * against the IdP's public certificate.
   *
   * @param {string} xml - Raw SAML assertion XML.
   * @param {string} certificate - PEM-encoded X.509 certificate from IdP metadata.
   * @returns {{valid: boolean, error: string|null, algorithm: string|null}}
   */
  verifySignature(xml, certificate) {
    if (!xml || !certificate) {
      return { valid: false, error: 'Missing XML or certificate', algorithm: null };
    }

    // Extract the SignatureValue from the XML
    const sigValueMatch = xml.match(/<(?:ds:)?SignatureValue[^>]*>([\s\S]*?)<\/(?:ds:)?SignatureValue>/i);
    if (!sigValueMatch) {
      return { valid: false, error: 'No SignatureValue element found in assertion', algorithm: null };
    }
    const signatureB64 = sigValueMatch[1].replace(/\s+/g, '');

    // Extract the SignedInfo block (the data that was signed)
    const signedInfoMatch = xml.match(/<(?:ds:)?SignedInfo[^>]*>([\s\S]*?)<\/(?:ds:)?SignedInfo>/i);
    if (!signedInfoMatch) {
      return { valid: false, error: 'No SignedInfo element found in assertion', algorithm: null };
    }
    // Reconstruct the canonicalized SignedInfo element
    const signedInfoXml = xml.match(/<(?:ds:)?SignedInfo[^>]*>[\s\S]*?<\/(?:ds:)?SignedInfo>/i)[0];

    // Detect signing algorithm
    const algMatch = xml.match(/Algorithm="([^"]*(?:rsa-sha(?:1|256|384|512))[^"]*)"/i);
    let algorithm = 'RSA-SHA256'; // default
    if (algMatch) {
      const algUri = algMatch[1].toLowerCase();
      if (algUri.includes('sha512')) algorithm = 'RSA-SHA512';
      else if (algUri.includes('sha384')) algorithm = 'RSA-SHA384';
      else if (algUri.includes('sha256')) algorithm = 'RSA-SHA256';
      else if (algUri.includes('sha1')) algorithm = 'RSA-SHA1';
    }

    // Map algorithm name to Node.js crypto algorithm
    const cryptoAlg = algorithm.replace('RSA-', '').toLowerCase().replace('-', '');

    // Normalize certificate to PEM format
    let pem = certificate.trim();
    if (!pem.startsWith('-----BEGIN')) {
      pem = '-----BEGIN CERTIFICATE-----\n' + pem.replace(/(.{64})/g, '$1\n').trim() + '\n-----END CERTIFICATE-----';
    }

    try {
      const verifier = crypto.createVerify(cryptoAlg);
      verifier.update(signedInfoXml);
      const signatureBuffer = Buffer.from(signatureB64, 'base64');
      const isValid = verifier.verify(pem, signatureBuffer);
      return { valid: isValid, error: isValid ? null : 'Signature does not match', algorithm };
    } catch (e) {
      return { valid: false, error: `Crypto error: ${e.message}`, algorithm };
    }
  }

  /**
   * Extract user attributes (email, name, groups, roles) from a SAML assertion.
   * @param {object} assertion - Object with either raw xml or pre-parsed attributes.
   * @returns {object} Extracted attributes {email, name, groups, roles, custom}.
   */
  extractAttributes(assertion) {
    const xml = assertion.xml || assertion.raw || '';
    const attributes = {
      email: null,
      name: null,
      groups: [],
      roles: [],
      custom: {}
    };

    // Extract email
    const emailPatterns = [
      /AttributeName="email"[^>]*>\s*<[^>]*AttributeValue[^>]*>([^<]+)/i,
      /AttributeName="http:\/\/schemas\.xmlsoap\.org\/ws\/2005\/05\/identity\/claims\/emailaddress"[^>]*>\s*<[^>]*AttributeValue[^>]*>([^<]+)/i,
      /AttributeName="mail"[^>]*>\s*<[^>]*AttributeValue[^>]*>([^<]+)/i
    ];
    for (const pattern of emailPatterns) {
      const match = xml.match(pattern);
      if (match) { attributes.email = match[1].trim(); break; }
    }

    // Extract name
    const namePatterns = [
      /AttributeName="displayName"[^>]*>\s*<[^>]*AttributeValue[^>]*>([^<]+)/i,
      /AttributeName="name"[^>]*>\s*<[^>]*AttributeValue[^>]*>([^<]+)/i,
      /AttributeName="http:\/\/schemas\.xmlsoap\.org\/ws\/2005\/05\/identity\/claims\/name"[^>]*>\s*<[^>]*AttributeValue[^>]*>([^<]+)/i
    ];
    for (const pattern of namePatterns) {
      const match = xml.match(pattern);
      if (match) { attributes.name = match[1].trim(); break; }
    }

    // Extract groups
    const groupPattern = /AttributeName="(?:groups?|memberOf|http:\/\/schemas\.xmlsoap\.org\/claims\/Group)"[^>]*>([\s\S]*?)<\/(?:saml2?:)?Attribute>/gi;
    const groupMatch = xml.match(groupPattern);
    if (groupMatch) {
      for (const block of groupMatch) {
        const valuePattern = /<[^>]*AttributeValue[^>]*>([^<]+)/gi;
        let valMatch;
        while ((valMatch = valuePattern.exec(block)) !== null) {
          attributes.groups.push(valMatch[1].trim());
        }
      }
    }

    // Extract roles
    const rolePattern = /AttributeName="(?:roles?|http:\/\/schemas\.microsoft\.com\/ws\/2008\/06\/identity\/claims\/role)"[^>]*>([\s\S]*?)<\/(?:saml2?:)?Attribute>/gi;
    const roleMatch = xml.match(rolePattern);
    if (roleMatch) {
      for (const block of roleMatch) {
        const valuePattern = /<[^>]*AttributeValue[^>]*>([^<]+)/gi;
        let valMatch;
        while ((valMatch = valuePattern.exec(block)) !== null) {
          attributes.roles.push(valMatch[1].trim());
        }
      }
    }

    return attributes;
  }

  /**
   * Build a SAML AuthnRequest for the given provider.
   * @param {object} provider - Provider config with metadata {ssoUrl, entityId, acsUrl}.
   * @returns {string} SAML AuthnRequest XML string.
   */
  buildAuthnRequest(provider) {
    const id = '_' + crypto.randomBytes(16).toString('hex');
    const issueInstant = new Date().toISOString();
    const metadata = provider.metadata || {};

    return [
      '<samlp:AuthnRequest',
      '  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"',
      '  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"',
      `  ID="${id}"`,
      '  Version="2.0"',
      `  IssueInstant="${issueInstant}"`,
      `  Destination="${metadata.ssoUrl || ''}"`,
      `  AssertionConsumerServiceURL="${metadata.acsUrl || ''}"`,
      '  ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">',
      `  <saml:Issuer>${metadata.entityId || ''}</saml:Issuer>`,
      '  <samlp:NameIDPolicy',
      '    Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"',
      '    AllowCreate="true"/>',
      '</samlp:AuthnRequest>'
    ].join('\n');
  }

  // --- Internal helpers ---

  _extractTag(xml, tagName) {
    const pattern = new RegExp(`<(?:[\\w-]+:)?${tagName}[^>]*>([^<]+)<\\/`, 'i');
    const match = xml.match(pattern);
    return match ? match[1].trim() : null;
  }

  _extractAttribute(xml, tagName, attrName) {
    const pattern = new RegExp(`<(?:[\\w-]+:)?${tagName}[^>]*${attrName}="([^"]*)"`, 'i');
    const match = xml.match(pattern);
    return match ? match[1].trim() : null;
  }
}

// =========================================================================
// OIDCHandler
// =========================================================================

/**
 * Simulated OpenID Connect handler. Builds auth URLs, exchanges codes,
 * and validates JWT-like id_tokens — all locally, no external calls.
 */
class OIDCHandler {
  /**
   * @param {object} config
   * @param {string} config.clientId - OIDC client ID.
   * @param {string} config.issuer - OIDC issuer URL.
   * @param {string} config.redirectUri - Redirect URI after authentication.
   */
  constructor(config = {}) {
    this.clientId = config.clientId || '';
    this.issuer = config.issuer || '';
    this.redirectUri = config.redirectUri || '';
  }

  /**
   * Build an OIDC authorization URL.
   * @param {string} state - Opaque state parameter for CSRF protection.
   * @returns {string} Authorization URL.
   */
  buildAuthorizationUrl(state) {
    const nonce = crypto.randomBytes(16).toString('hex');
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      scope: 'openid profile email groups',
      state: state || crypto.randomBytes(16).toString('hex'),
      nonce
    });
    return `${this.issuer}/authorize?${params.toString()}`;
  }

  /**
   * Simulate an authorization code exchange. Returns token-like objects.
   * @param {string} code - The authorization code.
   * @returns {object} Token response {access_token, id_token, token_type, expires_in}.
   */
  exchangeCode(code) {
    if (!code || typeof code !== 'string') {
      throw new Error('[Agent Shield] Authorization code is required');
    }

    const now = Math.floor(Date.now() / 1000);
    const payload = {
      iss: this.issuer,
      sub: 'user_' + code.substring(0, 8),
      aud: this.clientId,
      iat: now,
      exp: now + 3600,
      nonce: crypto.randomBytes(8).toString('hex')
    };

    const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const signature = crypto.randomBytes(32).toString('base64url');

    const idToken = `${header}.${body}.${signature}`;
    const accessToken = crypto.randomBytes(32).toString('base64url');

    return {
      access_token: accessToken,
      id_token: idToken,
      token_type: 'Bearer',
      expires_in: 3600
    };
  }

  /**
   * Validate a JWT id_token. Decodes, checks claims, and verifies signature
   * if a signing key or JWKS is configured.
   *
   * @param {string} token - JWT id_token string.
   * @param {object} [options] - Validation options.
   * @param {string} [options.signingKey] - PEM public key or certificate for RS256 verification.
   * @param {string} [options.secret] - Shared secret for HS256 verification.
   * @param {string} [options.nonce] - Expected nonce value for replay protection.
   * @returns {{valid: boolean, claims: object, errors: string[], signatureVerified: boolean}}
   */
  validateIdToken(token, options = {}) {
    const errors = [];
    let signatureVerified = false;

    if (!token || typeof token !== 'string') {
      return { valid: false, claims: null, errors: ['Token must be a non-empty string'], signatureVerified: false };
    }

    const parts = token.split('.');
    if (parts.length !== 3) {
      return { valid: false, claims: null, errors: ['Invalid JWT structure: expected 3 parts'], signatureVerified: false };
    }

    // Decode header
    let header;
    try {
      header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf-8'));
    } catch (e) {
      return { valid: false, claims: null, errors: ['Failed to decode JWT header'], signatureVerified: false };
    }

    // Decode claims
    let claims;
    try {
      claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf-8'));
    } catch (e) {
      return { valid: false, claims: null, errors: ['Failed to decode JWT payload'], signatureVerified: false };
    }

    // Verify signature
    const signingInput = parts[0] + '.' + parts[1];
    const signature = parts[2];
    const alg = (header.alg || '').toUpperCase();

    if (options.signingKey && (alg === 'RS256' || alg === 'RS384' || alg === 'RS512')) {
      // RSA signature verification
      const hashAlg = alg.replace('RS', 'sha');
      try {
        const verifier = crypto.createVerify(hashAlg);
        verifier.update(signingInput);
        const sigBuf = Buffer.from(signature, 'base64url');
        signatureVerified = verifier.verify(options.signingKey, sigBuf);
        if (!signatureVerified) {
          errors.push('JWT signature verification failed — token may be forged');
        }
      } catch (e) {
        errors.push(`JWT signature verification error: ${e.message}`);
      }
    } else if (options.secret && (alg === 'HS256' || alg === 'HS384' || alg === 'HS512')) {
      // HMAC signature verification
      const hashAlg = alg.replace('HS', 'sha');
      const expectedSig = crypto.createHmac(hashAlg, options.secret).update(signingInput).digest('base64url');
      const sigBuf = Buffer.from(signature, 'utf-8');
      const expectedBuf = Buffer.from(expectedSig, 'utf-8');
      // timingSafeEqual throws if lengths differ, so check length first
      signatureVerified = sigBuf.length === expectedBuf.length && crypto.timingSafeEqual(sigBuf, expectedBuf);
      if (!signatureVerified) {
        errors.push('JWT HMAC signature verification failed — token may be forged');
      }
    } else if (alg === 'NONE' || alg === '') {
      errors.push('JWT uses "none" algorithm — this is insecure and rejected');
    } else if (!options.signingKey && !options.secret) {
      errors.push('No signing key provided — JWT signature not verified. This is a security risk.');
    }

    // Validate issuer
    if (this.issuer && claims.iss !== this.issuer) {
      errors.push(`Issuer mismatch: expected "${this.issuer}", got "${claims.iss}"`);
    }

    // Validate audience
    if (this.clientId) {
      const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
      if (!aud.includes(this.clientId)) {
        errors.push(`Audience mismatch: expected "${this.clientId}", got "${claims.aud}"`);
      }
    }

    // Validate expiration
    const now = Math.floor(Date.now() / 1000);
    if (claims.exp && claims.exp < now) {
      errors.push('Token has expired');
    }

    // Validate issued-at is not in the future (with 60s clock skew tolerance)
    if (claims.iat && claims.iat > now + 60) {
      errors.push('Token issued-at is in the future');
    }

    // Validate nonce (replay protection)
    if (options.nonce && claims.nonce !== options.nonce) {
      errors.push(`Nonce mismatch: possible replay attack`);
    }

    return { valid: errors.length === 0, claims, errors, signatureVerified };
  }

  /**
   * Extract user info from an access token or id_token.
   * @param {string} accessToken - Access token or id_token.
   * @returns {object} User info {sub, email, name, groups}.
   */
  getUserInfo(accessToken) {
    if (!accessToken || typeof accessToken !== 'string') {
      throw new Error('[Agent Shield] Access token is required');
    }

    // Try to decode as JWT
    const parts = accessToken.split('.');
    if (parts.length === 3) {
      try {
        const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf-8'));
        return {
          sub: claims.sub || null,
          email: claims.email || null,
          name: claims.name || null,
          groups: claims.groups || []
        };
      } catch (e) {
        // Not a valid JWT, return minimal info
      }
    }

    // Fallback: return a stub based on the token
    return {
      sub: 'user_' + accessToken.substring(0, 8),
      email: null,
      name: null,
      groups: []
    };
  }
}

// =========================================================================
// SSOManager
// =========================================================================

/**
 * Main SSO orchestration. Registers identity providers, authenticates
 * users, manages sessions, and maps identities to Agent Shield RBAC roles.
 */
class SSOManager {
  /**
   * @param {object} [config]
   * @param {Array} [config.providers] - Pre-registered IdP configurations.
   * @param {string} [config.defaultRole] - Default role when no mapping matches.
   * @param {number} [config.sessionTTL] - Session TTL in milliseconds.
   * @param {boolean} [config.auditLog] - Whether to log authentication events.
   */
  constructor(config = {}) {
    this.providers = new Map();
    this.sessions = new Map();
    this.auditEntries = [];
    this.defaultRole = config.defaultRole || 'viewer';
    this.sessionTTL = config.sessionTTL || 3600000;
    this.auditLog = config.auditLog !== undefined ? config.auditLog : true;
    this.identityMapper = new IdentityMapper();
    this.samlParser = new SAMLParser();
    this.oidcHandler = null;

    // Register any providers passed in config
    if (Array.isArray(config.providers)) {
      for (const provider of config.providers) {
        this.registerProvider(provider);
      }
    }

    console.log('[Agent Shield] SSOManager initialized');
  }

  /**
   * Register an identity provider configuration.
   * @param {object} provider - Provider config {id, type, name, metadata}.
   * @returns {SSOManager}
   */
  registerProvider(provider) {
    if (!provider || !provider.id || !provider.type) {
      throw new Error('[Agent Shield] Provider must have id and type');
    }

    const validTypes = ['saml', 'oidc', 'ldap'];
    if (!validTypes.includes(provider.type)) {
      throw new Error(`[Agent Shield] Invalid provider type: ${provider.type}. Must be one of: ${validTypes.join(', ')}`);
    }

    this.providers.set(provider.id, {
      ...provider,
      registeredAt: new Date().toISOString()
    });

    // Initialize OIDC handler if provider is OIDC
    if (provider.type === 'oidc' && provider.metadata) {
      this.oidcHandler = new OIDCHandler({
        clientId: provider.metadata.clientId,
        issuer: provider.metadata.issuer,
        redirectUri: provider.metadata.redirectUri
      });
    }

    this._audit('provider_registered', { providerId: provider.id, type: provider.type });
    console.log(`[Agent Shield] SSO provider registered: ${provider.name || provider.id} (${provider.type})`);

    return this;
  }

  /**
   * Authenticate a user via SAML assertion or OIDC token.
   * @param {string} providerType - 'saml' or 'oidc'.
   * @param {string} assertion - SAML XML assertion or OIDC code/token.
   * @returns {SSOSession}
   */
  authenticate(providerType, assertion) {
    if (!assertion) {
      throw new Error('[Agent Shield] Assertion/token is required');
    }

    let identity;

    if (providerType === 'saml') {
      identity = this._authenticateSAML(assertion);
    } else if (providerType === 'oidc') {
      identity = this._authenticateOIDC(assertion);
    } else {
      throw new Error(`[Agent Shield] Unsupported provider type for authentication: ${providerType}`);
    }

    // Map identity to role
    const mapping = this.mapToRole(identity);
    const session = new SSOSession(identity, mapping.role, mapping.permissions, this.sessionTTL);

    this.sessions.set(session.id, session);
    this._audit('authentication_success', {
      sessionId: session.id,
      email: identity.email,
      role: mapping.role,
      providerType
    });

    console.log(`[Agent Shield] SSO authentication successful: ${identity.email || identity.nameId} -> ${mapping.role}`);

    return session;
  }

  /**
   * Map an identity to an Agent Shield RBAC role.
   * @param {object} identity - Identity with groups array.
   * @returns {{role: string, permissions: string[]}}
   */
  mapToRole(identity) {
    return this.identityMapper.mapIdentity(identity);
  }

  /**
   * Retrieve an active session by ID.
   * @param {string} sessionId
   * @returns {SSOSession|null}
   */
  getSession(sessionId) {
    const session = this.sessions.get(sessionId);
    if (!session) return null;
    if (!session.isValid()) {
      this.sessions.delete(sessionId);
      return null;
    }
    return session;
  }

  /**
   * Revoke an active session.
   * @param {string} sessionId
   * @returns {boolean} Whether the session was found and revoked.
   */
  revokeSession(sessionId) {
    const session = this.sessions.get(sessionId);
    if (!session) return false;

    session.revoked = true;
    this._audit('session_revoked', { sessionId });
    console.log(`[Agent Shield] Session revoked: ${sessionId}`);

    return true;
  }

  /**
   * List all active (non-expired, non-revoked) sessions.
   * @returns {SSOSession[]}
   */
  listActiveSessions() {
    const active = [];
    for (const [id, session] of this.sessions) {
      if (session.isValid()) {
        active.push(session);
      } else {
        this.sessions.delete(id);
      }
    }
    return active;
  }

  /**
   * Get the authentication audit log.
   * @returns {Array<object>}
   */
  getAuditLog() {
    return [...this.auditEntries];
  }

  // --- Internal helpers ---

  _authenticateSAML(xml) {
    const assertion = this.samlParser.parseAssertion(xml);

    // Find a SAML provider to validate against
    let samlProvider = null;
    for (const [, provider] of this.providers) {
      if (provider.type === 'saml') {
        samlProvider = provider;
        break;
      }
    }

    if (samlProvider) {
      const validation = this.samlParser.validateAssertion(assertion, samlProvider);
      if (!validation.valid) {
        this._audit('authentication_failed', { errors: validation.errors, providerType: 'saml' });
        throw new Error(`[Agent Shield] SAML validation failed: ${validation.errors.join('; ')}`);
      }
    }

    return {
      nameId: assertion.subject.nameId,
      email: assertion.attributes.email || assertion.subject.nameId,
      name: assertion.attributes.name,
      groups: assertion.attributes.groups || [],
      roles: assertion.attributes.roles || [],
      provider: 'saml'
    };
  }

  _authenticateOIDC(codeOrToken) {
    // If it looks like a JWT (has dots), validate directly
    if (codeOrToken.includes('.')) {
      const handler = this.oidcHandler || new OIDCHandler({});
      const validation = handler.validateIdToken(codeOrToken);
      if (!validation.valid) {
        this._audit('authentication_failed', { errors: validation.errors, providerType: 'oidc' });
        throw new Error(`[Agent Shield] OIDC token validation failed: ${validation.errors.join('; ')}`);
      }
      const claims = validation.claims;
      return {
        sub: claims.sub,
        email: claims.email || null,
        name: claims.name || null,
        groups: claims.groups || [],
        roles: claims.roles || [],
        provider: 'oidc'
      };
    }

    // Otherwise treat as authorization code
    const handler = this.oidcHandler || new OIDCHandler({});
    const tokens = handler.exchangeCode(codeOrToken);
    const validation = handler.validateIdToken(tokens.id_token);
    const claims = validation.claims || {};

    return {
      sub: claims.sub,
      email: claims.email || null,
      name: claims.name || null,
      groups: claims.groups || [],
      roles: claims.roles || [],
      provider: 'oidc'
    };
  }

  _audit(event, details) {
    if (!this.auditLog) return;
    this.auditEntries.push({
      timestamp: new Date().toISOString(),
      event,
      details
    });
  }
}

// =========================================================================
// Exports
// =========================================================================

module.exports = {
  SSOManager,
  SAMLParser,
  OIDCHandler,
  IdentityMapper,
  SSOSession,
  DEFAULT_MAPPINGS
};
