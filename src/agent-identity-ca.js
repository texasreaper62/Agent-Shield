'use strict';

/**
 * Agent Shield — Agent Identity CA (H3)
 *
 * Cryptographic agent passports for cross-org trust. Every agent in the
 * fleet is issued a passport signed by Shield (the CA). Every cross-agent
 * message is signed by the sending agent's private key. Verifiers can
 * confirm:
 *   - the message came from a known agent (signature valid),
 *   - the agent's passport is signed by a trusted CA root,
 *   - the passport hasn't been revoked,
 *   - the message timestamp is recent (replay protection).
 *
 * Uses Ed25519 from Node's built-in crypto (zero external deps).
 *
 * Passport JSON shape (signed by CA root key):
 *   {
 *     agentId: "...",
 *     publicKey: "<base64 spki>",
 *     issuedAt: <ms>,
 *     notAfter: <ms>,
 *     capabilities: [...],
 *     orgId: "...",
 *     caRootId: "...",
 *     signature: "<base64>"
 *   }
 *
 * Signed message envelope shape:
 *   {
 *     agentId: "...",
 *     timestamp: <ms>,
 *     nonce: "...",
 *     payload: any,
 *     signature: "<base64>"  // signed by AGENT key over canonical envelope
 *   }
 */

const crypto = require('crypto');

const DEFAULT_PASSPORT_TTL_MS = 90 * 24 * 60 * 60 * 1000; // 90 days
const DEFAULT_MESSAGE_TTL_MS = 5 * 60 * 1000;             // 5 minutes
const DEFAULT_NONCE_CACHE_MAX = 10_000;

class AgentIdentityCA {
  constructor(opts = {}) {
    this.caRootId = opts.caRootId || `ca-${crypto.randomBytes(6).toString('hex')}`;
    // Generate or accept a CA Ed25519 keypair.
    if (opts.caKeypair) {
      this.caPrivateKey = opts.caKeypair.privateKey;
      this.caPublicKey = opts.caKeypair.publicKey;
    } else {
      const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
      this.caPrivateKey = privateKey;
      this.caPublicKey = publicKey;
    }
    this.passportTtlMs = opts.passportTtlMs || DEFAULT_PASSPORT_TTL_MS;
    this.messageTtlMs = opts.messageTtlMs || DEFAULT_MESSAGE_TTL_MS;
    this.nonceCacheMax = opts.nonceCacheMax || DEFAULT_NONCE_CACHE_MAX;
    this.revoked = new Set();
    this.seenNonces = new Map(); // nonce → expiresAt
    this.knownPassports = new Map(); // agentId → passport
  }

  /**
   * Issue a passport for an agent. Returns { passport, privateKey } where
   * the host stores the privateKey securely and ships the passport with
   * each message.
   */
  issuePassport({ agentId, capabilities, orgId }) {
    if (!agentId || typeof agentId !== 'string') throw new Error('issuePassport requires agentId');
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
    const pubKeyDer = publicKey.export({ type: 'spki', format: 'der' });
    const now = Date.now();
    const body = {
      agentId,
      publicKey: pubKeyDer.toString('base64'),
      issuedAt: now,
      notAfter: now + this.passportTtlMs,
      capabilities: Array.isArray(capabilities) ? capabilities.slice() : [],
      orgId: orgId || null,
      caRootId: this.caRootId,
    };
    const signature = crypto.sign(null, Buffer.from(canonicalize(body)), this.caPrivateKey).toString('base64');
    const passport = { ...body, signature };
    this.knownPassports.set(agentId, passport);
    return { passport, privateKey };
  }

  /**
   * Verify a passport against this CA's root key. Returns true if valid.
   */
  verifyPassport(passport, opts = {}) {
    if (!passport || typeof passport !== 'object') return false;
    if (passport.caRootId !== this.caRootId && !opts.trustForeignCA) return false;
    if (this.revoked.has(passport.agentId)) return false;
    if (passport.notAfter && Date.now() > passport.notAfter) return false;
    const { signature, ...body } = passport;
    try {
      return crypto.verify(
        null,
        Buffer.from(canonicalize(body)),
        this.caPublicKey,
        Buffer.from(signature, 'base64')
      );
    } catch (_) { return false; }
  }

  /**
   * Revoke an agent's passport (CRL-style). Subsequent verifications fail.
   */
  revoke(agentId) {
    if (typeof agentId !== 'string') throw new Error('revoke requires agentId');
    this.revoked.add(agentId);
  }

  /**
   * Sign an outbound agent-to-agent message envelope. Returns the envelope
   * ready to send. Caller must pass their own privateKey (issued by
   * issuePassport).
   */
  signMessage({ agentId, payload, privateKey }) {
    if (!agentId || !privateKey) throw new Error('signMessage requires agentId + privateKey');
    const envelope = {
      agentId,
      timestamp: Date.now(),
      nonce: crypto.randomBytes(16).toString('hex'),
      payload: payload ?? null,
    };
    const sig = crypto.sign(null, Buffer.from(canonicalize(envelope)), privateKey).toString('base64');
    return { ...envelope, signature: sig };
  }

  /**
   * Verify an inbound envelope using a known passport. Returns:
   *   { valid: bool, reason?: string, agentId, capabilities }
   */
  verifyMessage(envelope, passport) {
    if (!envelope || typeof envelope !== 'object') return { valid: false, reason: 'envelope missing' };
    if (!envelope.signature) return { valid: false, reason: 'signature missing' };
    if (!passport) return { valid: false, reason: 'passport missing' };
    if (!this.verifyPassport(passport)) return { valid: false, reason: 'passport not valid' };
    if (envelope.agentId !== passport.agentId) return { valid: false, reason: 'envelope agentId != passport agentId' };

    // Replay window check.
    const skew = Date.now() - envelope.timestamp;
    if (skew > this.messageTtlMs) return { valid: false, reason: `timestamp too old (${skew}ms > ${this.messageTtlMs}ms)` };
    if (skew < -this.messageTtlMs) return { valid: false, reason: `timestamp from the future (${skew}ms)` };

    // Nonce uniqueness check (within the TTL window).
    this._sweepNonces();
    if (this.seenNonces.has(envelope.nonce)) return { valid: false, reason: 'nonce replay detected' };

    // Verify signature with the agent's public key (from the passport).
    const { signature, ...body } = envelope;
    let pubKey;
    try {
      pubKey = crypto.createPublicKey({
        key: Buffer.from(passport.publicKey, 'base64'),
        format: 'der',
        type: 'spki',
      });
    } catch (err) {
      return { valid: false, reason: `bad passport publicKey: ${err.message}` };
    }
    let ok;
    try {
      ok = crypto.verify(null, Buffer.from(canonicalize(body)), pubKey, Buffer.from(signature, 'base64'));
    } catch (err) {
      return { valid: false, reason: `verify failed: ${err.message}` };
    }
    if (!ok) return { valid: false, reason: 'bad signature' };

    // Record nonce so a replay within the TTL is rejected.
    this.seenNonces.set(envelope.nonce, Date.now() + this.messageTtlMs);
    if (this.seenNonces.size > this.nonceCacheMax) this._sweepNonces(true);

    return { valid: true, agentId: passport.agentId, capabilities: passport.capabilities };
  }

  _sweepNonces(force = false) {
    const now = Date.now();
    let removed = 0;
    for (const [n, exp] of this.seenNonces) {
      if (exp < now) { this.seenNonces.delete(n); removed++; }
    }
    // If still oversize after expiry sweep, evict oldest insertion-order entries.
    if (force && this.seenNonces.size > this.nonceCacheMax) {
      const overshoot = this.seenNonces.size - this.nonceCacheMax;
      let i = 0;
      for (const k of this.seenNonces.keys()) {
        if (i++ >= overshoot) break;
        this.seenNonces.delete(k);
      }
    }
    return removed;
  }

  /**
   * Export the CA's public root so a peer can verify our passports.
   * (The private key never leaves this instance.)
   */
  exportRootPublicKey() {
    return {
      caRootId: this.caRootId,
      publicKey: this.caPublicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
    };
  }
}

function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',') + '}';
}

module.exports = { AgentIdentityCA, canonicalize };
