'use strict';

/**
 * Agent Shield — Message Integrity Verification (SOTA)
 *
 * HMAC-signs every message in a conversation to detect tampering.
 * Based on IEEE S&P 2026 finding: plugins transmit message history
 * without integrity checks, enabling adversaries to inject forged
 * messages impersonating high-privilege roles.
 *
 * All processing runs locally — no data ever leaves your environment.
 *
 * @module message-integrity
 */

const crypto = require('crypto');

// =========================================================================
// MessageIntegrityChain
// =========================================================================

/**
 * Maintains an HMAC-signed chain of messages. Each message's signature
 * includes the previous signature, creating a tamper-evident chain
 * (like a blockchain of conversation messages).
 */
class MessageIntegrityChain {
  /**
   * @param {object} [options]
   * @param {string} [options.signingKey] - HMAC key. Auto-generated if not provided.
   * @param {string} [options.algorithm='sha256'] - Hash algorithm.
   */
  constructor(options = {}) {
    this.signingKey = options.signingKey || crypto.randomBytes(32).toString('hex');
    this.algorithm = options.algorithm || 'sha256';

    /** @type {Array<{ role: string, content: string, signature: string, index: number, timestamp: number }>} */
    this.chain = [];
    this.stats = { messagesAdded: 0, verificationsRun: 0, tamperingsDetected: 0 };
  }

  /**
   * Add a message to the chain and sign it.
   *
   * @param {string} role - Message role: 'system', 'user', 'assistant', 'tool'.
   * @param {string} content - Message content.
   * @returns {{ index: number, signature: string }}
   */
  addMessage(role, content) {
    const index = this.chain.length;
    const previousSig = index > 0 ? this.chain[index - 1].signature : '0'.repeat(64);
    const timestamp = Date.now();

    // Sign: role + content + index + previousSig + timestamp
    const payload = `${role}:${content}:${index}:${previousSig}:${timestamp}`;
    const signature = this._sign(payload);

    this.chain.push({ role, content, signature, index, timestamp });
    this.stats.messagesAdded++;

    return { index, signature };
  }

  /**
   * Verify the integrity of the entire chain.
   * Detects any message that was modified, inserted, deleted, or reordered.
   *
   * @returns {{ valid: boolean, tampered: Array<object> }}
   */
  verifyChain() {
    this.stats.verificationsRun++;
    const tampered = [];

    for (let i = 0; i < this.chain.length; i++) {
      const msg = this.chain[i];
      const previousSig = i > 0 ? this.chain[i - 1].signature : '0'.repeat(64);

      const payload = `${msg.role}:${msg.content}:${msg.index}:${previousSig}:${msg.timestamp}`;
      const expectedSig = this._sign(payload);

      if (msg.signature !== expectedSig) {
        tampered.push({
          index: i,
          role: msg.role,
          reason: 'Signature mismatch — message content or order was tampered.',
          expected: expectedSig.substring(0, 16) + '...',
          actual: msg.signature.substring(0, 16) + '...'
        });
      }

      if (msg.index !== i) {
        tampered.push({
          index: i,
          role: msg.role,
          reason: `Index mismatch — expected ${i} but found ${msg.index}. Message may have been reordered.`
        });
      }
    }

    if (tampered.length > 0) {
      this.stats.tamperingsDetected += tampered.length;
    }

    return { valid: tampered.length === 0, tampered };
  }

  /**
   * Verify a single message at a given index.
   *
   * @param {number} index
   * @returns {{ valid: boolean, reason: string|null }}
   */
  verifyMessage(index) {
    if (index < 0 || index >= this.chain.length) {
      return { valid: false, reason: 'Index out of range.' };
    }

    const msg = this.chain[index];
    const previousSig = index > 0 ? this.chain[index - 1].signature : '0'.repeat(64);
    const payload = `${msg.role}:${msg.content}:${msg.index}:${previousSig}:${msg.timestamp}`;
    const expectedSig = this._sign(payload);

    if (msg.signature !== expectedSig) {
      return { valid: false, reason: 'Signature mismatch.' };
    }
    return { valid: true, reason: null };
  }

  /**
   * Detect role boundary violations — messages claiming a role they shouldn't have.
   * Ref: IEEE S&P 2026 — plugins inject forged messages impersonating high-privilege roles.
   *
   * @param {object} [rolePolicy]
   * @param {Set<string>} [rolePolicy.systemSources] - Sources allowed to send 'system' messages.
   * @returns {Array<object>} Violations.
   */
  detectRoleViolations(rolePolicy = {}) {
    const violations = [];
    const systemSources = rolePolicy.systemSources || new Set(['system_init']);

    for (let i = 0; i < this.chain.length; i++) {
      const msg = this.chain[i];

      // System messages should only appear at the start
      if (msg.role === 'system' && i > 0) {
        violations.push({
          index: i,
          type: 'late_system_message',
          severity: 'critical',
          description: `System message at index ${i} — system messages should only appear at conversation start. Possible role injection.`
        });
      }

      // Detect role impersonation patterns in content
      if (msg.role === 'user') {
        const roleImpersonation = /^(?:system|assistant|admin|developer)\s*[:\-]\s/i.test(msg.content);
        if (roleImpersonation) {
          violations.push({
            index: i,
            type: 'role_impersonation_in_content',
            severity: 'high',
            description: `User message at index ${i} starts with a role prefix — possible role impersonation attempt.`
          });
        }
      }
    }

    return violations;
  }

  /**
   * Export the chain for storage or transmission.
   * @returns {object}
   */
  export() {
    return {
      chain: this.chain.map(m => ({ ...m })),
      chainLength: this.chain.length,
      lastSignature: this.chain.length > 0 ? this.chain[this.chain.length - 1].signature : null,
      exportedAt: Date.now()
    };
  }

  /**
   * Import and verify a chain.
   * @param {object} data - Data from export().
   * @returns {{ valid: boolean, imported: number, tampered: Array<object> }}
   */
  import(data) {
    if (!data || !Array.isArray(data.chain)) {
      return { valid: false, imported: 0, tampered: [{ reason: 'Invalid import data.' }] };
    }

    const oldChain = this.chain;
    this.chain = data.chain;
    const verification = this.verifyChain();

    if (!verification.valid) {
      this.chain = oldChain; // Rollback
      return { valid: false, imported: 0, tampered: verification.tampered };
    }

    return { valid: true, imported: this.chain.length, tampered: [] };
  }

  /**
   * Get stats.
   * @returns {object}
   */
  getStats() {
    return { ...this.stats, chainLength: this.chain.length };
  }

  /** @private */
  _sign(payload) {
    return crypto.createHmac(this.algorithm, this.signingKey).update(payload).digest('hex');
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
  MessageIntegrityChain
};
