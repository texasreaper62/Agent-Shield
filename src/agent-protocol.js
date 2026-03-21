'use strict';

/**
 * Agent Shield — Agent Protocol
 *
 * Standardized secure communication protocol between shielded AI agents.
 * Like mTLS but for AI agents: mutual authentication, HMAC-signed messages,
 * replay protection via sequence numbers, challenge-response handshake.
 *
 * All local, no network calls. Uses Node.js crypto for HMAC-SHA256.
 */

const crypto = require('crypto');

/** @type {string} */
const PROTOCOL_VERSION = '1.0';

// =========================================================================
// ProtocolMessage — Wire format for messages
// =========================================================================

/**
 * Wire format for protocol messages exchanged between agents.
 */
class ProtocolMessage {
  /**
   * Valid message types.
   * @type {string[]}
   */
  static TYPES = [
    'handshake_init',
    'handshake_response',
    'handshake_complete',
    'data',
    'scan_request',
    'scan_response',
    'threat_alert',
    'channel_close',
    'heartbeat'
  ];

  /**
   * @param {string} type - Message type (see ProtocolMessage.TYPES)
   * @param {*} payload - Message payload
   * @param {string} senderId - Sender agent ID
   * @param {number} sequenceNum - Sequence number for replay protection
   */
  constructor(type, payload, senderId, sequenceNum) {
    if (!ProtocolMessage.TYPES.includes(type)) {
      throw new Error(`[Agent Shield] Invalid message type: ${type}`);
    }
    this.type = type;
    this.payload = payload;
    this.senderId = senderId;
    this.sequenceNum = sequenceNum;
    this.timestamp = Date.now();
    this.id = crypto.randomBytes(8).toString('hex');
  }

  /**
   * Serialize to JSON string with signature placeholder.
   * @returns {string} JSON-encoded message
   */
  serialize() {
    return JSON.stringify({
      id: this.id,
      type: this.type,
      payload: this.payload,
      senderId: this.senderId,
      sequenceNum: this.sequenceNum,
      timestamp: this.timestamp
    });
  }

  /**
   * Parse and validate a serialized message.
   * @param {string} raw - Raw JSON string
   * @returns {ProtocolMessage} Parsed message
   */
  static deserialize(raw) {
    let data;
    try {
      data = JSON.parse(raw);
    } catch (e) {
      throw new Error('[Agent Shield] Failed to deserialize message: invalid JSON');
    }

    if (!data.type || !data.senderId || data.sequenceNum === undefined) {
      throw new Error('[Agent Shield] Malformed protocol message: missing required fields');
    }

    if (!ProtocolMessage.TYPES.includes(data.type)) {
      throw new Error(`[Agent Shield] Unknown message type: ${data.type}`);
    }

    const msg = new ProtocolMessage(data.type, data.payload, data.senderId, data.sequenceNum);
    msg.timestamp = data.timestamp || Date.now();
    msg.id = data.id || crypto.randomBytes(8).toString('hex');
    return msg;
  }

  /**
   * Check if the message has expired.
   * @param {number} timeout - Timeout in milliseconds
   * @returns {boolean} True if message is older than timeout
   */
  isExpired(timeout) {
    return (Date.now() - this.timestamp) > timeout;
  }
}

// =========================================================================
// AgentIdentity — Agent identity and capabilities
// =========================================================================

/**
 * Represents an agent's identity, capabilities, and trust level.
 */
class AgentIdentity {
  /**
   * Valid trust levels.
   * @type {string[]}
   */
  static TRUST_LEVELS = ['untrusted', 'verified', 'trusted', 'privileged'];

  /**
   * @param {string} agentId - Unique agent identifier
   * @param {string[]} capabilities - List of capabilities this agent possesses
   * @param {object} [metadata={}] - Additional metadata
   */
  constructor(agentId, capabilities = [], metadata = {}) {
    if (!agentId) {
      throw new Error('[Agent Shield] agentId is required for AgentIdentity');
    }
    this.agentId = agentId;
    this.capabilities = Array.isArray(capabilities) ? capabilities : [];
    this.metadata = metadata || {};
    this.created = Date.now();
    this.trustLevel = 'untrusted';
    this.signature = null;
  }

  /**
   * Create a signature over the identity fields using HMAC-SHA256.
   * @param {string} secretKey - Secret key for signing
   * @returns {string} Hex-encoded HMAC signature
   */
  sign(secretKey) {
    const data = `${this.agentId}:${this.capabilities.join(',')}:${this.created}`;
    this.signature = crypto.createHmac('sha256', secretKey).update(data).digest('hex');
    return this.signature;
  }

  /**
   * Verify an identity signature.
   * @param {string} signature - Signature to verify
   * @param {string} secretKey - Secret key used for signing
   * @returns {boolean} True if signature is valid
   */
  verify(signature, secretKey) {
    const data = `${this.agentId}:${this.capabilities.join(',')}:${this.created}`;
    const expected = crypto.createHmac('sha256', secretKey).update(data).digest('hex');
    try {
      return crypto.timingSafeEqual(Buffer.from(signature, 'hex'), Buffer.from(expected, 'hex'));
    } catch {
      return false;
    }
  }

  /**
   * Check if agent has a specific capability.
   * @param {string} cap - Capability to check
   * @returns {boolean} True if agent has the capability
   */
  hasCapability(cap) {
    return this.capabilities.includes(cap);
  }

  /**
   * Serialize identity to a plain object.
   * @returns {object} JSON-safe representation
   */
  toJSON() {
    return {
      agentId: this.agentId,
      capabilities: this.capabilities,
      metadata: this.metadata,
      created: this.created,
      trustLevel: this.trustLevel,
      signature: this.signature
    };
  }

  /**
   * Deserialize identity from a plain object.
   * @param {object} json - Serialized identity
   * @returns {AgentIdentity} Restored identity
   */
  static fromJSON(json) {
    if (!json || !json.agentId) {
      throw new Error('[Agent Shield] Invalid identity JSON: missing agentId');
    }
    const identity = new AgentIdentity(json.agentId, json.capabilities, json.metadata);
    identity.created = json.created || Date.now();
    identity.trustLevel = json.trustLevel || 'untrusted';
    identity.signature = json.signature || null;
    return identity;
  }
}

// =========================================================================
// SecureChannel — Encrypted bidirectional channel
// =========================================================================

/**
 * Encrypted bidirectional communication channel between two agents.
 * Uses HMAC-SHA256 for message signing and XOR cipher for encryption.
 */
class SecureChannel {
  /**
   * @param {AgentIdentity} localIdentity - Local agent identity
   * @param {AgentIdentity} remoteIdentity - Remote agent identity
   * @param {string} sharedSecret - Shared secret for encryption and signing
   */
  constructor(localIdentity, remoteIdentity, sharedSecret) {
    if (!localIdentity || !remoteIdentity || !sharedSecret) {
      throw new Error('[Agent Shield] SecureChannel requires localIdentity, remoteIdentity, and sharedSecret');
    }
    this.localIdentity = localIdentity;
    this.remoteIdentity = remoteIdentity;
    this.sharedSecret = sharedSecret;
    this.open = true;
    this.sendSeq = 0;
    this.recvSeq = 0;
    this.messageHistory = [];
    this._maxHistory = 1000;
    this._maxLatencies = 100;
    this.latencies = [];
    this.createdAt = Date.now();
    this._pendingTimestamps = new Map();
    this._lastPendingPurge = Date.now();
    this._pendingPurgeIntervalMs = 60000;
  }

  /**
   * Encrypt and send a protocol message.
   * @param {*} payload - Message payload
   * @param {string} [type='data'] - Message type
   * @returns {string} Signed, encrypted message (serialized)
   */
  send(payload, type = 'data') {
    if (!this.open) {
      throw new Error('[Agent Shield] Cannot send on a closed channel');
    }

    const msg = new ProtocolMessage(type, payload, this.localIdentity.agentId, this.sendSeq);
    const serialized = msg.serialize();
    const encrypted = this._encrypt(serialized, this.sharedSecret);
    const signature = this._sign(encrypted, this.sharedSecret);

    const envelope = JSON.stringify({
      encrypted,
      signature,
      senderId: this.localIdentity.agentId,
      sequenceNum: this.sendSeq
    });

    this._pendingTimestamps.set(this.sendSeq, Date.now());
    this.sendSeq++;

    if (this.messageHistory.length >= this._maxHistory) {
      this.messageHistory = this.messageHistory.slice(-Math.floor(this._maxHistory * 0.75));
    }
    this.messageHistory.push({
      direction: 'sent',
      type,
      sequenceNum: msg.sequenceNum,
      timestamp: msg.timestamp
    });

    return envelope;
  }

  /**
   * Receive, verify, and decrypt an incoming message.
   * @param {string} rawMessage - Raw message envelope (JSON string)
   * @returns {ProtocolMessage} Verified and decrypted message
   */
  receive(rawMessage) {
    if (!this.open) {
      throw new Error('[Agent Shield] Cannot receive on a closed channel');
    }

    let envelope;
    try {
      envelope = JSON.parse(rawMessage);
    } catch (e) {
      throw new Error('[Agent Shield] Invalid message envelope: bad JSON');
    }

    const { encrypted, signature, sequenceNum } = envelope;

    // Verify HMAC signature
    if (!this._verify(encrypted, signature, this.sharedSecret)) {
      throw new Error('[Agent Shield] Message signature verification failed');
    }

    // Replay protection: sequence number must match expected
    if (sequenceNum < this.recvSeq) {
      throw new Error(`[Agent Shield] Replay detected: sequence ${sequenceNum} already processed (expected >= ${this.recvSeq})`);
    }

    // Decrypt
    const decrypted = this._decrypt(encrypted, this.sharedSecret);
    const msg = ProtocolMessage.deserialize(decrypted);

    this.recvSeq = sequenceNum + 1;

    // Track latency if we have a pending timestamp for this sequence
    if (this._pendingTimestamps.has(sequenceNum)) {
      const latency = Date.now() - this._pendingTimestamps.get(sequenceNum);
      this.latencies.push(latency);
      if (this.latencies.length > this._maxLatencies) this.latencies.shift();
      this._pendingTimestamps.delete(sequenceNum);
    }

    // Purge stale pending timestamps periodically (not on every message)
    const now = Date.now();
    if (now - this._lastPendingPurge > this._pendingPurgeIntervalMs) {
      this._lastPendingPurge = now;
      for (const [seq, ts] of this._pendingTimestamps) {
        if (now - ts > this._pendingPurgeIntervalMs) this._pendingTimestamps.delete(seq);
      }
    }

    if (this.messageHistory.length >= this._maxHistory) {
      this.messageHistory = this.messageHistory.slice(-Math.floor(this._maxHistory * 0.75));
    }
    this.messageHistory.push({
      direction: 'received',
      type: msg.type,
      sequenceNum: msg.sequenceNum,
      timestamp: msg.timestamp
    });

    return msg;
  }

  /**
   * Gracefully close the channel with a close notification.
   * @returns {string|null} Close notification message, or null if already closed
   */
  close() {
    if (!this.open) {
      return null;
    }

    let closeMsg = null;
    try {
      closeMsg = this.send({ reason: 'channel_close' }, 'channel_close');
    } catch (e) {
      // Channel may already be in a bad state, just close it
    }

    this.open = false;
    this._pendingTimestamps.clear();
    return closeMsg;
  }

  /**
   * Check if the channel is currently open.
   * @returns {boolean} True if channel is open
   */
  isOpen() {
    return this.open;
  }

  /**
   * Get the average message round-trip latency.
   * @returns {number} Average latency in milliseconds, or 0 if no data
   */
  getLatency() {
    if (this.latencies.length === 0) return 0;
    const sum = this.latencies.reduce((a, b) => a + b, 0);
    return Math.round(sum / this.latencies.length);
  }

  /**
   * AES-256-GCM authenticated encryption.
   * @param {string} data - Plaintext data (UTF-8)
   * @param {string} secret - Secret key
   * @returns {string} Base64-encoded JSON envelope { iv, encrypted, authTag }
   * @private
   */
  _encrypt(data, secret) {
    const key = crypto.createHash('sha256').update(secret).digest();
    const iv = crypto.randomBytes(12); // 96-bit IV for GCM
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return Buffer.from(JSON.stringify({
      iv: iv.toString('base64'),
      ct: encrypted.toString('base64'),
      at: authTag.toString('base64')
    })).toString('base64');
  }

  /**
   * AES-256-GCM authenticated decryption.
   * @param {string} data - Base64-encoded JSON envelope from _encrypt
   * @param {string} secret - Secret key
   * @returns {string} Decrypted plaintext (UTF-8)
   * @private
   */
  _decrypt(data, secret) {
    const key = crypto.createHash('sha256').update(secret).digest();
    const envelope = JSON.parse(Buffer.from(data, 'base64').toString('utf8'));
    const iv = Buffer.from(envelope.iv, 'base64');
    const encrypted = Buffer.from(envelope.ct, 'base64');
    const authTag = Buffer.from(envelope.at, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
  }

  /**
   * Create an HMAC-SHA256 signature.
   * @param {string} data - Data to sign
   * @param {string} key - Signing key
   * @returns {string} Hex-encoded HMAC signature
   * @private
   */
  _sign(data, key) {
    return crypto.createHmac('sha256', key).update(data).digest('hex');
  }

  /**
   * Verify an HMAC-SHA256 signature using timing-safe comparison.
   * @param {string} data - Signed data
   * @param {string} signature - Signature to verify
   * @param {string} key - Signing key
   * @returns {boolean} True if signature is valid
   * @private
   */
  _verify(data, signature, key) {
    const expected = this._sign(data, key);
    try {
      return crypto.timingSafeEqual(Buffer.from(signature, 'hex'), Buffer.from(expected, 'hex'));
    } catch {
      return false;
    }
  }
}

// =========================================================================
// HandshakeManager — Mutual authentication handshake
// =========================================================================

/**
 * Manages mutual authentication handshakes between agents using
 * a challenge-response pattern with nonces and timestamp freshness.
 */
class HandshakeManager {
  /**
   * @param {AgentIdentity} localIdentity - Local agent identity
   * @param {string} secretKey - Secret key for HMAC operations
   */
  constructor(localIdentity, secretKey) {
    if (!localIdentity || !secretKey) {
      throw new Error('[Agent Shield] HandshakeManager requires localIdentity and secretKey');
    }
    this.localIdentity = localIdentity;
    this.secretKey = secretKey;
    this.pendingHandshakes = new Map();
    this.maxAge = 30000; // 30 seconds freshness window
  }

  /**
   * Initiate a handshake with a remote agent.
   * @param {string} remoteId - Remote agent ID
   * @returns {object} Handshake request with nonce, timestamp, and capabilities
   */
  initiateHandshake(remoteId) {
    const nonce = crypto.randomBytes(16).toString('hex');
    const timestamp = Date.now();

    const request = {
      type: 'handshake_init',
      fromAgent: this.localIdentity.agentId,
      toAgent: remoteId,
      nonce,
      timestamp,
      capabilities: this.localIdentity.capabilities,
      protocolVersion: PROTOCOL_VERSION
    };

    // Sign the request
    const signatureInput = `${request.fromAgent}:${request.toAgent}:${request.nonce}:${request.timestamp}`;
    request.signature = crypto.createHmac('sha256', this.secretKey).update(signatureInput).digest('hex');

    // Store pending handshake state
    this.pendingHandshakes.set(remoteId, {
      nonce,
      timestamp,
      state: 'initiated'
    });

    return request;
  }

  /**
   * Respond to an incoming handshake request. Validates timestamp freshness
   * and creates a response with a counter-nonce.
   * @param {object} request - Incoming handshake request
   * @returns {object} Handshake response with counter-nonce
   */
  respondToHandshake(request) {
    if (!request || request.type !== 'handshake_init') {
      throw new Error('[Agent Shield] Invalid handshake request');
    }

    // Check timestamp freshness
    const age = Date.now() - request.timestamp;
    if (age > this.maxAge) {
      throw new Error(`[Agent Shield] Handshake request expired: ${age}ms old (max ${this.maxAge}ms)`);
    }

    // Verify request signature
    const signatureInput = `${request.fromAgent}:${request.toAgent}:${request.nonce}:${request.timestamp}`;
    const expectedSig = crypto.createHmac('sha256', this.secretKey).update(signatureInput).digest('hex');

    try {
      const valid = crypto.timingSafeEqual(
        Buffer.from(request.signature, 'hex'),
        Buffer.from(expectedSig, 'hex')
      );
      if (!valid) {
        throw new Error('[Agent Shield] Handshake request signature invalid');
      }
    } catch (e) {
      if (e.message.includes('signature invalid')) throw e;
      throw new Error('[Agent Shield] Handshake request signature invalid');
    }

    // Create counter-nonce and response
    const counterNonce = crypto.randomBytes(16).toString('hex');
    const timestamp = Date.now();

    const response = {
      type: 'handshake_response',
      fromAgent: this.localIdentity.agentId,
      toAgent: request.fromAgent,
      nonce: request.nonce,
      counterNonce,
      timestamp,
      capabilities: this.localIdentity.capabilities,
      protocolVersion: PROTOCOL_VERSION
    };

    const responseSigInput = `${response.fromAgent}:${response.toAgent}:${response.nonce}:${response.counterNonce}:${response.timestamp}`;
    response.signature = crypto.createHmac('sha256', this.secretKey).update(responseSigInput).digest('hex');

    // Store pending state
    this.pendingHandshakes.set(request.fromAgent, {
      nonce: request.nonce,
      counterNonce,
      timestamp,
      state: 'responded'
    });

    return response;
  }

  /**
   * Complete the handshake by validating the response and deriving a shared secret.
   * @param {object} response - Handshake response from remote agent
   * @returns {object} { sharedSecret, remoteCapabilities }
   */
  completeHandshake(response) {
    if (!response || response.type !== 'handshake_response') {
      throw new Error('[Agent Shield] Invalid handshake response');
    }

    const pending = this.pendingHandshakes.get(response.fromAgent);
    if (!pending) {
      throw new Error(`[Agent Shield] No pending handshake for agent: ${response.fromAgent}`);
    }

    // Check timestamp freshness
    const age = Date.now() - response.timestamp;
    if (age > this.maxAge) {
      throw new Error(`[Agent Shield] Handshake response expired: ${age}ms old (max ${this.maxAge}ms)`);
    }

    // Verify nonce matches what we sent
    if (response.nonce !== pending.nonce) {
      throw new Error('[Agent Shield] Handshake nonce mismatch');
    }

    // Verify response signature
    const responseSigInput = `${response.fromAgent}:${response.toAgent}:${response.nonce}:${response.counterNonce}:${response.timestamp}`;
    const expectedSig = crypto.createHmac('sha256', this.secretKey).update(responseSigInput).digest('hex');

    try {
      const valid = crypto.timingSafeEqual(
        Buffer.from(response.signature, 'hex'),
        Buffer.from(expectedSig, 'hex')
      );
      if (!valid) {
        throw new Error('[Agent Shield] Handshake response signature invalid');
      }
    } catch (e) {
      if (e.message.includes('signature invalid')) throw e;
      throw new Error('[Agent Shield] Handshake response signature invalid');
    }

    // Derive shared secret from combined nonces
    const sharedSecret = crypto.createHmac('sha256', this.secretKey)
      .update(`${response.nonce}:${response.counterNonce}`)
      .digest('hex');

    // Mark handshake complete
    this.pendingHandshakes.set(response.fromAgent, {
      ...pending,
      counterNonce: response.counterNonce,
      state: 'completed',
      sharedSecret
    });

    return {
      sharedSecret,
      remoteCapabilities: response.capabilities || []
    };
  }
}

// =========================================================================
// MessageRouter — Routes messages between multiple agents
// =========================================================================

/**
 * Routes protocol messages between multiple connected agents.
 */
class MessageRouter {
  constructor() {
    /** @type {Map<string, SecureChannel>} */
    this.routes = new Map();
  }

  /**
   * Register a route to an agent.
   * @param {string} agentId - Agent ID to route to
   * @param {SecureChannel} channel - Channel to route through
   */
  addRoute(agentId, channel) {
    if (!agentId || !channel) {
      throw new Error('[Agent Shield] addRoute requires agentId and channel');
    }
    this.routes.set(agentId, channel);
  }

  /**
   * Unregister a route.
   * @param {string} agentId - Agent ID to remove
   * @returns {boolean} True if route existed and was removed
   */
  removeRoute(agentId) {
    return this.routes.delete(agentId);
  }

  /**
   * Route a message to the correct channel based on recipient.
   * @param {ProtocolMessage} message - Message to route (payload.recipient identifies target)
   * @returns {string|null} Encrypted envelope if routed, null if no route found
   */
  route(message) {
    const recipient = message.payload && message.payload.recipient;
    if (!recipient) {
      throw new Error('[Agent Shield] Message must have payload.recipient for routing');
    }

    const channel = this.routes.get(recipient);
    if (!channel || !channel.isOpen()) {
      return null;
    }

    return channel.send(message.payload, message.type);
  }

  /**
   * Broadcast a threat alert to all connected agents.
   * @param {object} threat - Threat information to broadcast
   * @returns {string[]} Array of sent envelopes
   */
  broadcastThreat(threat) {
    const results = [];
    for (const [agentId, channel] of this.routes.entries()) {
      if (channel.isOpen()) {
        try {
          const envelope = channel.send(threat, 'threat_alert');
          results.push(envelope);
        } catch (e) {
          console.error(`[Agent Shield] Failed to broadcast threat to ${agentId}: ${e.message}`);
        }
      }
    }
    return results;
  }

  /**
   * Get the network topology of connected agents.
   * @returns {object} Topology map: { agents, connections, openChannels }
   */
  getTopology() {
    const agents = [];
    const connections = [];
    let openChannels = 0;

    for (const [agentId, channel] of this.routes.entries()) {
      const isOpen = channel.isOpen();
      agents.push({
        agentId,
        isOpen,
        latency: channel.getLatency()
      });
      connections.push({
        from: channel.localIdentity.agentId,
        to: agentId,
        open: isOpen
      });
      if (isOpen) openChannels++;
    }

    return { agents, connections, openChannels };
  }

  /**
   * Get the number of active routes.
   * @returns {number} Number of registered routes
   */
  getRouteCount() {
    return this.routes.size;
  }
}

// =========================================================================
// AgentProtocol — Main protocol coordinator
// =========================================================================

/**
 * Main protocol coordinator for secure agent-to-agent communication.
 * Manages identities, channels, handshakes, and message routing.
 */
class AgentProtocol {
  /**
   * @param {object} [config={}]
   * @param {string} config.agentId - Unique agent identifier
   * @param {string} config.secretKey - Secret key for signing and encryption
   * @param {string} [config.protocolVersion='1.0'] - Protocol version
   * @param {number} [config.maxChannels=100] - Maximum concurrent channels
   * @param {number} [config.messageTimeout=30000] - Message timeout in ms
   * @param {boolean} [config.requireMutualAuth=true] - Require mutual authentication
   */
  constructor(config = {}) {
    if (!config.agentId) {
      throw new Error('[Agent Shield] AgentProtocol requires config.agentId');
    }
    if (!config.secretKey) {
      throw new Error('[Agent Shield] AgentProtocol requires config.secretKey');
    }

    this.agentId = config.agentId;
    this.secretKey = config.secretKey;
    this.protocolVersion = config.protocolVersion || PROTOCOL_VERSION;
    this.maxChannels = config.maxChannels || 100;
    this.messageTimeout = config.messageTimeout || 30000;
    this.requireMutualAuth = config.requireMutualAuth !== false;

    /** @type {Map<string, SecureChannel>} */
    this.channels = new Map();
    this.router = new MessageRouter();
    this.identity = null;

    this.stats = {
      messagesSent: 0,
      messagesReceived: 0,
      channelsOpened: 0,
      channelsClosed: 0,
      authFailures: 0,
      handshakesInitiated: 0,
      handshakesCompleted: 0
    };
  }

  /**
   * Create a signed agent identity.
   * @param {string} agentId - Agent identifier
   * @param {string[]} [capabilities=[]] - Agent capabilities
   * @param {object} [metadata={}] - Additional metadata
   * @returns {AgentIdentity} Signed identity
   */
  createIdentity(agentId, capabilities = [], metadata = {}) {
    const identity = new AgentIdentity(agentId, capabilities, metadata);
    identity.sign(this.secretKey);
    identity.trustLevel = 'verified';

    if (agentId === this.agentId) {
      this.identity = identity;
    }

    return identity;
  }

  /**
   * Initiate a handshake and open a secure channel to a remote agent.
   * @param {AgentIdentity} remoteIdentity - Remote agent's identity
   * @returns {object} { channel, handshakeRequest }
   */
  openChannel(remoteIdentity) {
    if (this.channels.size >= this.maxChannels) {
      throw new Error(`[Agent Shield] Maximum channels (${this.maxChannels}) reached`);
    }

    if (!this.identity) {
      this.identity = this.createIdentity(this.agentId, [], {});
    }

    const handshake = new HandshakeManager(this.identity, this.secretKey);
    const request = handshake.initiateHandshake(remoteIdentity.agentId);
    this.stats.handshakesInitiated++;

    // Store handshake manager for later completion
    this._pendingHandshakes = this._pendingHandshakes || new Map();
    this._pendingHandshakes.set(remoteIdentity.agentId, {
      handshake,
      remoteIdentity
    });

    return {
      channel: null, // Channel created after handshake completes
      handshakeRequest: request
    };
  }

  /**
   * Accept an incoming handshake and establish a secure channel.
   * @param {object} handshakeRequest - Incoming handshake request
   * @returns {object} { channel, handshakeResponse }
   */
  acceptChannel(handshakeRequest) {
    if (this.channels.size >= this.maxChannels) {
      throw new Error(`[Agent Shield] Maximum channels (${this.maxChannels}) reached`);
    }

    if (!this.identity) {
      this.identity = this.createIdentity(this.agentId, [], {});
    }

    const handshake = new HandshakeManager(this.identity, this.secretKey);

    let response;
    try {
      response = handshake.respondToHandshake(handshakeRequest);
    } catch (e) {
      this.stats.authFailures++;
      throw e;
    }

    // Derive shared secret for the responder side
    const sharedSecret = crypto.createHmac('sha256', this.secretKey)
      .update(`${handshakeRequest.nonce}:${response.counterNonce}`)
      .digest('hex');

    // Create remote identity from request info
    const remoteIdentity = new AgentIdentity(
      handshakeRequest.fromAgent,
      handshakeRequest.capabilities || [],
      {}
    );
    remoteIdentity.trustLevel = 'verified';

    const channel = new SecureChannel(this.identity, remoteIdentity, sharedSecret);
    this.channels.set(handshakeRequest.fromAgent, channel);
    this.router.addRoute(handshakeRequest.fromAgent, channel);
    this.stats.channelsOpened++;
    this.stats.handshakesCompleted++;

    return {
      channel,
      handshakeResponse: response
    };
  }

  /**
   * Complete an initiated handshake and open the channel.
   * Called by the initiator after receiving the handshake response.
   * @param {object} handshakeResponse - Response from the remote agent
   * @returns {SecureChannel} Established secure channel
   */
  completeChannel(handshakeResponse) {
    this._pendingHandshakes = this._pendingHandshakes || new Map();
    const pending = this._pendingHandshakes.get(handshakeResponse.fromAgent);
    if (!pending) {
      throw new Error(`[Agent Shield] No pending handshake for agent: ${handshakeResponse.fromAgent}`);
    }

    let result;
    try {
      result = pending.handshake.completeHandshake(handshakeResponse);
    } catch (e) {
      this.stats.authFailures++;
      throw e;
    }

    const channel = new SecureChannel(this.identity, pending.remoteIdentity, result.sharedSecret);
    this.channels.set(handshakeResponse.fromAgent, channel);
    this.router.addRoute(handshakeResponse.fromAgent, channel);
    this._pendingHandshakes.delete(handshakeResponse.fromAgent);
    this.stats.channelsOpened++;
    this.stats.handshakesCompleted++;

    return channel;
  }

  /**
   * Broadcast a message to multiple channels.
   * @param {*} message - Message payload to broadcast
   * @param {SecureChannel[]} [channels] - Channels to broadcast to (defaults to all)
   * @returns {string[]} Array of sent envelopes
   */
  broadcast(message, channels) {
    const targets = channels || Array.from(this.channels.values());
    const results = [];

    for (const channel of targets) {
      if (channel.isOpen()) {
        try {
          const envelope = channel.send(message, 'data');
          results.push(envelope);
          this.stats.messagesSent++;
        } catch (e) {
          console.error(`[Agent Shield] Broadcast failed: ${e.message}`);
        }
      }
    }

    return results;
  }

  /**
   * List all active (open) channels.
   * @returns {object[]} Array of channel info objects
   */
  getActiveChannels() {
    const active = [];
    for (const [agentId, channel] of this.channels.entries()) {
      if (channel.isOpen()) {
        active.push({
          agentId,
          localAgent: channel.localIdentity.agentId,
          remoteAgent: channel.remoteIdentity.agentId,
          open: true,
          latency: channel.getLatency(),
          messageCount: channel.messageHistory.length,
          createdAt: channel.createdAt
        });
      }
    }
    return active;
  }

  /**
   * Get protocol statistics.
   * @returns {object} Stats including messages sent/received, channels opened, auth failures
   */
  getStats() {
    return {
      ...this.stats,
      activeChannels: Array.from(this.channels.values()).filter(c => c.isOpen()).length,
      totalChannels: this.channels.size,
      routeCount: this.router.getRouteCount()
    };
  }
}

// =========================================================================
// Exports
// =========================================================================

module.exports = {
  AgentProtocol,
  SecureChannel,
  HandshakeManager,
  AgentIdentity,
  ProtocolMessage,
  MessageRouter,
  PROTOCOL_VERSION
};
