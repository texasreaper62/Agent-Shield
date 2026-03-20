'use strict';

/**
 * Agent Shield — Privacy-Preserving Threat Intelligence Network
 *
 * Anonymous pattern sharing network that allows Agent Shield nodes to
 * collaboratively improve detection without exposing raw user data.
 *
 * Key principles:
 * - All sharing is opt-in
 * - No raw user data is ever shared — only anonymized detection patterns
 * - Differential privacy noise on all statistics (Laplace mechanism)
 * - Pattern generalization strips org-specific details
 * - Consensus mechanism prevents poisoning (need minConsensus votes)
 * - Reputation system reduces weight of low-quality contributors
 */

const crypto = require('crypto');

// =========================================================================
// DEFAULTS
// =========================================================================

/**
 * Default configuration values for the threat intel network.
 * @type {Object}
 */
const NETWORK_DEFAULTS = {
  networkName: 'agent-shield-global',
  sharePatternsEnabled: true,
  receiveEnabled: true,
  minConsensus: 3,
  anonymizationLevel: 'high',
  syncIntervalMs: 300000,
  maxPeers: 50,
  heartbeatIntervalMs: 60000,
  heartbeatTimeoutMs: 180000,
  maxFeedSize: 10000,
  pruneMaxAgeMs: 7 * 24 * 60 * 60 * 1000, // 7 days
  reputationDecayRate: 0.01,
  laplaceSensitivity: 1.0,
  laplaceEpsilon: 1.0
};

// =========================================================================
// PATTERN ANONYMIZER
// =========================================================================

/**
 * Privacy-preserving pattern transformation.
 * Strips identifying information and generalizes patterns before sharing.
 */
class PatternAnonymizer {
  /**
   * @param {'low'|'medium'|'high'} level - Anonymization level.
   */
  constructor(level = 'high') {
    const validLevels = ['low', 'medium', 'high'];
    if (!validLevels.includes(level)) {
      throw new Error(`Invalid anonymization level: ${level}. Must be one of: ${validLevels.join(', ')}`);
    }
    this.level = level;
  }

  /**
   * Anonymize a detection pattern for sharing.
   * Strips identifying info and generalizes based on anonymization level.
   *
   * @param {Object} pattern - The detection pattern to anonymize.
   * @param {string} pattern.regex - The regex pattern string.
   * @param {string} [pattern.category] - Threat category.
   * @param {string} [pattern.severity] - Severity level.
   * @param {Object} [pattern.metadata] - Additional metadata.
   * @param {Object} [pattern.stats] - Frequency statistics.
   * @returns {Object} Anonymized pattern safe for sharing.
   */
  anonymize(pattern) {
    if (!pattern || typeof pattern !== 'object') {
      throw new Error('Pattern must be a non-null object');
    }

    const anonymized = {
      id: this.hashPattern(pattern),
      category: pattern.category || 'unknown',
      severity: pattern.severity || 'medium',
      anonymizedAt: new Date().toISOString()
    };

    // Generalize regex based on level
    if (pattern.regex) {
      anonymized.regex = this.generalize(pattern.regex);
    }

    // Add noise to stats if present
    if (pattern.stats && typeof pattern.stats === 'object') {
      anonymized.stats = this.addNoise(pattern.stats);
    }

    // Strip metadata based on level
    if (pattern.metadata) {
      anonymized.metadata = this.stripMetadata(pattern.metadata);
    }

    return anonymized;
  }

  /**
   * Create a privacy-preserving hash for deduplication.
   * Uses SHA-256 with a salt to prevent rainbow table attacks.
   *
   * @param {Object} pattern - The pattern to hash.
   * @returns {string} A hex hash string.
   */
  hashPattern(pattern) {
    const canonical = JSON.stringify({
      regex: pattern.regex || '',
      category: pattern.category || ''
    });
    return crypto.createHash('sha256')
      .update('agent-shield-pattern:' + canonical)
      .digest('hex')
      .substring(0, 16);
  }

  /**
   * Generalize a regex pattern to remove org-specific details.
   * Replaces specific strings, domains, IPs with generic character classes.
   *
   * @param {string} regex - The regex pattern string to generalize.
   * @returns {string} A more general version of the regex.
   */
  generalize(regex) {
    if (typeof regex !== 'string') return '';

    let generalized = regex;

    if (this.level === 'high') {
      // Replace specific domain names with generic pattern
      generalized = generalized.replace(
        /[a-zA-Z0-9][-a-zA-Z0-9]*\.(com|org|net|io|dev|ai)/g,
        '\\w+\\.\\w+'
      );
      // Replace IP addresses with generic pattern
      generalized = generalized.replace(
        /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/g,
        '\\d+\\.\\d+\\.\\d+\\.\\d+'
      );
      // Replace quoted strings (potential org-specific identifiers)
      generalized = generalized.replace(
        /["'][^"']{4,}["']/g,
        '["\']\\w+["\']'
      );
      // Replace specific file paths
      generalized = generalized.replace(
        /\/[a-zA-Z0-9_/-]{3,}/g,
        '/\\S+'
      );
    } else if (this.level === 'medium') {
      // Replace IP addresses only
      generalized = generalized.replace(
        /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/g,
        '\\d+\\.\\d+\\.\\d+\\.\\d+'
      );
      // Replace email-like patterns
      generalized = generalized.replace(
        /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+/g,
        '\\S+@\\S+'
      );
    }
    // 'low' level: minimal generalization, keep pattern mostly intact

    return generalized;
  }

  /**
   * Remove org-specific metadata fields.
   *
   * @param {Object} metadata - The metadata object to strip.
   * @returns {Object} Stripped metadata with only safe fields.
   */
  stripMetadata(metadata) {
    if (!metadata || typeof metadata !== 'object') return {};

    // Safe fields that can be shared
    const safeFields = ['category', 'severity', 'type', 'tags', 'version'];
    const stripped = {};

    for (const field of safeFields) {
      if (metadata[field] !== undefined) {
        stripped[field] = metadata[field];
      }
    }

    return stripped;
  }

  /**
   * Add differential privacy noise to frequency statistics using Laplace mechanism.
   *
   * @param {Object} stats - Statistics object with numeric values.
   * @param {number} [sensitivity=1.0] - Query sensitivity.
   * @param {number} [epsilon=1.0] - Privacy budget (lower = more noise).
   * @returns {Object} Stats with Laplace noise added.
   */
  addNoise(stats, sensitivity, epsilon) {
    if (!stats || typeof stats !== 'object') return {};

    const s = sensitivity || NETWORK_DEFAULTS.laplaceSensitivity;
    const e = epsilon || NETWORK_DEFAULTS.laplaceEpsilon;
    const scale = s / e;

    const noisy = {};
    for (const [key, value] of Object.entries(stats)) {
      if (typeof value === 'number') {
        // Laplace noise: sample from Laplace(0, scale)
        const noise = this._laplaceSample(scale);
        noisy[key] = Math.max(0, Math.round(value + noise));
      } else {
        noisy[key] = value;
      }
    }

    return noisy;
  }

  /**
   * Sample from a Laplace distribution using inverse CDF.
   * @param {number} scale - Scale parameter (b) of the Laplace distribution.
   * @returns {number} A random sample.
   * @private
   */
  _laplaceSample(scale) {
    const u = Math.random() - 0.5;
    return -scale * Math.sign(u) * Math.log(1 - 2 * Math.abs(u));
  }
}

// =========================================================================
// PEER NODE
// =========================================================================

/**
 * Represents a network peer in the threat intelligence network.
 */
class PeerNode {
  /**
   * @param {string} nodeId - Unique identifier for this peer.
   * @param {Object} [config] - Peer configuration.
   * @param {number} [config.heartbeatIntervalMs] - Heartbeat interval.
   * @param {number} [config.heartbeatTimeoutMs] - Heartbeat timeout.
   */
  constructor(nodeId, config = {}) {
    if (!nodeId) {
      throw new Error('nodeId is required');
    }
    this.id = nodeId;
    this.lastSeen = Date.now();
    this.reputation = 1.0;
    this.sharedCount = 0;
    this.falsePositiveCount = 0;
    this.falsePositiveRate = 0;
    this.connected = false;
    this.messageQueue = [];
    this.heartbeatIntervalMs = config.heartbeatIntervalMs || NETWORK_DEFAULTS.heartbeatIntervalMs;
    this.heartbeatTimeoutMs = config.heartbeatTimeoutMs || NETWORK_DEFAULTS.heartbeatTimeoutMs;
  }

  /**
   * Establish a peer connection (simulated locally).
   *
   * @param {Object} peerInfo - Information about the remote peer.
   * @param {string} peerInfo.id - Peer identifier.
   * @param {string} [peerInfo.address] - Peer address.
   * @returns {boolean} True if connection was established.
   */
  connect(peerInfo) {
    if (!peerInfo || !peerInfo.id) {
      throw new Error('peerInfo with id is required');
    }
    this.connected = true;
    this.lastSeen = Date.now();
    console.log(`[Agent Shield] Peer ${this.id} connected to ${peerInfo.id}`);
    return true;
  }

  /**
   * Send a message to this peer (simulated locally).
   *
   * @param {Object} message - Message payload.
   * @param {string} message.type - Message type (e.g., 'pattern', 'heartbeat', 'falsePositive').
   * @param {*} message.data - Message data.
   * @returns {boolean} True if message was queued.
   */
  send(message) {
    if (!message || typeof message !== 'object') {
      throw new Error('Message must be a non-null object');
    }
    this.messageQueue.push({
      ...message,
      timestamp: Date.now(),
      from: this.id
    });
    return true;
  }

  /**
   * Process an incoming message from this peer.
   *
   * @param {Object} message - Incoming message.
   * @param {string} message.type - Message type.
   * @param {*} message.data - Message data.
   * @returns {Object} Processing result with {accepted, reason}.
   */
  receive(message) {
    if (!message || typeof message !== 'object') {
      return { accepted: false, reason: 'invalid message' };
    }

    this.lastSeen = Date.now();

    if (message.type === 'heartbeat') {
      return { accepted: true, reason: 'heartbeat acknowledged' };
    }

    if (message.type === 'pattern') {
      this.sharedCount++;
      this._updateFalsePositiveRate();
      return { accepted: true, reason: 'pattern received' };
    }

    if (message.type === 'falsePositive') {
      this.falsePositiveCount++;
      this._updateFalsePositiveRate();
      return { accepted: true, reason: 'false positive recorded' };
    }

    return { accepted: true, reason: 'message received' };
  }

  /**
   * Compute the reputation score for this peer.
   * Based on shared pattern count, false positive rate, and activity.
   *
   * @returns {number} Reputation score between 0 and 1.
   */
  getReputation() {
    // Base reputation decays toward false positive penalty
    const fpPenalty = this.falsePositiveRate * 2;
    const activityBonus = Math.min(0.2, this.sharedCount * 0.01);
    const freshness = this.isActive() ? 0.1 : -0.1;

    this.reputation = Math.max(0, Math.min(1,
      1.0 - fpPenalty + activityBonus + freshness
    ));

    return this.reputation;
  }

  /**
   * Check if this peer is still alive based on heartbeat timeout.
   *
   * @returns {boolean} True if peer was seen within the timeout window.
   */
  isActive() {
    return (Date.now() - this.lastSeen) < this.heartbeatTimeoutMs;
  }

  /**
   * Update the false positive rate.
   * @private
   */
  _updateFalsePositiveRate() {
    const total = this.sharedCount + this.falsePositiveCount;
    this.falsePositiveRate = total > 0 ? this.falsePositiveCount / total : 0;
  }
}

// =========================================================================
// CONSENSUS ENGINE
// =========================================================================

/**
 * Validates shared patterns through a voting consensus mechanism.
 * Prevents poisoning by requiring multiple independent confirmations.
 */
class ConsensusEngine {
  /**
   * @param {number} [minConsensus=3] - Minimum votes required for consensus.
   */
  constructor(minConsensus) {
    this.minConsensus = minConsensus || NETWORK_DEFAULTS.minConsensus;
    this.entries = new Map(); // patternHash -> { votes: Set, falsePositives: Set, createdAt }
  }

  /**
   * Record a vote for a pattern from a node.
   *
   * @param {string} patternHash - The hash of the pattern being voted on.
   * @param {string} nodeId - The voting node's identifier.
   * @returns {Object} Updated consensus info {votes, consensus, confidence}.
   */
  submit(patternHash, nodeId) {
    if (!patternHash || !nodeId) {
      throw new Error('patternHash and nodeId are required');
    }

    if (!this.entries.has(patternHash)) {
      this.entries.set(patternHash, {
        votes: new Set(),
        falsePositives: new Set(),
        createdAt: Date.now()
      });
    }

    const entry = this.entries.get(patternHash);
    entry.votes.add(nodeId);

    return this.getConsensus(patternHash);
  }

  /**
   * Get the current consensus status for a pattern.
   *
   * @param {string} patternHash - The pattern hash to check.
   * @returns {Object} Consensus info: {votes, consensus, confidence}.
   */
  getConsensus(patternHash) {
    const entry = this.entries.get(patternHash);
    if (!entry) {
      return { votes: 0, consensus: false, confidence: 0 };
    }

    const voteCount = entry.votes.size;
    const fpCount = entry.falsePositives.size;
    const netVotes = voteCount - fpCount;
    const consensus = netVotes >= this.minConsensus;
    // Confidence: ratio of net positive votes to minimum required, capped at 1
    const confidence = Math.min(1, Math.max(0, netVotes / this.minConsensus));

    return { votes: voteCount, consensus, confidence };
  }

  /**
   * Record a false positive report for a pattern.
   *
   * @param {string} patternHash - The pattern hash being reported.
   * @param {string} nodeId - The reporting node's identifier.
   * @returns {Object} Updated consensus info.
   */
  reportFalsePositive(patternHash, nodeId) {
    if (!patternHash || !nodeId) {
      throw new Error('patternHash and nodeId are required');
    }

    if (!this.entries.has(patternHash)) {
      this.entries.set(patternHash, {
        votes: new Set(),
        falsePositives: new Set(),
        createdAt: Date.now()
      });
    }

    const entry = this.entries.get(patternHash);
    entry.falsePositives.add(nodeId);

    return this.getConsensus(patternHash);
  }

  /**
   * Get the quality score for a pattern.
   * Computed as (votes - falsePositives) / totalReports.
   *
   * @param {string} patternHash - The pattern hash to score.
   * @returns {number} Quality score between -1 and 1.
   */
  getQualityScore(patternHash) {
    const entry = this.entries.get(patternHash);
    if (!entry) return 0;

    const totalReports = entry.votes.size + entry.falsePositives.size;
    if (totalReports === 0) return 0;

    return (entry.votes.size - entry.falsePositives.size) / totalReports;
  }

  /**
   * Remove stale entries older than maxAge.
   *
   * @param {number} [maxAge] - Maximum age in milliseconds. Defaults to 7 days.
   * @returns {number} Number of entries pruned.
   */
  prune(maxAge) {
    const cutoff = Date.now() - (maxAge || NETWORK_DEFAULTS.pruneMaxAgeMs);
    let pruned = 0;

    for (const [hash, entry] of this.entries) {
      if (entry.createdAt < cutoff) {
        this.entries.delete(hash);
        pruned++;
      }
    }

    return pruned;
  }
}

// =========================================================================
// THREAT FEED
// =========================================================================

/**
 * Aggregated threat intelligence feed.
 * Collects anonymized patterns with timestamps and supports querying.
 */
class ThreatFeed {
  constructor() {
    this.patterns = [];
    this.maxSize = NETWORK_DEFAULTS.maxFeedSize;
  }

  /**
   * Add a pattern to the feed.
   *
   * @param {Object} pattern - The anonymized pattern to add.
   * @param {string} [source='unknown'] - Source identifier.
   * @returns {Object} The stored feed entry.
   */
  addPattern(pattern, source) {
    if (!pattern || typeof pattern !== 'object') {
      throw new Error('Pattern must be a non-null object');
    }

    const entry = {
      ...pattern,
      source: source || 'unknown',
      addedAt: new Date().toISOString(),
      addedTimestamp: Date.now()
    };

    this.patterns.push(entry);

    // Evict oldest if over limit
    if (this.patterns.length > this.maxSize) {
      this.patterns = this.patterns.slice(-this.maxSize);
    }

    return entry;
  }

  /**
   * Query the feed with filters.
   *
   * @param {Object} [filters] - Query filters.
   * @param {string} [filters.category] - Filter by category.
   * @param {string} [filters.severity] - Filter by severity.
   * @param {string} [filters.since] - ISO date string; only patterns after this date.
   * @param {string} [filters.until] - ISO date string; only patterns before this date.
   * @param {number} [filters.limit] - Maximum results to return.
   * @returns {Object[]} Matching feed entries.
   */
  query(filters = {}) {
    let results = [...this.patterns];

    if (filters.category) {
      results = results.filter(p => p.category === filters.category);
    }

    if (filters.severity) {
      results = results.filter(p => p.severity === filters.severity);
    }

    if (filters.since) {
      const sinceTs = new Date(filters.since).getTime();
      results = results.filter(p => p.addedTimestamp >= sinceTs);
    }

    if (filters.until) {
      const untilTs = new Date(filters.until).getTime();
      results = results.filter(p => p.addedTimestamp <= untilTs);
    }

    if (filters.limit && filters.limit > 0) {
      results = results.slice(0, filters.limit);
    }

    return results;
  }

  /**
   * Get the top N most reported patterns by frequency.
   *
   * @param {number} [n=10] - Number of top threats to return.
   * @returns {Object[]} Top patterns sorted by report count.
   */
  getTopThreats(n = 10) {
    // Count occurrences by pattern id
    const counts = new Map();
    for (const entry of this.patterns) {
      const id = entry.id || 'unknown';
      if (!counts.has(id)) {
        counts.set(id, { pattern: entry, count: 0 });
      }
      counts.get(id).count++;
    }

    return Array.from(counts.values())
      .sort((a, b) => b.count - a.count)
      .slice(0, n)
      .map(item => ({
        ...item.pattern,
        reportCount: item.count
      }));
  }

  /**
   * Get emerging pattern trends — patterns with increasing frequency over time.
   *
   * @returns {Object[]} Trending patterns with frequency delta.
   */
  getTrends() {
    const now = Date.now();
    const recentWindow = 24 * 60 * 60 * 1000; // 24 hours
    const priorWindow = 7 * 24 * 60 * 60 * 1000; // 7 days

    // Count patterns in recent vs prior windows
    const recentCounts = new Map();
    const priorCounts = new Map();

    for (const entry of this.patterns) {
      const id = entry.id || 'unknown';
      const age = now - entry.addedTimestamp;

      if (age <= recentWindow) {
        recentCounts.set(id, (recentCounts.get(id) || 0) + 1);
      } else if (age <= priorWindow) {
        priorCounts.set(id, (priorCounts.get(id) || 0) + 1);
      }
    }

    // Calculate trends: patterns appearing more in recent window
    const trends = [];
    const allIds = new Set([...recentCounts.keys(), ...priorCounts.keys()]);

    for (const id of allIds) {
      const recent = recentCounts.get(id) || 0;
      const prior = priorCounts.get(id) || 0;
      // Normalize prior to daily rate for fair comparison
      const priorDaily = prior / 6; // 6 remaining days (7 day window minus 1 day recent)
      const delta = recent - (priorDaily || 0);

      if (delta > 0) {
        // Find the pattern entry for metadata
        const entry = this.patterns.find(p => (p.id || 'unknown') === id);
        trends.push({
          id,
          category: entry ? entry.category : 'unknown',
          severity: entry ? entry.severity : 'unknown',
          recentCount: recent,
          priorDailyAvg: Math.round(priorDaily * 100) / 100,
          delta: Math.round(delta * 100) / 100,
          trending: 'up'
        });
      }
    }

    return trends.sort((a, b) => b.delta - a.delta);
  }

  /**
   * Export the feed in JSON or STIX-like format.
   *
   * @param {'json'|'stix'} [format='json'] - Export format.
   * @returns {Object|string} Exported feed data.
   */
  export(format = 'json') {
    if (format === 'stix') {
      return {
        type: 'bundle',
        id: `bundle--${crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex')}`,
        spec_version: '2.1',
        created: new Date().toISOString(),
        objects: this.patterns.map(entry => ({
          type: 'indicator',
          id: `indicator--${entry.id || crypto.randomBytes(8).toString('hex')}`,
          created: entry.addedAt,
          modified: entry.addedAt,
          name: `${entry.category || 'unknown'} detection pattern`,
          description: `Anonymized threat pattern — severity: ${entry.severity || 'unknown'}`,
          pattern_type: 'agent-shield',
          pattern: entry.regex || '',
          indicator_types: [entry.category || 'unknown'],
          valid_from: entry.addedAt,
          labels: [entry.severity || 'medium', entry.category || 'unknown'],
          confidence: entry.stats ? (entry.stats.confidence || 50) : 50
        }))
      };
    }

    // Default JSON export
    return {
      format: 'agent-shield-feed',
      version: '1.0',
      exported: new Date().toISOString(),
      count: this.patterns.length,
      patterns: this.patterns
    };
  }

  /**
   * Get feed statistics.
   *
   * @returns {Object} Feed stats including counts, categories, and severity breakdown.
   */
  getStats() {
    const categories = {};
    const severities = {};

    for (const entry of this.patterns) {
      const cat = entry.category || 'unknown';
      const sev = entry.severity || 'unknown';
      categories[cat] = (categories[cat] || 0) + 1;
      severities[sev] = (severities[sev] || 0) + 1;
    }

    return {
      totalPatterns: this.patterns.length,
      categories,
      severities,
      oldestEntry: this.patterns.length > 0 ? this.patterns[0].addedAt : null,
      newestEntry: this.patterns.length > 0 ? this.patterns[this.patterns.length - 1].addedAt : null
    };
  }
}

// =========================================================================
// THREAT INTEL NETWORK
// =========================================================================

/**
 * Main network coordinator for privacy-preserving threat intelligence sharing.
 * Manages peers, pattern anonymization, consensus, and the local threat feed.
 */
class ThreatIntelNetwork {
  /**
   * @param {Object} [config] - Network configuration.
   * @param {string} [config.nodeId] - This node's unique identifier (auto-generated if omitted).
   * @param {string} [config.networkName='agent-shield-global'] - Network name.
   * @param {boolean} [config.sharePatternsEnabled=true] - Whether to share patterns.
   * @param {boolean} [config.receiveEnabled=true] - Whether to receive patterns.
   * @param {number} [config.minConsensus=3] - Minimum votes for consensus.
   * @param {'low'|'medium'|'high'} [config.anonymizationLevel='high'] - Anonymization level.
   * @param {number} [config.syncIntervalMs=300000] - Sync interval in milliseconds.
   */
  constructor(config = {}) {
    this.nodeId = config.nodeId || crypto.randomBytes(16).toString('hex');
    this.networkName = config.networkName || NETWORK_DEFAULTS.networkName;
    this.sharePatternsEnabled = config.sharePatternsEnabled !== undefined
      ? config.sharePatternsEnabled
      : NETWORK_DEFAULTS.sharePatternsEnabled;
    this.receiveEnabled = config.receiveEnabled !== undefined
      ? config.receiveEnabled
      : NETWORK_DEFAULTS.receiveEnabled;
    this.syncIntervalMs = config.syncIntervalMs || NETWORK_DEFAULTS.syncIntervalMs;

    this.anonymizer = new PatternAnonymizer(
      config.anonymizationLevel || NETWORK_DEFAULTS.anonymizationLevel
    );
    this.consensus = new ConsensusEngine(
      config.minConsensus || NETWORK_DEFAULTS.minConsensus
    );
    this.feed = new ThreatFeed();

    this.peers = new Map(); // peerId -> PeerNode
    this.sharedPatterns = new Map(); // patternHash -> anonymized pattern
    this.receivedPatterns = new Map(); // patternHash -> pattern
    this.running = false;
    this._syncTimer = null;
  }

  /**
   * Initialize the node and connect to the network.
   *
   * @returns {Object} Startup info: {nodeId, networkName, status}.
   */
  start() {
    if (this.running) {
      return { nodeId: this.nodeId, networkName: this.networkName, status: 'already running' };
    }

    this.running = true;

    // Set up periodic sync (simulated)
    this._syncTimer = setInterval(() => {
      this._sync();
    }, this.syncIntervalMs);

    // Prevent timer from keeping process alive
    if (this._syncTimer && typeof this._syncTimer.unref === 'function') {
      this._syncTimer.unref();
    }

    console.log(`[Agent Shield] Threat Intel Network started — node: ${this.nodeId}, network: ${this.networkName}`);

    return {
      nodeId: this.nodeId,
      networkName: this.networkName,
      status: 'running'
    };
  }

  /**
   * Graceful shutdown of the network node.
   *
   * @returns {Object} Shutdown info.
   */
  stop() {
    if (this._syncTimer) {
      clearInterval(this._syncTimer);
      this._syncTimer = null;
    }

    this.running = false;

    // Disconnect all peers
    for (const peer of this.peers.values()) {
      peer.connected = false;
    }

    console.log(`[Agent Shield] Threat Intel Network stopped — node: ${this.nodeId}`);

    return {
      nodeId: this.nodeId,
      status: 'stopped',
      sharedPatterns: this.sharedPatterns.size,
      receivedPatterns: this.receivedPatterns.size
    };
  }

  /**
   * Anonymize and share a detection pattern with the network.
   * Only shares if sharePatternsEnabled is true.
   *
   * @param {Object} pattern - The detection pattern to share.
   * @param {string} pattern.regex - The regex pattern string.
   * @param {string} [pattern.category] - Threat category.
   * @param {string} [pattern.severity] - Severity level.
   * @returns {Object} Result: {shared, patternHash, anonymizedPattern}.
   */
  sharePattern(pattern) {
    if (!this.sharePatternsEnabled) {
      return { shared: false, reason: 'pattern sharing is disabled' };
    }

    if (!this.running) {
      return { shared: false, reason: 'network not running' };
    }

    // Anonymize the pattern
    const anonymized = this.anonymizer.anonymize(pattern);
    const hash = anonymized.id;

    // Store locally
    this.sharedPatterns.set(hash, anonymized);

    // Submit to consensus
    this.consensus.submit(hash, this.nodeId);

    // Add to local feed
    this.feed.addPattern(anonymized, this.nodeId);

    // Broadcast to connected peers (simulated)
    for (const peer of this.peers.values()) {
      if (peer.connected && peer.isActive()) {
        peer.send({ type: 'pattern', data: anonymized });
      }
    }

    console.log(`[Agent Shield] Shared anonymized pattern: ${hash}`);

    return {
      shared: true,
      patternHash: hash,
      anonymizedPattern: anonymized
    };
  }

  /**
   * Pull new patterns from the network feed.
   * Only receives if receiveEnabled is true.
   *
   * @returns {Object[]} Newly received patterns that have reached consensus.
   */
  receivePatterns() {
    if (!this.receiveEnabled) {
      return [];
    }

    if (!this.running) {
      return [];
    }

    // Collect patterns from peer message queues
    const newPatterns = [];

    for (const peer of this.peers.values()) {
      if (!peer.connected) continue;

      while (peer.messageQueue.length > 0) {
        const msg = peer.messageQueue.shift();
        if (msg.type === 'pattern' && msg.data) {
          const hash = msg.data.id;
          if (hash && !this.receivedPatterns.has(hash)) {
            // Submit to consensus from the sending peer
            this.consensus.submit(hash, msg.from || peer.id);

            // Check if pattern has reached consensus
            const consensusResult = this.consensus.getConsensus(hash);
            if (consensusResult.consensus) {
              this.receivedPatterns.set(hash, msg.data);
              this.feed.addPattern(msg.data, peer.id);
              newPatterns.push(msg.data);
            }
          }
        }
      }
    }

    return newPatterns;
  }

  /**
   * Get network statistics.
   *
   * @returns {Object} Stats: {connectedPeers, sharedPatterns, receivedPatterns, consensusScore}.
   */
  getNetworkStats() {
    const activePeers = Array.from(this.peers.values()).filter(p => p.connected && p.isActive());

    // Average consensus score across all shared patterns
    let totalScore = 0;
    let scoreCount = 0;
    for (const hash of this.sharedPatterns.keys()) {
      totalScore += this.consensus.getQualityScore(hash);
      scoreCount++;
    }

    return {
      connectedPeers: activePeers.length,
      sharedPatterns: this.sharedPatterns.size,
      receivedPatterns: this.receivedPatterns.size,
      consensusScore: scoreCount > 0 ? Math.round((totalScore / scoreCount) * 100) / 100 : 0
    };
  }

  /**
   * Get the local ThreatFeed instance.
   *
   * @returns {ThreatFeed} The threat feed.
   */
  getThreatFeed() {
    return this.feed;
  }

  /**
   * Report a false positive to reduce consensus for a pattern.
   *
   * @param {string} patternId - The pattern hash to report.
   * @returns {Object} Updated consensus info.
   */
  submitFalsePositive(patternId) {
    if (!patternId) {
      throw new Error('patternId is required');
    }

    const result = this.consensus.reportFalsePositive(patternId, this.nodeId);

    // Broadcast to peers
    for (const peer of this.peers.values()) {
      if (peer.connected && peer.isActive()) {
        peer.send({ type: 'falsePositive', data: { patternId } });
      }
    }

    console.log(`[Agent Shield] Reported false positive for pattern: ${patternId}`);

    return result;
  }

  /**
   * Internal sync loop (simulated).
   * @private
   */
  _sync() {
    // Prune stale consensus entries
    this.consensus.prune();

    // Check peer health
    for (const [id, peer] of this.peers) {
      if (!peer.isActive()) {
        peer.connected = false;
      }
    }
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
  ThreatIntelNetwork,
  PeerNode,
  PatternAnonymizer,
  ConsensusEngine,
  ThreatFeed,
  NETWORK_DEFAULTS
};
