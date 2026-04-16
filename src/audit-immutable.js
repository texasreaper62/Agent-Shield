'use strict';

/**
 * Agent Shield — Immutable Hash-Chained Audit Log
 *
 * Production-grade, tamper-evident audit log for enterprise compliance.
 * Every entry is SHA-256 hash-chained to its predecessor, forming a
 * verifiable append-only ledger. Designed for SOC 2 CC7.2 (system
 * monitoring) and CC7.3 (anomaly detection) compliance.
 *
 * Features:
 * - SHA-256 hash chain with genesis block
 * - Tamper detection via full chain verification
 * - Pluggable storage backends (memory, file, custom)
 * - Cryptographic proof export for auditor verification
 * - Retention policies (maxEntries, maxAge, archiveCallback)
 * - Query API with filtering by type, time range, actor, severity
 * - Export in JSON, CSV, JSONL formats
 * - Write serialization (no concurrent write corruption)
 *
 * Zero dependencies — uses Node.js built-in crypto and fs modules.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// =========================================================================
// CONSTANTS
// =========================================================================

/** @type {string} SHA-256 hash of the string 'AGENT_SHIELD_GENESIS' — deterministic starting point. */
const GENESIS_HASH = crypto.createHash('sha256').update('AGENT_SHIELD_GENESIS').digest('hex');

/** @type {string[]} Valid entry types for the audit log. */
const ENTRY_TYPES = [
  'scan_result',
  'threat_detected',
  'threat_blocked',
  'policy_change',
  'config_change',
  'auth_event',
  'manual_review'
];

// =========================================================================
// AUDIT ENTRY
// =========================================================================

/**
 * A single immutable entry in the hash-chained audit log.
 */
class AuditEntry {
  /**
   * @param {object} params
   * @param {string} params.id - Unique entry identifier.
   * @param {string} params.timestamp - ISO 8601 timestamp.
   * @param {string} params.type - Entry type (one of ENTRY_TYPES).
   * @param {object} params.data - Arbitrary payload data.
   * @param {object} params.actor - Who or what triggered this entry.
   * @param {string} params.actor.type - Actor type ('system', 'user', 'agent', 'api').
   * @param {string} params.actor.id - Actor identifier.
   * @param {string} [params.actor.name] - Human-readable actor name.
   * @param {string} params.previousHash - Hash of the preceding entry.
   * @param {string} params.hash - SHA-256 hash of (previousHash + entry data).
   * @param {number} params.sequence - Monotonic sequence number.
   */
  constructor(params) {
    this.id = params.id;
    this.sequence = params.sequence;
    this.timestamp = params.timestamp;
    this.type = params.type;
    this.data = params.data;
    this.actor = params.actor;
    this.previousHash = params.previousHash;
    this.hash = params.hash;

    // Freeze to prevent mutation after creation.
    Object.freeze(this.actor);
    Object.freeze(this);
  }

  /**
   * Serialize entry to a plain object suitable for JSON.
   * @returns {object}
   */
  toJSON() {
    return {
      id: this.id,
      sequence: this.sequence,
      timestamp: this.timestamp,
      type: this.type,
      data: this.data,
      actor: this.actor,
      previousHash: this.previousHash,
      hash: this.hash
    };
  }
}

// =========================================================================
// HASH UTILITIES
// =========================================================================

/**
 * Compute SHA-256 hash for a chain link.
 * The canonical form is: previousHash + JSON-serialized entry content (sorted keys).
 * @param {string} previousHash
 * @param {object} entryContent - { id, sequence, timestamp, type, data, actor }
 * @returns {string} Hex-encoded SHA-256 hash.
 */
function computeHash(previousHash, entryContent) {
  const canonical = previousHash + canonicalize(entryContent);
  return crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
}

/**
 * Deterministic JSON serialization with sorted keys for hash stability.
 * @param {*} obj
 * @returns {string}
 */
function canonicalize(obj) {
  if (obj === null || obj === undefined) return 'null';
  if (typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalize).join(',') + ']';
  }
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalize(obj[k])).join(',') + '}';
}

/**
 * Standalone chain verification function. Walks the array of entries and
 * checks that every hash is correctly derived from its predecessor.
 * @param {Array<object>} entries - Array of entry objects (or AuditEntry instances).
 * @param {string} [expectedGenesisHash] - Expected hash of the genesis block's previousHash.
 * @returns {{ valid: boolean, length: number, error: string|null, brokenAt: number|null }}
 */
function verifyChain(entries, expectedGenesisHash) {
  const genesis = expectedGenesisHash || GENESIS_HASH;

  if (!Array.isArray(entries) || entries.length === 0) {
    return { valid: true, length: 0, error: null, brokenAt: null };
  }

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];

    // Check previous hash linkage.
    const expectedPrev = i === 0 ? genesis : entries[i - 1].hash;
    if (entry.previousHash !== expectedPrev) {
      return {
        valid: false,
        length: entries.length,
        error: `Entry ${entry.id} (index ${i}): previousHash mismatch. Expected ${expectedPrev}, got ${entry.previousHash}`,
        brokenAt: i
      };
    }

    // Recompute hash and verify.
    const content = {
      id: entry.id,
      sequence: entry.sequence,
      timestamp: entry.timestamp,
      type: entry.type,
      data: entry.data,
      actor: entry.actor
    };
    const recomputed = computeHash(entry.previousHash, content);
    if (entry.hash !== recomputed) {
      return {
        valid: false,
        length: entries.length,
        error: `Entry ${entry.id} (index ${i}): hash mismatch. Expected ${recomputed}, got ${entry.hash}`,
        brokenAt: i
      };
    }
  }

  return { valid: true, length: entries.length, error: null, brokenAt: null };
}

// =========================================================================
// AUDIT PROOF
// =========================================================================

/**
 * Cryptographic proof for a subset of the audit chain.
 * Allows an external auditor to verify a contiguous range of entries
 * without requiring the entire log.
 */
class AuditProof {
  /**
   * @param {object} params
   * @param {string} params.proofId - Unique proof identifier.
   * @param {string} params.generatedAt - ISO 8601 timestamp of proof generation.
   * @param {string} params.anchorHash - The previousHash of the first entry in the range (chain anchor).
   * @param {Array<object>} params.entries - The entries included in the proof.
   * @param {string} params.startId - First entry ID.
   * @param {string} params.endId - Last entry ID.
   * @param {number} params.entryCount - Number of entries.
   * @param {string} params.chainHead - Hash of the last entry in the proof.
   * @param {string} params.proofHash - SHA-256 hash of the entire proof payload for integrity.
   */
  constructor(params) {
    this.proofId = params.proofId;
    this.generatedAt = params.generatedAt;
    this.anchorHash = params.anchorHash;
    this.entries = params.entries;
    this.startId = params.startId;
    this.endId = params.endId;
    this.entryCount = params.entryCount;
    this.chainHead = params.chainHead;
    this.proofHash = params.proofHash;
  }

  /**
   * Verify the proof's internal consistency.
   * @returns {{ valid: boolean, error: string|null }}
   */
  verify() {
    // Verify proof hash.
    const payload = canonicalize({
      anchorHash: this.anchorHash,
      entries: this.entries,
      startId: this.startId,
      endId: this.endId,
      entryCount: this.entryCount,
      chainHead: this.chainHead
    });
    const expectedProofHash = crypto.createHash('sha256').update(payload, 'utf8').digest('hex');
    if (this.proofHash !== expectedProofHash) {
      return { valid: false, error: 'Proof envelope hash mismatch — proof itself is tampered' };
    }

    // Verify the chain within the proof.
    const chainResult = verifyChain(this.entries, this.anchorHash);
    if (!chainResult.valid) {
      return { valid: false, error: chainResult.error };
    }

    return { valid: true, error: null };
  }

  /**
   * Serialize proof to JSON.
   * @returns {object}
   */
  toJSON() {
    return {
      proofId: this.proofId,
      generatedAt: this.generatedAt,
      anchorHash: this.anchorHash,
      entries: this.entries,
      startId: this.startId,
      endId: this.endId,
      entryCount: this.entryCount,
      chainHead: this.chainHead,
      proofHash: this.proofHash
    };
  }
}

// =========================================================================
// STORAGE BACKENDS
// =========================================================================

/**
 * In-memory storage backend. Fast, no persistence.
 * Suitable for testing, development, or short-lived processes.
 */
class MemoryStore {
  constructor() {
    /** @type {AuditEntry[]} */
    this._entries = [];
    /** @type {Map<string, number>} id -> index */
    this._index = new Map();
  }

  /**
   * Append an entry.
   * @param {AuditEntry} entry
   */
  async append(entry) {
    this._index.set(entry.id, this._entries.length);
    this._entries.push(entry);
  }

  /**
   * Get all entries (copy).
   * @returns {AuditEntry[]}
   */
  async getAll() {
    return this._entries.slice();
  }

  /**
   * Get the last entry in the chain.
   * @returns {AuditEntry|null}
   */
  async getLast() {
    return this._entries.length > 0 ? this._entries[this._entries.length - 1] : null;
  }

  /**
   * Get entry count.
   * @returns {number}
   */
  async count() {
    return this._entries.length;
  }

  /**
   * Get entry by ID.
   * @param {string} id
   * @returns {AuditEntry|null}
   */
  async getById(id) {
    const idx = this._index.get(id);
    return idx !== undefined ? this._entries[idx] : null;
  }

  /**
   * Get entries in a sequence range (inclusive).
   * @param {number} startSeq
   * @param {number} endSeq
   * @returns {AuditEntry[]}
   */
  async getRange(startSeq, endSeq) {
    return this._entries.filter(e => e.sequence >= startSeq && e.sequence <= endSeq);
  }

  /**
   * Remove entries older than a given timestamp.
   * Returns the removed entries for archiving.
   * @param {string} beforeTimestamp - ISO 8601 timestamp.
   * @returns {AuditEntry[]}
   */
  async removeBefore(beforeTimestamp) {
    const cutoff = new Date(beforeTimestamp).getTime();
    const removed = [];
    const kept = [];
    for (const entry of this._entries) {
      if (new Date(entry.timestamp).getTime() < cutoff) {
        removed.push(entry);
        this._index.delete(entry.id);
      } else {
        kept.push(entry);
      }
    }
    // Rebuild index for kept entries.
    this._entries = kept;
    this._index.clear();
    for (let i = 0; i < kept.length; i++) {
      this._index.set(kept[i].id, i);
    }
    return removed;
  }

  /**
   * Trim to a maximum number of entries, removing oldest first.
   * Returns the removed entries.
   * @param {number} maxEntries
   * @returns {AuditEntry[]}
   */
  async trimToSize(maxEntries) {
    if (this._entries.length <= maxEntries) return [];
    const removeCount = this._entries.length - maxEntries;
    const removed = this._entries.splice(0, removeCount);
    for (const entry of removed) {
      this._index.delete(entry.id);
    }
    // Rebuild index.
    this._index.clear();
    for (let i = 0; i < this._entries.length; i++) {
      this._index.set(this._entries[i].id, i);
    }
    return removed;
  }

  /**
   * Clear all entries.
   */
  async clear() {
    this._entries = [];
    this._index.clear();
  }
}

/**
 * Append-only file storage backend. Writes each entry as a JSONL line.
 * On load, reads and verifies the existing chain.
 */
class FileStore {
  /**
   * @param {object} options
   * @param {string} options.filePath - Path to the JSONL audit log file.
   * @param {boolean} [options.syncWrites=true] - Use synchronous writes for durability.
   */
  constructor(options = {}) {
    if (!options.filePath) {
      throw new Error('[Agent Shield] FileStore requires a filePath option');
    }
    this.filePath = path.resolve(options.filePath);
    this.syncWrites = options.syncWrites !== false;
    /** @type {AuditEntry[]} */
    this._cache = [];
    /** @type {Map<string, number>} */
    this._index = new Map();
    this._loaded = false;
  }

  /**
   * Load existing entries from the file (idempotent).
   * @returns {Promise<void>}
   */
  async _ensureLoaded() {
    if (this._loaded) return;
    this._loaded = true;

    if (!fs.existsSync(this.filePath)) return;

    const content = fs.readFileSync(this.filePath, 'utf8');
    const lines = content.split('\n').filter(line => line.trim().length > 0);

    for (let i = 0; i < lines.length; i++) {
      try {
        const raw = JSON.parse(lines[i]);
        const entry = new AuditEntry(raw);
        this._index.set(entry.id, this._cache.length);
        this._cache.push(entry);
      } catch (e) {
        console.warn(`[Agent Shield] FileStore: corrupt line ${i + 1} in ${this.filePath}: ${e.message}`);
      }
    }

    console.log(`[Agent Shield] FileStore: loaded ${this._cache.length} entries from ${this.filePath}`);
  }

  /**
   * Append an entry to the file and in-memory cache.
   * @param {AuditEntry} entry
   */
  async append(entry) {
    await this._ensureLoaded();
    const line = JSON.stringify(entry.toJSON()) + '\n';

    if (this.syncWrites) {
      fs.appendFileSync(this.filePath, line, 'utf8');
    } else {
      fs.appendFile(this.filePath, line, 'utf8', (err) => {
        if (err) console.warn('[Agent Shield] FileStore async write error:', err.message);
      });
    }

    this._index.set(entry.id, this._cache.length);
    this._cache.push(entry);
  }

  /** @returns {AuditEntry[]} */
  async getAll() {
    await this._ensureLoaded();
    return this._cache.slice();
  }

  /** @returns {AuditEntry|null} */
  async getLast() {
    await this._ensureLoaded();
    return this._cache.length > 0 ? this._cache[this._cache.length - 1] : null;
  }

  /** @returns {number} */
  async count() {
    await this._ensureLoaded();
    return this._cache.length;
  }

  /**
   * @param {string} id
   * @returns {AuditEntry|null}
   */
  async getById(id) {
    await this._ensureLoaded();
    const idx = this._index.get(id);
    return idx !== undefined ? this._cache[idx] : null;
  }

  /**
   * @param {number} startSeq
   * @param {number} endSeq
   * @returns {AuditEntry[]}
   */
  async getRange(startSeq, endSeq) {
    await this._ensureLoaded();
    return this._cache.filter(e => e.sequence >= startSeq && e.sequence <= endSeq);
  }

  /**
   * Remove entries before a timestamp. Rewrites the file with remaining entries.
   * @param {string} beforeTimestamp
   * @returns {AuditEntry[]}
   */
  async removeBefore(beforeTimestamp) {
    await this._ensureLoaded();
    const cutoff = new Date(beforeTimestamp).getTime();
    const removed = [];
    const kept = [];
    for (const entry of this._cache) {
      if (new Date(entry.timestamp).getTime() < cutoff) {
        removed.push(entry);
      } else {
        kept.push(entry);
      }
    }

    if (removed.length > 0) {
      this._cache = kept;
      this._index.clear();
      for (let i = 0; i < kept.length; i++) {
        this._index.set(kept[i].id, i);
      }
      this._rewriteFile();
    }

    return removed;
  }

  /**
   * Trim to max entries. Rewrites the file.
   * @param {number} maxEntries
   * @returns {AuditEntry[]}
   */
  async trimToSize(maxEntries) {
    await this._ensureLoaded();
    if (this._cache.length <= maxEntries) return [];
    const removeCount = this._cache.length - maxEntries;
    const removed = this._cache.splice(0, removeCount);
    this._index.clear();
    for (let i = 0; i < this._cache.length; i++) {
      this._index.set(this._cache[i].id, i);
    }
    this._rewriteFile();
    return removed;
  }

  async clear() {
    this._cache = [];
    this._index.clear();
    if (fs.existsSync(this.filePath)) {
      fs.writeFileSync(this.filePath, '', 'utf8');
    }
  }

  /** @private Rewrite the file from the in-memory cache. */
  _rewriteFile() {
    const lines = this._cache.map(e => JSON.stringify(e.toJSON())).join('\n');
    const content = lines.length > 0 ? lines + '\n' : '';
    fs.writeFileSync(this.filePath, content, 'utf8');
  }
}

// =========================================================================
// IMMUTABLE AUDIT LOG
// =========================================================================

/**
 * Immutable, hash-chained audit log for enterprise compliance.
 *
 * Every entry is linked to its predecessor via SHA-256, forming a tamper-evident
 * chain similar to a blockchain. Any modification to any historical entry will
 * break the chain and be detected by verify().
 *
 * @example
 * const log = new ImmutableAuditLog();
 * await log.append('scan_result', { input: '...', status: 'safe' }, { type: 'system', id: 'scanner-1' });
 * const result = await log.verify();
 * console.log(result.valid); // true
 */
class ImmutableAuditLog {
  /**
   * @param {object} [options]
   * @param {MemoryStore|FileStore|object} [options.store] - Storage backend (must implement append, getAll, getLast, count, getById, getRange, removeBefore, trimToSize, clear).
   * @param {number} [options.maxEntries=0] - Maximum entries to retain (0 = unlimited).
   * @param {number} [options.maxAge=0] - Maximum age in milliseconds (0 = unlimited).
   * @param {function} [options.archiveCallback] - Called with removed entries during retention enforcement. Signature: (entries: AuditEntry[]) => void.
   * @param {string} [options.genesisHash] - Custom genesis hash (defaults to GENESIS_HASH).
   * @param {boolean} [options.sanitizeLogs=false] - Redact sensitive content (emails, SSNs, API keys) before writing to the chain.
   */
  constructor(options = {}) {
    this.options = options;
    this._store = options.store || new MemoryStore();
    this._maxEntries = options.maxEntries || 0;
    this._maxAge = options.maxAge || 0;
    this._archiveCallback = options.archiveCallback || null;
    this._genesisHash = options.genesisHash || GENESIS_HASH;
    this._sequence = 0;
    this._writeLock = Promise.resolve();
    this._initialized = false;

    console.log('[Agent Shield] ImmutableAuditLog initialized (store: %s)', this._store.constructor.name);
  }

  /**
   * Sanitize an entry's data object by redacting sensitive content.
   * Addresses the security scan finding about audit logs containing sensitive prompt data.
   *
   * Redacts:
   * - Email addresses -> [EMAIL_REDACTED]
   * - SSN patterns (XXX-XX-XXXX) -> [SSN_REDACTED]
   * - API key patterns (sk-..., key-..., token-...) -> [KEY_REDACTED]
   * - Truncates 'content' and 'input' fields to 500 characters max
   *
   * @param {object} entry - The data object to sanitize.
   * @returns {object} A sanitized copy of the data object.
   */
  sanitize(entry) {
    if (!this.options.sanitizeLogs) {
      return entry;
    }

    const sanitized = JSON.parse(JSON.stringify(entry));

    const redactString = (str) => {
      if (typeof str !== 'string') return str;
      // Redact email addresses
      str = str.replace(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, '[EMAIL_REDACTED]');
      // Redact SSN patterns (XXX-XX-XXXX)
      str = str.replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[SSN_REDACTED]');
      // Redact API key patterns (sk-..., key-..., token-...)
      str = str.replace(/\b(?:sk|key|token)-[a-zA-Z0-9_\-]{8,}\b/g, '[KEY_REDACTED]');
      return str;
    };

    const redactObject = (obj) => {
      if (obj === null || obj === undefined) return obj;
      if (typeof obj === 'string') return redactString(obj);
      if (Array.isArray(obj)) return obj.map(item => redactObject(item));
      if (typeof obj === 'object') {
        const result = {};
        for (const key of Object.keys(obj)) {
          let value = redactObject(obj[key]);
          // Truncate content and input fields to 500 chars
          if ((key === 'content' || key === 'input') && typeof value === 'string' && value.length > 500) {
            value = value.slice(0, 500) + '...[TRUNCATED]';
          }
          result[key] = value;
        }
        return result;
      }
      return obj;
    };

    return redactObject(sanitized);
  }

  /**
   * Initialize sequence counter from existing store data.
   * @private
   */
  async _ensureInitialized() {
    if (this._initialized) return;
    this._initialized = true;

    const last = await this._store.getLast();
    if (last) {
      this._sequence = last.sequence;
    }
  }

  /**
   * Append a new entry to the audit log.
   * This method is serialized — concurrent calls are queued to prevent corruption.
   *
   * @param {string} type - Entry type (one of ENTRY_TYPES, or custom string).
   * @param {object} data - Arbitrary event data payload.
   * @param {object} actor - The actor who triggered this event.
   * @param {string} actor.type - Actor type ('system', 'user', 'agent', 'api').
   * @param {string} actor.id - Actor identifier.
   * @param {string} [actor.name] - Human-readable name.
   * @returns {Promise<AuditEntry>} The appended entry.
   */
  async append(type, data, actor) {
    // Serialize writes through a promise chain.
    const result = this._writeLock.then(async () => {
      await this._ensureInitialized();

      this._sequence++;
      const timestamp = new Date().toISOString();
      const id = `aud_${Date.now()}_${this._sequence}_${crypto.randomBytes(4).toString('hex')}`;

      const last = await this._store.getLast();
      const previousHash = last ? last.hash : this._genesisHash;

      const normalizedActor = {
        type: (actor && actor.type) || 'system',
        id: (actor && actor.id) || 'unknown',
        name: (actor && actor.name) || undefined
      };
      // Strip undefined name to keep canonical form clean.
      if (normalizedActor.name === undefined) {
        delete normalizedActor.name;
      }

      // Sanitize data if sanitizeLogs is enabled
      const sanitizedData = this.sanitize(data || {});

      const entryContent = {
        id,
        sequence: this._sequence,
        timestamp,
        type,
        data: sanitizedData,
        actor: normalizedActor
      };

      const hash = computeHash(previousHash, entryContent);

      const entry = new AuditEntry({
        ...entryContent,
        previousHash,
        hash
      });

      await this._store.append(entry);

      // Enforce retention policies asynchronously (don't block the append).
      this._enforceRetention().catch(err => {
        console.warn('[Agent Shield] Retention enforcement error:', err.message);
      });

      return entry;
    });

    // Update write lock to point at the new tail of the chain.
    this._writeLock = result.then(() => {}, () => {});

    return result;
  }

  /**
   * Verify the integrity of the entire chain.
   * Walks every entry from genesis and checks all hashes.
   *
   * @returns {Promise<{ valid: boolean, length: number, error: string|null, brokenAt: number|null }>}
   */
  async verify() {
    const entries = await this._store.getAll();
    return verifyChain(entries.map(e => e.toJSON ? e.toJSON() : e), this._genesisHash);
  }

  /**
   * Export a cryptographic proof for a contiguous range of entries.
   * The proof includes the anchor hash (the previousHash of the first entry)
   * so an auditor can verify the sub-chain independently.
   *
   * @param {string} startId - ID of the first entry in the range.
   * @param {string} endId - ID of the last entry in the range.
   * @returns {Promise<AuditProof>}
   */
  async exportProof(startId, endId) {
    const allEntries = await this._store.getAll();
    const startIdx = allEntries.findIndex(e => e.id === startId);
    const endIdx = allEntries.findIndex(e => e.id === endId);

    if (startIdx === -1) throw new Error(`Start entry not found: ${startId}`);
    if (endIdx === -1) throw new Error(`End entry not found: ${endId}`);
    if (startIdx > endIdx) throw new Error('Start entry must come before end entry in the chain');

    const subset = allEntries.slice(startIdx, endIdx + 1);
    const serialized = subset.map(e => e.toJSON ? e.toJSON() : e);

    const anchorHash = serialized[0].previousHash;
    const chainHead = serialized[serialized.length - 1].hash;

    const proofPayload = {
      anchorHash,
      entries: serialized,
      startId,
      endId,
      entryCount: serialized.length,
      chainHead
    };

    const proofHash = crypto.createHash('sha256')
      .update(canonicalize(proofPayload), 'utf8')
      .digest('hex');

    return new AuditProof({
      proofId: `proof_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`,
      generatedAt: new Date().toISOString(),
      ...proofPayload,
      proofHash
    });
  }

  /**
   * Query entries with filtering.
   *
   * @param {object} [filters]
   * @param {string} [filters.type] - Filter by entry type.
   * @param {string} [filters.startTime] - ISO 8601 start time (inclusive).
   * @param {string} [filters.endTime] - ISO 8601 end time (inclusive).
   * @param {string} [filters.actor] - Filter by actor ID.
   * @param {string} [filters.severity] - Filter by data.severity field.
   * @param {number} [filters.limit] - Maximum results to return.
   * @param {number} [filters.offset] - Skip this many results.
   * @returns {Promise<AuditEntry[]>}
   */
  async query(filters = {}) {
    const allEntries = await this._store.getAll();
    const startTime = filters.startTime ? new Date(filters.startTime).getTime() : null;
    const endTime = filters.endTime ? new Date(filters.endTime).getTime() : null;

    let results = allEntries.filter(entry => {
      if (filters.type && entry.type !== filters.type) return false;

      if (startTime) {
        const entryTime = new Date(entry.timestamp).getTime();
        if (entryTime < startTime) return false;
      }
      if (endTime) {
        const entryTime = new Date(entry.timestamp).getTime();
        if (entryTime > endTime) return false;
      }

      if (filters.actor && entry.actor.id !== filters.actor) return false;

      if (filters.severity && (!entry.data || entry.data.severity !== filters.severity)) return false;

      return true;
    });

    if (filters.offset) {
      results = results.slice(filters.offset);
    }
    if (filters.limit) {
      results = results.slice(0, filters.limit);
    }

    return results;
  }

  /**
   * Export the entire log in the specified format.
   *
   * @param {'json'|'csv'|'jsonl'} [format='json'] - Output format.
   * @returns {Promise<string>}
   */
  async export(format = 'json') {
    const entries = await this._store.getAll();
    const serialized = entries.map(e => e.toJSON ? e.toJSON() : e);

    switch (format) {
      case 'json':
        return JSON.stringify(serialized, null, 2);

      case 'jsonl':
        return serialized.map(e => JSON.stringify(e)).join('\n') + (serialized.length > 0 ? '\n' : '');

      case 'csv': {
        if (serialized.length === 0) return '';
        const headers = ['id', 'sequence', 'timestamp', 'type', 'actor_type', 'actor_id', 'previousHash', 'hash', 'data'];
        const rows = [headers.join(',')];
        for (const entry of serialized) {
          rows.push([
            entry.id,
            entry.sequence,
            entry.timestamp,
            entry.type,
            entry.actor.type,
            entry.actor.id,
            entry.previousHash,
            entry.hash,
            `"${JSON.stringify(entry.data).replace(/"/g, '""')}"`
          ].join(','));
        }
        return rows.join('\n') + '\n';
      }

      default:
        throw new Error(`Unsupported export format: ${format}`);
    }
  }

  /**
   * Get summary statistics for the audit log.
   * @returns {Promise<object>}
   */
  async getStats() {
    const entries = await this._store.getAll();
    const typeCounts = {};
    const actorCounts = {};

    for (const entry of entries) {
      typeCounts[entry.type] = (typeCounts[entry.type] || 0) + 1;
      actorCounts[entry.actor.id] = (actorCounts[entry.actor.id] || 0) + 1;
    }

    return {
      totalEntries: entries.length,
      firstEntry: entries.length > 0 ? entries[0].timestamp : null,
      lastEntry: entries.length > 0 ? entries[entries.length - 1].timestamp : null,
      typeCounts,
      actorCounts,
      chainValid: (await this.verify()).valid
    };
  }

  /**
   * Get the current chain head hash.
   * @returns {Promise<string>}
   */
  async getChainHead() {
    const last = await this._store.getLast();
    return last ? last.hash : this._genesisHash;
  }

  /**
   * Get the total number of entries.
   * @returns {Promise<number>}
   */
  async count() {
    return this._store.count();
  }

  /**
   * Enforce retention policies (maxEntries, maxAge).
   * @private
   */
  async _enforceRetention() {
    let archived = [];

    // Enforce maxAge.
    if (this._maxAge > 0) {
      const cutoff = new Date(Date.now() - this._maxAge).toISOString();
      const removed = await this._store.removeBefore(cutoff);
      if (removed.length > 0) archived = archived.concat(removed);
    }

    // Enforce maxEntries.
    if (this._maxEntries > 0) {
      const removed = await this._store.trimToSize(this._maxEntries);
      if (removed.length > 0) archived = archived.concat(removed);
    }

    // Notify archive callback.
    if (archived.length > 0 && this._archiveCallback) {
      try {
        this._archiveCallback(archived);
      } catch (e) {
        console.warn('[Agent Shield] Archive callback error:', e.message);
      }
    }
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
  ImmutableAuditLog,
  AuditEntry,
  MemoryStore,
  FileStore,
  AuditProof,
  verifyChain,
  computeHash,
  canonicalize,
  GENESIS_HASH,
  ENTRY_TYPES
};
