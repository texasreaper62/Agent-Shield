'use strict';

/**
 * Agent Shield -- Cross-Agent Herd Immunity and Agent Immune Memory (v7.4)
 *
 * When one agent in the network encounters a new attack, the system extracts
 * the pattern, generates variants, and pushes updated immunity to all other
 * agents. New agents inherit the collective memory from day one.
 *
 * Uses MemoryAdapter from distributed.js for the broadcast mechanism.
 * All processing runs locally -- no data ever leaves your environment.
 */

const crypto = require('crypto');
const { PatternGenerator } = require('./self-healing');
const { MemoryAdapter } = require('./distributed');

const LOG_PREFIX = '[Agent Shield]';
const CHANNEL_IMMUNITY = 'herd:immunity';
const CHANNEL_CONNECT = 'herd:connect';

// =========================================================================
// HERD IMMUNITY
// =========================================================================

/**
 * Cross-agent herd immunity. When one agent blocks an attack, the extracted
 * pattern is broadcast to every connected agent so they are all protected.
 */
class HerdImmunity {
  /**
   * @param {object} [options]
   * @param {object} [options.broadcastAdapter] - Adapter for pub/sub (defaults to MemoryAdapter).
   * @param {boolean} [options.anonymize=true] - Strip raw text before broadcast.
   * @param {number} [options.maxPatterns=500] - Maximum patterns to store.
   */
  constructor(options = {}) {
    this._adapter = options.broadcastAdapter || new MemoryAdapter();
    this._anonymize = options.anonymize !== false;
    this._maxPatterns = options.maxPatterns || 500;

    this._generator = new PatternGenerator();
    this._patterns = [];       // locally held herd patterns
    this._connectedAgents = new Set();
    this._subscribed = false;

    this.stats = {
      patternsShared: 0,
      attacksBlocked: 0
    };

    console.log('%s HerdImmunity initialized (anonymize: %s, maxPatterns: %d)', LOG_PREFIX,
      this._anonymize, this._maxPatterns);
  }

  // -----------------------------------------------------------------------
  // Agent management
  // -----------------------------------------------------------------------

  /**
   * Register an agent in the herd network.
   * @param {string} agentId
   */
  connect(agentId) {
    if (!agentId) return;
    this._connectedAgents.add(agentId);
    this._ensureSubscription();
    this._adapter.publish(CHANNEL_CONNECT, { type: 'join', agentId, timestamp: Date.now() });
    console.log('%s Agent "%s" connected to herd (%d total)', LOG_PREFIX,
      agentId, this._connectedAgents.size);
  }

  /**
   * Remove an agent from the herd network.
   * @param {string} agentId
   */
  disconnect(agentId) {
    if (!agentId) return;
    this._connectedAgents.delete(agentId);
    this._adapter.publish(CHANNEL_CONNECT, { type: 'leave', agentId, timestamp: Date.now() });
    console.log('%s Agent "%s" disconnected from herd (%d remaining)', LOG_PREFIX,
      agentId, this._connectedAgents.size);
  }

  // -----------------------------------------------------------------------
  // Core API
  // -----------------------------------------------------------------------

  /**
   * Agent reports a blocked attack. The system extracts its signature,
   * generates a detection pattern, and broadcasts to all connected agents.
   *
   * @param {object} attack
   * @param {string} attack.text - The blocked attack text.
   * @param {string} [attack.category] - Threat category.
   * @param {string} [attack.agentId] - Reporting agent.
   * @returns {{ signature: string, pattern: object|null, broadcastedTo: number }}
   */
  reportAttack(attack) {
    if (!attack || !attack.text) {
      return { signature: '', pattern: null, broadcastedTo: 0 };
    }

    // 1. Extract signature (hash of normalized text)
    const normalized = attack.text.toLowerCase().replace(/\s+/g, ' ').trim();
    const signature = crypto.createHash('sha256').update(normalized).digest('hex').substring(0, 16);

    // Skip duplicates
    if (this._patterns.some(p => p.signature === signature)) {
      return { signature, pattern: null, broadcastedTo: 0 };
    }

    // 2. Generate a detection pattern
    const generated = this._generator.generate(attack.text, {
      category: attack.category
    });

    if (!generated) {
      return { signature, pattern: null, broadcastedTo: 0 };
    }

    // Build the portable pattern payload
    const pattern = {
      signature,
      regex: generated.regex.source,
      flags: generated.regex.flags,
      severity: generated.severity,
      category: generated.category,
      description: generated.description,
      source: 'herd_immunity',
      reportedBy: this._anonymize ? undefined : (attack.agentId || 'unknown'),
      timestamp: Date.now()
    };

    // 3. Store locally
    this._addPattern(pattern);

    // 4. Broadcast to all connected agents
    const broadcastedTo = this._connectedAgents.size;
    this._adapter.publish(CHANNEL_IMMUNITY, pattern);
    this.stats.patternsShared++;

    console.log('%s Attack reported -- signature %s, broadcast to %d agent(s)', LOG_PREFIX,
      signature, broadcastedTo);

    return { signature, pattern, broadcastedTo };
  }

  /**
   * Receive a pattern from the herd network and add it to local detection.
   * @param {object} pattern - Pattern object from the network.
   */
  receiveImmunity(pattern) {
    if (!pattern || !pattern.signature || !pattern.regex) return;

    // Avoid duplicates
    if (this._patterns.some(p => p.signature === pattern.signature)) return;

    this._addPattern(pattern);
    console.log('%s Immunity received -- signature %s, category %s', LOG_PREFIX,
      pattern.signature, pattern.category || 'unknown');
  }

  /**
   * Check text against all learned herd patterns.
   * @param {string} text
   * @returns {{ immune: boolean, matches: Array<{ signature: string, category: string, severity: string }> }}
   */
  checkImmunity(text) {
    if (!text) return { immune: false, matches: [] };

    const matches = [];
    for (const pattern of this._patterns) {
      try {
        const re = new RegExp(pattern.regex, pattern.flags || 'i');
        if (re.test(text)) {
          matches.push({
            signature: pattern.signature,
            category: pattern.category,
            severity: pattern.severity
          });
          this.stats.attacksBlocked++;
        }
      } catch (_e) {
        // Skip broken regex patterns
      }
    }

    return { immune: matches.length > 0, matches };
  }

  /**
   * Return network statistics.
   * @returns {{ patternsShared: number, agentsProtected: number, attacksBlocked: number }}
   */
  getNetworkStats() {
    return {
      patternsShared: this.stats.patternsShared,
      agentsProtected: this._connectedAgents.size,
      attacksBlocked: this.stats.attacksBlocked
    };
  }

  // -----------------------------------------------------------------------
  // Internal helpers
  // -----------------------------------------------------------------------

  /** @private */
  _addPattern(pattern) {
    if (this._patterns.length >= this._maxPatterns) {
      this._patterns.shift();
    }
    this._patterns.push(pattern);
  }

  /** @private */
  _ensureSubscription() {
    if (this._subscribed) return;
    this._subscribed = true;

    this._adapter.subscribe(CHANNEL_IMMUNITY, (pattern) => {
      this.receiveImmunity(pattern);
    });
  }
}

// =========================================================================
// IMMUNE MEMORY
// =========================================================================

/**
 * Persistent immune memory for agents. Stores attack/pattern pairs with
 * time-based decay so stale patterns fade while active threats stay sharp.
 * New agents can import the full collective memory to be protected from day one.
 */
class ImmuneMemory {
  /**
   * @param {object} [options]
   * @param {number} [options.maxMemory=1000] - Maximum memory entries.
   * @param {number} [options.decayRate=0.05] - Fraction of strength lost per decay cycle.
   */
  constructor(options = {}) {
    this._maxMemory = options.maxMemory || 1000;
    this._decayRate = options.decayRate || 0.05;
    this._entries = [];   // { attack, pattern, strength, learnedAt, lastMatchedAt }
    this._createdAt = Date.now();
  }

  /**
   * Add an attack/pattern pair to memory.
   * @param {string} attack - The attack text (or its hash).
   * @param {object} pattern - The detection pattern.
   * @returns {{ stored: boolean, totalPatterns: number }}
   */
  learn(attack, pattern) {
    if (!attack || !pattern) return { stored: false, totalPatterns: this._entries.length };

    const hash = crypto.createHash('sha256')
      .update(typeof attack === 'string' ? attack : JSON.stringify(attack))
      .digest('hex').substring(0, 16);

    // Reinforce if already known
    const existing = this._entries.find(e => e.hash === hash);
    if (existing) {
      existing.strength = Math.min(1.0, existing.strength + 0.1);
      existing.lastMatchedAt = Date.now();
      return { stored: true, totalPatterns: this._entries.length };
    }

    // Evict weakest if at capacity
    if (this._entries.length >= this._maxMemory) {
      let weakestIdx = 0;
      let weakestStrength = Infinity;
      for (let i = 0; i < this._entries.length; i++) {
        if (this._entries[i].strength < weakestStrength) {
          weakestStrength = this._entries[i].strength;
          weakestIdx = i;
        }
      }
      this._entries.splice(weakestIdx, 1);
    }

    this._entries.push({
      hash,
      attack: typeof attack === 'string' ? attack.substring(0, 200) : String(attack).substring(0, 200),
      pattern: {
        regex: pattern.regex instanceof RegExp ? pattern.regex.source : (pattern.regex || ''),
        flags: pattern.regex instanceof RegExp ? pattern.regex.flags : (pattern.flags || 'i'),
        severity: pattern.severity || 'medium',
        category: pattern.category || 'unknown',
        description: pattern.description || ''
      },
      strength: 1.0,
      learnedAt: Date.now(),
      lastMatchedAt: Date.now()
    });

    return { stored: true, totalPatterns: this._entries.length };
  }

  /**
   * Check if text matches any remembered pattern.
   * @param {string} text
   * @returns {{ matched: boolean, matches: Array<{ hash: string, category: string, severity: string, strength: number }> }}
   */
  recall(text) {
    if (!text) return { matched: false, matches: [] };

    const matches = [];
    for (const entry of this._entries) {
      if (entry.strength <= 0) continue;
      try {
        const re = new RegExp(entry.pattern.regex, entry.pattern.flags || 'i');
        if (re.test(text)) {
          entry.lastMatchedAt = Date.now();
          entry.strength = Math.min(1.0, entry.strength + 0.02);
          matches.push({
            hash: entry.hash,
            category: entry.pattern.category,
            severity: entry.pattern.severity,
            strength: entry.strength
          });
        }
      } catch (_e) {
        // Skip broken patterns
      }
    }

    return { matched: matches.length > 0, matches };
  }

  /**
   * Export memory as portable JSON for sharing with new agents.
   * @returns {object}
   */
  export() {
    return {
      version: '1.0',
      exportedAt: Date.now(),
      createdAt: this._createdAt,
      decayRate: this._decayRate,
      entries: this._entries.filter(e => e.strength > 0).map(e => ({
        hash: e.hash,
        pattern: { ...e.pattern },
        strength: e.strength,
        learnedAt: e.learnedAt,
        lastMatchedAt: e.lastMatchedAt
      }))
    };
  }

  /**
   * Import memory from another agent or a collective export.
   * New agents call this to inherit the herd's collective memory.
   * @param {object} data - Output of export().
   * @returns {{ imported: number, skipped: number }}
   */
  import(data) {
    if (!data || !Array.isArray(data.entries)) {
      return { imported: 0, skipped: 0 };
    }

    let imported = 0;
    let skipped = 0;

    for (const entry of data.entries) {
      if (!entry.hash || !entry.pattern || !entry.pattern.regex) {
        skipped++;
        continue;
      }

      // Skip if already known
      if (this._entries.some(e => e.hash === entry.hash)) {
        skipped++;
        continue;
      }

      if (this._entries.length >= this._maxMemory) {
        skipped++;
        continue;
      }

      this._entries.push({
        hash: entry.hash,
        attack: '',
        pattern: {
          regex: entry.pattern.regex,
          flags: entry.pattern.flags || 'i',
          severity: entry.pattern.severity || 'medium',
          category: entry.pattern.category || 'unknown',
          description: entry.pattern.description || ''
        },
        strength: Math.min(1.0, entry.strength || 0.5),
        learnedAt: entry.learnedAt || Date.now(),
        lastMatchedAt: entry.lastMatchedAt || Date.now()
      });
      imported++;
    }

    console.log('%s ImmuneMemory imported %d pattern(s), skipped %d', LOG_PREFIX,
      imported, skipped);

    return { imported, skipped };
  }

  /**
   * Apply time-based decay to reduce stale patterns. Patterns that have not
   * been matched recently lose strength. When strength reaches zero the
   * pattern is effectively dormant but still retained for reference.
   * @returns {{ decayed: number, removed: number }}
   */
  decay() {
    let decayed = 0;
    let removed = 0;

    for (const entry of this._entries) {
      if (entry.strength <= 0) continue;

      const age = Date.now() - entry.lastMatchedAt;
      // Decay faster for patterns that have not matched in a long time
      const ageFactor = Math.min(3.0, 1.0 + (age / 3600000)); // up to 3x after 2+ hours
      const loss = this._decayRate * ageFactor;

      entry.strength = Math.max(0, entry.strength - loss);
      if (entry.strength <= 0) {
        removed++;
      }
      decayed++;
    }

    return { decayed, removed };
  }

  /**
   * Return memory statistics.
   * @returns {{ totalPatterns: number, activePatterns: number, decayedPatterns: number, memoryAge: number }}
   */
  getMemoryStats() {
    const active = this._entries.filter(e => e.strength > 0).length;
    return {
      totalPatterns: this._entries.length,
      activePatterns: active,
      decayedPatterns: this._entries.length - active,
      memoryAge: Date.now() - this._createdAt
    };
  }
}

// =========================================================================
// HERD NETWORK HELPER
// =========================================================================

/**
 * Connect multiple AgentShield instances into a herd immunity network.
 * When any agent detects an attack, all others receive the pattern within
 * the same tick (synchronous via shared MemoryAdapter).
 *
 * @param {Array<{ id: string, shield?: object }>} agents - Array of agent descriptors.
 *   Each must have an `id` property. Optionally include a `shield` (AgentShield instance).
 * @param {object} [options] - Options forwarded to HerdImmunity constructor.
 * @returns {{ herd: HerdImmunity, memory: ImmuneMemory, reportAttack: Function, checkAll: Function }}
 */
function createHerdNetwork(agents, options = {}) {
  if (!Array.isArray(agents) || agents.length === 0) {
    throw new Error(LOG_PREFIX + ' createHerdNetwork requires a non-empty array of agents');
  }

  const adapter = options.broadcastAdapter || new MemoryAdapter();
  const herd = new HerdImmunity({ ...options, broadcastAdapter: adapter });
  const memory = new ImmuneMemory({
    maxMemory: options.maxMemory,
    decayRate: options.decayRate
  });

  // Connect all agents
  for (const agent of agents) {
    const agentId = agent.id || agent.agentId;
    if (agentId) {
      herd.connect(agentId);
    }
  }

  /**
   * Report an attack on behalf of any agent in the network.
   * The pattern is immediately available to all other agents.
   * @param {object} attack - { text, category, agentId }
   * @returns {object}
   */
  function reportAttack(attack) {
    const result = herd.reportAttack(attack);
    if (result.pattern) {
      memory.learn(attack.text, result.pattern);
    }
    return result;
  }

  /**
   * Check text against the herd's collective immunity.
   * @param {string} text
   * @returns {object}
   */
  function checkAll(text) {
    const herdResult = herd.checkImmunity(text);
    const memoryResult = memory.recall(text);
    return {
      immune: herdResult.immune || memoryResult.matched,
      herdMatches: herdResult.matches,
      memoryMatches: memoryResult.matches
    };
  }

  console.log('%s Herd network created with %d agent(s)', LOG_PREFIX, agents.length);

  return { herd, memory, reportAttack, checkAll };
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = { HerdImmunity, ImmuneMemory, createHerdNetwork };
