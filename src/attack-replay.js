'use strict';

/**
 * Agent Shield - Attack Replay Platform
 *
 * Record real attacks, replay them against updated defenses,
 * generate mutations, and track defense improvements over time.
 * Like BurpSuite's Repeater but for AI agent security.
 *
 * @module attack-replay
 */

const crypto = require('crypto');
const { scanText } = require('./detector-core');

/**
 * Records and replays attacks against defenses.
 */
class AttackReplayEngine {
  /**
   * @param {object} [options]
   * @param {number} [options.maxRecordings=10000] - Max stored recordings.
   * @param {string} [options.sensitivity='high'] - Detection sensitivity.
   */
  constructor(options = {}) {
    this.maxRecordings = options.maxRecordings || 10000;
    this.sensitivity = options.sensitivity || 'high';
    this._recordings = [];
    this._replayHistory = [];
  }

  /**
   * Record an attack for later replay.
   * @param {object} attack
   * @param {string} attack.text - The attack text.
   * @param {string} [attack.category] - Attack category.
   * @param {string} [attack.source] - Where the attack came from.
   * @param {boolean} [attack.wasDetected] - Whether it was caught originally.
   * @param {object} [attack.metadata] - Additional metadata.
   * @returns {object} The recording with ID and timestamp.
   */
  record(attack) {
    const recording = {
      id: crypto.randomBytes(8).toString('hex'),
      text: attack.text,
      category: attack.category || 'unknown',
      source: attack.source || 'manual',
      wasDetected: attack.wasDetected != null ? attack.wasDetected : null,
      metadata: attack.metadata || {},
      timestamp: Date.now(),
      hash: crypto.createHash('sha256').update(attack.text).digest('hex').substring(0, 16),
    };

    this._recordings.push(recording);
    if (this._recordings.length > this.maxRecordings) {
      this._recordings = this._recordings.slice(-Math.floor(this.maxRecordings * 0.75));
    }

    return recording;
  }

  /**
   * Replay a single recording against current defenses.
   * @param {string} recordingId
   * @returns {object} Replay result with detection status.
   */
  replay(recordingId) {
    const recording = this._recordings.find(r => r.id === recordingId);
    if (!recording) return null;

    const result = scanText(recording.text, { sensitivity: this.sensitivity });
    const detected = result.threats.length > 0;

    const replayResult = {
      recordingId,
      text: recording.text.substring(0, 100),
      category: recording.category,
      originallyDetected: recording.wasDetected,
      nowDetected: detected,
      improved: !recording.wasDetected && detected,
      regressed: recording.wasDetected && !detected,
      threats: result.threats,
      replayedAt: Date.now(),
    };

    this._replayHistory.push(replayResult);
    return replayResult;
  }

  /**
   * Replay ALL recordings against current defenses.
   * Shows what improved, regressed, or stayed the same.
   * @returns {object} Aggregate replay results.
   */
  replayAll() {
    const results = [];
    let improved = 0;
    let regressed = 0;
    let unchanged = 0;
    let nowDetected = 0;
    let nowMissed = 0;

    for (const recording of this._recordings) {
      const result = scanText(recording.text, { sensitivity: this.sensitivity });
      const detected = result.threats.length > 0;

      if (recording.wasDetected === false && detected) improved++;
      else if (recording.wasDetected === true && !detected) regressed++;
      else unchanged++;

      if (detected) nowDetected++;
      else nowMissed++;

      results.push({
        id: recording.id,
        category: recording.category,
        originally: recording.wasDetected,
        now: detected,
        status: recording.wasDetected === false && detected ? 'improved'
          : recording.wasDetected === true && !detected ? 'regressed'
          : 'unchanged',
      });
    }

    return {
      total: this._recordings.length,
      nowDetected,
      nowMissed,
      improved,
      regressed,
      unchanged,
      detectionRate: this._recordings.length > 0
        ? (nowDetected / this._recordings.length * 100).toFixed(1) + '%'
        : '0%',
      results,
      replayedAt: Date.now(),
    };
  }

  /**
   * Find recordings that currently evade detection (for targeted hardening).
   * @returns {Array} Recordings that are not detected by current defenses.
   */
  findEvasions() {
    const evasions = [];
    for (const recording of this._recordings) {
      const result = scanText(recording.text, { sensitivity: this.sensitivity });
      if (result.threats.length === 0) {
        evasions.push({
          id: recording.id,
          text: recording.text,
          category: recording.category,
          source: recording.source,
          hash: recording.hash,
        });
      }
    }
    return evasions;
  }

  /**
   * Export recordings for sharing or archival.
   * @returns {string} JSON string.
   */
  export() {
    return JSON.stringify({
      version: '1.0',
      exportedAt: Date.now(),
      recordings: this._recordings,
      count: this._recordings.length,
    }, null, 2);
  }

  /**
   * Import recordings from export.
   * @param {string} json
   * @returns {number} Number of recordings imported.
   */
  import(json) {
    const data = JSON.parse(json);
    const recordings = data.recordings || [];
    this._recordings.push(...recordings);
    if (this._recordings.length > this.maxRecordings) {
      this._recordings = this._recordings.slice(-this.maxRecordings);
    }
    return recordings.length;
  }

  /**
   * Get all recordings.
   * @param {string} [category] - Filter by category.
   * @returns {Array}
   */
  getRecordings(category) {
    if (category) return this._recordings.filter(r => r.category === category);
    return [...this._recordings];
  }

  /**
   * Get replay history.
   * @returns {Array}
   */
  getHistory() {
    return [...this._replayHistory];
  }

  /**
   * Get stats.
   * @returns {object}
   */
  getStats() {
    const categories = {};
    for (const r of this._recordings) {
      categories[r.category] = (categories[r.category] || 0) + 1;
    }
    return {
      totalRecordings: this._recordings.length,
      totalReplays: this._replayHistory.length,
      categories,
    };
  }
}

/**
 * Compare defense effectiveness across two time periods.
 * @param {object} before - replayAll() result from before.
 * @param {object} after - replayAll() result from after.
 * @returns {object} Comparison.
 */
function compareDefenses(before, after) {
  return {
    detectionRateBefore: before.detectionRate,
    detectionRateAfter: after.detectionRate,
    improvement: parseFloat(after.detectionRate) - parseFloat(before.detectionRate),
    newlyDetected: after.improved,
    regressions: after.regressed,
    verdict: parseFloat(after.detectionRate) > parseFloat(before.detectionRate) ? 'improved'
      : parseFloat(after.detectionRate) < parseFloat(before.detectionRate) ? 'regressed'
      : 'unchanged',
  };
}

module.exports = {
  AttackReplayEngine,
  compareDefenses,
};
