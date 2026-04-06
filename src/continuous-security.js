'use strict';

/**
 * Agent Shield — Continuous Security Service (SOTA)
 *
 * Background service that continuously monitors, hardens, and improves
 * the security posture of AI agent deployments. Inspired by Microsoft's
 * Agent 365 control plane and NIST continuous exposure management.
 *
 * Runs: self-training hardening, drift monitoring, attack surface scanning,
 * defense effectiveness benchmarking, and posture reporting on configurable
 * intervals.
 *
 * All processing runs locally — no data ever leaves your environment.
 *
 * @module continuous-security
 */

// =========================================================================
// ContinuousSecurityService
// =========================================================================

/**
 * Background security service for AI agent deployments.
 */
class ContinuousSecurityService {
  /**
   * @param {object} options
   * @param {object} options.guard - MCPGuard instance.
   * @param {object} [options.hardener] - AutonomousHardener instance.
   * @param {number} [options.postureScanIntervalMs=300000] - Posture scan interval (default: 5 min).
   * @param {number} [options.hardeningIntervalMs=3600000] - Self-training interval (default: 1 hour).
   * @param {number} [options.defenseCheckIntervalMs=1800000] - Defense check interval (default: 30 min).
   * @param {Function} [options.onPostureChange] - Callback when posture score changes.
   * @param {Function} [options.onAlert] - Callback for security alerts.
   */
  constructor(options = {}) {
    if (!options.guard) throw new Error('[Agent Shield] ContinuousSecurityService requires a guard instance.');
    this.guard = options.guard;
    this.hardener = options.hardener || null;
    this.postureScanInterval = options.postureScanIntervalMs || 300000;
    this.hardeningInterval = options.hardeningIntervalMs || 3600000;
    this.defenseCheckInterval = options.defenseCheckIntervalMs || 1800000;
    this.onPostureChange = options.onPostureChange || null;
    this.persistPath = options.persistPath || null; // Issue 17 fix: persist state
    this.onAlert = options.onAlert || null;

    this._timers = [];
    this._running = false;
    this._lastPosture = null;

    this.history = {
      postureScans: [],
      hardeningCycles: [],
      defenseChecks: [],
      alerts: []
    };
  }

  /**
   * Start the continuous security service.
   */
  start() {
    if (this._running) return;
    this._running = true;

    console.log('[Agent Shield] Continuous security service started.');

    // Load persisted state if available
    this.loadState();

    // Run immediately
    this._runPostureScan();
    this._runDefenseCheck();

    // Schedule recurring
    this._timers.push(setInterval(() => this._runPostureScan(), this.postureScanInterval));
    this._timers.push(setInterval(() => this._runDefenseCheck(), this.defenseCheckInterval));

    if (this.hardener) {
      this.hardener.start();
    }
  }

  /**
   * Stop the continuous security service.
   */
  stop() {
    for (const timer of this._timers) clearInterval(timer);
    this._timers = [];
    this._running = false;
    if (this.hardener) this.hardener.stop();
    console.log('[Agent Shield] Continuous security service stopped.');
  }

  /**
   * Get the current status.
   * @returns {object}
   */
  getStatus() {
    return {
      running: this._running,
      lastPosture: this._lastPosture,
      totalPostureScans: this.history.postureScans.length,
      totalDefenseChecks: this.history.defenseChecks.length,
      totalAlerts: this.history.alerts.length,
      hardenerStatus: this.hardener ? this.hardener.getStatus() : null,
      uptime: this._running ? Date.now() - (this.history.postureScans[0] || { timestamp: Date.now() }).timestamp : 0
    };
  }

  /**
   * Get a comprehensive security report aggregating all history.
   * @returns {object}
   */
  getReport() {
    const postures = this.history.postureScans;
    const scores = postures.map(p => p.score);

    return {
      currentScore: this._lastPosture ? this._lastPosture.score : null,
      currentGrade: this._lastPosture ? this._lastPosture.grade : null,
      scoreHistory: scores.slice(-20),
      scoreTrend: scores.length >= 2 ? (scores[scores.length - 1] > scores[scores.length - 2] ? 'improving' : scores[scores.length - 1] < scores[scores.length - 2] ? 'degrading' : 'stable') : 'insufficient_data',
      averageScore: scores.length > 0 ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : null,
      totalPostureScans: postures.length,
      totalDefenseChecks: this.history.defenseChecks.length,
      totalAlerts: this.history.alerts.length,
      recentAlerts: this.history.alerts.slice(-10),
      hardenerStatus: this.hardener ? this.hardener.getStatus() : null,
      timestamp: Date.now()
    };
  }

  /**
   * Run a single posture scan manually.
   * @returns {object}
   */
  runPostureScan() {
    return this._runPostureScan();
  }

  /**
   * Run a single defense check manually.
   * @returns {object}
   */
  runDefenseCheck() {
    return this._runDefenseCheck();
  }

  // -----------------------------------------------------------------------
  // Private
  // -----------------------------------------------------------------------

  /** @private */
  _runPostureScan() {
    try {
      const posture = this.guard.getSecurityPosture();
      const entry = {
        timestamp: Date.now(),
        score: posture.securityScore,
        grade: posture.grade,
        activeLayers: posture.activeLayers,
        totalThreats: posture.totalThreats,
        serverCount: posture.serverCount
      };

      this.history.postureScans.push(entry);
      if (this.history.postureScans.length > 500) {
        this.history.postureScans = this.history.postureScans.slice(-500);
      }

      // Detect posture degradation
      if (this._lastPosture && posture.securityScore < this._lastPosture.score - 10) {
        const alert = {
          timestamp: Date.now(),
          type: 'posture_degradation',
          severity: 'high',
          previousScore: this._lastPosture.score,
          currentScore: posture.securityScore,
          description: `Security posture degraded from ${this._lastPosture.score} to ${posture.securityScore}.`
        };
        this.history.alerts.push(alert);
        if (this.onAlert) try { this.onAlert(alert); } catch { /* ignore */ }
      }

      // Notify on posture change
      if (this.onPostureChange && (!this._lastPosture || this._lastPosture.score !== posture.securityScore)) {
        try { this.onPostureChange(entry); } catch { /* ignore */ }
      }

      this._lastPosture = entry;
      this.saveState();
      return entry;
    } catch (err) {
      return { timestamp: Date.now(), error: err.message };
    }
  }

  /** @private */
  _runDefenseCheck() {
    try {
      const effectiveness = this.guard.measureDefenseEffectiveness();
      const entry = {
        timestamp: Date.now(),
        ...effectiveness
      };

      this.history.defenseChecks.push(entry);
      if (this.history.defenseChecks.length > 100) {
        this.history.defenseChecks = this.history.defenseChecks.slice(-100);
      }

      // Alert if defense gaps found
      if (effectiveness.effectiveness.combined.caught < effectiveness.totalAttacks) {
        const missed = effectiveness.totalAttacks - effectiveness.effectiveness.combined.caught;
        const alert = {
          timestamp: Date.now(),
          type: 'defense_gap',
          severity: 'high',
          missedAttacks: missed,
          totalAttacks: effectiveness.totalAttacks,
          description: `Defense check: ${missed}/${effectiveness.totalAttacks} test attacks bypassed all layers.`
        };
        this.history.alerts.push(alert);
        if (this.onAlert) try { this.onAlert(alert); } catch { /* ignore */ }
      }

      return entry;
    } catch (err) {
      return { timestamp: Date.now(), error: err.message };
    }
  }

  /**
   * Save state to disk for persistence across restarts (Issue 17 fix).
   */
  saveState() {
    if (!this.persistPath) return;
    try {
      const fs = require('fs');
      const path = require('path');
      const dir = path.dirname(this.persistPath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(this.persistPath, JSON.stringify({
        postureScans: this.history.postureScans.slice(-100),
        defenseChecks: this.history.defenseChecks.slice(-20),
        alerts: this.history.alerts.slice(-50),
        lastPosture: this._lastPosture,
        savedAt: Date.now()
      }));
    } catch (err) {
      console.warn(`[Agent Shield] Failed to save state: ${err.message}`);
    }
  }

  /**
   * Load state from disk (Issue 17 fix).
   */
  loadState() {
    if (!this.persistPath) return;
    try {
      const fs = require('fs');
      if (!fs.existsSync(this.persistPath)) return;
      const data = JSON.parse(fs.readFileSync(this.persistPath, 'utf8'));
      if (data.postureScans) this.history.postureScans = data.postureScans;
      if (data.defenseChecks) this.history.defenseChecks = data.defenseChecks;
      if (data.alerts) this.history.alerts = data.alerts;
      if (data.lastPosture) this._lastPosture = data.lastPosture;
      console.log(`[Agent Shield] Loaded ${this.history.postureScans.length} posture scans from disk.`);
    } catch (err) {
      console.warn(`[Agent Shield] Failed to load state: ${err.message}`);
    }
  }
}

module.exports = {
  ContinuousSecurityService
};
