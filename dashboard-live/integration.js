'use strict';

const { ThreatStreamServer } = require('./server');

/**
 * Integrates the live dashboard with an AgentShield instance.
 * Wraps shield.scan() to automatically feed results to the dashboard server.
 */
class DashboardIntegration {
  /**
   * @param {Object} shield — an AgentShield instance (or any object with a .scan() method)
   * @param {Object} [serverConfig] — config passed to ThreatStreamServer
   * @param {number} [serverConfig.port=8080]
   * @param {number} [serverConfig.maxClients=100]
   * @param {number} [serverConfig.historySize=1000]
   */
  constructor(shield, serverConfig = {}) {
    this.shield = shield;
    this.server = new ThreatStreamServer(serverConfig);
    this._originalScan = null;
    this._running = false;
  }

  /**
   * Start the dashboard server and hook into shield scans.
   * @returns {Promise<void>}
   */
  async start() {
    if (this._running) return;

    await this.server.start();
    this._running = true;

    if (this.shield && typeof this.shield.scan === 'function') {
      this.wrapScan(this.shield.scan);
    }

    console.log(`[Agent Shield] Dashboard available at ${this.getUrl()}`);
  }

  /**
   * Stop the dashboard server and restore the original scan method.
   * @returns {Promise<void>}
   */
  async stop() {
    if (!this._running) return;

    // Restore original scan
    if (this.shield && this._originalScan) {
      this.shield.scan = this._originalScan;
      this._originalScan = null;
    }

    await this.server.stop();
    this._running = false;
  }

  /**
   * Monkey-patch the shield's scan method to also ingest results into the dashboard.
   * @param {Function} originalScan — the original scan method
   */
  wrapScan(originalScan) {
    this._originalScan = originalScan;
    const server = this.server;
    const shield = this.shield;

    this.shield.scan = function wrappedScan() {
      const startTime = Date.now();
      const result = originalScan.apply(shield, arguments);

      // Handle both sync and async scan methods
      if (result && typeof result.then === 'function') {
        return result.then(function(scanResult) {
          const latency = Date.now() - startTime;
          const enriched = Object.assign({}, scanResult, { latency: latency });
          server.ingestScan(enriched);
          return scanResult;
        });
      }

      const latency = Date.now() - startTime;
      const enriched = Object.assign({}, result, { latency: latency });
      server.ingestScan(enriched);
      return result;
    };
  }

  /**
   * Get the dashboard URL.
   * @returns {string}
   */
  getUrl() {
    return 'http://localhost:' + this.server.port;
  }
}

module.exports = { DashboardIntegration };
