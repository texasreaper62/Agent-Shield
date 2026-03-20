'use strict';

/**
 * Agent Shield — Benchmark Leaderboard
 *
 * Manages ranked results, formatted output, badges, and historical tracking
 * for detection engine benchmarks.
 *
 * All processing runs locally — no data ever leaves your environment.
 */

// =========================================================================
// LEADERBOARD
// =========================================================================

/**
 * Leaderboard for tracking and ranking detection engine benchmark results.
 */
class Leaderboard {
  constructor() {
    /** @type {Array<Object>} All benchmark entries */
    this.entries = [];
    /** @type {Map<string, Array<Object>>} Historical results per engine */
    this.history = new Map();
  }

  /**
   * Add a benchmark result.
   * @param {string} engineId - Engine identifier
   * @param {string} engineName - Display name
   * @param {Object} metrics - Metrics object from benchmark run
   * @returns {void}
   */
  addResult(engineId, engineName, metrics) {
    const entry = {
      engineId,
      engineName,
      metrics: { ...metrics },
      timestamp: new Date().toISOString()
    };

    // Update or add entry (keep latest per engine)
    const existingIdx = this.entries.findIndex(e => e.engineId === engineId);
    if (existingIdx >= 0) {
      this.entries[existingIdx] = entry;
    } else {
      this.entries.push(entry);
    }

    // Track history
    if (!this.history.has(engineId)) {
      this.history.set(engineId, []);
    }
    this.history.get(engineId).push(entry);
  }

  /**
   * Get sorted rankings by a specific metric.
   * @param {string} [sortBy='f1'] - Metric to sort by (accuracy, throughput, latency, f1)
   * @returns {Array<Object>} Sorted entries with rank
   */
  getRankings(sortBy = 'f1') {
    const sorted = [...this.entries].sort((a, b) => {
      const aVal = this._getMetricValue(a, sortBy);
      const bVal = this._getMetricValue(b, sortBy);
      // For latency, lower is better
      if (sortBy === 'latency') return aVal - bVal;
      return bVal - aVal;
    });

    return sorted.map((entry, i) => ({
      rank: i + 1,
      ...entry
    }));
  }

  /**
   * Format rankings as an ASCII table.
   * @param {string} [sortBy='f1'] - Metric to sort by
   * @returns {string} ASCII table
   */
  formatTable(sortBy = 'f1') {
    const rankings = this.getRankings(sortBy);

    if (rankings.length === 0) {
      return '[Agent Shield] No benchmark results yet.';
    }

    const header = [
      'Rank', 'Engine', 'F1', 'Accuracy', 'Precision', 'Recall',
      'MCC', 'FPR', 'Throughput'
    ];
    const widths = [6, 24, 8, 10, 11, 8, 8, 8, 12];

    const pad = (str, width) => {
      const s = String(str);
      return s + ' '.repeat(Math.max(0, width - s.length));
    };

    const sep = widths.map(w => '-'.repeat(w)).join('-+-');
    const lines = [];

    lines.push(header.map((h, i) => pad(h, widths[i])).join(' | '));
    lines.push(sep);

    for (const entry of rankings) {
      const m = entry.metrics;
      const row = [
        `#${entry.rank}`,
        entry.engineName.slice(0, 22),
        this._pct(m.f1),
        this._pct(m.accuracy),
        this._pct(m.precision),
        this._pct(m.recall),
        m.mcc !== null && m.mcc !== undefined ? m.mcc.toFixed(3) : 'N/A',
        this._pct(m.falsePositiveRate),
        m.throughput !== undefined ? `${m.throughput.toFixed(0)} t/s` : 'N/A'
      ];
      lines.push(row.map((val, i) => pad(val, widths[i])).join(' | '));
    }

    return lines.join('\n');
  }

  /**
   * Format rankings as a Markdown table.
   * @param {string} [sortBy='f1'] - Metric to sort by
   * @returns {string} Markdown table
   */
  formatMarkdown(sortBy = 'f1') {
    const rankings = this.getRankings(sortBy);

    if (rankings.length === 0) {
      return '_No benchmark results yet._';
    }

    const lines = [
      '| Rank | Engine | F1 | Accuracy | Precision | Recall | MCC | FPR | Throughput |',
      '|------|--------|-----|----------|-----------|--------|-----|-----|------------|'
    ];

    for (const entry of rankings) {
      const m = entry.metrics;
      lines.push(
        `| #${entry.rank} ` +
        `| ${entry.engineName} ` +
        `| ${this._pct(m.f1)} ` +
        `| ${this._pct(m.accuracy)} ` +
        `| ${this._pct(m.precision)} ` +
        `| ${this._pct(m.recall)} ` +
        `| ${m.mcc !== null && m.mcc !== undefined ? m.mcc.toFixed(3) : 'N/A'} ` +
        `| ${this._pct(m.falsePositiveRate)} ` +
        `| ${m.throughput !== undefined ? m.throughput.toFixed(0) + ' t/s' : 'N/A'} |`
      );
    }

    return lines.join('\n');
  }

  /**
   * Generate an SVG badge for an engine showing its score.
   * @param {string} engineId - Engine identifier
   * @returns {string} SVG badge markup
   */
  getBadge(engineId) {
    const entry = this.entries.find(e => e.engineId === engineId);
    if (!entry) {
      return this._createBadge('shield score', 'N/A', '#999');
    }

    const f1 = entry.metrics.f1;
    const score = Math.round(f1 * 100);
    let color = '#e05d44'; // red
    if (score >= 90) color = '#44cc11'; // green
    else if (score >= 80) color = '#97ca00'; // yellow-green
    else if (score >= 70) color = '#dfb317'; // yellow
    else if (score >= 60) color = '#fe7d37'; // orange

    return this._createBadge('shield score', `${score}%`, color);
  }

  /**
   * Get historical results for an engine.
   * @param {string} engineId - Engine identifier
   * @returns {Array<Object>} Historical entries
   */
  getHistory(engineId) {
    return this.history.get(engineId) || [];
  }

  /**
   * Get trend data showing improvement over time for all engines.
   * @returns {Object} Trends keyed by engine ID
   */
  getTrends() {
    const trends = {};

    for (const [engineId, runs] of this.history) {
      if (runs.length < 2) {
        trends[engineId] = {
          engineName: runs[0] ? runs[0].engineName : engineId,
          dataPoints: runs.length,
          trend: 'insufficient_data'
        };
        continue;
      }

      const first = runs[0].metrics;
      const last = runs[runs.length - 1].metrics;
      const f1Delta = (last.f1 || 0) - (first.f1 || 0);
      const accDelta = (last.accuracy || 0) - (first.accuracy || 0);

      let direction = 'stable';
      if (f1Delta > 0.01) direction = 'improving';
      else if (f1Delta < -0.01) direction = 'declining';

      trends[engineId] = {
        engineName: runs[0].engineName,
        dataPoints: runs.length,
        trend: direction,
        f1Delta: Math.round(f1Delta * 10000) / 10000,
        accuracyDelta: Math.round(accDelta * 10000) / 10000,
        firstRun: runs[0].timestamp,
        lastRun: runs[runs.length - 1].timestamp
      };
    }

    return trends;
  }

  // --- Private helpers ---

  /**
   * @private
   * @param {Object} entry
   * @param {string} metric
   * @returns {number}
   */
  _getMetricValue(entry, metric) {
    const m = entry.metrics;
    switch (metric) {
      case 'accuracy': return m.accuracy || 0;
      case 'throughput': return m.throughput || 0;
      case 'latency': return m.latency ? m.latency.p50 : Infinity;
      case 'f1': return m.f1 || 0;
      case 'precision': return m.precision || 0;
      case 'recall': return m.recall || 0;
      case 'mcc': return m.mcc || 0;
      default: return m.f1 || 0;
    }
  }

  /**
   * @private
   * @param {number} val
   * @returns {string}
   */
  _pct(val) {
    if (val === undefined || val === null) return 'N/A';
    return (val * 100).toFixed(1) + '%';
  }

  /**
   * @private
   * @param {string} label
   * @param {string} value
   * @param {string} color
   * @returns {string}
   */
  _createBadge(label, value, color) {
    const labelWidth = label.length * 7 + 10;
    const valueWidth = value.length * 7 + 10;
    const totalWidth = labelWidth + valueWidth;

    return `<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="20">
  <linearGradient id="smooth" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="round">
    <rect width="${totalWidth}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#round)">
    <rect width="${labelWidth}" height="20" fill="#555"/>
    <rect x="${labelWidth}" width="${valueWidth}" height="20" fill="${color}"/>
    <rect width="${totalWidth}" height="20" fill="url(#smooth)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,sans-serif" font-size="11">
    <text x="${labelWidth / 2}" y="15" fill="#010101" fill-opacity=".3">${label}</text>
    <text x="${labelWidth / 2}" y="14">${label}</text>
    <text x="${labelWidth + valueWidth / 2}" y="15" fill="#010101" fill-opacity=".3">${value}</text>
    <text x="${labelWidth + valueWidth / 2}" y="14">${value}</text>
  </g>
</svg>`;
  }
}

module.exports = { Leaderboard };
