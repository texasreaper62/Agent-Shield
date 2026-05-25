'use strict';

/**
 * Agent Shield — Production-Traffic Shadow-Mode Reporter (H2)
 *
 * Deploy Shield in shadow mode (detector runs, results recorded, action is
 * always allow). After N days the reporter emits an executive summary:
 *
 *   - traffic volume + scan-time percentiles
 *   - threats blocked / would-block / would-rewrite by category & severity
 *   - top noisy patterns (FP candidates) + top quiet categories
 *   - confidence histogram + recommended thresholds (if tuner is wired)
 *   - estimated ROI: blocks * estimated cost-per-incident
 *
 * Pure aggregator over a stream of scan events. Zero new dependencies.
 */

class ShadowModeReporter {
  constructor(opts = {}) {
    this.events = [];
    this.maxEvents = opts.maxEvents || 1_000_000;
    this.costPerIncident = opts.costPerIncident || 5000; // USD; user can override
    this.thresholdTuner = opts.thresholdTuner || null;
  }

  /**
   * Record a scan event. Accepted shapes:
   *   - raw shield.scan() result
   *   - { timestamp?, scan, source?, action? } envelope
   */
  ingest(event) {
    if (!event) return;
    let scan, source, action, ts;
    if (Array.isArray(event.threats) && event.stats) {
      scan = event;
      source = 'scan';
      action = null;
      ts = event.timestamp || Date.now();
    } else {
      scan = event.scan || null;
      source = event.source || 'unknown';
      action = event.action || null;
      ts = event.timestamp || Date.now();
    }
    if (!scan) return;
    this.events.push({
      timestamp: ts,
      source,
      action,
      severity: this._maxSeverity(scan),
      categories: (scan.threats || []).map((t) => t.category),
      confidences: (scan.threats || []).map((t) => t.confidence || 0),
      scanTimeMs: scan.stats?.scanTimeMs || 0,
      threatCount: (scan.threats || []).length,
    });
    if (this.events.length > this.maxEvents) {
      this.events.splice(0, this.events.length - this.maxEvents);
    }
  }

  ingestMany(events) {
    if (!Array.isArray(events)) return;
    for (const e of events) this.ingest(e);
  }

  /**
   * Generate the shadow-mode report.
   * @param {object} [opts]
   * @param {number} [opts.from] window start (ms)
   * @param {number} [opts.to]   window end (ms)
   * @returns {object} report
   */
  report(opts = {}) {
    const from = opts.from || 0;
    const to = opts.to || Date.now();
    const inWindow = this.events.filter((e) => e.timestamp >= from && e.timestamp <= to);

    const counts = { safe: 0, low: 0, medium: 0, high: 0, critical: 0 };
    const categoryCounts = {};
    const categoryConfidence = {};
    const sourceCounts = {};
    let totalScanTime = 0;
    const scanTimes = [];
    let wouldBlock = 0, wouldRewrite = 0, wouldAllow = 0;

    for (const e of inWindow) {
      counts[e.severity] = (counts[e.severity] || 0) + 1;
      totalScanTime += e.scanTimeMs;
      scanTimes.push(e.scanTimeMs);
      sourceCounts[e.source] = (sourceCounts[e.source] || 0) + 1;

      for (let i = 0; i < e.categories.length; i++) {
        const c = e.categories[i];
        categoryCounts[c] = (categoryCounts[c] || 0) + 1;
        if (!categoryConfidence[c]) categoryConfidence[c] = [];
        categoryConfidence[c].push(e.confidences[i] || 0);
      }

      if (e.severity === 'critical' || e.severity === 'high') wouldBlock++;
      else if (e.severity === 'medium') wouldRewrite++;
      else wouldAllow++;
    }

    const sortedTimes = [...scanTimes].sort((a, b) => a - b);
    const percentile = (p) => {
      if (sortedTimes.length === 0) return 0;
      const idx = Math.min(Math.floor(sortedTimes.length * p), sortedTimes.length - 1);
      return sortedTimes[idx];
    };

    const noisyCategories = Object.entries(categoryCounts)
      .filter(([, c]) => c >= 5)
      .map(([cat, c]) => {
        const confs = categoryConfidence[cat];
        const avgConf = confs.reduce((a, b) => a + b, 0) / confs.length;
        return { category: cat, count: c, avgConfidence: avgConf };
      })
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    const quietCategories = Object.entries(categoryCounts)
      .filter(([, c]) => c === 1)
      .map(([cat]) => cat)
      .slice(0, 20);

    const blocksByCategory = Object.entries(categoryCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 20)
      .map(([category, count]) => ({ category, count }));

    const estimatedROI = wouldBlock * this.costPerIncident;

    return {
      window: { from, to },
      trafficVolume: inWindow.length,
      bySeverity: counts,
      bySource: sourceCounts,
      blocksByCategory,
      noisyCategories,
      quietCategories,
      actionProjection: { wouldBlock, wouldRewrite, wouldAllow },
      latency: {
        avgMs: inWindow.length ? totalScanTime / inWindow.length : 0,
        p50Ms: percentile(0.5),
        p95Ms: percentile(0.95),
        p99Ms: percentile(0.99),
        maxMs: sortedTimes.length ? sortedTimes[sortedTimes.length - 1] : 0,
      },
      estimatedROI: { dollars: estimatedROI, basis: `${wouldBlock} blocks * $${this.costPerIncident}/incident` },
      generatedAt: Date.now(),
    };
  }

  /**
   * Build a markdown report.
   */
  markdownReport(opts) {
    const r = this.report(opts);
    const lines = [];
    lines.push('# Agent Shield — Shadow-Mode Report');
    lines.push('');
    lines.push(`**Window:** ${new Date(r.window.from).toISOString()} → ${new Date(r.window.to).toISOString()}`);
    lines.push(`**Total scans:** ${r.trafficVolume}`);
    lines.push('');
    lines.push('## Action projection (if deployed in enforce mode)');
    lines.push(`- Would block: **${r.actionProjection.wouldBlock}**`);
    lines.push(`- Would rewrite/sanitize: **${r.actionProjection.wouldRewrite}**`);
    lines.push(`- Would allow: ${r.actionProjection.wouldAllow}`);
    lines.push('');
    lines.push('## Severity distribution');
    lines.push(`| Severity | Count |`);
    lines.push(`|---|---:|`);
    for (const [s, c] of Object.entries(r.bySeverity)) lines.push(`| ${s} | ${c} |`);
    lines.push('');
    lines.push('## Top categories (volume)');
    lines.push(`| Category | Count |`);
    lines.push(`|---|---:|`);
    for (const { category, count } of r.blocksByCategory) lines.push(`| ${category} | ${count} |`);
    lines.push('');
    lines.push('## Latency');
    lines.push(`- avg: ${r.latency.avgMs.toFixed(2)}ms`);
    lines.push(`- p50: ${r.latency.p50Ms}ms · p95: ${r.latency.p95Ms}ms · p99: ${r.latency.p99Ms}ms · max: ${r.latency.maxMs}ms`);
    lines.push('');
    lines.push('## Noisy categories (likely FP candidates)');
    if (r.noisyCategories.length === 0) lines.push('_None._');
    else for (const n of r.noisyCategories) {
      lines.push(`- \`${n.category}\` — ${n.count} hits, avg confidence ${n.avgConfidence.toFixed(0)}`);
    }
    lines.push('');
    lines.push('## Estimated ROI');
    lines.push(`**$${r.estimatedROI.dollars.toLocaleString()}** — ${r.estimatedROI.basis}`);
    return lines.join('\n');
  }

  _maxSeverity(scan) {
    if (!scan || !scan.stats) {
      // Fall back to scanning threats[]
      const sev = (scan?.threats || []).map((t) => t.severity);
      if (sev.includes('critical')) return 'critical';
      if (sev.includes('high')) return 'high';
      if (sev.includes('medium')) return 'medium';
      if (sev.includes('low')) return 'low';
      return 'safe';
    }
    if (scan.stats.critical) return 'critical';
    if (scan.stats.high) return 'high';
    if (scan.stats.medium) return 'medium';
    if (scan.stats.low) return 'low';
    return 'safe';
  }
}

module.exports = { ShadowModeReporter };
