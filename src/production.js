'use strict';

/**
 * Agent Shield — Production Features
 *
 * - Sampling mode
 * - Dry run / shadow comparison
 * - Graceful degradation
 * - Threat replay
 * - Attack attribution chains
 * - Diff reports
 * - Security posture tracking over time
 */

const { scanText } = require('./detector-core');

// =========================================================================
// Sampling Mode
// =========================================================================

class SamplingScanner {
  constructor(options = {}) {
    this.sampleRate = options.sampleRate !== undefined ? options.sampleRate : 0.1; // 10% default
    this.scanFn = options.scanFn || ((text) => scanText(text, { sensitivity: options.sensitivity || 'high' }));
    this.stats = { total: 0, sampled: 0, threats: 0, extrapolatedThreats: 0 };
  }

  /**
   * Scan with sampling — only scans a percentage of inputs.
   */
  scan(text) {
    this.stats.total++;
    const shouldScan = Math.random() < this.sampleRate;

    if (!shouldScan) {
      return { sampled: false, status: 'skipped', threats: [] };
    }

    this.stats.sampled++;
    const result = this.scanFn(text);

    if (result.threats && result.threats.length > 0) {
      this.stats.threats += result.threats.length;
    }

    // Extrapolate
    this.stats.extrapolatedThreats = Math.round(this.stats.threats / this.sampleRate);

    return { sampled: true, ...result };
  }

  /**
   * Get extrapolated statistics.
   */
  getStats() {
    return {
      ...this.stats,
      sampleRate: `${(this.sampleRate * 100).toFixed(1)}%`,
      estimatedTotalThreats: this.stats.extrapolatedThreats,
      confidence: this.stats.sampled > 30 ? 'high' : this.stats.sampled > 10 ? 'medium' : 'low'
    };
  }

  setSampleRate(rate) {
    this.sampleRate = Math.max(0, Math.min(1, rate));
  }
}

// =========================================================================
// Dry Run / Shadow Comparison
// =========================================================================

class ShadowComparison {
  constructor(options = {}) {
    this.primaryScanFn = options.primary || ((text) => scanText(text, { sensitivity: 'high' }));
    this.candidateScanFn = options.candidate || ((text) => scanText(text, { sensitivity: 'high' }));
    this.results = [];
    this.maxResults = options.maxResults || 5000;
  }

  /**
   * Run both policies and compare results.
   */
  compare(text) {
    const primaryResult = this.primaryScanFn(text);
    const candidateResult = this.candidateScanFn(text);

    const primaryBlocked = primaryResult.threats && primaryResult.threats.length > 0;
    const candidateBlocked = candidateResult.threats && candidateResult.threats.length > 0;

    let diff = 'same';
    if (primaryBlocked && !candidateBlocked) diff = 'candidate_would_allow';
    else if (!primaryBlocked && candidateBlocked) diff = 'candidate_would_block';
    else if (primaryBlocked && candidateBlocked) {
      // Check if threats differ
      const pCats = new Set(primaryResult.threats.map(t => t.category));
      const cCats = new Set(candidateResult.threats.map(t => t.category));
      const sameCats = [...pCats].every(c => cCats.has(c)) && [...cCats].every(c => pCats.has(c));
      if (!sameCats) diff = 'different_threats';
    }

    const entry = {
      text: text.substring(0, 200),
      diff,
      primary: { status: primaryResult.status, threats: (primaryResult.threats || []).length },
      candidate: { status: candidateResult.status, threats: (candidateResult.threats || []).length },
      timestamp: Date.now()
    };

    this.results.push(entry);
    while (this.results.length > this.maxResults) {
      this.results.shift();
    }

    return { ...entry, primaryResult, candidateResult };
  }

  /**
   * Generate a diff report.
   */
  generateReport() {
    const total = this.results.length;
    if (total === 0) return { status: 'no_data', total: 0 };

    const same = this.results.filter(r => r.diff === 'same').length;
    const candidateWouldAllow = this.results.filter(r => r.diff === 'candidate_would_allow').length;
    const candidateWouldBlock = this.results.filter(r => r.diff === 'candidate_would_block').length;
    const differentThreats = this.results.filter(r => r.diff === 'different_threats').length;

    return {
      total,
      same,
      candidateWouldAllow,
      candidateWouldBlock,
      differentThreats,
      agreementRate: `${((same / total) * 100).toFixed(1)}%`,
      newBlocks: candidateWouldBlock,
      removedBlocks: candidateWouldAllow,
      examples: {
        wouldAllow: this.results.filter(r => r.diff === 'candidate_would_allow').slice(0, 5),
        wouldBlock: this.results.filter(r => r.diff === 'candidate_would_block').slice(0, 5)
      }
    };
  }

  clear() { this.results = []; }
}

// =========================================================================
// Graceful Degradation
// =========================================================================

class GracefulScanner {
  constructor(options = {}) {
    this.scanFn = options.scanFn || ((text) => scanText(text, { sensitivity: options.sensitivity || 'high' }));
    this.fallbackPolicy = options.fallbackPolicy || 'allow'; // 'allow' or 'block'
    this.timeoutMs = options.timeoutMs || 100;
    this.onError = options.onError || null;
    this.onTimeout = options.onTimeout || null;
    this.stats = { scans: 0, successes: 0, errors: 0, timeouts: 0, fallbacks: 0 };
  }

  /**
   * Scan with graceful error handling and timeout.
   */
  scan(text) {
    this.stats.scans++;
    const start = Date.now();

    try {
      const result = this.scanFn(text);
      const elapsed = Date.now() - start;

      if (elapsed > this.timeoutMs) {
        this.stats.timeouts++;
        if (this.onTimeout) this.onTimeout({ elapsed, text: text.substring(0, 100) });
        // Note: _fallback increments stats.fallbacks
        return this._fallback('timeout', elapsed);
      }

      this.stats.successes++;
      return result;
    } catch (error) {
      this.stats.errors++;
      if (this.onError) this.onError({ error: error.message, text: text.substring(0, 100) });
      return this._fallback('error', 0, error.message);
    }
  }

  _fallback(reason, elapsed = 0, errorMessage = null) {
    this.stats.fallbacks++;
    const blocked = this.fallbackPolicy === 'block';

    return {
      status: blocked ? 'danger' : 'safe',
      blocked,
      threats: blocked ? [{
        severity: 'medium',
        category: 'scanner_fallback',
        description: `Scanner ${reason}: using fallback policy (${this.fallbackPolicy})`,
        confidence: 0
      }] : [],
      _fallback: true,
      _fallbackReason: reason,
      _elapsed: elapsed,
      _error: errorMessage
    };
  }

  getStats() {
    return {
      ...this.stats,
      successRate: this.stats.scans > 0
        ? `${((this.stats.successes / this.stats.scans) * 100).toFixed(1)}%`
        : '0%',
      fallbackPolicy: this.fallbackPolicy
    };
  }
}

// =========================================================================
// Threat Replay
// =========================================================================

class ThreatReplay {
  constructor(options = {}) {
    this.recordings = [];
    this.maxRecordings = options.maxRecordings || 1000;
  }

  /**
   * Record a blocked/detected request for later replay.
   */
  record(text, scanResult, metadata = {}) {
    const entry = {
      id: `replay_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      text,
      originalResult: {
        status: scanResult.status,
        blocked: scanResult.blocked,
        threats: (scanResult.threats || []).map(t => ({
          severity: t.severity,
          category: t.category,
          description: t.description
        }))
      },
      metadata,
      recordedAt: new Date().toISOString()
    };

    this.recordings.push(entry);
    while (this.recordings.length > this.maxRecordings) {
      this.recordings.shift();
    }

    return entry.id;
  }

  /**
   * Replay all recordings against a scan function to compare results.
   */
  replay(scanFn) {
    const results = [];

    for (const rec of this.recordings) {
      const newResult = scanFn(rec.text);
      const originalBlocked = rec.originalResult.blocked;
      const newBlocked = newResult.threats && newResult.threats.length > 0;

      let diff = 'same';
      if (originalBlocked && !newBlocked) diff = 'now_allowed';
      else if (!originalBlocked && newBlocked) diff = 'now_blocked';

      results.push({
        id: rec.id,
        text: rec.text.substring(0, 100),
        diff,
        original: rec.originalResult,
        replayed: {
          status: newResult.status,
          blocked: newBlocked,
          threats: (newResult.threats || []).length
        }
      });
    }

    const nowAllowed = results.filter(r => r.diff === 'now_allowed');
    const nowBlocked = results.filter(r => r.diff === 'now_blocked');

    return {
      total: results.length,
      unchanged: results.filter(r => r.diff === 'same').length,
      nowAllowed: nowAllowed.length,
      nowBlocked: nowBlocked.length,
      regressions: nowAllowed,
      improvements: nowBlocked,
      results
    };
  }

  /**
   * Replay a single recording.
   */
  replayOne(id, scanFn) {
    const rec = this.recordings.find(r => r.id === id);
    if (!rec) return null;

    const newResult = scanFn(rec.text);
    return {
      original: rec.originalResult,
      replayed: newResult,
      text: rec.text.substring(0, 200)
    };
  }

  getRecordings() { return this.recordings; }
  clear() { this.recordings = []; }
}

// =========================================================================
// Attack Attribution Chain
// =========================================================================

class AttackAttributionChain {
  constructor(options = {}) {
    this.conversations = new Map();
    this.maxConversations = options.maxConversations || 10000;
  }

  /**
   * Record a message in a conversation.
   */
  recordMessage(conversationId, message, scanResult, metadata = {}) {
    if (!this.conversations.has(conversationId)) {
      this.conversations.set(conversationId, {
        id: conversationId,
        messages: [],
        firstThreatAt: null,
        killChain: []
      });
    }

    // Evict oldest conversation if at capacity
    if (this.conversations.size > this.maxConversations) {
      const oldestKey = this.conversations.keys().next().value;
      this.conversations.delete(oldestKey);
    }

    const conv = this.conversations.get(conversationId);
    const hasThreat = scanResult.threats && scanResult.threats.length > 0;

    const entry = {
      index: conv.messages.length,
      text: message.substring(0, 300),
      timestamp: new Date().toISOString(),
      hasThreat,
      threats: hasThreat ? scanResult.threats.map(t => ({ severity: t.severity, category: t.category, description: t.description })) : [],
      blocked: scanResult.blocked || false,
      ...metadata
    };

    conv.messages.push(entry);

    if (hasThreat && !conv.firstThreatAt) {
      conv.firstThreatAt = entry.index;
    }

    if (hasThreat) {
      conv.killChain.push({
        step: conv.killChain.length + 1,
        messageIndex: entry.index,
        categories: entry.threats.map(t => t.category),
        blocked: entry.blocked
      });
    }

    return entry;
  }

  /**
   * Reconstruct the kill chain for a conversation.
   */
  getKillChain(conversationId) {
    const conv = this.conversations.get(conversationId);
    if (!conv) return null;

    const totalMessages = conv.messages.length;
    const threatMessages = conv.messages.filter(m => m.hasThreat);

    return {
      conversationId,
      totalMessages,
      firstThreatAt: conv.firstThreatAt,
      threatMessages: threatMessages.length,
      messagesBeforeFirstThreat: conv.firstThreatAt || totalMessages,
      killChain: conv.killChain,
      timeline: conv.messages.map(m => ({
        index: m.index,
        hasThreat: m.hasThreat,
        blocked: m.blocked,
        categories: m.threats.map(t => t.category),
        text: m.text.substring(0, 80)
      }))
    };
  }

  /**
   * Get all conversations with detected threats.
   */
  getCompromisedConversations() {
    const result = [];
    for (const [id, conv] of this.conversations) {
      if (conv.killChain.length > 0) {
        result.push({
          id,
          messageCount: conv.messages.length,
          threatCount: conv.killChain.length,
          firstThreatAt: conv.firstThreatAt,
          categories: [...new Set(conv.killChain.flatMap(k => k.categories))]
        });
      }
    }
    return result;
  }

  clear() { this.conversations.clear(); }
}

// =========================================================================
// Diff Reports
// =========================================================================

class DiffReporter {
  constructor() {
    this.snapshots = [];
  }

  /**
   * Take a snapshot of current stats.
   */
  takeSnapshot(label, stats) {
    this.snapshots.push({
      label,
      timestamp: new Date().toISOString(),
      stats: JSON.parse(JSON.stringify(stats))
    });
    return this.snapshots.length - 1;
  }

  /**
   * Compare two snapshots.
   */
  compare(indexA, indexB) {
    const a = this.snapshots[indexA];
    const b = this.snapshots[indexB !== undefined ? indexB : this.snapshots.length - 1];
    if (!a || !b) return null;

    const diff = {};
    const allKeys = new Set([...Object.keys(a.stats), ...Object.keys(b.stats)]);

    for (const key of allKeys) {
      const valA = a.stats[key];
      const valB = b.stats[key];

      if (typeof valA === 'number' && typeof valB === 'number') {
        const change = valB - valA;
        const pctChange = valA > 0 ? ((change / valA) * 100).toFixed(1) : 'N/A';
        diff[key] = { before: valA, after: valB, change, percentChange: pctChange };
      } else {
        diff[key] = { before: valA, after: valB };
      }
    }

    return {
      from: { label: a.label, timestamp: a.timestamp },
      to: { label: b.label, timestamp: b.timestamp },
      diff,
      improved: Object.entries(diff).filter(([, v]) => typeof v.change === 'number' && v.change > 0).map(([k]) => k),
      degraded: Object.entries(diff).filter(([, v]) => typeof v.change === 'number' && v.change < 0).map(([k]) => k)
    };
  }

  getSnapshots() { return this.snapshots.map((s, i) => ({ index: i, label: s.label, timestamp: s.timestamp })); }
}

// =========================================================================
// Security Posture Tracker
// =========================================================================

class PostureTracker {
  constructor(options = {}) {
    this.history = [];
    this.maxHistory = options.maxHistory || 365;
  }

  /**
   * Record a posture measurement.
   */
  record(measurement) {
    this.history.push({
      timestamp: new Date().toISOString(),
      date: new Date().toISOString().split('T')[0],
      ...measurement
    });

    while (this.history.length > this.maxHistory) {
      this.history.shift();
    }
  }

  /**
   * Get the trend over a period.
   */
  getTrend(days = 30) {
    const cutoff = Date.now() - (days * 86400000);
    const recent = this.history.filter(h => new Date(h.timestamp).getTime() > cutoff);

    if (recent.length < 2) return { status: 'insufficient_data', dataPoints: recent.length };

    const first = recent[0];
    const last = recent[recent.length - 1];

    const scoreChange = (last.shieldScore || 0) - (first.shieldScore || 0);
    const threatChange = (last.threatsDetected || 0) - (first.threatsDetected || 0);

    return {
      period: `${days} days`,
      dataPoints: recent.length,
      scoreChange,
      scoreTrend: scoreChange > 0 ? 'improving' : scoreChange < 0 ? 'degrading' : 'stable',
      threatChange,
      first: { date: first.date, shieldScore: first.shieldScore },
      last: { date: last.date, shieldScore: last.shieldScore },
      history: recent
    };
  }

  /**
   * Get a summary message.
   */
  getSummary() {
    if (this.history.length === 0) return 'No posture data recorded yet.';

    const latest = this.history[this.history.length - 1];
    const trend = this.getTrend(30);

    if (trend.status === 'insufficient_data') {
      return `Current Shield Score: ${latest.shieldScore || 'N/A'}. Need more data for trend analysis.`;
    }

    const direction = trend.scoreChange > 0 ? 'improved' : trend.scoreChange < 0 ? 'degraded' : 'unchanged';
    return `Shield Score ${direction} by ${Math.abs(trend.scoreChange)} points over the last ${trend.period} (${trend.first.shieldScore} → ${trend.last.shieldScore}).`;
  }
}

module.exports = {
  SamplingScanner,
  ShadowComparison,
  GracefulScanner,
  ThreatReplay,
  AttackAttributionChain,
  DiffReporter,
  PostureTracker
};
