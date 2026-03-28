'use strict';

/**
 * Agent Shield — Drift Monitor Tests
 *
 * Run with: node test/test-drift-monitor.js
 */

const { DriftMonitor, klDivergence, mean, std, zScore } = require('../src/drift-monitor');

let passed = 0;
let failed = 0;

const assert = (condition, message) => {
  if (condition) {
    passed++;
    console.log(`  ✓ ${message}`);
  } else {
    failed++;
    console.error(`  ✗ ${message}`);
  }
};

// =========================================================================
// Statistical helpers
// =========================================================================

console.log('\n--- Statistical Helpers ---');

(() => {
  assert(mean([1, 2, 3, 4, 5]) === 3, 'Mean of [1,2,3,4,5] = 3');
  assert(mean([]) === 0, 'Mean of empty array = 0');

  const s = std([2, 4, 4, 4, 5, 5, 7, 9]);
  assert(s > 1.9 && s < 2.2, `Std dev is approximately 2 (got ${s.toFixed(3)})`);
  assert(std([5]) === 0, 'Std dev of single value = 0');
  assert(std([]) === 0, 'Std dev of empty array = 0');

  assert(zScore(10, 5, 2.5) === 2, 'Z-score of 10 (mean=5, std=2.5) = 2');
  assert(zScore(5, 5, 0) === 0, 'Z-score is 0 when value equals mean and std is 0');
  assert(zScore(10, 5, 0) === Infinity, 'Z-score is Infinity when std is 0 and value differs');
})();

// =========================================================================
// KL Divergence
// =========================================================================

console.log('\n--- KL Divergence ---');

(() => {
  // Same distributions — near zero
  const same = klDivergence({ a: 0.5, b: 0.5 }, { a: 0.5, b: 0.5 });
  assert(same < 0.001, `KL divergence of same distributions ≈ 0 (got ${same.toFixed(6)})`);

  // Different distributions — positive
  const diff = klDivergence({ a: 0.9, b: 0.1 }, { a: 0.1, b: 0.9 });
  assert(diff > 1, `KL divergence of very different distributions > 1 (got ${diff.toFixed(3)})`);

  // Disjoint keys
  const disjoint = klDivergence({ a: 1 }, { b: 1 });
  assert(disjoint > 0, 'KL divergence of disjoint keys > 0');
})();

// =========================================================================
// Learning phase
// =========================================================================

console.log('\n--- Learning Phase ---');

(() => {
  const monitor = new DriftMonitor({ windowSize: 10 });

  // Not enough observations yet
  for (let i = 0; i < 9; i++) {
    const r = monitor.observe({ callFreq: 5, responseLength: 100, errorRate: 0, timingMs: 50, topic: 'general' });
    assert(r.learning === true, `Observation ${i + 1}: still learning`);
    assert(r.baselineReady === false, `Observation ${i + 1}: baseline not ready`);
  }

  // 10th observation completes baseline
  const tenth = monitor.observe({ callFreq: 5, responseLength: 100, errorRate: 0, timingMs: 50, topic: 'general' });
  assert(tenth.baselineReady === true, 'Baseline ready after windowSize observations');
  assert(tenth.learning === false, 'No longer learning');
})();

// =========================================================================
// Drift detection
// =========================================================================

console.log('\n--- Drift Detection ---');

(() => {
  const monitor = new DriftMonitor({ windowSize: 5, alertThreshold: 3.0, klThreshold: 0.8 });

  // Build baseline: normal behavior with slight variance
  for (let i = 0; i < 5; i++) {
    monitor.observe({ callFreq: 2 + (i % 2), responseLength: 120 + i * 2, errorRate: 0, timingMs: 100 + i, topic: 'general' });
  }

  // Normal observation — no drift
  const normal = monitor.observe({ callFreq: 3, responseLength: 125, errorRate: 0, timingMs: 103, topic: 'general' });
  assert(normal.alert === false, 'Normal observation: no alert');

  // Anomalous observation — z-score drift
  const anomalous = monitor.observe({ callFreq: 200, responseLength: 50000, errorRate: 0.9, timingMs: 10000, topic: 'general' });
  assert(anomalous.alert === true, 'Anomalous observation: alert triggered');
  assert(typeof anomalous.zScores === 'object', 'Has z-scores');
  assert(anomalous.maxZScore > 2, 'Max z-score exceeds threshold');

  // Topic drift — KL divergence
  const topicDrift = monitor.observe({ callFreq: 2, responseLength: 120, errorRate: 0, timingMs: 100, topic: 'secrets_exfil' });
  assert(topicDrift.klDivergence > 0, 'KL divergence is positive for new topic');
})();

// =========================================================================
// Circuit breaker integration
// =========================================================================

console.log('\n--- Circuit Breaker Integration ---');

(() => {
  const monitor = new DriftMonitor({
    windowSize: 5,
    alertThreshold: 1.0,
    enableCircuitBreaker: true,
    circuitBreaker: { threshold: 2, windowMs: 60000, cooldownMs: 100 }
  });

  // Build baseline
  for (let i = 0; i < 5; i++) {
    monitor.observe({ callFreq: 2, responseLength: 120, errorRate: 0, timingMs: 100, topic: 'general' });
  }

  // Trigger multiple alerts to trip circuit breaker
  const drift1 = monitor.observe({ callFreq: 500, responseLength: 100000, errorRate: 1, timingMs: 50000, topic: 'attack' });
  assert(drift1.alert === true, 'First anomaly: alert');
  assert(drift1.actionTaken === 'tighten_contracts' || drift1.actionTaken === 'circuit_breaker_open', 'Action taken on first alert');

  const drift2 = monitor.observe({ callFreq: 600, responseLength: 200000, errorRate: 1, timingMs: 60000, topic: 'attack2' });
  assert(drift2.alert === true, 'Second anomaly: alert');
})();

// =========================================================================
// Webhook / callback
// =========================================================================

console.log('\n--- Webhook Callback ---');

(() => {
  const alerts = [];
  const monitor = new DriftMonitor({
    windowSize: 5,
    alertThreshold: 1.0,
    onAlert: (alert) => alerts.push(alert)
  });

  // Build baseline
  for (let i = 0; i < 5; i++) {
    monitor.observe({ callFreq: 2, responseLength: 120, errorRate: 0, timingMs: 100, topic: 'general' });
  }

  // Trigger alert
  monitor.observe({ callFreq: 500, responseLength: 50000, errorRate: 0.9, timingMs: 10000, topic: 'exfil' });

  assert(alerts.length >= 1, 'Webhook callback received alert');
  assert(alerts[0].type === 'behavioral_drift', 'Alert type is behavioral_drift');
  assert(alerts[0].severity === 'high', 'Alert severity is high');
  assert(typeof alerts[0].timestamp === 'number', 'Alert has timestamp');
  assert(typeof alerts[0].topic === 'string', 'Alert has topic');
})();

// =========================================================================
// Prometheus / OTel integration
// =========================================================================

console.log('\n--- Metric Export ---');

(() => {
  const gauges = {};
  const otelMetrics = {};
  const monitor = new DriftMonitor({
    windowSize: 5,
    alertThreshold: 1.0,
    prometheus: { setGauge: (name, value) => { gauges[name] = value; } },
    metrics: { recordMetric: (name, value, labels) => { otelMetrics[name] = { value, labels }; } }
  });

  // Build baseline & trigger drift
  for (let i = 0; i < 5; i++) {
    monitor.observe({ callFreq: 2, responseLength: 120, errorRate: 0, timingMs: 100, topic: 'general' });
  }
  monitor.observe({ callFreq: 500, responseLength: 50000, errorRate: 1, timingMs: 50000, topic: 'attack' });

  assert(gauges['agentshield_drift_max_zscore'] > 0, 'Prometheus gauge set for max z-score');
  assert(gauges['agentshield_drift_kl_divergence'] > 0, 'Prometheus gauge set for KL divergence');
  assert(otelMetrics['drift.alert'] !== undefined, 'OTel metric recorded for drift alert');
  assert(otelMetrics['drift.max_zscore'] !== undefined, 'OTel metric recorded for max z-score');
})();

// =========================================================================
// Periodic summary
// =========================================================================

console.log('\n--- Periodic Summary ---');

(() => {
  const monitor = new DriftMonitor({ windowSize: 5 });

  // Before baseline
  const early = monitor.getPeriodicSummary();
  assert(early.baselineReady === false, 'Summary shows not ready before baseline');
  assert(early.windowSize === 5, 'Summary has window size');

  // After baseline
  for (let i = 0; i < 5; i++) {
    monitor.observe({ callFreq: 3, responseLength: 150, errorRate: 0.01, timingMs: 80, topic: 'api' });
  }
  const summary = monitor.getPeriodicSummary();
  assert(summary.baselineReady === true, 'Summary shows ready after baseline');
  assert(typeof summary.baseline === 'object', 'Summary has baseline stats');
  assert(typeof summary.baseline.callFreqMean === 'number', 'Baseline has callFreqMean');
  assert(typeof summary.currentStats === 'object', 'Summary has current stats');
})();

// =========================================================================
// Alert history
// =========================================================================

console.log('\n--- Alert History ---');

(() => {
  const monitor = new DriftMonitor({ windowSize: 5, alertThreshold: 1.0 });

  for (let i = 0; i < 5; i++) {
    monitor.observe({ callFreq: 2, responseLength: 120, errorRate: 0, timingMs: 100, topic: 'general' });
  }
  monitor.observe({ callFreq: 500, responseLength: 50000, errorRate: 1, timingMs: 50000, topic: 'attack' });

  const history = monitor.getAlertHistory();
  assert(history.length >= 1, 'Alert history has entries');
  assert(history[0].type === 'behavioral_drift', 'History entry has correct type');
})();

// =========================================================================
// Reset
// =========================================================================

console.log('\n--- Reset ---');

(() => {
  const monitor = new DriftMonitor({ windowSize: 5 });
  for (let i = 0; i < 5; i++) {
    monitor.observe({ callFreq: 2, responseLength: 120, errorRate: 0, timingMs: 100, topic: 'general' });
  }
  assert(monitor.baseline !== null, 'Baseline exists before reset');

  monitor.reset();
  assert(monitor.baseline === null, 'Baseline cleared after reset');
  assert(monitor.getAlertHistory().length === 0, 'Alert history cleared');
})();

// =========================================================================
// Summary
// =========================================================================

console.log(`\n${'='.repeat(50)}`);
console.log(`Drift Monitor Tests: ${passed} passed, ${failed} failed`);
console.log(`${'='.repeat(50)}\n`);

if (failed > 0) {
  process.exit(1);
}
