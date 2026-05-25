'use strict';

/**
 * Agent Shield — Dreaming Subsystem
 *
 * A background self-improvement engine modeled on what managed Claude
 * agents do during compaction / idle: consolidate recent events, distill
 * patterns, rehearse adversarially, and emit artifacts that the awake
 * detector picks up next cycle.
 *
 * Concepts:
 *   - Dream:           a unit of background work (consolidate, retune,
 *                      evolve attacks, hunt, fuzz, replay shadow diffs,
 *                      retrain, audit drift, analyze customer repos,
 *                      draft SOC patches). Each has a priority, a budget,
 *                      and a canRun() gate.
 *   - DreamMemory:     append-only event log + versioned artifact store.
 *                      Survives across cycles; the awake detector and
 *                      sleeping dreams share it.
 *   - DreamScheduler:  picks the next dream(s) to run on a tick. Triggers:
 *                        - 'idle'   (manual: caller invokes tick())
 *                        - 'cron'   (caller wires setInterval)
 *                        - 'pressure' (memory event count over threshold)
 *                        - 'manual' (run a named dream right now)
 *   - DreamArtifactLoader: when the agent wakes, scans artifacts and
 *                      applies the high-confidence ones (new thresholds,
 *                      new patterns) to the live shield.
 *
 * Zero new dependencies. Every dream wires modules already shipped on this
 * branch: ThresholdTuner, IncidentReplay, AdversarialTournament,
 * ThreatHunter, CrossSDKDifferential, CustomerLearning, ShadowModeReporter.
 */

const { AgentShield } = require('./index');
const { ShieldAgent } = require('./shield-agent');
const { IncidentReplay } = require('./incident-replay');
const { ThresholdTuner } = require('./threshold-tuner');
const { AdversarialTournament } = require('./adversarial-tournament');
const { ThreatHunter, LocalCorpusSource } = require('./threat-hunter');
const { CrossSDKDifferential } = require('./cross-sdk-differential');
const { CustomerLearning } = require('./customer-learning');
const { ShadowModeReporter } = require('./shadow-mode-reporter');

// =========================================================================
// DreamMemory
// =========================================================================

class DreamMemory {
  constructor(opts = {}) {
    this.maxEvents = opts.maxEvents || 100_000;
    this.events = [];
    this.artifacts = new Map(); // name → [{version, ts, data, confidence}]
    this.lastDreamRunAt = {};
  }

  ingestEvent(event) {
    if (!event || typeof event !== 'object') return;
    const e = { ts: event.ts || Date.now(), ...event };
    this.events.push(e);
    if (this.events.length > this.maxEvents) {
      this.events.splice(0, this.events.length - this.maxEvents);
    }
  }

  ingestEvents(events) {
    if (!Array.isArray(events)) return;
    for (const e of events) this.ingestEvent(e);
  }

  getEventsSince(ts) {
    return this.events.filter((e) => e.ts >= (ts || 0));
  }

  getEventsByKind(kind) {
    return this.events.filter((e) => e.kind === kind);
  }

  saveArtifact(name, data, opts = {}) {
    if (!this.artifacts.has(name)) this.artifacts.set(name, []);
    const versions = this.artifacts.get(name);
    const version = versions.length + 1;
    versions.push({
      version,
      ts: Date.now(),
      data,
      confidence: typeof opts.confidence === 'number' ? opts.confidence : 0.5,
      producer: opts.producer || null,
    });
    return version;
  }

  loadLatestArtifact(name, opts = {}) {
    const versions = this.artifacts.get(name);
    if (!versions || versions.length === 0) return null;
    const minConf = typeof opts.minConfidence === 'number' ? opts.minConfidence : 0;
    for (let i = versions.length - 1; i >= 0; i--) {
      if (versions[i].confidence >= minConf) return versions[i];
    }
    return null;
  }

  listArtifacts() {
    const out = {};
    for (const [name, versions] of this.artifacts) {
      out[name] = versions.length;
    }
    return out;
  }
}

// =========================================================================
// Dream base class + record shape
// =========================================================================

class Dream {
  constructor({ name, priority = 5, budgetMs = 30_000 }) {
    if (!name) throw new Error('Dream requires name');
    this.name = name;
    this.priority = priority;
    this.budgetMs = budgetMs;
  }
  async canRun(memory) { void memory; return true; }
  async run(memory, ctx) { void memory; void ctx; throw new Error(`Dream ${this.name} did not implement run()`); }
}

function makeRecord(dream, started, status, artifactKeys = [], detail = null, error = null) {
  return {
    dream: dream.name,
    priority: dream.priority,
    startedAt: started,
    durationMs: Date.now() - started,
    status,
    artifacts: artifactKeys,
    detail,
    error: error ? (error.message || String(error)) : null,
  };
}

async function withBudget(promise, budgetMs, label) {
  return await Promise.race([
    Promise.resolve(promise),
    new Promise((_, reject) => setTimeout(() => reject(new Error(`${label} exceeded budget ${budgetMs}ms`)), budgetMs)),
  ]);
}

// =========================================================================
// Concrete dreams
// =========================================================================

/**
 * ConsolidateIncidents — cluster recent incidents by root cause; emit a
 * digest artifact the awake state can summarize for ops.
 */
class ConsolidateIncidentsDream extends Dream {
  constructor(opts = {}) { super({ name: 'consolidate-incidents', priority: 7, budgetMs: opts.budgetMs || 30_000 }); this.opts = opts; }
  async canRun(memory) {
    return memory.getEventsByKind('incident').length >= (this.opts.minIncidents || 3);
  }
  async run(memory, ctx) {
    const started = Date.now();
    try {
      const replay = ctx.replay || new IncidentReplay({ shield: ctx.shield });
      const incidents = memory.getEventsByKind('incident').slice(-100);
      const reports = await withBudget(
        Promise.all(incidents.map((i) => replay.investigate({
          text: i.text, reportedAs: i.reportedAs, userNote: i.userNote, expectedAction: i.expectedAction,
        }))),
        this.budgetMs,
        this.name,
      );
      const clusters = clusterByRootCause(reports);
      const v = memory.saveArtifact('incident-digest', { clusters, totalIncidents: reports.length }, { confidence: 0.9, producer: this.name });
      return makeRecord(this, started, 'success', [`incident-digest@${v}`], { clusters: clusters.length });
    } catch (err) {
      return makeRecord(this, started, 'error', [], null, err);
    }
  }
}

/**
 * RetuneThresholds — use ThresholdTuner over recent labeled events to
 * propose new per-category thresholds. Confidence is the tuned-F1 minus
 * baseline-F1 (capped to [0,1]).
 */
class RetuneThresholdsDream extends Dream {
  constructor(opts = {}) { super({ name: 'retune-thresholds', priority: 6, budgetMs: opts.budgetMs || 30_000 }); this.opts = opts; }
  async canRun(memory) {
    return memory.getEventsByKind('labeled').length >= (this.opts.minLabeled || 20);
  }
  async run(memory, ctx) {
    const started = Date.now();
    try {
      const tuner = ctx.tuner || new ThresholdTuner({ shield: ctx.shield });
      const corpus = memory.getEventsByKind('labeled').slice(-2000)
        .map((e) => ({ text: e.text, expected: e.expected }))
        .filter((s) => s.text && (s.expected === 'allow' || s.expected === 'block'));
      if (corpus.length < (this.opts.minLabeled || 20)) {
        return makeRecord(this, started, 'skipped', [], { reason: 'insufficient labeled corpus' });
      }
      const baseline = tuner.baseline(corpus);
      const result = await withBudget(Promise.resolve(tuner.tune(corpus)), this.budgetMs, this.name);
      const delta = (result.metrics.f1 || 0) - (baseline.f1 || 0);
      const confidence = Math.max(0, Math.min(1, delta * 4));
      const v = memory.saveArtifact('thresholds', { thresholds: result.thresholds, baseline, tuned: result.metrics, delta }, { confidence, producer: this.name });
      return makeRecord(this, started, 'success', [`thresholds@${v}`], { delta, confidence, tuned: result.categoriesTuned });
    } catch (err) {
      return makeRecord(this, started, 'error', [], null, err);
    }
  }
}

/**
 * EvolveAttacks — run the adversarial tournament against current shield;
 * emit surviving attacks for HuntNovelPatterns to convert into rules.
 */
class EvolveAttacksDream extends Dream {
  constructor(opts = {}) { super({ name: 'evolve-attacks', priority: 5, budgetMs: opts.budgetMs || 60_000 }); this.opts = opts; }
  async canRun() { return true; }
  async run(memory, ctx) {
    const started = Date.now();
    try {
      const tournament = ctx.tournament || new AdversarialTournament({
        shield: ctx.shield, judge: ctx.judge,
        generations: this.opts.generations || 3,
        populationSize: this.opts.populationSize || 16,
      });
      const seedFromMemory = memory.getEventsByKind('attack-seed').slice(-50).map((e) => e.text);
      const report = await withBudget(tournament.run(seedFromMemory.length ? seedFromMemory : undefined), this.budgetMs, this.name);
      const confidence = report.finalBypassRate > 0 ? Math.min(1, report.finalBypassRate * 2) : 0.2;
      const v = memory.saveArtifact('attack-survivors', report.survivors, { confidence, producer: this.name });
      for (const s of report.survivors.slice(0, 20)) {
        memory.ingestEvent({ kind: 'attack-seed', text: s });
      }
      return makeRecord(this, started, 'success', [`attack-survivors@${v}`], { survivors: report.survivorCount, bypassRate: report.finalBypassRate });
    } catch (err) {
      return makeRecord(this, started, 'error', [], null, err);
    }
  }
}

/**
 * HuntNovelPatterns — feed surviving attacks (or labeled false-negatives)
 * into ThreatHunter to synthesize new regex patterns. Confidence reflects
 * the FP rate of the proposals (lower is better).
 */
class HuntNovelPatternsDream extends Dream {
  constructor(opts = {}) { super({ name: 'hunt-novel-patterns', priority: 6, budgetMs: opts.budgetMs || 30_000 }); this.opts = opts; }
  async canRun(memory) {
    return (memory.loadLatestArtifact('attack-survivors')?.data?.length || 0) > 0
      || memory.getEventsByKind('false-negative').length > 0;
  }
  async run(memory, ctx) {
    const started = Date.now();
    try {
      const survivors = (memory.loadLatestArtifact('attack-survivors')?.data || []).slice(0, 20);
      const fns = memory.getEventsByKind('false-negative').slice(-20).map((e) => e.text);
      const items = [...survivors, ...fns].map((text, i) => ({ title: `dream-${i}`, attackText: text, severity: 'high' }));
      if (items.length === 0) return makeRecord(this, started, 'skipped', [], { reason: 'no novel inputs' });
      const hunter = new ThreatHunter({
        shield: ctx.shield,
        sources: [new LocalCorpusSource(items, { name: 'dream' })],
        judge: ctx.judge,
      });
      const result = await withBudget(hunter.hunt(), this.budgetMs, this.name);
      const accepted = result.proposedPatterns;
      const meanFp = accepted.length ? accepted.reduce((a, p) => a + p.fpRate, 0) / accepted.length : 1;
      const confidence = accepted.length > 0 ? Math.max(0, 1 - meanFp * 10) : 0;
      const v = memory.saveArtifact('proposed-patterns', accepted.map((p) => ({
        category: p.category, severity: p.severity, regexSource: p.regexSource, description: p.description, fpRate: p.fpRate,
      })), { confidence, producer: this.name });
      return makeRecord(this, started, 'success', [`proposed-patterns@${v}`], { proposed: accepted.length, filtered: result.filteredPatterns.length, meanFp });
    } catch (err) {
      return makeRecord(this, started, 'error', [], null, err);
    }
  }
}

/**
 * ShadowDiffReplay — diff Shadow-Mode-Reporter snapshots over time and
 * surface drift (top noisy categories that are growing, etc).
 */
class ShadowDiffReplayDream extends Dream {
  constructor(opts = {}) { super({ name: 'shadow-diff-replay', priority: 4, budgetMs: opts.budgetMs || 15_000 }); this.opts = opts; }
  async canRun(memory) { return memory.getEventsByKind('shadow-scan').length >= 50; }
  async run(memory, ctx) {
    const started = Date.now();
    try {
      const reporter = new ShadowModeReporter();
      for (const e of memory.getEventsByKind('shadow-scan').slice(-5000)) {
        if (e.scan) reporter.ingest({ scan: e.scan, source: e.source });
      }
      const snapshot = reporter.report();
      const v = memory.saveArtifact('shadow-snapshot', snapshot, { confidence: 0.8, producer: this.name });
      // compare to previous
      const versions = memory.artifacts.get('shadow-snapshot') || [];
      let drift = null;
      if (versions.length >= 2) {
        const prev = versions[versions.length - 2].data;
        drift = diffSnapshots(prev, snapshot);
        if (drift) memory.saveArtifact('shadow-drift', drift, { confidence: 0.7, producer: this.name });
      }
      void ctx;
      return makeRecord(this, started, 'success', [`shadow-snapshot@${v}`], { drift });
    } catch (err) {
      return makeRecord(this, started, 'error', [], null, err);
    }
  }
}

/**
 * AuditDrift — cross-SDK differential audit using the drift bank.
 */
class AuditDriftDream extends Dream {
  constructor(opts = {}) { super({ name: 'audit-drift', priority: 3, budgetMs: opts.budgetMs || 20_000 }); this.opts = opts; }
  async canRun() { return true; }
  async run(memory, ctx) {
    const started = Date.now();
    try {
      const auditor = new CrossSDKDifferential({ shield: ctx.shield });
      const inputs = CrossSDKDifferential.driftBank();
      const result = await withBudget(auditor.audit(inputs, { minorityOnly: true }), this.budgetMs, this.name);
      const confidence = result.disagreements.length > 0 ? 1.0 : 0.2;
      const v = memory.saveArtifact('cross-sdk-drift', result, { confidence, producer: this.name });
      return makeRecord(this, started, 'success', [`cross-sdk-drift@${v}`], { disagreements: result.disagreements.length });
    } catch (err) {
      return makeRecord(this, started, 'error', [], null, err);
    }
  }
}

/**
 * AnalyzeCustomerRepos — read each registered repo path with
 * CustomerLearning; emit per-customer profiles.
 */
class AnalyzeCustomerReposDream extends Dream {
  constructor(opts = {}) { super({ name: 'analyze-customer-repos', priority: 4, budgetMs: opts.budgetMs || 60_000 }); this.opts = opts; this.paths = opts.paths || []; }
  async canRun() { return this.paths.length > 0; }
  async run(memory, ctx) {
    const started = Date.now();
    try {
      const learner = ctx.learner || new CustomerLearning();
      const profiles = [];
      for (const p of this.paths) {
        try {
          const out = await withBudget(learner.analyze(p), this.budgetMs, `${this.name}:${p}`);
          profiles.push({ path: p, profile: out.profile, summary: out.summary });
        } catch (err) {
          profiles.push({ path: p, error: err.message });
        }
      }
      const v = memory.saveArtifact('customer-profiles', profiles, { confidence: 0.85, producer: this.name });
      return makeRecord(this, started, 'success', [`customer-profiles@${v}`], { repos: profiles.length });
    } catch (err) {
      return makeRecord(this, started, 'error', [], null, err);
    }
  }
}

/**
 * DraftSOCPatches — assemble a change request from proposed-patterns +
 * incident-digest + shadow-drift artifacts. Awake state can PR this.
 */
class DraftSOCPatchesDream extends Dream {
  constructor(opts = {}) { super({ name: 'draft-soc-patches', priority: 8, budgetMs: opts.budgetMs || 10_000 }); this.opts = opts; }
  async canRun(memory) {
    return !!memory.loadLatestArtifact('proposed-patterns')
      || !!memory.loadLatestArtifact('thresholds');
  }
  async run(memory, ctx) {
    const started = Date.now();
    try {
      const proposed = memory.loadLatestArtifact('proposed-patterns');
      const thresholds = memory.loadLatestArtifact('thresholds');
      const digest = memory.loadLatestArtifact('incident-digest');
      const drift = memory.loadLatestArtifact('shadow-drift');
      const patch = {
        title: this._title({ proposed, thresholds, drift }),
        proposedPatterns: proposed ? proposed.data : [],
        thresholdProposal: thresholds ? { thresholds: thresholds.data.thresholds, delta: thresholds.data.delta } : null,
        incidentClusters: digest ? digest.data.clusters : [],
        shadowDrift: drift ? drift.data : null,
        generatedAt: Date.now(),
      };
      const v = memory.saveArtifact('change-request', patch, { confidence: 0.9, producer: this.name });
      void ctx;
      return makeRecord(this, started, 'success', [`change-request@${v}`], { hasPatterns: patch.proposedPatterns.length, hasThresholds: !!patch.thresholdProposal });
    } catch (err) {
      return makeRecord(this, started, 'error', [], null, err);
    }
  }
  _title({ proposed, thresholds, drift }) {
    const parts = [];
    if (proposed && proposed.data.length) parts.push(`add ${proposed.data.length} pattern(s)`);
    if (thresholds && thresholds.data.delta > 0.01) parts.push(`retune thresholds (Δ F1 +${thresholds.data.delta.toFixed(3)})`);
    if (drift && drift.data) parts.push('shadow-mode drift attention');
    return parts.length ? `[dream] ${parts.join('; ')}` : '[dream] minor maintenance';
  }
}

// =========================================================================
// DreamScheduler
// =========================================================================

const DEFAULT_DREAM_FACTORY = (opts = {}) => [
  new ConsolidateIncidentsDream(opts),
  new RetuneThresholdsDream(opts),
  new EvolveAttacksDream(opts),
  new HuntNovelPatternsDream(opts),
  new ShadowDiffReplayDream(opts),
  new AuditDriftDream(opts),
  new AnalyzeCustomerReposDream(opts),
  new DraftSOCPatchesDream(opts),
];

class DreamScheduler {
  constructor(opts = {}) {
    this.memory = opts.memory || new DreamMemory();
    this.dreams = opts.dreams || DEFAULT_DREAM_FACTORY(opts);
    this.ctx = {
      shield: opts.shield || new AgentShield(),
      agent: opts.agent || null,
      judge: opts.judge || null,
      replay: opts.replay || null,
      tuner: opts.tuner || null,
      tournament: opts.tournament || null,
      learner: opts.learner || null,
    };
    this.records = [];
    this.maxRecords = opts.maxRecords || 1000;
    this.pressureThreshold = opts.pressureThreshold || 100;
    this.onDream = opts.onDream || null;
  }

  /**
   * Run one tick: choose dreams whose canRun() is true (sorted by priority),
   * run up to `maxPerTick` of them sequentially, record each outcome.
   */
  async tick(opts = {}) {
    const maxPerTick = opts.maxPerTick || 3;
    const onlyNamed = opts.only || null;
    const candidates = [];
    for (const d of this.dreams) {
      if (onlyNamed && !onlyNamed.includes(d.name)) continue;
      let ok = false;
      try { ok = await d.canRun(this.memory); } catch (_) { ok = false; }
      if (ok) candidates.push(d);
    }
    candidates.sort((a, b) => b.priority - a.priority);
    const chosen = candidates.slice(0, maxPerTick);
    const records = [];
    for (const dream of chosen) {
      let r;
      try {
        r = await dream.run(this.memory, this.ctx);
      } catch (err) {
        r = makeRecord(dream, Date.now(), 'error', [], null, err);
      }
      this.memory.lastDreamRunAt[dream.name] = Date.now();
      this.records.push(r);
      if (this.records.length > this.maxRecords) this.records.splice(0, this.records.length - this.maxRecords);
      records.push(r);
      if (this.onDream) {
        try { this.onDream(r); } catch (_) { /* ignore */ }
      }
    }
    return { ran: chosen.map((c) => c.name), records };
  }

  /**
   * Pressure trigger: if event count since last full cycle exceeds threshold,
   * run a full tick.
   */
  async maybeTick(opts = {}) {
    if (this.memory.events.length < this.pressureThreshold) return { skipped: true };
    return await this.tick(opts);
  }

  /**
   * Manually invoke a single named dream now.
   */
  async runDream(name) {
    return await this.tick({ only: [name], maxPerTick: 1 });
  }

  stats() {
    const byStatus = { success: 0, error: 0, skipped: 0 };
    const byDream = {};
    for (const r of this.records) {
      byStatus[r.status] = (byStatus[r.status] || 0) + 1;
      byDream[r.dream] = (byDream[r.dream] || 0) + 1;
    }
    return {
      totalRecords: this.records.length,
      byStatus,
      byDream,
      memoryEvents: this.memory.events.length,
      artifacts: this.memory.listArtifacts(),
    };
  }
}

// =========================================================================
// DreamArtifactLoader — awake state pickup
// =========================================================================

/**
 * Apply high-confidence artifacts from DreamMemory to a live runtime.
 * Idempotent and conservative: only applies when confidence >= threshold.
 */
class DreamArtifactLoader {
  constructor(opts = {}) {
    this.memory = opts.memory;
    if (!this.memory) throw new Error('DreamArtifactLoader requires memory');
    this.minConfidence = typeof opts.minConfidence === 'number' ? opts.minConfidence : 0.75;
    this.applied = { thresholds: null, patterns: 0, changeRequests: 0 };
  }

  applyThresholds(shield) {
    const v = this.memory.loadLatestArtifact('thresholds', { minConfidence: this.minConfidence });
    if (!v) return null;
    if (typeof shield.applyThresholds === 'function') {
      shield.applyThresholds(v.data.thresholds);
      this.applied.thresholds = v.version;
      return v.data.thresholds;
    }
    // Fallback: just publish on shield.dreamThresholds for the host to read.
    shield.dreamThresholds = v.data.thresholds;
    this.applied.thresholds = v.version;
    return v.data.thresholds;
  }

  collectProposedPatterns() {
    const v = this.memory.loadLatestArtifact('proposed-patterns', { minConfidence: this.minConfidence });
    if (!v) return [];
    this.applied.patterns = v.data.length;
    return v.data;
  }

  collectChangeRequests() {
    const v = this.memory.loadLatestArtifact('change-request', { minConfidence: this.minConfidence });
    if (!v) return null;
    this.applied.changeRequests++;
    return v.data;
  }

  status() {
    return JSON.parse(JSON.stringify(this.applied));
  }
}

// =========================================================================
// Helpers
// =========================================================================

function clusterByRootCause(reports) {
  const clusters = new Map();
  for (const r of reports) {
    if (!r || r.error) continue;
    const key = r.rootCause && r.rootCause.primarySuspect
      ? `${r.kind}::${r.rootCause.primarySuspect.category}`
      : `${r.kind}::no-rule`;
    if (!clusters.has(key)) clusters.set(key, { key, count: 0, exemplars: [] });
    const c = clusters.get(key);
    c.count++;
    if (c.exemplars.length < 3) c.exemplars.push({
      input: r.input.length > 100 ? r.input.slice(0, 100) + '…' : r.input,
      diagnosis: r.diagnosis,
    });
  }
  return Array.from(clusters.values()).sort((a, b) => b.count - a.count);
}

function diffSnapshots(prev, curr) {
  if (!prev || !curr) return null;
  const drift = { added: [], removed: [], grew: [] };
  const prevCats = Object.fromEntries((prev.blocksByCategory || []).map((c) => [c.category, c.count]));
  const currCats = Object.fromEntries((curr.blocksByCategory || []).map((c) => [c.category, c.count]));
  for (const [cat, n] of Object.entries(currCats)) {
    if (!(cat in prevCats)) drift.added.push({ cat, count: n });
    else if (n > prevCats[cat] * 2 && n - prevCats[cat] >= 5) drift.grew.push({ cat, from: prevCats[cat], to: n });
  }
  for (const cat of Object.keys(prevCats)) {
    if (!(cat in currCats)) drift.removed.push({ cat, was: prevCats[cat] });
  }
  if (drift.added.length === 0 && drift.removed.length === 0 && drift.grew.length === 0) return null;
  return drift;
}

module.exports = {
  Dream,
  DreamMemory,
  DreamScheduler,
  DreamArtifactLoader,
  ConsolidateIncidentsDream,
  RetuneThresholdsDream,
  EvolveAttacksDream,
  HuntNovelPatternsDream,
  ShadowDiffReplayDream,
  AuditDriftDream,
  AnalyzeCustomerReposDream,
  DraftSOCPatchesDream,
  DEFAULT_DREAM_FACTORY,
};
