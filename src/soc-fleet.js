'use strict';

/**
 * Agent Shield — Multi-Agent SOC Fleet (H3)
 *
 * Orchestrates the H1+H2 modules into a coordinated security operations
 * center: Defender + Detective + Forensics + Patch-writer + Reviewer +
 * Releaser. Each role wraps existing capabilities; the fleet routes events
 * through them and produces an audit-trailed timeline.
 *
 * Roles:
 *   - Defender:   ShieldAgent triage of incoming events.
 *   - Detective:  IncidentReplay deep dive when Defender escalates.
 *   - Forensics:  ShadowModeReporter context + ComplianceNarrator framing.
 *   - PatchWriter:ThreatHunter-style pattern synthesis for novel attacks.
 *   - Reviewer:   judge-backed sanity check (or rule-based fallback).
 *   - Releaser:   emits a PR-ready bundle + ChangeRequest object.
 *
 * Zero new dependencies; pure orchestration. Every role's input/output is
 * captured as a SOCEvent in the timeline so the entire decision chain is
 * replayable and auditable.
 */

const { ShieldAgent, ACTIONS } = require('./shield-agent');
const { IncidentReplay, INCIDENT_KINDS } = require('./incident-replay');
const { ShadowModeReporter } = require('./shadow-mode-reporter');
const { ComplianceNarrator, FRAMEWORKS } = require('./compliance-narrator');
const { ThreatHunter, LocalCorpusSource } = require('./threat-hunter');

const ROLES = Object.freeze({
  DEFENDER: 'defender',
  DETECTIVE: 'detective',
  FORENSICS: 'forensics',
  PATCH_WRITER: 'patch_writer',
  REVIEWER: 'reviewer',
  RELEASER: 'releaser',
});

class SOCFleet {
  constructor(opts = {}) {
    this.shieldAgent = opts.shieldAgent || new ShieldAgent({ judge: opts.judge });
    this.judge = opts.judge || null;
    this.replay = opts.replay || new IncidentReplay({ shield: this.shieldAgent.shield, agent: this.shieldAgent });
    this.reporter = opts.reporter || new ShadowModeReporter();
    this.narrator = opts.narrator || new ComplianceNarrator({ framework: opts.framework || FRAMEWORKS.SOC2, judge: this.judge });
    this.timeline = [];
    this.maxTimeline = opts.maxTimeline || 10_000;
    this.reviewerJudgeBudgetMs = opts.reviewerJudgeBudgetMs || 5000;
  }

  /**
   * Main entrypoint. Run an event through the fleet.
   * @param {object} event { text, source, provenance?, expectedAction?, kind? }
   * @returns {Promise<object>} a ChangeRequest bundle
   */
  async handle(event) {
    if (!event || typeof event.text !== 'string') {
      throw new Error('handle requires {text: string}');
    }
    const traceId = `soc-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;
    const ctx = { traceId, event, decisions: [], artifacts: {} };

    // Defender: triage.
    const verdict = await this.shieldAgent.investigate(event.text, {
      source: event.source,
      provenance: event.provenance,
    });
    this._record(ctx, ROLES.DEFENDER, { verdict });

    // Reporter: every event feeds the shadow-mode aggregator.
    this.reporter.ingest({ scan: verdict.scan, source: event.source || 'soc', action: verdict.action });

    // Narrator: every event feeds the compliance log.
    this.narrator.ingest({
      severity: (verdict.scan && verdict.scan.severity) || 'unknown',
      category: (verdict.indicators && verdict.indicators[0]) || 'unknown',
      description: verdict.reason || '',
      source: event.source || 'soc',
      action: verdict.action,
    });

    // If Defender blocked or escalated, dispatch the rest of the fleet.
    if (verdict.action === ACTIONS.BLOCK || verdict.action === ACTIONS.ESCALATE || event.forceFullPipeline) {
      // Detective: reproduce + root-cause.
      const investigation = await this.replay.investigate({
        text: event.text,
        reportedAs: event.kind || (verdict.verdict === 'malicious' ? INCIDENT_KINDS.FALSE_NEGATIVE : INCIDENT_KINDS.FALSE_POSITIVE),
        expectedAction: event.expectedAction,
        userNote: event.userNote || verdict.reason,
      });
      ctx.artifacts.investigation = investigation;
      this._record(ctx, ROLES.DETECTIVE, { investigation });

      // Forensics: build a window report around this event (last 5 min).
      const now = Date.now();
      const reporterSnapshot = this.reporter.report({ from: now - 5 * 60_000, to: now });
      const narrative = await this.narrator.narrate({ from: now - 5 * 60_000, to: now });
      ctx.artifacts.shadowReport = reporterSnapshot;
      ctx.artifacts.complianceNarrative = narrative;
      this._record(ctx, ROLES.FORENSICS, { shadowSummary: reporterSnapshot.actionProjection, narrativeFramework: narrative.framework });

      // PatchWriter: if this was a novel attack, propose patterns via ThreatHunter.
      if (investigation.kind === INCIDENT_KINDS.FALSE_NEGATIVE) {
        const hunter = new ThreatHunter({
          shield: this.shieldAgent.shield,
          sources: [new LocalCorpusSource([
            { title: 'soc-novel', url: null, attackText: event.text, severity: 'high' },
          ], { name: 'soc-detective' })],
          judge: this.judge,
        });
        const hunt = await hunter.hunt();
        ctx.artifacts.patches = hunt.proposedPatterns;
        this._record(ctx, ROLES.PATCH_WRITER, { proposed: hunt.proposedPatterns.length, filtered: hunt.filteredPatterns.length });
      } else {
        ctx.artifacts.patches = [];
      }

      // Reviewer: judge-backed (or rule-based fallback) approval.
      const review = await this._review(ctx);
      ctx.artifacts.review = review;
      this._record(ctx, ROLES.REVIEWER, review);

      // Releaser: bundle the ChangeRequest.
      const changeRequest = this._bundle(ctx);
      ctx.artifacts.changeRequest = changeRequest;
      this._record(ctx, ROLES.RELEASER, { bundled: true, hasPatches: changeRequest.patches.length > 0 });
    }

    return {
      traceId: ctx.traceId,
      verdict,
      decisions: ctx.decisions,
      artifacts: ctx.artifacts,
    };
  }

  async _review(ctx) {
    if (!this.judge) {
      // Rule-based: approve patches with fpRate=0 and at most 5 patches; reject otherwise.
      const patches = ctx.artifacts.patches || [];
      const accept = patches.length > 0 && patches.length <= 5 && patches.every((p) => p.fpRate === 0);
      return {
        verdict: accept ? 'approve' : (patches.length === 0 ? 'no_op' : 'reject'),
        reason: accept ? 'rule-based: ≤5 patches with zero FP'
          : patches.length === 0 ? 'rule-based: no patches to review'
          : 'rule-based: rejected due to non-zero FP or >5 patches',
      };
    }
    const summary = {
      traceId: ctx.traceId,
      investigation: ctx.artifacts.investigation && {
        kind: ctx.artifacts.investigation.kind,
        diagnosis: ctx.artifacts.investigation.diagnosis,
      },
      patches: (ctx.artifacts.patches || []).map((p) => ({
        category: p.category,
        severity: p.severity,
        regex: p.regexSource,
        fpRate: p.fpRate,
      })),
    };
    const prompt = `You are the SOC reviewer. Approve or reject this change request. Reply with {"verdict":"approve|reject|no_op","reason":"..."} and nothing else.\n\n${JSON.stringify(summary, null, 2)}`;
    try {
      const reply = await Promise.race([
        Promise.resolve(this.judge({ system: 'You are a security reviewer. Reply with JSON only.', user: prompt })),
        new Promise((_, reject) => setTimeout(() => reject(new Error('judge timeout')), this.reviewerJudgeBudgetMs)),
      ]);
      const s = String(reply).trim();
      const start = s.indexOf('{');
      const end = s.lastIndexOf('}');
      if (start < 0 || end < 0) throw new Error('no JSON');
      return JSON.parse(s.slice(start, end + 1));
    } catch (err) {
      return { verdict: 'no_op', reason: `reviewer judge unavailable: ${err.message}` };
    }
  }

  _bundle(ctx) {
    const inv = ctx.artifacts.investigation || {};
    const patches = ctx.artifacts.patches || [];
    return {
      traceId: ctx.traceId,
      title: this._titleForChange(inv, patches),
      summary: inv.diagnosis || 'SOC fleet event',
      kind: inv.kind || 'unknown',
      patches: patches.map((p) => ({
        category: p.category,
        severity: p.severity,
        regexSource: p.regexSource,
        description: p.description,
        fpRate: p.fpRate,
      })),
      testCases: inv.testCase ? [inv.testCase] : [],
      review: ctx.artifacts.review || null,
      framework: ctx.artifacts.complianceNarrative && ctx.artifacts.complianceNarrative.framework,
      generatedAt: Date.now(),
    };
  }

  _titleForChange(inv, patches) {
    if (inv.kind === 'false_negative' && patches.length > 0) return `Add ${patches.length} detection pattern(s) — ${(inv.diagnosis || 'novel attack').slice(0, 80)}`;
    if (inv.kind === 'false_positive') return `Tighten pattern: ${(inv.diagnosis || '').slice(0, 80)}`;
    if (inv.kind === 'redos') return `Fix ReDoS: ${(inv.diagnosis || '').slice(0, 80)}`;
    if (inv.kind === 'crash') return `Fix detector crash on observed input`;
    return 'SOC change request';
  }

  _record(ctx, role, data) {
    const entry = { traceId: ctx.traceId, role, timestamp: Date.now(), data };
    ctx.decisions.push(entry);
    this.timeline.push(entry);
    if (this.timeline.length > this.maxTimeline) {
      this.timeline.splice(0, this.timeline.length - this.maxTimeline);
    }
  }

  /**
   * Snapshot of all SOC roles' recent activity.
   */
  status() {
    const byRole = {};
    for (const r of Object.values(ROLES)) byRole[r] = 0;
    for (const t of this.timeline) {
      if (t.role in byRole) byRole[t.role]++;
    }
    return {
      timelineLength: this.timeline.length,
      eventsByRole: byRole,
      lastEvent: this.timeline[this.timeline.length - 1] || null,
    };
  }
}

module.exports = { SOCFleet, ROLES };
