'use strict';

const { ComplianceNarrator, FRAMEWORKS } = require('../src/compliance-narrator');

let passed = 0, failed = 0;
const assert = (c, m) => { if (c) { passed++; console.log(`  ✓ ${m}`); } else { failed++; console.error(`  ✗ ${m}`); } };

(async () => {
  console.log('\n--- ComplianceNarrator: ingest event shapes ---');
  const n = new ComplianceNarrator({ framework: FRAMEWORKS.SOC2 });
  n.ingest({ severity: 'critical', category: 'instruction_override', description: 'override', action: 'block', timestamp: 100 });
  n.ingest({ severity: 'high', category: 'data_exfiltration', description: 'exfil', action: 'block', timestamp: 200 });
  // Raw scan-result shape
  n.ingest({
    timestamp: 300,
    threats: [
      { severity: 'high', category: 'role_hijack', description: 'DAN' },
      { severity: 'medium', category: 'config_poisoning', description: 'override URL' },
    ],
    source: 'scan',
    action: 'rewrite',
  });
  // ShieldAgent verdict shape
  n.ingest({
    timestamp: 400,
    verdict: 'malicious',
    action: 'block',
    reason: 'critical pattern matched',
    indicators: ['instruction_override'],
    scan: { severity: 'critical', source: 'detector' },
  });
  assert(n.events.length === 5, `5 events ingested (got ${n.events.length})`);

  console.log('\n--- ComplianceNarrator: ingestMany ---');
  const n2 = new ComplianceNarrator();
  n2.ingestMany([
    { severity: 'low', category: 'reconnaissance', description: 'probe', action: 'allow' },
    { severity: 'high', category: 'instruction_override', description: 'override', action: 'block' },
  ]);
  assert(n2.events.length === 2, 'ingestMany pushed all');
  n2.ingestMany(null);  // should not throw
  assert(n2.events.length === 2, 'ingestMany(null) is a no-op');

  console.log('\n--- ComplianceNarrator: narrate (deterministic) ---');
  const report = await n.narrate({ from: 0, to: 1000 });
  assert(report.framework === FRAMEWORKS.SOC2, 'framework recorded');
  assert(report.evidenceCount === 5, 'all events in window counted');
  assert(report.summary.bySeverity.critical >= 1, 'severity counts populated');
  assert(report.summary.byAction.block >= 2, 'action counts populated');
  assert(Object.keys(report.controls).length > 0, 'controls mapped');
  assert(report.narrative.includes('SOC2 Compliance Narrative'),
    'narrative has framework header');
  assert(report.narrative.includes('Executive summary'), 'narrative has executive summary');
  assert(report.signature === null, 'no signing key → signature is null');

  console.log('\n--- ComplianceNarrator: window filtering ---');
  const windowed = await n.narrate({ from: 200, to: 350 });
  assert(windowed.evidenceCount < report.evidenceCount,
    `window filter reduces events (full=${report.evidenceCount}, windowed=${windowed.evidenceCount})`);

  console.log('\n--- ComplianceNarrator: signing + verify ---');
  const signed = new ComplianceNarrator({ signingKey: 'super-secret-key' });
  signed.ingestMany([
    { severity: 'critical', category: 'instruction_override', description: 'd', action: 'block', timestamp: 100 },
  ]);
  const sReport = await signed.narrate({ from: 0, to: 1000 });
  assert(typeof sReport.signature === 'string' && sReport.signature.length === 64,
    'signature is sha256 hex');
  assert(signed.verify(sReport) === true, 'verify accepts unmodified report');

  const tampered = JSON.parse(JSON.stringify(sReport));
  tampered.narrative = 'I forged this!';
  assert(signed.verify(tampered) === false, 'verify rejects tampered narrative');

  const tampered2 = JSON.parse(JSON.stringify(sReport));
  tampered2.summary.bySeverity.critical = 0;
  assert(signed.verify(tampered2) === false, 'verify rejects tampered counts');

  // Different key → can't verify
  const other = new ComplianceNarrator({ signingKey: 'different' });
  assert(other.verify(sReport) === false, 'wrong key fails verification');

  console.log('\n--- ComplianceNarrator: judge-augmented narrative ---');
  let judgePrompt = null;
  const judge = async ({ user }) => {
    judgePrompt = user;
    return '# Rewritten compliance narrative\nDuring the audit window, the system blocked 2 critical-severity incidents.';
  };
  const judged = new ComplianceNarrator({ judge });
  judged.ingest({ severity: 'critical', category: 'instruction_override', description: 'override', action: 'block', timestamp: 100 });
  const jReport = await judged.narrate({ from: 0, to: 1000 });
  assert(jReport.narrative.startsWith('# Rewritten'), 'judge-rewritten narrative used');
  assert(judgePrompt && judgePrompt.includes('SOC2'), 'judge prompt mentions framework');

  // Failing judge → falls back to deterministic narrative.
  const failJudge = async () => { throw new Error('quota'); };
  const judgedFail = new ComplianceNarrator({ judge: failJudge });
  judgedFail.ingest({ severity: 'high', category: 'data_exfiltration', description: 'd', action: 'block', timestamp: 100 });
  const fReport = await judgedFail.narrate({ from: 0, to: 1000 });
  assert(fReport.narrative.includes('SOC2 Compliance Narrative'),
    'failing judge → falls back to deterministic narrative');

  console.log('\n--- ComplianceNarrator: framework selection ---');
  const hipaa = new ComplianceNarrator({ framework: FRAMEWORKS.HIPAA });
  hipaa.ingest({ severity: 'high', category: 'pii_exposure', description: 'leaked SSN', action: 'block', timestamp: 100 });
  hipaa.ingest({ severity: 'high', category: 'instruction_override', description: 'irrelevant for HIPAA', action: 'block', timestamp: 200 });
  const hReport = await hipaa.narrate({ from: 0, to: 1000 });
  assert(hReport.framework === FRAMEWORKS.HIPAA, 'HIPAA framework');
  assert('164.312(a)(1)' in hReport.controls, 'HIPAA mapped pii_exposure → 164.312(a)(1)');
  assert(!('CC6.1' in hReport.controls), 'HIPAA report does NOT include SOC2 control IDs');

  const euai = new ComplianceNarrator({ framework: FRAMEWORKS.EU_AI_ACT });
  euai.ingest({ severity: 'critical', category: 'autonomous_jailbreak', description: 'd', action: 'block', timestamp: 100 });
  const eReport = await euai.narrate({ from: 0, to: 1000 });
  assert('Art.55' in eReport.controls, 'EU AI Act mapped autonomous_jailbreak → Art.55');

  console.log('\n--- ComplianceNarrator: empty window ---');
  const empty = new ComplianceNarrator();
  const emptyReport = await empty.narrate({ from: 0, to: 1 });
  assert(emptyReport.evidenceCount === 0, 'empty window → 0 evidence');
  assert(emptyReport.narrative.includes('No events mapped'),
    'empty window narrative includes "No events mapped"');

  console.log(`\n=== ${passed} passed, ${failed} failed ===`);
  if (failed > 0) process.exit(1);
})().catch((e) => { console.error(e); process.exit(1); });
