'use strict';

const path = require('path');
const fs = require('fs');
const os = require('os');
const { DreamMemory } = require('../src/dreams');
const { DreamPRBot } = require('../src/dream-pr-bot');

let passed = 0, failed = 0;
const assert = (c, m) => { if (c) { passed++; console.log(`  ✓ ${m}`); } else { failed++; console.error(`  ✗ ${m}`); } };

(async () => {
  console.log('\n--- DreamPRBot: dry-run with no artifact ---');
  const empty = new DreamPRBot({ memory: new DreamMemory() });
  const e = await empty.propose();
  assert(e.proposed === false, 'empty memory → no proposal');
  assert(e.reason && e.reason.includes('confidence'), 'reason mentions confidence threshold');

  console.log('\n--- DreamPRBot: dry-run with change-request artifact ---');
  const mem = new DreamMemory();
  mem.saveArtifact('change-request', {
    title: '[dream] add 2 pattern(s); retune thresholds (Δ F1 +0.040)',
    proposedPatterns: [
      { category: 'novel_one', severity: 'high', regexSource: 'novel.+pattern', description: 'd1', fpRate: 0.02 },
      { category: 'novel_two', severity: 'medium', regexSource: 'another', description: 'd2', fpRate: 0.0 },
    ],
    thresholdProposal: { thresholds: { instruction_override: 55 }, delta: 0.04 },
    incidentClusters: [
      { key: 'false_negative::role_hijack', count: 4 },
      { key: 'false_positive::path_traversal', count: 2 },
    ],
    shadowDrift: { added: [{ cat: 'novel_one', count: 5 }] },
    generatedAt: Date.now(),
  }, { confidence: 0.92 });

  const bot = new DreamPRBot({ memory: mem });
  const r = await bot.propose();
  assert(r.proposed === true, 'proposal returned');
  assert(r.dryRun === true, 'dryRun flag set in default mode');
  assert(r.branch.startsWith('dream/auto/'), `branch under default prefix (${r.branch})`);
  assert(r.title.startsWith('[dream]'), 'title preserved from artifact');
  assert(r.body.includes('Proposed detection patterns'), 'body includes patterns section');
  assert(r.body.includes('Threshold retune'), 'body includes thresholds section');
  assert(r.body.includes('Incident clusters'), 'body includes incident clusters');
  assert(r.body.includes('Shadow-mode drift'), 'body includes shadow drift');
  assert(r.body.includes('draft by default'), 'body notes draft default');
  assert(Array.isArray(r.files) && r.files.length === 2, '2 file artifacts emitted');
  assert(r.files.every((f) => f.path && f.bytes > 0), 'each file has path + bytes');

  console.log('\n--- DreamPRBot: confidence gating ---');
  const lowConfBot = new DreamPRBot({ memory: mem, minConfidence: 0.99 });
  const skipped = await lowConfBot.propose();
  assert(skipped.proposed === false, 'confidence below threshold → no proposal');

  console.log('\n--- DreamPRBot: local-git mode commits the patches ---');
  const tmpRepo = fs.mkdtempSync(path.join(os.tmpdir(), 'dreambot-'));
  // The git runner doesn't have to be real git; we just record what was called.
  const gitCalls = [];
  const fakeGit = async (args) => { gitCalls.push(args); return ''; };
  const localBot = new DreamPRBot({
    memory: mem,
    mode: 'local-git',
    repoRoot: tmpRepo,
    artifactDir: path.join(tmpRepo, 'config', 'dreams'),
    gitRunner: fakeGit,
  });
  const lr = await localBot.propose();
  assert(lr.proposed === true && lr.applied && lr.applied.committed, 'local-git applied + committed');
  assert(gitCalls.some((c) => c[0] === 'checkout' && c[1] === '-b'), 'git checkout -b called');
  assert(gitCalls.some((c) => c[0] === 'commit'), 'git commit called');
  // The artifact files should exist on disk.
  const patchesPath = path.join(tmpRepo, 'config', 'dreams', 'dream-patches.json');
  const thresholdsPath = path.join(tmpRepo, 'config', 'dreams', 'dream-thresholds.json');
  assert(fs.existsSync(patchesPath), 'dream-patches.json written');
  assert(fs.existsSync(thresholdsPath), 'dream-thresholds.json written');
  const parsedPatches = JSON.parse(fs.readFileSync(patchesPath, 'utf8'));
  assert(parsedPatches.patterns.length === 2, 'patches file has both patterns');
  const parsedThresholds = JSON.parse(fs.readFileSync(thresholdsPath, 'utf8'));
  assert(parsedThresholds.thresholds.instruction_override === 55, 'thresholds file correct');
  fs.rmSync(tmpRepo, { recursive: true, force: true });

  console.log('\n--- DreamPRBot: local-git requires gitRunner ---');
  let threw = false;
  try {
    const bad = new DreamPRBot({ memory: mem, mode: 'local-git', repoRoot: '/tmp' });
    await bad.propose();
  } catch (_) { threw = true; }
  assert(threw, 'local-git without gitRunner throws on propose()');

  console.log('\n--- DreamPRBot: mcp-github mode calls adapter ---');
  const adapterCalls = { createBranch: 0, putFile: 0, openPR: 0 };
  const adapter = {
    createBranch: async (a) => { adapterCalls.createBranch++; return a.branch; },
    putFile: async () => { adapterCalls.putFile++; },
    openPR: async (a) => { adapterCalls.openPR++; return `https://github.com/x/y/pull/123?branch=${a.branch}`; },
  };
  const mcpBot = new DreamPRBot({ memory: mem, mode: 'mcp-github', mcpAdapter: adapter });
  const mr = await mcpBot.propose();
  assert(mr.proposed === true, 'mcp-github proposed');
  assert(adapterCalls.createBranch === 1, 'createBranch called once');
  assert(adapterCalls.putFile === 2, 'putFile called once per file');
  assert(adapterCalls.openPR === 1, 'openPR called once');
  assert(mr.prUrl && mr.prUrl.includes('pull/123'), 'PR URL returned');

  console.log('\n--- DreamPRBot: mcp-github mode validates adapter shape ---');
  threw = false;
  try {
    const bad = new DreamPRBot({ memory: mem, mode: 'mcp-github' });
    await bad.propose();
  } catch (_) { threw = true; }
  assert(threw, 'mcp-github without adapter throws');
  threw = false;
  try {
    const bad = new DreamPRBot({ memory: mem, mode: 'mcp-github', mcpAdapter: { createBranch: () => {} } });
    await bad.propose();
  } catch (_) { threw = true; }
  assert(threw, 'mcp-github with incomplete adapter throws');

  console.log('\n--- DreamPRBot: input validation ---');
  threw = false;
  try { new DreamPRBot({}); } catch (_) { threw = true; }
  assert(threw, 'constructor without memory throws');
  threw = false;
  try { new DreamPRBot({ memory: mem, mode: 'banana' }); } catch (_) { threw = true; }
  assert(threw, 'unknown mode throws');

  console.log('\n--- DreamPRBot: stats ---');
  assert(bot.stats().proposalsMade >= 1, 'stats.proposalsMade incremented');
  assert(bot.stats().mode === 'dry-run', 'stats.mode reports configured mode');

  console.log(`\n=== ${passed} passed, ${failed} failed ===`);
  if (failed > 0) process.exit(1);
})().catch((e) => { console.error(e); process.exit(1); });
