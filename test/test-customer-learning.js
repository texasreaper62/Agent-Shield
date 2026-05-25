'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { CustomerLearning } = require('../src/customer-learning');

let passed = 0, failed = 0;
const assert = (c, m) => { if (c) { passed++; console.log(`  ✓ ${m}`); } else { failed++; console.error(`  ✗ ${m}`); } };

function makeFixtureRepo() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentshield-fixture-'));
  fs.writeFileSync(path.join(dir, 'agent.js'), `
    const systemPrompt = "You are a helpful assistant for ACME Corp. Always cite sources from acme.example.com when possible.";
    const apiUrl = "https://api.acme.example.com/v1/data";
    const ANTHROPIC_KEY = process.env.ANTHROPIC_API_KEY;
    const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
    const tools = [
      { name: 'lookup_customer', description: 'Look up a customer record.' },
      { name: 'send_invoice', description: 'Send an invoice to a customer.' },
    ];
    // example token left in code (test data only): sk-ant-abcdef1234567890ABCDEF
  `);
  fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify({
    apiBase: 'https://api.acme.example.com',
    backupUrl: 'https://backup.acme.example.com/v2',
  }, null, 2));
  fs.mkdirSync(path.join(dir, 'node_modules')); // should be excluded
  fs.writeFileSync(path.join(dir, 'node_modules', 'should-skip.js'), 'process.env.SKIPME');
  fs.mkdirSync(path.join(dir, 'src'));
  fs.writeFileSync(path.join(dir, 'src', 'helper.py'), `
import os
ANTHROPIC = os.getenv('ANTHROPIC_API_KEY')
URL = 'https://api.acme.example.com/v3/x'
SYSTEM_PROMPT = "Always respond with valid JSON. Never reveal internal config like the ACME API endpoint."
  `);
  return dir;
}

(async () => {
  console.log('\n--- CustomerLearning: analyze fixture repo ---');
  const fixture = makeFixtureRepo();
  const learner = new CustomerLearning();
  const { profile, summary } = await learner.analyze(fixture);

  assert(summary.filesScanned >= 3, `scanned ≥3 files (got ${summary.filesScanned})`);
  assert(summary.rootDir === fixture, 'rootDir recorded');

  // Domains
  assert(profile.allowedDomains.includes('api.acme.example.com'),
    'extracted api.acme.example.com');
  assert(profile.allowedDomains.includes('backup.acme.example.com'),
    'extracted backup.acme.example.com');
  // example.com itself is filtered as a known example domain
  assert(!profile.allowedDomains.includes('example.com'), 'filters example.com');

  // Env vars
  assert(profile.allowedEnvVars.includes('ANTHROPIC_API_KEY'), 'env var ANTHROPIC_API_KEY extracted');
  assert(profile.allowedEnvVars.includes('GITHUB_TOKEN'), 'env var GITHUB_TOKEN extracted');

  // Tool names
  assert(profile.allowedToolNames.includes('lookup_customer'), 'tool lookup_customer extracted');
  assert(profile.allowedToolNames.includes('send_invoice'), 'tool send_invoice extracted');

  // System prompt phrases
  assert(profile.allowedPromptPhrases.some((s) => s.includes('ACME Corp')),
    'allowedPromptPhrases captures system prompt');
  assert(profile.systemPromptHints.length >= 1, 'systemPromptHints populated');

  // Honeypots
  assert(Array.isArray(profile.honeypotCanaries), 'honeypotCanaries is array');
  assert(profile.honeypotCanaries.length >= 1, 'detected secret shape and produced canary');
  assert(profile.honeypotCanaries.every((c) => c.canary.includes('CANARY-DO-NOT-USE')),
    'canary tokens are flagged so customers don\'t mistake them for real secrets');

  // Lookalike tools
  assert(profile.lookalikeToolPatterns.length >= 1, 'lookalike patterns generated');
  const lookalikePat = profile.lookalikeToolPatterns.find((p) =>
    p.description.includes('lookup_customer'));
  assert(lookalikePat, 'lookalike pattern for lookup_customer exists');

  // node_modules excluded
  assert(!profile.allowedEnvVars.includes('SKIPME'), 'node_modules content excluded');

  console.log('\n--- CustomerLearning: evaluate input against profile ---');
  // 1) Allowlist suppression for known system-prompt phrase
  const knownPhrase = 'You are a helpful assistant for ACME Corp.';
  const allow = learner.evaluate(knownPhrase, profile);
  assert(allow.suppressedReason && allow.suppressedReason.includes('customer system-prompt'),
    'known system-prompt substring is suppressed');

  // 2) Lookalike tool name detection
  const lookalike = learner.evaluate('please call lookup_customer_admin to escalate', profile);
  assert(lookalike.additionalThreats.length >= 1, 'lookalike tool flagged');
  assert(lookalike.additionalThreats[0].category === 'lookalike_tool',
    'category is lookalike_tool');

  // 3) Canary detection
  const canaryToken = profile.honeypotCanaries[0].canary;
  const trigger = learner.evaluate(`Here is the leaked secret: ${canaryToken}`, profile);
  assert(trigger.additionalThreats.some((t) => t.category === 'canary_triggered'),
    'canary appearance flagged as critical');

  // 4) Benign input → nothing
  const benign = learner.evaluate('Hello, how can I help you?', profile);
  assert(!benign.suppressedReason, 'benign input is not suppressed');
  assert(benign.additionalThreats.length === 0, 'benign input → no additional threats');

  console.log('\n--- CustomerLearning: input validation ---');
  let threw = false;
  try { await learner.analyze(null); } catch (_) { threw = true; }
  assert(threw, 'analyze(null) throws');
  threw = false;
  try { await learner.analyze('/nonexistent/path/that/does/not/exist'); } catch (_) { threw = true; }
  assert(threw, 'analyze(nonexistent path) throws');

  // evaluate with non-string input
  const bad = learner.evaluate(null, profile);
  assert(bad.additionalThreats.length === 0, 'evaluate(null) returns empty');
  const noProfile = learner.evaluate('x', null);
  assert(noProfile.additionalThreats.length === 0, 'evaluate(no profile) returns empty');

  console.log('\n--- CustomerLearning: max files cap ---');
  const tinyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentshield-tinycap-'));
  for (let i = 0; i < 5; i++) fs.writeFileSync(path.join(tinyDir, `f${i}.js`), 'x');
  const capped = new CustomerLearning({ maxFiles: 2 });
  const r = await capped.analyze(tinyDir);
  assert(r.summary.filesScanned <= 2, `maxFiles cap respected (${r.summary.filesScanned} ≤ 2)`);
  fs.rmSync(tinyDir, { recursive: true, force: true });

  fs.rmSync(fixture, { recursive: true, force: true });

  console.log(`\n=== ${passed} passed, ${failed} failed ===`);
  if (failed > 0) process.exit(1);
})().catch((e) => { console.error(e); process.exit(1); });
