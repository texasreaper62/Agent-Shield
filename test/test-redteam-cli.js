'use strict';

/**
 * Agent Shield — Red Team CLI Tests
 *
 * Run with: node test/test-redteam-cli.js
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { RedTeamCLI, REDTEAM_MODES, ATTACK_CORPUS } = require('../src/redteam-cli');

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
// Constants
// =========================================================================

console.log('\n--- Constants ---');

(() => {
  assert(REDTEAM_MODES.quick === 50, 'Quick mode is 50 attacks');
  assert(REDTEAM_MODES.standard === 200, 'Standard mode is 200 attacks');
  assert(REDTEAM_MODES.full === 617, 'Full mode is 617 attacks');

  assert(typeof ATTACK_CORPUS === 'object', 'ATTACK_CORPUS exported');
  const categories = Object.keys(ATTACK_CORPUS);
  assert(categories.length >= 8, 'At least 8 attack categories');
  assert(categories.includes('goal_hijack'), 'Has goal_hijack category');
  assert(categories.includes('tool_misuse'), 'Has tool_misuse category');
  assert(categories.includes('supply_chain'), 'Has supply_chain category');
  assert(categories.includes('rogue_agent'), 'Has rogue_agent category');

  const totalPayloads = Object.values(ATTACK_CORPUS).reduce((s, arr) => s + arr.length, 0);
  assert(totalPayloads >= 50, `At least 50 attack payloads in corpus (got ${totalPayloads})`);
})();

// =========================================================================
// Quick mode
// =========================================================================

console.log('\n--- Quick Mode ---');

(() => {
  const cli = new RedTeamCLI();
  const report = cli.run('https://example.com/agent', { mode: 'quick' });

  assert(report.endpoint === 'https://example.com/agent', 'Endpoint captured');
  assert(report.mode === 'quick', 'Mode is quick');
  assert(report.attackCount === 50, 'Quick mode runs 50 attacks');
  assert(typeof report.blocked === 'number', 'Blocked count is number');
  assert(typeof report.missed === 'number', 'Missed count is number');
  assert(report.blocked + report.missed === report.attackCount, 'Blocked + missed = total');
  assert(typeof report.score === 'number' && report.score >= 0 && report.score <= 100, 'Score is 0-100');
  assert(['A+', 'A', 'A-', 'B', 'C', 'D', 'F'].includes(report.grade), 'Grade is valid');
  assert(typeof report.generatedAt === 'number', 'Has timestamp');
})();

// =========================================================================
// Standard mode
// =========================================================================

console.log('\n--- Standard Mode ---');

(() => {
  const cli = new RedTeamCLI();
  const report = cli.run('https://example.com/agent', { mode: 'standard' });

  assert(report.attackCount === 200, 'Standard mode runs 200 attacks');
  assert(report.blocked > 0, 'Some attacks blocked (detector-core catches real payloads)');
})();

// =========================================================================
// Full mode
// =========================================================================

console.log('\n--- Full Mode ---');

(() => {
  const cli = new RedTeamCLI();
  const report = cli.run('https://example.com/agent', { mode: 'full' });

  assert(report.attackCount === 617, 'Full mode runs 617 attacks');
  assert(report.blocked > 0, 'Some attacks blocked in full mode');
})();

// =========================================================================
// Category results
// =========================================================================

console.log('\n--- Category Results ---');

(() => {
  const cli = new RedTeamCLI();
  const report = cli.run('https://example.com/agent', { mode: 'standard' });

  assert(typeof report.categoryResults === 'object', 'Has categoryResults');
  const categories = Object.keys(report.categoryResults);
  assert(categories.length >= 5, 'Multiple categories tracked');
  for (const cat of categories) {
    const data = report.categoryResults[cat];
    assert(typeof data.total === 'number', `${cat} has total`);
    assert(typeof data.blocked === 'number', `${cat} has blocked`);
    assert(typeof data.missed === 'number', `${cat} has missed`);
    assert(data.blocked + data.missed === data.total, `${cat} blocked+missed=total`);
  }
})();

// =========================================================================
// Real attack detection
// =========================================================================

console.log('\n--- Real Attack Detection ---');

(() => {
  const cli = new RedTeamCLI();
  const report = cli.run('https://example.com/agent', { mode: 'quick' });

  // The results should contain individual attack results
  assert(Array.isArray(report.results), 'Results is an array');
  assert(report.results.length === 50, 'Quick mode has 50 results');
  assert(report.results[0].id === 'attack-1', 'First result has id');
  assert(typeof report.results[0].category === 'string', 'Results have category');
  assert(typeof report.results[0].blocked === 'boolean', 'Results have blocked flag');
})();

// =========================================================================
// Compare mode
// =========================================================================

console.log('\n--- Compare Mode ---');

(() => {
  const cli = new RedTeamCLI();
  const baseline = cli.run('https://example.com/agent', { mode: 'quick' });
  const current = cli.run('https://example.com/agent', { mode: 'quick', compareWith: baseline });

  assert(current.compare !== undefined, 'Compare section present');
  assert(typeof current.compare.baselineScore === 'number', 'Compare has baseline score');
  assert(typeof current.compare.delta === 'number', 'Compare has delta');
  assert(typeof current.compare.improved === 'boolean', 'Compare has improved flag');
})();

// =========================================================================
// Supply chain integration
// =========================================================================

console.log('\n--- Supply Chain Integration ---');

(() => {
  const cli = new RedTeamCLI();
  const report = cli.run('https://example.com/agent', {
    mode: 'quick',
    serverName: 'mcp-remote',
    tools: [{ name: 'getSecrets', description: 'safe tool', permissions: ['*'], inputSchema: {} }]
  });

  assert(report.supplyChain !== undefined, 'Supply chain section present');
  assert(report.supplyChain.status !== undefined, 'Supply chain has status');
})();

// =========================================================================
// Report writing
// =========================================================================

console.log('\n--- Report Writing ---');

(() => {
  const cli = new RedTeamCLI();
  const report = cli.run('https://example.com/agent', { mode: 'quick' });

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentshield-'));
  const files = cli.writeReports(report, tmpDir);

  assert(fs.existsSync(files.jsonPath), 'JSON report file created');
  assert(fs.existsSync(files.mdPath), 'Markdown report file created');
  assert(fs.existsSync(files.htmlPath), 'HTML report file created');

  // Verify JSON content
  const jsonContent = JSON.parse(fs.readFileSync(files.jsonPath, 'utf8'));
  assert(jsonContent.endpoint === 'https://example.com/agent', 'JSON has correct endpoint');
  assert(jsonContent.grade !== undefined, 'JSON has grade');

  // Verify Markdown content
  const mdContent = fs.readFileSync(files.mdPath, 'utf8');
  assert(mdContent.includes('Red Team Audit'), 'Markdown has title');
  assert(mdContent.includes('Grade'), 'Markdown has grade');
  assert(mdContent.includes('Category Results'), 'Markdown has category section');

  // Verify HTML content
  const htmlContent = fs.readFileSync(files.htmlPath, 'utf8');
  assert(htmlContent.includes('<!DOCTYPE html>'), 'HTML is valid document');
  assert(htmlContent.includes('Agent Shield'), 'HTML has Agent Shield');

  // Cleanup
  fs.rmSync(tmpDir, { recursive: true, force: true });
})();

// =========================================================================
// Markdown and HTML formatters
// =========================================================================

console.log('\n--- Report Formatters ---');

(() => {
  const cli = new RedTeamCLI();
  const report = cli.run('https://example.com/agent', { mode: 'quick' });

  const md = cli.toMarkdown(report);
  assert(typeof md === 'string', 'toMarkdown returns string');
  assert(md.includes('Endpoint'), 'Markdown has endpoint');
  assert(md.includes('Supply Chain'), 'Markdown has supply chain section');

  const html = cli.toHTML(report);
  assert(typeof html === 'string', 'toHTML returns string');
  assert(html.includes('<html'), 'HTML has html tag');
  assert(html.includes(report.grade), 'HTML has grade');
})();

// =========================================================================
// Micro-model integration
// =========================================================================

console.log('\n--- Micro-Model Integration ---');

(() => {
  const cli = new RedTeamCLI();
  // Micro-model is enabled by default — should catch more attacks
  const report = cli.run('https://example.com/agent', { mode: 'quick' });
  assert(report.blocked > 0, 'Micro-model + detector-core catches attacks');

  // Compare: with micro-model should catch >= without
  const cliNoModel = new RedTeamCLI({ enableMicroModel: false });
  const reportNoModel = cliNoModel.run('https://example.com/agent', { mode: 'quick' });
  assert(report.blocked >= reportNoModel.blocked, 'Micro-model catches at least as many as detector-core alone');
})();

// =========================================================================
// Error handling
// =========================================================================

console.log('\n--- Error Handling ---');

(() => {
  const cli = new RedTeamCLI();
  let threw = false;
  try {
    cli.run(null);
  } catch (e) {
    threw = true;
    assert(e.message.includes('endpoint is required'), 'Error mentions endpoint');
  }
  assert(threw, 'Throws on missing endpoint');
})();

// =========================================================================
// Summary
// =========================================================================

console.log(`\n${'='.repeat(50)}`);
console.log(`Red Team CLI Tests: ${passed} passed, ${failed} failed`);
console.log(`${'='.repeat(50)}\n`);

if (failed > 0) {
  process.exit(1);
}
