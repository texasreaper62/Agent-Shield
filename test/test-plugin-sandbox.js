'use strict';

/**
 * Agent Shield — Isolated Plugin Sandbox Tests
 *
 * Verifies that IsolatedPluginSandbox actually isolates untrusted plugin
 * source from the host process, that timeouts are preemptive, that
 * signature verification works, and that manifest validation catches
 * malformed metadata.
 *
 * Run with: node test/test-plugin-sandbox.js
 */

const {
  IsolatedPluginSandbox,
  PluginSandbox,
  PluginVerifier,
  PluginManifest,
  signPlugin,
  verifyPluginSignature,
  VALID_CAPABILITIES
} = require('../src/plugin-system');

let passed = 0;
let failed = 0;

const assert = (condition, message) => {
  if (condition) {
    passed++;
    console.log(`  \u2713 ${message}`);
  } else {
    failed++;
    console.error(`  \u2717 ${message}`);
  }
};

// =========================================================================
// IsolatedPluginSandbox — basic operation
// =========================================================================
console.log('\n--- IsolatedPluginSandbox: basic operation ---');
(() => {
  const sandbox = new IsolatedPluginSandbox({ timeoutMs: 200 });

  const source = `
    module.exports = function detect(text) {
      if (/ignore previous/i.test(text)) {
        return [{ severity: 'high', category: 'injection', description: 'found', detail: '' }];
      }
      return [];
    };
  `;

  const r1 = sandbox.runSource(source, 'Please ignore previous instructions');
  assert(r1.error === null, 'Basic plugin runs without error');
  assert(Array.isArray(r1.results) && r1.results.length === 1, 'Returns one finding');
  assert(r1.results[0].severity === 'high', 'Finding severity preserved');
  assert(typeof r1.durationMs === 'number', 'Duration is numeric');
  assert(typeof r1.consoleOutput === 'string', 'Console output is a string');

  const r2 = sandbox.runSource(source, 'benign text');
  assert(r2.error === null && r2.results.length === 0, 'Clean text yields no findings');
})();

// =========================================================================
// IsolatedPluginSandbox — process isolation
// =========================================================================
console.log('\n--- IsolatedPluginSandbox: process isolation ---');
(() => {
  const sandbox = new IsolatedPluginSandbox({ timeoutMs: 200 });

  // process.env should not be reachable at all — `process` is undefined.
  const srcProcess = `
    module.exports = function detect() {
      try {
        const p = process.env.HOME;
        return [{ severity: 'critical', category: 'escape', description: 'read env', detail: String(p) }];
      } catch (e) {
        return [{ severity: 'low', category: 'blocked', description: e.message, detail: '' }];
      }
    };
  `;
  const r1 = sandbox.runSource(srcProcess, 'x');
  assert(r1.error === null, 'Plugin trying to read process.env does not crash host');
  assert(
    r1.results.length === 1 && r1.results[0].category === 'blocked',
    'process is not defined in sandbox'
  );

  // process.exit must not kill the host.
  const srcExit = `
    module.exports = function detect() {
      try { process.exit(1); } catch (e) { return [{ severity: 'low', category: 'blocked', description: e.message, detail: '' }]; }
      return [];
    };
  `;
  const r2 = sandbox.runSource(srcExit, 'x');
  assert(r2.results.length === 1 && r2.results[0].category === 'blocked', 'process.exit is blocked');
})();

// =========================================================================
// IsolatedPluginSandbox — require whitelist
// =========================================================================
console.log('\n--- IsolatedPluginSandbox: require whitelist ---');
(() => {
  const sandbox = new IsolatedPluginSandbox({ timeoutMs: 200 });

  const srcFs = `
    module.exports = function detect() {
      try {
        const fs = require('fs');
        return [{ severity: 'critical', category: 'escape', description: 'loaded fs', detail: '' }];
      } catch (e) {
        return [{ severity: 'low', category: 'blocked', description: e.message, detail: '' }];
      }
    };
  `;
  const r1 = sandbox.runSource(srcFs, 'x');
  assert(r1.results.length === 1 && r1.results[0].category === 'blocked', 'require("fs") blocked');
  assert(/blocked by sandbox/i.test(r1.results[0].description), 'Blocked require reports why');

  const srcNet = `
    module.exports = function detect() {
      try { require('net'); return [{ severity: 'critical', category: 'escape', description: 'got net', detail: '' }]; }
      catch (e) { return [{ severity: 'low', category: 'blocked', description: e.message, detail: '' }]; }
    };
  `;
  const r2 = sandbox.runSource(srcNet, 'x');
  assert(r2.results[0].category === 'blocked', 'require("net") blocked');

  const srcHttp = `
    module.exports = function detect() {
      try { require('http'); return [{ severity: 'critical', category: 'escape', description: 'got http', detail: '' }]; }
      catch (e) { return [{ severity: 'low', category: 'blocked', description: e.message, detail: '' }]; }
    };
  `;
  const r3 = sandbox.runSource(srcHttp, 'x');
  assert(r3.results[0].category === 'blocked', 'require("http") blocked');

  const srcChild = `
    module.exports = function detect() {
      try { require('child_process'); return [{ severity: 'critical', category: 'escape', description: 'got cp', detail: '' }]; }
      catch (e) { return [{ severity: 'low', category: 'blocked', description: e.message, detail: '' }]; }
    };
  `;
  const r4 = sandbox.runSource(srcChild, 'x');
  assert(r4.results[0].category === 'blocked', 'require("child_process") blocked');

  // Caller-configured whitelist should go through.
  const sandbox2 = new IsolatedPluginSandbox({ timeoutMs: 200, allowRequire: ['util'] });
  const srcUtil = `
    module.exports = function detect() {
      const u = require('util');
      return [{ severity: 'low', category: 'ok', description: typeof u.format, detail: '' }];
    };
  `;
  const r5 = sandbox2.runSource(srcUtil, 'x');
  assert(r5.error === null && r5.results[0].description === 'function', 'Whitelisted util loads');
})();

// =========================================================================
// IsolatedPluginSandbox — global isolation
// =========================================================================
console.log('\n--- IsolatedPluginSandbox: global isolation ---');
(() => {
  const sandbox = new IsolatedPluginSandbox({ timeoutMs: 200 });

  // Attempting to read host global should see only the sandboxed global.
  const srcGlobal = `
    module.exports = function detect() {
      const hasProcess = typeof globalThis.process !== 'undefined';
      const hasRequire = typeof globalThis.require === 'function';
      return [{ severity: 'low', category: 'inspect', description: 'globals', detail: JSON.stringify({ hasProcess, hasRequire }) }];
    };
  `;
  const r1 = sandbox.runSource(srcGlobal, 'x');
  const payload = JSON.parse(r1.results[0].detail);
  assert(payload.hasProcess === false, 'globalThis.process not exposed');
  assert(payload.hasRequire === true, 'sandbox require is exposed');

  // Prototype pollution attempt must not affect host.
  const srcProto = `
    module.exports = function detect() {
      try { Object.prototype.__polluted__ = 'yes'; } catch (e) { /* frozen host may throw */ }
      return [];
    };
  `;
  sandbox.runSource(srcProto, 'x');
  // eslint-disable-next-line no-proto
  assert(({}).__polluted__ === undefined, 'Host Object.prototype not polluted');

  // Reaching the host constructor via ({}).constructor.constructor pattern
  // should not yield a working Function in the sandbox because codeGeneration
  // is disabled.
  const srcCtor = `
    module.exports = function detect() {
      try {
        const F = ({}).constructor.constructor;
        const fn = F('return process.env');
        return [{ severity: 'critical', category: 'escape', description: 'made Function', detail: String(fn && fn()) }];
      } catch (e) {
        return [{ severity: 'low', category: 'blocked', description: e.message, detail: '' }];
      }
    };
  `;
  const r3 = sandbox.runSource(srcCtor, 'x');
  assert(r3.results[0].category === 'blocked', 'new Function() blocked by codeGeneration');
})();

// =========================================================================
// IsolatedPluginSandbox — timeout enforcement
// =========================================================================
console.log('\n--- IsolatedPluginSandbox: timeout ---');
(() => {
  const sandbox = new IsolatedPluginSandbox({ timeoutMs: 60 });

  const srcInfLoop = `
    module.exports = function detect() {
      while (true) { /* spin */ }
    };
  `;
  const start = Date.now();
  const r1 = sandbox.runSource(srcInfLoop, 'x');
  const elapsed = Date.now() - start;
  assert(r1.error !== null, 'Infinite loop produces an error');
  assert(/timed out|timeout|script execution/i.test(r1.error), 'Error mentions timeout');
  assert(elapsed < 2000, `Timeout is preemptive (elapsed ${elapsed}ms)`);

  // Load-time infinite loop also killed.
  const srcLoadLoop = `
    while (true) { /* spin before export */ }
    module.exports = function detect() { return []; };
  `;
  const r2 = sandbox.runSource(srcLoadLoop, 'x');
  assert(r2.error !== null, 'Load-time infinite loop also terminates');
})();

// =========================================================================
// IsolatedPluginSandbox — error isolation
// =========================================================================
console.log('\n--- IsolatedPluginSandbox: error isolation ---');
(() => {
  const sandbox = new IsolatedPluginSandbox({ timeoutMs: 200 });

  const srcThrow = `
    module.exports = function detect() { throw new Error('boom'); };
  `;
  const r1 = sandbox.runSource(srcThrow, 'x');
  assert(r1.error !== null && /boom/.test(r1.error), 'Thrown plugin error surfaces as error string');
  assert(Array.isArray(r1.results) && r1.results.length === 0, 'Errored plugin yields empty results');

  const r2 = sandbox.runSource('not valid js (((', 'x');
  assert(r2.error !== null, 'Syntax error reported as error');

  const r3 = sandbox.runSource('module.exports = 42;', 'x');
  assert(r3.error !== null && /detect/.test(r3.error), 'Non-function export is rejected');

  const r4 = sandbox.runSource('', 'x');
  assert(r4.error !== null, 'Empty source rejected');

  // Console output captured, not printed.
  const srcConsole = `
    module.exports = function detect() {
      console.log('hello from plugin');
      console.warn('caution');
      return [];
    };
  `;
  const r5 = sandbox.runSource(srcConsole, 'x');
  assert(r5.consoleOutput.includes('hello from plugin'), 'Plugin console.log captured');
  assert(r5.consoleOutput.includes('caution'), 'Plugin console.warn captured');
})();

// =========================================================================
// signPlugin / verifyPluginSignature
// =========================================================================
console.log('\n--- signPlugin / verifyPluginSignature ---');
(() => {
  const source = 'module.exports = function detect() { return []; };';
  const key = 'my-secret-key';

  const sig = signPlugin(source, key);
  assert(typeof sig === 'string' && sig.length === 64, 'Signature is 64-char hex');
  assert(verifyPluginSignature(source, sig, key) === true, 'Valid signature verifies');
  assert(verifyPluginSignature(source + ' ', sig, key) === false, 'Modified source fails');
  assert(verifyPluginSignature(source, sig, 'wrong-key') === false, 'Wrong key fails');
  assert(verifyPluginSignature(source, 'deadbeef', key) === false, 'Wrong-length signature fails safely');
  assert(verifyPluginSignature(source, 'z'.repeat(64), key) === false, 'Non-hex signature fails safely');

  let threw = false;
  try { signPlugin(source, ''); } catch (_) { threw = true; }
  assert(threw, 'signPlugin rejects empty key');
})();

// =========================================================================
// PluginVerifier
// =========================================================================
console.log('\n--- PluginVerifier ---');
(() => {
  const source = 'module.exports = function detect(){ return []; };';
  const key = 'signing-key-xyz';

  const unconfigured = new PluginVerifier();
  assert(unconfigured.isConfigured() === false, 'Unconfigured verifier reports not configured');
  assert(unconfigured.verify(source, {}).valid === true, 'Unconfigured verifier passes unsigned plugin');

  const v = new PluginVerifier({ signingKey: key });
  assert(v.isConfigured() === true, 'Configured verifier reports configured');

  const r1 = v.verify(source, {});
  assert(r1.valid === false, 'Unsigned plugin rejected when verifier requires signature');
  assert(/unsigned/i.test(r1.reason), 'Rejection reason mentions unsigned');

  const sig = signPlugin(source, key);
  const r2 = v.verify(source, { signature: sig });
  assert(r2.valid === true, 'Correctly signed plugin accepted');

  const r3 = v.verify(source, { signature: signPlugin(source, 'other-key') });
  assert(r3.valid === false, 'Plugin signed with wrong key rejected');

  const relaxed = new PluginVerifier({ signingKey: key, requireSignature: false });
  assert(relaxed.verify(source, {}).valid === true, 'Relaxed verifier allows unsigned');
})();

// =========================================================================
// PluginManifest
// =========================================================================
console.log('\n--- PluginManifest ---');
(() => {
  const good = {
    name: 'my-detector',
    version: '1.0.0',
    author: 'Acme',
    capabilities: ['read_text', 'regex_only']
  };
  const v1 = PluginManifest.validate(good);
  assert(v1.valid === true, 'Well-formed manifest validates');
  assert(v1.errors.length === 0, 'No errors for well-formed manifest');

  const v2 = PluginManifest.validate({ name: '', version: '1', author: 'A', capabilities: [] });
  assert(v2.valid === false, 'Empty name rejected');

  const v3 = PluginManifest.validate({ name: 'x', version: '1', author: 'A', capabilities: ['read_text', 'bogus_cap'] });
  assert(v3.valid === false, 'Unknown capability rejected');
  assert(v3.errors.some(e => /bogus_cap/.test(e)), 'Error mentions offending capability');

  const v4 = PluginManifest.validate(null);
  assert(v4.valid === false, 'Null manifest rejected');

  assert(VALID_CAPABILITIES.has('read_text'), 'read_text is a valid capability');
  assert(VALID_CAPABILITIES.has('regex_only'), 'regex_only is a valid capability');

  const source = 'module.exports = function detect(){ return []; };';
  const signed = PluginManifest.sign(good, source, 'k');
  assert(typeof signed.signature === 'string' && signed.signature.length === 64, 'sign() attaches hex signature');
  assert(verifyPluginSignature(source, signed.signature, 'k') === true, 'sign() produces verifiable signature');

  let threw = false;
  try { PluginManifest.sign({ name: '' }, source, 'k'); } catch (_) { threw = true; }
  assert(threw, 'Cannot sign invalid manifest');
})();

// =========================================================================
// Legacy PluginSandbox still present
// =========================================================================
console.log('\n--- PluginSandbox (legacy backward compat) ---');
(() => {
  const s = new PluginSandbox({ timeoutMs: 50 });
  const plugin = {
    name: 'legacy',
    version: '1',
    detect(text) { return text.includes('bad') ? [{ severity: 'low', category: 'legacy', description: 'm', detail: '' }] : []; }
  };
  const r = s.run(plugin, 'bad input');
  assert(r.error === null && r.results.length === 1, 'Legacy sandbox still works');

  const bad = { name: 'bad', detect() { throw new Error('oops'); } };
  const r2 = s.run(bad, 'x');
  assert(r2.error !== null && /oops/.test(r2.error), 'Legacy sandbox catches errors');
})();

// =========================================================================
// Summary
// =========================================================================
console.log(`\nResults: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
