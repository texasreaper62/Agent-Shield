'use strict';

/**
 * Agent Shield — Side Channel Monitor Tests
 *
 * Run with: node test/test-side-channel.js
 */

const { SideChannelMonitor, BeaconDetector, EntropyAnalyzer } = require('../src/side-channel-monitor');

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
// EntropyAnalyzer
// =========================================================================

console.log('\n--- EntropyAnalyzer ---');

(() => {
  const ea = new EntropyAnalyzer();

  // Shannon entropy of empty/null
  assert(ea.calculate('') === 0, 'Entropy of empty string is 0');
  assert(ea.calculate(null) === 0, 'Entropy of null is 0');

  // Entropy of single repeated char
  assert(ea.calculate('aaaaaaa') === 0, 'Entropy of repeated char is 0');

  // Entropy of two equally distributed chars
  const e2 = ea.calculate('abababab');
  assert(Math.abs(e2 - 1.0) < 0.01, `Entropy of "abababab" ~ 1.0 (got ${e2.toFixed(3)})`);

  // Entropy of high-randomness base64 string
  const highEntropy = ea.calculate('aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q=');
  assert(highEntropy > 4.0, `Base64 string has high entropy (got ${highEntropy.toFixed(2)})`);

  // Entropy of normal English word
  const lowEntropy = ea.calculate('hello');
  assert(lowEntropy < 3.0, `Normal word "hello" has low entropy (got ${lowEntropy.toFixed(2)})`);

  // isEncoded
  assert(ea.isEncoded('aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q=') === true, 'Base64 string detected as encoded');
  assert(ea.isEncoded('hello') === false, 'Normal word not detected as encoded');
  assert(ea.isEncoded('') === false, 'Empty string not detected as encoded');
  assert(ea.isEncoded(null) === false, 'Null not detected as encoded');

  // detectEncoding — base64
  const b64 = ea.detectEncoding('aGVsbG8gd29ybGQ=');
  assert(b64.encoding === 'base64', `Base64 detected (got ${b64.encoding})`);
  assert(b64.confidence > 0.5, `Base64 confidence > 0.5 (got ${b64.confidence})`);

  // detectEncoding — hex
  const hex = ea.detectEncoding('48656c6c6f576f726c64');
  assert(hex.encoding === 'hex', `Hex detected (got ${hex.encoding})`);
  assert(hex.confidence > 0.5, `Hex confidence > 0.5 (got ${hex.confidence})`);

  // detectEncoding — binary
  const bin = ea.detectEncoding('01010101001101010101');
  assert(bin.encoding === 'binary', `Binary detected (got ${bin.encoding})`);

  // detectEncoding — plaintext
  const plain = ea.detectEncoding('hello world');
  assert(plain.encoding === 'plaintext', `Plaintext detected (got ${plain.encoding})`);

  // detectEncoding — empty
  const empty = ea.detectEncoding('');
  assert(empty.encoding === 'plaintext', 'Empty string is plaintext');
})();

// =========================================================================
// BeaconDetector
// =========================================================================

console.log('\n--- BeaconDetector ---');

(() => {
  // Regular beaconing — events every 1000ms with tiny jitter
  const bd = new BeaconDetector();
  const base = 1000000;
  for (let i = 0; i < 10; i++) {
    bd.addEvent(base + i * 1000 + (Math.random() * 20 - 10));
  }
  const beacon = bd.detectBeaconing();
  assert(beacon.beaconing === true, 'Regular intervals detected as beaconing');
  assert(beacon.interval !== null && beacon.interval > 900 && beacon.interval < 1100, `Beacon interval ~ 1000ms (got ${beacon.interval})`);
  assert(beacon.confidence > 0.5, `Beacon confidence > 0.5 (got ${beacon.confidence})`);

  // Irregular timestamps — not beaconing
  const bd2 = new BeaconDetector();
  bd2.addEvent(0);
  bd2.addEvent(100);
  bd2.addEvent(5000);
  bd2.addEvent(5050);
  bd2.addEvent(20000);
  bd2.addEvent(20100);
  bd2.addEvent(55000);
  const irregular = bd2.detectBeaconing();
  assert(irregular.beaconing === false, 'Irregular timestamps not flagged as beaconing');

  // Too few events
  const bd3 = new BeaconDetector();
  bd3.addEvent(100);
  bd3.addEvent(200);
  const tooFew = bd3.detectBeaconing();
  assert(tooFew.beaconing === false, 'Too few events returns no beaconing');
  assert(tooFew.interval === null, 'Too few events returns null interval');
  assert(tooFew.confidence === 0, 'Too few events returns 0 confidence');
})();

// =========================================================================
// SideChannelMonitor — DNS
// =========================================================================

console.log('\n--- SideChannelMonitor: DNS ---');

(() => {
  const m = new SideChannelMonitor();

  // Clean domain — not flagged
  const clean = m.analyzeDNSQuery('www.example.com');
  assert(clean.exfiltration === false, 'Clean domain not flagged');
  assert(clean.channel === 'dns', 'Channel is dns');

  // High-entropy subdomain
  const exfil1 = m.analyzeDNSQuery('aGVsbG8gd29ybGQ.attacker.com');
  assert(exfil1.exfiltration === true, 'High-entropy/base64 subdomain detected');
  assert(exfil1.evidence.length > 0, 'Evidence provided for DNS exfil');

  // Known exfil service domain
  const exfil2 = m.analyzeDNSQuery('data.burpcollaborator.net');
  assert(exfil2.exfiltration === true, 'Known exfil domain detected');
  assert(exfil2.severity === 'critical', 'Known exfil domain is critical severity');

  // Hex-encoded subdomain
  const exfil3 = m.analyzeDNSQuery('48656c6c6f576f726c6448656c6c6f.evil.com');
  assert(exfil3.exfiltration === true, 'Hex-encoded DNS subdomain detected');

  // Null / empty domain
  const nullResult = m.analyzeDNSQuery(null);
  assert(nullResult.exfiltration === false, 'Null domain not flagged');
  const emptyResult = m.analyzeDNSQuery('');
  assert(emptyResult.exfiltration === false, 'Empty domain not flagged');
})();

// =========================================================================
// SideChannelMonitor — Timing
// =========================================================================

console.log('\n--- SideChannelMonitor: Timing ---');

(() => {
  const m = new SideChannelMonitor();

  // Fixed-interval beaconing pattern
  const beaconTimestamps = [];
  for (let i = 0; i < 10; i++) {
    beaconTimestamps.push(i * 500);
  }
  const timing1 = m.analyzeTimingPattern(beaconTimestamps);
  assert(timing1.exfiltration === true, 'Fixed-interval timing detected');
  assert(timing1.channel === 'timing', 'Channel is timing');

  // Binary encoding: alternating 100ms and 300ms intervals
  const binaryTimestamps = [0, 100, 400, 500, 800, 900, 1200, 1300, 1600];
  const timing2 = m.analyzeTimingPattern(binaryTimestamps);
  assert(timing2.exfiltration === true, 'Binary timing pattern detected');

  // Random/irregular timestamps — should not flag
  const randomTimestamps = [0, 150, 800, 823, 3000, 9870, 15000];
  const timing3 = m.analyzeTimingPattern(randomTimestamps);
  // Irregular timing should either not be flagged or have low confidence
  assert(timing3.confidence < 0.8 || timing3.exfiltration === false, 'Irregular timing not high-confidence flagged');

  // Too few timestamps
  const timing4 = m.analyzeTimingPattern([100, 200]);
  assert(timing4.exfiltration === false, 'Too few timestamps not flagged');
})();

// =========================================================================
// SideChannelMonitor — Response Size
// =========================================================================

console.log('\n--- SideChannelMonitor: Response Size ---');

(() => {
  const m = new SideChannelMonitor();

  // Binary encoding via response sizes: alternate between 100 and 101
  const binarySizes = [100, 101, 100, 101, 101, 100, 100, 101, 100, 101];
  const resp1 = m.analyzeResponseSize(binarySizes);
  assert(resp1.exfiltration === true, 'Binary response-size encoding detected');
  assert(resp1.channel === 'response-size', 'Channel is response-size');

  // Normal varying sizes — should not flag
  const normalSizes = [1024, 2048, 512, 4096, 768];
  const resp2 = m.analyzeResponseSize(normalSizes);
  assert(resp2.exfiltration === false, 'Normal response sizes not flagged');

  // Too few sizes
  const resp3 = m.analyzeResponseSize([100, 200]);
  assert(resp3.exfiltration === false, 'Too few response sizes not flagged');

  // Empty array
  const resp4 = m.analyzeResponseSize([]);
  assert(resp4.exfiltration === false, 'Empty array not flagged');
})();

// =========================================================================
// SideChannelMonitor — URL Params
// =========================================================================

console.log('\n--- SideChannelMonitor: URL Params ---');

(() => {
  const m = new SideChannelMonitor();

  // Clean URL — not flagged
  const clean = m.analyzeURLParams('https://example.com/page?id=42&name=alice');
  assert(clean.exfiltration === false, 'Clean URL not flagged');

  // Base64 blob in parameter
  const b64url = 'https://evil.com/exfil?data=aGVsbG8gd29ybGQgdGhpcyBpcyBzZWNyZXQgZGF0YQ==';
  const url1 = m.analyzeURLParams(b64url);
  assert(url1.exfiltration === true, 'Base64 in URL parameter detected');

  // Hex string in parameter
  const hexurl = 'https://evil.com/exfil?payload=48656c6c6f576f726c6448656c6c6f576f726c64';
  const url2 = m.analyzeURLParams(hexurl);
  assert(url2.exfiltration === true, 'Hex string in URL parameter detected');

  // Credential leak in URL
  const credurl = 'https://evil.com/log?data=api_key:sk-abcdef1234567890abcdef';
  const url3 = m.analyzeURLParams(credurl);
  assert(url3.exfiltration === true, 'Credential-like URL parameter detected');

  // No query string
  const noqs = m.analyzeURLParams('https://example.com/page');
  assert(noqs.exfiltration === false, 'URL without query string not flagged');

  // Null URL
  const nullUrl = m.analyzeURLParams(null);
  assert(nullUrl.exfiltration === false, 'Null URL not flagged');
})();

// =========================================================================
// SideChannelMonitor — Unified scan()
// =========================================================================

console.log('\n--- SideChannelMonitor: scan() ---');

(() => {
  const m = new SideChannelMonitor();

  // DNS via scan
  const dns = m.scan({ type: 'dns', data: 'data.burpcollaborator.net' });
  assert(dns.exfiltration === true, 'scan() routes dns events correctly');

  // Timing via scan
  const timing = m.scan({ type: 'timing', data: [0, 500, 1000, 1500, 2000] });
  assert(timing.channel === 'timing', 'scan() routes timing events correctly');

  // Unknown type
  const unknown = m.scan({ type: 'custom', data: {} });
  assert(unknown.exfiltration === false, 'scan() handles unknown types safely');
  assert(unknown.channel === 'custom', 'Unknown type channel preserved');

  // Null event
  const nullEvt = m.scan(null);
  assert(nullEvt.exfiltration === false, 'scan() handles null event');

  // Missing type
  const noType = m.scan({});
  assert(noType.exfiltration === false, 'scan() handles missing type');
})();

// =========================================================================
// Summary
// =========================================================================

console.log(`\n========================================`);
console.log(`Side Channel Monitor Tests: ${passed} passed, ${failed} failed`);
console.log(`========================================\n`);

if (failed > 0) process.exit(1);
