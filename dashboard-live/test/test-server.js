'use strict';

const http = require('http');
const crypto = require('crypto');
const { ThreatStreamServer } = require('../server');

const WS_MAGIC_STRING = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

let passed = 0;
let failed = 0;
let testPort = 9100;

function assert(condition, message) {
  if (!condition) {
    throw new Error('Assertion failed: ' + message);
  }
}

function nextPort() {
  return testPort++;
}

async function runTest(name, fn) {
  try {
    await fn();
    passed++;
    console.log('  PASS  ' + name);
  } catch (err) {
    failed++;
    console.log('  FAIL  ' + name + ' — ' + err.message);
  }
}

function httpGet(port, path) {
  return new Promise((resolve, reject) => {
    const req = http.get('http://localhost:' + port + path, (res) => {
      let body = '';
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => {
        resolve({ status: res.statusCode, headers: res.headers, body: body });
      });
    });
    req.on('error', reject);
    req.setTimeout(3000, () => { req.destroy(); reject(new Error('Timeout')); });
  });
}

function httpPost(port, path, data) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(data);
    const req = http.request({
      hostname: 'localhost',
      port: port,
      path: path,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
    }, (res) => {
      let resBody = '';
      res.on('data', (chunk) => { resBody += chunk; });
      res.on('end', () => {
        resolve({ status: res.statusCode, headers: res.headers, body: resBody });
      });
    });
    req.on('error', reject);
    req.setTimeout(3000, () => { req.destroy(); reject(new Error('Timeout')); });
    req.write(body);
    req.end();
  });
}

async function main() {
  console.log('\n[Agent Shield] Dashboard Server Tests\n');

  // Test 1: Server starts and stops
  await runTest('Server starts and stops cleanly', async () => {
    const port = nextPort();
    const server = new ThreatStreamServer({ port });
    await server.start();
    assert(server._server !== null, 'Server should be running');
    await server.stop();
    assert(server._server === null, 'Server should be stopped');
  });

  // Test 2: HTTP /api/stats returns JSON
  await runTest('GET /api/stats returns valid JSON', async () => {
    const port = nextPort();
    const server = new ThreatStreamServer({ port });
    await server.start();
    try {
      const res = await httpGet(port, '/api/stats');
      assert(res.status === 200, 'Status should be 200, got ' + res.status);
      const stats = JSON.parse(res.body);
      assert(typeof stats.totalScans === 'number', 'totalScans should be a number');
      assert(typeof stats.totalThreats === 'number', 'totalThreats should be a number');
      assert(typeof stats.throughputPerSecond === 'object', 'throughputPerSecond should exist');
      assert(typeof stats.threatsBySeverity === 'object', 'threatsBySeverity should exist');
    } finally {
      await server.stop();
    }
  });

  // Test 3: HTTP /api/threats returns JSON array
  await runTest('GET /api/threats returns JSON array', async () => {
    const port = nextPort();
    const server = new ThreatStreamServer({ port });
    await server.start();
    try {
      const res = await httpGet(port, '/api/threats');
      assert(res.status === 200, 'Status should be 200');
      const threats = JSON.parse(res.body);
      assert(Array.isArray(threats), 'Should be an array');
    } finally {
      await server.stop();
    }
  });

  // Test 4: Scan ingestion updates stats
  await runTest('Scan ingestion updates stats correctly', async () => {
    const port = nextPort();
    const server = new ThreatStreamServer({ port });
    await server.start();
    try {
      server.ingestScan({
        latency: 25,
        threats: [
          { category: 'prompt_injection', severity: 'critical', message: 'Injection detected' },
          { category: 'data_exfiltration', severity: 'high', message: 'Data leak attempt' }
        ]
      });

      assert(server._stats.totalScans === 1, 'totalScans should be 1');
      assert(server._stats.totalThreats === 2, 'totalThreats should be 2');
      assert(server._stats.threatsByCategory['prompt_injection'] === 1, 'prompt_injection count should be 1');
      assert(server._stats.threatsByCategory['data_exfiltration'] === 1, 'data_exfiltration count should be 1');
      assert(server._stats.threatsBySeverity['critical'] === 1, 'critical should be 1');
      assert(server._stats.threatsBySeverity['high'] === 1, 'high should be 1');
    } finally {
      await server.stop();
    }
  });

  // Test 5: Threat broadcasting (verify threat appears in history)
  await runTest('Threat broadcasting adds to history', async () => {
    const port = nextPort();
    const server = new ThreatStreamServer({ port });
    await server.start();
    try {
      server.ingestScan({
        threats: [{ category: 'tool_abuse', severity: 'medium', message: 'Tool abuse' }]
      });
      assert(server._threatHistory.length === 1, 'History should have 1 threat');
      assert(server._threatHistory[0].category === 'tool_abuse', 'Category should match');
      assert(server._threatHistory[0].severity === 'medium', 'Severity should match');
    } finally {
      await server.stop();
    }
  });

  // Test 6: WebSocket frame encoding/decoding roundtrip
  await runTest('WebSocket frame encode/decode roundtrip', async () => {
    const server = new ThreatStreamServer({ port: nextPort() });

    // Encode a text frame
    const testData = JSON.stringify({ type: 'stats', data: { totalScans: 42 } });
    const frame = server._encodeFrame(testData);

    // Verify frame structure
    assert(Buffer.isBuffer(frame), 'Frame should be a Buffer');
    assert((frame[0] & 0x80) !== 0, 'FIN bit should be set');
    assert((frame[0] & 0x0F) === 0x01, 'Opcode should be 0x01 (text)');

    // Decode the frame
    const decoded = server._decodeFrame(frame);
    assert(decoded !== null, 'Decoded result should not be null');
    assert(decoded.opcode === 0x01, 'Decoded opcode should be 0x01');
    assert(decoded.payload.toString('utf8') === testData, 'Payload should match original data');
  });

  // Test 7: Sec-WebSocket-Accept hash computation
  await runTest('Sec-WebSocket-Accept hash is correct per RFC 6455', async () => {
    const server = new ThreatStreamServer({ port: nextPort() });

    // RFC 6455 Section 4.2.2 example
    const testKey = 'dGhlIHNhbXBsZSBub25jZQ==';
    const expected = 's3pPLMBiTxaQ9kYGzzhZRbK+xOo=';
    const result = server._computeAcceptKey(testKey);
    assert(result === expected, 'Accept key should be "' + expected + '", got "' + result + '"');
  });

  // Test 8: History size limit
  await runTest('History respects historySize limit', async () => {
    const port = nextPort();
    const server = new ThreatStreamServer({ port, historySize: 5 });
    await server.start();
    try {
      for (let i = 0; i < 10; i++) {
        server.ingestScan({
          threats: [{ category: 'cat_' + i, severity: 'low', message: 'Threat ' + i }]
        });
      }
      assert(server._threatHistory.length === 5, 'History should be limited to 5, got ' + server._threatHistory.length);
      assert(server._threatHistory[0].category === 'cat_5', 'Oldest should be cat_5, got ' + server._threatHistory[0].category);
      assert(server._threatHistory[4].category === 'cat_9', 'Newest should be cat_9');
    } finally {
      await server.stop();
    }
  });

  // Test 9: Throughput calculation
  await runTest('Throughput calculation over rolling window', async () => {
    const port = nextPort();
    const server = new ThreatStreamServer({ port });
    await server.start();
    try {
      // Ingest several scans
      for (let i = 0; i < 10; i++) {
        server.ingestScan({ threats: [] });
      }

      const stats = server._buildStatsPayload();
      assert(stats.totalScans === 10, 'totalScans should be 10');
      assert(Array.isArray(stats.throughputPerSecond), 'throughputPerSecond should be array');
      assert(stats.throughputPerSecond.length === 60, 'Should have 60 data points');

      // All 10 scans should be in the most recent second bucket
      const totalInWindow = stats.throughputPerSecond.reduce((a, b) => a + b, 0);
      assert(totalInWindow === 10, 'Total throughput should be 10, got ' + totalInWindow);
    } finally {
      await server.stop();
    }
  });

  // Test 10: POST /api/ingest endpoint
  await runTest('POST /api/ingest processes scan results', async () => {
    const port = nextPort();
    const server = new ThreatStreamServer({ port });
    await server.start();
    try {
      const res = await httpPost(port, '/api/ingest', {
        latency: 15,
        threats: [{ category: 'encoding_attack', severity: 'high', message: 'Base64 encoded payload' }]
      });
      assert(res.status === 200, 'Status should be 200, got ' + res.status);
      const body = JSON.parse(res.body);
      assert(body.ok === true, 'Response should have ok: true');
      assert(server._stats.totalScans === 1, 'Should have 1 scan');
      assert(server._stats.totalThreats === 1, 'Should have 1 threat');
    } finally {
      await server.stop();
    }
  });

  // Test 11: Frame encoding for various payload sizes
  await runTest('Frame encoding handles small and medium payloads', async () => {
    const server = new ThreatStreamServer({ port: nextPort() });

    // Small payload (< 126 bytes)
    const small = server._encodeFrame('hello');
    const decodedSmall = server._decodeFrame(small);
    assert(decodedSmall.payload.toString('utf8') === 'hello', 'Small payload roundtrip');

    // Medium payload (126-65535 bytes)
    const mediumData = 'x'.repeat(1000);
    const medium = server._encodeFrame(mediumData);
    const decodedMedium = server._decodeFrame(medium);
    assert(decodedMedium.payload.toString('utf8') === mediumData, 'Medium payload roundtrip');
    assert(medium[1] === 126, 'Medium payload should use 126 length marker');
  });

  // Test 12: getConnectedClients returns correct count
  await runTest('getConnectedClients returns 0 initially', async () => {
    const port = nextPort();
    const server = new ThreatStreamServer({ port });
    await server.start();
    try {
      assert(server.getConnectedClients() === 0, 'Should be 0 clients initially');
    } finally {
      await server.stop();
    }
  });

  // Test 13: Multiple scans update latency histogram
  await runTest('Latency histogram tracks correctly', async () => {
    const port = nextPort();
    const server = new ThreatStreamServer({ port });
    await server.start();
    try {
      server.ingestScan({ latency: 5, threats: [] });
      server.ingestScan({ latency: 25, threats: [] });
      server.ingestScan({ latency: 75, threats: [] });
      server.ingestScan({ latency: 200, threats: [] });

      assert(server._stats.latencyHistogram.length === 4, 'Should have 4 latency records');
      const avg = server._stats.latencyHistogram.reduce((a, b) => a + b, 0) / 4;
      assert(Math.abs(avg - 76.25) < 0.01, 'Average should be 76.25, got ' + avg);
    } finally {
      await server.stop();
    }
  });

  // Test 14: Detection rate calculation
  await runTest('Detection rate calculated correctly', async () => {
    const port = nextPort();
    const server = new ThreatStreamServer({ port });
    await server.start();
    try {
      server.ingestScan({ threats: [{ category: 'a', severity: 'low', message: 't' }] });
      server.ingestScan({ threats: [] });
      server.ingestScan({ threats: [] });
      server.ingestScan({ threats: [{ category: 'b', severity: 'high', message: 't' }] });

      const stats = server._buildStatsPayload();
      // 2 threats out of 4 scans = 50%
      assert(parseFloat(stats.detectionRate) === 50.00, 'Detection rate should be 50%, got ' + stats.detectionRate);
    } finally {
      await server.stop();
    }
  });

  // Summary
  console.log('\n' + (passed + failed) + ' tests, ' + passed + ' passed, ' + failed + ' failed\n');
  process.exit(failed > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error('Test runner error:', err);
  process.exit(1);
});
