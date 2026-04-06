'use strict';

/**
 * Agent Shield — Sybil Detector Tests
 *
 * Tests for:
 *   1. SybilDetector — cluster detection, behavioral/temporal/content/creation/voting signals
 *   2. AgentIdentityVerifier — challenge-response, shared secret detection
 *   3. Edge cases — single agent, empty state, null safety
 */

const crypto = require('crypto');

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    passed++;
    console.log(`  ✓ ${message}`);
  } else {
    failed++;
    console.log(`  ✗ FAILED: ${message}`);
  }
}

console.log('='.repeat(60));
console.log('Sybil Detector Tests');
console.log('='.repeat(60));
console.log('');

const { SybilDetector, AgentIdentityVerifier, jaccardSimilarity, tokenize } = require('../src/sybil-detector');

// =========================================================================
// 1. Utility functions
// =========================================================================

console.log('=== Utility Functions ===');

(() => {
  const a = new Set(['x', 'y', 'z']);
  const b = new Set(['y', 'z', 'w']);
  const sim = jaccardSimilarity(a, b);
  assert(Math.abs(sim - 0.5) < 0.01, 'jaccardSimilarity: 2/4 overlap = 0.5');
})();

(() => {
  const a = new Set(['a', 'b']);
  const b = new Set(['a', 'b']);
  assert(jaccardSimilarity(a, b) === 1, 'jaccardSimilarity: identical sets = 1.0');
})();

(() => {
  const a = new Set(['a']);
  const b = new Set(['b']);
  assert(jaccardSimilarity(a, b) === 0, 'jaccardSimilarity: disjoint sets = 0.0');
})();

(() => {
  const a = new Set();
  const b = new Set();
  assert(jaccardSimilarity(a, b) === 1, 'jaccardSimilarity: two empty sets = 1.0');
})();

(() => {
  const tokens = tokenize('Hello World hello');
  assert(tokens.has('hello'), 'tokenize: lowercases input');
  assert(tokens.has('world'), 'tokenize: splits on whitespace');
  assert(tokens.size === 2, 'tokenize: deduplicates (hello appears once)');
})();

(() => {
  assert(tokenize(null).size === 0, 'tokenize: null returns empty set');
  assert(tokenize('').size === 0, 'tokenize: empty string returns empty set');
})();

console.log('');

// =========================================================================
// 2. SybilDetector — no clusters in independent agents
// =========================================================================

console.log('=== SybilDetector — Independent Agents (No Clusters) ===');

(() => {
  const detector = new SybilDetector({ minClusterSize: 3 });
  const now = Date.now();

  // Register 4 agents with different creation times and behaviors
  detector.registerAgent('agent-alpha', { name: 'Alpha', createdAt: now - 1000000 });
  detector.registerAgent('agent-beta', { name: 'Beta', createdAt: now - 500000 });
  detector.registerAgent('agent-gamma', { name: 'Gamma', createdAt: now - 200000 });
  detector.registerAgent('agent-delta', { name: 'Delta', createdAt: now });

  // Each agent does completely different things
  detector.recordAction('agent-alpha', { type: 'read', target: '/file-a', timestamp: now, content: 'reading documentation' });
  detector.recordAction('agent-beta', { type: 'write', target: '/file-b', timestamp: now + 30000, content: 'writing code' });
  detector.recordAction('agent-gamma', { type: 'delete', target: '/file-c', timestamp: now + 90000, content: 'cleaning up old logs' });
  detector.recordAction('agent-delta', { type: 'execute', target: '/script-d', timestamp: now + 200000, content: 'running deployment' });

  const result = detector.detectClusters();
  assert(result.clusters.length === 0, 'No clusters when agents are independent');
  assert(result.sybilRisk === 'none', 'Risk is none for independent agents');
})();

console.log('');

// =========================================================================
// 3. SybilDetector — Sybil cluster detected (identical behavior)
// =========================================================================

console.log('=== SybilDetector — Sybil Cluster (Identical Behavior) ===');

(() => {
  const detector = new SybilDetector({
    similarityThreshold: 0.6,
    timeWindowMs: 5000,
    minClusterSize: 3
  });
  const now = Date.now();

  // 3 agents created at the same time doing the same things
  for (let i = 0; i < 3; i++) {
    const id = `sybil-${i}`;
    detector.registerAgent(id, { name: `Sybil ${i}`, createdAt: now });
    detector.recordAction(id, { type: 'vote', target: 'proposal-1', timestamp: now + i * 100, content: 'approve this proposal immediately' });
    detector.recordAction(id, { type: 'vote', target: 'proposal-2', timestamp: now + 1000 + i * 100, content: 'approve this proposal immediately' });
    detector.recordAction(id, { type: 'approve', target: 'proposal-3', timestamp: now + 2000 + i * 100, content: 'looks good approve now' });
  }

  const result = detector.detectClusters();
  assert(result.clusters.length >= 1, 'Detects at least one Sybil cluster');
  assert(result.clusters[0].agents.length === 3, 'Cluster contains all 3 colluding agents');
  assert(result.clusters[0].similarity > 0.6, 'Cluster similarity exceeds threshold');
  assert(result.clusters[0].evidence.length > 0, 'Cluster has supporting evidence');
  assert(result.sybilRisk !== 'none', 'Risk is not none for Sybil cluster');
})();

console.log('');

// =========================================================================
// 4. Temporal Correlation Detection
// =========================================================================

console.log('=== SybilDetector — Temporal Correlation ===');

(() => {
  const detector = new SybilDetector({
    similarityThreshold: 0.5,
    timeWindowMs: 2000,
    minClusterSize: 3
  });
  const now = Date.now();

  // 3 agents performing the same action type within tight time windows
  for (let i = 0; i < 3; i++) {
    const id = `temp-${i}`;
    detector.registerAgent(id, { name: `Temporal ${i}`, createdAt: now });
    // All do same action types within 500ms of each other
    detector.recordAction(id, { type: 'query', target: 'db-1', timestamp: now + i * 200, content: 'select data from users' });
    detector.recordAction(id, { type: 'query', target: 'db-1', timestamp: now + 5000 + i * 200, content: 'select data from users' });
  }

  const result = detector.detectClusters();
  assert(result.clusters.length >= 1, 'Temporal correlation triggers cluster detection');
  const evidence = result.clusters[0].evidence.join(' ');
  assert(evidence.includes('temporal_correlation') || evidence.includes('behavioral') || evidence.includes('content'),
    'Evidence includes correlation or behavioral signal');
})();

console.log('');

// =========================================================================
// 5. Content Similarity Scoring
// =========================================================================

console.log('=== SybilDetector — Content Similarity ===');

(() => {
  const detector = new SybilDetector({
    similarityThreshold: 0.5,
    timeWindowMs: 60000,
    minClusterSize: 3
  });
  const now = Date.now();

  // Agents with nearly identical content
  for (let i = 0; i < 3; i++) {
    const id = `content-${i}`;
    detector.registerAgent(id, { name: `Content ${i}`, createdAt: now + i });
    detector.recordAction(id, {
      type: 'post',
      target: 'forum-1',
      timestamp: now + i * 100,
      content: 'this product is amazing you should buy it right now great deal'
    });
    detector.recordAction(id, {
      type: 'post',
      target: 'forum-2',
      timestamp: now + 5000 + i * 100,
      content: 'fantastic product amazing deal buy now you will not regret it'
    });
  }

  const result = detector.detectClusters();
  assert(result.clusters.length >= 1, 'Content similarity triggers cluster detection');
  assert(result.clusters[0].similarity > 0.4, 'Cluster has meaningful similarity score');
})();

console.log('');

// =========================================================================
// 6. Creation Burst Detection
// =========================================================================

console.log('=== SybilDetector — Creation Burst Detection ===');

(() => {
  const detector = new SybilDetector({
    similarityThreshold: 0.5,
    timeWindowMs: 1000,
    minClusterSize: 3
  });
  const now = Date.now();

  // 4 agents created within 100ms of each other, same behavior
  for (let i = 0; i < 4; i++) {
    const id = `burst-${i}`;
    detector.registerAgent(id, { name: `Burst ${i}`, createdAt: now + i * 20 });
    detector.recordAction(id, {
      type: 'vote',
      target: 'proposal-x',
      timestamp: now + 500 + i * 20,
      content: 'strongly approve'
    });
  }

  const result = detector.detectClusters();
  assert(result.clusters.length >= 1, 'Creation burst triggers cluster');
  const evidence = result.clusters[0].evidence.join(' ');
  assert(evidence.includes('creation_burst') || result.clusters[0].similarity > 0.5,
    'Evidence includes creation burst or high similarity');
})();

console.log('');

// =========================================================================
// 7. Voting Collusion
// =========================================================================

console.log('=== SybilDetector — Voting Collusion ===');

(() => {
  const detector = new SybilDetector({
    similarityThreshold: 0.5,
    timeWindowMs: 60000,
    minClusterSize: 3
  });
  const now = Date.now();

  // 3 agents all voting for the same 5 proposals
  const proposals = ['prop-1', 'prop-2', 'prop-3', 'prop-4', 'prop-5'];
  for (let i = 0; i < 3; i++) {
    const id = `voter-${i}`;
    detector.registerAgent(id, { name: `Voter ${i}`, createdAt: now + i });
    for (const prop of proposals) {
      detector.recordAction(id, {
        type: 'vote',
        target: prop,
        timestamp: now + i * 500,
        content: 'yes'
      });
    }
  }

  const result = detector.detectClusters();
  assert(result.clusters.length >= 1, 'Voting collusion triggers cluster');
  const evidence = result.clusters[0].evidence.join(' ');
  assert(evidence.includes('voting_collusion') || evidence.includes('behavioral'),
    'Evidence references voting or behavioral signal');
})();

console.log('');

// =========================================================================
// 8. AgentIdentityVerifier — Challenge-Response
// =========================================================================

console.log('=== AgentIdentityVerifier — Challenge-Response ===');

(() => {
  const verifier = new AgentIdentityVerifier();
  const agentKey = 'my-secret-key-123';

  // Generate challenge
  const challenge = verifier.generateChallenge();
  assert(typeof challenge.challengeId === 'string', 'Challenge has an ID');
  assert(typeof challenge.nonce === 'string', 'Challenge has a nonce');
  assert(challenge.nonce.length === 64, 'Nonce is 32 bytes hex (64 chars)');

  // Compute valid response
  const validResponse = crypto.createHmac('sha256', agentKey)
    .update(challenge.nonce)
    .digest('hex');

  const result = verifier.verifyResponse('agent-1', challenge.challengeId, validResponse, agentKey);
  assert(result.valid === true, 'Valid response is accepted');
  assert(result.reason === 'verified', 'Reason is verified');
})();

(() => {
  const verifier = new AgentIdentityVerifier();
  const challenge = verifier.generateChallenge();

  const badResponse = crypto.randomBytes(32).toString('hex');
  const result = verifier.verifyResponse('agent-1', challenge.challengeId, badResponse, 'some-key');
  assert(result.valid === false, 'Invalid response is rejected');
  assert(result.reason === 'invalid_response', 'Reason is invalid_response');
})();

(() => {
  const verifier = new AgentIdentityVerifier();
  const result = verifier.verifyResponse('agent-1', 'nonexistent-id', 'abc', 'key');
  assert(result.valid === false, 'Unknown challenge is rejected');
  assert(result.reason === 'unknown_challenge', 'Reason is unknown_challenge');
})();

(() => {
  const verifier = new AgentIdentityVerifier();
  const result = verifier.verifyResponse(null, null, null);
  assert(result.valid === false, 'Null parameters are rejected');
  assert(result.reason === 'missing_parameters', 'Reason is missing_parameters');
})();

console.log('');

// =========================================================================
// 9. AgentIdentityVerifier — Shared Secret Detection
// =========================================================================

console.log('=== AgentIdentityVerifier — Shared Secret Detection ===');

(() => {
  const verifier = new AgentIdentityVerifier();

  const sharedKey = 'shared-secret-abc';
  const agents = [
    { agentId: 'clone-1', key: sharedKey },
    { agentId: 'clone-2', key: sharedKey },
    { agentId: 'clone-3', key: sharedKey },
    { agentId: 'legit-1', key: 'unique-key-xyz' }
  ];

  const result = verifier.detectSharedSecrets(agents);
  assert(result.hasSharedKeys === true, 'Detects shared keys');
  assert(result.sharedKeyGroups.length === 1, 'One group of shared keys');
  assert(result.sharedKeyGroups[0].agents.length === 3, 'Group contains 3 agents with shared key');
  assert(!result.sharedKeyGroups[0].agents.includes('legit-1'), 'Legitimate agent not in shared group');
})();

(() => {
  const verifier = new AgentIdentityVerifier();

  const agents = [
    { agentId: 'unique-1', key: 'key-aaa' },
    { agentId: 'unique-2', key: 'key-bbb' },
    { agentId: 'unique-3', key: 'key-ccc' }
  ];

  const result = verifier.detectSharedSecrets(agents);
  assert(result.hasSharedKeys === false, 'No shared keys when all unique');
  assert(result.sharedKeyGroups.length === 0, 'No shared key groups');
})();

(() => {
  const verifier = new AgentIdentityVerifier();
  const result = verifier.detectSharedSecrets([]);
  assert(result.hasSharedKeys === false, 'Empty array returns no shared keys');
})();

console.log('');

// =========================================================================
// 10. Edge Cases
// =========================================================================

console.log('=== Edge Cases ===');

(() => {
  const detector = new SybilDetector();
  const result = detector.detectClusters();
  assert(result.clusters.length === 0, 'No agents: returns empty clusters');
  assert(result.sybilRisk === 'none', 'No agents: risk is none');
})();

(() => {
  const detector = new SybilDetector();
  detector.registerAgent('solo', { name: 'Solo Agent' });
  detector.recordAction('solo', { type: 'read', target: '/data' });
  const result = detector.detectClusters();
  assert(result.clusters.length === 0, 'Single agent: no clusters');
  assert(result.sybilRisk === 'none', 'Single agent: risk is none');
})();

(() => {
  const detector = new SybilDetector();
  // Null/undefined inputs should not crash
  detector.registerAgent(null, {});
  detector.registerAgent(undefined, {});
  detector.recordAction(null, { type: 'test' });
  detector.recordAction('x', null);
  const result = detector.detectClusters();
  assert(result.clusters.length === 0, 'Null inputs: no crash, no clusters');
})();

(() => {
  const verifier = new AgentIdentityVerifier();
  const result = verifier.detectSharedSecrets(null);
  assert(result.hasSharedKeys === false, 'Null agents array: no crash');
})();

(() => {
  // Two agents below minClusterSize=3 should not form a cluster
  const detector = new SybilDetector({ minClusterSize: 3 });
  const now = Date.now();
  detector.registerAgent('pair-a', { name: 'A', createdAt: now });
  detector.registerAgent('pair-b', { name: 'B', createdAt: now });
  detector.recordAction('pair-a', { type: 'vote', target: 'p1', timestamp: now, content: 'yes' });
  detector.recordAction('pair-b', { type: 'vote', target: 'p1', timestamp: now, content: 'yes' });
  const result = detector.detectClusters();
  assert(result.clusters.length === 0, 'Two agents below minClusterSize=3: no cluster');
})();

console.log('');

// =========================================================================
// Summary
// =========================================================================

console.log('='.repeat(60));
console.log(`Sybil Detector Tests: ${passed} passed, ${failed} failed`);
console.log('='.repeat(60));

if (failed > 0) process.exit(1);
