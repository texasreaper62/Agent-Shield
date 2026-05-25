'use strict';

const { AgentIdentityCA } = require('../src/agent-identity-ca');

let passed = 0, failed = 0;
const assert = (c, m) => { if (c) { passed++; console.log(`  ✓ ${m}`); } else { failed++; console.error(`  ✗ ${m}`); } };

(async () => {
console.log('\n--- AgentIdentityCA: issue + verify passport ---');
const ca = new AgentIdentityCA();
const { passport, privateKey } = ca.issuePassport({
  agentId: 'agent-alpha',
  capabilities: ['read', 'scan'],
  orgId: 'org-acme',
});
assert(passport.agentId === 'agent-alpha', 'agentId set');
assert(passport.capabilities.length === 2, 'capabilities set');
assert(passport.orgId === 'org-acme', 'orgId set');
assert(typeof passport.signature === 'string' && passport.signature.length > 0, 'signature present');
assert(passport.caRootId === ca.caRootId, 'caRootId stamped');
assert(ca.verifyPassport(passport), 'CA verifies own passport');

console.log('\n--- AgentIdentityCA: tampered passport rejected ---');
const tampered = JSON.parse(JSON.stringify(passport));
tampered.capabilities = ['admin'];
assert(!ca.verifyPassport(tampered), 'tampered capabilities rejected');

const tampered2 = JSON.parse(JSON.stringify(passport));
tampered2.agentId = 'other-agent';
assert(!ca.verifyPassport(tampered2), 'tampered agentId rejected');

console.log('\n--- AgentIdentityCA: revoked passport rejected ---');
ca.revoke('agent-alpha');
assert(!ca.verifyPassport(passport), 'revoked passport rejected even though signature is valid');

const { passport: passportB, privateKey: keyB } = ca.issuePassport({ agentId: 'agent-bravo' });
assert(ca.verifyPassport(passportB), 'fresh passport for another agent still valid');

console.log('\n--- AgentIdentityCA: sign + verify message ---');
const envelope = ca.signMessage({ agentId: 'agent-bravo', payload: { msg: 'hello fleet' }, privateKey: keyB });
assert(typeof envelope.signature === 'string', 'envelope signed');
assert(typeof envelope.nonce === 'string' && envelope.nonce.length >= 16, 'nonce present');
const v = ca.verifyMessage(envelope, passportB);
assert(v.valid === true, 'fresh envelope verifies');
assert(v.agentId === 'agent-bravo', 'verified agentId returned');

console.log('\n--- AgentIdentityCA: tampered envelope rejected ---');
// Make a *fresh* envelope so the nonce check doesn't fire first (the previous
// envelope's nonce is now in seenNonces).
const freshEnv = ca.signMessage({ agentId: 'agent-bravo', payload: { msg: 'original' }, privateKey: keyB });
const tamperedEnv = JSON.parse(JSON.stringify(freshEnv));
tamperedEnv.payload = { msg: 'forged' };
const v2 = ca.verifyMessage(tamperedEnv, passportB);
assert(v2.valid === false, 'tampered payload rejected');
assert(v2.reason && (v2.reason.includes('signature') || v2.reason.includes('bad')),
  `rejection reason mentions bad signature (got: ${v2.reason})`);

console.log('\n--- AgentIdentityCA: nonce replay rejected ---');
const env2 = ca.signMessage({ agentId: 'agent-bravo', payload: 'x', privateKey: keyB });
const first = ca.verifyMessage(env2, passportB);
assert(first.valid === true, 'first verify accepted');
const replay = ca.verifyMessage(env2, passportB);
assert(replay.valid === false, 'replay of same nonce rejected');
assert(replay.reason && replay.reason.includes('replay'), 'rejection reason is "replay"');

console.log('\n--- AgentIdentityCA: stale message rejected ---');
const fastCa = new AgentIdentityCA({ messageTtlMs: 10 });
const { passport: pPort, privateKey: pKey } = fastCa.issuePassport({ agentId: 'agent-charlie' });
const oldEnv = fastCa.signMessage({ agentId: 'agent-charlie', payload: 'x', privateKey: pKey });
await new Promise((r) => setTimeout(r, 30));
const stale = fastCa.verifyMessage(oldEnv, pPort);
assert(stale.valid === false, 'stale envelope rejected');
assert(stale.reason && stale.reason.includes('too old'), 'rejection reason mentions staleness');

console.log('\n--- AgentIdentityCA: future-dated message rejected ---');
const futureEnv = { ...envelope, timestamp: Date.now() + 60_000, nonce: 'future-nonce-1234' };
// Re-sign because changing timestamp breaks signature; for this assertion
// we want to test the timestamp-skew check specifically. The simplest path:
// sign a fresh envelope and then move its timestamp forward.
const futEnv = ca.signMessage({ agentId: 'agent-bravo', payload: 'x', privateKey: keyB });
futEnv.timestamp += 10 * 60_000; // 10 min in the future
const futResult = ca.verifyMessage(futEnv, passportB);
assert(futResult.valid === false, 'future-timestamp envelope rejected (signature will also fail)');

console.log('\n--- AgentIdentityCA: agentId mismatch rejected ---');
const env3 = ca.signMessage({ agentId: 'agent-bravo', payload: 'x', privateKey: keyB });
env3.agentId = 'agent-alpha';
const mismatch = ca.verifyMessage(env3, passportB);
assert(mismatch.valid === false, 'mismatched agentId rejected');

console.log('\n--- AgentIdentityCA: passport from another CA rejected ---');
const otherCa = new AgentIdentityCA();
const { passport: foreignPassport } = otherCa.issuePassport({ agentId: 'foreign' });
assert(!ca.verifyPassport(foreignPassport), 'foreign-CA passport rejected by default');
assert(ca.verifyPassport(foreignPassport, { trustForeignCA: true }) === false,
  'trustForeignCA still requires correct signature for OUR CA root (other root signed it, so false)');

console.log('\n--- AgentIdentityCA: exportRootPublicKey ---');
const exported = ca.exportRootPublicKey();
assert(exported.caRootId === ca.caRootId, 'exports caRootId');
assert(typeof exported.publicKey === 'string' && exported.publicKey.length > 30,
  'exports SPKI base64 public key');

console.log('\n--- AgentIdentityCA: input validation ---');
let threw = false;
try { ca.issuePassport({}); } catch (_) { threw = true; }
assert(threw, 'issuePassport without agentId throws');
threw = false;
try { ca.signMessage({ agentId: 'x' }); } catch (_) { threw = true; }
assert(threw, 'signMessage without privateKey throws');
threw = false;
try { ca.revoke(null); } catch (_) { threw = true; }
assert(threw, 'revoke(null) throws');

console.log(`\n=== ${passed} passed, ${failed} failed ===`);
if (failed > 0) process.exit(1);
})().catch((e) => { console.error(e); process.exit(1); });
