'use strict';

/**
 * Agent Shield Pro — License Key Tests
 */

const { generateLicenseKey, validateLicenseKey, LicenseManager, TIER_FEATURES, TIER_ORDER } = require('../src/license');

let passed = 0;
let failed = 0;

function assert(condition, label) {
  if (condition) {
    console.log(`  ✓ ${label}`);
    passed++;
  } else {
    console.log(`  ✗ FAIL: ${label}`);
    failed++;
  }
}

const SECRET = 'test-signing-secret-do-not-use-in-production';

console.log('=== License Key Generation ===');

const { key: proKey, payload: proPayload } = generateLicenseKey({
  tier: 'pro',
  orgId: 'test-org',
  orgName: 'Test Organization',
  signingSecret: SECRET,
  expiresInDays: 365,
  seats: 5
});

assert(proKey.startsWith('AS-PRO-'), 'Pro key has correct prefix');
assert(proKey.includes('.'), 'Key has signature separator');
assert(proPayload.tier === 'pro', 'Payload tier is pro');
assert(proPayload.orgId === 'test-org', 'Payload has orgId');
assert(proPayload.orgName === 'Test Organization', 'Payload has orgName');
assert(proPayload.seats === 5, 'Payload has seats');
assert(proPayload.features.length > 0, 'Payload has features');
assert(proPayload.keyId, 'Payload has keyId');
assert(proPayload.expiresAt > Date.now(), 'Expiry is in the future');

const { key: teamKey } = generateLicenseKey({
  tier: 'team',
  orgId: 'team-org',
  signingSecret: SECRET
});
assert(teamKey.startsWith('AS-TEAM-'), 'Team key has correct prefix');

const { key: entKey, payload: entPayload } = generateLicenseKey({
  tier: 'enterprise',
  orgId: 'ent-org',
  signingSecret: SECRET,
  seats: 100,
  extraFeatures: ['custom-feature-1']
});
assert(entKey.startsWith('AS-ENTERPRISE-'), 'Enterprise key has correct prefix');
assert(entPayload.features.includes('custom-feature-1'), 'Extra features included');
assert(entPayload.seats === 100, 'Enterprise seats = 100');

console.log('\n=== License Key Validation ===');

const validResult = validateLicenseKey(proKey, SECRET);
assert(validResult.valid === true, 'Valid key validates');
assert(validResult.tier === 'pro', 'Tier extracted correctly');
assert(validResult.features.length > 0, 'Features extracted');
assert(validResult.payload.orgId === 'test-org', 'OrgId preserved');

const wrongSecret = validateLicenseKey(proKey, 'wrong-secret');
assert(wrongSecret.valid === false, 'Wrong secret rejects');
assert(wrongSecret.error === 'Invalid signature', 'Error says invalid signature');

const tamperedKey = proKey.replace('PRO', 'ENTERPRISE');
const tamperedResult = validateLicenseKey(tamperedKey, SECRET);
assert(tamperedResult.valid === false, 'Tampered key rejected');

const nullResult = validateLicenseKey(null, SECRET);
assert(nullResult.valid === false, 'Null key rejected');

const emptyResult = validateLicenseKey('', SECRET);
assert(emptyResult.valid === false, 'Empty key rejected');

const noSigResult = validateLicenseKey('AS-PRO-abc', SECRET);
assert(noSigResult.valid === false, 'Key without signature rejected');

console.log('\n=== Expired License ===');

const { key: expiredKey } = generateLicenseKey({
  tier: 'pro',
  orgId: 'expired-org',
  signingSecret: SECRET,
  expiresInDays: -1
});
const expiredResult = validateLicenseKey(expiredKey, SECRET);
assert(expiredResult.valid === false, 'Expired key rejected');
assert(expiredResult.error === 'License expired', 'Error says license expired');

console.log('\n=== LicenseManager ===');

const manager = new LicenseManager();
assert(manager.isLicensed === false, 'Initially not licensed');
assert(manager.tier === null, 'Initially no tier');

const activateResult = manager.activate(proKey, SECRET);
assert(activateResult.activated === true, 'Activation succeeds');
assert(activateResult.tier === 'pro', 'Activated tier is pro');
assert(manager.isLicensed === true, 'Now licensed');
assert(manager.tier === 'pro', 'Tier accessible');
assert(manager.orgId === 'test-org', 'OrgId accessible');

assert(manager.hasFeature('ensemble'), 'Has ensemble feature');
assert(manager.hasFeature('persistent-learning'), 'Has persistent-learning feature');
assert(manager.hasFeature('smart-config'), 'Has smart-config feature');
assert(!manager.hasFeature('threat-intel-feed'), 'Pro does not have enterprise feature');

assert(manager.hasTier('pro'), 'Has pro tier');
assert(!manager.hasTier('team'), 'Does not have team tier');
assert(!manager.hasTier('enterprise'), 'Does not have enterprise tier');

console.log('\n=== Feature Gating ===');

let caught = false;
try {
  manager.requireFeature('ensemble');
} catch (_e) {
  caught = true;
}
assert(!caught, 'requireFeature does not throw for licensed feature');

caught = false;
try {
  manager.requireFeature('threat-intel-feed', 'Threat intel');
} catch (e) {
  caught = true;
  assert(e.message.includes('requires'), 'Error message mentions requirement');
  assert(e.message.includes('Upgrade'), 'Error message mentions upgrade');
}
assert(caught, 'requireFeature throws for unlicensed feature');

console.log('\n=== License Status ===');

const status = manager.getStatus();
assert(status.licensed === true, 'Status shows licensed');
assert(status.tier === 'pro', 'Status shows tier');
assert(status.orgId === 'test-org', 'Status shows orgId');
assert(status.daysRemaining > 360, 'Days remaining > 360');
assert(status.features.length > 0, 'Features listed');

console.log('\n=== Deactivation ===');

manager.deactivate();
assert(manager.isLicensed === false, 'Deactivated');
assert(manager.tier === null, 'Tier cleared');
assert(manager.hasFeature('ensemble') === false, 'Features cleared');

const statusAfter = manager.getStatus();
assert(statusAfter.licensed === false, 'Status shows not licensed');
assert(statusAfter.tier === 'community', 'Tier shows community');

console.log('\n=== Tier Hierarchy ===');

manager.activate(entKey, SECRET);
assert(manager.hasTier('pro'), 'Enterprise has pro tier');
assert(manager.hasTier('team'), 'Enterprise has team tier');
assert(manager.hasTier('enterprise'), 'Enterprise has enterprise tier');
assert(manager.hasFeature('threat-intel-feed'), 'Enterprise has threat-intel-feed');
assert(manager.hasFeature('sso-integration'), 'Enterprise has sso-integration');

console.log('\n=== TIER_FEATURES ===');

assert(TIER_FEATURES.pro.length >= 8, 'Pro has 8+ features');
assert(TIER_FEATURES.team.length >= 13, 'Team has 13+ features');
assert(TIER_FEATURES.enterprise.length >= 18, 'Enterprise has 18+ features');
assert(TIER_ORDER.pro === 1, 'Pro order = 1');
assert(TIER_ORDER.team === 2, 'Team order = 2');
assert(TIER_ORDER.enterprise === 3, 'Enterprise order = 3');

console.log('\n=== Error Handling ===');

let errCaught = false;
try {
  generateLicenseKey({ tier: 'invalid', orgId: 'x', signingSecret: SECRET });
} catch (e) {
  errCaught = true;
  assert(e.message.includes('Invalid tier'), 'Invalid tier error');
}
assert(errCaught, 'Invalid tier throws');

errCaught = false;
try {
  generateLicenseKey({ tier: 'pro', orgId: '', signingSecret: SECRET });
} catch (_e) {
  errCaught = true;
}
assert(errCaught, 'Empty orgId throws');

errCaught = false;
try {
  generateLicenseKey({ tier: 'pro', orgId: 'x', signingSecret: '' });
} catch (_e) {
  errCaught = true;
}
assert(errCaught, 'Empty secret throws');

const badActivate = manager.activate(proKey, 'wrong-secret');
assert(badActivate.activated === false, 'Bad secret activation fails');

console.log(`\n${'='.repeat(50)}`);
console.log(`License Tests: ${passed} passed, ${failed} failed`);
console.log('='.repeat(50));

if (failed > 0) process.exit(1);
