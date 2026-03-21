'use strict';

/**
 * Tests for Confused Deputy Prevention module
 * Validates: AuthorizationContext, EphemeralTokenManager, IntentValidator, ConfusedDeputyGuard
 */

const {
  AuthorizationContext,
  EphemeralTokenManager,
  IntentValidator,
  ConfusedDeputyGuard
} = require('../src/main');

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    passed++;
    console.log(`  ✓ ${message}`);
  } else {
    failed++;
    console.log(`  ✗ ${message}`);
  }
}

// =========================================================================
// Exports
// =========================================================================
console.log('=== Confused Deputy Exports ===');
assert(typeof AuthorizationContext === 'function', 'AuthorizationContext exported');
assert(typeof EphemeralTokenManager === 'function', 'EphemeralTokenManager exported');
assert(typeof IntentValidator === 'function', 'IntentValidator exported');
assert(typeof ConfusedDeputyGuard === 'function', 'ConfusedDeputyGuard exported');

// =========================================================================
// AuthorizationContext
// =========================================================================
console.log('\n=== AuthorizationContext ===');

const ctx = new AuthorizationContext({
  userId: 'user-1',
  agentId: 'agent-1',
  roles: ['engineer'],
  scopes: ['read', 'write', 'tool:search'],
  intent: 'Summarize quarterly report',
  ttlMs: 300000
});

assert(ctx.contextId.length > 0, 'Context has unique ID');
assert(ctx.userId === 'user-1', 'userId preserved');
assert(ctx.agentId === 'agent-1', 'agentId preserved');
assert(ctx.roles.length === 1, 'Roles set');
assert(ctx.scopes.length === 3, 'Scopes set');
assert(ctx.intent === 'Summarize quarterly report', 'Intent set');
assert(!ctx.isExpired(), 'Context not expired');
assert(ctx.verify(), 'Context signature valid');

// Scope checks
assert(ctx.hasScope('read'), 'Has read scope');
assert(ctx.hasScope('write'), 'Has write scope');
assert(!ctx.hasScope('admin'), 'Does not have admin scope');

// Role checks
assert(ctx.hasRole('engineer'), 'Has engineer role');
assert(!ctx.hasRole('admin'), 'Does not have admin role');

// Immutability
let threw = false;
try { ctx.roles.push('admin'); } catch (e) { threw = true; }
assert(threw || ctx.roles.length === 1, 'Roles are immutable');

// Delegation
const delegated = ctx.delegate('agent-2', ['read', 'tool:search']);
assert(delegated.userId === 'user-1', 'Delegation preserves userId');
assert(delegated.agentId === 'agent-2', 'Delegation sets new agentId');
assert(delegated.scopes.length === 2, 'Delegation narrows scopes');
assert(!delegated.scopes.includes('write'), 'Write scope not delegated');
assert(delegated.parentContextId === ctx.contextId, 'Parent context linked');
assert(delegated.delegationDepth === 1, 'Delegation depth incremented');
assert(delegated.verify(), 'Delegated context signature valid');

// Scope narrowing enforcement
const narrowed = ctx.delegate('agent-3', ['read', 'admin']); // admin not in parent
assert(narrowed.scopes.length === 1, 'Cannot widen scopes via delegation');
assert(narrowed.scopes[0] === 'read', 'Only matching scopes delegated');

// Required fields
let errMsg = '';
try { new AuthorizationContext({ agentId: 'a' }); } catch (e) { errMsg = e.message; }
assert(errMsg.includes('userId'), 'Requires userId');

try { new AuthorizationContext({ userId: 'u' }); } catch (e) { errMsg = e.message; }
assert(errMsg.includes('agentId'), 'Requires agentId');

// Expired context cannot delegate
const expiredCtx = new AuthorizationContext({
  userId: 'u', agentId: 'a', ttlMs: 0
});
let delegateErr = '';
try { expiredCtx.delegate('b'); } catch (e) { delegateErr = e.message; }
assert(delegateErr.includes('expired'), 'Cannot delegate expired context');

// =========================================================================
// EphemeralTokenManager
// =========================================================================
console.log('\n=== EphemeralTokenManager ===');

const tokenMgr = new EphemeralTokenManager({ tokenTtlMs: 300000, maxTokensPerUser: 3 });

const token1 = tokenMgr.issueToken(ctx, ['read']);
assert(token1.tokenId.length > 0, 'Token has ID');
assert(token1.token.length > 0, 'Token has encoded value');
assert(token1.scopes.length === 1, 'Token scoped to read');
assert(token1.expiresAt > Date.now(), 'Token not expired');

// Validate token
const validation = tokenMgr.validateToken(token1.tokenId);
assert(validation.valid, 'Token validates successfully');
assert(validation.userId === 'user-1', 'Token carries userId');
assert(validation.scopes.length === 1, 'Token carries scopes');

// Invalid token
const badValidation = tokenMgr.validateToken('nonexistent');
assert(!badValidation.valid, 'Nonexistent token is invalid');
assert(badValidation.reason === 'Token not found', 'Reason: not found');

// Revoke token
tokenMgr.revokeToken(token1.tokenId);
const revokedValidation = tokenMgr.validateToken(token1.tokenId);
assert(!revokedValidation.valid, 'Revoked token is invalid');
assert(revokedValidation.reason.includes('revoked'), 'Reason: revoked');

// Rotate token
const token2 = tokenMgr.issueToken(ctx, ['read', 'write']);
const rotated = tokenMgr.rotateToken(token2.tokenId, ctx);
assert(rotated !== null, 'Token rotated successfully');
assert(rotated.tokenId !== token2.tokenId, 'New token has different ID');

// Revoke all for user
const token3 = tokenMgr.issueToken(ctx, ['read']);
const revokeCount = tokenMgr.revokeAllForUser('user-1');
assert(revokeCount > 0, `Revoked ${revokeCount} tokens for user`);

// Max tokens per user enforcement
const tokenMgr2 = new EphemeralTokenManager({ maxTokensPerUser: 2 });
tokenMgr2.issueToken(ctx, ['read']);
tokenMgr2.issueToken(ctx, ['write']);
tokenMgr2.issueToken(ctx, ['tool:search']); // should evict oldest
const stats = tokenMgr2.getStats();
assert(stats.issued === 3, 'Issued 3 tokens total');
assert(stats.revoked >= 1, 'Auto-revoked oldest when limit hit');

// Scope narrowing
const narrowToken = tokenMgr.issueToken(ctx, ['read', 'admin']); // admin not in ctx
assert(narrowToken.scopes.length === 1, 'Token scopes narrowed to ctx scopes');
assert(narrowToken.scopes[0] === 'read', 'Only valid scope granted');

// =========================================================================
// IntentValidator
// =========================================================================
console.log('\n=== IntentValidator ===');

const validator = new IntentValidator({ requireIntent: true, maxDelegationDepth: 3 });

// Register policies
validator.addPolicy({
  tool: 'database_query',
  requiredScopes: ['db:read'],
  requiredRoles: ['engineer', 'analyst'],
  allowedIntents: ['report', 'analysis', 'query']
});

validator.addPolicy({
  tool: 'file_delete',
  requiredScopes: ['fs:delete'],
  requiredRoles: ['admin'],
  requiresHumanApproval: true
});

// Valid action
const dbCtx = new AuthorizationContext({
  userId: 'u1', agentId: 'a1',
  roles: ['engineer'],
  scopes: ['db:read', 'fs:read'],
  intent: 'Generate quarterly report'
});

const dbResult = validator.validateAction('database_query', { sql: 'SELECT *' }, dbCtx);
assert(dbResult.allowed, 'DB query allowed for engineer with db:read scope');
assert(dbResult.violations.length === 0, 'No violations');

// Missing scope
const noScopeCtx = new AuthorizationContext({
  userId: 'u2', agentId: 'a2',
  roles: ['engineer'],
  scopes: ['fs:read'],
  intent: 'Run analysis'
});

const noScopeResult = validator.validateAction('database_query', {}, noScopeCtx);
assert(!noScopeResult.allowed, 'DB query denied without db:read scope');
assert(noScopeResult.violations.some(v => v.type === 'scope'), 'Scope violation recorded');

// Missing role
const noRoleCtx = new AuthorizationContext({
  userId: 'u3', agentId: 'a3',
  roles: ['intern'],
  scopes: ['fs:delete'],
  intent: 'Clean up files'
});

const noRoleResult = validator.validateAction('file_delete', {}, noRoleCtx);
assert(!noRoleResult.allowed, 'File delete denied without admin role');
assert(noRoleResult.violations.some(v => v.type === 'role'), 'Role violation recorded');

// Human approval required
const adminCtx = new AuthorizationContext({
  userId: 'u4', agentId: 'a4',
  roles: ['admin'],
  scopes: ['fs:delete'],
  intent: 'Clean up temp files'
});

const approvalResult = validator.validateAction('file_delete', {}, adminCtx);
assert(approvalResult.requiresApproval, 'File delete requires human approval');

// Intent mismatch
const wrongIntentCtx = new AuthorizationContext({
  userId: 'u5', agentId: 'a5',
  roles: ['engineer'],
  scopes: ['db:read'],
  intent: 'Delete everything'
});

const intentResult = validator.validateAction('database_query', {}, wrongIntentCtx);
assert(!intentResult.allowed, 'DB query denied with wrong intent');
assert(intentResult.violations.some(v => v.type === 'intent'), 'Intent violation recorded');

// Missing intent when required
const noIntentCtx = new AuthorizationContext({
  userId: 'u6', agentId: 'a6',
  roles: ['engineer'],
  scopes: ['db:read']
});

const noIntentResult = validator.validateAction('database_query', {}, noIntentCtx);
assert(!noIntentResult.allowed, 'Denied when intent required but missing');
assert(noIntentResult.violations.some(v => v.type === 'missing_intent'), 'Missing intent violation');

// Delegation depth exceeded
const deepCtx = new AuthorizationContext({
  userId: 'u7', agentId: 'a7',
  roles: ['engineer'],
  scopes: ['db:read'],
  intent: 'Run report'
});
deepCtx.delegationDepth = 5;
deepCtx._signature = deepCtx._sign();

const deepResult = validator.validateAction('database_query', {}, deepCtx);
assert(!deepResult.allowed, 'Denied when delegation depth exceeded');
assert(deepResult.violations.some(v => v.type === 'delegation_depth'), 'Depth violation recorded');

// Expired context
const expiredResult = validator.validateAction('database_query', {}, expiredCtx);
assert(!expiredResult.allowed, 'Denied with expired context');
assert(expiredResult.violations.some(v => v.type === 'expired'), 'Expired violation');

// Audit log
const auditLog = validator.getAuditLog();
assert(auditLog.length > 0, `Audit log has ${auditLog.length} entries`);
assert(auditLog[0].toolName !== undefined, 'Audit entries have toolName');
assert(auditLog[0].userId !== undefined, 'Audit entries have userId');

// =========================================================================
// ConfusedDeputyGuard
// =========================================================================
console.log('\n=== ConfusedDeputyGuard ===');

const guard = new ConfusedDeputyGuard({ enforceContext: true });

// Register tools
guard.registerTool('bash', { scopes: ['exec'], roles: ['admin'] });
guard.registerTool('search', { scopes: ['read'] });
guard.registerTool('deploy', { scopes: ['deploy'], roles: ['devops'], requiresHumanApproval: true });

// Valid call
const validCtx = new AuthorizationContext({
  userId: 'dev-1', agentId: 'agent-1',
  roles: ['admin'],
  scopes: ['exec', 'read']
});

const validResult = guard.wrapToolCall('bash', { cmd: 'ls' }, validCtx);
assert(validResult.allowed, 'Bash allowed for admin with exec scope');
assert(validResult.token !== null, 'Ephemeral token issued');

// No context — confused deputy detected
const noCtxResult = guard.wrapToolCall('bash', { cmd: 'ls' });
assert(!noCtxResult.allowed, 'Denied without authorization context');
assert(noCtxResult.violations[0].type === 'missing_context', 'Missing context violation');

// Wrong role
const wrongRoleCtx = new AuthorizationContext({
  userId: 'dev-2', agentId: 'agent-2',
  roles: ['intern'],
  scopes: ['exec']
});

const wrongRoleResult = guard.wrapToolCall('bash', { cmd: 'rm -rf' }, wrongRoleCtx);
assert(!wrongRoleResult.allowed, 'Bash denied for intern');
assert(wrongRoleResult.violations.some(v => v.type === 'role'), 'Role violation');

// Wrong scope
const wrongScopeCtx = new AuthorizationContext({
  userId: 'dev-3', agentId: 'agent-3',
  roles: ['admin'],
  scopes: ['read']
});

const wrongScopeResult = guard.wrapToolCall('bash', { cmd: 'ls' }, wrongScopeCtx);
assert(!wrongScopeResult.allowed, 'Bash denied without exec scope');

// Human approval needed
const devopsCtx = new AuthorizationContext({
  userId: 'ops-1', agentId: 'deploy-agent',
  roles: ['devops'],
  scopes: ['deploy']
});

const deployResult = guard.wrapToolCall('deploy', { env: 'prod' }, devopsCtx);
assert(deployResult.allowed, 'Deploy allowed for devops');
assert(deployResult.requiresApproval, 'Deploy requires human approval');

// Log-only mode
const logOnlyGuard = new ConfusedDeputyGuard({ enforceContext: true, logOnly: true });
logOnlyGuard.registerTool('bash', { scopes: ['exec'], roles: ['admin'] });
const logResult = logOnlyGuard.wrapToolCall('bash', { cmd: 'rm' });
assert(logResult.allowed, 'Log-only mode allows without context');

// Stats
const guardStats = guard.getStats();
assert(guardStats.checked > 0, `Checked ${guardStats.checked} calls`);
assert(guardStats.denied > 0, `Denied ${guardStats.denied} calls`);
assert(guardStats.tokens.issued > 0, 'Tokens issued');
assert(guardStats.auditEntries > 0, 'Audit entries recorded');

// Audit log
const guardAudit = guard.getAuditLog();
assert(guardAudit.length > 0, `Guard audit log has ${guardAudit.length} entries`);

// =========================================================================
// Integration: Full confused deputy scenario
// =========================================================================
console.log('\n=== Integration: Confused Deputy Scenario ===');

// Simulate: User A asks Agent 1 to summarize. Agent 1 delegates to Agent 2.
// Agent 2 tries to call a tool that User A doesn't have access to.
const fullGuard = new ConfusedDeputyGuard({ enforceContext: true });
fullGuard.registerTool('read_file', { scopes: ['fs:read'] });
fullGuard.registerTool('delete_file', { scopes: ['fs:delete'], roles: ['admin'] });
fullGuard.registerTool('send_email', { scopes: ['comm:send'] });

// User A's context
const userACtx = new AuthorizationContext({
  userId: 'user-A', agentId: 'agent-1',
  roles: ['analyst'],
  scopes: ['fs:read', 'comm:send'],
  intent: 'Summarize Q4 earnings'
});

// Agent 1 delegates to Agent 2
const agent2Ctx = userACtx.delegate('agent-2', ['fs:read']);

// Agent 2 can read files (delegated)
const readResult = fullGuard.wrapToolCall('read_file', { path: '/data/q4.csv' }, agent2Ctx);
assert(readResult.allowed, 'Agent 2 can read files (delegated from User A)');

// Agent 2 CANNOT delete files (not in User A's scopes)
const deleteResult = fullGuard.wrapToolCall('delete_file', { path: '/data/q4.csv' }, agent2Ctx);
assert(!deleteResult.allowed, 'Agent 2 cannot delete (confused deputy prevented)');

// Agent 2 CANNOT send email (not delegated even though User A has it)
const emailResult = fullGuard.wrapToolCall('send_email', { to: 'ceo@corp.com' }, agent2Ctx);
assert(!emailResult.allowed, 'Agent 2 cannot email (scope not delegated)');

// Original agent CAN send email
const emailOk = fullGuard.wrapToolCall('send_email', { to: 'team@corp.com' }, userACtx);
assert(emailOk.allowed, 'Agent 1 can email (User A has comm:send scope)');

console.log();
console.log('==================================================');
console.log(`Confused Deputy Tests: ${passed} passed, ${failed} failed`);
console.log('==================================================');

if (failed > 0) process.exit(1);
