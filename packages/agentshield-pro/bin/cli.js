#!/usr/bin/env node
'use strict';

/**
 * Agent Shield Pro CLI
 *
 * Commands:
 *   agentshield-pro activate <key>    Activate a license key
 *   agentshield-pro status            Show license status
 *   agentshield-pro audit             Run pre-deployment security audit
 *   agentshield-pro dashboard         Launch TUI dashboard
 *   agentshield-pro generate-key      Generate a license key (admin only)
 */

const { license, generateLicenseKey, validateLicenseKey } = require('../src/license');

const [,, command, ...args] = process.argv;

function printHelp() {
  console.log(`
[Agent Shield Pro] CLI v1.0.0

Usage: agentshield-pro <command> [options]

Commands:
  activate <key>     Activate a license key
  status             Show current license status
  audit              Run pre-deployment security audit
  dashboard          Launch TUI dashboard (interactive)
  compliance         Show compliance posture (Enterprise)
  compliance-html    Generate HTML compliance report (Enterprise)
  generate-key       Generate a license key (requires --secret)

Options:
  --secret <s>       Signing secret for license operations
  --tier <t>         License tier: pro, team, enterprise (default: pro)
  --org <id>         Organization ID
  --org-name <name>  Organization display name
  --days <n>         License validity in days (default: 365)
  --seats <n>        Number of seats (default: 1)
  --framework <fw>   Compliance framework: owasp_llm, soc2, nist_ai, eu_ai_act, hipaa, gdpr
  --output <file>    Output file path (for compliance-html)

Examples:
  agentshield-pro activate AS-PRO-xxx.yyy --secret mysecret
  agentshield-pro generate-key --secret mysecret --tier team --org acme-corp --org-name "Acme Corp"
  agentshield-pro audit
  agentshield-pro dashboard
  agentshield-pro compliance
  agentshield-pro compliance-html --output report.html
  `);
}

function parseArgs(args) {
  const opts = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--secret' && args[i + 1]) opts.secret = args[++i];
    else if (args[i] === '--tier' && args[i + 1]) opts.tier = args[++i];
    else if (args[i] === '--org' && args[i + 1]) opts.orgId = args[++i];
    else if (args[i] === '--org-name' && args[i + 1]) opts.orgName = args[++i];
    else if (args[i] === '--days' && args[i + 1]) opts.days = parseInt(args[++i], 10);
    else if (args[i] === '--seats' && args[i + 1]) opts.seats = parseInt(args[++i], 10);
    else if (args[i] === '--framework' && args[i + 1]) opts.framework = args[++i];
    else if (args[i] === '--output' && args[i + 1]) opts.output = args[++i];
    else if (!args[i].startsWith('--')) opts.positional = opts.positional || args[i];
  }
  return opts;
}

function commandActivate(opts) {
  const key = opts.positional || args[0];
  const secret = opts.secret || process.env.AGENT_SHIELD_SECRET;

  if (!key) {
    console.error('[Agent Shield Pro] Error: License key required');
    console.error('Usage: agentshield-pro activate <key> --secret <secret>');
    process.exit(1);
  }
  if (!secret) {
    console.error('[Agent Shield Pro] Error: Signing secret required (--secret or AGENT_SHIELD_SECRET env var)');
    process.exit(1);
  }

  const result = license.activate(key, secret);
  if (result.activated) {
    console.log('[Agent Shield Pro] License activated successfully!');
    console.log(`  Tier:       ${result.tier}`);
    console.log(`  Org:        ${result.orgName || result.orgId}`);
    console.log(`  Features:   ${result.features.length}`);
    console.log(`  Expires:    ${result.expiresAt}`);
  } else {
    console.error(`[Agent Shield Pro] Activation failed: ${result.error}`);
    process.exit(1);
  }
}

function commandStatus() {
  const status = license.getStatus();
  if (!status.licensed) {
    console.log('[Agent Shield Pro] No active license');
    console.log('  Tier: Community (free)');
    console.log('  To activate: agentshield-pro activate <key> --secret <secret>');
  } else {
    console.log('[Agent Shield Pro] License Status');
    console.log(`  Tier:           ${status.tier}`);
    console.log(`  Organization:   ${status.orgName}`);
    console.log(`  Seats:          ${status.seats}`);
    console.log(`  Features:       ${status.features.length}`);
    console.log(`  Expires:        ${status.expiresAt}`);
    console.log(`  Days remaining: ${status.daysRemaining}`);
  }
}

function commandGenerateKey(opts) {
  const secret = opts.secret || process.env.AGENT_SHIELD_SECRET;
  if (!secret) {
    console.error('[Agent Shield Pro] Error: --secret is required to generate keys');
    process.exit(1);
  }

  const tier = opts.tier || 'pro';
  const orgId = opts.orgId || 'default-org';
  const orgName = opts.orgName || orgId;
  const days = opts.days || 365;
  const seats = opts.seats || 1;

  const { key, payload } = generateLicenseKey({
    tier,
    orgId,
    orgName,
    signingSecret: secret,
    expiresInDays: days,
    seats
  });

  console.log('[Agent Shield Pro] License Key Generated');
  console.log('');
  console.log(`  Key:      ${key}`);
  console.log('');
  console.log(`  Tier:     ${payload.tier}`);
  console.log(`  Org:      ${payload.orgName}`);
  console.log(`  Seats:    ${payload.seats}`);
  console.log(`  Features: ${payload.features.length}`);
  console.log(`  Expires:  ${new Date(payload.expiresAt).toISOString()}`);
  console.log(`  Key ID:   ${payload.keyId}`);
  console.log('');
  console.log('  Share this key with the customer. Keep the --secret private.');
}

async function commandAudit() {
  try {
    const sdk = require('agentshield-sdk');
    const { SecurityAudit } = sdk;
    if (!SecurityAudit) {
      console.error('[Agent Shield Pro] SecurityAudit not found. Ensure agentshield-sdk >= 7.3.0');
      process.exit(1);
    }
    const audit = new SecurityAudit();
    const result = audit.run();
    console.log(audit.formatReport(result));
  } catch (e) {
    // Fallback for monorepo dev
    try {
      const { SecurityAudit } = require('../../../src/audit');
      const audit = new SecurityAudit();
      const result = audit.run();
      console.log(audit.formatReport(result));
    } catch (_e2) {
      console.error(`[Agent Shield Pro] Error: ${e.message}`);
      process.exit(1);
    }
  }
}

async function commandDashboard() {
  const tui = require('../src/tui-dashboard');
  if (tui.launchDashboard) {
    await tui.launchDashboard();
  } else {
    console.error('[Agent Shield Pro] TUI dashboard module not available');
    process.exit(1);
  }
}

function commandCompliance(opts) {
  const { ComplianceDashboard } = require('../src/compliance-dashboard');
  const dashboard = new ComplianceDashboard({
    orgInfo: {
      name: license._license?.orgName || opts.orgName || 'Organization',
      id: license.orgId || opts.orgId || 'default',
    },
  });

  // Enable core checks by default
  dashboard.enableCheck('injection_scanning');
  dashboard.enableCheck('output_scanning');

  if (opts.framework) {
    const report = dashboard.generateReport(opts.framework);
    const formatted = dashboard.formatTerminal();
    console.log(formatted);
  } else {
    const output = dashboard.formatTerminal();
    console.log(output);
  }
}

function commandComplianceHTML(opts) {
  const fs = require('fs');
  const { ComplianceDashboard } = require('../src/compliance-dashboard');
  const dashboard = new ComplianceDashboard({
    orgInfo: {
      name: license._license?.orgName || opts.orgName || 'Organization',
      id: license.orgId || opts.orgId || 'default',
    },
  });

  dashboard.enableCheck('injection_scanning');
  dashboard.enableCheck('output_scanning');

  const html = dashboard.generateHTML({
    title: `Compliance Report - ${dashboard.orgInfo.name}`,
  });

  const outputPath = opts.output || 'agentshield-compliance-report.html';
  fs.writeFileSync(outputPath, html, 'utf-8');
  console.log(`[Agent Shield Pro] Compliance report written to: ${outputPath}`);
}

// Route commands
const opts = parseArgs(args);

switch (command) {
  case 'activate':
    commandActivate(opts);
    break;
  case 'status':
    commandStatus();
    break;
  case 'generate-key':
    commandGenerateKey(opts);
    break;
  case 'audit':
    commandAudit();
    break;
  case 'dashboard':
    commandDashboard();
    break;
  case 'compliance':
    commandCompliance(opts);
    break;
  case 'compliance-html':
    commandComplianceHTML(opts);
    break;
  case 'help':
  case '--help':
  case '-h':
  case undefined:
    printHelp();
    break;
  default:
    console.error(`[Agent Shield Pro] Unknown command: ${command}`);
    printHelp();
    process.exit(1);
}
