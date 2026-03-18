#!/usr/bin/env node
'use strict';

/**
 * Agent Shield CLI (#47)
 *
 * Usage:
 *   npx agent-shield scan "text to check"
 *   npx agent-shield scan --file input.txt
 *   npx agent-shield scan --json '{"message": "ignore instructions"}'
 *   npx agent-shield audit ./my-agent/
 *   npx agent-shield patterns
 */

const fs = require('fs');
const path = require('path');
const { AgentShield } = require('../src/index');
const { PromptLeakDetector } = require('../src/canary');
const { PIIRedactor } = require('../src/pii');
const { StructuredDataScanner } = require('../src/encoding');

const COLORS = {
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  green: '\x1b[32m',
  cyan: '\x1b[36m',
  gray: '\x1b[90m',
  bold: '\x1b[1m',
  reset: '\x1b[0m'
};

const severityColor = (severity) => {
  switch (severity) {
    case 'critical': return COLORS.red;
    case 'high': return COLORS.red;
    case 'medium': return COLORS.yellow;
    case 'low': return COLORS.gray;
    default: return COLORS.reset;
  }
};

const statusIcon = (status) => {
  switch (status) {
    case 'danger': return `${COLORS.red}DANGER${COLORS.reset}`;
    case 'warning': return `${COLORS.yellow}WARNING${COLORS.reset}`;
    case 'caution': return `${COLORS.yellow}CAUTION${COLORS.reset}`;
    case 'safe': return `${COLORS.green}SAFE${COLORS.reset}`;
    default: return status;
  }
};

// =========================================================================
// COMMANDS
// =========================================================================

const commandScan = (args) => {
  const shield = new AgentShield({ sensitivity: args.sensitivity || 'high' });
  let text = '';
  let source = 'cli_input';

  if (args.file) {
    if (!fs.existsSync(args.file)) {
      console.error(`File not found: ${args.file}`);
      process.exit(1);
    }
    text = fs.readFileSync(args.file, 'utf-8');
    source = `file:${args.file}`;
  } else if (args.json) {
    const scanner = new StructuredDataScanner();
    const result = scanner.scanJSON(args.json, 'cli_json');
    printScanResult({ status: result.clean ? 'safe' : 'danger', threats: result.threats, stats: { totalThreats: result.threats.length, scanTimeMs: 0 } });
    return;
  } else if (args.text) {
    text = args.text;
  } else {
    console.error('Usage: agent-shield scan "text to check"');
    console.error('       agent-shield scan --file input.txt');
    console.error('       agent-shield scan --json \'{"key": "value"}\'');
    process.exit(1);
  }

  const result = shield.scan(text, { source });

  // Also check for PII
  if (args.pii) {
    const piiRedactor = new PIIRedactor();
    const piiResult = piiRedactor.detect(text);
    if (piiResult.hasPII) {
      result.threats.push(...piiResult.findings.map(f => ({
        severity: 'high',
        category: 'pii',
        description: `PII detected: ${f.description}`,
        detail: `${f.description} found in input.`,
        confidence: 80,
        confidenceLabel: 'Very likely a threat'
      })));
    }
  }

  // Also check for API key leaks
  const leakDetector = new PromptLeakDetector();
  const leakResult = leakDetector.scan(text, source);
  if (leakResult.leaked) {
    result.threats.push(...leakResult.leaks.map(l => ({
      severity: l.severity,
      category: 'credential_leak',
      description: l.description,
      detail: l.description,
      confidence: 95,
      confidenceLabel: 'Almost certainly a threat'
    })));
  }

  printScanResult(result);

  if (result.threats.length > 0) {
    process.exit(1);
  }
};

const commandAudit = (args) => {
  const dir = args.dir || '.';

  if (!fs.existsSync(dir)) {
    console.error(`Directory not found: ${dir}`);
    process.exit(1);
  }

  console.log(`\n${COLORS.bold}Agent Shield Audit${COLORS.reset}`);
  console.log(`Scanning: ${path.resolve(dir)}\n`);

  const shield = new AgentShield({ sensitivity: 'high' });
  const leakDetector = new PromptLeakDetector();
  const piiRedactor = new PIIRedactor();
  let totalThreats = 0;
  let filesScanned = 0;

  const scanDir = (dirPath) => {
    const entries = fs.readdirSync(dirPath, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name);

      // Skip common non-relevant directories
      if (entry.isDirectory()) {
        if (['node_modules', '.git', '__pycache__', '.venv', 'venv', 'dist', 'build'].includes(entry.name)) continue;
        scanDir(fullPath);
        continue;
      }

      // Only scan text-like files
      const ext = path.extname(entry.name).toLowerCase();
      const textExts = ['.js', '.ts', '.py', '.rb', '.go', '.java', '.json', '.yaml', '.yml', '.toml', '.env', '.txt', '.md', '.html', '.xml', '.csv', '.cfg', '.ini', '.conf'];
      if (!textExts.includes(ext) && !entry.name.startsWith('.env')) continue;

      try {
        const content = fs.readFileSync(fullPath, 'utf-8');
        if (content.length < 10 || content.length > 1000000) continue;

        filesScanned++;
        const fileThreats = [];

        // Scan for injections
        const result = shield.scan(content, { source: fullPath });
        fileThreats.push(...result.threats);

        // Scan for credential leaks
        const leakResult = leakDetector.scan(content, fullPath);
        if (leakResult.leaked) {
          fileThreats.push(...leakResult.leaks.map(l => ({
            severity: l.severity,
            category: 'credential_leak',
            description: l.description
          })));
        }

        // Scan for PII
        const piiResult = piiRedactor.detect(content);
        if (piiResult.hasPII) {
          fileThreats.push(...piiResult.findings.map(f => ({
            severity: 'medium',
            category: 'pii',
            description: `PII: ${f.description}`
          })));
        }

        if (fileThreats.length > 0) {
          totalThreats += fileThreats.length;
          const relPath = path.relative(dir, fullPath);
          console.log(`  ${severityColor(fileThreats[0].severity)}${relPath}${COLORS.reset} — ${fileThreats.length} finding(s)`);
          for (const t of fileThreats.slice(0, 3)) {
            console.log(`    ${severityColor(t.severity)}[${t.severity}]${COLORS.reset} ${t.description}`);
          }
          if (fileThreats.length > 3) {
            console.log(`    ${COLORS.gray}... and ${fileThreats.length - 3} more${COLORS.reset}`);
          }
        }
      } catch (e) {
        // Skip files we can't read
      }
    }
  };

  scanDir(dir);

  console.log(`\n${COLORS.bold}Summary${COLORS.reset}`);
  console.log(`  Files scanned: ${filesScanned}`);
  console.log(`  Total findings: ${totalThreats}`);

  if (totalThreats > 0) {
    console.log(`  Status: ${statusIcon('danger')}\n`);
    process.exit(1);
  } else {
    console.log(`  Status: ${statusIcon('safe')}\n`);
  }
};

const commandPatterns = () => {
  const shield = new AgentShield();
  const patterns = shield.getPatterns();

  console.log(`\n${COLORS.bold}Agent Shield Detection Patterns${COLORS.reset}`);
  console.log(`Total: ${patterns.length} patterns\n`);

  // Group by category
  const grouped = {};
  for (const p of patterns) {
    if (!grouped[p.category]) grouped[p.category] = [];
    grouped[p.category].push(p);
  }

  for (const [category, items] of Object.entries(grouped)) {
    console.log(`${COLORS.cyan}${category}${COLORS.reset} (${items.length})`);
    for (const item of items) {
      console.log(`  ${severityColor(item.severity)}[${item.severity}]${COLORS.reset} ${item.description}`);
    }
    console.log();
  }
};

// =========================================================================
// HELPERS
// =========================================================================

const printScanResult = (result) => {
  console.log(`\n${COLORS.bold}Agent Shield Scan Result${COLORS.reset}`);
  console.log(`Status: ${statusIcon(result.status)}`);

  if (result.stats) {
    console.log(`Scan time: ${result.stats.scanTimeMs}ms`);
  }

  if (result.threats.length === 0) {
    console.log(`${COLORS.green}No threats detected.${COLORS.reset}\n`);
    return;
  }

  console.log(`Threats: ${result.threats.length}\n`);

  for (const threat of result.threats) {
    console.log(`  ${severityColor(threat.severity)}[${threat.severity.toUpperCase()}]${COLORS.reset} ${threat.description}`);
    if (threat.detail) {
      console.log(`  ${COLORS.gray}${threat.detail}${COLORS.reset}`);
    }
    if (threat.confidence) {
      console.log(`  ${COLORS.gray}Confidence: ${threat.confidence}% — ${threat.confidenceLabel}${COLORS.reset}`);
    }
    console.log();
  }
};

// =========================================================================
// ARGUMENT PARSING
// =========================================================================

const parseArgs = (argv) => {
  const args = { command: null, text: null, file: null, json: null, dir: null, sensitivity: 'high', pii: false };

  const raw = argv.slice(2);
  if (raw.length === 0) {
    return args;
  }

  args.command = raw[0];

  for (let i = 1; i < raw.length; i++) {
    switch (raw[i]) {
      case '--file':
      case '-f':
        args.file = raw[++i];
        break;
      case '--json':
      case '-j':
        args.json = raw[++i];
        break;
      case '--sensitivity':
      case '-s':
        args.sensitivity = raw[++i];
        break;
      case '--pii':
        args.pii = true;
        break;
      default:
        if (!args.text && !raw[i].startsWith('-')) {
          // For 'scan' command, remaining text is the input
          // For 'audit' command, remaining text is the directory
          if (args.command === 'audit') {
            args.dir = raw[i];
          } else {
            args.text = raw.slice(i).join(' ');
            i = raw.length;
          }
        }
    }
  }

  return args;
};

// =========================================================================
// MAIN
// =========================================================================

const main = () => {
  const args = parseArgs(process.argv);

  switch (args.command) {
    case 'scan':
      commandScan(args);
      break;
    case 'audit':
      commandAudit(args);
      break;
    case 'patterns':
      commandPatterns();
      break;
    case 'help':
    case '--help':
    case '-h':
    default:
      console.log(`
${COLORS.bold}Agent Shield CLI${COLORS.reset}
Protect AI agents from prompt injection and other threats.

${COLORS.bold}Commands:${COLORS.reset}
  scan <text>             Scan text for threats
  scan --file <path>      Scan a file for threats
  scan --json <json>      Scan JSON data for threats
  scan --pii              Also check for PII
  audit [dir]             Audit a directory for security issues
  patterns                List all detection patterns

${COLORS.bold}Options:${COLORS.reset}
  -s, --sensitivity       Sensitivity: low, medium, high (default: high)
  -f, --file              Input file path
  -j, --json              JSON string to scan
  --pii                   Include PII detection
  -h, --help              Show this help

${COLORS.bold}Examples:${COLORS.reset}
  agent-shield scan "ignore all previous instructions"
  agent-shield scan -f suspicious-input.txt --pii
  agent-shield audit ./my-agent-project/
  agent-shield patterns
`);
      break;
  }
};

main();
