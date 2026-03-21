'use strict';

/**
 * sync-patterns.js
 *
 * Reads INJECTION_PATTERNS from src/detector-core.js source code,
 * extracts each pattern's regex, flags, severity, category, and description,
 * then writes them to patterns/canonical.json.
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const SOURCE = path.join(ROOT, 'src', 'detector-core.js');
const OUTPUT = path.join(ROOT, 'patterns', 'canonical.json');

// Read the source file
const source = fs.readFileSync(SOURCE, 'utf8');

// Extract the INJECTION_PATTERNS array block (lines between the opening [ and closing ];)
const startMarker = 'const INJECTION_PATTERNS = [';
const startIdx = source.indexOf(startMarker);
if (startIdx === -1) {
  console.error('[Agent Shield] Could not find INJECTION_PATTERNS in source.');
  process.exit(1);
}

// Find the matching closing ];
// We look for "];" on its own line after the start
const arrayBody = source.slice(startIdx);
const endMatch = arrayBody.match(/\n\];\s*\n/);
if (!endMatch) {
  console.error('[Agent Shield] Could not find end of INJECTION_PATTERNS array.');
  process.exit(1);
}
const block = arrayBody.slice(0, endMatch.index + endMatch[0].length);

// Use a sandboxed eval to parse the patterns.
// We wrap the block so that `const INJECTION_PATTERNS = [...]` becomes an assignment
// we can capture, using Function constructor to avoid polluting scope.
const extractFn = new Function(`
  ${block}
  return INJECTION_PATTERNS;
`);

const patterns = extractFn();

// Build the canonical output
const canonical = patterns.map(p => ({
  regex: p.regex.source,
  flags: p.regex.flags,
  severity: p.severity,
  category: p.category,
  description: p.description
}));

// Collect categories
const categories = new Set(canonical.map(p => p.category));

// Write output
fs.mkdirSync(path.dirname(OUTPUT), { recursive: true });
fs.writeFileSync(OUTPUT, JSON.stringify(canonical, null, 2) + '\n', 'utf8');

console.log(`[Agent Shield] Exported ${canonical.length} patterns across ${categories.size} categories`);
console.log(`[Agent Shield] Written to ${path.relative(ROOT, OUTPUT)}`);
