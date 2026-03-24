'use strict';

/**
 * Agent Shield Lint Check
 *
 * Simple static analysis checks — no external dependencies required.
 * Validates code style rules defined in CLAUDE.md.
 *
 * Run with: node test/lint.js
 */

const fs = require('fs');
const path = require('path');

const SRC_DIR = path.join(__dirname, '..', 'src');
const JS_FILES = fs.readdirSync(SRC_DIR)
  .filter(f => f.endsWith('.js'))
  .map(f => path.join(SRC_DIR, f));

let errors = 0;

const check = (file, lineNum, condition, message) => {
  if (condition) {
    errors++;
    const basename = path.basename(file);
    console.log(`  ${basename}:${lineNum} — ${message}`);
  }
};

console.log('Agent Shield Lint Check\n');

for (const file of JS_FILES) {
  const content = fs.readFileSync(file, 'utf8');
  const lines = content.split('\n');
  const basename = path.basename(file);

  // Check for 'use strict'
  if (!content.startsWith("'use strict'")) {
    check(file, 1, true, "File must start with 'use strict'");
  }

  // Check for var usage
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    // Skip comments and strings
    if (trimmed.startsWith('//') || trimmed.startsWith('*')) continue;

    // No var declarations
    if (/\bvar\s+/.test(trimmed) && !trimmed.startsWith('//') && !trimmed.startsWith('*')) {
      check(file, i + 1, true, `Use 'const' or 'let' instead of 'var': ${trimmed.substring(0, 60)}`);
    }

    // No console.error without [Agent Shield] prefix (except in test files)
    if (/console\.(log|warn|error)\s*\(/.test(trimmed) && !basename.includes('test')) {
      // Skip GitHub Actions annotation/output format (::error::, ::set-output, etc.)
      if (/`::|::/.test(trimmed)) continue;
      // Skip console.log inside string literals (code snippets / templates)
      if (/['"`].*console\.(log|warn|error)/.test(trimmed)) continue;
      // Skip console.log inside arrow functions within template strings
      if (/=>\s*console\.(log|warn|error)/.test(trimmed) && /return\s+`|`/.test(lines.slice(Math.max(0, i - 20), i).join('\n'))) continue;
      // Skip lines that push string containing console.log (generated code)
      if (/\.push\(/.test(trimmed)) continue;
      if (!/\[Agent Shield\]/.test(trimmed) && !/console\.(warn|error)\s*\(\s*'\[Agent Shield\]/.test(trimmed)) {
        // Allow console calls that reference [Agent Shield] on the same line
        // Also allow calls using LOG_PREFIX or similar prefix constants
        if (!/Agent Shield/.test(trimmed) && !/LOG_PREFIX|SHIELD_PREFIX|PREFIX/.test(trimmed)) {
          check(file, i + 1, true, `Console output should be prefixed with [Agent Shield]: ${trimmed.substring(0, 60)}`);
        }
      }
    }

    // Check for trailing whitespace
    if (line.length > 0 && line !== lines[lines.length - 1] && /\s+$/.test(line)) {
      check(file, i + 1, true, 'Trailing whitespace');
    }
  }

  // Check for tabs (we use spaces)
  if (/\t/.test(content)) {
    check(file, 0, true, 'File contains tabs — use spaces for indentation');
  }
}

console.log('');
if (errors > 0) {
  console.log(`Found ${errors} issue${errors !== 1 ? 's' : ''}.`);
  process.exit(1);
} else {
  console.log('All checks passed!');
  process.exit(0);
}
