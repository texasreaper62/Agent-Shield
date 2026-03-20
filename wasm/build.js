'use strict';

/**
 * Agent Shield — WASM/Universal Build Script
 *
 * Reads src/detector-core.js, strips Node.js-specific code,
 * and outputs universal modules:
 *   - dist/agent-shield.esm.js  (ES Modules)
 *   - dist/agent-shield.umd.js  (UMD — browser <script>, require(), AMD)
 *   - dist/agent-shield.min.js  (Minified UMD)
 *
 * Usage: node wasm/build.js
 */

const fs = require('fs');
const path = require('path');

const SRC = path.resolve(__dirname, '..', 'src', 'detector-core.js');
const DIST = path.resolve(__dirname, 'dist');

console.log('[Agent Shield] Build starting...');

// -------------------------------------------------------------------------
// 1. Read source
// -------------------------------------------------------------------------

if (!fs.existsSync(SRC)) {
  console.error(`[Agent Shield] Source not found: ${SRC}`);
  process.exit(1);
}

let source = fs.readFileSync(SRC, 'utf-8');

// -------------------------------------------------------------------------
// 2. Strip Node.js-specific code
// -------------------------------------------------------------------------

// Remove 'use strict' (we add our own wrapper)
source = source.replace(/^'use strict';\s*/m, '');

// Remove module.exports line
source = source.replace(/^module\.exports\s*=\s*\{[^}]*\};\s*$/m, '');

// Remove any require() calls
source = source.replace(/^.*require\s*\([^)]*\).*$/gm, '');

// Remove process.* references (wrap in typeof guard if needed)
source = source.replace(/\bprocess\.exit\s*\([^)]*\)/g, '/* process.exit removed */');
source = source.replace(/\bprocess\.env\b/g, '({})');

// -------------------------------------------------------------------------
// 3. Ensure dist directory exists
// -------------------------------------------------------------------------

if (!fs.existsSync(DIST)) {
  fs.mkdirSync(DIST, { recursive: true });
}

// -------------------------------------------------------------------------
// 4. Build ESM
// -------------------------------------------------------------------------

const esmOutput = `'use strict';

/**
 * Agent Shield — Core Detection Engine (ESM)
 *
 * Universal module that works in browsers, Deno, Bun, and Cloudflare Workers.
 * All detection runs locally — no data ever leaves your environment.
 *
 * @module agent-shield
 */

${source.trim()}

export { scanText, getPatterns, SEVERITY_ORDER, MAX_INPUT_SIZE };
export default { scanText, getPatterns, SEVERITY_ORDER, MAX_INPUT_SIZE };
`;

const esmPath = path.join(DIST, 'agent-shield.esm.js');
fs.writeFileSync(esmPath, esmOutput);
console.log(`[Agent Shield] ESM  -> ${esmPath}`);

// -------------------------------------------------------------------------
// 5. Build UMD
// -------------------------------------------------------------------------

const umdOutput = `'use strict';

/**
 * Agent Shield — Core Detection Engine (UMD)
 *
 * Works with:
 *   - Browser <script> tags (sets window.AgentShield)
 *   - Node.js require()
 *   - AMD / define()
 *
 * All detection runs locally — no data ever leaves your environment.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    // AMD
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS / Node.js
    module.exports = factory();
  } else {
    // Browser global
    root.AgentShield = factory();
  }
}(typeof globalThis !== 'undefined' ? globalThis
  : typeof self !== 'undefined' ? self
  : typeof window !== 'undefined' ? window
  : typeof global !== 'undefined' ? global
  : this, function () {

${source.trim()}

  return { scanText: scanText, getPatterns: getPatterns, SEVERITY_ORDER: SEVERITY_ORDER, MAX_INPUT_SIZE: MAX_INPUT_SIZE };
}));
`;

const umdPath = path.join(DIST, 'agent-shield.umd.js');
fs.writeFileSync(umdPath, umdOutput);
console.log(`[Agent Shield] UMD  -> ${umdPath}`);

// -------------------------------------------------------------------------
// 6. Build minified (basic minification — no external tools)
// -------------------------------------------------------------------------

/**
 * Basic minification: strip comments, collapse whitespace.
 * This is intentionally simple — no AST parsing, no external deps.
 *
 * IMPORTANT: We only strip lines that are pure comments (no code).
 * This avoids breaking regex literals that contain // sequences.
 */
const minify = (code) => {
  const lines = code.split('\n');
  const result = [];

  let inBlockComment = false;

  for (const line of lines) {
    const trimmed = line.trim();

    // Track block comments — but only remove pure-comment lines
    if (inBlockComment) {
      if (trimmed.includes('*/')) {
        inBlockComment = false;
        // If there is code after */, keep that part
        const after = trimmed.substring(trimmed.indexOf('*/') + 2).trim();
        if (after) result.push(after);
      }
      // Skip lines entirely inside block comments
      continue;
    }

    // Start of block comment on a line by itself (or with only whitespace)
    if (/^\s*\/\*/.test(line) && !trimmed.includes('*/')) {
      inBlockComment = true;
      continue;
    }

    // Single-line block comment on its own line: /* ... */
    if (/^\s*\/\*.*\*\/\s*$/.test(line)) {
      continue;
    }

    // Pure single-line comment (entire line is a comment)
    if (/^\s*\/\//.test(line)) {
      continue;
    }

    // Separator lines: // ------- or // =========
    if (/^\s*\/\/\s*[-=]+\s*$/.test(line)) {
      continue;
    }

    // Skip empty lines after stripping
    if (!trimmed) {
      // Keep at most one blank line
      if (result.length > 0 && result[result.length - 1] === '') continue;
      result.push('');
      continue;
    }

    // Remove trailing whitespace
    result.push(line.trimEnd());
  }

  return result.join('\n').trim() + '\n';
};

const minOutput = minify(umdOutput);
const minPath = path.join(DIST, 'agent-shield.min.js');
fs.writeFileSync(minPath, minOutput);
console.log(`[Agent Shield] MIN  -> ${minPath}`);

// -------------------------------------------------------------------------
// 7. Summary
// -------------------------------------------------------------------------

const sizes = [esmPath, umdPath, minPath].map(p => {
  const stat = fs.statSync(p);
  return `  ${path.basename(p)}: ${(stat.size / 1024).toFixed(1)} KB`;
});

console.log('[Agent Shield] Build complete.');
console.log(sizes.join('\n'));
