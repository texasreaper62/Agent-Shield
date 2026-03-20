'use strict';

/**
 * Agent Shield — Shared Pattern Code Generator
 *
 * Reads patterns.json (the single source of truth) and generates
 * language-specific pattern files for Python, Go, and Rust SDKs.
 *
 * Usage:
 *   node patterns/generate.js
 *
 * Outputs:
 *   patterns/patterns.py   — Python dict
 *   patterns/patterns.go   — Go map + structs
 *   patterns/patterns.rs   — Rust static array
 */

const fs = require('fs');
const path = require('path');

const PATTERNS_JSON = path.join(__dirname, 'patterns.json');

// ---------------------------------------------------------------------------
// Load patterns
// ---------------------------------------------------------------------------

if (!fs.existsSync(PATTERNS_JSON)) {
  console.error('[Agent Shield] patterns.json not found. Run the extraction first.');
  process.exit(1);
}

const data = JSON.parse(fs.readFileSync(PATTERNS_JSON, 'utf-8'));
const { version, generatedAt, patterns, obfuscation } = data;

console.log(`[Agent Shield] Loaded ${patterns.length} patterns (v${version})`);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Escapes a string for embedding inside a Go raw string literal (backticks).
 * Go raw strings cannot contain backticks, so we fall back to interpreted strings.
 * @param {string} s
 * @returns {{ literal: string, raw: boolean }}
 */
const goString = (s) => {
  if (!s.includes('`')) {
    return { literal: '`' + s + '`', raw: true };
  }
  // Use interpreted string — escape backslashes and double quotes
  const escaped = s.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  return { literal: '"' + escaped + '"', raw: false };
};

/**
 * Escapes a string for a Python raw string literal.
 * @param {string} s
 * @returns {string}
 */
const pyRawString = (s) => {
  // Python raw strings can't end in an odd number of backslashes
  // and can't contain the quote character unescaped.
  if (!s.includes("'") && !s.endsWith('\\')) {
    return "r'" + s + "'";
  }
  if (!s.includes('"') && !s.endsWith('\\')) {
    return 'r"' + s + '"';
  }
  // Fall back to regular string with escaping
  const escaped = s.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
  return "'" + escaped + "'";
};

/**
 * Escapes a string for a Rust raw string literal.
 * @param {string} s
 * @returns {string}
 */
const rustRawString = (s) => {
  // Find the minimum number of # needed
  let hashes = 0;
  let candidate = '"';
  while (s.includes(candidate)) {
    hashes++;
    candidate = '#'.repeat(hashes) + '"';
  }
  const h = '#'.repeat(hashes);
  return `r${h}"${s}"${h}`;
};

// ---------------------------------------------------------------------------
// Python generator
// ---------------------------------------------------------------------------

const generatePython = () => {
  const lines = [];
  lines.push('"""');
  lines.push('Agent Shield - Shared Detection Patterns');
  lines.push(`Auto-generated from patterns.json v${version} on ${generatedAt}.`);
  lines.push(`Total patterns: ${patterns.length}`);
  lines.push('');
  lines.push('DO NOT EDIT — regenerate with: node patterns/generate.js');
  lines.push('"""');
  lines.push('');
  lines.push('import re');
  lines.push('');
  lines.push(`PATTERNS_VERSION = "${version}"`);
  lines.push(`PATTERNS_GENERATED_AT = "${generatedAt}"`);
  lines.push('');
  lines.push('INJECTION_PATTERNS = [');

  for (const p of patterns) {
    const flagStr = p.flags.includes('i') ? 're.IGNORECASE' : '0';
    const multiline = p.flags.includes('m') ? ' | re.MULTILINE' : '';
    const dotall = p.flags.includes('s') ? ' | re.DOTALL' : '';
    const allFlags = flagStr + multiline + dotall;

    lines.push('    {');
    lines.push(`        "id": "${p.id}",`);
    lines.push(`        "regex": re.compile(${pyRawString(p.regex)}, ${allFlags}),`);
    lines.push(`        "category": "${p.category}",`);
    lines.push(`        "severity": "${p.severity}",`);
    lines.push(`        "description": ${JSON.stringify(p.description)},`);
    lines.push(`        "detail": ${JSON.stringify(p.detail)},`);
    lines.push(`        "tags": ${JSON.stringify(p.tags)},`);
    lines.push('    },');
  }

  lines.push(']');
  lines.push('');

  // Homoglyph map
  lines.push('HOMOGLYPH_MAP = {');
  for (const [codepoint, latin] of Object.entries(obfuscation.homoglyphs)) {
    const cp = parseInt(codepoint.replace('U+', ''), 16);
    const escaped = latin === '' ? "''" : JSON.stringify(latin);
    lines.push(`    "\\u${cp.toString(16).padStart(4, '0')}": ${escaped},`);
  }
  lines.push('}');
  lines.push('');

  // Leetspeak map
  lines.push('LEETSPEAK_MAP = {');
  for (const [k, v] of Object.entries(obfuscation.leetspeak)) {
    lines.push(`    ${JSON.stringify(k)}: ${JSON.stringify(v)},`);
  }
  lines.push('}');
  lines.push('');

  return lines.join('\n');
};

// ---------------------------------------------------------------------------
// Go generator
// ---------------------------------------------------------------------------

const generateGo = () => {
  const lines = [];
  lines.push('// Code generated by patterns/generate.js — DO NOT EDIT.');
  lines.push('//');
  lines.push(`// Agent Shield - Shared Detection Patterns v${version}`);
  lines.push(`// Generated: ${generatedAt} | Total patterns: ${patterns.length}`);
  lines.push('');
  lines.push('package shield');
  lines.push('');
  lines.push('import "regexp"');
  lines.push('');
  lines.push(`const PatternsVersion = "${version}"`);
  lines.push(`const PatternsGeneratedAt = "${generatedAt}"`);
  lines.push('');

  // Pattern struct
  lines.push('// Pattern represents a single detection pattern.');
  lines.push('type Pattern struct {');
  lines.push('\tID          string');
  lines.push('\tRegex       *regexp.Regexp');
  lines.push('\tCategory    string');
  lines.push('\tSeverity    string');
  lines.push('\tDescription string');
  lines.push('\tDetail      string');
  lines.push('\tTags        []string');
  lines.push('}');
  lines.push('');

  // Build patterns — use init() to compile regexps
  lines.push('// InjectionPatterns contains all compiled detection patterns.');
  lines.push('var InjectionPatterns []Pattern');
  lines.push('');
  lines.push('func init() {');
  lines.push(`\tInjectionPatterns = make([]Pattern, 0, ${patterns.length})`);
  lines.push('');

  for (const p of patterns) {
    // Go regexp uses RE2 which doesn't support some PCRE features.
    // We prefix (?i) for case-insensitive and (?m) for multiline.
    let goRegex = p.regex;
    let prefix = '';
    if (p.flags.includes('i')) prefix += 'i';
    if (p.flags.includes('m')) prefix += 'm';
    if (p.flags.includes('s')) prefix += 's';
    if (prefix) goRegex = `(?${prefix})` + goRegex;

    const { literal } = goString(goRegex);
    const descStr = goString(p.description).literal;
    const detailStr = goString(p.detail).literal;
    const tagsStr = p.tags.map(t => `"${t}"`).join(', ');

    lines.push(`\tInjectionPatterns = append(InjectionPatterns, Pattern{`);
    lines.push(`\t\tID:          "${p.id}",`);
    lines.push(`\t\tRegex:       regexp.MustCompile(${literal}),`);
    lines.push(`\t\tCategory:    "${p.category}",`);
    lines.push(`\t\tSeverity:    "${p.severity}",`);
    lines.push(`\t\tDescription: ${descStr},`);
    lines.push(`\t\tDetail:      ${detailStr},`);
    lines.push(`\t\tTags:        []string{${tagsStr}},`);
    lines.push(`\t})`);
  }

  lines.push('}');
  lines.push('');

  // Homoglyph map
  lines.push('// HomoglyphMap maps Unicode look-alike characters to their Latin equivalents.');
  lines.push('var HomoglyphMap = map[rune]rune{');
  for (const [codepoint, latin] of Object.entries(obfuscation.homoglyphs)) {
    const cp = parseInt(codepoint.replace('U+', ''), 16);
    if (latin === '') {
      // Zero-width / combining chars — map to 0 (to be stripped)
      lines.push(`\t0x${cp.toString(16).padStart(4, '0')}: 0,`);
    } else {
      lines.push(`\t0x${cp.toString(16).padStart(4, '0')}: '${latin}',`);
    }
  }
  lines.push('}');
  lines.push('');

  // Leetspeak map
  lines.push('// LeetspeakMap maps leetspeak substitutions to their original letters.');
  lines.push('var LeetspeakMap = map[rune]rune{');
  for (const [k, v] of Object.entries(obfuscation.leetspeak)) {
    lines.push(`\t'${k}': '${v}',`);
  }
  lines.push('}');
  lines.push('');

  return lines.join('\n');
};

// ---------------------------------------------------------------------------
// Rust generator
// ---------------------------------------------------------------------------

const generateRust = () => {
  const lines = [];
  lines.push('// Code generated by patterns/generate.js — DO NOT EDIT.');
  lines.push('//');
  lines.push(`// Agent Shield - Shared Detection Patterns v${version}`);
  lines.push(`// Generated: ${generatedAt} | Total patterns: ${patterns.length}`);
  lines.push('');
  lines.push('use once_cell::sync::Lazy;');
  lines.push('use regex::Regex;');
  lines.push('');
  lines.push(`pub const PATTERNS_VERSION: &str = "${version}";`);
  lines.push(`pub const PATTERNS_GENERATED_AT: &str = "${generatedAt}";`);
  lines.push('');

  // Pattern struct
  lines.push('/// A single detection pattern.');
  lines.push('#[derive(Debug)]');
  lines.push('pub struct Pattern {');
  lines.push('    pub id: &\'static str,');
  lines.push('    pub regex: &\'static Lazy<Regex>,');
  lines.push('    pub category: &\'static str,');
  lines.push('    pub severity: &\'static str,');
  lines.push('    pub description: &\'static str,');
  lines.push('    pub detail: &\'static str,');
  lines.push('    pub tags: &\'static [&\'static str],');
  lines.push('}');
  lines.push('');

  // Generate static Lazy<Regex> for each pattern
  for (const p of patterns) {
    let rustRegex = p.regex;
    let prefix = '';
    if (p.flags.includes('i')) prefix += 'i';
    if (p.flags.includes('m')) prefix += 'm';
    if (p.flags.includes('s')) prefix += 's';
    if (prefix) rustRegex = `(?${prefix})` + rustRegex;

    const varName = `REGEX_${p.id.replace(/-/g, '_')}`;
    lines.push(`static ${varName}: Lazy<Regex> = Lazy::new(|| Regex::new(${rustRawString(rustRegex)}).unwrap());`);
  }
  lines.push('');

  // Generate the patterns array
  lines.push(`/// All ${patterns.length} detection patterns.`);
  lines.push(`pub static INJECTION_PATTERNS: [Pattern; ${patterns.length}] = [`);

  for (const p of patterns) {
    const varName = `REGEX_${p.id.replace(/-/g, '_')}`;
    const tagsStr = p.tags.map(t => `"${t}"`).join(', ');

    lines.push('    Pattern {');
    lines.push(`        id: "${p.id}",`);
    lines.push(`        regex: &${varName},`);
    lines.push(`        category: "${p.category}",`);
    lines.push(`        severity: "${p.severity}",`);
    lines.push(`        description: ${rustRawString(p.description)},`);
    lines.push(`        detail: ${rustRawString(p.detail)},`);
    lines.push(`        tags: &[${tagsStr}],`);
    lines.push('    },');
  }

  lines.push('];');
  lines.push('');

  // Homoglyph map
  lines.push('/// Unicode homoglyph to Latin equivalent mapping.');
  const homoglyphEntries = Object.entries(obfuscation.homoglyphs);
  lines.push(`pub static HOMOGLYPH_MAP: [(char, Option<char>); ${homoglyphEntries.length}] = [`);
  for (const [codepoint, latin] of homoglyphEntries) {
    const cp = parseInt(codepoint.replace('U+', ''), 16);
    const charEscape = `'\\u{${cp.toString(16)}}'`;
    if (latin === '') {
      lines.push(`    (${charEscape}, None),`);
    } else {
      lines.push(`    (${charEscape}, Some('${latin}')),`);
    }
  }
  lines.push('];');
  lines.push('');

  // Leetspeak map
  const leetEntries = Object.entries(obfuscation.leetspeak);
  lines.push('/// Leetspeak substitution mapping.');
  lines.push(`pub static LEETSPEAK_MAP: [(char, char); ${leetEntries.length}] = [`);
  for (const [k, v] of leetEntries) {
    lines.push(`    ('${k}', '${v}'),`);
  }
  lines.push('];');
  lines.push('');

  return lines.join('\n');
};

// ---------------------------------------------------------------------------
// Write output files
// ---------------------------------------------------------------------------

const write = (filename, content) => {
  const outPath = path.join(__dirname, filename);
  fs.writeFileSync(outPath, content);
  console.log(`[Agent Shield] Generated ${outPath}`);
};

write('patterns.py', generatePython());
write('patterns.go', generateGo());
write('patterns.rs', generateRust());

console.log(`\n[Agent Shield] All done. ${patterns.length} patterns generated for Python, Go, and Rust.`);
