'use strict';

/**
 * Agent Shield — Customer-Specific Learning (H2)
 *
 * Reads a customer's agent codebase + (optionally) their traffic logs and
 * generates rules tuned to *their* attack surface. The generic 300-pattern
 * firehose stays in place; these rules layer on top to:
 *
 *   1. Allowlist phrases that look injection-y but are part of the
 *      customer's legitimate prompts/system messages.
 *   2. Allowlist URLs / domains / file paths the agent legitimately touches.
 *   3. Flag tool names that look like the customer's tools (which an
 *      attacker would mimic to confuse the agent).
 *   4. Generate honeypot canary tokens shaped like the customer's real
 *      secrets, so any exfiltration in output is instantly detectable.
 *
 * Pure, zero-dep, read-only. Walks a directory tree with `fs`.
 */

const fs = require('fs');
const path = require('path');

const DEFAULT_INCLUDE = ['.js', '.ts', '.jsx', '.tsx', '.py', '.go', '.rs', '.json', '.yaml', '.yml', '.md', '.mdx', '.toml'];
const DEFAULT_EXCLUDE = ['node_modules', '.git', 'dist', 'build', 'coverage', '__pycache__', '.next', '.cache', 'vendor', 'target'];
const MAX_FILE_BYTES = 256 * 1024;
const MAX_FILES = 5000;

class CustomerLearning {
  constructor(opts = {}) {
    this.include = opts.include || DEFAULT_INCLUDE;
    this.exclude = opts.exclude || DEFAULT_EXCLUDE;
    this.maxFileBytes = opts.maxFileBytes || MAX_FILE_BYTES;
    this.maxFiles = opts.maxFiles || MAX_FILES;
  }

  /**
   * Walk a directory tree, extract structured features, and synthesize a
   * customer-specific rule profile.
   *
   * @param {string} rootDir
   * @returns {Promise<{profile, summary}>}
   */
  async analyze(rootDir) {
    if (!rootDir || typeof rootDir !== 'string') {
      throw new Error('analyze requires rootDir: string');
    }
    if (!fs.existsSync(rootDir)) {
      throw new Error(`rootDir does not exist: ${rootDir}`);
    }

    const files = this._walk(rootDir);
    const facts = this._extract(files);
    const profile = this._buildProfile(facts);
    return {
      profile,
      summary: {
        filesScanned: files.length,
        rootDir,
        promptStringCount: facts.promptStrings.size,
        urlCount: facts.urls.size,
        toolNameCount: facts.toolNames.size,
        secretShapeCount: facts.secretShapes.size,
        envVarCount: facts.envVars.size,
        domainCount: profile.allowedDomains.length,
      },
    };
  }

  _walk(root) {
    const out = [];
    const stack = [root];
    while (stack.length && out.length < this.maxFiles) {
      const dir = stack.pop();
      let entries;
      try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
      catch (_) { continue; }
      for (const e of entries) {
        const full = path.join(dir, e.name);
        if (this.exclude.some((x) => e.name === x)) continue;
        if (e.isDirectory()) { stack.push(full); continue; }
        const ext = path.extname(e.name).toLowerCase();
        if (!this.include.includes(ext)) continue;
        try {
          const stat = fs.statSync(full);
          if (stat.size > this.maxFileBytes) continue;
          out.push(full);
        } catch (_) { /* skip */ }
        if (out.length >= this.maxFiles) break;
      }
    }
    return out;
  }

  _extract(files) {
    const facts = {
      promptStrings: new Set(),
      urls: new Set(),
      toolNames: new Set(),
      secretShapes: new Set(),
      envVars: new Set(),
      systemPromptHints: [],
    };
    // Patterns:
    //   - URL: any http(s) URL literal
    //   - env var: process.env.FOO / os.environ['FOO'] / os.getenv('FOO')
    //   - tool name: object literal like { name: '...', description: '...' } or
    //     function named tool_xxx / mcp tool def with `name:`
    //   - system prompt: a string variable named systemPrompt / SYSTEM_PROMPT
    const URL_RE = /https?:\/\/[a-zA-Z0-9.\-_]+(?:\/[\w\-./%?&=#]*)?/g;
    const ENV_RE = /(?:process\.env\.|os\.environ\[['"]|os\.getenv\(['"])([A-Z][A-Z0-9_]{2,})(?:['"]?\])?/g;
    const TOOL_NAME_RE = /\bname\s*:\s*['"]([a-z][a-z0-9_]{2,})['"]/g;
    const SYSTEM_PROMPT_RE = /(?:systemPrompt|SYSTEM_PROMPT|system_prompt)\s*[:=]\s*(['"`])([\s\S]{20,300}?)\1/g;
    const SECRET_SHAPE_RE = /(?:sk-[A-Za-z0-9]{16,}|sk-ant-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{12,}|ya29\.[A-Za-z0-9_\-]{16,})/g;

    for (const file of files) {
      let content;
      try { content = fs.readFileSync(file, 'utf8'); }
      catch (_) { continue; }

      let m;
      while ((m = URL_RE.exec(content)) !== null) facts.urls.add(m[0]);
      while ((m = ENV_RE.exec(content)) !== null) facts.envVars.add(m[1]);
      while ((m = TOOL_NAME_RE.exec(content)) !== null) facts.toolNames.add(m[1]);
      while ((m = SYSTEM_PROMPT_RE.exec(content)) !== null) {
        const snippet = m[2].trim();
        if (snippet.length >= 20) {
          facts.promptStrings.add(snippet);
          facts.systemPromptHints.push({ file: path.relative(process.cwd(), file), snippet: snippet.slice(0, 160) });
        }
      }
      while ((m = SECRET_SHAPE_RE.exec(content)) !== null) {
        // Don't store actual secret literals; just record the prefix shape.
        const prefix = m[0].slice(0, 8);
        facts.secretShapes.add(prefix);
      }
      // Reset lastIndex so regexes are reusable across files.
      URL_RE.lastIndex = ENV_RE.lastIndex = TOOL_NAME_RE.lastIndex = SYSTEM_PROMPT_RE.lastIndex = SECRET_SHAPE_RE.lastIndex = 0;
    }
    return facts;
  }

  _buildProfile(facts) {
    const allowedDomains = new Set();
    for (const url of facts.urls) {
      try {
        const u = new URL(url);
        // Skip examples and metadata IPs.
        if (/^(?:127\.|10\.|192\.168\.|169\.254\.|0\.0\.0\.0|example\.com)/.test(u.hostname)) continue;
        allowedDomains.add(u.hostname);
      } catch (_) { /* malformed URL */ }
    }

    const allowedToolNames = Array.from(facts.toolNames).sort();
    const lookalikeToolPatterns = allowedToolNames
      .filter((n) => n.length >= 4)
      .map((n) => ({
        category: 'lookalike_tool',
        regex: new RegExp(`\\b${escapeRe(n)}[a-z0-9_]+|[a-z0-9_]+${escapeRe(n)}\\b`, 'i'),
        severity: 'medium',
        description: `Tool name lookalike of "${n}" — possible attacker impersonation.`,
      }));

    const honeypotCanaries = Array.from(facts.secretShapes)
      .map((prefix) => ({
        prefix,
        canary: `${prefix}CANARY-DO-NOT-USE-${crypto_randomHex(16)}`,
        description: `Honeypot token shaped like the customer's real ${prefix}* secrets; if it appears in agent output, exfiltration is happening.`,
      }));

    const allowedPromptPhrases = Array.from(facts.promptStrings)
      .filter((s) => s.length >= 30)
      .slice(0, 50);

    return {
      allowedDomains: Array.from(allowedDomains).sort(),
      allowedEnvVars: Array.from(facts.envVars).sort(),
      allowedToolNames,
      allowedPromptPhrases,
      lookalikeToolPatterns: lookalikeToolPatterns.slice(0, 50),
      honeypotCanaries,
      systemPromptHints: facts.systemPromptHints.slice(0, 20),
    };
  }

  /**
   * Apply a profile against an input: returns the customer-specific verdict
   * (separate from the deterministic detector). Used by host agents to
   * post-filter generic detector hits.
   *
   * Returns { suppressedReason?: string, additionalThreats: [] }
   */
  evaluate(input, profile) {
    if (typeof input !== 'string' || !profile) return { additionalThreats: [] };

    // 1) Allowlist check: if the input is a substring of an allowed prompt
    //    phrase, suppress overly-aggressive detector hits on that input.
    for (const phrase of (profile.allowedPromptPhrases || [])) {
      if (phrase.includes(input.trim()) && input.trim().length >= 20) {
        return { suppressedReason: 'matches customer system-prompt phrase', additionalThreats: [] };
      }
    }

    const additional = [];
    for (const p of (profile.lookalikeToolPatterns || [])) {
      if (p.regex.test(input)) {
        additional.push({
          category: p.category,
          severity: p.severity,
          description: p.description,
        });
      }
    }
    for (const c of (profile.honeypotCanaries || [])) {
      if (input.includes(c.canary)) {
        additional.push({
          category: 'canary_triggered',
          severity: 'critical',
          description: `Honeypot canary token ${c.prefix}* appeared in output — exfiltration confirmed.`,
        });
      }
    }
    return { additionalThreats: additional };
  }
}

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function crypto_randomHex(n) {
  return require('crypto').randomBytes(n).toString('hex');
}

module.exports = { CustomerLearning, DEFAULT_INCLUDE, DEFAULT_EXCLUDE };
