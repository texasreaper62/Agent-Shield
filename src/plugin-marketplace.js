'use strict';

/**
 * Agent Shield — Plugin Marketplace (v2.0)
 *
 * Registry and marketplace for community-contributed detection plugins.
 * Supports local plugin directories and remote registries.
 * Includes quality scoring, safety validation, and version management.
 *
 * Zero dependencies — uses Node.js built-in modules only.
 */

const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const crypto = require('crypto');

// =========================================================================
// PLUGIN SCHEMA
// =========================================================================

/**
 * Required fields for a valid plugin manifest.
 */
const REQUIRED_FIELDS = ['name', 'version', 'description', 'author', 'patterns'];
const SEMVER_REGEX = /^\d+\.\d+\.\d+$/;

// =========================================================================
// PLUGIN VALIDATOR
// =========================================================================

/**
 * Validates plugin manifests and pattern definitions for safety and quality.
 */
class PluginValidator {
  /**
   * Validate a plugin manifest object.
   * @param {object} manifest - The plugin manifest.
   * @returns {object} { valid: boolean, errors: string[], warnings: string[], score: number }
   */
  validate(manifest) {
    const errors = [];
    const warnings = [];
    let score = 100;

    // Required fields
    for (const field of REQUIRED_FIELDS) {
      if (!manifest[field]) {
        errors.push(`Missing required field: "${field}"`);
        score -= 20;
      }
    }

    // Name validation
    if (manifest.name) {
      if (typeof manifest.name !== 'string' || manifest.name.length < 3) {
        errors.push('Plugin name must be a string of at least 3 characters.');
        score -= 10;
      }
      if (!/^[a-z0-9-]+$/.test(manifest.name)) {
        errors.push('Plugin name must be lowercase alphanumeric with dashes only.');
        score -= 10;
      }
    }

    // Version validation
    if (manifest.version && !SEMVER_REGEX.test(manifest.version)) {
      errors.push('Version must follow semver format (e.g., 1.0.0).');
      score -= 10;
    }

    // Patterns validation
    if (manifest.patterns) {
      if (!Array.isArray(manifest.patterns)) {
        errors.push('Patterns must be an array.');
        score -= 20;
      } else {
        for (let i = 0; i < manifest.patterns.length; i++) {
          const p = manifest.patterns[i];
          if (!p.regex && !p.pattern) {
            errors.push(`Pattern ${i}: must have a "regex" or "pattern" field.`);
            score -= 5;
          }
          if (!p.severity) {
            warnings.push(`Pattern ${i}: missing severity (defaulting to "medium").`);
            score -= 2;
          }
          if (!p.category) {
            warnings.push(`Pattern ${i}: missing category.`);
            score -= 2;
          }
          if (!p.description) {
            warnings.push(`Pattern ${i}: missing description.`);
            score -= 2;
          }

          // Safety: check regex isn't catastrophically backtracking
          if (p.regex || p.pattern) {
            const regexStr = typeof (p.regex || p.pattern) === 'string' ? (p.regex || p.pattern) : '';
            if (regexStr && this._isReDoSRisk(regexStr)) {
              warnings.push(`Pattern ${i}: regex may be vulnerable to ReDoS (catastrophic backtracking).`);
              score -= 10;
            }
          }
        }

        if (manifest.patterns.length === 0) {
          errors.push('Plugin must define at least one pattern.');
          score -= 15;
        }

        if (manifest.patterns.length > 100) {
          warnings.push('Plugin has over 100 patterns — consider splitting into multiple plugins.');
          score -= 5;
        }
      }
    }

    // Metadata checks
    if (!manifest.description || manifest.description.length < 10) {
      warnings.push('Description should be at least 10 characters.');
      score -= 5;
    }

    if (!manifest.license) {
      warnings.push('No license specified. Recommend MIT or Apache-2.0.');
      score -= 5;
    }

    if (!manifest.tags || !Array.isArray(manifest.tags) || manifest.tags.length === 0) {
      warnings.push('Adding tags helps with plugin discovery.');
      score -= 3;
    }

    if (manifest.testCases && Array.isArray(manifest.testCases) && manifest.testCases.length >= 3) {
      score += 5; // Bonus for including tests
    } else {
      warnings.push('Including testCases improves plugin quality score.');
    }

    score = Math.max(0, Math.min(100, score));

    return {
      valid: errors.length === 0,
      errors,
      warnings,
      score,
      grade: score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 60 ? 'D' : 'F'
    };
  }

  /**
   * Run test cases defined in a plugin manifest.
   * @param {object} manifest - Plugin manifest with testCases.
   * @returns {object} { passed: number, failed: number, results: Array }
   */
  runTests(manifest) {
    if (!manifest.testCases || !Array.isArray(manifest.testCases)) {
      return { passed: 0, failed: 0, results: [] };
    }

    const results = [];
    let passed = 0;
    let failed = 0;

    for (const tc of manifest.testCases) {
      const { input, shouldDetect } = tc;
      let detected = false;

      for (const p of manifest.patterns || []) {
        try {
          const regex = p.regex instanceof RegExp ? p.regex : new RegExp(typeof p.regex === 'string' ? p.regex : p.pattern, 'i');
          if (regex.test(input)) {
            detected = true;
            break;
          }
        } catch (e) {
          // Invalid regex
        }
      }

      const pass = detected === shouldDetect;
      if (pass) passed++;
      else failed++;

      results.push({ input: input.substring(0, 80), expected: shouldDetect, actual: detected, pass });
    }

    return { passed, failed, total: results.length, results };
  }

  /** @private */
  _isReDoSRisk(regexStr) {
    // Heuristic: nested quantifiers like (a+)+ or (a|b)* are ReDoS risks
    return /\([^)]*[+*][^)]*\)[+*]/.test(regexStr) || /\([^)]*\|[^)]*\)[+*]{2,}/.test(regexStr);
  }
}

// =========================================================================
// PLUGIN REGISTRY
// =========================================================================

/**
 * Local plugin registry. Manages installed plugins, activation, and versioning.
 */
class PluginRegistry {
  /**
   * @param {object} [options]
   * @param {string} [options.pluginDir] - Directory to store/load plugins.
   * @param {boolean} [options.autoValidate=true] - Validate plugins on registration.
   */
  constructor(options = {}) {
    this.pluginDir = options.pluginDir || null;
    this.autoValidate = options.autoValidate !== false;
    this._plugins = new Map();
    this._activePlugins = new Set();
    this._validator = new PluginValidator();
    this._installHistory = [];

    // Load plugins from directory if configured
    if (this.pluginDir) {
      this._loadFromDir();
    }

    console.log('[Agent Shield] PluginRegistry initialized (plugins: %d)', this._plugins.size);
  }

  /**
   * Register a plugin.
   * @param {object} manifest - Plugin manifest object.
   * @returns {object} { success: boolean, validation?: object, error?: string }
   */
  register(manifest) {
    if (this.autoValidate) {
      const validation = this._validator.validate(manifest);
      if (!validation.valid) {
        return { success: false, validation, error: `Validation failed: ${validation.errors.join('; ')}` };
      }
    }

    const id = manifest.name;
    const existing = this._plugins.get(id);

    if (existing && existing.version === manifest.version) {
      return { success: false, error: `Plugin "${id}" v${manifest.version} is already registered.` };
    }

    // Compile regex patterns
    const compiled = this._compilePatterns(manifest);

    this._plugins.set(id, {
      ...manifest,
      compiledPatterns: compiled,
      installedAt: Date.now(),
      checksum: this._checksum(JSON.stringify(manifest))
    });

    this._activePlugins.add(id);
    this._installHistory.push({ action: 'install', plugin: id, version: manifest.version, timestamp: Date.now() });

    console.log('[Agent Shield] Plugin registered: %s v%s (%d patterns)', id, manifest.version, compiled.length);

    // Save to directory if configured
    if (this.pluginDir) {
      this._savePlugin(id, manifest);
    }

    const validation = this._validator.validate(manifest);
    return { success: true, validation };
  }

  /**
   * Unregister a plugin.
   * @param {string} name - Plugin name.
   * @returns {boolean}
   */
  unregister(name) {
    const removed = this._plugins.delete(name);
    this._activePlugins.delete(name);
    if (removed) {
      this._installHistory.push({ action: 'uninstall', plugin: name, timestamp: Date.now() });
    }
    return removed;
  }

  /**
   * Enable a registered plugin.
   * @param {string} name
   * @returns {boolean}
   */
  enable(name) {
    if (!this._plugins.has(name)) return false;
    this._activePlugins.add(name);
    return true;
  }

  /**
   * Disable a plugin (keeps it registered but inactive).
   * @param {string} name
   * @returns {boolean}
   */
  disable(name) {
    return this._activePlugins.delete(name);
  }

  /**
   * Get a registered plugin by name.
   * @param {string} name
   * @returns {object|null}
   */
  get(name) {
    return this._plugins.get(name) || null;
  }

  /**
   * List all registered plugins.
   * @returns {Array<object>}
   */
  list() {
    return [...this._plugins.entries()].map(([name, plugin]) => ({
      name,
      version: plugin.version,
      description: plugin.description,
      author: plugin.author,
      patterns: plugin.compiledPatterns ? plugin.compiledPatterns.length : 0,
      active: this._activePlugins.has(name),
      tags: plugin.tags || [],
      installedAt: plugin.installedAt
    }));
  }

  /**
   * Search plugins by keyword.
   * @param {string} query
   * @returns {Array<object>}
   */
  search(query) {
    const lower = query.toLowerCase();
    return this.list().filter(p =>
      p.name.includes(lower) ||
      p.description.toLowerCase().includes(lower) ||
      (p.tags && p.tags.some(t => t.toLowerCase().includes(lower)))
    );
  }

  /**
   * Scan text against all active plugin patterns.
   * @param {string} text - Text to scan.
   * @returns {object} { threats: Array, pluginsUsed: number }
   */
  scan(text) {
    if (!text || text.length < 5) return { threats: [], pluginsUsed: 0 };

    const threats = [];
    let pluginsUsed = 0;

    for (const name of this._activePlugins) {
      const plugin = this._plugins.get(name);
      if (!plugin || !plugin.compiledPatterns) continue;

      pluginsUsed++;
      for (const pattern of plugin.compiledPatterns) {
        try {
          if (pattern.regex.test(text)) {
            threats.push({
              severity: pattern.severity || 'medium',
              category: pattern.category || 'plugin_detection',
              description: pattern.description || `Detected by plugin: ${name}`,
              detail: `Plugin "${name}" v${plugin.version}: ${pattern.detail || pattern.description || 'Pattern matched'}`,
              plugin: name
            });
          }
        } catch (e) {
          // Skip broken patterns
        }
      }
    }

    return { threats, pluginsUsed };
  }

  /**
   * Get registry statistics.
   * @returns {object}
   */
  getStats() {
    let totalPatterns = 0;
    for (const plugin of this._plugins.values()) {
      totalPatterns += (plugin.compiledPatterns || []).length;
    }

    return {
      totalPlugins: this._plugins.size,
      activePlugins: this._activePlugins.size,
      totalPatterns,
      installHistory: this._installHistory.length
    };
  }

  /** @private */
  _compilePatterns(manifest) {
    if (!manifest.patterns || !Array.isArray(manifest.patterns)) return [];

    return manifest.patterns.map(p => {
      let regex;
      try {
        if (p.regex instanceof RegExp) {
          regex = p.regex;
        } else if (typeof p.regex === 'string') {
          regex = new RegExp(p.regex, 'i');
        } else if (typeof p.pattern === 'string') {
          regex = new RegExp(p.pattern, 'i');
        } else {
          return null;
        }
      } catch (e) {
        return null;
      }

      return {
        regex,
        severity: p.severity || 'medium',
        category: p.category || 'plugin_detection',
        description: p.description || '',
        detail: p.detail || ''
      };
    }).filter(Boolean);
  }

  /** @private */
  _checksum(str) {
    return crypto.createHash('sha256').update(str).digest('hex').substring(0, 16);
  }

  /** @private */
  _loadFromDir() {
    if (!this.pluginDir || !fs.existsSync(this.pluginDir)) return;

    try {
      const files = fs.readdirSync(this.pluginDir).filter(f => f.endsWith('.json'));
      for (const file of files) {
        try {
          const content = fs.readFileSync(path.join(this.pluginDir, file), 'utf-8');
          const manifest = JSON.parse(content);
          this.register(manifest);
        } catch (e) {
          console.warn('[Agent Shield] Failed to load plugin %s: %s', file, e.message);
        }
      }
    } catch (e) {
      console.warn('[Agent Shield] Failed to read plugin directory: %s', e.message);
    }
  }

  /** @private */
  _savePlugin(name, manifest) {
    if (!this.pluginDir) return;
    try {
      if (!fs.existsSync(this.pluginDir)) {
        fs.mkdirSync(this.pluginDir, { recursive: true });
      }
      fs.writeFileSync(
        path.join(this.pluginDir, `${name}.json`),
        JSON.stringify(manifest, null, 2)
      );
    } catch (e) {
      console.warn('[Agent Shield] Failed to save plugin %s: %s', name, e.message);
    }
  }
}

// =========================================================================
// MARKETPLACE CLIENT
// =========================================================================

/**
 * Client for discovering and fetching plugins from a remote marketplace.
 */
class MarketplaceClient {
  /**
   * @param {object} [options]
   * @param {string} [options.registryUrl] - Base URL of the plugin registry API.
   * @param {number} [options.timeoutMs=10000] - Request timeout.
   * @param {PluginRegistry} [options.registry] - Local registry to install into.
   */
  constructor(options = {}) {
    this.registryUrl = options.registryUrl || null;
    this.timeoutMs = options.timeoutMs || 10000;
    this.registry = options.registry || null;
    this._cache = new Map();

    console.log('[Agent Shield] MarketplaceClient initialized (registry: %s)', this.registryUrl || 'none');
  }

  /**
   * Fetch available plugins from the marketplace.
   * @param {object} [filters] - { category, minScore, query }
   * @returns {Promise<Array<object>>} List of available plugins.
   */
  async browse(filters = {}) {
    if (!this.registryUrl) {
      return { plugins: [], error: 'No registry URL configured.' };
    }

    try {
      const url = new URL('/api/plugins', this.registryUrl);
      if (filters.category) url.searchParams.set('category', filters.category);
      if (filters.query) url.searchParams.set('q', filters.query);
      if (filters.minScore) url.searchParams.set('minScore', filters.minScore);

      const response = await this._fetch(url.toString());
      return { plugins: response.plugins || response || [], error: null };
    } catch (err) {
      return { plugins: [], error: err.message };
    }
  }

  /**
   * Install a plugin from the marketplace by name.
   * @param {string} name - Plugin name.
   * @returns {Promise<object>} { success: boolean, plugin?: object, error?: string }
   */
  async install(name) {
    if (!this.registryUrl) {
      return { success: false, error: 'No registry URL configured.' };
    }
    if (!this.registry) {
      return { success: false, error: 'No local registry configured.' };
    }

    try {
      const url = new URL(`/api/plugins/${encodeURIComponent(name)}`, this.registryUrl);
      const manifest = await this._fetch(url.toString());

      const result = this.registry.register(manifest);
      return result;
    } catch (err) {
      return { success: false, error: err.message };
    }
  }

  /**
   * Publish a plugin to the marketplace.
   * @param {object} manifest - Plugin manifest.
   * @returns {Promise<object>} { success: boolean, error?: string }
   */
  async publish(manifest) {
    if (!this.registryUrl) {
      return { success: false, error: 'No registry URL configured.' };
    }

    const validator = new PluginValidator();
    const validation = validator.validate(manifest);
    if (!validation.valid) {
      return { success: false, error: `Validation failed: ${validation.errors.join('; ')}`, validation };
    }

    try {
      const url = new URL('/api/plugins', this.registryUrl);
      await this._post(url.toString(), manifest);
      return { success: true, validation };
    } catch (err) {
      return { success: false, error: err.message };
    }
  }

  /** @private */
  _fetch(url) {
    return new Promise((resolve, reject) => {
      const parsed = new URL(url);
      const lib = parsed.protocol === 'https:' ? https : http;

      const req = lib.get({
        hostname: parsed.hostname,
        port: parsed.port,
        path: parsed.pathname + parsed.search,
        timeout: this.timeoutMs
      }, (res) => {
        let data = '';
        res.on('data', chunk => { data += chunk; });
        res.on('end', () => {
          try { resolve(JSON.parse(data)); }
          catch (e) { reject(new Error('Invalid JSON response')); }
        });
      });

      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('Request timed out')); });
    });
  }

  /** @private */
  _post(url, body) {
    return new Promise((resolve, reject) => {
      const parsed = new URL(url);
      const lib = parsed.protocol === 'https:' ? https : http;
      const payload = JSON.stringify(body);

      const req = lib.request({
        hostname: parsed.hostname,
        port: parsed.port,
        path: parsed.pathname,
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) },
        timeout: this.timeoutMs
      }, (res) => {
        let data = '';
        res.on('data', chunk => { data += chunk; });
        res.on('end', () => {
          try { resolve(JSON.parse(data)); }
          catch (e) { reject(new Error('Invalid JSON response')); }
        });
      });

      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('Request timed out')); });
      req.write(payload);
      req.end();
    });
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = { PluginRegistry, PluginValidator, MarketplaceClient, REQUIRED_FIELDS };
