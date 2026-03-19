'use strict';

/**
 * Agent Shield — Plugin System
 *
 * Lets users write custom detectors as lightweight plugin objects.
 * Plugins are simple objects with a detect() method that returns an array
 * of threat findings. All detection runs locally — no data ever leaves
 * your environment.
 */

const path = require('path');
const fs = require('fs');

// =========================================================================
// HELPERS
// =========================================================================

/**
 * Get current time in ms.
 * @returns {number}
 */
const now = () => {
  if (typeof performance !== 'undefined' && performance.now) {
    return performance.now();
  }
  return Date.now();
};

// =========================================================================
// PLUGIN SANDBOX
// =========================================================================

/**
 * Runs plugins with timeout protection and error isolation.
 * Prevents a misbehaving plugin from crashing the host agent.
 */
class PluginSandbox {
  /**
   * @param {object} [options]
   * @param {number} [options.timeoutMs=100] - Maximum execution time per plugin in ms
   */
  constructor(options = {}) {
    this.timeoutMs = options.timeoutMs || 100;
  }

  /**
   * Execute a plugin's detect() method with timeout and error isolation.
   * @param {object} plugin - Plugin object with detect() method
   * @param {string} text - Text to scan
   * @param {object} [options] - Options passed to detect()
   * @returns {{results: Array, error: string|null, durationMs: number}}
   */
  run(plugin, text, options = {}) {
    const start = now();
    let results = [];
    let error = null;

    try {
      // Run detection synchronously with a time check after completion.
      // True preemptive timeout would require worker_threads, but for a
      // lightweight zero-dependency SDK we keep it simple: run, measure,
      // and flag if it exceeded the budget.
      const output = plugin.detect(text, options);
      const durationMs = now() - start;

      if (durationMs > this.timeoutMs) {
        console.log(`[Agent Shield] Plugin "${plugin.name}" exceeded timeout (${durationMs.toFixed(1)}ms > ${this.timeoutMs}ms)`);
      }

      if (Array.isArray(output)) {
        results = output;
      }

      return { results, error: null, durationMs };
    } catch (err) {
      const durationMs = now() - start;
      error = err.message || String(err);
      console.log(`[Agent Shield] Plugin "${plugin.name}" threw an error: ${error}`);
      return { results: [], error, durationMs };
    }
  }
}

// =========================================================================
// PLUGIN TEMPLATE
// =========================================================================

/**
 * Helper class to create well-formed plugins from patterns or functions.
 */
class PluginTemplate {
  /**
   * Create a plugin from pattern definitions (detector-core format).
   * @param {object} config
   * @param {string} config.name - Plugin name
   * @param {string} [config.version='1.0.0'] - Plugin version
   * @param {Array<{regex: RegExp, severity: string, category: string, description: string, detail: string}>} config.patterns
   * @returns {object} A valid plugin object
   */
  static create({ name, version = '1.0.0', patterns = [] }) {
    return {
      name,
      version,
      detect(text) {
        const findings = [];
        for (const pattern of patterns) {
          if (pattern.regex && pattern.regex.test(text)) {
            findings.push({
              severity: pattern.severity || 'medium',
              category: pattern.category || name,
              description: pattern.description || 'Pattern match detected',
              detail: pattern.detail || ''
            });
          }
        }
        return findings;
      }
    };
  }

  /**
   * Wrap a bare detection function as a plugin object.
   * @param {object} config
   * @param {string} config.name - Plugin name
   * @param {string} [config.version='1.0.0'] - Plugin version
   * @param {function} config.detect - Detection function (text, options) => Array
   * @returns {object} A valid plugin object
   */
  static createFromFunction({ name, version = '1.0.0', detect }) {
    return { name, version, detect };
  }

  /**
   * Validate that a plugin object has the required fields and correct types.
   * @param {object} plugin - Plugin object to validate
   * @returns {{valid: boolean, errors: string[]}}
   */
  static validate(plugin) {
    const errors = [];

    if (!plugin || typeof plugin !== 'object') {
      return { valid: false, errors: ['Plugin must be a non-null object'] };
    }
    if (typeof plugin.name !== 'string' || plugin.name.length === 0) {
      errors.push('Plugin must have a non-empty string "name" property');
    }
    if (typeof plugin.detect !== 'function') {
      errors.push('Plugin must have a "detect" function');
    }
    if (plugin.version !== undefined && typeof plugin.version !== 'string') {
      errors.push('Plugin "version" must be a string if provided');
    }

    return { valid: errors.length === 0, errors };
  }
}

// =========================================================================
// PLUGIN MANAGER
// =========================================================================

/**
 * Manages the lifecycle of detector plugins: registration, toggling,
 * scanning, and per-plugin statistics.
 */
class PluginManager {
  /**
   * Initialize an empty plugin registry.
   */
  constructor() {
    /** @type {Map<string, {plugin: object, enabled: boolean, stats: {scans: number, threats: number, totalMs: number}}>} */
    this._registry = new Map();
    this._sandbox = new PluginSandbox();
  }

  /**
   * Register a plugin object.
   * @param {object} plugin - Plugin with name, version, and detect()
   * @throws {Error} If plugin is invalid or name is already registered
   */
  register(plugin) {
    const { valid, errors } = PluginTemplate.validate(plugin);
    if (!valid) {
      throw new Error(`[Agent Shield] Invalid plugin: ${errors.join('; ')}`);
    }
    if (this._registry.has(plugin.name)) {
      throw new Error(`[Agent Shield] Plugin "${plugin.name}" is already registered`);
    }

    this._registry.set(plugin.name, {
      plugin,
      enabled: true,
      stats: { scans: 0, threats: 0, totalMs: 0 }
    });

    console.log(`[Agent Shield] Registered plugin "${plugin.name}" v${plugin.version || 'unknown'}`);
  }

  /**
   * Load and register a plugin from a .js file.
   * @param {string} filePath - Absolute or relative path to a .js plugin file
   */
  registerFromFile(filePath) {
    const resolved = path.resolve(filePath);
    const plugin = require(resolved);
    this.register(plugin);
  }

  /**
   * Load all .js files from a directory as plugins.
   * Skips files that fail to load and logs a warning.
   * @param {string} dirPath - Path to directory containing plugin .js files
   */
  loadDirectory(dirPath) {
    const resolved = path.resolve(dirPath);
    let files;
    try {
      files = fs.readdirSync(resolved);
    } catch (err) {
      console.log(`[Agent Shield] Could not read plugin directory "${resolved}": ${err.message}`);
      return;
    }

    const jsFiles = files.filter(f => f.endsWith('.js'));
    for (const file of jsFiles) {
      try {
        this.registerFromFile(path.join(resolved, file));
      } catch (err) {
        console.log(`[Agent Shield] Failed to load plugin from "${file}": ${err.message}`);
      }
    }
  }

  /**
   * Remove a plugin from the registry.
   * @param {string} name - Plugin name
   * @returns {boolean} True if the plugin was found and removed
   */
  unregister(name) {
    const removed = this._registry.delete(name);
    if (removed) {
      console.log(`[Agent Shield] Unregistered plugin "${name}"`);
    }
    return removed;
  }

  /**
   * List all registered plugins.
   * @returns {Array<{name: string, version: string, enabled: boolean}>}
   */
  list() {
    const result = [];
    for (const [name, entry] of this._registry) {
      result.push({
        name,
        version: entry.plugin.version || 'unknown',
        enabled: entry.enabled
      });
    }
    return result;
  }

  /**
   * Enable a registered plugin.
   * @param {string} name - Plugin name
   * @throws {Error} If plugin is not registered
   */
  enable(name) {
    const entry = this._registry.get(name);
    if (!entry) {
      throw new Error(`[Agent Shield] Plugin "${name}" is not registered`);
    }
    entry.enabled = true;
    console.log(`[Agent Shield] Enabled plugin "${name}"`);
  }

  /**
   * Disable a registered plugin.
   * @param {string} name - Plugin name
   * @throws {Error} If plugin is not registered
   */
  disable(name) {
    const entry = this._registry.get(name);
    if (!entry) {
      throw new Error(`[Agent Shield] Plugin "${name}" is not registered`);
    }
    entry.enabled = false;
    console.log(`[Agent Shield] Disabled plugin "${name}"`);
  }

  /**
   * Run all enabled plugins against the given text and merge results.
   * @param {string} text - Text to scan
   * @param {object} [options] - Options passed to each plugin's detect()
   * @returns {Array<{severity: string, category: string, description: string, detail: string, plugin: string}>}
   */
  scan(text, options = {}) {
    const merged = [];

    for (const [name, entry] of this._registry) {
      if (!entry.enabled) continue;

      const { results, error, durationMs } = this._sandbox.run(entry.plugin, text, options);

      entry.stats.scans += 1;
      entry.stats.totalMs += durationMs;

      if (!error) {
        for (const finding of results) {
          merged.push({
            severity: finding.severity,
            category: finding.category,
            description: finding.description,
            detail: finding.detail || '',
            plugin: name
          });
        }
        entry.stats.threats += results.length;
      }
    }

    return merged;
  }

  /**
   * Get per-plugin scan statistics.
   * @returns {Array<{name: string, scans: number, threats: number, avgMs: number}>}
   */
  getStats() {
    const result = [];
    for (const [name, entry] of this._registry) {
      const { scans, threats, totalMs } = entry.stats;
      result.push({
        name,
        scans,
        threats,
        avgMs: scans > 0 ? Math.round((totalMs / scans) * 100) / 100 : 0
      });
    }
    return result;
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = { PluginManager, PluginTemplate, PluginSandbox };
