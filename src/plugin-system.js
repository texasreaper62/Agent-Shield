'use strict';

/**
 * Agent Shield — Plugin System
 *
 * Lets users write custom detectors as lightweight plugin objects.
 * Plugins are simple objects with a detect() method that returns an array
 * of threat findings. All detection runs locally — no data ever leaves
 * your environment.
 *
 * This module now includes IsolatedPluginSandbox which uses Node's built-in
 * `vm` module to run untrusted plugin source code in a sanitized context
 * with no access to process, fs, net, http, or child_process. It also
 * enforces a preemptive timeout via vm.Script's `timeout` option.
 */

const path = require('path');
const fs = require('fs');
const vm = require('vm');
const crypto = require('crypto');

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

// Try to raise the old-space memory cap a bit so tight infinite-loop plugins
// still get killed by the vm timeout (which is what provides the real bound).
try {
  const v8 = require('v8');
  if (typeof v8.setFlagsFromString === 'function') {
    // Best-effort only; ignored silently if not permitted.
    v8.setFlagsFromString('--max-old-space-size=4096');
  }
} catch (_err) {
  // v8 module missing or setFlagsFromString unavailable — silently skip.
}

// =========================================================================
// PLUGIN SANDBOX (legacy — kept for backward compatibility)
// =========================================================================

/**
 * Runs plugins with timeout protection and error isolation.
 * Prevents a misbehaving plugin from crashing the host agent.
 *
 * NOTE: This sandbox only times execution and catches errors. It does not
 * isolate plugin code from the host process. Use IsolatedPluginSandbox for
 * untrusted plugin source.
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
// ISOLATED PLUGIN SANDBOX (vm-based, real isolation)
// =========================================================================

/**
 * Whitelist of modules considered safe to expose to plugins via the
 * restricted `require`. Anything else is blocked.
 * @type {Set<string>}
 */
const DEFAULT_SAFE_MODULES = new Set([
  'util'
]);

/**
 * Build a sanitized console that writes to a string buffer instead of stdout.
 * @param {{buffer: string}} sink - Object whose `buffer` field gets appended to
 * @returns {object} Console-like object
 */
function makeSafeConsole(sink) {
  const write = (level) => (...args) => {
    const line = args.map((a) => {
      if (typeof a === 'string') return a;
      try { return JSON.stringify(a); } catch (_) { return String(a); }
    }).join(' ');
    sink.buffer += `[${level}] ${line}\n`;
  };
  return {
    log: write('log'),
    info: write('info'),
    warn: write('warn'),
    error: write('error'),
    debug: write('debug')
  };
}

/**
 * Real plugin sandbox using Node's `vm` module. Plugin source runs in a
 * brand-new context with no access to the host globals or the require()
 * function of the host process.
 */
class IsolatedPluginSandbox {
  /**
   * @param {object} [options]
   * @param {number} [options.timeoutMs=100] - Hard execution budget in ms (preemptive)
   * @param {string[]} [options.allowRequire=[]] - Whitelist of module IDs the plugin may require()
   */
  constructor(options = {}) {
    this.timeoutMs = options.timeoutMs || 100;
    // Combine the default whitelist with any caller-supplied entries.
    this.allowRequire = new Set([
      ...DEFAULT_SAFE_MODULES,
      ...(Array.isArray(options.allowRequire) ? options.allowRequire : [])
    ]);
  }

  /**
   * Build a safe restricted `require` function for the plugin context.
   * @returns {function}
   * @private
   */
  _makeSafeRequire() {
    const allowed = this.allowRequire;
    return function safeRequire(id) {
      if (typeof id !== 'string' || id.length === 0) {
        throw new Error('require(id) expects a non-empty string');
      }
      if (!allowed.has(id)) {
        throw new Error(`[Agent Shield] require("${id}") blocked by sandbox. Allowed: ${[...allowed].join(', ') || '(none)'}`);
      }
      // Only absolute, unambiguous module names reach here.
      // eslint-disable-next-line global-require
      return require(id);
    };
  }

  /**
   * Run untrusted plugin source. The source is expected to export a
   * detect(text, options) function by assigning to `module.exports`
   * or by assigning a top-level `detect` binding.
   *
   * @param {string} source - Plugin source code as a string
   * @param {string} text - Text to scan
   * @param {object} [options] - Options passed to detect()
   * @returns {{results: Array, error: string|null, durationMs: number, consoleOutput: string}}
   */
  runSource(source, text, options = {}) {
    if (typeof source !== 'string' || source.length === 0) {
      return { results: [], error: 'Plugin source must be a non-empty string', durationMs: 0, consoleOutput: '' };
    }

    const sink = { buffer: '' };
    const safeConsole = makeSafeConsole(sink);
    const moduleShim = { exports: {} };

    // Build a fresh object so the plugin cannot mutate the host's globals
    // by poisoning the prototype chain from inside the context.
    const sandboxGlobals = Object.create(null);

    // Use vm.runInNewContext to realm-isolate the built-ins. Each call gets
    // its own Object/Array/String/etc so that prototype pollution inside the
    // plugin does NOT affect the host process.
    const realm = vm.runInNewContext(`({
      String, Number, Boolean, Array, Object, RegExp, Math, Date, JSON,
      Map, Set, WeakMap, WeakSet, Error, TypeError, RangeError, SyntaxError,
      Symbol, Promise
    })`, Object.create(null), { timeout: this.timeoutMs });

    sandboxGlobals.String = realm.String;
    sandboxGlobals.Number = realm.Number;
    sandboxGlobals.Boolean = realm.Boolean;
    sandboxGlobals.Array = realm.Array;
    sandboxGlobals.Object = realm.Object;
    sandboxGlobals.RegExp = realm.RegExp;
    sandboxGlobals.Math = realm.Math;
    sandboxGlobals.Date = realm.Date;
    sandboxGlobals.JSON = realm.JSON;
    sandboxGlobals.Map = realm.Map;
    sandboxGlobals.Set = realm.Set;
    sandboxGlobals.WeakMap = realm.WeakMap;
    sandboxGlobals.WeakSet = realm.WeakSet;
    sandboxGlobals.Error = realm.Error;
    sandboxGlobals.TypeError = realm.TypeError;
    sandboxGlobals.RangeError = realm.RangeError;
    sandboxGlobals.SyntaxError = realm.SyntaxError;
    sandboxGlobals.Symbol = realm.Symbol;
    sandboxGlobals.Promise = realm.Promise;

    // Restricted surface for the plugin.
    sandboxGlobals.console = safeConsole;
    sandboxGlobals.require = this._makeSafeRequire();
    sandboxGlobals.module = moduleShim;
    sandboxGlobals.exports = moduleShim.exports;

    // Plugin inputs are made available as globals for convenience.
    sandboxGlobals.__text = text;
    sandboxGlobals.__options = options;

    // Create a sanitized `globalThis` / `global` that points at the same
    // frozen-ish object so the plugin sees a self-consistent environment
    // without being able to reach the host.
    sandboxGlobals.globalThis = sandboxGlobals;
    sandboxGlobals.global = sandboxGlobals;

    // Create the context. Do NOT use codeGeneration: {strings: true} — we
    // explicitly forbid eval/new Function inside the plugin.
    const context = vm.createContext(sandboxGlobals, {
      name: 'agent-shield-plugin-sandbox',
      codeGeneration: { strings: false, wasm: false }
    });

    // Wrap source so that if the plugin assigns `detect = ...` without
    // module.exports, we still find it.
    const wrapped = `
      (function() {
        'use strict';
        ${source}
        ;if (typeof module.exports === 'function') { return module.exports; }
        if (module.exports && typeof module.exports.detect === 'function') { return module.exports.detect; }
        if (typeof detect === 'function') { return detect; }
        return null;
      })()
    `;

    const start = now();
    let script;
    try {
      script = new vm.Script(wrapped, { filename: 'plugin.js' });
    } catch (err) {
      return {
        results: [],
        error: `Plugin compile error: ${err.message || String(err)}`,
        durationMs: now() - start,
        consoleOutput: sink.buffer
      };
    }

    let detectFn;
    try {
      detectFn = script.runInContext(context, { timeout: this.timeoutMs });
    } catch (err) {
      const durationMs = now() - start;
      const msg = err && err.message ? err.message : String(err);
      console.log(`[Agent Shield] Isolated plugin load failed: ${msg}`);
      return { results: [], error: msg, durationMs, consoleOutput: sink.buffer };
    }

    if (typeof detectFn !== 'function') {
      return {
        results: [],
        error: 'Plugin did not export a detect() function',
        durationMs: now() - start,
        consoleOutput: sink.buffer
      };
    }

    // Invoke detect() inside the same context with its own timeout so that
    // a tight infinite loop here is still killed.
    const callScript = new vm.Script(
      '__detect(__text, __options)',
      { filename: 'plugin-invoke.js' }
    );
    context.__detect = detectFn;

    let output;
    try {
      output = callScript.runInContext(context, { timeout: this.timeoutMs });
    } catch (err) {
      const durationMs = now() - start;
      const msg = err && err.message ? err.message : String(err);
      console.log(`[Agent Shield] Isolated plugin threw: ${msg}`);
      return { results: [], error: msg, durationMs, consoleOutput: sink.buffer };
    }

    const durationMs = now() - start;
    const results = Array.isArray(output) ? output : [];
    return { results, error: null, durationMs, consoleOutput: sink.buffer };
  }
}

// =========================================================================
// PLUGIN VERIFIER / SIGNING
// =========================================================================

/**
 * Compute an HMAC-SHA256 signature for a plugin source string.
 * @param {string} source - Plugin source code
 * @param {string} key - HMAC secret
 * @returns {string} Hex-encoded signature
 */
function signPlugin(source, key) {
  if (typeof source !== 'string') {
    throw new TypeError('signPlugin: source must be a string');
  }
  if (typeof key !== 'string' || key.length === 0) {
    throw new TypeError('signPlugin: key must be a non-empty string');
  }
  return crypto.createHmac('sha256', key).update(source, 'utf8').digest('hex');
}

/**
 * Verify a plugin signature using HMAC-SHA256 with a constant-time compare.
 * @param {string} source - Plugin source code
 * @param {string} signature - Hex-encoded signature to check
 * @param {string} key - HMAC secret
 * @returns {boolean} true if the signature is valid
 */
function verifyPluginSignature(source, signature, key) {
  if (typeof source !== 'string' || typeof signature !== 'string' || typeof key !== 'string') {
    return false;
  }
  let expected;
  try {
    expected = signPlugin(source, key);
  } catch (_err) {
    return false;
  }
  if (expected.length !== signature.length) return false;
  try {
    return crypto.timingSafeEqual(
      Buffer.from(expected, 'hex'),
      Buffer.from(signature, 'hex')
    );
  } catch (_err) {
    return false;
  }
}

/**
 * Verifier for plugin signatures. If configured with a signing key, any
 * unsigned or invalidly signed plugin is rejected.
 */
class PluginVerifier {
  /**
   * @param {object} [options]
   * @param {string} [options.signingKey] - HMAC secret. If omitted, all plugins pass.
   * @param {boolean} [options.requireSignature=true] - Reject unsigned plugins when key is set
   */
  constructor(options = {}) {
    this.signingKey = typeof options.signingKey === 'string' ? options.signingKey : null;
    this.requireSignature = options.requireSignature !== false;
  }

  /**
   * Returns true when this verifier was configured with a signing key.
   * @returns {boolean}
   */
  isConfigured() {
    return typeof this.signingKey === 'string' && this.signingKey.length > 0;
  }

  /**
   * Verify a manifest + source bundle.
   * @param {string} source - Plugin source code
   * @param {PluginManifest|object} manifest - Plugin manifest (may contain .signature)
   * @returns {{valid: boolean, reason: string|null}}
   */
  verify(source, manifest) {
    if (!this.isConfigured()) {
      return { valid: true, reason: null };
    }
    const signature = manifest && typeof manifest.signature === 'string' ? manifest.signature : '';
    if (!signature) {
      if (this.requireSignature) {
        return { valid: false, reason: 'Plugin is unsigned but verifier requires a signature' };
      }
      return { valid: true, reason: null };
    }
    const ok = verifyPluginSignature(source, signature, this.signingKey);
    return ok
      ? { valid: true, reason: null }
      : { valid: false, reason: 'Plugin signature does not match' };
  }
}

// =========================================================================
// PLUGIN MANIFEST
// =========================================================================

/**
 * Capability strings a plugin may declare. A plugin that only uses regex
 * matching should declare ['read_text', 'regex_only'] so the host can
 * decide what to trust it with.
 */
const VALID_CAPABILITIES = new Set([
  'read_text',
  'regex_only',
  'read_options',
  'network',           // explicit — almost always should NOT be granted
  'filesystem',        // explicit — almost always should NOT be granted
  'require_modules'
]);

/**
 * Manifest schema helper for plugins. A manifest describes what the plugin
 * is and what it needs access to.
 */
class PluginManifest {
  /**
   * Validate a manifest object.
   * @param {object} manifest
   * @returns {{valid: boolean, errors: string[]}}
   */
  static validate(manifest) {
    const errors = [];
    if (!manifest || typeof manifest !== 'object') {
      return { valid: false, errors: ['Manifest must be a non-null object'] };
    }
    if (typeof manifest.name !== 'string' || manifest.name.length === 0) {
      errors.push('Manifest "name" must be a non-empty string');
    }
    if (typeof manifest.version !== 'string' || manifest.version.length === 0) {
      errors.push('Manifest "version" must be a non-empty string');
    }
    if (typeof manifest.author !== 'string' || manifest.author.length === 0) {
      errors.push('Manifest "author" must be a non-empty string');
    }
    if (!Array.isArray(manifest.capabilities)) {
      errors.push('Manifest "capabilities" must be an array of strings');
    } else {
      for (const cap of manifest.capabilities) {
        if (typeof cap !== 'string' || !VALID_CAPABILITIES.has(cap)) {
          errors.push(`Unknown capability: ${String(cap)}`);
        }
      }
    }
    if (manifest.signature !== undefined && typeof manifest.signature !== 'string') {
      errors.push('Manifest "signature" must be a string if provided');
    }
    return { valid: errors.length === 0, errors };
  }

  /**
   * Create a signed manifest by attaching an HMAC signature over `source`.
   * @param {object} manifest - Base manifest (name, version, author, capabilities)
   * @param {string} source - Plugin source code
   * @param {string} key - HMAC secret
   * @returns {object} A new manifest object with a `signature` field
   */
  static sign(manifest, source, key) {
    const { valid, errors } = PluginManifest.validate({ ...manifest, capabilities: manifest.capabilities || [] });
    if (!valid) {
      throw new Error(`[Agent Shield] Cannot sign invalid manifest: ${errors.join('; ')}`);
    }
    return { ...manifest, signature: signPlugin(source, key) };
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

module.exports = {
  PluginManager,
  PluginTemplate,
  PluginSandbox,
  IsolatedPluginSandbox,
  PluginVerifier,
  PluginManifest,
  signPlugin,
  verifyPluginSignature,
  VALID_CAPABILITIES
};
