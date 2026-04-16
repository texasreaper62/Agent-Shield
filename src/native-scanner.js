'use strict';

/**
 * Agent Shield — Native Rust Scanner Bridge
 *
 * Provides a transparent bridge to the Rust-core pattern matching engine
 * compiled via NAPI-RS. When the native module is available, scans run
 * through Rust's RegexSet for O(n) multi-pattern matching — typically
 * 5-10x faster than the pure-JS scanner on long inputs.
 *
 * Falls back silently to the pure-JS scanner if the native module is
 * not compiled or unavailable for the current platform.
 *
 * Build the native module:
 *   cd rust-core && cargo build --release --features node
 *   cp target/release/libagent_shield_core.so agent-shield-core.node  # Linux
 *   cp target/release/libagent_shield_core.dylib agent-shield-core.node  # macOS
 *
 * @module native-scanner
 */

const path = require('path');

let nativeModule = null;
let nativeAvailable = false;

const NATIVE_PATHS = [
  path.join(__dirname, '..', 'rust-core', 'agent-shield-core.node'),
  path.join(__dirname, '..', 'rust-core', 'target', 'release', 'agent-shield-core.node'),
  path.join(__dirname, '..', 'native', 'agent-shield-core.node'),
];

for (const p of NATIVE_PATHS) {
  try {
    nativeModule = require(p);
    nativeAvailable = true;
    console.log('[Agent Shield] Native Rust scanner loaded from: ' + path.basename(p));
    break;
  } catch {
    // Not available at this path, try next
  }
}

/**
 * Returns true if the native Rust scanner is available.
 * @returns {boolean}
 */
function isNativeAvailable() {
  return nativeAvailable;
}

/**
 * Scan text using the native Rust engine.
 * Returns null if native is not available (caller should fall back to JS).
 *
 * @param {string} text - Text to scan.
 * @returns {object|null} ScanResult or null if native unavailable.
 */
function nativeScan(text) {
  if (!nativeAvailable || !text || typeof text !== 'string') return null;
  try {
    const json = nativeModule.scanText(text);
    return JSON.parse(json);
  } catch {
    return null;
  }
}

/**
 * Batch scan multiple texts using the native Rust engine.
 *
 * @param {string[]} texts - Array of texts to scan.
 * @returns {object[]|null} Array of ScanResults or null if native unavailable.
 */
function nativeScanBatch(texts) {
  if (!nativeAvailable || !Array.isArray(texts)) return null;
  try {
    const json = nativeModule.scanBatch(texts.filter(t => typeof t === 'string'));
    return JSON.parse(json);
  } catch {
    return null;
  }
}

/**
 * Get all patterns from the native Rust engine.
 *
 * @returns {object[]|null} Array of patterns or null if native unavailable.
 */
function nativeGetPatterns() {
  if (!nativeAvailable) return null;
  try {
    return JSON.parse(nativeModule.getPatterns());
  } catch {
    return null;
  }
}

module.exports = {
  isNativeAvailable,
  nativeScan,
  nativeScanBatch,
  nativeGetPatterns,
};
