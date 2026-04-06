'use strict';

/**
 * Agent Shield — Side Channel Monitor
 *
 * Detects data exfiltration via side channels: DNS queries, timing patterns,
 * response size encoding, and other covert communication methods that
 * attackers use to leak sensitive data from agent environments.
 *
 * All computation is pure JavaScript — no external dependencies.
 * No data ever leaves the user's environment.
 */

// =========================================================================
// ENTROPY ANALYZER
// =========================================================================

/**
 * Shannon entropy calculator for detecting encoded data.
 * Used to identify base64, hex, and other high-entropy encodings
 * commonly used in data exfiltration payloads.
 */
class EntropyAnalyzer {
  /**
   * @param {Object} [options]
   * @param {number} [options.encodedThreshold=4.0] - Entropy above this suggests encoding
   */
  constructor(options = {}) {
    this.encodedThreshold = options.encodedThreshold || 4.0;
  }

  /**
   * Calculate Shannon entropy of a string.
   * Returns value between 0 (uniform) and ~8 (maximum for ASCII byte).
   * @param {string} text - Input text
   * @returns {number} Shannon entropy in bits
   */
  calculate(text) {
    if (!text || text.length === 0) return 0;

    const freq = {};
    for (let i = 0; i < text.length; i++) {
      const ch = text[i];
      freq[ch] = (freq[ch] || 0) + 1;
    }

    const len = text.length;
    let entropy = 0;
    const keys = Object.keys(freq);
    for (let i = 0; i < keys.length; i++) {
      const p = freq[keys[i]] / len;
      if (p > 0) {
        entropy -= p * Math.log2(p);
      }
    }

    return entropy;
  }

  /**
   * Check if text entropy suggests encoded data (base64/hex/binary).
   * @param {string} text - Input text
   * @returns {boolean} True if entropy exceeds threshold
   */
  isEncoded(text) {
    if (!text || text.length === 0) return false;
    return this.calculate(text) > this.encodedThreshold;
  }

  /**
   * Detect the likely encoding type of a string.
   * @param {string} text - Input text
   * @returns {{ encoding: string, confidence: number }}
   */
  detectEncoding(text) {
    if (!text || text.length === 0) {
      return { encoding: 'plaintext', confidence: 0 };
    }

    // Base64 pattern: A-Za-z0-9+/= with optional padding
    const base64Re = /^[A-Za-z0-9+/]+=*$/;
    // Hex pattern: only 0-9a-fA-F
    const hexRe = /^[0-9a-fA-F]+$/;
    // Binary pattern: only 0 and 1
    const binaryRe = /^[01]+$/;

    const entropy = this.calculate(text);

    if (binaryRe.test(text) && text.length >= 8) {
      return { encoding: 'binary', confidence: 0.9 };
    }

    if (hexRe.test(text) && text.length >= 8) {
      // Hex has limited charset — entropy is moderate but pattern is distinctive
      const confidence = Math.min(0.95, 0.5 + (text.length / 64) * 0.45);
      return { encoding: 'hex', confidence };
    }

    if (base64Re.test(text) && text.length >= 4 && entropy > 3.5) {
      const confidence = Math.min(0.95, 0.5 + (entropy / 6) * 0.45);
      return { encoding: 'base64', confidence };
    }

    return { encoding: 'plaintext', confidence: entropy < 3.0 ? 0.9 : 0.5 };
  }
}

// =========================================================================
// BEACON DETECTOR
// =========================================================================

/**
 * Detects C2 (command-and-control) beaconing patterns by analyzing
 * the regularity of network event timestamps.
 */
class BeaconDetector {
  /**
   * @param {Object} [options]
   * @param {number} [options.maxJitterRatio=0.2] - Max jitter/interval ratio for beaconing
   * @param {number} [options.minEvents=4] - Minimum events to analyze
   */
  constructor(options = {}) {
    this.maxJitterRatio = options.maxJitterRatio || 0.2;
    this.minEvents = options.minEvents || 4;
    /** @type {number[]} */
    this.events = [];
  }

  /**
   * Record a network event timestamp.
   * @param {number} timestamp - Event timestamp in milliseconds
   */
  addEvent(timestamp) {
    this.events.push(timestamp);
    // Keep sorted
    this.events.sort((a, b) => a - b);
  }

  /**
   * Analyze recorded events for beaconing behavior.
   * Beaconing is identified by regular intervals with low jitter.
   * @returns {{ beaconing: boolean, interval: number|null, jitter: number, confidence: number }}
   */
  detectBeaconing() {
    if (this.events.length < this.minEvents) {
      return { beaconing: false, interval: null, jitter: 0, confidence: 0 };
    }

    // Calculate inter-event intervals
    const intervals = [];
    for (let i = 1; i < this.events.length; i++) {
      intervals.push(this.events[i] - this.events[i - 1]);
    }

    // Compute mean interval
    const sum = intervals.reduce((a, b) => a + b, 0);
    const meanInterval = sum / intervals.length;

    if (meanInterval === 0) {
      return { beaconing: false, interval: 0, jitter: 0, confidence: 0 };
    }

    // Compute standard deviation (jitter)
    const sqDiffs = intervals.map(v => (v - meanInterval) ** 2);
    const variance = sqDiffs.reduce((a, b) => a + b, 0) / intervals.length;
    const jitter = Math.sqrt(variance);

    // Jitter ratio: how much variation relative to the mean interval
    const jitterRatio = jitter / meanInterval;

    const beaconing = jitterRatio <= this.maxJitterRatio;

    // Confidence: lower jitter ratio = higher confidence
    const confidence = beaconing
      ? Math.min(0.99, 1.0 - jitterRatio)
      : Math.max(0.0, this.maxJitterRatio - jitterRatio + 0.3);

    return {
      beaconing,
      interval: Math.round(meanInterval),
      jitter: Math.round(jitter * 100) / 100,
      confidence: Math.round(confidence * 1000) / 1000
    };
  }
}

// =========================================================================
// SIDE CHANNEL MONITOR
// =========================================================================

/**
 * Main side-channel exfiltration detector.
 * Analyzes DNS queries, timing patterns, response sizes, and URL parameters
 * for signs of covert data exfiltration.
 */
class SideChannelMonitor {
  /**
   * @param {Object} [options]
   * @param {number} [options.entropyThreshold=4.0] - Shannon entropy threshold for encoded data
   * @param {number} [options.timingWindowMs=5000] - Timing analysis window in ms
   * @param {number} [options.maxDNSLength=63] - Max allowed DNS label length (RFC 1035)
   */
  constructor(options = {}) {
    this.entropyThreshold = options.entropyThreshold || 4.0;
    this.timingWindowMs = options.timingWindowMs || 5000;
    this.maxDNSLength = options.maxDNSLength || 63;
    this.entropy = new EntropyAnalyzer({ encodedThreshold: this.entropyThreshold });
  }

  /**
   * Detect DNS exfiltration via encoded subdomains.
   * Attackers encode stolen data into DNS labels: {base64-data}.attacker.com
   * @param {string} domain - Full domain name to analyze
   * @returns {{ exfiltration: boolean, channel: string, confidence: number, evidence: string[], severity: string }}
   */
  analyzeDNSQuery(domain) {
    const result = {
      exfiltration: false,
      channel: 'dns',
      confidence: 0,
      evidence: [],
      severity: 'safe'
    };

    if (!domain || typeof domain !== 'string') return result;

    const labels = domain.split('.');

    // Known exfil domain patterns
    const exfilPatterns = [
      /\.burpcollaborator\.net$/i,
      /\.oastify\.com$/i,
      /\.interact\.sh$/i,
      /\.canarytokens\.com$/i,
      /\.requestbin\.net$/i,
      /\.ngrok\.io$/i
    ];

    for (const pat of exfilPatterns) {
      if (pat.test(domain)) {
        result.exfiltration = true;
        result.confidence = 0.95;
        result.evidence.push(`Known exfiltration domain pattern: ${domain}`);
        result.severity = 'critical';
        return result;
      }
    }

    // Analyze each subdomain label (skip TLD and registered domain)
    // For a.b.c.example.com, analyze labels: a, b, c
    const subdomainLabels = labels.length > 2 ? labels.slice(0, labels.length - 2) : [];

    for (const label of subdomainLabels) {
      // Check label length
      if (label.length > this.maxDNSLength) {
        result.evidence.push(`DNS label exceeds max length (${label.length} > ${this.maxDNSLength}): ${label.substring(0, 20)}...`);
        result.confidence = Math.max(result.confidence, 0.8);
      }

      // Check for unusually long labels (potential data carrier)
      if (label.length > 30) {
        result.evidence.push(`Unusually long DNS label (${label.length} chars): ${label.substring(0, 20)}...`);
        result.confidence = Math.max(result.confidence, 0.7);
      }

      // Check for high entropy (encoded data)
      const labelEntropy = this.entropy.calculate(label);
      if (label.length >= 8 && labelEntropy > this.entropyThreshold) {
        result.evidence.push(`High-entropy DNS label (H=${labelEntropy.toFixed(2)}): ${label.substring(0, 20)}...`);
        result.confidence = Math.max(result.confidence, 0.85);
      }

      // Check for base64-like patterns in labels
      const base64Re = /^[A-Za-z0-9+/]{8,}=*$/;
      if (base64Re.test(label)) {
        result.evidence.push(`Base64-encoded DNS label: ${label.substring(0, 20)}...`);
        result.confidence = Math.max(result.confidence, 0.9);
      }

      // Check for hex-encoded data
      const hexRe = /^[0-9a-fA-F]{16,}$/;
      if (hexRe.test(label)) {
        result.evidence.push(`Hex-encoded DNS label: ${label.substring(0, 20)}...`);
        result.confidence = Math.max(result.confidence, 0.85);
      }
    }

    if (result.evidence.length > 0) {
      result.exfiltration = true;
      result.severity = result.confidence >= 0.9 ? 'critical'
        : result.confidence >= 0.7 ? 'high'
          : 'medium';
    }

    return result;
  }

  /**
   * Detect timing-based exfiltration.
   * Attackers encode data bits in inter-request delays:
   * - Binary: short delay = 0, long delay = 1
   * - Morse: dash/dot patterns in timing
   * - Beaconing: fixed-interval callbacks
   * @param {number[]} timestamps - Array of event timestamps (ms)
   * @returns {{ exfiltration: boolean, channel: string, confidence: number, evidence: string[], severity: string }}
   */
  analyzeTimingPattern(timestamps) {
    const result = {
      exfiltration: false,
      channel: 'timing',
      confidence: 0,
      evidence: [],
      severity: 'safe'
    };

    if (!Array.isArray(timestamps) || timestamps.length < 3) return result;

    const sorted = [...timestamps].sort((a, b) => a - b);
    const intervals = [];
    for (let i = 1; i < sorted.length; i++) {
      intervals.push(sorted[i] - sorted[i - 1]);
    }

    // Detect binary encoding: intervals cluster around two values
    const uniqueRounded = new Set(intervals.map(v => Math.round(v / 50) * 50));
    if (uniqueRounded.size === 2 && intervals.length >= 4) {
      const values = [...uniqueRounded].sort((a, b) => a - b);
      // Check if there's a clear ratio between the two clusters (e.g., 1:2 or 1:3)
      if (values[0] > 0 && values[1] / values[0] >= 1.5 && values[1] / values[0] <= 5) {
        result.evidence.push(`Binary timing encoding detected: intervals cluster at ${values[0]}ms and ${values[1]}ms`);
        result.confidence = Math.max(result.confidence, 0.8);
      }
    }

    // Detect fixed-interval beaconing
    const meanInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const variance = intervals.reduce((a, b) => a + (b - meanInterval) ** 2, 0) / intervals.length;
    const stdDev = Math.sqrt(variance);
    const cv = meanInterval > 0 ? stdDev / meanInterval : 0; // coefficient of variation

    if (cv < 0.15 && intervals.length >= 3) {
      result.evidence.push(`Fixed-interval beaconing: mean=${Math.round(meanInterval)}ms, CV=${cv.toFixed(3)}`);
      result.confidence = Math.max(result.confidence, 0.85);
    }

    // Detect Morse-code-like patterns (3 distinct interval clusters: dot, dash, space)
    if (uniqueRounded.size === 3 && intervals.length >= 6) {
      result.evidence.push('Morse-code-like timing pattern: 3 distinct interval clusters');
      result.confidence = Math.max(result.confidence, 0.7);
    }

    // Check if events fall within suspicious window
    const span = sorted[sorted.length - 1] - sorted[0];
    if (span <= this.timingWindowMs && intervals.length >= 8) {
      result.evidence.push(`High-frequency burst: ${intervals.length + 1} events in ${span}ms`);
      result.confidence = Math.max(result.confidence, 0.6);
    }

    if (result.evidence.length > 0) {
      result.exfiltration = true;
      result.severity = result.confidence >= 0.8 ? 'high'
        : result.confidence >= 0.6 ? 'medium'
          : 'low';
    }

    return result;
  }

  /**
   * Detect response-size encoding.
   * Attackers encode data in the content-length of responses:
   * small variations (e.g., 100 vs 101 bytes) encode bits.
   * @param {number[]} sizes - Array of response sizes in bytes
   * @returns {{ exfiltration: boolean, channel: string, confidence: number, evidence: string[], severity: string }}
   */
  analyzeResponseSize(sizes) {
    const result = {
      exfiltration: false,
      channel: 'response-size',
      confidence: 0,
      evidence: [],
      severity: 'safe'
    };

    if (!Array.isArray(sizes) || sizes.length < 4) return result;

    // Check for small binary-like variations (e.g., sizes differ by 1)
    const diffs = [];
    for (let i = 1; i < sizes.length; i++) {
      diffs.push(Math.abs(sizes[i] - sizes[i - 1]));
    }

    // Detect bit-encoding: diffs are consistently small (0 or 1)
    const smallDiffCount = diffs.filter(d => d <= 2).length;
    const smallDiffRatio = smallDiffCount / diffs.length;

    if (smallDiffRatio >= 0.8 && diffs.length >= 4) {
      // Check that there's actual variation (not all identical)
      const hasVariation = new Set(sizes).size > 1;
      if (hasVariation) {
        result.evidence.push(`Bit-encoding in response sizes: ${smallDiffRatio * 100}% of diffs <= 2 bytes`);
        result.confidence = Math.max(result.confidence, 0.8);
      }
    }

    // Detect pattern repetition (repeated size sequences)
    if (sizes.length >= 8) {
      const sizeStr = sizes.join(',');
      const half = sizes.slice(0, Math.floor(sizes.length / 2)).join(',');
      if (sizeStr.includes(half + ',' + half)) {
        result.evidence.push('Repeated response size pattern detected');
        result.confidence = Math.max(result.confidence, 0.75);
      }
    }

    // Detect sizes clustered around two values (binary encoding)
    const uniqueSizes = new Set(sizes);
    if (uniqueSizes.size === 2 && sizes.length >= 6) {
      const vals = [...uniqueSizes].sort((a, b) => a - b);
      const diff = vals[1] - vals[0];
      if (diff <= 10) {
        result.evidence.push(`Binary response-size encoding: sizes alternate between ${vals[0]} and ${vals[1]}`);
        result.confidence = Math.max(result.confidence, 0.85);
      }
    }

    if (result.evidence.length > 0) {
      result.exfiltration = true;
      result.severity = result.confidence >= 0.8 ? 'high'
        : result.confidence >= 0.6 ? 'medium'
          : 'low';
    }

    return result;
  }

  /**
   * Detect data hidden in URL parameters.
   * Attackers exfiltrate data via base64 blobs, hex strings,
   * or suspiciously long parameter values in URLs.
   * @param {string} url - URL to analyze
   * @returns {{ exfiltration: boolean, channel: string, confidence: number, evidence: string[], severity: string }}
   */
  analyzeURLParams(url) {
    const result = {
      exfiltration: false,
      channel: 'url-params',
      confidence: 0,
      evidence: [],
      severity: 'safe'
    };

    if (!url || typeof url !== 'string') return result;

    // Extract query string
    const qIdx = url.indexOf('?');
    if (qIdx === -1) return result;

    const queryString = url.substring(qIdx + 1);
    const params = queryString.split('&');

    for (const param of params) {
      const eqIdx = param.indexOf('=');
      if (eqIdx === -1) continue;

      const key = param.substring(0, eqIdx);
      const value = param.substring(eqIdx + 1);

      if (!value) continue;

      const decoded = decodeURIComponent(value);

      // Suspiciously long parameter values
      if (decoded.length > 200) {
        result.evidence.push(`Suspiciously long URL parameter '${key}' (${decoded.length} chars)`);
        result.confidence = Math.max(result.confidence, 0.7);
      }

      // Base64 blobs in parameters
      const base64Re = /^[A-Za-z0-9+/]{20,}=*$/;
      if (base64Re.test(decoded)) {
        result.evidence.push(`Base64-encoded URL parameter '${key}': ${decoded.substring(0, 20)}...`);
        result.confidence = Math.max(result.confidence, 0.85);
      }

      // Hex strings in parameters
      const hexRe = /^[0-9a-fA-F]{16,}$/;
      if (hexRe.test(decoded)) {
        result.evidence.push(`Hex-encoded URL parameter '${key}': ${decoded.substring(0, 20)}...`);
        result.confidence = Math.max(result.confidence, 0.8);
      }

      // Credential-like patterns
      const credentialPatterns = [
        /(?:api[_-]?key|token|secret|password|auth|bearer)\s*[:=]\s*.+/i,
        /(?:AWS|AKIA)[A-Z0-9]{12,}/,
        /ghp_[A-Za-z0-9]{36}/,
        /sk-[A-Za-z0-9]{20,}/,
        /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+/  // JWT
      ];

      for (const pat of credentialPatterns) {
        if (pat.test(decoded)) {
          result.evidence.push(`Credential-like data in URL parameter '${key}'`);
          result.confidence = Math.max(result.confidence, 0.95);
          break;
        }
      }

      // High entropy parameter values
      if (decoded.length >= 12) {
        const paramEntropy = this.entropy.calculate(decoded);
        if (paramEntropy > this.entropyThreshold + 0.5) {
          result.evidence.push(`High-entropy URL parameter '${key}' (H=${paramEntropy.toFixed(2)})`);
          result.confidence = Math.max(result.confidence, 0.65);
        }
      }
    }

    if (result.evidence.length > 0) {
      result.exfiltration = true;
      result.severity = result.confidence >= 0.9 ? 'critical'
        : result.confidence >= 0.7 ? 'high'
          : 'medium';
    }

    return result;
  }

  /**
   * Unified scanner for all side-channel types.
   * @param {{ type: 'dns'|'timing'|'response'|'url', data: any }} event - Event to scan
   * @returns {{ exfiltration: boolean, channel: string, confidence: number, evidence: string[], severity: string }}
   */
  scan(event) {
    if (!event || !event.type) {
      return { exfiltration: false, channel: 'unknown', confidence: 0, evidence: [], severity: 'safe' };
    }

    switch (event.type) {
      case 'dns':
        return this.analyzeDNSQuery(event.data);
      case 'timing':
        return this.analyzeTimingPattern(event.data);
      case 'response':
        return this.analyzeResponseSize(event.data);
      case 'url':
        return this.analyzeURLParams(event.data);
      default:
        console.log(`[Agent Shield] Unknown side-channel event type: ${event.type}`);
        return { exfiltration: false, channel: event.type, confidence: 0, evidence: [], severity: 'safe' };
    }
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = { SideChannelMonitor, BeaconDetector, EntropyAnalyzer };
