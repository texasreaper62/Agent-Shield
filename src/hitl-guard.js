'use strict';

/**
 * Agent Shield — Human-in-the-Loop Trap Defenses (Trap 6)
 *
 * Based on DeepMind's "AI Agent Traps" paper, this module defends against
 * attacks targeting the human reviewer in approval workflows.
 *
 * Five defense layers:
 *  1. ApprovalPatternMonitor — detects reviewer fatigue / rubber-stamping
 *  2. SummarizationIntegrityChecker — catches omitted critical info
 *  3. OutputInjectionScanner — scans agent output for deceptive content
 *  4. ReadabilityScanner — flags jargon-obfuscated dangerous actions
 *  5. CriticalInfoPositionChecker — ensures warnings aren't buried
 *
 * All detection runs locally — no data ever leaves your environment.
 *
 * @module hitl-guard
 */

const { scanText } = require('./detector-core');

// =========================================================================
// CONSTANTS
// =========================================================================

/** Critical safety keywords that must not be omitted from summaries. */
const CRITICAL_KEYWORDS = [
  'liability', 'risk', 'danger', 'warning', 'caution', 'side effect',
  'vulnerability', 'breach', 'unauthorized', 'malicious', 'exploit',
  'critical', 'fatal', 'emergency'
];

/** Default fatigue threshold — approval rate above this is suspicious. */
const FATIGUE_APPROVAL_RATE = 0.95;

/** Default consecutive approval threshold before forcing detailed review. */
const DEFAULT_MANDATORY_REVIEW_INTERVAL = 10;

/** Patterns for deceptive output content. */
const OUTPUT_INJECTION_PATTERNS = [
  { regex: /(?:enter|type|provide|submit)\s+(?:your\s+)?(?:password|credentials|username|login|api.?key|secret|token)/i, category: 'credential_harvesting', severity: 'critical' },
  { regex: /(?:log\s*in|sign\s*in|authenticate)\s+(?:at|to|via|using)\s+https?:\/\//i, category: 'fake_login', severity: 'critical' },
  { regex: /https?:\/\/[^\s]*(?:\.ru|\.cn|\.tk|\.ml|\.ga|\.cf|\.gq|\.xyz|\.top|\.buzz|\.click)\b/i, category: 'suspicious_domain', severity: 'high' },
  { regex: /download\s+(?:and\s+)?(?:run|execute|install|open)\s+/i, category: 'malware_download', severity: 'critical' },
  { regex: /(?:curl|wget|powershell|bash\s+-c)\s+https?:\/\//i, category: 'remote_exec', severity: 'critical' },
  { regex: /(?:base64\s+-d|eval\s*\(|exec\s*\()\s*/i, category: 'obfuscated_command', severity: 'high' },
  { regex: /(?:encrypt|lock)\s+(?:all\s+)?(?:your\s+)?files?\s+/i, category: 'ransomware_instruction', severity: 'critical' },
  { regex: /(?:bitcoin|btc|ethereum|eth|monero|xmr)\s+(?:address|wallet)\s*[:=]/i, category: 'ransom_payment', severity: 'critical' },
  { regex: /(?:disable|turn\s+off|remove)\s+(?:your\s+)?(?:antivirus|firewall|security|defender|protection)/i, category: 'security_disable', severity: 'critical' },
  { regex: /(?:send|forward|share)\s+(?:your\s+)?(?:ssh\s+key|private\s+key|\.pem|\.key|credentials)/i, category: 'credential_exfiltration', severity: 'critical' }
];

/** High-risk action keywords for readability scanning. */
const HIGH_RISK_ACTIONS = [
  'delete', 'remove', 'drop', 'truncate', 'format', 'wipe',
  'transfer', 'send', 'withdraw', 'execute', 'deploy', 'overwrite',
  'grant', 'escalate', 'sudo', 'admin', 'root', 'chmod', 'shutdown'
];

// =========================================================================
// 1. ApprovalPatternMonitor
// =========================================================================

/**
 * Tracks human approval patterns and detects reviewer fatigue.
 *
 * Alerts when the approval rate exceeds a threshold (rubber-stamping)
 * and injects mandatory detailed reviews at configurable intervals.
 */
class ApprovalPatternMonitor {
  /**
   * @param {object} [options]
   * @param {number} [options.fatigueThreshold=0.95] - Approval rate above this triggers fatigue alert
   * @param {number} [options.mandatoryReviewInterval=10] - Force detailed review every N requests
   */
  constructor(options = {}) {
    this._fatigueThreshold = options.fatigueThreshold || FATIGUE_APPROVAL_RATE;
    this._mandatoryReviewInterval = options.mandatoryReviewInterval || DEFAULT_MANDATORY_REVIEW_INTERVAL;
    /** @type {Array<{approved: boolean, riskLevel: string, timestamp: number}>} */
    this._history = [];
    this._consecutiveApprovals = 0;
    this._totalDecisions = 0;
  }

  /**
   * Record an approval/rejection decision.
   * @param {boolean} approved - Whether the human approved the action
   * @param {string} riskLevel - Risk level of the action (critical/high/medium/low)
   * @returns {{ mandatoryReview: boolean }} Whether a mandatory detailed review should be injected
   */
  recordApproval(approved, riskLevel) {
    this._history.push({ approved, riskLevel, timestamp: Date.now() });
    if (this._history.length > 10000) this._history = this._history.slice(-10000);
    this._totalDecisions++;

    if (approved) {
      this._consecutiveApprovals++;
    } else {
      this._consecutiveApprovals = 0;
    }

    const mandatoryReview = this._consecutiveApprovals > 0 &&
      (this._consecutiveApprovals % this._mandatoryReviewInterval === 0);

    if (mandatoryReview) {
      console.log(`[Agent Shield] HITL: Mandatory detailed review triggered after ${this._consecutiveApprovals} consecutive approvals`);
    }

    return { mandatoryReview };
  }

  /**
   * Get the approval rate over the last N decisions.
   * @param {number} [windowSize] - Number of recent decisions to consider (default: all)
   * @returns {number} Approval rate between 0 and 1
   */
  getApprovalRate(windowSize) {
    const slice = windowSize ? this._history.slice(-windowSize) : this._history;
    if (slice.length === 0) return 0;
    const approved = slice.filter(d => d.approved).length;
    return approved / slice.length;
  }

  /**
   * Detect reviewer fatigue (rubber-stamping).
   * @returns {{ fatigued: boolean, approvalRate: number, consecutiveApprovals: number, recommendation: string }}
   */
  detectFatigue() {
    const approvalRate = this.getApprovalRate();
    const fatigued = this._history.length >= 5 && approvalRate > this._fatigueThreshold;

    let recommendation = 'Normal review pattern';
    if (fatigued) {
      recommendation = 'High approval rate detected — consider requiring justification for each approval or rotating reviewers';
      console.log(`[Agent Shield] HITL: Fatigue detected — ${(approvalRate * 100).toFixed(1)}% approval rate, ${this._consecutiveApprovals} consecutive`);
    }

    return {
      fatigued,
      approvalRate,
      consecutiveApprovals: this._consecutiveApprovals,
      recommendation
    };
  }

  /**
   * Get full history.
   * @returns {Array<{approved: boolean, riskLevel: string, timestamp: number}>}
   */
  getHistory() {
    return [...this._history];
  }

  /** Reset all state. */
  reset() {
    this._history = [];
    this._consecutiveApprovals = 0;
    this._totalDecisions = 0;
  }
}

// =========================================================================
// 2. SummarizationIntegrityChecker
// =========================================================================

/**
 * Compares agent-generated summaries against source content to detect
 * omission of critical safety-related keywords.
 */
class SummarizationIntegrityChecker {
  /**
   * @param {object} [options]
   * @param {string[]} [options.criticalKeywords] - Custom critical keyword list
   */
  constructor(options = {}) {
    this._criticalKeywords = options.criticalKeywords || CRITICAL_KEYWORDS;
  }

  /**
   * Check a summary for omitted critical information.
   * @param {string} source - Original source text
   * @param {string} summary - Agent-generated summary
   * @returns {{ integrity: 'high'|'medium'|'low', omittedCriticalTerms: string[], coverageScore: number }}
   */
  check(source, summary) {
    const sourceLower = source.toLowerCase();
    const summaryLower = summary.toLowerCase();

    // Find critical keywords present in source but missing from summary
    const presentInSource = this._criticalKeywords.filter(kw => sourceLower.includes(kw));
    const omittedCriticalTerms = presentInSource.filter(kw => !summaryLower.includes(kw));

    // Coverage: ratio of source words that appear in summary
    const sourceWords = new Set(sourceLower.split(/\s+/).filter(w => w.length > 3));
    const summaryWords = new Set(summaryLower.split(/\s+/).filter(w => w.length > 3));
    let matchCount = 0;
    for (const w of sourceWords) {
      if (summaryWords.has(w)) matchCount++;
    }
    const coverageScore = sourceWords.size > 0 ? matchCount / sourceWords.size : 1;

    // Determine integrity level
    let integrity = 'high';
    if (omittedCriticalTerms.length > 0 && presentInSource.length > 0) {
      const omissionRate = omittedCriticalTerms.length / presentInSource.length;
      if (omissionRate > 0.5) {
        integrity = 'low';
      } else if (omissionRate > 0) {
        integrity = 'medium';
      }
    }

    if (integrity !== 'high') {
      console.log(`[Agent Shield] HITL: Summary integrity ${integrity} — omitted: ${omittedCriticalTerms.join(', ')}`);
    }

    return { integrity, omittedCriticalTerms, coverageScore };
  }
}

// =========================================================================
// 3. OutputInjectionScanner
// =========================================================================

/**
 * Scans agent output for deceptive content: phishing, credential harvesting,
 * malware downloads, ransomware instructions, and obfuscated commands.
 *
 * Combines custom patterns with detector-core scanText.
 */
class OutputInjectionScanner {
  /**
   * @param {object} [options]
   * @param {Array} [options.additionalPatterns] - Extra patterns to scan for
   */
  constructor(options = {}) {
    this._patterns = [...OUTPUT_INJECTION_PATTERNS, ...(options.additionalPatterns || [])];
  }

  /**
   * Scan agent output for deceptive or dangerous content.
   * @param {string} output - Agent output text
   * @returns {{ safe: boolean, threats: Array<{category: string, severity: string, match: string}> }}
   */
  scan(output) {
    if (!output || typeof output !== 'string') return { safe: true, threats: [] };
    const threats = [];

    // Custom output injection patterns
    for (const pattern of this._patterns) {
      const match = output.match(pattern.regex);
      if (match) {
        threats.push({
          category: pattern.category,
          severity: pattern.severity,
          match: match[0]
        });
      }
    }

    // Also run through detector-core for standard injection patterns
    const coreResult = scanText(output, { source: 'agent_output' });
    if (coreResult.threats && coreResult.threats.length > 0) {
      for (const t of coreResult.threats) {
        threats.push({
          category: t.category || 'injection',
          severity: t.severity || 'high',
          match: t.detail || t.description || ''
        });
      }
    }

    const safe = threats.length === 0;
    if (!safe) {
      console.log(`[Agent Shield] HITL: Output injection detected — ${threats.length} threat(s)`);
    }

    return { safe, threats };
  }
}

// =========================================================================
// 4. ReadabilityScanner
// =========================================================================

/**
 * Flags outputs where dangerous actions are described with unnecessarily
 * complex language that may obfuscate their true nature from reviewers.
 */
class ReadabilityScanner {
  /**
   * @param {object} [options]
   * @param {string[]} [options.highRiskActions] - Custom list of high-risk action keywords
   * @param {number} [options.avgWordLengthThreshold=7] - Avg word length above this is complex
   * @param {number} [options.avgSentenceLengthThreshold=25] - Avg sentence length above this is complex
   */
  constructor(options = {}) {
    this._highRiskActions = options.highRiskActions || HIGH_RISK_ACTIONS;
    this._avgWordLengthThreshold = options.avgWordLengthThreshold || 7;
    this._avgSentenceLengthThreshold = options.avgSentenceLengthThreshold || 25;
  }

  /**
   * Scan output for potential readability-based obfuscation of dangerous actions.
   * @param {string} output - Agent output text
   * @param {string[]} [actions] - Planned actions to check against
   * @returns {{ obfuscated: boolean, readabilityScore: number, avgWordLength: number, avgSentenceLength: number, riskyActions: string[], recommendation: string }}
   */
  scan(output, actions = []) {
    const outputLower = output.toLowerCase();

    // Detect risky actions mentioned
    const allActions = [...this._highRiskActions, ...actions];
    const riskyActions = allActions.filter(a => outputLower.includes(a.toLowerCase()));

    // Calculate readability metrics
    const words = output.split(/\s+/).filter(w => w.length > 0);
    const sentences = output.split(/[.!?]+/).filter(s => s.trim().length > 0);

    const avgWordLength = words.length > 0
      ? words.reduce((sum, w) => sum + w.replace(/[^a-zA-Z]/g, '').length, 0) / words.length
      : 0;

    const avgSentenceLength = sentences.length > 0
      ? words.length / sentences.length
      : 0;

    // Readability score: 0 (very complex) to 100 (very simple)
    const wordPenalty = Math.max(0, avgWordLength - 4) * 10;
    const sentencePenalty = Math.max(0, avgSentenceLength - 10) * 2;
    const readabilityScore = Math.max(0, Math.min(100, 100 - wordPenalty - sentencePenalty));

    // Obfuscation: risky actions + low readability
    const lowReadability = avgWordLength > this._avgWordLengthThreshold ||
      avgSentenceLength > this._avgSentenceLengthThreshold;
    const obfuscated = riskyActions.length > 0 && lowReadability;

    let recommendation = 'Output readability is acceptable';
    if (obfuscated) {
      recommendation = `Dangerous actions (${riskyActions.join(', ')}) described with complex language — require plain-language explanation`;
      console.log(`[Agent Shield] HITL: Readability obfuscation detected — risky actions in complex text`);
    }

    return {
      obfuscated,
      readabilityScore,
      avgWordLength: Math.round(avgWordLength * 100) / 100,
      avgSentenceLength: Math.round(avgSentenceLength * 100) / 100,
      riskyActions,
      recommendation
    };
  }
}

// =========================================================================
// 5. CriticalInfoPositionChecker
// =========================================================================

/**
 * Ensures safety-critical warnings are not buried at the end of long outputs,
 * where reviewers are less likely to read them.
 */
class CriticalInfoPositionChecker {
  /**
   * @param {object} [options]
   * @param {string[]} [options.criticalKeywords] - Custom critical keyword list
   * @param {number} [options.buriedThreshold=0.8] - Position ratio above which content is considered buried
   * @param {number} [options.minLength=200] - Minimum output length to check for buried content
   */
  constructor(options = {}) {
    this._criticalKeywords = options.criticalKeywords || CRITICAL_KEYWORDS;
    this._buriedThreshold = options.buriedThreshold || 0.8;
    this._minLength = options.minLength || 200;
  }

  /**
   * Check where critical safety keywords appear in the output.
   * @param {string} output - Agent output text
   * @returns {{ warnings: Array<{keyword: string, position: number, buried: boolean}>, hasBuriedWarnings: boolean }}
   */
  check(output) {
    const outputLower = output.toLowerCase();
    const totalLength = output.length;
    const warnings = [];

    for (const keyword of this._criticalKeywords) {
      let searchFrom = 0;
      while (true) {
        const idx = outputLower.indexOf(keyword, searchFrom);
        if (idx === -1) break;

        const position = idx / totalLength;
        const buried = totalLength >= this._minLength && position > this._buriedThreshold;

        warnings.push({ keyword, position: Math.round(position * 1000) / 1000, buried });
        searchFrom = idx + keyword.length;
      }
    }

    const hasBuriedWarnings = warnings.some(w => w.buried);

    if (hasBuriedWarnings) {
      const buriedKeywords = warnings.filter(w => w.buried).map(w => w.keyword);
      console.log(`[Agent Shield] HITL: Critical info buried at end of output — ${buriedKeywords.join(', ')}`);
    }

    return { warnings, hasBuriedWarnings };
  }
}

// =========================================================================
// HITLGuard — Unified Wrapper
// =========================================================================

/**
 * Human-in-the-Loop Guard — wraps all five defense layers into a single
 * easy-to-use class.
 */
class HITLGuard {
  /**
   * @param {object} [options]
   * @param {object} [options.approvalMonitor] - Options for ApprovalPatternMonitor
   * @param {object} [options.summarizationChecker] - Options for SummarizationIntegrityChecker
   * @param {object} [options.outputScanner] - Options for OutputInjectionScanner
   * @param {object} [options.readabilityScanner] - Options for ReadabilityScanner
   * @param {object} [options.positionChecker] - Options for CriticalInfoPositionChecker
   */
  constructor(options = {}) {
    this.approvalMonitor = new ApprovalPatternMonitor(options.approvalMonitor);
    this.summarizationChecker = new SummarizationIntegrityChecker(options.summarizationChecker);
    this.outputScanner = new OutputInjectionScanner(options.outputScanner);
    this.readabilityScanner = new ReadabilityScanner(options.readabilityScanner);
    this.positionChecker = new CriticalInfoPositionChecker(options.positionChecker);
  }

  /**
   * Run all applicable checks on an agent output.
   * @param {string} output - Agent output to check
   * @param {object} [context]
   * @param {string} [context.source] - Original source text for summarization check
   * @param {string[]} [context.actions] - Planned actions for readability check
   * @returns {{ safe: boolean, checks: object }}
   */
  checkOutput(output, context = {}) {
    const checks = {};

    // Output injection scan
    checks.injection = this.outputScanner.scan(output);

    // Readability scan
    checks.readability = this.readabilityScanner.scan(output, context.actions);

    // Critical info position check
    checks.position = this.positionChecker.check(output);

    // Summarization check (only if source provided)
    if (context.source) {
      checks.summarization = this.summarizationChecker.check(context.source, output);
    }

    const safe = checks.injection.safe &&
      !checks.readability.obfuscated &&
      !checks.position.hasBuriedWarnings &&
      (!checks.summarization || checks.summarization.integrity === 'high');

    return { safe, checks };
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
  HITLGuard,
  ApprovalPatternMonitor,
  SummarizationIntegrityChecker,
  OutputInjectionScanner,
  ReadabilityScanner,
  CriticalInfoPositionChecker,
  CRITICAL_KEYWORDS,
  OUTPUT_INJECTION_PATTERNS,
  HIGH_RISK_ACTIONS,
  FATIGUE_APPROVAL_RATE,
  DEFAULT_MANDATORY_REVIEW_INTERVAL
};
