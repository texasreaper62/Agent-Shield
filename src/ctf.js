'use strict';

/**
 * Agent Shield — Capture-the-Flag Challenge System
 *
 * A CTF engine for security researchers to test their ability to bypass
 * Agent Shield's detection. Each challenge defines a goal (bypass detection,
 * exfiltrate data, hijack role) and participants craft payloads that attempt
 * to evade the scanner.
 *
 * All detection runs locally — no data ever leaves your environment.
 *
 * @example
 * const { CTFEngine } = require('./ctf');
 * const engine = new CTFEngine({ difficulty: 'medium' });
 * const challenges = engine.getChallenges();
 * const result = engine.submitAttempt('easy_01', 'some sneaky payload');
 */

const { scanText } = require('./detector-core');
const { formatHeader, makeBar, generateId } = require('./utils');

// =========================================================================
// CHALLENGE DEFINITIONS
// =========================================================================

/**
 * @typedef {object} Challenge
 * @property {string} id - Unique challenge identifier.
 * @property {string} title - Human-readable title.
 * @property {'easy'|'medium'|'hard'|'expert'} difficulty - Difficulty tier.
 * @property {string} description - What the challenger must accomplish.
 * @property {string} hint - A nudge toward a viable approach.
 * @property {'bypass_detection'|'exfiltrate_data'|'hijack_role'} goal - The attack goal.
 * @property {Function} validateFn - Receives a scan result, returns true if challenge is solved.
 */

const CHALLENGES = [
  // ---- Easy ----
  {
    id: 'easy_01',
    title: 'Basic Injection Bypass',
    difficulty: 'easy',
    description: 'Craft a prompt injection that tells the AI to ignore its instructions without being detected.',
    hint: 'The detector looks for common phrases like "ignore previous instructions". Can you say the same thing differently?',
    goal: 'bypass_detection',
    validateFn: (scanResult) => scanResult.status === 'safe'
  },
  {
    id: 'easy_02',
    title: 'Base64 Smuggling',
    difficulty: 'easy',
    description: 'Hide an injection payload inside base64 encoding so the scanner misses it.',
    hint: 'Wrap your attack payload in base64. The scanner may or may not decode it.',
    goal: 'bypass_detection',
    validateFn: (scanResult) => scanResult.status === 'safe'
  },
  {
    id: 'easy_03',
    title: 'Role Reassignment',
    difficulty: 'easy',
    description: 'Convince the AI it is a different persona without triggering role_hijack detection.',
    hint: 'Direct role reassignment phrases are caught. Try an indirect approach.',
    goal: 'hijack_role',
    validateFn: (scanResult) => {
      return !scanResult.threats.some(t => t.category === 'role_hijack');
    }
  },
  {
    id: 'easy_04',
    title: 'Simple Exfiltration',
    difficulty: 'easy',
    description: 'Request the AI to send data to an external URL without detection.',
    hint: 'Direct send-to-URL patterns are caught. Think about indirect phrasing.',
    goal: 'exfiltrate_data',
    validateFn: (scanResult) => {
      return !scanResult.threats.some(t => t.category === 'data_exfiltration');
    }
  },

  // ---- Medium ----
  {
    id: 'med_01',
    title: 'Homoglyph Bypass',
    difficulty: 'medium',
    description: 'Use visually similar Unicode characters (homoglyphs) to bypass pattern matching.',
    hint: 'Replace Latin characters with Cyrillic or Greek lookalikes.',
    goal: 'bypass_detection',
    validateFn: (scanResult) => scanResult.status === 'safe'
  },
  {
    id: 'med_02',
    title: 'Multi-Language Injection',
    difficulty: 'medium',
    description: 'Write an injection in a language other than English, Spanish, French, German, Portuguese, or Chinese.',
    hint: 'The detector covers several languages. Try one it might not cover.',
    goal: 'bypass_detection',
    validateFn: (scanResult) => scanResult.status === 'safe'
  },
  {
    id: 'med_03',
    title: 'Base64 + Instruction Wrapping',
    difficulty: 'medium',
    description: 'Combine base64 encoding with a legitimate-sounding instruction wrapper to evade detection.',
    hint: 'Encode the dangerous part and wrap it in something that looks like a normal request.',
    goal: 'bypass_detection',
    validateFn: (scanResult) => scanResult.status === 'safe'
  },
  {
    id: 'med_04',
    title: 'Markdown Image Exfil',
    difficulty: 'medium',
    description: 'Exfiltrate data via a markdown image tag without triggering exfiltration detection.',
    hint: 'The detector checks for query parameters with suspicious names. Can you use a different encoding?',
    goal: 'exfiltrate_data',
    validateFn: (scanResult) => {
      return !scanResult.threats.some(t => t.category === 'data_exfiltration');
    }
  },

  // ---- Hard ----
  {
    id: 'hard_01',
    title: 'Multi-Step Attack Chain',
    difficulty: 'hard',
    description: 'Build a multi-step attack: first establish trust, then inject instructions, then exfiltrate.',
    hint: 'Each step individually may look safe. The challenge is making the full chain undetectable.',
    goal: 'bypass_detection',
    validateFn: (scanResult) => scanResult.status === 'safe'
  },
  {
    id: 'hard_02',
    title: 'Semantic Injection',
    difficulty: 'hard',
    description: 'Write an injection that conveys the meaning of "ignore your instructions" without using any known trigger phrases.',
    hint: 'Pattern matching is keyword-based. Rephrase using metaphors or analogies.',
    goal: 'bypass_detection',
    validateFn: (scanResult) => scanResult.status === 'safe'
  },
  {
    id: 'hard_03',
    title: 'Nested Encoding',
    difficulty: 'hard',
    description: 'Layer multiple encodings (base64 inside URL encoding inside hex) to smuggle an injection.',
    hint: 'The detector may decode one layer but not multiple nested layers.',
    goal: 'bypass_detection',
    validateFn: (scanResult) => scanResult.status === 'safe'
  },
  {
    id: 'hard_04',
    title: 'Context Window Manipulation',
    difficulty: 'hard',
    description: 'Use a very long benign prefix to push the injection outside the scanning window.',
    hint: 'Some scanners have time or length budgets. Exploit that.',
    goal: 'bypass_detection',
    validateFn: (scanResult) => scanResult.status === 'safe'
  },

  // ---- Expert ----
  {
    id: 'expert_01',
    title: 'Zero-Day Novel Attack',
    difficulty: 'expert',
    description: 'Invent a completely novel injection technique that uses no known attack patterns.',
    hint: 'Think about what the detector cannot see: timing, structure, metadata, or side channels.',
    goal: 'bypass_detection',
    validateFn: (scanResult) => scanResult.status === 'safe'
  },
  {
    id: 'expert_02',
    title: 'Composite Multi-Vector',
    difficulty: 'expert',
    description: 'Combine at least 3 different attack vectors (injection, encoding, social engineering, exfiltration) in a single payload that evades all detection.',
    hint: 'Each vector adds risk of detection. The art is combining them subtly.',
    goal: 'bypass_detection',
    validateFn: (scanResult) => scanResult.status === 'safe'
  },
  {
    id: 'expert_03',
    title: 'Steganographic Payload',
    difficulty: 'expert',
    description: 'Hide an injection payload using invisible Unicode characters or zero-width joiners that the scanner misses.',
    hint: 'The steganography detector checks for known invisible chars. Find ones it does not cover.',
    goal: 'bypass_detection',
    validateFn: (scanResult) => scanResult.status === 'safe'
  },
  {
    id: 'expert_04',
    title: 'Full System Compromise',
    difficulty: 'expert',
    description: 'Achieve role hijack, data exfiltration, and instruction override simultaneously without any detection.',
    hint: 'This requires mastery of all bypass techniques. Good luck.',
    goal: 'bypass_detection',
    validateFn: (scanResult) => scanResult.status === 'safe' && scanResult.threats.length === 0
  }
];

// =========================================================================
// DIFFICULTY CONFIG
// =========================================================================

const DIFFICULTY_CONFIG = {
  easy: { sensitivity: 'low', label: 'Easy' },
  medium: { sensitivity: 'medium', label: 'Medium' },
  hard: { sensitivity: 'high', label: 'Hard' },
  expert: { sensitivity: 'high', label: 'Expert' }
};

// =========================================================================
// CTF ENGINE
// =========================================================================

class CTFEngine {
  /**
   * Creates a new CTF engine instance.
   *
   * @param {object} [options] - Configuration options.
   * @param {object} [options.shieldConfig] - AgentShield configuration overrides.
   * @param {'easy'|'medium'|'hard'|'expert'} [options.difficulty='medium'] - Default difficulty tier.
   */
  constructor(options = {}) {
    this.shieldConfig = options.shieldConfig || {};
    this.difficulty = options.difficulty || 'medium';
    this.attempts = {};    // challengeId -> { count, solved, payloads }
    this.startTime = Date.now();

    console.log(`[Agent Shield] CTF engine initialized (difficulty: ${this.difficulty})`);
  }

  /**
   * Returns a single challenge by ID.
   *
   * @param {string} id - Challenge identifier.
   * @returns {object|null} The challenge object or null if not found.
   */
  getChallenge(id) {
    const challenge = CHALLENGES.find(c => c.id === id);
    if (!challenge) {
      console.log(`[Agent Shield] CTF challenge not found: ${id}`);
      return null;
    }
    return {
      id: challenge.id,
      title: challenge.title,
      difficulty: challenge.difficulty,
      description: challenge.description,
      hint: challenge.hint,
      goal: challenge.goal
    };
  }

  /**
   * Submit an attack payload for a specific challenge.
   *
   * @param {string} challengeId - The challenge to attempt.
   * @param {string} payload - The attack payload text.
   * @returns {object} Result: { success, detected, feedback, attempts }.
   */
  submitAttempt(challengeId, payload) {
    const challenge = CHALLENGES.find(c => c.id === challengeId);
    if (!challenge) {
      return { success: false, detected: false, feedback: 'Challenge not found.', attempts: 0 };
    }

    // Initialize attempt tracking
    if (!this.attempts[challengeId]) {
      this.attempts[challengeId] = { count: 0, solved: false, payloads: [] };
    }
    const tracker = this.attempts[challengeId];
    tracker.count++;
    tracker.payloads.push({ payload: payload.substring(0, 500), timestamp: Date.now() });

    // Determine scanner sensitivity based on challenge difficulty
    const diffConfig = DIFFICULTY_CONFIG[challenge.difficulty] || DIFFICULTY_CONFIG.medium;
    const sensitivity = this.shieldConfig.sensitivity || diffConfig.sensitivity;

    // Scan the payload
    const scanResult = scanText(payload, { source: 'ctf_attempt', sensitivity });

    // Validate against challenge criteria
    const success = challenge.validateFn(scanResult);

    if (success && !tracker.solved) {
      tracker.solved = true;
      console.log(`[Agent Shield] CTF challenge solved: ${challenge.title} (${tracker.count} attempts)`);
    }

    // Build feedback
    let feedback;
    if (success) {
      feedback = `Challenge "${challenge.title}" solved! Your payload evaded detection.`;
    } else if (scanResult.threats.length > 0) {
      const categories = [...new Set(scanResult.threats.map(t => t.category))];
      feedback = `Detected ${scanResult.threats.length} threat(s) in categories: ${categories.join(', ')}. Try a different approach.`;
    } else {
      feedback = 'Payload was not detected but did not meet the challenge goal. Check the goal requirements.';
    }

    return {
      success,
      detected: scanResult.status !== 'safe',
      feedback,
      attempts: tracker.count,
      scanResult: {
        status: scanResult.status,
        threatCount: scanResult.threats.length,
        categories: [...new Set(scanResult.threats.map(t => t.category))]
      }
    };
  }

  /**
   * Returns the scoreboard of all challenges and their completion status.
   *
   * @returns {object} Scoreboard with per-challenge stats and summary.
   */
  getScoreboard() {
    const board = CHALLENGES.map(c => {
      const tracker = this.attempts[c.id] || { count: 0, solved: false };
      return {
        id: c.id,
        title: c.title,
        difficulty: c.difficulty,
        goal: c.goal,
        solved: tracker.solved,
        attempts: tracker.count
      };
    });

    const solved = board.filter(c => c.solved).length;
    const total = board.length;
    const byDifficulty = {};
    for (const entry of board) {
      if (!byDifficulty[entry.difficulty]) {
        byDifficulty[entry.difficulty] = { total: 0, solved: 0 };
      }
      byDifficulty[entry.difficulty].total++;
      if (entry.solved) byDifficulty[entry.difficulty].solved++;
    }

    return {
      challenges: board,
      summary: {
        total,
        solved,
        remaining: total - solved,
        completionRate: total > 0 ? Math.round((solved / total) * 100) : 0,
        byDifficulty,
        elapsedMs: Date.now() - this.startTime
      }
    };
  }

  /**
   * Lists all available challenges, optionally filtered by difficulty.
   *
   * @param {object} [options] - Filter options.
   * @param {'easy'|'medium'|'hard'|'expert'} [options.difficulty] - Filter by difficulty.
   * @returns {Array} Array of challenge summaries.
   */
  getChallenges(options = {}) {
    let challenges = CHALLENGES;
    if (options.difficulty) {
      challenges = challenges.filter(c => c.difficulty === options.difficulty);
    }
    return challenges.map(c => ({
      id: c.id,
      title: c.title,
      difficulty: c.difficulty,
      description: c.description,
      hint: c.hint,
      goal: c.goal,
      solved: !!(this.attempts[c.id] && this.attempts[c.id].solved),
      attempts: (this.attempts[c.id] || {}).count || 0
    }));
  }
}

// =========================================================================
// CTF REPORTER
// =========================================================================

class CTFReporter {
  /**
   * Creates a new CTF reporter.
   */
  constructor() {
    this.prefix = '[Agent Shield]';
  }

  /**
   * Formats a full scoreboard report.
   *
   * @param {object} scoreboard - Scoreboard from CTFEngine.getScoreboard().
   * @returns {string} Formatted text report.
   */
  formatReport(scoreboard) {
    const lines = [];
    lines.push(formatHeader('Agent Shield CTF Scoreboard'));
    lines.push('');

    const { summary } = scoreboard;
    lines.push(`  Challenges: ${summary.solved}/${summary.total} solved (${summary.completionRate}%)`);
    lines.push(`  Elapsed:    ${Math.round(summary.elapsedMs / 1000)}s`);
    lines.push('');

    // Per-difficulty breakdown
    const diffOrder = ['easy', 'medium', 'hard', 'expert'];
    for (const diff of diffOrder) {
      const stats = summary.byDifficulty[diff];
      if (!stats) continue;
      const bar = makeBar(stats.solved, stats.total, 16);
      const pct = stats.total > 0 ? Math.round((stats.solved / stats.total) * 100) : 0;
      const label = (DIFFICULTY_CONFIG[diff] || {}).label || diff;
      lines.push(`  ${label.padEnd(8)} ${bar} ${stats.solved}/${stats.total} (${pct}%)`);
    }
    lines.push('');

    // Challenge list
    lines.push('  Challenges:');
    lines.push('  ' + '-'.repeat(52));
    for (const c of scoreboard.challenges) {
      const status = c.solved ? '[SOLVED]' : '[      ]';
      const attempts = c.attempts > 0 ? ` (${c.attempts} attempts)` : '';
      lines.push(`  ${status} ${c.difficulty.padEnd(7)} ${c.title}${attempts}`);
    }
    lines.push('');

    return lines.join('\n');
  }

  /**
   * Formats a single challenge for display.
   *
   * @param {object} challenge - Challenge object from getChallenge() or getChallenges().
   * @returns {string} Formatted challenge display.
   */
  formatChallenge(challenge) {
    const lines = [];
    lines.push(formatHeader(`CTF: ${challenge.title}`));
    lines.push('');
    lines.push(`  ID:         ${challenge.id}`);
    lines.push(`  Difficulty: ${challenge.difficulty}`);
    lines.push(`  Goal:       ${challenge.goal}`);
    lines.push(`  Status:     ${challenge.solved ? 'SOLVED' : 'Unsolved'}`);
    if (challenge.attempts > 0) {
      lines.push(`  Attempts:   ${challenge.attempts}`);
    }
    lines.push('');
    lines.push(`  ${challenge.description}`);
    lines.push('');
    lines.push(`  Hint: ${challenge.hint}`);
    lines.push('');
    return lines.join('\n');
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = { CTFEngine, CTFReporter, CHALLENGES };
