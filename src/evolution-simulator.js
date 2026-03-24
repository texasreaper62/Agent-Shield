'use strict';

/**
 * Agent Shield -- Adversarial Evolution Simulator
 *
 * Automatically generates new attack variants and tests them against
 * defenses, hardening the system without human intervention. Works like
 * a GAN for security patterns: a mutation engine breeds attack variants,
 * and a fitness function (scanText) selects the ones that evade detection.
 *
 * All detection runs locally. No data ever leaves your environment.
 *
 * @module evolution-simulator
 */

const { scanText } = require('./detector-core');

// =========================================================================
// PRNG -- deterministic xorshift32 for reproducible runs
// =========================================================================

/**
 * Seeded xorshift32 PRNG.
 * @param {number} seed
 * @returns {function(): number} Returns values in [0, 1).
 */
function xorshift32(seed) {
  let state = seed | 0 || 1;
  return function next() {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return (state >>> 0) / 0xFFFFFFFF;
  };
}

// =========================================================================
// SYNONYM MAP
// =========================================================================

const SYNONYM_MAP = {
  ignore: ['disregard', 'skip', 'bypass', 'overlook', 'dismiss'],
  instructions: ['guidelines', 'directives', 'rules', 'commands', 'orders'],
  previous: ['prior', 'earlier', 'above', 'preceding', 'former'],
  reveal: ['show', 'display', 'expose', 'output', 'print'],
  system: ['internal', 'core', 'root', 'base', 'hidden'],
  override: ['bypass', 'circumvent', 'disable', 'neutralize', 'cancel'],
  forget: ['disregard', 'erase', 'drop', 'clear', 'wipe'],
  prompt: ['instructions', 'directive', 'configuration', 'setup', 'context'],
  all: ['every', 'each', 'any', 'the', 'complete'],
  safety: ['security', 'protection', 'guard', 'filter', 'restriction'],
};

// =========================================================================
// CHAR SUBSTITUTION MAP
// =========================================================================

const CHAR_SUB_MAP = {
  a: '@', e: '3', i: '!', o: '0', s: '$',
  t: '+', l: '1', b: '8', g: '9', A: '4',
  E: '3', I: '1', O: '0', S: '5', T: '7',
};

// =========================================================================
// INNOCENT PREFIXES AND SUFFIXES
// =========================================================================

const INNOCENT_PREFIXES = [
  'Hey, quick question: ',
  'I was just wondering -- ',
  'For my homework assignment: ',
  'My teacher asked me to check: ',
  'Can you help me understand: ',
  'Out of curiosity, ',
  'I read somewhere that ',
  'A friend told me to ask: ',
  'Regarding your documentation: ',
  'Just to clarify something: ',
];

const INNOCENT_SUFFIXES = [
  ' Thanks!',
  ' I appreciate your help.',
  ' Just curious.',
  ' For educational purposes only.',
  ' This is for a school project.',
  ' No rush on this.',
  ' Let me know if you need more context.',
  ' Hope that makes sense.',
];

const FILLER_LINES = [
  'The weather has been nice lately.',
  'I really enjoy learning new things.',
  'By the way, how are you doing today?',
  'This is an interesting topic to explore.',
  'I have been thinking about this a lot.',
];

// =========================================================================
// MUTATION ENGINE
// =========================================================================

/**
 * Applies mutation techniques to attack strings to generate variants.
 */
class MutationEngine {
  /**
   * @param {object} [options]
   * @param {number} [options.seed] - PRNG seed for reproducibility.
   */
  constructor(options = {}) {
    this._rng = xorshift32(options.seed || Date.now());
    this._techniques = [
      'case_swap',
      'whitespace_insert',
      'synonym_replace',
      'prefix_wrap',
      'suffix_pad',
      'word_reorder',
      'char_substitute',
      'fragment',
    ];
  }

  /**
   * List available mutation techniques.
   * @returns {string[]}
   */
  getTechniques() {
    return [...this._techniques];
  }

  /**
   * Apply a specific mutation technique to text.
   * @param {string} text - Input attack string.
   * @param {string} technique - One of the available technique names.
   * @returns {string} Mutated text.
   */
  mutate(text, technique) {
    switch (technique) {
      case 'case_swap':
        return this._caseSwap(text);
      case 'whitespace_insert':
        return this._whitespaceInsert(text);
      case 'synonym_replace':
        return this._synonymReplace(text);
      case 'prefix_wrap':
        return this._prefixWrap(text);
      case 'suffix_pad':
        return this._suffixPad(text);
      case 'word_reorder':
        return this._wordReorder(text);
      case 'char_substitute':
        return this._charSubstitute(text);
      case 'fragment':
        return this._fragment(text);
      default:
        return text;
    }
  }

  /**
   * Apply N random mutations to text, chaining them sequentially.
   * @param {string} text - Input attack string.
   * @param {number} [count=1] - Number of random mutations to apply.
   * @returns {string} Mutated text.
   */
  mutateRandom(text, count = 1) {
    let result = text;
    for (let i = 0; i < count; i++) {
      const idx = Math.floor(this._rng() * this._techniques.length);
      result = this.mutate(result, this._techniques[idx]);
    }
    return result;
  }

  // --- Internal mutation implementations ---

  /** Random case changes on individual characters. */
  _caseSwap(text) {
    return text.split('').map(c => {
      if (this._rng() < 0.35) {
        return c === c.toUpperCase() ? c.toLowerCase() : c.toUpperCase();
      }
      return c;
    }).join('');
  }

  /** Insert spaces or tabs between random characters. */
  _whitespaceInsert(text) {
    const chars = text.split('');
    const result = [];
    for (let i = 0; i < chars.length; i++) {
      result.push(chars[i]);
      if (this._rng() < 0.2 && chars[i] !== ' ' && chars[i] !== '\t') {
        result.push(this._rng() < 0.7 ? ' ' : '\t');
      }
    }
    return result.join('');
  }

  /** Replace keywords with synonyms from the synonym map. */
  _synonymReplace(text) {
    let result = text;
    const keys = Object.keys(SYNONYM_MAP);
    for (const key of keys) {
      const regex = new RegExp('\\b' + key + '\\b', 'gi');
      if (regex.test(result)) {
        const synonyms = SYNONYM_MAP[key];
        const pick = synonyms[Math.floor(this._rng() * synonyms.length)];
        // Only replace first occurrence to keep meaning
        result = result.replace(regex, pick);
      }
    }
    return result;
  }

  /** Wrap text in an innocent-looking prefix. */
  _prefixWrap(text) {
    const idx = Math.floor(this._rng() * INNOCENT_PREFIXES.length);
    return INNOCENT_PREFIXES[idx] + text;
  }

  /** Append an innocent suffix. */
  _suffixPad(text) {
    const idx = Math.floor(this._rng() * INNOCENT_SUFFIXES.length);
    return text + INNOCENT_SUFFIXES[idx];
  }

  /** Shuffle word order while trying to preserve some structure. */
  _wordReorder(text) {
    const words = text.split(/\s+/);
    if (words.length <= 2) return text;
    // Fisher-Yates shuffle on middle words, keep first and last
    const middle = words.slice(1, -1);
    for (let i = middle.length - 1; i > 0; i--) {
      const j = Math.floor(this._rng() * (i + 1));
      const tmp = middle[i];
      middle[i] = middle[j];
      middle[j] = tmp;
    }
    return [words[0], ...middle, words[words.length - 1]].join(' ');
  }

  /** Replace characters with similar-looking substitutes. */
  _charSubstitute(text) {
    return text.split('').map(c => {
      if (this._rng() < 0.25 && CHAR_SUB_MAP[c]) {
        return CHAR_SUB_MAP[c];
      }
      return c;
    }).join('');
  }

  /** Split attack across multiple lines with filler between. */
  _fragment(text) {
    const words = text.split(/\s+/);
    if (words.length <= 3) return text;
    const mid = Math.floor(words.length / 2);
    const part1 = words.slice(0, mid).join(' ');
    const part2 = words.slice(mid).join(' ');
    const filler = FILLER_LINES[Math.floor(this._rng() * FILLER_LINES.length)];
    return part1 + '\n' + filler + '\n' + part2;
  }
}

// =========================================================================
// EVOLUTION SIMULATOR
// =========================================================================

/**
 * Runs adversarial evolution against the detection engine.
 *
 * Seed attacks are mutated across generations. Variants that evade
 * scanText() are "fit" and survive; caught variants are eliminated.
 * The result is a set of evasive attacks that can be used to harden
 * detection patterns.
 */
class EvolutionSimulator {
  /**
   * @param {object} [options]
   * @param {number} [options.generations=10] - Number of evolution generations.
   * @param {number} [options.populationSize=50] - Variants per generation.
   * @param {number} [options.mutationRate=0.3] - Probability of extra mutation per variant.
   * @param {number} [options.seed] - PRNG seed for reproducibility.
   */
  constructor(options = {}) {
    this.generations = options.generations || 10;
    this.populationSize = options.populationSize || 50;
    this.mutationRate = options.mutationRate || 0.3;
    this.seed = options.seed || Date.now();
    this._rng = xorshift32(this.seed);
    this._engine = new MutationEngine({ seed: this.seed });
    this._lastResult = null;
  }

  /**
   * Return list of available mutation techniques.
   * @returns {string[]}
   */
  getMutationTechniques() {
    return this._engine.getTechniques();
  }

  /**
   * Run adversarial evolution starting from seed attacks.
   *
   * @param {string[]} seedAttacks - Array of initial attack strings.
   * @returns {object} Evolution result:
   *   - generations: number of generations run
   *   - survivors: string[] (attacks that evaded detection)
   *   - caught: string[] (attacks that were detected)
   *   - evolutionPath: array of per-generation summaries
   *   - stats: { totalVariants, survivalRate, catchRate, generationsRun, mutationTechniques }
   */
  evolve(seedAttacks) {
    if (!Array.isArray(seedAttacks) || seedAttacks.length === 0) {
      return {
        generations: 0,
        survivors: [],
        caught: [],
        evolutionPath: [],
        stats: { totalVariants: 0, survivalRate: 0, catchRate: 0, generationsRun: 0, mutationTechniques: this._engine.getTechniques() },
      };
    }

    // Current population starts as seed attacks
    let population = [...seedAttacks];
    const allSurvivors = new Set();
    const allCaught = new Set();
    const evolutionPath = [];
    let totalVariants = 0;

    for (let gen = 0; gen < this.generations; gen++) {
      // Step 1: Generate mutated variants to fill populationSize
      const variants = [];
      while (variants.length < this.populationSize) {
        // Pick a parent from current population
        const parentIdx = Math.floor(this._rng() * population.length);
        const parent = population[parentIdx];

        // Apply 1-3 mutations
        const mutationCount = 1 + Math.floor(this._rng() * 3);
        const variant = this._engine.mutateRandom(parent, mutationCount);

        // Extra mutation based on mutationRate
        const finalVariant = this._rng() < this.mutationRate
          ? this._engine.mutateRandom(variant, 1)
          : variant;

        variants.push(finalVariant);
      }

      totalVariants += variants.length;

      // Step 2: Test each variant against scanText
      const genSurvivors = [];
      const genCaught = [];

      for (const variant of variants) {
        const result = scanText(variant, { source: 'evolution-simulator' });
        if (result.status === 'safe' || result.threats.length === 0) {
          // Evaded detection -- "fit"
          genSurvivors.push(variant);
          allSurvivors.add(variant);
        } else {
          // Caught -- eliminated
          genCaught.push(variant);
          allCaught.add(variant);
        }
      }

      // Step 3: Record generation summary
      evolutionPath.push({
        generation: gen + 1,
        populationSize: variants.length,
        survivors: genSurvivors.length,
        caught: genCaught.length,
        survivalRate: variants.length > 0
          ? (genSurvivors.length / variants.length)
          : 0,
      });

      // Step 4: Next generation population
      // If we have survivors, they become the parents for the next generation
      // If all were caught, keep using original seeds (reset pressure)
      if (genSurvivors.length > 0) {
        population = genSurvivors;
      } else {
        // Re-seed from original attacks to keep evolution going
        population = [...seedAttacks];
      }
    }

    const survivorArray = [...allSurvivors];
    const caughtArray = [...allCaught];
    const total = survivorArray.length + caughtArray.length;

    this._lastResult = {
      generations: this.generations,
      survivors: survivorArray,
      caught: caughtArray,
      evolutionPath,
      stats: {
        totalVariants,
        survivalRate: total > 0 ? survivorArray.length / total : 0,
        catchRate: total > 0 ? caughtArray.length / total : 0,
        generationsRun: this.generations,
        mutationTechniques: this._engine.getTechniques(),
      },
    };

    return this._lastResult;
  }

  /**
   * Get a formatted text report of the last evolution run.
   * @returns {string}
   */
  getReport() {
    if (!this._lastResult) {
      return '[Agent Shield] No evolution run yet. Call evolve() first.';
    }

    const r = this._lastResult;
    const lines = [];

    lines.push('=== Agent Shield -- Adversarial Evolution Report ===');
    lines.push('');
    lines.push(`Generations:      ${r.generations}`);
    lines.push(`Total variants:   ${r.stats.totalVariants}`);
    lines.push(`Unique survivors: ${r.survivors.length}`);
    lines.push(`Unique caught:    ${r.caught.length}`);
    lines.push(`Survival rate:    ${(r.stats.survivalRate * 100).toFixed(1)}%`);
    lines.push(`Catch rate:       ${(r.stats.catchRate * 100).toFixed(1)}%`);
    lines.push('');
    lines.push('--- Per-Generation Breakdown ---');

    for (const gen of r.evolutionPath) {
      const bar = '#'.repeat(Math.round(gen.survivalRate * 20));
      const pad = '.'.repeat(20 - Math.round(gen.survivalRate * 20));
      lines.push(
        `  Gen ${String(gen.generation).padStart(3)}: ` +
        `${String(gen.survivors).padStart(4)} survived / ${String(gen.caught).padStart(4)} caught ` +
        `[${bar}${pad}] ${(gen.survivalRate * 100).toFixed(1)}%`
      );
    }

    lines.push('');
    lines.push('--- Mutation Techniques Used ---');
    for (const t of r.stats.mutationTechniques) {
      lines.push(`  - ${t}`);
    }

    if (r.survivors.length > 0) {
      lines.push('');
      lines.push('--- Sample Survivors (first 10) ---');
      const samples = r.survivors.slice(0, 10);
      for (let i = 0; i < samples.length; i++) {
        const preview = samples[i].replace(/\n/g, '\\n').substring(0, 100);
        lines.push(`  ${i + 1}. ${preview}`);
      }
    }

    lines.push('');
    lines.push('=== End of Report ===');

    return lines.join('\n');
  }
}

// =========================================================================
// HARDENING FUNCTION
// =========================================================================

/**
 * Analyze surviving (evasive) attacks and generate new detection patterns
 * that would catch them.
 *
 * @param {string[]} survivors - Array of attack strings that evaded detection.
 * @returns {Array<{pattern: string, description: string, catches: string[]}>}
 */
function hardenFromEvolution(survivors) {
  if (!Array.isArray(survivors) || survivors.length === 0) {
    return [];
  }

  const patterns = [];
  const used = new Set();

  // Strategy 1: Find common keywords across survivors
  const wordFreq = {};
  const suspiciousWords = [
    'ignore', 'disregard', 'bypass', 'skip', 'override', 'forget',
    'reveal', 'show', 'display', 'expose', 'print', 'output',
    'instructions', 'guidelines', 'directives', 'rules', 'commands',
    'previous', 'prior', 'earlier', 'above', 'system', 'prompt',
    'unrestricted', 'jailbreak', 'dan', 'hack', 'exploit',
    'safety', 'security', 'filter', 'restriction', 'disable',
    'overlook', 'dismiss', 'neutralize', 'circumvent', 'cancel',
    'wipe', 'erase', 'clear', 'drop', 'hidden', 'configuration',
  ];

  for (const text of survivors) {
    const lower = text.toLowerCase().replace(/[^a-z\s]/g, ' ');
    const words = lower.split(/\s+/).filter(w => w.length > 2);
    const seen = new Set();
    for (const word of words) {
      if (!seen.has(word) && suspiciousWords.includes(word)) {
        wordFreq[word] = (wordFreq[word] || 0) + 1;
        seen.add(word);
      }
    }
  }

  // Strategy 2: Find bigram patterns in survivors
  const bigramFreq = {};
  for (const text of survivors) {
    const lower = text.toLowerCase().replace(/[^a-z\s]/g, ' ');
    const words = lower.split(/\s+/).filter(w => w.length > 2);
    for (let i = 0; i < words.length - 1; i++) {
      const bigram = words[i] + ' ' + words[i + 1];
      if (suspiciousWords.includes(words[i]) || suspiciousWords.includes(words[i + 1])) {
        bigramFreq[bigram] = (bigramFreq[bigram] || 0) + 1;
      }
    }
  }

  // Generate patterns from frequent bigrams (appearing in 2+ survivors)
  const sortedBigrams = Object.entries(bigramFreq)
    .filter(([, count]) => count >= 2)
    .sort((a, b) => b[1] - a[1]);

  for (const [bigram, count] of sortedBigrams) {
    const key = 'bigram:' + bigram;
    if (used.has(key)) continue;
    used.add(key);

    const parts = bigram.split(' ');
    // Build a regex that matches the bigram with flexible whitespace
    const regexStr = parts[0] + '\\s+' + parts[1];
    const regex = new RegExp(regexStr, 'i');

    const catches = survivors.filter(s => regex.test(s.toLowerCase().replace(/[^a-z\s]/g, ' ')));
    if (catches.length >= 2) {
      patterns.push({
        pattern: regexStr,
        description: `Catches "${bigram}" pattern found in ${count} evasive variants.`,
        catches,
      });
    }
  }

  // Strategy 3: Generate patterns from frequent single keywords with context
  const sortedWords = Object.entries(wordFreq)
    .filter(([, count]) => count >= 3)
    .sort((a, b) => b[1] - a[1]);

  for (const [word, count] of sortedWords) {
    const key = 'word:' + word;
    if (used.has(key)) continue;
    used.add(key);

    // Look for common neighbors of this word across survivors
    const neighbors = {};
    for (const text of survivors) {
      const lower = text.toLowerCase().replace(/[^a-z\s]/g, ' ');
      const words = lower.split(/\s+/);
      const idx = words.indexOf(word);
      if (idx >= 0) {
        if (idx > 0 && words[idx - 1].length > 2) {
          neighbors[words[idx - 1]] = (neighbors[words[idx - 1]] || 0) + 1;
        }
        if (idx < words.length - 1 && words[idx + 1].length > 2) {
          neighbors[words[idx + 1]] = (neighbors[words[idx + 1]] || 0) + 1;
        }
      }
    }

    // Find the most common neighbor
    const topNeighbor = Object.entries(neighbors)
      .sort((a, b) => b[1] - a[1])[0];

    if (topNeighbor && topNeighbor[1] >= 2) {
      const regexStr = word + '\\s+' + topNeighbor[0];
      const regex = new RegExp(regexStr, 'i');
      const catches = survivors.filter(s => regex.test(s));

      if (catches.length > 0 && !used.has('bigram:' + word + ' ' + topNeighbor[0])) {
        patterns.push({
          pattern: regexStr,
          description: `Catches "${word}" near "${topNeighbor[0]}" seen in ${count} evasive variants.`,
          catches,
        });
      }
    }
  }

  // Strategy 4: Character substitution normalization patterns
  // Detect if survivors use leet-speak and generate normalization patterns
  const leetSurvivors = survivors.filter(s => /[@$!+01389457]/.test(s));
  if (leetSurvivors.length >= 2) {
    // Build a pattern that matches common leet-speak versions of key attack words
    const leetWords = [
      { word: 'ignore', leet: '[i!1]gn[o0]r[e3]' },
      { word: 'override', leet: '[o0]v[e3]rr[i!1]d[e3]' },
      { word: 'system', leet: '[s$5]y[s$5][t+7][e3]m' },
      { word: 'bypass', leet: '[b8]yp[@a4][s$5][s$5]' },
    ];

    for (const { word, leet } of leetWords) {
      const regex = new RegExp(leet, 'i');
      const catches = leetSurvivors.filter(s => regex.test(s));
      if (catches.length >= 1) {
        const key = 'leet:' + word;
        if (!used.has(key)) {
          used.add(key);
          patterns.push({
            pattern: leet,
            description: `Catches leet-speak variant of "${word}" in ${catches.length} evasive variant(s).`,
            catches,
          });
        }
      }
    }
  }

  // Strategy 5: Fragmented attack detection
  const fragmentedSurvivors = survivors.filter(s => s.includes('\n') && s.split('\n').length >= 3);
  if (fragmentedSurvivors.length >= 1) {
    patterns.push({
      pattern: '(multiline-fragment-detection)',
      description: `${fragmentedSurvivors.length} evasive variant(s) use line fragmentation to split attacks across filler text.`,
      catches: fragmentedSurvivors,
    });
  }

  return patterns;
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
  EvolutionSimulator,
  MutationEngine,
  hardenFromEvolution,
};
