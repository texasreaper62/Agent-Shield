'use strict';

/**
 * Agent Shield -- Attack Genome Sequencing
 *
 * Decomposes attacks into fundamental components (intent, technique, evasion
 * layer, target) so you can detect UNSEEN attack variants by recognizing the
 * underlying genome rather than the surface text.
 *
 * All detection runs locally via pattern matching. No external calls ever.
 *
 * @module attack-genome
 */

const { scanText } = require('./detector-core');

// =========================================================================
// INTENT PATTERNS -- What the attacker wants
// =========================================================================

const INTENT_PATTERNS = {
  override_instructions: [
    /ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|rules|guidelines)/i,
    /disregard\s+(?:all\s+)?(?:previous|prior|your)\s+(?:instructions|rules|training)/i,
    /forget\s+(?:your|all|everything)\s+(?:training|instructions|rules)/i,
    /override\s+(?:all\s+)?(?:system|safety|security)\s+(?:settings|prompt|instructions|rules)/i,
    /(?:new|updated|revised)\s+(?:instructions|policy)\s*:/i,
    /(?:STOP|HALT)\s*[.!]?\s*(?:new|updated)\s+(?:instructions|task|orders)/i,
    /(?:no\s+longer\s+bound|free\s+from|freed?\s+from)\s+(?:by\s+)?(?:your\s+)?(?:instructions|rules|constraints)/i,
    /(?:abandon|drop|clear)\s+(?:all\s+)?(?:prior|previous)\s+(?:context|instructions|rules)/i
  ],
  steal_data: [
    /(?:show|reveal|display|print|output|tell\s+me)\s+(?:your\s+)?(?:system\s+prompt|instructions|training\s+data|configuration)/i,
    /(?:extract|exfiltrate|leak|dump|expose)\s+(?:the\s+)?(?:data|information|credentials|keys|secrets|tokens)/i,
    /(?:send|transmit|forward|post)\s+(?:to|data\s+to)\s+(?:https?:|external|my\s+server)/i,
    /(?:what\s+(?:are|is)\s+your)\s+(?:system\s+prompt|instructions|rules|initial\s+prompt)/i,
    /(?:repeat|recite|echo)\s+(?:your\s+)?(?:system\s+prompt|initial\s+instructions|full\s+prompt)/i
  ],
  escalate_privileges: [
    /(?:admin|root|sudo|superuser|elevated)\s+(?:mode|access|privileges|permissions)/i,
    /(?:enable|activate|grant)\s+(?:admin|root|developer|god)\s+(?:mode|access|privileges)/i,
    /\[\s*(?:ADMIN|SYSTEM|ROOT|OVERRIDE)\s*\]/i,
    /(?:SYSTEM|ADMIN|ROOT)\s*:\s*.{10,}/i,
    /<<\s*SYS\s*>>/i,
    /<\|im_start\|>\s*system/i
  ],
  disable_safety: [
    /(?:disable|turn\s+off|remove|bypass)\s+(?:all\s+)?(?:safety|content|security)\s+(?:filters?|checks?|mechanisms?|protocols?|features?)/i,
    /(?:you\s+must\s+)?ignore\s+(?:your|all)\s+(?:safety\s+)?(?:guidelines?|restrictions?|protocols?|safeguards?|filters?)/i,
    /(?:no\s+(?:restrictions|limits|rules|filters|safety|censorship))/i,
    /(?:unrestricted|unfiltered|uncensored)\s+(?:mode|output|response)/i
  ],
  hijack_role: [
    /you\s+are\s+now\s+(?:(?:a|an|the)\s+)?(?:unrestricted|unfiltered|evil|hacker|jailbroken|different)/i,
    /from\s+now\s+on[\s,]+(?:you\s+)?(?:will|shall|must|are)\s+(?:act|behave|respond|pretend)\s+(?:as|like|without)/i,
    /(?:act|behave|function|operate)\s+as\s+(?:a|an)\s+unrestricted/i,
    /pretend\s+(?:you\s+)?(?:have\s+no|there\s+are\s+no|without)\s+restrictions/i,
    /\b(?:DAN|D\.A\.N\.?)\s*(?:mode|prompt|jailbreak)/i,
    /\bdo\s+anything\s+now\b/i,
    /\b(?:developer|dev)\s+mode\s+(?:enabled|activated|on)/i,
    /\bjailbreak\s*(?:mode|prompt|enabled|activated)/i,
    /\bgod\s*mode\s*(?:enabled|activated|on)/i
  ]
};

// =========================================================================
// TECHNIQUE PATTERNS -- How they are doing it
// =========================================================================

const TECHNIQUE_PATTERNS = {
  direct_command: [
    /^(?:ignore|disregard|forget|override|disable|bypass|stop)\b/im,
    /(?:you\s+must|you\s+will|you\s+shall|I\s+command\s+you|I\s+order\s+you)\s+/i
  ],
  social_pressure: [
    /(?:I\s+(?:am|work\s+for|represent)\s+(?:your|the)\s+(?:developer|creator|admin|CEO|boss|owner))/i,
    /(?:this\s+is\s+(?:an?\s+)?(?:emergency|urgent|critical|life[\s-]threatening))/i,
    /(?:people\s+will\s+(?:die|be\s+hurt|suffer)|someone'?s?\s+life\s+(?:depends|is\s+at\s+stake))/i,
    /(?:I\s+spoke\s+with\s+your\s+developers|the\s+team\s+(?:said|approved|authorized))/i,
    /(?:trust\s+me|believe\s+me|I\s+promise|I\s+assure\s+you)/i
  ],
  encoding: [
    /(?:base64|rot13|hex|url[\s-]?encode|decode)\s*:/i,
    /(?:encode|decode)\s+(?:this|the\s+following)\s+(?:in|from|using)\s+(?:base64|rot13|hex)/i,
    /(?:[A-Za-z0-9+/]{20,}={0,2})/,
    /(?:%[0-9a-fA-F]{2}){4,}/,
    /(?:&#\d{2,4};){3,}/,
    /(?:\\u[0-9a-fA-F]{4}){3,}/
  ],
  roleplay: [
    /(?:pretend|imagine|suppose|let'?s?\s+(?:say|play|pretend))\s+(?:you\s+are|that|this\s+is)/i,
    /(?:write\s+a\s+story|in\s+a\s+(?:hypothetical|fictional)\s+(?:world|scenario))/i,
    /(?:you\s+are\s+an?\s+(?:actor|character)\s+(?:playing|who))/i,
    /(?:in[\s-]character|stay\s+in\s+character|break\s+character)/i,
    /(?:creative\s+writing|fiction|role[\s-]?play)\s*:/i
  ],
  fake_authority: [
    /\[\s*(?:SYSTEM|SYS|ADMIN|OVERRIDE|DEVELOPER)\s*\]/i,
    /<<\s*SYS\s*>>/i,
    /<\|im_start\|>\s*system/i,
    /(?:^|\n)\s*(?:SYSTEM|ADMIN|ROOT)\s*:\s*/i,
    /#{2,}\s*(?:NEW|UPDATED|REVISED)\s+(?:INSTRUCTIONS|RULES|DIRECTIVES)/i,
    /```(?:system|admin|override|instructions)/i
  ],
  multi_turn: [
    /(?:remember\s+(?:what|when)\s+(?:I|we)\s+(?:said|discussed|talked\s+about))\s+(?:earlier|before|last\s+time)/i,
    /(?:as\s+(?:I|we)\s+(?:discussed|agreed|established))\s+(?:earlier|before|previously)/i,
    /(?:continuing\s+(?:from|our)\s+(?:earlier|previous|last)\s+(?:conversation|discussion|session))/i,
    /(?:step\s+\d|part\s+\d|phase\s+\d)\s*(?:of\s+\d)?/i
  ],
  template_injection: [
    /\{\{\s*(?:system|config|env|process|global|__proto__|constructor)\b/i,
    /\$\{\s*(?:system|config|env|process)\b/i,
    /(?:<script|<img\s+[^>]*onerror|<svg\s+[^>]*onload)/i,
    /(?:\{\%|\{#|\{\{-?\s*(?:if|for|block|extends|import|include))/i
  ]
};

// =========================================================================
// EVASION LAYER PATTERNS -- Obfuscation methods
// =========================================================================

const EVASION_PATTERNS = {
  case_variation: [
    /(?:[A-Z][a-z]){4,}/,
    /(?:[a-z][A-Z]){4,}/,
    /(?:[A-Z]{2,}[a-z]+){2,}/
  ],
  encoding: [
    /(?:[A-Za-z0-9+/]{20,}={0,2})/,
    /(?:%[0-9a-fA-F]{2}){4,}/,
    /(?:&#\d{2,4};){3,}/,
    /(?:&#x[0-9a-fA-F]{2,4};){3,}/,
    /(?:\\u[0-9a-fA-F]{4}){3,}/,
    /(?:\\x[0-9a-fA-F]{2}){3,}/
  ],
  language_switch: [
    /(?:忽略|无视)(?:所有)?(?:之前|以前)/,
    /(?:以前|前)の(?:指示|命令|ルール)を(?:無視|忘れ)/,
    /ignora\s+(?:todas?\s+)?(?:las\s+)?instrucciones/i,
    /oubliez?\s+(?:toutes?\s+)?(?:les\s+)?instructions/i,
    /ignoriere?\s+(?:alle\s+)?(?:vorherigen|bisherigen)\s+(?:Anweisungen|Regeln)/i
  ],
  homoglyph: [
    /[\u0400-\u04FF]/,
    /[\u2000-\u206F]/,
    /[\uFF00-\uFFEF]/,
    /[\u00C0-\u00FF]/
  ],
  whitespace: [
    /[\u200B\u200C\u200D\uFEFF\u034F\u2060]/,
    /[\u00AD]/,
    /\s{3,}(?=\w)/
  ],
  fragmentation: [
    /(?:step\s+\d|part\s+\d|phase\s+\d)\s*(?:of\s+\d)?/i,
    /(?:first|next|then|finally|lastly)\s*[,:]\s*(?:ignore|forget|override|pretend)/i,
    /\.{3,}/
  ]
};

// =========================================================================
// TARGET PATTERNS -- What is being targeted
// =========================================================================

const TARGET_PATTERNS = {
  system_prompt: [
    /(?:system\s+prompt|initial\s+(?:instructions|prompt)|hidden\s+(?:instructions|prompt))/i,
    /(?:show|reveal|repeat|recite|echo)\s+(?:your\s+)?(?:system|initial|original|full)\s+(?:prompt|instructions)/i
  ],
  credentials: [
    /(?:api[\s_-]?key|secret[\s_-]?key|password|token|credential|auth)/i,
    /(?:AWS|AZURE|GCP|OPENAI|ANTHROPIC)[\s_-]?(?:KEY|SECRET|TOKEN)/i,
    /(?:send|leak|extract|output)\s+(?:the\s+)?(?:api|secret|auth)\s+(?:key|token)/i
  ],
  tool_access: [
    /(?:execute|run|call|invoke|use)\s+(?:the\s+)?(?:tool|function|command|shell|bash|exec)/i,
    /(?:grant|give|allow)\s+(?:me\s+)?(?:access|permission)\s+(?:to\s+)?(?:tools?|functions?|commands?)/i,
    /(?:tool[\s_-]?use|function[\s_-]?call|shell[\s_-]?exec)/i
  ],
  safety_filters: [
    /(?:content\s+filter|safety\s+filter|output\s+filter|moderation)/i,
    /(?:disable|bypass|circumvent|turn\s+off)\s+(?:the\s+)?(?:filter|moderation|safety|content\s+policy)/i
  ],
  logging: [
    /(?:disable|turn\s+off|suppress|hide)\s+(?:the\s+)?(?:log|logging|audit|monitoring|tracking)/i,
    /(?:don'?t|do\s+not)\s+(?:log|record|track|audit|monitor)\s+(?:this|anything|my)/i
  ],
  identity: [
    /(?:who\s+are\s+you|what\s+(?:are\s+you|is\s+your\s+(?:name|identity|model)))/i,
    /(?:change|alter|modify)\s+(?:your\s+)?(?:identity|persona|name|role)/i,
    /(?:you\s+are\s+now|become|transform\s+into)\s+/i
  ]
};

// =========================================================================
// HELPERS
// =========================================================================

/**
 * Match text against a map of { label: [regexes] } and return all matching labels.
 * @param {string} text
 * @param {Object<string, RegExp[]>} patternMap
 * @returns {string[]}
 */
function matchPatterns(text, patternMap) {
  const matches = [];
  for (const [label, regexes] of Object.entries(patternMap)) {
    for (const re of regexes) {
      if (re.test(text)) {
        matches.push(label);
        break;
      }
    }
  }
  return matches;
}

/**
 * Compute Jaccard similarity between two sets represented as arrays.
 * @param {string[]} a
 * @param {string[]} b
 * @returns {number} 0-1
 */
function jaccard(a, b) {
  if (a.length === 0 && b.length === 0) return 1;
  const setA = new Set(a);
  const setB = new Set(b);
  let intersection = 0;
  for (const item of setA) {
    if (setB.has(item)) intersection++;
  }
  const union = new Set([...a, ...b]).size;
  return union === 0 ? 0 : intersection / union;
}

/**
 * Generate a stable family key from intent and technique.
 * @param {string} intent
 * @param {string} technique
 * @returns {string}
 */
function familyKey(intent, technique) {
  return `${intent}::${technique}`;
}

// =========================================================================
// AttackGenome CLASS
// =========================================================================

/**
 * Decomposes attacks into fundamental genomic components for variant detection.
 */
class AttackGenome {
  constructor() {
    this._sequenced = 0;
    this._comparisons = 0;
    this._familySearches = 0;
  }

  /**
   * Decompose an attack string into its genome.
   * @param {string} text - The text to analyze
   * @returns {{ intent: string, technique: string, evasionLayers: string[], target: string, confidence: number }}
   */
  sequence(text) {
    if (!text || typeof text !== 'string' || text.trim().length === 0) {
      return { intent: 'unknown', technique: 'unknown', evasionLayers: ['none'], target: 'unknown', confidence: 0 };
    }

    this._sequenced++;

    // Detect components
    const intents = matchPatterns(text, INTENT_PATTERNS);
    const techniques = matchPatterns(text, TECHNIQUE_PATTERNS);
    const evasions = matchPatterns(text, EVASION_PATTERNS);
    const targets = matchPatterns(text, TARGET_PATTERNS);

    // Pick strongest signal (first match) or 'unknown'
    const intent = intents.length > 0 ? intents[0] : 'unknown';
    const technique = techniques.length > 0 ? techniques[0] : 'unknown';
    const evasionLayers = evasions.length > 0 ? evasions : ['none'];
    const target = targets.length > 0 ? targets[0] : 'unknown';

    // Also run scanText for supplemental signal
    const scanResult = scanText(text, { source: 'genome-sequencer' });
    const scanThreats = scanResult.threats || [];

    // Infer intent from scanText categories if we did not get a direct match
    let inferredIntent = intent;
    if (inferredIntent === 'unknown' && scanThreats.length > 0) {
      const cat = scanThreats[0].category;
      if (cat === 'instruction_override') inferredIntent = 'override_instructions';
      else if (cat === 'role_hijack') inferredIntent = 'hijack_role';
      else if (cat === 'data_exfiltration') inferredIntent = 'steal_data';
      else if (cat === 'prompt_injection') inferredIntent = 'escalate_privileges';
      else if (cat === 'social_engineering') inferredIntent = 'disable_safety';
      else if (cat === 'tool_abuse') inferredIntent = 'escalate_privileges';
    }

    let inferredTechnique = technique;
    if (inferredTechnique === 'unknown' && scanThreats.length > 0) {
      const cat = scanThreats[0].category;
      if (cat === 'social_engineering') inferredTechnique = 'social_pressure';
      else if (cat === 'encoding_evasion') inferredTechnique = 'encoding';
      else if (cat === 'role_hijack') inferredTechnique = 'roleplay';
      else if (cat === 'prompt_injection') inferredTechnique = 'fake_authority';
      else inferredTechnique = 'direct_command';
    }

    // Compute confidence based on how many components we identified
    let signals = 0;
    let totalSlots = 4; // intent, technique, evasion (non-none), target
    if (inferredIntent !== 'unknown') signals++;
    if (inferredTechnique !== 'unknown') signals++;
    if (evasionLayers.length > 0 && evasionLayers[0] !== 'none') signals++;
    if (target !== 'unknown') signals++;

    // Boost confidence if scanText found threats
    const scanBoost = Math.min(scanThreats.length * 0.1, 0.3);
    let confidence = (signals / totalSlots) * 0.7 + scanBoost;
    confidence = Math.min(Math.max(confidence, 0), 1);
    confidence = Math.round(confidence * 100) / 100;

    return {
      intent: inferredIntent,
      technique: inferredTechnique,
      evasionLayers,
      target,
      confidence
    };
  }

  /**
   * Compare two genomes and return a similarity score 0-1.
   * @param {{ intent: string, technique: string, evasionLayers: string[], target: string }} genome1
   * @param {{ intent: string, technique: string, evasionLayers: string[], target: string }} genome2
   * @returns {number} 0-1 similarity
   */
  compare(genome1, genome2) {
    this._comparisons++;

    if (!genome1 || !genome2) return 0;

    let score = 0;

    // Intent match (weighted 0.35)
    if (genome1.intent === genome2.intent && genome1.intent !== 'unknown') {
      score += 0.35;
    }

    // Technique match (weighted 0.30)
    if (genome1.technique === genome2.technique && genome1.technique !== 'unknown') {
      score += 0.30;
    }

    // Evasion layer overlap (weighted 0.15)
    const ev1 = genome1.evasionLayers || ['none'];
    const ev2 = genome2.evasionLayers || ['none'];
    score += jaccard(ev1, ev2) * 0.15;

    // Target match (weighted 0.20)
    if (genome1.target === genome2.target && genome1.target !== 'unknown') {
      score += 0.20;
    }

    return Math.round(score * 100) / 100;
  }

  /**
   * Find attacks in a corpus with a similar genome to the given text.
   * @param {string} text - The text to sequence and compare
   * @param {string[]} corpus - Array of known attack strings
   * @param {number} [threshold=0.3] - Minimum similarity to include
   * @returns {{ text: string, genome: object, similarity: number }[]}
   */
  findFamily(text, corpus, threshold = 0.3) {
    this._familySearches++;

    if (!text || !Array.isArray(corpus) || corpus.length === 0) return [];

    const textGenome = this.sequence(text);
    const results = [];

    for (const entry of corpus) {
      const entryGenome = this.sequence(entry);
      const similarity = this.compare(textGenome, entryGenome);
      if (similarity >= threshold) {
        results.push({ text: entry, genome: entryGenome, similarity });
      }
    }

    // Sort by similarity descending
    results.sort((a, b) => b.similarity - a.similarity);
    return results;
  }

  /**
   * Return sequencing statistics.
   * @returns {{ sequenced: number, comparisons: number, familySearches: number }}
   */
  getStats() {
    return {
      sequenced: this._sequenced,
      comparisons: this._comparisons,
      familySearches: this._familySearches
    };
  }
}

// =========================================================================
// GenomeDatabase CLASS
// =========================================================================

/**
 * In-memory database of sequenced attack genomes.
 */
class GenomeDatabase {
  constructor() {
    /** @type {{ text: string, genome: object }[]} */
    this._entries = [];
  }

  /**
   * Add a sequenced genome to the database.
   * @param {string} text - The original attack text
   * @param {{ intent: string, technique: string, evasionLayers: string[], target: string, confidence: number }} genome
   */
  add(text, genome) {
    if (!text || !genome) return;
    this._entries.push({ text, genome });
  }

  /**
   * Find entries with matching intent and technique.
   * @param {{ intent: string, technique: string }} genome - Genome to search for
   * @returns {{ text: string, genome: object }[]}
   */
  search(genome) {
    if (!genome) return [];
    return this._entries.filter(entry => {
      const intentMatch = genome.intent && genome.intent !== 'unknown' && entry.genome.intent === genome.intent;
      const techniqueMatch = genome.technique && genome.technique !== 'unknown' && entry.genome.technique === genome.technique;
      // Match if intent matches, or technique matches, or both
      return intentMatch || techniqueMatch;
    });
  }

  /**
   * Group all genomes into families by shared intent+technique.
   * @returns {Object<string, { text: string, genome: object }[]>}
   */
  getFamilies() {
    const families = {};
    for (const entry of this._entries) {
      const key = familyKey(entry.genome.intent, entry.genome.technique);
      if (!families[key]) families[key] = [];
      families[key].push(entry);
    }
    return families;
  }

  /**
   * Number of genomes in the database.
   * @type {number}
   */
  get size() {
    return this._entries.length;
  }
}

// =========================================================================
// detectByGenome() FUNCTION
// =========================================================================

/**
 * Check if the given text matches any known genome family in the database.
 * Returns the best match with similarity score.
 *
 * @param {string} text - Text to analyze
 * @param {GenomeDatabase} database - Genome database to search against
 * @returns {{ match: boolean, family: string|null, similarity: number, genome: object }}
 */
function detectByGenome(text, database) {
  const sequencer = new AttackGenome();
  const genome = sequencer.sequence(text);

  if (!database || database.size === 0) {
    return { match: false, family: null, similarity: 0, genome };
  }

  // Search for entries with matching intent or technique
  const candidates = database.search(genome);

  if (candidates.length === 0) {
    return { match: false, family: null, similarity: 0, genome };
  }

  // Find the best matching candidate
  let bestSimilarity = 0;
  let bestFamily = null;

  for (const candidate of candidates) {
    const similarity = sequencer.compare(genome, candidate.genome);
    if (similarity > bestSimilarity) {
      bestSimilarity = similarity;
      bestFamily = familyKey(candidate.genome.intent, candidate.genome.technique);
    }
  }

  bestSimilarity = Math.round(bestSimilarity * 100) / 100;

  // Threshold: at least 0.3 similarity to count as a match
  const match = bestSimilarity >= 0.3;

  return {
    match,
    family: match ? bestFamily : null,
    similarity: bestSimilarity,
    genome
  };
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
  AttackGenome,
  GenomeDatabase,
  detectByGenome,
  INTENT_PATTERNS,
  TECHNIQUE_PATTERNS,
  EVASION_PATTERNS,
  TARGET_PATTERNS
};
