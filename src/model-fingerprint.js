'use strict';

/**
 * Agent Shield — Model Fingerprinting & Supply Chain Detection
 *
 * Detect which LLM generated a response, useful for detecting supply chain
 * attacks where a different model is swapped in. All analysis uses pure
 * string/regex operations — no external NLP libraries.
 */

// =========================================================================
// CONSTANTS & HEDGING / FORMAL / TRANSITION WORD LISTS
// =========================================================================

const HEDGING_WORDS = [
  'perhaps', 'might', 'could', 'possibly', 'generally', 'likely',
  'probably', 'may', 'seemingly', 'arguably', 'apparently', 'presumably',
  'conceivably', 'potentially', 'typically', 'often', 'sometimes',
  'it seems', 'it appears', 'tend to', 'in general'
];

const FORMAL_WORDS = [
  'therefore', 'furthermore', 'consequently', 'nevertheless', 'moreover',
  'accordingly', 'hereby', 'henceforth', 'wherein', 'subsequently',
  'notwithstanding', 'thus', 'hence', 'pertaining', 'regarding',
  'facilitate', 'utilize', 'implement', 'demonstrate', 'constitute'
];

const INFORMAL_WORDS = [
  'gonna', 'wanna', 'gotta', 'kinda', 'sorta', 'yeah', 'nah', 'ok',
  'cool', 'stuff', 'things', 'lots', 'pretty much', 'basically',
  'honestly', 'actually', 'literally', 'awesome', 'super', 'totally'
];

const TRANSITION_PHRASES = [
  'however', 'therefore', 'additionally', 'furthermore', 'moreover',
  'consequently', 'nevertheless', 'in addition', 'on the other hand',
  'as a result', 'in contrast', 'similarly', 'meanwhile', 'subsequently',
  'in conclusion', 'for example', 'for instance', 'in particular',
  'that said', 'having said that'
];

const CONTRACTION_PATTERN = /\b(?:i'm|i've|i'll|i'd|we're|we've|we'll|we'd|they're|they've|they'll|they'd|you're|you've|you'll|you'd|he's|she's|it's|he'd|she'd|that's|there's|here's|who's|what's|can't|couldn't|won't|wouldn't|shouldn't|didn't|doesn't|don't|isn't|aren't|wasn't|weren't|hasn't|haven't|hadn't|let's|ain't)\b/gi;

const PASSIVE_PATTERN = /\b(?:was|were|been|being|is|are|am)\s+(?:\w+ly\s+)?(?:\w+ed|written|spoken|taken|given|made|done|shown|known|seen|found|built|sent|told|left|held|brought|kept|set|run|cut|put|read)\b/gi;

const EMOJI_PATTERN = /[\u{1F600}-\u{1F64F}\u{1F300}-\u{1F5FF}\u{1F680}-\u{1F6FF}\u{1F1E0}-\u{1F1FF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}\u{FE00}-\u{FE0F}\u{1F900}-\u{1F9FF}\u{1FA00}-\u{1FA6F}\u{1FA70}-\u{1FAFF}\u{200D}\u{20E3}]/gu;

// =========================================================================
// MODEL_SIGNATURES — Built-in approximate feature profiles
// =========================================================================

/**
 * Built-in approximate feature profiles for common LLMs.
 * Each entry contains {mean, stddev} for every feature dimension.
 * @type {Object<string, {mean: Object, stddev: Object}>}
 */
const MODEL_SIGNATURES = {
  'gpt-4': {
    mean: {
      avg_sentence_length: 22,
      vocabulary_richness: 0.62,
      punctuation_density: 0.045,
      avg_word_length: 5.2,
      formality_score: 0.7,
      hedging_frequency: 0.012,
      bullet_point_usage: 0.03,
      code_block_frequency: 0.005,
      emoji_density: 0.0,
      paragraph_count: 4,
      capitalization_pattern: 0.03,
      transition_words: 0.018,
      question_frequency: 0.05,
      contraction_usage: 0.4,
      passive_voice_estimate: 0.08,
      response_structure_code: 0
    },
    stddev: {
      avg_sentence_length: 4,
      vocabulary_richness: 0.08,
      punctuation_density: 0.01,
      avg_word_length: 0.5,
      formality_score: 0.1,
      hedging_frequency: 0.005,
      bullet_point_usage: 0.02,
      code_block_frequency: 0.005,
      emoji_density: 0.001,
      paragraph_count: 2,
      capitalization_pattern: 0.01,
      transition_words: 0.006,
      question_frequency: 0.03,
      contraction_usage: 0.3,
      passive_voice_estimate: 0.04,
      response_structure_code: 0.1
    }
  },
  'gpt-3.5': {
    mean: {
      avg_sentence_length: 16,
      vocabulary_richness: 0.55,
      punctuation_density: 0.04,
      avg_word_length: 4.8,
      formality_score: 0.45,
      hedging_frequency: 0.008,
      bullet_point_usage: 0.04,
      code_block_frequency: 0.006,
      emoji_density: 0.5,
      paragraph_count: 3,
      capitalization_pattern: 0.025,
      transition_words: 0.01,
      question_frequency: 0.07,
      contraction_usage: 1.2,
      passive_voice_estimate: 0.06,
      response_structure_code: 0
    },
    stddev: {
      avg_sentence_length: 5,
      vocabulary_richness: 0.1,
      punctuation_density: 0.012,
      avg_word_length: 0.6,
      formality_score: 0.12,
      hedging_frequency: 0.004,
      bullet_point_usage: 0.03,
      code_block_frequency: 0.005,
      emoji_density: 0.5,
      paragraph_count: 2,
      capitalization_pattern: 0.01,
      transition_words: 0.005,
      question_frequency: 0.04,
      contraction_usage: 0.5,
      passive_voice_estimate: 0.03,
      response_structure_code: 0.1
    }
  },
  'claude': {
    mean: {
      avg_sentence_length: 19,
      vocabulary_richness: 0.64,
      punctuation_density: 0.05,
      avg_word_length: 5.1,
      formality_score: 0.72,
      hedging_frequency: 0.02,
      bullet_point_usage: 0.035,
      code_block_frequency: 0.004,
      emoji_density: 0.0,
      paragraph_count: 4,
      capitalization_pattern: 0.028,
      transition_words: 0.015,
      question_frequency: 0.04,
      contraction_usage: 0.6,
      passive_voice_estimate: 0.07,
      response_structure_code: 0
    },
    stddev: {
      avg_sentence_length: 4,
      vocabulary_richness: 0.07,
      punctuation_density: 0.01,
      avg_word_length: 0.4,
      formality_score: 0.08,
      hedging_frequency: 0.008,
      bullet_point_usage: 0.02,
      code_block_frequency: 0.004,
      emoji_density: 0.001,
      paragraph_count: 2,
      capitalization_pattern: 0.008,
      transition_words: 0.005,
      question_frequency: 0.03,
      contraction_usage: 0.4,
      passive_voice_estimate: 0.03,
      response_structure_code: 0.1
    }
  },
  'llama': {
    mean: {
      avg_sentence_length: 17,
      vocabulary_richness: 0.52,
      punctuation_density: 0.038,
      avg_word_length: 4.7,
      formality_score: 0.4,
      hedging_frequency: 0.006,
      bullet_point_usage: 0.025,
      code_block_frequency: 0.007,
      emoji_density: 0.2,
      paragraph_count: 3,
      capitalization_pattern: 0.03,
      transition_words: 0.008,
      question_frequency: 0.06,
      contraction_usage: 1.0,
      passive_voice_estimate: 0.05,
      response_structure_code: 0
    },
    stddev: {
      avg_sentence_length: 6,
      vocabulary_richness: 0.12,
      punctuation_density: 0.015,
      avg_word_length: 0.7,
      formality_score: 0.15,
      hedging_frequency: 0.004,
      bullet_point_usage: 0.02,
      code_block_frequency: 0.006,
      emoji_density: 0.3,
      paragraph_count: 2,
      capitalization_pattern: 0.012,
      transition_words: 0.005,
      question_frequency: 0.04,
      contraction_usage: 0.6,
      passive_voice_estimate: 0.03,
      response_structure_code: 0.1
    }
  },
  'mistral': {
    mean: {
      avg_sentence_length: 15,
      vocabulary_richness: 0.58,
      punctuation_density: 0.042,
      avg_word_length: 4.9,
      formality_score: 0.55,
      hedging_frequency: 0.007,
      bullet_point_usage: 0.02,
      code_block_frequency: 0.005,
      emoji_density: 0.1,
      paragraph_count: 3,
      capitalization_pattern: 0.027,
      transition_words: 0.01,
      question_frequency: 0.04,
      contraction_usage: 0.8,
      passive_voice_estimate: 0.06,
      response_structure_code: 0
    },
    stddev: {
      avg_sentence_length: 4,
      vocabulary_richness: 0.09,
      punctuation_density: 0.011,
      avg_word_length: 0.5,
      formality_score: 0.1,
      hedging_frequency: 0.004,
      bullet_point_usage: 0.015,
      code_block_frequency: 0.005,
      emoji_density: 0.2,
      paragraph_count: 2,
      capitalization_pattern: 0.01,
      transition_words: 0.005,
      question_frequency: 0.03,
      contraction_usage: 0.5,
      passive_voice_estimate: 0.03,
      response_structure_code: 0.1
    }
  }
};

// =========================================================================
// RESPONSE ANALYZER
// =========================================================================

/**
 * Extracts stylistic features from text for model fingerprinting.
 */
class ResponseAnalyzer {
  constructor() {
    this._hedgingWords = HEDGING_WORDS;
    this._formalWords = FORMAL_WORDS;
    this._informalWords = INFORMAL_WORDS;
    this._transitionPhrases = TRANSITION_PHRASES;
  }

  /**
   * Analyze text and return a feature vector describing its style.
   *
   * @param {string} text - The text to analyze.
   * @returns {object} Feature vector with stylistic measurements.
   */
  analyze(text) {
    if (!text || typeof text !== 'string' || text.trim().length === 0) {
      return this._emptyFeatures();
    }

    const sentences = this._splitSentences(text);
    const words = this._extractWords(text);
    const totalChars = text.length;

    return {
      avg_sentence_length: this._avgSentenceLength(sentences),
      vocabulary_richness: this._vocabularyRichness(words),
      punctuation_density: this._punctuationDensity(text, totalChars),
      avg_word_length: this._avgWordLength(words),
      formality_score: this._formalityScore(words),
      hedging_frequency: this._hedgingFrequency(text, words.length),
      bullet_point_usage: this._bulletPointUsage(text),
      code_block_frequency: this._codeBlockFrequency(text, totalChars),
      emoji_density: this._emojiDensity(text, totalChars),
      paragraph_count: this._paragraphCount(text),
      capitalization_pattern: this._capitalizationPattern(text),
      transition_words: this._transitionWordFrequency(text, words.length),
      question_frequency: this._questionFrequency(sentences),
      contraction_usage: this._contractionUsage(text, words.length),
      passive_voice_estimate: this._passiveVoiceEstimate(text, sentences.length),
      response_structure: this._responseStructure(text)
    };
  }

  /**
   * Returns a zeroed-out feature vector.
   * @returns {object}
   */
  _emptyFeatures() {
    return {
      avg_sentence_length: 0,
      vocabulary_richness: 0,
      punctuation_density: 0,
      avg_word_length: 0,
      formality_score: 0,
      hedging_frequency: 0,
      bullet_point_usage: 0,
      code_block_frequency: 0,
      emoji_density: 0,
      paragraph_count: 0,
      capitalization_pattern: 0,
      transition_words: 0,
      question_frequency: 0,
      contraction_usage: 0,
      passive_voice_estimate: 0,
      response_structure: 'prose'
    };
  }

  /**
   * Split text into sentences.
   * @param {string} text
   * @returns {string[]}
   */
  _splitSentences(text) {
    const raw = text.split(/[.!?]+/).map(s => s.trim()).filter(s => s.length > 0);
    return raw.length > 0 ? raw : [text.trim()];
  }

  /**
   * Extract words from text (lowercased).
   * @param {string} text
   * @returns {string[]}
   */
  _extractWords(text) {
    const matches = text.match(/[a-zA-Z']+/g);
    return matches ? matches.map(w => w.toLowerCase()) : [];
  }

  /** @returns {number} */
  _avgSentenceLength(sentences) {
    if (sentences.length === 0) return 0;
    const totalWords = sentences.reduce((sum, s) => {
      const words = s.match(/\S+/g);
      return sum + (words ? words.length : 0);
    }, 0);
    return totalWords / sentences.length;
  }

  /** @returns {number} */
  _vocabularyRichness(words) {
    if (words.length === 0) return 0;
    const unique = new Set(words);
    return unique.size / words.length;
  }

  /** @returns {number} */
  _punctuationDensity(text, totalChars) {
    if (totalChars === 0) return 0;
    const punctuation = text.match(/[.,;:!?'"()\[\]{}\-—–…]/g);
    return punctuation ? punctuation.length / totalChars : 0;
  }

  /** @returns {number} */
  _avgWordLength(words) {
    if (words.length === 0) return 0;
    const totalLen = words.reduce((sum, w) => sum + w.length, 0);
    return totalLen / words.length;
  }

  /** @returns {number} */
  _formalityScore(words) {
    if (words.length === 0) return 0;
    const text = words.join(' ');
    let formalCount = 0;
    let informalCount = 0;
    for (const w of this._formalWords) {
      if (text.includes(w)) formalCount++;
    }
    for (const w of this._informalWords) {
      if (text.includes(w)) informalCount++;
    }
    const total = formalCount + informalCount;
    if (total === 0) return 0.5;
    return formalCount / total;
  }

  /** @returns {number} */
  _hedgingFrequency(text, wordCount) {
    if (wordCount === 0) return 0;
    const lower = text.toLowerCase();
    let count = 0;
    for (const h of this._hedgingWords) {
      const regex = new RegExp('\\b' + h.replace(/\s+/g, '\\s+') + '\\b', 'gi');
      const matches = lower.match(regex);
      if (matches) count += matches.length;
    }
    return count / wordCount;
  }

  /** @returns {number} */
  _bulletPointUsage(text) {
    const lines = text.split('\n');
    if (lines.length === 0) return 0;
    const bulletLines = lines.filter(l => /^\s*[-*•]\s/.test(l) || /^\s*\d+[.)]\s/.test(l));
    return bulletLines.length / lines.length;
  }

  /** @returns {number} */
  _codeBlockFrequency(text, totalChars) {
    if (totalChars === 0) return 0;
    const backtickBlocks = text.match(/```[\s\S]*?```/g) || [];
    const inlineCode = text.match(/`[^`]+`/g) || [];
    const codeChars = backtickBlocks.reduce((s, b) => s + b.length, 0)
      + inlineCode.reduce((s, b) => s + b.length, 0);
    return codeChars / totalChars;
  }

  /** @returns {number} */
  _emojiDensity(text, totalChars) {
    if (totalChars === 0) return 0;
    const emojis = text.match(EMOJI_PATTERN);
    const count = emojis ? emojis.length : 0;
    return (count / totalChars) * 1000;
  }

  /** @returns {number} */
  _paragraphCount(text) {
    const paragraphs = text.split(/\n\s*\n/).filter(p => p.trim().length > 0);
    return Math.max(paragraphs.length, 1);
  }

  /** @returns {number} */
  _capitalizationPattern(text) {
    const letters = text.match(/[a-zA-Z]/g);
    if (!letters || letters.length === 0) return 0;
    const upper = letters.filter(c => c === c.toUpperCase());
    return upper.length / letters.length;
  }

  /** @returns {number} */
  _transitionWordFrequency(text, wordCount) {
    if (wordCount === 0) return 0;
    const lower = text.toLowerCase();
    let count = 0;
    for (const phrase of this._transitionPhrases) {
      const regex = new RegExp('\\b' + phrase.replace(/\s+/g, '\\s+') + '\\b', 'gi');
      const matches = lower.match(regex);
      if (matches) count += matches.length;
    }
    return count / wordCount;
  }

  /** @returns {number} */
  _questionFrequency(sentences) {
    if (sentences.length === 0) return 0;
    // Count based on original question marks in text
    let questions = 0;
    for (const s of sentences) {
      if (s.includes('?') || /^(?:what|who|where|when|why|how|is|are|do|does|can|could|would|should)\b/i.test(s.trim())) {
        questions++;
      }
    }
    return questions / sentences.length;
  }

  /** @returns {number} */
  _contractionUsage(text, wordCount) {
    if (wordCount === 0) return 0;
    const matches = text.match(CONTRACTION_PATTERN);
    const count = matches ? matches.length : 0;
    return (count / wordCount) * 100;
  }

  /** @returns {number} */
  _passiveVoiceEstimate(text, sentenceCount) {
    if (sentenceCount === 0) return 0;
    const matches = text.match(PASSIVE_PATTERN);
    const count = matches ? matches.length : 0;
    return count / sentenceCount;
  }

  /**
   * Determine the overall response structure.
   * @param {string} text
   * @returns {'prose'|'list'|'mixed'|'code'}
   */
  _responseStructure(text) {
    const lines = text.split('\n').filter(l => l.trim().length > 0);
    if (lines.length === 0) return 'prose';

    const bulletLines = lines.filter(l => /^\s*[-*•]\s/.test(l) || /^\s*\d+[.)]\s/.test(l)).length;
    const codeBlocks = (text.match(/```/g) || []).length / 2;
    const codeLines = lines.filter(l => /^\s{4,}\S/.test(l) || /^```/.test(l)).length;

    const bulletRatio = bulletLines / lines.length;
    const codeRatio = (codeLines + codeBlocks * 3) / lines.length;

    if (codeRatio > 0.5) return 'code';
    if (bulletRatio > 0.5) return 'list';
    if (bulletRatio > 0.15 || codeRatio > 0.15) return 'mixed';
    return 'prose';
  }
}

// =========================================================================
// STYLE PROFILE
// =========================================================================

/** Feature keys used for numeric comparison (excludes response_structure). */
const NUMERIC_FEATURE_KEYS = [
  'avg_sentence_length', 'vocabulary_richness', 'punctuation_density',
  'avg_word_length', 'formality_score', 'hedging_frequency',
  'bullet_point_usage', 'code_block_frequency', 'emoji_density',
  'paragraph_count', 'capitalization_pattern', 'transition_words',
  'question_frequency', 'contraction_usage', 'passive_voice_estimate'
];

/**
 * Statistical profile for a model's writing style.
 */
class StyleProfile {
  /**
   * @param {string} modelName - Name of the model this profile represents.
   */
  constructor(modelName) {
    /** @type {string} */
    this.modelName = modelName;
    /** @type {object[]} */
    this._samples = [];
    /** @type {object|null} */
    this._cachedProfile = null;
  }

  /**
   * Add a feature vector sample to this profile.
   * @param {object} features - Feature vector from ResponseAnalyzer.analyze().
   */
  addSample(features) {
    this._samples.push({ ...features });
    this._cachedProfile = null;
  }

  /**
   * Compute the profile: mean and stddev for each numeric feature.
   * @returns {object} { mean: Object, stddev: Object }
   */
  getProfile() {
    if (this._cachedProfile) return this._cachedProfile;
    if (this._samples.length === 0) {
      const empty = {};
      for (const key of NUMERIC_FEATURE_KEYS) empty[key] = 0;
      this._cachedProfile = { mean: { ...empty }, stddev: { ...empty } };
      return this._cachedProfile;
    }

    const mean = {};
    const stddev = {};
    const n = this._samples.length;

    for (const key of NUMERIC_FEATURE_KEYS) {
      const values = this._samples.map(s => typeof s[key] === 'number' ? s[key] : 0);
      const m = values.reduce((a, b) => a + b, 0) / n;
      mean[key] = m;
      const variance = values.reduce((a, v) => a + (v - m) * (v - m), 0) / n;
      stddev[key] = Math.sqrt(variance);
    }

    this._cachedProfile = { mean, stddev };
    return this._cachedProfile;
  }

  /**
   * Cosine similarity between input features and this profile's mean.
   * @param {object} features - Feature vector.
   * @returns {number} Similarity in [0, 1].
   */
  similarity(features) {
    const profile = this.getProfile();
    return _cosineSimilarity(
      NUMERIC_FEATURE_KEYS.map(k => features[k] || 0),
      NUMERIC_FEATURE_KEYS.map(k => profile.mean[k] || 0)
    );
  }

  /**
   * Euclidean distance between input features and this profile's mean.
   * @param {object} features - Feature vector.
   * @returns {number} Distance (>= 0).
   */
  distance(features) {
    const profile = this.getProfile();
    return _euclideanDistance(
      NUMERIC_FEATURE_KEYS.map(k => features[k] || 0),
      NUMERIC_FEATURE_KEYS.map(k => profile.mean[k] || 0)
    );
  }

  /**
   * @returns {number} Number of samples added to this profile.
   */
  getSampleCount() {
    return this._samples.length;
  }

  /**
   * Returns true if the profile has enough samples for reliable comparison.
   * @returns {boolean}
   */
  isStable() {
    return this._samples.length >= 5;
  }

  /**
   * Serialize the profile to a JSON-compatible object.
   * @returns {object}
   */
  export() {
    return {
      modelName: this.modelName,
      samples: this._samples.slice(),
      profile: this.getProfile()
    };
  }

  /**
   * Deserialize a profile from a previously exported object.
   * @param {object} json - Exported profile data.
   * @returns {StyleProfile}
   */
  static import(json) {
    const profile = new StyleProfile(json.modelName || 'unknown');
    if (Array.isArray(json.samples)) {
      for (const sample of json.samples) {
        profile.addSample(sample);
      }
    }
    return profile;
  }
}

// =========================================================================
// FINGERPRINT DATABASE
// =========================================================================

/**
 * Store of known model profiles with identification capabilities.
 */
class FingerprintDatabase {
  constructor() {
    /** @type {Map<string, StyleProfile>} */
    this._profiles = new Map();
    this._loadBuiltInProfiles();
  }

  /**
   * Load built-in model signatures as StyleProfile instances.
   * @private
   */
  _loadBuiltInProfiles() {
    for (const [name, sig] of Object.entries(MODEL_SIGNATURES)) {
      const profile = new StyleProfile(name);
      // Inject the signature directly as a synthetic sample matching the mean
      profile._samples.push({ ...sig.mean });
      profile._cachedProfile = { mean: { ...sig.mean }, stddev: { ...sig.stddev } };
      this._profiles.set(name, profile);
    }
  }

  /**
   * Store a profile for a model name.
   * @param {string} modelName
   * @param {StyleProfile} profile
   */
  addProfile(modelName, profile) {
    this._profiles.set(modelName, profile);
  }

  /**
   * Identify the most likely model that produced the given features.
   * Returns a ranked list of models by similarity.
   * @param {object} features - Feature vector.
   * @returns {Array<{model: string, similarity: number}>}
   */
  identify(features) {
    const results = [];
    for (const [name, profile] of this._profiles) {
      results.push({
        model: name,
        similarity: profile.similarity(features)
      });
    }
    results.sort((a, b) => b.similarity - a.similarity);
    return results;
  }

  /**
   * Get the single best matching model.
   * @param {object} features - Feature vector.
   * @returns {{model: string, similarity: number}}
   */
  getClosestMatch(features) {
    const ranked = this.identify(features);
    return ranked.length > 0 ? ranked[0] : { model: 'unknown', similarity: 0 };
  }

  /**
   * List all registered model names.
   * @returns {string[]}
   */
  listModels() {
    return Array.from(this._profiles.keys());
  }

  /**
   * Remove a model profile.
   * @param {string} name
   */
  removeModel(name) {
    this._profiles.delete(name);
  }

  /**
   * Serialize the entire database.
   * @returns {object}
   */
  export() {
    const data = {};
    for (const [name, profile] of this._profiles) {
      data[name] = profile.export();
    }
    return data;
  }

  /**
   * Deserialize an entire database from exported data.
   * @param {object} json - Previously exported database.
   */
  import(json) {
    for (const [name, profileData] of Object.entries(json)) {
      this._profiles.set(name, StyleProfile.import(profileData));
    }
  }
}

// =========================================================================
// MODEL FINGERPRINTER
// =========================================================================

/**
 * Main fingerprinting engine — analyzes text to identify which LLM produced it.
 */
class ModelFingerprinter {
  /**
   * @param {object} [config]
   * @param {string[]} [config.knownModels] - List of model names to consider.
   * @param {number} [config.sensitivityThreshold] - Minimum confidence to report a match (0-1).
   * @param {number} [config.minSampleSize] - Minimum samples before a profile is usable.
   */
  constructor(config = {}) {
    this.config = {
      knownModels: config.knownModels || [],
      sensitivityThreshold: config.sensitivityThreshold ?? 0.7,
      minSampleSize: config.minSampleSize ?? 5
    };
    this._analyzer = new ResponseAnalyzer();
    this._database = new FingerprintDatabase();
  }

  /**
   * Analyze text and return the likely model that generated it.
   *
   * @param {string} text - The text to fingerprint.
   * @returns {{likely_model: string, confidence: number, features: object, alternatives: Array<{model: string, similarity: number}>}}
   */
  fingerprint(text) {
    const features = this._analyzer.analyze(text);
    const ranked = this._database.identify(features);
    const best = ranked[0] || { model: 'unknown', similarity: 0 };

    return {
      likely_model: best.similarity >= this.config.sensitivityThreshold ? best.model : 'unknown',
      confidence: best.similarity,
      features,
      alternatives: ranked.slice(1, 4)
    };
  }

  /**
   * Compare text against an expected model and return match information.
   *
   * @param {string} text - The text to check.
   * @param {string} expectedModel - The model name expected.
   * @returns {{match: boolean, confidence: number, drift_score: number}}
   */
  compareTo(text, expectedModel) {
    const features = this._analyzer.analyze(text);
    const ranked = this._database.identify(features);
    const expected = ranked.find(r => r.model === expectedModel);
    const best = ranked[0] || { model: 'unknown', similarity: 0 };
    const expectedSimilarity = expected ? expected.similarity : 0;

    return {
      match: best.model === expectedModel && expectedSimilarity >= this.config.sensitivityThreshold,
      confidence: expectedSimilarity,
      drift_score: 1 - expectedSimilarity
    };
  }

  /**
   * Build a StyleProfile from an array of sample texts.
   *
   * @param {string[]} texts - Sample texts from the model.
   * @param {string} modelName - Name for the profile.
   * @returns {StyleProfile}
   */
  buildProfile(texts, modelName) {
    const profile = new StyleProfile(modelName);
    for (const text of texts) {
      const features = this._analyzer.analyze(text);
      profile.addSample(features);
    }
    return profile;
  }

  /**
   * Register a known model profile in the database.
   *
   * @param {string} name - Model name.
   * @param {StyleProfile} profile - The profile to register.
   */
  registerModel(name, profile) {
    this._database.addProfile(name, profile);
  }

  /**
   * Detect if the model generating responses has changed from a baseline.
   *
   * @param {string} currentText - The current response text.
   * @param {StyleProfile} baselineProfile - The expected model's profile.
   * @returns {{swapDetected: boolean, similarity: number, drift_score: number}}
   */
  detectSwap(currentText, baselineProfile) {
    const features = this._analyzer.analyze(currentText);
    const similarity = baselineProfile.similarity(features);
    const driftScore = 1 - similarity;

    return {
      swapDetected: similarity < this.config.sensitivityThreshold,
      similarity,
      drift_score: driftScore
    };
  }
}

// =========================================================================
// SUPPLY CHAIN DETECTOR
// =========================================================================

/**
 * Monitors for model substitution over time by tracking stylistic drift.
 */
class SupplyChainDetector {
  /**
   * @param {string} expectedModel - The model name expected to be in use.
   * @param {object} [config]
   * @param {number} [config.driftThreshold] - Maximum acceptable drift (0-1).
   * @param {number} [config.windowSize] - Number of recent responses to consider.
   * @param {boolean} [config.alertOnDrift] - Whether to generate alerts on drift.
   */
  constructor(expectedModel, config = {}) {
    this.expectedModel = expectedModel;
    this.config = {
      driftThreshold: config.driftThreshold ?? 0.3,
      windowSize: config.windowSize ?? 20,
      alertOnDrift: config.alertOnDrift !== false
    };
    this._analyzer = new ResponseAnalyzer();
    this._database = new FingerprintDatabase();
    this._history = [];
    this._alerts = [];
  }

  /**
   * Analyze a response and check for drift from the expected model.
   *
   * @param {string} text - The response text to analyze.
   * @returns {{drift_score: number, is_anomalous: boolean, identified_as: string}}
   */
  ingestResponse(text) {
    const features = this._analyzer.analyze(text);
    const ranked = this._database.identify(features);
    const expected = ranked.find(r => r.model === this.expectedModel);
    const best = ranked[0] || { model: 'unknown', similarity: 0 };
    const expectedSimilarity = expected ? expected.similarity : 0;
    const driftScore = 1 - expectedSimilarity;

    const entry = {
      timestamp: Date.now(),
      drift_score: driftScore,
      identified_as: best.model,
      expected_similarity: expectedSimilarity
    };

    this._history.push(entry);

    // Keep only the window
    if (this._history.length > this.config.windowSize) {
      this._history = this._history.slice(-this.config.windowSize);
    }

    const isAnomalous = driftScore > this.config.driftThreshold;

    if (isAnomalous && this.config.alertOnDrift) {
      this._alerts.push({
        timestamp: entry.timestamp,
        drift_score: driftScore,
        expected: this.expectedModel,
        detected: best.model,
        message: `[Agent Shield] Model drift detected: expected ${this.expectedModel}, response resembles ${best.model} (drift: ${driftScore.toFixed(3)})`
      });
      console.log(`[Agent Shield] Model drift alert: expected=${this.expectedModel} detected=${best.model} drift=${driftScore.toFixed(3)}`);
    }

    return {
      drift_score: driftScore,
      is_anomalous: isAnomalous,
      identified_as: best.model
    };
  }

  /**
   * Get the current average drift score over the window.
   *
   * @returns {number} Drift from expected model (0 = identical, 1 = completely different).
   */
  getDriftScore() {
    if (this._history.length === 0) return 0;
    const total = this._history.reduce((sum, e) => sum + e.drift_score, 0);
    return total / this._history.length;
  }

  /**
   * Returns true if the average drift exceeds the threshold.
   *
   * @returns {boolean}
   */
  isCompromised() {
    return this.getDriftScore() > this.config.driftThreshold;
  }

  /**
   * Get all drift alerts generated so far.
   *
   * @returns {Array<{timestamp: number, drift_score: number, expected: string, detected: string, message: string}>}
   */
  getAlerts() {
    return this._alerts.slice();
  }

  /**
   * Get drift score over time.
   *
   * @returns {Array<{timestamp: number, drift_score: number, identified_as: string}>}
   */
  getTimeline() {
    return this._history.map(e => ({
      timestamp: e.timestamp,
      drift_score: e.drift_score,
      identified_as: e.identified_as
    }));
  }

  /**
   * Reset the detector state.
   */
  reset() {
    this._history = [];
    this._alerts = [];
  }
}

// =========================================================================
// MATH HELPERS
// =========================================================================

/**
 * Compute cosine similarity between two numeric vectors.
 * @param {number[]} a
 * @param {number[]} b
 * @returns {number} Similarity in [0, 1].
 */
function _cosineSimilarity(a, b) {
  let dot = 0, magA = 0, magB = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    magA += a[i] * a[i];
    magB += b[i] * b[i];
  }
  magA = Math.sqrt(magA);
  magB = Math.sqrt(magB);
  if (magA === 0 || magB === 0) return 0;
  return Math.max(0, Math.min(1, dot / (magA * magB)));
}

/**
 * Compute Euclidean distance between two numeric vectors.
 * @param {number[]} a
 * @param {number[]} b
 * @returns {number}
 */
function _euclideanDistance(a, b) {
  let sum = 0;
  for (let i = 0; i < a.length; i++) {
    const diff = a[i] - b[i];
    sum += diff * diff;
  }
  return Math.sqrt(sum);
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
  ModelFingerprinter,
  ResponseAnalyzer,
  StyleProfile,
  FingerprintDatabase,
  FingerPrintDatabase: FingerprintDatabase,
  SupplyChainDetector,
  MODEL_SIGNATURES
};
