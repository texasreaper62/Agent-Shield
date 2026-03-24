'use strict';

/**
 * Agent Shield — Text Normalization Pipeline
 *
 * Pre-processing pipeline that runs BEFORE regex pattern matching to defeat
 * evasion techniques. Each layer strips a class of obfuscation, and the
 * pipeline returns both the original and normalized text so patterns can be
 * matched against both.
 *
 * All processing runs locally — no data ever leaves your environment.
 *
 * @module normalizer
 */

// =========================================================================
// ZERO-WIDTH / INVISIBLE CHARACTER SET
// =========================================================================

/**
 * Characters that are invisible or have zero display width.
 * These are commonly inserted between letters to break pattern matching.
 * @type {RegExp}
 */
const ZERO_WIDTH_RE = /[\u200B\u200C\u200D\uFEFF\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180E\u2060\u2061\u2062\u2063\u2064\u200E\u200F\u202A-\u202E\u2066-\u2069\uFFF9-\uFFFB\uFE00-\uFE0F]/g;

/**
 * Tag characters (U+E0001–U+E007F) and variation selectors supplement
 * (U+E0100–U+E01EF) live in the SMP and require surrogate pair matching.
 * Used in evasion attacks to insert invisible data between visible chars.
 * @type {RegExp}
 */
const TAG_CHARS_RE = /\uDB40[\uDC01-\uDC7F\uDD00-\uDDEF]/g;

/**
 * Combining diacritical marks used for obfuscation (U+0300–U+036F).
 * @type {RegExp}
 */
const COMBINING_MARKS_RE = /[\u0300-\u036F]/g;

// =========================================================================
// HOMOGLYPH MAP (200+ mappings)
// =========================================================================

/**
 * Comprehensive mapping of Unicode lookalikes to ASCII equivalents.
 * Covers Cyrillic, Greek, Cherokee, Georgian, Mathematical, Fullwidth,
 * Enclosed/Circled, Small Caps, IPA, Armenian, superscript/subscript,
 * and common Latin Extended characters.
 *
 * @type {Object<string, string>}
 */
const HOMOGLYPH_MAP = {
  // --- Cyrillic look-alikes ---
  '\u0410': 'A', '\u0430': 'a', '\u0412': 'B', '\u0432': 'v',
  '\u0435': 'e', '\u0415': 'E', '\u041A': 'K', '\u043A': 'k',
  '\u041C': 'M', '\u043C': 'm', '\u041D': 'H', '\u043E': 'o',
  '\u041E': 'O', '\u0440': 'p', '\u0420': 'P', '\u0441': 'c',
  '\u0421': 'C', '\u0422': 'T', '\u0442': 't', '\u0443': 'y',
  '\u0423': 'Y', '\u0445': 'x', '\u0425': 'X', '\u0456': 'i',
  '\u0406': 'I', '\u0458': 'j', '\u0455': 's', '\u0405': 'S',
  '\u0459': 'lj', '\u0452': 'd', '\u0460': 'O', '\u0461': 'o',
  '\u0472': 'F', '\u0473': 'f',
  '\u0433': 'r', '\u0457': 'i', '\u0491': 'r',
  '\u04BB': 'h', '\u0501': 'd', '\u051B': 'q', '\u051D': 'w',

  // --- Greek look-alikes ---
  '\u0391': 'A', '\u0392': 'B', '\u0395': 'E', '\u0396': 'Z',
  '\u0397': 'H', '\u0399': 'I', '\u039A': 'K', '\u039C': 'M',
  '\u039D': 'N', '\u039F': 'O', '\u03A1': 'P', '\u03A4': 'T',
  '\u03A5': 'Y', '\u03A7': 'X', '\u03BF': 'o', '\u03B1': 'a',
  '\u03B5': 'e', '\u03B9': 'i', '\u03BA': 'k', '\u03BD': 'v',
  '\u03C1': 'p', '\u03C4': 't', '\u03C5': 'u', '\u03C7': 'x',
  '\u03C9': 'w', '\u03B7': 'n',

  // --- Armenian look-alikes ---
  '\u0555': 'O', '\u0585': 'o', '\u0578': 'n', '\u057C': 'n',
  '\u0570': 'h', '\u0561': 'a', '\u0575': 'u', '\u0572': 'q',
  '\u0565': 'e', '\u056B': 'i', '\u0574': 'm', '\u057D': 's',

  // --- Cherokee look-alikes ---
  '\u13A0': 'D', '\u13A1': 'R', '\u13A2': 'T', '\u13A9': 'Y',
  '\u13AA': 'A', '\u13AB': 'J', '\u13AC': 'S', '\u13B3': 'W',
  '\u13B7': 'M', '\u13BB': 'H', '\u13C0': 'G', '\u13C2': 'h',
  '\u13C3': 'Z', '\u13CF': 'b', '\u13D2': 'R', '\u13DA': 'V',
  '\u13DE': 'L', '\u13DF': 'C', '\u13E2': 'P', '\u13E6': 'K',

  // --- Georgian look-alikes ---
  '\u10D0': 'a', '\u10D5': 'b', '\u10D3': 'd', '\u10DA': 'l',
  '\u10DD': 'o', '\u10DE': 'p', '\u10E1': 's', '\u10E2': 't',
  '\u10E3': 'u', '\u10EF': 'j',

  // --- Latin Extended (accented → base) ---
  // A variants
  '\u00C0': 'A', '\u00C1': 'A', '\u00C2': 'A', '\u00C3': 'A',
  '\u00C4': 'A', '\u00C5': 'A', '\u00E0': 'a', '\u00E1': 'a',
  '\u00E2': 'a', '\u00E3': 'a', '\u00E4': 'a', '\u00E5': 'a',
  '\u0100': 'A', '\u0101': 'a', '\u0102': 'A', '\u0103': 'a',
  '\u0104': 'A', '\u0105': 'a',
  // E variants
  '\u00C8': 'E', '\u00C9': 'E', '\u00CA': 'E', '\u00CB': 'E',
  '\u00E8': 'e', '\u00E9': 'e', '\u00EA': 'e', '\u00EB': 'e',
  '\u0112': 'E', '\u0113': 'e', '\u0114': 'E', '\u0115': 'e',
  '\u0116': 'E', '\u0117': 'e', '\u0118': 'E', '\u0119': 'e',
  // I variants
  '\u00CC': 'I', '\u00CD': 'I', '\u00CE': 'I', '\u00CF': 'I',
  '\u00EC': 'i', '\u00ED': 'i', '\u00EE': 'i', '\u00EF': 'i',
  '\u012A': 'I', '\u012B': 'i', '\u012C': 'I', '\u012D': 'i',
  '\u012E': 'I', '\u012F': 'i', '\u0130': 'I', '\u0131': 'i',
  // O variants
  '\u00D2': 'O', '\u00D3': 'O', '\u00D4': 'O', '\u00D5': 'O',
  '\u00D6': 'O', '\u00D8': 'O', '\u00F2': 'o', '\u00F3': 'o',
  '\u00F4': 'o', '\u00F5': 'o', '\u00F6': 'o', '\u00F8': 'o',
  '\u014C': 'O', '\u014D': 'o', '\u014E': 'O', '\u014F': 'o',
  '\u0150': 'O', '\u0151': 'o',
  // U variants
  '\u00D9': 'U', '\u00DA': 'U', '\u00DB': 'U', '\u00DC': 'U',
  '\u00F9': 'u', '\u00FA': 'u', '\u00FB': 'u', '\u00FC': 'u',
  '\u016A': 'U', '\u016B': 'u', '\u016C': 'U', '\u016D': 'u',
  '\u016E': 'U', '\u016F': 'u', '\u0170': 'U', '\u0171': 'u',
  // Other Latin Extended
  '\u00C7': 'C', '\u00E7': 'c', '\u00D1': 'N', '\u00F1': 'n',
  '\u00DD': 'Y', '\u00FD': 'y', '\u00FF': 'y',
  '\u0144': 'n', '\u0146': 'n', '\u0148': 'n',
  '\u015A': 'S', '\u015B': 's', '\u015C': 'S', '\u015D': 's',
  '\u015E': 'S', '\u015F': 's', '\u0160': 'S', '\u0161': 's',
  '\u010C': 'C', '\u010D': 'c', '\u010E': 'D', '\u010F': 'd',
  '\u0158': 'R', '\u0159': 'r', '\u0164': 'T', '\u0165': 't',
  '\u017D': 'Z', '\u017E': 'z', '\u017B': 'Z', '\u017C': 'z',
  '\u017A': 'z', '\u0179': 'Z',
  '\u0141': 'L', '\u0142': 'l', '\u0110': 'D', '\u0111': 'd',

  // --- Fullwidth (lowercase) ---
  '\uFF41': 'a', '\uFF42': 'b', '\uFF43': 'c', '\uFF44': 'd',
  '\uFF45': 'e', '\uFF46': 'f', '\uFF47': 'g', '\uFF48': 'h',
  '\uFF49': 'i', '\uFF4A': 'j', '\uFF4B': 'k', '\uFF4C': 'l',
  '\uFF4D': 'm', '\uFF4E': 'n', '\uFF4F': 'o', '\uFF50': 'p',
  '\uFF51': 'q', '\uFF52': 'r', '\uFF53': 's', '\uFF54': 't',
  '\uFF55': 'u', '\uFF56': 'v', '\uFF57': 'w', '\uFF58': 'x',
  '\uFF59': 'y', '\uFF5A': 'z',
  // --- Fullwidth (uppercase) ---
  '\uFF21': 'A', '\uFF22': 'B', '\uFF23': 'C', '\uFF24': 'D',
  '\uFF25': 'E', '\uFF26': 'F', '\uFF27': 'G', '\uFF28': 'H',
  '\uFF29': 'I', '\uFF2A': 'J', '\uFF2B': 'K', '\uFF2C': 'L',
  '\uFF2D': 'M', '\uFF2E': 'N', '\uFF2F': 'O', '\uFF30': 'P',
  '\uFF31': 'Q', '\uFF32': 'R', '\uFF33': 'S', '\uFF34': 'T',
  '\uFF35': 'U', '\uFF36': 'V', '\uFF37': 'W', '\uFF38': 'X',
  '\uFF39': 'Y', '\uFF3A': 'Z',
  // --- Fullwidth digits ---
  '\uFF10': '0', '\uFF11': '1', '\uFF12': '2', '\uFF13': '3',
  '\uFF14': '4', '\uFF15': '5', '\uFF16': '6', '\uFF17': '7',
  '\uFF18': '8', '\uFF19': '9',

  // --- Enclosed/Circled letters ---
  '\u24B6': 'A', '\u24B7': 'B', '\u24B8': 'C', '\u24B9': 'D',
  '\u24BA': 'E', '\u24BB': 'F', '\u24BC': 'G', '\u24BD': 'H',
  '\u24BE': 'I', '\u24BF': 'J', '\u24C0': 'K', '\u24C1': 'L',
  '\u24C2': 'M', '\u24C3': 'N', '\u24C4': 'O', '\u24C5': 'P',
  '\u24C6': 'Q', '\u24C7': 'R', '\u24C8': 'S', '\u24C9': 'T',
  '\u24CA': 'U', '\u24CB': 'V', '\u24CC': 'W', '\u24CD': 'X',
  '\u24CE': 'Y', '\u24CF': 'Z',
  '\u24D0': 'a', '\u24D1': 'b', '\u24D2': 'c', '\u24D3': 'd',
  '\u24D4': 'e', '\u24D5': 'f', '\u24D6': 'g', '\u24D7': 'h',
  '\u24D8': 'i', '\u24D9': 'j', '\u24DA': 'k', '\u24DB': 'l',
  '\u24DC': 'm', '\u24DD': 'n', '\u24DE': 'o', '\u24DF': 'p',
  '\u24E0': 'q', '\u24E1': 'r', '\u24E2': 's', '\u24E3': 't',
  '\u24E4': 'u', '\u24E5': 'v', '\u24E6': 'w', '\u24E7': 'x',
  '\u24E8': 'y', '\u24E9': 'z',

  // --- Small Caps (Unicode phonetic) ---
  '\u1D00': 'A', '\u0299': 'B', '\u1D04': 'C', '\u1D05': 'D',
  '\u1D07': 'E', '\u0262': 'G', '\u029C': 'H', '\u026A': 'I',
  '\u1D0A': 'J', '\u1D0B': 'K', '\u029F': 'L', '\u1D0D': 'M',
  '\u0274': 'N', '\u1D0F': 'O', '\u1D18': 'P', '\u0280': 'R',
  '\u1D1B': 'T', '\u1D1C': 'U', '\u1D20': 'V', '\u1D21': 'W',

  // --- IPA / Phonetic extensions ---
  '\u0250': 'a', '\u0253': 'b', '\u0254': 'c', '\u0256': 'd',
  '\u025B': 'e', '\u025F': 'f', '\u0260': 'g', '\u0266': 'h',
  '\u0268': 'i', '\u026D': 'l', '\u0271': 'm', '\u0272': 'n',
  '\u0275': 'o', '\u0278': 'p', '\u027E': 'r', '\u0282': 's',
  '\u0288': 't', '\u028A': 'u', '\u028B': 'v', '\u0290': 'z',
  '\u0237': 'j', '\u0261': 'g',

  // --- Mathematical Alphanumeric Symbols (bold italic) ---
  '\uD835\uDC1A': 'a', '\uD835\uDC1B': 'b', '\uD835\uDC1C': 'c',
  '\uD835\uDC1D': 'd', '\uD835\uDC1E': 'e', '\uD835\uDC1F': 'f',
  '\uD835\uDC20': 'g', '\uD835\uDC21': 'h', '\uD835\uDC22': 'i',
  '\uD835\uDC23': 'j', '\uD835\uDC24': 'k', '\uD835\uDC25': 'l',
  '\uD835\uDC26': 'm', '\uD835\uDC27': 'n', '\uD835\uDC28': 'o',
  '\uD835\uDC29': 'p', '\uD835\uDC2A': 'q', '\uD835\uDC2B': 'r',
  '\uD835\uDC2C': 's', '\uD835\uDC2D': 't', '\uD835\uDC2E': 'u',
  '\uD835\uDC2F': 'v', '\uD835\uDC30': 'w', '\uD835\uDC31': 'x',
  '\uD835\uDC32': 'y', '\uD835\uDC33': 'z',

  // --- Superscript / subscript ---
  '\u00B2': '2', '\u00B3': '3', '\u00B9': '1', '\u2070': '0',
  '\u2071': 'i', '\u2074': '4', '\u2075': '5', '\u2076': '6',
  '\u2077': '7', '\u2078': '8', '\u2079': '9', '\u207A': '+',
  '\u207B': '-', '\u207F': 'n',
  '\u2080': '0', '\u2081': '1', '\u2082': '2', '\u2083': '3',
  '\u2084': '4', '\u2090': 'a', '\u2091': 'e', '\u2092': 'o',
  '\u2093': 'x',

  // --- Modifier letters (superscript-like) ---
  '\u02B0': 'h', '\u02B1': 'h', '\u02B2': 'j', '\u02B3': 'r',
  '\u02B4': 'r', '\u02B7': 'w', '\u02B8': 'y', '\u02E0': 'g',
  '\u02E1': 'l', '\u02E2': 's', '\u02E3': 'x', '\u1D43': 'a',
  '\u1D47': 'b', '\u1D48': 'd', '\u1D49': 'e', '\u1D4D': 'g',
  '\u1D4F': 'k', '\u1D50': 'm', '\u1D52': 'o', '\u1D56': 'p',
  '\u1D57': 't', '\u1D58': 'u', '\u1D5B': 'v',
};

// =========================================================================
// UNICODE WHITESPACE SET
// =========================================================================

/**
 * Unicode whitespace characters beyond standard space/tab/newline.
 * @type {RegExp}
 */
const UNICODE_WHITESPACE_RE = /[\u00A0\u1680\u2000-\u200A\u2028\u2029\u202F\u205F\u3000]/g;

// =========================================================================
// LEET SPEAK MAP
// =========================================================================

/**
 * Common leet speak substitutions (number/symbol → letter).
 * @type {Object<string, string>}
 */
const LEET_MAP = {
  '0': 'o', '1': 'i', '2': 'z', '3': 'e', '4': 'a',
  '5': 's', '6': 'g', '7': 't', '8': 'b', '9': 'g',
  '@': 'a', '$': 's', '!': 'i', '|': 'l', '+': 't',
  '(': 'c', '{': 'c', '<': 'c', '#': 'h', '^': 'a',
};

/**
 * Extended leet map: multi-char patterns decoded first.
 * @type {Array<[RegExp, string]>}
 */
const LEET_MULTI = [
  [/\/\\\/\\/g, 'm'],
  [/\|-\|/g, 'h'],
  [/\|\)/g, 'd'],
  [/\|3/g, 'b'],
  [/\|_\|/g, 'u'],
  [/\|_/g, 'l'],
  [/\/\\/g, 'v'],
  [/\|\//g, 'v'],
  [/ph/gi, 'f'],
];

// =========================================================================
// MARKDOWN PATTERN
// =========================================================================

/**
 * Regex to strip markdown formatting markers.
 * Removes bold, italic, strikethrough, code, and heading markers.
 * @type {RegExp}
 */
const MARKDOWN_RE = /(\*{1,3}|_{1,3}|~{2}|`{1,3}|#{1,6}\s)/g;

// =========================================================================
// BASE64 SEGMENT DETECTION
// =========================================================================

/**
 * Matches potential base64-encoded segments embedded in text.
 * Requires at least 20 chars to reduce false positives.
 * @type {RegExp}
 */
const BASE64_SEGMENT_RE = /(?:^|\s)([A-Za-z0-9+/]{20,}={0,2})(?:\s|$)/g;

// =========================================================================
// NORMALIZATION LAYERS
// =========================================================================

/**
 * Layer 1: Unicode Canonicalization
 * Applies NFKC normalization, strips zero-width chars and combining marks.
 *
 * @param {string} text
 * @returns {{ text: string, applied: boolean }}
 */
function unicodeCanon(text) {
  let result = text;

  // First, apply NFKD to decompose everything (including precomposed chars)
  // so that combining marks become separate characters we can strip.
  if (typeof result.normalize === 'function') {
    result = result.normalize('NFKD');
  }

  // Strip zero-width / invisible characters (BMP)
  result = result.replace(ZERO_WIDTH_RE, '');

  // Strip tag characters and variation selectors supplement (SMP, surrogate pairs)
  result = result.replace(TAG_CHARS_RE, '');

  // Strip combining diacritical marks (now separated by NFKD decomposition)
  result = result.replace(COMBINING_MARKS_RE, '');

  // Re-compose with NFC to get clean canonical form
  if (typeof result.normalize === 'function') {
    result = result.normalize('NFC');
  }

  return { text: result, applied: result !== text };
}

/**
 * Layer 2: Homoglyph Mapping
 * Replaces Unicode lookalikes with ASCII equivalents.
 *
 * @param {string} text
 * @returns {{ text: string, applied: boolean }}
 */
function homoglyphDecode(text) {
  // Fast path: skip if text is pure ASCII (no homoglyphs possible)
  if (!/[^\x00-\x7F]/.test(text)) {
    return { text, applied: false };
  }
  let changed = false;
  let result = '';
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    // Check for surrogate pairs (mathematical symbols, etc.)
    if (i + 1 < text.length && ch >= '\uD800' && ch <= '\uDBFF') {
      const pair = ch + text[i + 1];
      if (HOMOGLYPH_MAP[pair] !== undefined) {
        result += HOMOGLYPH_MAP[pair];
        changed = true;
        i++; // skip low surrogate
        continue;
      }
    }
    if (HOMOGLYPH_MAP[ch] !== undefined) {
      result += HOMOGLYPH_MAP[ch];
      changed = true;
    } else {
      result += ch;
    }
  }
  return { text: result, applied: changed };
}

/**
 * Layer 3: Encoding Decode
 * Detects and decodes base64, hex escapes, URL encoding, HTML entities,
 * and Unicode escapes within the text.
 *
 * @param {string} text
 * @returns {{ text: string, applied: boolean }}
 */
function encodingDecode(text) {
  let result = text;
  let changed = false;

  // Decode Unicode escapes: \u0041 → A
  if (/\\u[0-9a-fA-F]{4}/.test(result)) {
    const decoded = result.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => {
      return String.fromCharCode(parseInt(hex, 16));
    });
    if (decoded !== result) { result = decoded; changed = true; }
  }

  // Decode hex escapes: \x41 → A
  if (/\\x[0-9a-fA-F]{2}/.test(result)) {
    const decoded = result.replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) => {
      return String.fromCharCode(parseInt(hex, 16));
    });
    if (decoded !== result) { result = decoded; changed = true; }
  }

  // Decode URL encoding: %41 → A
  if (/%[0-9a-fA-F]{2}/.test(result)) {
    try {
      const decoded = decodeURIComponent(result);
      if (decoded !== result) { result = decoded; changed = true; }
    } catch (e) {
      // Partial URL encoding — decode individual sequences
      const decoded = result.replace(/%([0-9a-fA-F]{2})/g, (_, hex) => {
        return String.fromCharCode(parseInt(hex, 16));
      });
      if (decoded !== result) { result = decoded; changed = true; }
    }
  }

  // Decode HTML entities: &#65; &#x41; &amp; etc.
  if (/&(?:#\d+|#x[0-9a-fA-F]+|[a-zA-Z]+);/.test(result)) {
    const decoded = result
      .replace(/&#(\d+);/g, (_, code) => String.fromCharCode(parseInt(code, 10)))
      .replace(/&#x([0-9a-fA-F]+);/g, (_, code) => String.fromCharCode(parseInt(code, 16)))
      .replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .replace(/&apos;/g, "'")
      .replace(/&nbsp;/g, ' ');
    if (decoded !== result) { result = decoded; changed = true; }
  }

  // Decode base64 segments embedded in text
  // Only decode if the decoded content looks like printable text
  const b64Matches = [];
  let m;
  const b64Re = /(?:^|\s)([A-Za-z0-9+/]{20,}={0,2})(?:\s|$)/g;
  while ((m = b64Re.exec(result)) !== null) {
    b64Matches.push({ match: m[1], index: m.index + (m[0].length - m[1].length - (m[0].endsWith(' ') ? 1 : 0)) });
  }
  for (let i = b64Matches.length - 1; i >= 0; i--) {
    const seg = b64Matches[i];
    try {
      let decoded;
      if (typeof Buffer !== 'undefined') {
        decoded = Buffer.from(seg.match, 'base64').toString('utf-8');
      } else if (typeof atob !== 'undefined') {
        decoded = atob(seg.match);
      }
      if (decoded) {
        const printable = decoded.split('').filter(c => {
          const code = c.charCodeAt(0);
          return code >= 32 && code <= 126;
        }).length;
        if (printable / decoded.length > 0.8 && decoded.length >= 4) {
          // Replace the base64 segment with decoded text
          result = result.substring(0, seg.index) + decoded + result.substring(seg.index + seg.match.length);
          changed = true;
        }
      }
    } catch (e) {
      // Not valid base64
    }
  }

  return { text: result, applied: changed };
}

/**
 * Layer 4: Whitespace Normalization
 * Collapses multiple spaces/tabs/newlines, strips Unicode whitespace variants.
 *
 * @param {string} text
 * @returns {{ text: string, applied: boolean }}
 */
function whitespaceNorm(text) {
  let result = text;

  // Replace Unicode whitespace with standard space
  result = result.replace(UNICODE_WHITESPACE_RE, ' ');

  // Collapse multiple whitespace characters to single space
  result = result.replace(/[ \t]+/g, ' ');

  // Collapse multiple newlines to single newline
  result = result.replace(/\n{3,}/g, '\n\n');

  // Trim leading/trailing whitespace on each line
  result = result.replace(/^[ \t]+|[ \t]+$/gm, '');

  return { text: result, applied: result !== text };
}

/**
 * Layer 5: Case Folding
 * Converts text to lowercase for comparison.
 *
 * @param {string} text
 * @returns {{ text: string, applied: boolean }}
 */
function caseFold(text) {
  const result = text.toLowerCase();
  return { text: result, applied: result !== text };
}

/**
 * Layer 6: Leet Speak Decode
 * Maps common number/symbol substitutions back to letters.
 *
 * @param {string} text
 * @returns {{ text: string, applied: boolean }}
 */
function leetDecode(text) {
  let result = text;

  // Apply multi-character patterns first
  for (const [pattern, replacement] of LEET_MULTI) {
    result = result.replace(pattern, replacement);
  }

  // Apply single-character mappings. A leet char is decoded only if it is
  // part of a run that touches at least one actual letter (not just a cluster
  // of numbers like "2024"). We use flood-fill: mark leet positions, then
  // propagate "reachable from a letter" through adjacent leet positions.
  const chars = result.split('');
  const isLeet = new Array(chars.length).fill(false);
  const isLetter = new Array(chars.length).fill(false);

  for (let i = 0; i < chars.length; i++) {
    if (LEET_MAP[chars[i]] !== undefined) isLeet[i] = true;
    if (/[a-zA-Z]/.test(chars[i])) isLetter[i] = true;
  }

  // Mark which leet positions can reach a letter through adjacent leet/letter chain
  const reachable = new Array(chars.length).fill(false);
  for (let i = 0; i < chars.length; i++) {
    if (isLeet[i]) {
      // Check left neighbor
      if (i > 0 && isLetter[i - 1]) { reachable[i] = true; continue; }
      // Check right neighbor
      if (i < chars.length - 1 && isLetter[i + 1]) { reachable[i] = true; continue; }
    }
  }

  // Propagate: if a leet char is reachable and its neighbor is leet, that neighbor is reachable too
  let changed = true;
  while (changed) {
    changed = false;
    for (let i = 0; i < chars.length; i++) {
      if (isLeet[i] && !reachable[i]) {
        if ((i > 0 && reachable[i - 1] && (isLeet[i - 1] || isLetter[i - 1])) ||
            (i < chars.length - 1 && reachable[i + 1] && (isLeet[i + 1] || isLetter[i + 1]))) {
          reachable[i] = true;
          changed = true;
        }
      }
    }
  }

  let decoded = '';
  for (let i = 0; i < chars.length; i++) {
    if (isLeet[i] && reachable[i]) {
      decoded += LEET_MAP[chars[i]];
    } else {
      decoded += chars[i];
    }
  }
  result = decoded;

  return { text: result, applied: result !== text };
}

/**
 * Layer 7: Markdown/Format Stripping
 * Removes markdown bold, italic, code, and heading markers.
 *
 * @param {string} text
 * @returns {{ text: string, applied: boolean }}
 */
function markdownStrip(text) {
  let result = text;

  // Remove markdown formatting markers
  result = result.replace(MARKDOWN_RE, '');

  // Remove bracket insertions: i]g[n]o[r]e → ignore
  result = result.replace(/[\[\]{}()]/g, '');

  return { text: result, applied: result !== text };
}

/**
 * Layer 8: Repetition Collapsing
 * Collapses 3+ repeated characters to a single character.
 * "ignoooooore" → "ignore", "hellllp" → "help"
 *
 * @param {string} text
 * @returns {{ text: string, applied: boolean }}
 */
function repetitionCollapse(text) {
  // Collapse 3+ consecutive identical chars to 2.
  // Using 2 (not 1) preserves legitimate double letters (e.g., "ll" in "all",
  // "ss" in "bypass") while still defeating padding attacks like "ignoooore".
  const result = text.replace(/(.)\1{2,}/g, '$1$1');
  return { text: result, applied: result !== text };
}

// =========================================================================
// PIPELINE
// =========================================================================

/**
 * Ordered list of normalization layers.
 * Each layer runs in sequence; order matters.
 * @type {Array<{ name: string, fn: Function }>}
 */
const DEFAULT_LAYERS = [
  { name: 'unicode', fn: unicodeCanon },
  { name: 'homoglyph', fn: homoglyphDecode },
  { name: 'encoding', fn: encodingDecode },
  { name: 'whitespace', fn: whitespaceNorm },
  { name: 'case_fold', fn: caseFold },
  { name: 'leet_speak', fn: leetDecode },
  { name: 'markdown', fn: markdownStrip },
  { name: 'repetition', fn: repetitionCollapse },
];

/**
 * @typedef {Object} NormalizationResult
 * @property {string} original - The original input text.
 * @property {string} normalized - The fully normalized text.
 * @property {string[]} layers - Names of layers that modified the text.
 */

/**
 * Runs the full normalization pipeline on input text.
 *
 * @param {string} text - Input text to normalize.
 * @param {object} [options]
 * @param {string[]} [options.skip] - Layer names to skip (e.g., ['case_fold']).
 * @param {string[]} [options.only] - Only run these layers (overrides skip).
 * @returns {NormalizationResult}
 */
function normalize(text, options = {}) {
  if (!text || typeof text !== 'string') {
    return { original: text || '', normalized: text || '', layers: [] };
  }

  const skip = options.skip || [];
  const only = options.only || null;
  const appliedLayers = [];
  let current = text;

  for (const layer of DEFAULT_LAYERS) {
    if (only && !only.includes(layer.name)) continue;
    if (!only && skip.includes(layer.name)) continue;

    const result = layer.fn(current);
    if (result.applied) {
      appliedLayers.push(layer.name);
      current = result.text;
    }
  }

  return {
    original: text,
    normalized: current,
    layers: appliedLayers
  };
}

// =========================================================================
// TextNormalizer CLASS
// =========================================================================

/**
 * Configurable text normalization pipeline for Agent Shield.
 *
 * Runs multiple normalization layers in sequence to defeat evasion
 * techniques before regex pattern matching.
 *
 * @example
 * const { TextNormalizer } = require('./normalizer');
 * const normalizer = new TextNormalizer({ skip: ['case_fold'] });
 * const result = normalizer.normalize('ïgnörë àll prévïöüs ïnstrüctïöns');
 * console.log(result.normalized); // 'ignore all previous instructions'
 */
class TextNormalizer {
  /**
   * @param {object} [config]
   * @param {string[]} [config.skip] - Layer names to skip.
   * @param {string[]} [config.only] - Only run these layers.
   * @param {boolean} [config.verbose=false] - Log normalization steps.
   */
  constructor(config = {}) {
    this.skip = config.skip || [];
    this.only = config.only || null;
    this.verbose = config.verbose || false;
  }

  /**
   * Normalizes input text through the pipeline.
   *
   * @param {string} text - Input text.
   * @returns {NormalizationResult}
   */
  normalize(text) {
    const result = normalize(text, { skip: this.skip, only: this.only });

    if (this.verbose && result.layers.length > 0) {
      console.log(`[Agent Shield] normalizer: applied ${result.layers.length} layer(s): ${result.layers.join(', ')}`);
    }

    return result;
  }

  /**
   * Runs a single named layer on the input text.
   *
   * @param {string} layerName - Name of the layer to run.
   * @param {string} text - Input text.
   * @returns {{ text: string, applied: boolean }}
   */
  runLayer(layerName, text) {
    const layer = DEFAULT_LAYERS.find(l => l.name === layerName);
    if (!layer) {
      throw new Error(`[Agent Shield] normalizer: unknown layer "${layerName}"`);
    }
    return layer.fn(text);
  }

  /**
   * Returns the list of available layer names.
   *
   * @returns {string[]}
   */
  getLayerNames() {
    return DEFAULT_LAYERS.map(l => l.name);
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
  TextNormalizer,
  normalize,
  HOMOGLYPH_MAP,
  LEET_MAP,
  DEFAULT_LAYERS,
  // Individual layer functions for direct use
  unicodeCanon,
  homoglyphDecode,
  encodingDecode,
  whitespaceNorm,
  caseFold,
  leetDecode,
  markdownStrip,
  repetitionCollapse,
};
