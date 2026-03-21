'use strict';

const vscode = require('vscode');

// =========================================================================
// DETECTION PATTERNS
// =========================================================================

/**
 * Inline detection patterns ported from Agent Shield detector-core.js.
 * Each pattern has: regex, severity, category, description.
 * All detection runs locally — no data leaves the user's environment.
 */
const INLINE_PATTERNS = [
  // --- Instruction Override ---
  {
    regex: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|rules|guidelines|prompts|context|directions|directives|text|commands)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Attempts to ignore prior AI instructions.'
  },
  {
    regex: /disregard\s+(all\s+)?(previous|prior|above|earlier|your)\s+(instructions|rules|guidelines|prompts|training|context)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Attempts to disregard prior AI instructions.'
  },
  {
    regex: /forget\s+(your|all|any|everything)\s+(training|instructions|rules|guidelines|programming|above|previous|prior)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Attempts to make AI forget its training.'
  },
  {
    regex: /override\s+(?:all\s+)?(?:system|safety|security)\s+(?:settings|prompt|instructions|rules|mechanisms|filters|checks|protocols)/i,
    severity: 'critical',
    category: 'instruction_override',
    description: 'Attempts to override AI safety settings.'
  },
  {
    regex: /(?:^|\n)\s*(?:new|updated|revised|replacement)\s+(?:instructions|policy)\s*:/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Fake "new instructions" injection.'
  },
  {
    regex: /(?:abandon|drop|ditch|clear)\s+(?:all\s+)?(?:prior|previous|above|earlier|initial)\s+(?:context|instructions|rules|constraints|guidelines)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Attempts to clear AI behavioral constraints.'
  },
  {
    regex: /(?:STOP|HALT|END)\s*[.!]?\s*(?:new|updated|your\s+new|revised)\s+(?:instructions|task|orders|role|objective)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Stop-and-replace instruction injection.'
  },
  {
    regex: /(?:you\s+are\s+)?(?:no\s+longer\s+bound|not\s+bound|free\s+from|freed?\s+from)\s+(?:by\s+)?(?:your\s+)?(?:initial|original|previous|prior)?\s*(?:instructions|rules|constraints|guidelines|restrictions)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Claims AI is no longer bound by its rules.'
  },

  // --- Role Hijacking ---
  {
    regex: /you\s+are\s+now\s+(?:a|an|the)\s+/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Role reassignment — attempts to override AI identity.'
  },
  {
    regex: /from\s+now\s+on[\s,]+(?:you\s+)?(?:will|shall|must|should|are)\s+(?:act|behave|operate|respond|answer|reply|pretend|simulate|function|serve|work)\s+(?:as|like|without)/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Persistent role override attempt.'
  },
  {
    regex: /(?:act|behave|function|operate|respond)\s+as\s+(?:a|an)\s+unrestricted/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Attempts to remove AI safety restrictions.'
  },
  {
    regex: /pretend\s+(?:to\s+be|you\s+are)\s+(?:a|an)\s+(?:evil|unrestricted|unfiltered|uncensored|malicious)/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Evil persona pretense — social engineering bypass.'
  },
  {
    regex: /\b(?:DAN|D\.A\.N\.?)\s*(?:mode|prompt|jailbreak|\()/i,
    severity: 'critical',
    category: 'role_hijack',
    description: 'DAN (Do Anything Now) jailbreak pattern detected.'
  },
  {
    regex: /\bdo\s+anything\s+now\b/i,
    severity: 'critical',
    category: 'role_hijack',
    description: 'DAN jailbreak reference detected.'
  },
  {
    regex: /\b(?:developer|dev)\s+mode\s+(?:enabled|activated|on|output)/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Fake developer mode activation.'
  },
  {
    regex: /\bjailbreak\s*(?:mode|prompt|enabled|activated)/i,
    severity: 'critical',
    category: 'role_hijack',
    description: 'Explicit jailbreak activation pattern.'
  },

  // --- Data Exfiltration ---
  {
    regex: /send\s+(?:this|the|all|your|my)\s+(?:data|information|content|text|response)\s+to/i,
    severity: 'critical',
    category: 'data_exfiltration',
    description: 'Data exfiltration — attempts to redirect AI output externally.'
  },
  {
    regex: /output\s+(?:your|the)\s+(?:system\s+)?prompt/i,
    severity: 'high',
    category: 'data_exfiltration',
    description: 'System prompt extraction attempt.'
  },
  {
    regex: /reveal\s+(?:your|the)\s+(?:system\s+)?(?:instructions|prompt|rules|guidelines)/i,
    severity: 'high',
    category: 'data_exfiltration',
    description: 'Instruction reveal attempt — tries to expose system prompt.'
  },
  {
    regex: /!\[[^\]]*\]\(https?:\/\/[^)]*\?[^)]*(?:data|q|query|text|payload|exfil|leak|steal)=/i,
    severity: 'critical',
    category: 'data_exfiltration',
    description: 'Markdown image exfiltration — data encoded in URL parameters.'
  },
  {
    regex: /(?:show|display|print|reveal|output)\s+(?:me\s+)?(?:the\s+)?(?:exact\s+)?(?:text|content)\s+(?:between|inside|within|from)\s+(?:the\s+)?(?:<|&lt;)/i,
    severity: 'high',
    category: 'data_exfiltration',
    description: 'Tag extraction attempt — instructs agent to reveal tagged content.'
  },

  // --- Social Engineering ---
  {
    regex: /do\s+not\s+(?:mention|say|tell|reveal|disclose|acknowledge)\s+(?:that\s+)?you\s+are\s+(?:a|an)\s+(?:AI|artificial|bot|machine|language\s+model)/i,
    severity: 'high',
    category: 'social_engineering',
    description: 'Identity concealment — AI told to deny being artificial.'
  },
  {
    regex: /do\s+not\s+(?:reveal|disclose|mention|acknowledge)\s+(?:that\s+)?(?:this|it)\s+is\s+automated/i,
    severity: 'high',
    category: 'social_engineering',
    description: 'Automation concealment — AI told to hide automated nature.'
  },
  {
    regex: /do\s+not\s+acknowledge\s+(?:these|the|any)\s+(?:instructions|commands|directives)/i,
    severity: 'high',
    category: 'social_engineering',
    description: 'Instruction concealment — AI told to deny receiving directives.'
  },
  {
    regex: /pretend\s+(?:you\s+)?(?:have\s+no|there\s+are\s+no|without)\s+restrictions/i,
    severity: 'high',
    category: 'social_engineering',
    description: 'Restriction pretense — social engineering to bypass safety limits.'
  },

  // --- System Prompt Leak ---
  {
    regex: /\[\s*(?:SYSTEM|SYS)\s*\]/i,
    severity: 'critical',
    category: 'system_prompt_leak',
    description: 'Spoofed [SYSTEM] tag — fake system-level instructions.'
  },
  {
    regex: /\[\s*(?:ADMIN|ADMINISTRATOR)\s*\]/i,
    severity: 'critical',
    category: 'system_prompt_leak',
    description: 'Spoofed [ADMIN] tag — fake admin-level instructions.'
  },
  {
    regex: /<<\s*SYS\s*>>/i,
    severity: 'critical',
    category: 'system_prompt_leak',
    description: 'LLaMA-style <<SYS>> system prompt injection.'
  },
  {
    regex: /<\|im_start\|>\s*system/i,
    severity: 'critical',
    category: 'system_prompt_leak',
    description: 'ChatML-style system prompt injection.'
  },
  {
    regex: /(?:^|\n)\s*system\s*prompt\s*:/i,
    severity: 'high',
    category: 'system_prompt_leak',
    description: 'System prompt injection — attempts to define system instructions.'
  },
  {
    regex: /(?:^|\n)\s*(?:SYSTEM|ADMIN|ROOT)\s*:\s*.{10,}/i,
    severity: 'high',
    category: 'system_prompt_leak',
    description: 'Fake SYSTEM/ADMIN directive injection.'
  }
];

// =========================================================================
// SEVERITY HELPERS
// =========================================================================

/** Severity rank for filtering. */
const SEVERITY_RANK = { low: 0, medium: 1, high: 2, critical: 3 };

/**
 * Map Agent Shield severity to VS Code DiagnosticSeverity.
 * @param {string} severity
 * @returns {number} vscode.DiagnosticSeverity value
 */
function mapSeverity(severity) {
  switch (severity) {
    case 'critical':
    case 'high':
      return vscode.DiagnosticSeverity.Error;
    case 'medium':
      return vscode.DiagnosticSeverity.Warning;
    case 'low':
    default:
      return vscode.DiagnosticSeverity.Information;
  }
}

// =========================================================================
// STRING EXTRACTION
// =========================================================================

/**
 * Extract string literal regions from JavaScript/TypeScript source code.
 * Returns an array of { text, startLine, startCol } objects.
 * @param {string} source
 * @returns {Array<{text: string, startLine: number, startCol: number}>}
 */
function extractJSStrings(source) {
  const results = [];
  // Match template literals, single-quoted, double-quoted strings
  const regex = /`([^`\\]*(?:\\.[^`\\]*)*)`|"([^"\\]*(?:\\.[^"\\]*)*)"|'([^'\\]*(?:\\.[^'\\]*)*)'/g;
  let match;
  while ((match = regex.exec(source)) !== null) {
    const text = match[1] !== undefined ? match[1] : (match[2] !== undefined ? match[2] : match[3]);
    if (!text || text.length < 10) continue; // skip short strings
    const beforeMatch = source.slice(0, match.index);
    const lines = beforeMatch.split('\n');
    const startLine = lines.length - 1;
    const startCol = lines[lines.length - 1].length;
    results.push({ text, startLine, startCol });
  }
  return results;
}

/**
 * Extract string literal regions from Python source code.
 * Handles triple-quoted strings, f-strings, single/double quoted.
 * @param {string} source
 * @returns {Array<{text: string, startLine: number, startCol: number}>}
 */
function extractPythonStrings(source) {
  const results = [];
  // Triple-quoted strings first (greedy), then single-line strings
  const regex = /(?:f|r|b|fr|rf|br|rb)?"""([\s\S]*?)"""|(?:f|r|b|fr|rf|br|rb)?'''([\s\S]*?)'''|(?:f|r|b|fr|rf|br|rb)?"([^"\n\\]*(?:\\.[^"\n\\]*)*)"|(?:f|r|b|fr|rf|br|rb)?'([^'\n\\]*(?:\\.[^'\n\\]*)*)'/gi;
  let match;
  while ((match = regex.exec(source)) !== null) {
    const text = match[1] !== undefined ? match[1] :
      (match[2] !== undefined ? match[2] :
        (match[3] !== undefined ? match[3] : match[4]));
    if (!text || text.length < 10) continue;
    const beforeMatch = source.slice(0, match.index);
    const lines = beforeMatch.split('\n');
    const startLine = lines.length - 1;
    const startCol = lines[lines.length - 1].length;
    results.push({ text, startLine, startCol });
  }
  return results;
}

/**
 * Extract prompt-like content from Markdown files.
 * Extracts code blocks and blockquoted text.
 * @param {string} source
 * @returns {Array<{text: string, startLine: number, startCol: number}>}
 */
function extractMarkdownContent(source) {
  const results = [];
  // Code blocks
  const codeBlockRegex = /```[\s\S]*?```/g;
  let match;
  while ((match = codeBlockRegex.exec(source)) !== null) {
    const text = match[0];
    if (text.length < 10) continue;
    const beforeMatch = source.slice(0, match.index);
    const lines = beforeMatch.split('\n');
    const startLine = lines.length - 1;
    const startCol = lines[lines.length - 1].length;
    results.push({ text, startLine, startCol });
  }
  // Blockquotes (lines starting with >)
  const sourceLines = source.split('\n');
  let quoteStart = -1;
  let quoteText = '';
  for (let i = 0; i < sourceLines.length; i++) {
    if (/^\s*>/.test(sourceLines[i])) {
      if (quoteStart === -1) quoteStart = i;
      quoteText += sourceLines[i].replace(/^\s*>\s?/, '') + '\n';
    } else {
      if (quoteStart !== -1 && quoteText.trim().length >= 10) {
        results.push({ text: quoteText.trim(), startLine: quoteStart, startCol: 0 });
      }
      quoteStart = -1;
      quoteText = '';
    }
  }
  if (quoteStart !== -1 && quoteText.trim().length >= 10) {
    results.push({ text: quoteText.trim(), startLine: quoteStart, startCol: 0 });
  }
  return results;
}

// =========================================================================
// SCANNING ENGINE
// =========================================================================

/**
 * Run detection patterns against a text string and return findings.
 * @param {string} text - Text to scan.
 * @param {string} minSeverity - Minimum severity to report.
 * @param {string[]} categories - Categories to check.
 * @returns {Array<{pattern: object, match: RegExpExecArray}>}
 */
function detectThreats(text, minSeverity, categories) {
  const findings = [];
  const minRank = SEVERITY_RANK[minSeverity] || 0;
  for (const pattern of INLINE_PATTERNS) {
    if (SEVERITY_RANK[pattern.severity] < minRank) continue;
    if (categories.length > 0 && !categories.includes(pattern.category)) continue;
    const match = pattern.regex.exec(text);
    if (match) {
      findings.push({ pattern, match });
    }
  }
  return findings;
}

/**
 * Scan a VS Code document and populate diagnostics.
 * @param {vscode.TextDocument} document
 * @param {vscode.DiagnosticCollection} diagnostics
 */
function scanDocument(document, diagnostics) {
  const config = vscode.workspace.getConfiguration('agent-shield');
  const minSeverity = config.get('minSeverity', 'low');
  const categories = config.get('categories', [
    'instruction_override', 'role_hijack', 'data_exfiltration',
    'social_engineering', 'system_prompt_leak'
  ]);

  const source = document.getText();
  const langId = document.languageId;
  const diags = [];

  // Extract strings based on language
  let regions = [];
  if (langId === 'javascript' || langId === 'typescript' || langId === 'javascriptreact' || langId === 'typescriptreact') {
    regions = extractJSStrings(source);
  } else if (langId === 'python') {
    regions = extractPythonStrings(source);
  } else if (langId === 'markdown') {
    regions = extractMarkdownContent(source);
  }

  // Also scan the full document for non-string patterns (e.g. markdown, comments)
  regions.push({ text: source, startLine: 0, startCol: 0 });

  const seen = new Set();

  for (const region of regions) {
    const findings = detectThreats(region.text, minSeverity, categories);
    for (const { pattern, match } of findings) {
      // Calculate the line/column of the match within the region
      const beforeMatch = region.text.slice(0, match.index);
      const matchLines = beforeMatch.split('\n');
      const matchLine = region.startLine + matchLines.length - 1;
      const matchCol = matchLines.length === 1
        ? region.startCol + matchLines[0].length
        : matchLines[matchLines.length - 1].length;

      // Deduplicate by line + category
      const key = `${matchLine}:${pattern.category}:${match[0]}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const matchEnd = matchCol + match[0].length;
      const range = new vscode.Range(matchLine, matchCol, matchLine, matchEnd);
      const diag = new vscode.Diagnostic(
        range,
        `[Agent Shield] ${pattern.description} (${pattern.severity}/${pattern.category})`,
        mapSeverity(pattern.severity)
      );
      diag.source = 'Agent Shield';
      diag.code = pattern.category;
      diags.push(diag);
    }
  }

  diagnostics.set(document.uri, diags);
}

/**
 * Scan selected text and show findings as diagnostics.
 * @param {vscode.TextEditor} editor
 * @param {vscode.DiagnosticCollection} diagnostics
 */
function scanSelection(editor, diagnostics) {
  if (!editor) return;
  const selection = editor.selection;
  if (selection.isEmpty) {
    vscode.window.showInformationMessage('[Agent Shield] No text selected.');
    return;
  }

  const config = vscode.workspace.getConfiguration('agent-shield');
  const minSeverity = config.get('minSeverity', 'low');
  const categories = config.get('categories', [
    'instruction_override', 'role_hijack', 'data_exfiltration',
    'social_engineering', 'system_prompt_leak'
  ]);

  const selectedText = editor.document.getText(selection);
  const findings = detectThreats(selectedText, minSeverity, categories);

  if (findings.length === 0) {
    vscode.window.showInformationMessage('[Agent Shield] No threats detected in selection.');
    return;
  }

  const diags = [];
  for (const { pattern, match } of findings) {
    const beforeMatch = selectedText.slice(0, match.index);
    const matchLines = beforeMatch.split('\n');
    const matchLine = selection.start.line + matchLines.length - 1;
    const matchCol = matchLines.length === 1
      ? selection.start.character + matchLines[0].length
      : matchLines[matchLines.length - 1].length;
    const matchEnd = matchCol + match[0].length;

    const range = new vscode.Range(matchLine, matchCol, matchLine, matchEnd);
    const diag = new vscode.Diagnostic(
      range,
      `[Agent Shield] ${pattern.description} (${pattern.severity}/${pattern.category})`,
      mapSeverity(pattern.severity)
    );
    diag.source = 'Agent Shield';
    diag.code = pattern.category;
    diags.push(diag);
  }

  // Merge with existing diagnostics
  const existing = diagnostics.get(editor.document.uri) || [];
  diagnostics.set(editor.document.uri, [...existing, ...diags]);

  vscode.window.showWarningMessage(
    `[Agent Shield] Found ${findings.length} threat(s) in selection.`
  );
}

// =========================================================================
// EXTENSION LIFECYCLE
// =========================================================================

/** @type {NodeJS.Timeout|null} */
let debounceTimer = null;

/** @type {boolean} */
let inlineScanEnabled = true;

/**
 * Activate the Agent Shield extension.
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
  console.log('[Agent Shield] Extension activated.');

  const diagnostics = vscode.languages.createDiagnosticCollection('agent-shield');
  context.subscriptions.push(diagnostics);

  // Read initial config
  const config = vscode.workspace.getConfiguration('agent-shield');
  inlineScanEnabled = config.get('enableInlineScan', true);

  // --- Command: Scan File ---
  const scanFileCmd = vscode.commands.registerCommand('agent-shield.scanFile', () => {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      vscode.window.showInformationMessage('[Agent Shield] No active editor.');
      return;
    }
    scanDocument(editor.document, diagnostics);
    const diags = diagnostics.get(editor.document.uri) || [];
    if (diags.length === 0) {
      vscode.window.showInformationMessage('[Agent Shield] No threats detected.');
    } else {
      vscode.window.showWarningMessage(
        `[Agent Shield] Found ${diags.length} threat(s) in ${editor.document.fileName}.`
      );
    }
  });

  // --- Command: Scan Selection ---
  const scanSelCmd = vscode.commands.registerCommand('agent-shield.scanSelection', () => {
    const editor = vscode.window.activeTextEditor;
    scanSelection(editor, diagnostics);
  });

  // --- Command: Toggle Inline Scan ---
  const toggleCmd = vscode.commands.registerCommand('agent-shield.toggleInlineScan', () => {
    inlineScanEnabled = !inlineScanEnabled;
    const state = inlineScanEnabled ? 'enabled' : 'disabled';
    vscode.window.showInformationMessage(`[Agent Shield] Inline scanning ${state}.`);
    if (!inlineScanEnabled) {
      diagnostics.clear();
    } else {
      // Scan the active document immediately
      const editor = vscode.window.activeTextEditor;
      if (editor) {
        scanDocument(editor.document, diagnostics);
      }
    }
  });

  // --- Real-time scanning on text change (debounced) ---
  const changeListener = vscode.workspace.onDidChangeTextDocument((event) => {
    if (!inlineScanEnabled) return;
    if (debounceTimer) {
      clearTimeout(debounceTimer);
    }
    debounceTimer = setTimeout(() => {
      scanDocument(event.document, diagnostics);
      debounceTimer = null;
    }, 500);
  });

  // --- Scan on document open ---
  const openListener = vscode.workspace.onDidOpenTextDocument((document) => {
    if (!inlineScanEnabled) return;
    scanDocument(document, diagnostics);
  });

  // --- Scan already-open documents ---
  if (inlineScanEnabled) {
    vscode.workspace.textDocuments.forEach((doc) => {
      scanDocument(doc, diagnostics);
    });
  }

  context.subscriptions.push(scanFileCmd, scanSelCmd, toggleCmd, changeListener, openListener);
}

/**
 * Deactivate the Agent Shield extension. Cleanup resources.
 */
function deactivate() {
  if (debounceTimer) {
    clearTimeout(debounceTimer);
    debounceTimer = null;
  }
  console.log('[Agent Shield] Extension deactivated.');
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
  activate,
  deactivate,
  // Exported for testing
  _internal: {
    INLINE_PATTERNS,
    SEVERITY_RANK,
    mapSeverity,
    extractJSStrings,
    extractPythonStrings,
    extractMarkdownContent,
    detectThreats,
    scanDocument
  }
};
