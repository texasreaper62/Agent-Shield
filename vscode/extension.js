'use strict';

/**
 * Agent Shield — VS Code Extension
 *
 * Scans code and prompts for AI security threats directly in the editor.
 *
 * Commands:
 *   agentShield.scanSelection  — Scan selected text for threats
 *   agentShield.scanFile       — Scan the entire active file
 *   agentShield.lintPrompt     — Lint a prompt template file
 *   agentShield.showScore      — Show shield score in a panel
 */

let vscode;
try {
  vscode = require('vscode');
} catch {
  // Running outside VS Code — provide stubs for testing
  vscode = null;
}

// Lazy-load Agent Shield (resolved at activation time relative to the extension)
let shield = null;
let promptLinter = null;
let scoreCalculator = null;

/**
 * Loads Agent Shield modules.
 * Resolves from the workspace or falls back to a relative path.
 */
function loadShieldModules() {
  try {
    const main = require('../src/main');
    shield = new main.AgentShield({ sensitivity: 'high', blockOnThreat: false, logging: false });
    promptLinter = new main.PromptLinter();
    scoreCalculator = new main.ShieldScoreCalculator({ sensitivity: 'high' });
    return true;
  } catch (err) {
    if (vscode) {
      vscode.window.showErrorMessage(`[Agent Shield] Failed to load SDK: ${err.message}`);
    }
    return false;
  }
}

// =========================================================================
// Diagnostics
// =========================================================================

/** @type {import('vscode').DiagnosticCollection|null} */
let diagnosticCollection = null;

/**
 * Converts Agent Shield threats to VS Code diagnostics.
 * @param {import('vscode').TextDocument} document
 * @param {Array} threats
 */
function updateDiagnostics(document, threats) {
  if (!diagnosticCollection || !vscode) return;

  const diagnostics = threats.map(threat => {
    // Try to find the threat text in the document for precise positioning
    const text = document.getText();
    let range;

    if (threat.matched) {
      const idx = text.indexOf(threat.matched);
      if (idx >= 0) {
        const startPos = document.positionAt(idx);
        const endPos = document.positionAt(idx + threat.matched.length);
        range = new vscode.Range(startPos, endPos);
      }
    }

    // Fall back to the first line if no match found
    if (!range) {
      range = new vscode.Range(0, 0, 0, 0);
    }

    const severity = threat.severity === 'critical' || threat.severity === 'high'
      ? vscode.DiagnosticSeverity.Error
      : threat.severity === 'medium'
        ? vscode.DiagnosticSeverity.Warning
        : vscode.DiagnosticSeverity.Information;

    const diag = new vscode.Diagnostic(range, `[Agent Shield] ${threat.description}`, severity);
    diag.source = 'Agent Shield';
    diag.code = threat.category || 'unknown';
    return diag;
  });

  diagnosticCollection.set(document.uri, diagnostics);
}

// =========================================================================
// Status Bar
// =========================================================================

/** @type {import('vscode').StatusBarItem|null} */
let statusBarItem = null;

/**
 * Updates the status bar with the latest scan result.
 * @param {string} status - 'safe', 'caution', 'warning', or 'danger'
 * @param {number} threatCount
 */
function updateStatusBar(status, threatCount) {
  if (!statusBarItem || !vscode) return;

  if (status === 'safe') {
    statusBarItem.text = '$(shield) Agent Shield: Safe';
    statusBarItem.backgroundColor = undefined;
  } else {
    statusBarItem.text = `$(shield) Agent Shield: ${threatCount} threat(s)`;
    statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
  }

  statusBarItem.show();
}

// =========================================================================
// Commands
// =========================================================================

/**
 * Scans the currently selected text for threats.
 */
function scanSelection() {
  if (!vscode) return;

  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showWarningMessage('[Agent Shield] No active editor.');
    return;
  }

  const selection = editor.selection;
  const text = editor.document.getText(selection);
  if (!text) {
    vscode.window.showWarningMessage('[Agent Shield] No text selected.');
    return;
  }

  const result = shield.scan(text, { source: 'vscode_selection' });

  if (result.threats.length === 0) {
    vscode.window.showInformationMessage('[Agent Shield] No threats detected in selection.');
  } else {
    vscode.window.showWarningMessage(
      `[Agent Shield] ${result.threats.length} threat(s) found in selection.`
    );
  }

  updateDiagnostics(editor.document, result.threats);
  updateStatusBar(result.status, result.threats.length);
}

/**
 * Scans the entire active file for threats.
 */
function scanFile() {
  if (!vscode) return;

  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showWarningMessage('[Agent Shield] No active editor.');
    return;
  }

  const text = editor.document.getText();
  const result = shield.scan(text, { source: 'vscode_file' });

  if (result.threats.length === 0) {
    vscode.window.showInformationMessage('[Agent Shield] No threats detected in file.');
  } else {
    vscode.window.showWarningMessage(
      `[Agent Shield] ${result.threats.length} threat(s) found in file.`
    );
  }

  updateDiagnostics(editor.document, result.threats);
  updateStatusBar(result.status, result.threats.length);
}

/**
 * Lints a prompt template file for security issues.
 */
function lintPrompt() {
  if (!vscode) return;

  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showWarningMessage('[Agent Shield] No active editor.');
    return;
  }

  const text = editor.document.getText();
  const lintResult = promptLinter.lint(text);
  const scanResult = shield.scan(text, { source: 'vscode_lint' });

  const totalIssues = (lintResult.issues ? lintResult.issues.length : 0) + scanResult.threats.length;

  if (totalIssues === 0) {
    vscode.window.showInformationMessage('[Agent Shield] Prompt template looks clean.');
  } else {
    vscode.window.showWarningMessage(
      `[Agent Shield] ${totalIssues} issue(s) found in prompt template.`
    );
  }

  // Combine lint issues and scan threats into diagnostics
  const combinedThreats = [...scanResult.threats];
  if (lintResult.issues) {
    for (const issue of lintResult.issues) {
      combinedThreats.push({
        severity: issue.severity || 'medium',
        category: 'prompt_lint',
        description: issue.message || issue.description || 'Prompt lint issue',
        matched: issue.matched || null
      });
    }
  }

  updateDiagnostics(editor.document, combinedThreats);
  updateStatusBar(scanResult.status, totalIssues);
}

/**
 * Shows the Shield Score in a webview panel.
 */
function showScore() {
  if (!vscode) return;

  const score = scoreCalculator.calculate();

  const panel = vscode.window.createWebviewPanel(
    'agentShieldScore',
    'Agent Shield Score',
    vscode.ViewColumn.One,
    { enableScripts: false }
  );

  const categoryRows = Object.entries(score.categories || {}).map(([key, cat]) => {
    const pct = typeof cat.score === 'number' ? cat.score : 0;
    return `<tr>
      <td>${cat.name || key}</td>
      <td>${pct}/100</td>
      <td><div style="background:#333;border-radius:4px;overflow:hidden;height:16px;">
        <div style="background:${pct >= 80 ? '#4caf50' : pct >= 50 ? '#ff9800' : '#f44336'};width:${pct}%;height:100%;"></div>
      </div></td>
    </tr>`;
  }).join('\n');

  panel.webview.html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <style>
    body { font-family: var(--vscode-font-family, sans-serif); padding: 20px; color: #ccc; background: #1e1e1e; }
    h1 { color: #fff; }
    .score-big { font-size: 64px; font-weight: bold; color: #4caf50; }
    table { width: 100%; border-collapse: collapse; margin-top: 20px; }
    th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #333; }
    th { color: #888; }
  </style>
</head>
<body>
  <h1>Agent Shield Score</h1>
  <div class="score-big">${score.overall || score.score || 0}</div>
  <p>Overall security posture</p>
  <table>
    <tr><th>Category</th><th>Score</th><th>Bar</th></tr>
    ${categoryRows}
  </table>
  <p style="margin-top:20px;color:#666;">Generated at ${new Date().toISOString()}</p>
</body>
</html>`;
}

// =========================================================================
// Activation / Deactivation
// =========================================================================

/**
 * Called when the extension is activated.
 * @param {import('vscode').ExtensionContext} context
 */
function activate(context) {
  console.log('[Agent Shield] Extension activating...');

  if (!loadShieldModules()) {
    return;
  }

  // Create diagnostic collection
  diagnosticCollection = vscode.languages.createDiagnosticCollection('agentShield');
  context.subscriptions.push(diagnosticCollection);

  // Create status bar item
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBarItem.text = '$(shield) Agent Shield';
  statusBarItem.tooltip = 'Agent Shield — AI Security Scanner';
  statusBarItem.command = 'agentShield.scanFile';
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);

  // Register commands
  context.subscriptions.push(
    vscode.commands.registerCommand('agentShield.scanSelection', scanSelection),
    vscode.commands.registerCommand('agentShield.scanFile', scanFile),
    vscode.commands.registerCommand('agentShield.lintPrompt', lintPrompt),
    vscode.commands.registerCommand('agentShield.showScore', showScore)
  );

  console.log('[Agent Shield] Extension activated successfully.');
}

/**
 * Called when the extension is deactivated.
 */
function deactivate() {
  if (diagnosticCollection) {
    diagnosticCollection.clear();
    diagnosticCollection.dispose();
  }
  if (statusBarItem) {
    statusBarItem.dispose();
  }
  console.log('[Agent Shield] Extension deactivated.');
}

module.exports = { activate, deactivate };
