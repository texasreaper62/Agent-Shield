# Agent Shield — VS Code Extension

Scan AI prompts and agent code for prompt injection vulnerabilities, directly in your editor. Catches instruction overrides, role hijacking, data exfiltration, social engineering, and system prompt leaks before they reach production.

## Features

- **Real-time inline scanning** — detects threats as you type with debounced analysis.
- **Multi-language support** — scans JavaScript, TypeScript, Python, and Markdown files.
- **Smart string extraction** — parses template literals, f-strings, triple-quoted strings, and markdown code blocks.
- **20+ detection patterns** — ported from the Agent Shield core detection engine.
- **Severity mapping** — critical/high threats show as errors, medium as warnings, low as information.
- **Configurable** — filter by severity level and threat category.

## Commands

| Command | Description | Keybinding |
|---------|-------------|------------|
| `Agent Shield: Scan Current File` | Scan the entire active document | — |
| `Agent Shield: Scan Selection` | Scan selected text only | `Ctrl+Shift+S` |
| `Agent Shield: Toggle Inline Scanning` | Enable or disable real-time scanning | — |

## Configuration

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `agent-shield.enableInlineScan` | boolean | `true` | Enable real-time inline scanning |
| `agent-shield.minSeverity` | string | `"low"` | Minimum severity to report (`low`, `medium`, `high`, `critical`) |
| `agent-shield.categories` | array | all categories | Threat categories to scan for |

## Installation

1. Package the extension: `npx vsce package` from the `vscode-extension/` directory.
2. Install the `.vsix` file: **Extensions** > **...** > **Install from VSIX**.

Or, during development, open this folder in VS Code and press `F5` to launch the Extension Development Host.

## How It Works

The extension extracts string literals and prompt-like content from your code, then runs them against embedded detection patterns from the Agent Shield engine. All detection runs locally — no data leaves your environment.

## Threat Categories

- **instruction_override** — attempts to override or ignore prior instructions
- **role_hijacking** — attempts to reassign the AI's identity or role
- **data_exfiltration** — attempts to extract system prompts or send data externally
- **social_engineering** — attempts to manipulate AI into hiding its nature
- **system_prompt_leak** — attempts to inject fake system-level commands

## License

MIT
