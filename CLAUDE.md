# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## Project Overview

Agent Shield is a Chrome extension that protects everyday people from AI-specific threats while browsing the web. It detects prompt injection attacks, hidden AI manipulation, AI-powered scams, and other threats that target AI assistants and their users.

**Design Philosophy:** Built for non-technical users. Every warning, alert, and UI element must be understandable by someone who doesn't know what "prompt injection" means. Plain language. No jargon.

**Privacy First:** All detection runs locally in the browser. No data ever leaves the user's machine.

## Build & Development

This is a vanilla JavaScript Chrome Extension (Manifest V3). No build tools or frameworks required.

```bash
# Load the extension in Chrome:
# 1. Open chrome://extensions/
# 2. Enable "Developer mode"
# 3. Click "Load unpacked" and select this directory

# Test the extension:
# Open test/test-page.html in Chrome to verify detections

# Run tests (future):
# npm test
```

## Code Style

- Vanilla JavaScript only — no frameworks or build tools for v0.1
- IIFE pattern for content scripts to avoid global scope pollution
- JSDoc comments on all public functions
- Console logging prefixed with `[Agent Shield]` for easy filtering
- All CSS injected into pages must use `!important` to prevent conflicts
- Use `const` and `let`, never `var`
- Strict mode (`'use strict'`) in all scripts
- Follow existing patterns in the codebase
- Use meaningful variable and function names
- Keep functions focused and concise

## Project Structure

```
/
├── .claude/
│   └── settings.json    # Claude Code project settings
├── icons/
│   ├── shield-green-16.png
│   ├── shield-green-32.png
│   ├── shield-green-48.png
│   └── shield-green-128.png
├── src/
│   ├── detector.js      # Detection engine (core brain)
│   ├── content.js       # Content script (runs on every page)
│   ├── content.css      # Warning banner styles
│   ├── background.js    # Service worker
│   ├── popup.html       # Popup interface
│   ├── popup.css        # Popup styles
│   └── popup.js         # Popup logic
├── test/
│   └── test-page.html   # Test page with injection examples
├── manifest.json        # Chrome Extension manifest (V3)
├── LICENSE              # MIT License
├── README.md            # Project documentation
├── PROJECT_BRIEF.md     # Detailed project specification
└── CLAUDE.md            # This file
```

## Important Conventions

- Commit messages should be clear and descriptive
- All new features should include tests
- Update documentation when changing public APIs
- All detection must run locally — never transmit user data
- Use plain language in all user-facing text
- Severity levels: critical > high > medium > low
- Status levels: danger > warning > caution > safe

## Testing

- Load the extension in Chrome Developer mode
- Open `test/test-page.html` to verify all detection categories work
- Check the popup UI shows correct threat counts and descriptions
- Verify the warning banner appears on pages with critical/high threats
- Verify badge colors update correctly per tab
- Performance: scans should complete in under 100ms for typical pages

## Architecture Notes

- **detector.js** is the core brain — self-contained, no DOM dependencies for pattern matching
- **content.js** orchestrates scanning on each page, manages the warning banner, handles messaging
- **background.js** manages badge state, cross-tab stats, and message routing
- **popup.js** displays results and handles user interaction with the popup

## Additional Notes

- Agent Teams is enabled via `CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1` in `.claude/settings.json`
