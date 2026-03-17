#!/bin/bash
set -euo pipefail

# Only run in remote (web) environment
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "$CLAUDE_PROJECT_DIR"

# Install npm dependencies (if any are added in the future)
if [ -f "package.json" ]; then
  npm install 2>/dev/null || true
fi

# Validate the environment by running a quick check
node -e "console.log('[AI Shield] Session hook: Node.js ' + process.version + ' ready')"
