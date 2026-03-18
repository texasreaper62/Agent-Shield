# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## Project Overview

Agent Shield is a security SDK for AI agents. It protects agents from prompt injection, data exfiltration, tool abuse, and 30+ other AI-specific threats. It runs as a sub-agent or middleware inside any agent pipeline — Claude SDK, OpenAI, LangChain, or custom agents.

**Design Philosophy:** Zero-dependency, local-only detection. Drop it into any Node.js agent and it works. No API keys, no cloud calls, no data leaves the user's environment.

**Privacy First:** All detection runs locally via pattern matching. No external calls ever.

## Build & Development

```bash
# Install (no external dependencies)
npm install

# Run tests
npm test

# Run full test suite (40 features)
npm run test:all

# Red team attack simulation
npm run redteam

# Shield score / benchmarks
npm run score
npm run benchmark
```

## Code Style

- Vanilla JavaScript (Node.js >=16) — no frameworks or build tools
- CommonJS modules (`require`/`module.exports`)
- JSDoc comments on all public functions
- Console logging prefixed with `[Agent Shield]` for easy filtering
- Use `const` and `let`, never `var`
- Strict mode (`'use strict'`) in all scripts
- Follow existing patterns in the codebase
- Keep functions focused and concise

## Project Structure

```
/
├── src/
│   ├── index.js             # AgentShield class — main SDK entry point
│   ├── main.js              # Unified entry point (all exports)
│   ├── detector-core.js     # Core detection engine (patterns, scanning)
│   ├── middleware.js         # wrapAgent, shieldTools, Express middleware
│   ├── integrations.js      # Anthropic, OpenAI, LangChain, Vercel AI
│   ├── canary.js            # Canary tokens, prompt leak detection
│   ├── pii.js               # PII redaction, DLP engine
│   ├── tool-guard.js        # Tool sequence analysis, permission boundaries
│   ├── circuit-breaker.js   # Circuit breaker, rate limiter, shadow mode
│   ├── conversation.js      # Fragmentation, language switch, behavioral fingerprint
│   ├── multi-agent.js       # Agent firewall, delegation chain, shared threat state
│   ├── multi-agent-trust.js # Message signing, capability tokens, blast radius
│   ├── encoding.js          # Steganography, encoding bruteforce, structured data
│   ├── watermark.js         # Output watermarking, differential privacy
│   ├── policy.js            # Policy loading, structured logging, webhooks
│   ├── policy-extended.js   # A/B testing, threat intel, pattern builder
│   ├── compliance.js        # SOC2/HIPAA/GDPR reporting, audit trail
│   ├── enterprise.js        # Multi-tenant, RBAC, debug mode
│   ├── scanners.js          # RAG scanner, prompt linter, tool schema validator
│   ├── production.js        # Sampling, shadow comparison, graceful scanner
│   ├── testing.js           # Test suite generator, agent contracts
│   ├── redteam.js           # Attack simulator, payload fuzzer
│   ├── shield-score.js      # Shield score calculator, benchmarks
│   ├── threat-encyclopedia.js # Threat reference database
│   ├── presets.js           # Config presets, snippet generator
│   ├── badges.js            # Badge generator, GitHub Action reporter
│   ├── allowlist.js         # Allowlists, feedback loop, scan cache
│   └── utils.js             # Shared utilities
├── test/
│   ├── test.js              # Core tests
│   ├── test-modules.js      # Module tests
│   ├── test-new-features.js # New feature tests
│   ├── test-all-40-features.js # Full feature test suite
│   ├── detector.test.js     # Detector unit tests
│   └── lint.js              # Linting
├── examples/
│   ├── quick-start.js       # Quick start demo
│   ├── protect-agent.js     # Agent protection example
│   └── agent-shield.json    # Example config
├── types/
│   └── index.d.ts           # TypeScript type definitions
├── bin/
│   └── agent-shield.js      # CLI tool
├── dashboard/
│   └── index.html           # Security dashboard
├── package.json
├── LICENSE
├── README.md
└── CLAUDE.md
```

## Important Conventions

- Commit messages should be clear and descriptive
- All new features should include tests
- All detection must run locally — never transmit user data
- Severity levels: critical > high > medium > low
- Status levels: danger > warning > caution > safe

## Testing

- `npm test` — core and module tests
- `npm run test:all` — full 40-feature suite
- `npm run redteam` — attack simulation
- `node examples/quick-start.js` — verify SDK works end-to-end

## Architecture Notes

- **detector-core.js** — standalone pattern matching engine, no DOM dependencies
- **index.js** — `AgentShield` class wrapping the detector with config, stats, blocking
- **main.js** — unified re-export of all modules for `require('agent-shield')`
- **integrations.js** — framework-specific wrappers (Anthropic, OpenAI, LangChain, Vercel)
- **middleware.js** — generic agent wrapping and Express middleware

## Additional Notes

- Agent Teams is enabled via `CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1` in `.claude/settings.json`
