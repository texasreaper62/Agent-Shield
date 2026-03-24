# Contributing to Agent Shield

Thank you for your interest in making AI agents safer! Contributions of all kinds are welcome — bug reports, detection pattern improvements, new features, documentation, and tests.

## Getting Started

```bash
# Clone the repo
git clone https://github.com/texasreaper62/Agent-Shield.git
cd Agent-Shield

# Install (zero external dependencies)
npm install

# Run tests to make sure everything works
npm test
npm run test:all
```

## Development Workflow

1. **Fork** the repository and create a feature branch from `main`
2. **Make your changes** following the code style below
3. **Add tests** for any new detection patterns or features
4. **Run the full test suite** — all tests must pass before submitting
5. **Submit a pull request** with a clear description of what you changed and why

## Code Style

- **Vanilla JavaScript** — Node.js >= 16, no frameworks, no build tools
- **CommonJS modules** — use `require()` and `module.exports`
- **`const` and `let`** — never `var`
- **Strict mode** — `'use strict'` at the top of every file
- **JSDoc comments** on all public functions
- **Console logging** prefixed with `[Agent Shield]`
- Keep functions focused — one function, one job
- Follow existing patterns in the codebase

## Running Tests

```bash
npm test              # Core and module tests
npm run test:all      # Full 40-feature suite
npm run redteam       # Attack simulation (49 payloads)
npm run test:fp       # False positive tests (103 benign inputs)
npm run test:benchmark # External benchmark (108 attacks)
npm run lint          # Code style checks
npm run score         # Shield score
```

All tests must pass before a PR will be merged.

## Adding Detection Patterns

Agent Shield's detection lives in `src/detector-core.js`. To add a new detection pattern:

1. Add the regex pattern to the appropriate category array in `detector-core.js`
2. Include a clear comment explaining what the pattern detects
3. Add test cases in `test/` — both attack inputs (should detect) and benign inputs (should not detect)
4. Run `npm run test:fp` to verify zero false positives
5. Run `npm run redteam` to verify detection works end-to-end

### Pattern Guidelines

- Patterns must be **deterministic** — regex only, no ML or heuristics that vary
- Patterns must run **locally** — no network calls, no external APIs
- Patterns must have **zero false positives** on the benign test suite
- Prefer **specific patterns** over overly broad ones
- Test against **multiple languages** if the attack vector is language-independent

## Adding New Modules

If you're adding a new module (new `.js` file in `src/`):

1. Follow the existing module structure
2. Export your public API from the module
3. Re-export it from `src/main.js` so users can access it via `require('agent-shield')`
4. Add TypeScript type definitions to `types/index.d.ts`
5. Add tests in `test/`
6. Update the project structure section in `CLAUDE.md`

## Reporting Bugs

- Use [GitHub Issues](https://github.com/texasreaper62/Agent-Shield/issues)
- Include: Node.js version, Agent Shield version, minimal reproduction, expected vs actual behavior
- For **security vulnerabilities**, see [SECURITY.md](SECURITY.md) — do not open a public issue

## Submitting Pull Requests

- Keep PRs focused — one feature or fix per PR
- Write a clear description of what changed and why
- Reference any related issues
- Ensure all CI checks pass
- Be responsive to review feedback

## Core Principles

All contributions must align with Agent Shield's core principles:

1. **Zero dependencies** — do not add npm packages
2. **Local-only** — no network calls, no telemetry, no data exfiltration
3. **Privacy first** — never transmit user data anywhere
4. **Deterministic** — detection must be reproducible and predictable
5. **Low overhead** — keep scan latency under 1ms

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
