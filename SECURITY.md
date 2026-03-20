# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.x     | Yes                |
| < 1.0   | No                 |

## Reporting a Vulnerability

If you discover a security vulnerability in Agent Shield, **please do not open a public issue.** Instead, report it privately so we can address it before disclosure.

### How to Report

1. **GitHub Security Advisories (preferred):** Use the [Security Advisories](https://github.com/texasreaper62/Agent-Shield/security/advisories/new) feature to report privately
2. **Email:** Send a detailed report to **security@agent-shield.dev**

### What to Include

- A clear description of the vulnerability
- Steps to reproduce (minimal test case preferred)
- The version(s) of Agent Shield affected
- Any potential impact or exploit scenarios you've identified
- CVSS score estimate if possible
- Suggested fix, if you have one

### Response SLAs

| Severity | Acknowledgment | Triage | Fix Target |
|----------|---------------|--------|------------|
| Critical | 24 hours | 48 hours | 7 days |
| High | 48 hours | 5 days | 14 days |
| Medium | 72 hours | 10 days | 30 days |
| Low | 7 days | 14 days | Next release |

### What to Expect

- **Acknowledgment** within the SLA above, confirming receipt
- **Triage** — we assess severity, impact, and affected versions
- **Fix** — a patch is developed, tested, and released within the target window
- **Advisory** — a GitHub Security Advisory is published after the fix is released
- **Credit** — reporters are credited in the release notes and advisory (unless they prefer anonymity)

## Scope

The following are **in scope** for security reports:

- **Detection bypasses** — inputs that should be flagged but aren't
- **False negatives** — attack patterns that evade all detectors
- **Pattern regex issues** — ReDoS (Regular Expression Denial of Service) in detection patterns
- **CLI vulnerabilities** — command injection or unsafe input handling in the CLI tool
- **Type confusion** — inputs that crash or cause unexpected behavior in public APIs
- **Resource exhaustion** — inputs that cause excessive CPU or memory usage
- **Dependency issues** — though Agent Shield has zero dependencies, report any if introduced

The following are **out of scope**:

- Feature requests or general bugs (use [GitHub Issues](https://github.com/texasreaper62/Agent-Shield/issues))
- Attacks that require modifying the Agent Shield source code itself
- Social engineering attacks against project maintainers

## Security Design Principles

Agent Shield is built with these security principles:

1. **Zero dependencies** — no supply chain risk from third-party packages
2. **Local-only detection** — no data ever leaves the user's environment
3. **No network calls** — no API keys, no cloud services, no telemetry
4. **Pattern matching only** — deterministic detection, no ML model dependencies
5. **Fail-safe defaults** — when in doubt, flag as suspicious
6. **Input validation** — public APIs validate types and reject invalid input

## Disclosure Policy

We follow coordinated disclosure:

1. Reporter submits vulnerability privately
2. We acknowledge and begin triage within the SLA
3. A fix is developed and tested
4. A patched version is released to npm
5. A GitHub Security Advisory is published
6. The reporter is credited (if desired)
7. The fix is documented in CHANGELOG.md

## Security Audits

Agent Shield runs the following automated security checks in CI:

- `npm audit` — checks for known vulnerabilities in the dependency tree
- Red team simulation — 49+ attack payloads tested on every commit
- False positive validation — 103+ benign inputs verified on every commit
- Shield score — detection coverage tracked across all threat categories

Thank you for helping keep Agent Shield and its users safe.
