# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.x     | Yes                |
| < 1.0   | No                 |

## Reporting a Vulnerability

If you discover a security vulnerability in Agent Shield, **please do not open a public issue.** Instead, report it privately so we can address it before disclosure.

### How to Report

1. **Email:** Send a detailed report to the repository maintainer via GitHub private vulnerability reporting
2. **GitHub:** Use the [Security Advisories](https://github.com/texasreaper62/Agent-Shield/security/advisories/new) feature to report privately

### What to Include

- A clear description of the vulnerability
- Steps to reproduce (minimal test case preferred)
- The version(s) of Agent Shield affected
- Any potential impact or exploit scenarios you've identified
- Suggested fix, if you have one

### What to Expect

- **Acknowledgment** within 48 hours
- **Status update** within 7 days with our assessment
- **Fix timeline** — critical issues will be patched as fast as possible, typically within 14 days
- **Credit** — reporters will be credited in the release notes (unless they prefer anonymity)

## Scope

The following are in scope for security reports:

- **Detection bypasses** — inputs that should be flagged but aren't
- **False negatives** — attack patterns that evade all detectors
- **Pattern regex issues** — ReDoS (Regular Expression Denial of Service) in detection patterns
- **CLI vulnerabilities** — command injection or unsafe input handling in the CLI tool
- **Dependency issues** — though Agent Shield has zero dependencies, report any if introduced

The following are **out of scope**:

- Feature requests or general bugs (use GitHub Issues)
- Attacks that require modifying the Agent Shield source code itself
- Social engineering attacks against project maintainers

## Security Design Principles

Agent Shield is built with these security principles:

1. **Zero dependencies** — no supply chain risk from third-party packages
2. **Local-only detection** — no data ever leaves the user's environment
3. **No network calls** — no API keys, no cloud services, no telemetry
4. **Pattern matching only** — deterministic detection, no ML model dependencies
5. **Fail-safe defaults** — when in doubt, flag as suspicious

## Disclosure Policy

We follow coordinated disclosure. Once a fix is available, we will:

1. Release a patched version to npm
2. Publish a GitHub Security Advisory
3. Credit the reporter (if desired)
4. Document the fix in CHANGELOG.md

Thank you for helping keep Agent Shield and its users safe.
