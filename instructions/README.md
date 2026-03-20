# Agent Shield Instructions

Complete documentation for using Agent Shield v5.0 — a zero-dependency security SDK for AI agents. Covers Node.js, Python, Go, Rust, and WebAssembly.

## Core Guides (v1.0)

| # | Guide | Description |
|---|-------|-------------|
| 01 | [Getting Started](01-getting-started.md) | Installation, first shield, basic scanning, sensitivity levels |
| 02 | [Framework Integrations](02-framework-integrations.md) | Claude SDK, OpenAI, LangChain, Vercel AI, Express, generic wrappers |
| 03 | [Configuration](03-configuration.md) | All options, presets, config builder, policy files, allowlists |
| 04 | [Threat Detection](04-threat-detection.md) | Threat categories, severity levels, detection patterns, multi-language |
| 05 | [Tool Protection](05-tool-protection.md) | Tool scanning, wrappers, sequence analysis, permission boundaries |
| 06 | [PII & Data Protection](06-pii-and-data-protection.md) | PII redaction, DLP, canary tokens, watermarking |
| 07 | [Multi-Agent Security](07-multi-agent-security.md) | Agent firewall, delegation chains, message signing, capability tokens |
| 08 | [Testing & Red Teaming](08-testing-and-red-teaming.md) | Red team sim, shield score, test generation, agent contracts |
| 09 | [Production Deployment](09-production-deployment.md) | Monitoring, compliance, enterprise, performance, shadow mode |
| 10 | [CLI Reference](10-cli-reference.md) | All CLI commands, flags, exit codes, scripting |

## Advanced Guides (v1.2–v5.0)

| # | Guide | Version | Description |
|---|-------|---------|-------------|
| 11 | [Semantic Detection & Plugins](11-semantic-detection.md) | v1.2–v2.0 | Semantic analysis, plugin marketplace, custom detectors |
| 12 | [Enterprise & Infrastructure](12-enterprise-and-infrastructure.md) | v2.0–v2.1 | Multi-tenant, RBAC, Kubernetes, Terraform, OpenTelemetry, VS Code |
| 13 | [Autonomous Defense](13-autonomous-defense.md) | v3.0 | Threat intelligence, adaptive policies, A/B testing, pattern builder |
| 14 | [Polyglot SDKs](14-polyglot-sdks.md) | v4.0 | Python, Go, Rust, and WebAssembly SDKs |
| 15 | [Advanced Capabilities](15-advanced-capabilities.md) | v5.0 | Agent protocol, policy DSL, fuzzer, model fingerprinting, cost optimizer |
| 16 | [Live Dashboard](16-live-dashboard.md) | v2.0+ | Real-time WebSocket threat monitoring UI |

## Quick Links

- **Just starting?** → [Getting Started](01-getting-started.md)
- **Using Claude/OpenAI/LangChain?** → [Framework Integrations](02-framework-integrations.md)
- **Going to production?** → [Production Deployment](09-production-deployment.md)
- **Running security tests?** → [Testing & Red Teaming](08-testing-and-red-teaming.md)
- **Need compliance reports?** → [Production Deployment](09-production-deployment.md#compliance-reporting)
- **Using Python/Go/Rust?** → [Polyglot SDKs](14-polyglot-sdks.md)
- **Writing custom policies?** → [Advanced Capabilities](15-advanced-capabilities.md#policy-dsl)
- **Setting up Kubernetes?** → [Enterprise & Infrastructure](12-enterprise-and-infrastructure.md#kubernetes-operator)
- **Real-time monitoring?** → [Live Dashboard](16-live-dashboard.md)

## Additional Resources

- [README](../README.md) — Project overview and quick start
- [CHANGELOG](../CHANGELOG.md) — Release history
- [CONTRIBUTING](../CONTRIBUTING.md) — How to contribute
- [SECURITY](../SECURITY.md) — Vulnerability reporting
- [PRIVACY](../PRIVACY.md) — Privacy policy
- [Examples](../examples/) — Working code examples
