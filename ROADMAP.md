# Agent Shield Roadmap

This document outlines the planned features and improvements for Agent Shield. Our mission is to protect AI agents from prompt injection, data exfiltration, tool abuse, and other AI-specific threats.

**Guiding principles:**
- Privacy first — all detection runs locally, always
- Zero dependencies — drop-in security for any agent pipeline
- Framework agnostic — works with Claude SDK, OpenAI, LangChain, or custom agents

---

## v1.0.0 — SDK Release (Current)

**Status: Complete**

- Core detection engine with 110 injection patterns across 10+ categories
- Multi-language attack detection (7 languages)
- Obfuscation detection (homoglyphs, zero-width chars, Base64, nested encoding)
- AgentShield class with scan/scanInput/scanOutput/scanToolCall
- Framework integrations: Anthropic SDK, OpenAI SDK, LangChain, Vercel AI
- Generic middleware: wrapAgent, shieldTools, Express middleware
- Canary tokens and prompt leak detection
- PII redaction and DLP engine
- Tool sequence analysis and permission boundaries
- Circuit breaker and rate limiter
- Multi-agent security (firewall, delegation chain, shared threat state)
- Message signing and capability tokens
- Compliance reporting (SOC2, HIPAA, GDPR)
- Audit trail and incident playbooks
- Red team attack simulator and payload fuzzer
- Shield score calculator and benchmarks (A+ 100/100 certified)
- TypeScript type definitions (154 exports)
- CLI tool with 12 commands
- 537 test assertions across 7 test suites
- Certification system and adaptive detection
- Stream scanner, plugin system, token analysis
- Document scanner, tool output validator
- Worker scanner, alert tuning, observability
- OpenTelemetry integration
- CTF engine and MCP server
- Python SDK bindings

---

## v1.1.0 — Enhanced Agent Integration

**Status: Complete**

- ~~Native Claude Agent SDK sub-agent mode~~ ✓ Implemented
- ~~Streaming message scanning (scan as tokens arrive)~~ ✓ Stream scanner module
- ~~Async scanning hooks for high-throughput pipelines~~ ✓ Worker scanner module
- ~~OpenClaw framework integration~~ ✓ OpenClaw skill + message hook
- AutoGen / CrewAI framework support

---

## v1.2.0 — Intelligence & Learning

**Status: Complete**

- ~~Adaptive pattern learning from feedback loop~~ ✓ Adaptive detection module
- ~~Custom pattern authoring API~~ ✓ Plugin system module
- ~~Threat trend analytics dashboard~~ ✓ Security dashboard
- Community threat pattern sharing (opt-in, anonymized)

---

## v2.0.0 — Enterprise

**Status: In Progress**

- ~~Multi-tenant deployment~~ ✓ Enterprise module
- ~~RBAC integration~~ ✓ Enterprise module
- ~~Centralized policy management~~ ✓ Policy module
- ~~Team-level threat dashboards~~ ✓ Live dashboard
- SSO integration
- SLA-backed detection guarantees

---

## Contributing

Have ideas for the roadmap? Open an issue at: https://github.com/texasreaper62/Agent-Shield/issues
