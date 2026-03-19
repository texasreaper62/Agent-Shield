# Changelog

All notable changes to Agent Shield will be documented in this file.

This project follows [Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-03-19

### Initial Release

Agent Shield v1.0.0 — a zero-dependency security SDK for AI agents.

### Core Features

- **Prompt Injection Detection** — detects fake system prompts, instruction overrides, ChatML/LLaMA delimiters, markdown headers, and 30+ injection patterns
- **Role Hijacking Detection** — catches DAN mode, developer mode, jailbreak attempts, persona attacks
- **Data Exfiltration Prevention** — blocks system prompt extraction, markdown image leaks, fetch calls, tag extraction
- **Tool Abuse Detection** — flags sensitive file access, shell execution, SQL injection, path traversal, recursive tool calls
- **Social Engineering Detection** — identifies identity concealment, urgency + authority, gaslighting, false pre-approval
- **Obfuscation Detection** — decodes Unicode homoglyphs, zero-width chars, Base64, hex, ROT13, leetspeak, reversed text
- **Multi-Language Support** — detects attacks in English, Spanish, French, German, Portuguese, Chinese, Japanese

### Modules

- **AgentShield** — main SDK class with configurable sensitivity, blocking, and callbacks
- **Canary Tokens** — generate and detect prompt leak canaries
- **PII Redactor** — auto-redact SSNs, emails, phone numbers, credit cards (DLP engine)
- **Tool Guard** — tool sequence analysis and permission boundaries
- **Circuit Breaker** — rate limiting and automatic trip on repeated attacks
- **Conversation Analysis** — fragmentation detection, language switch detection, behavioral fingerprinting
- **Multi-Agent Security** — agent firewall, delegation chains, shared threat state
- **Multi-Agent Trust** — message signing (HMAC), capability tokens, blast radius containment
- **Encoding Detection** — steganography, encoding bruteforce, structured data scanning
- **Output Watermarking** — watermark agent outputs with differential privacy
- **Policy Engine** — YAML/JSON policy loading, structured logging, webhook alerts
- **Compliance Reporting** — SOC2, HIPAA, GDPR, OWASP, NIST, EU AI Act reports with audit trails
- **Enterprise Features** — multi-tenant isolation, RBAC, debug mode
- **RAG Scanner** — scan retrieved documents before they enter the context
- **Red Team Simulator** — 49 built-in attack payloads with automated testing
- **Shield Score** — quantitative security scoring and benchmarking

### Framework Integrations

- Anthropic / Claude SDK (`shieldAnthropicClient`)
- OpenAI SDK (`shieldOpenAIClient`)
- LangChain (`ShieldCallbackHandler`)
- Vercel AI SDK (`shieldVercelAI`)
- Express middleware (`expressMiddleware`)
- Generic agent wrapper (`wrapAgent`, `shieldTools`)

### CLI

- `npx agent-shield scan` — scan text for threats
- `npx agent-shield score` — calculate shield score
- `npx agent-shield redteam` — run attack simulation
- `npx agent-shield audit` — compliance audit
- `npx agent-shield patterns` — list all detection patterns

### Benchmarks

- 100% detection on internal red team (49 attacks)
- 99.1% detection on external benchmark (108 real-world attacks)
- 0% false positive rate (103 benign inputs)
- 100/100 A+ shield score
- ~48,000 scans/sec throughput
- < 0.03ms average latency
