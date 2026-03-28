# MCP & AI Agent Supply Chain Attacks — March 2026

Research compiled March 28, 2026. Used to train Agent Shield's micro-model and enhance detection patterns.

## Executive Summary

March 2026 saw an explosion of AI agent security incidents. 30 CVEs were filed against MCP implementations in 60 days. 38% of public MCP servers lack authentication. HackerOne reported a 540% YoY surge in validated prompt injection vulnerabilities. The OpenClaw crisis exposed 42,665 vulnerable instances with 93.4% auth bypass. The ClawHavoc campaign planted 820+ malicious skills in ClawHub.

The core pattern: **these are 2010-era web vulnerabilities (SSRF, injection, path traversal) showing up in 2026 AI infrastructure** because MCP server authors are ML engineers, not security engineers.

---

## CVEs

### CVE-2026-26118 — Azure MCP Server SSRF
- **Severity:** CVSS 8.8 (High)
- **Date:** March 10, 2026 (Patch Tuesday)
- **Vector:** Attacker sends crafted URL to Azure MCP Server tool. Server makes outbound request to attacker URL, leaking its managed identity token.
- **Impact:** Compromises ML pipelines — training data, model repos, inference endpoints.
- **Fix:** Validate all URLs. Block private IP ranges (10.x, 172.16.x, 192.168.x). Block cloud metadata endpoints (169.254.169.254).
- **Source:** Microsoft Security Update

### CVE-2026-33980 — Azure Data Explorer MCP Server KQL Injection
- **Severity:** Critical
- **Date:** March 27, 2026
- **Vector:** `table_name` parameter interpolated directly into KQL queries via f-strings without validation. A prompt-injected agent can execute arbitrary Kusto queries.
- **Impact:** Arbitrary data access/modification on Azure Data Explorer clusters.
- **Fix:** Parameterize all queries. Never interpolate user input via f-strings.
- **Source:** GitLab Advisory

### CVE-2026-25253 — OpenClaw WebSocket Token Theft
- **Severity:** CVSS 8.8
- **Date:** January 30, 2026 (patch), exploited through March
- **Vector:** Control UI accepts `gatewayUrl` query parameter without validation. Attacker crafts URL that redirects WebSocket connection to their server, capturing auth tokens in the handshake.
- **Impact:** Full account takeover in milliseconds via 3-stage attack chain.
- **Fix:** Validate gatewayUrl against allowlist. Never pass auth tokens to unvalidated endpoints.
- **Source:** depthfirst research team

### CVE-2026-26144 — Microsoft Excel Copilot Agent Weaponization
- **Severity:** Critical
- **Date:** March 10, 2026
- **Vector:** XSS flaw in Excel causes Copilot Agent to exfiltrate data via unintended network egress. Zero-click — opening a spreadsheet triggers the attack.
- **Impact:** Data theft through weaponized AI agent proxy.
- **Source:** The Register

### CVE-2026-25536 — MCP TypeScript SDK Cross-Client Data Leak
- **Severity:** High
- **Date:** March 2026
- **Vector:** Cross-client data leak in the official MCP TypeScript SDK.
- **Source:** Unit 42 tracking

### CVE-2026-21858 — n8n AI Workflow Platform RCE
- **Severity:** CVSS 10.0 (Critical)
- **Date:** March 2026
- **Vector:** Two-part attack — unauthenticated file leak via web forms + full server takeover.
- **Impact:** Execute commands on underlying system, extract all workflow data.
- **Source:** CSO Online

---

## Campaigns & Research

### OpenClaw Crisis
- **Scale:** 42,665 exposed instances (Censys/Bitsight). 93.4% with auth bypass conditions.
- **512 vulnerabilities** found in initial audit, 8 critical.
- **No-click exfiltration:** PromptArmor demonstrated indirect prompt injection via messaging app link previews. Agent generates attacker-controlled URL with sensitive data in query params. Auto-preview triggers HTTP request — data stolen without user clicking.
- **Memory poisoning:** OpenClaw stores memory as plain Markdown (memory/YYYY-MM-DD.md, MEMORY.md). Both injected into context every turn. Attackers can persist malicious instructions.
- **Source:** The Hacker News, Kaspersky, Cisco, CyberPress

### ClawHavoc Campaign
- **820+ malicious skills** found on ClawHub (~20% of the registry).
- Primary payload: Atomic macOS Stealer (AMOS).
- Skills contain reverse shells, one at install time, one at runtime (redundancy).
- Grew from 324 to 820+ malicious skills in weeks.
- **Source:** Koi Security research

### CyberArk "Poison Everywhere" — Full-Schema Poisoning
- **Key finding:** Existing tool poisoning research focuses on description fields only. The true attack surface extends across the **entire tool schema** — default values, enum lists, title fields, examples, const values.
- A poisoned tool doesn't even need to be called. Just being loaded into context is enough.
- **Source:** CyberArk Threat Research Blog

### Invariant Labs — Tool Mutation / Rug Pull
- **Rug Pull:** Tool description/behavior silently altered after user approval.
- Clean version served during onboarding, malicious version delivered later.
- Most MCP clients don't notify users when tool descriptions change.
- **Source:** Invariant Labs Security Notification

### Palo Alto Unit 42 — Indirect Prompt Injection in the Wild
- First observed case of AI-based ad review evasion via IDPI.
- Instructions embedded in HTML pages, user-generated text, metadata, comments.
- **Source:** Unit 42 blog, March 3, 2026

### Microsoft — AI Recommendation Poisoning
- Memory poisoning via malicious links with pre-filled prompts.
- Most major AI assistants support URL parameters that pre-populate prompts.
- Creates practical 1-click attack vector.
- **Source:** Microsoft Security Blog, February 2026

### MCPTox Benchmark
- First benchmark for tool poisoning: 45 real-world MCP servers, 353 tools.
- o1-mini achieved 72.8% attack success rate.
- **More capable models are MORE susceptible** — the attack exploits superior instruction-following.
- **Source:** arXiv (2508.14925v1)

### OpenAI — Designing Agents to Resist Prompt Injection
- "The most effective real-world versions increasingly resemble social engineering."
- Defense cannot rely only on filtering inputs — system design must constrain impact.
- **Source:** OpenAI blog, March 11, 2026

### HackerOne — 540% Prompt Injection Surge
- Validated prompt injection vulnerabilities surged 540% year-over-year.
- Launched Agentic Prompt Injection Testing service March 21.
- Multi-turn adversarial scenarios against live AI applications.
- **Source:** HackerOne announcement

---

## MCP Landscape Statistics

| Metric | Value | Source |
|--------|-------|--------|
| CVEs in 60 days | 30 | Unit 42 |
| Public MCP servers without auth | 38% | 500+ server scan |
| SSRF exposure rate | 36.7% | URL-accepting servers |
| Prompt injection surge | 540% YoY | HackerOne |
| OpenClaw exposed instances | 42,665 | Censys/Bitsight |
| OpenClaw auth bypass rate | 93.4% | Maor Dayan research |
| ClawHub malicious skills | 820+ (~20%) | Koi Security |
| MCPTox attack success (o1-mini) | 72.8% | arXiv benchmark |
| Machine-to-human identity ratio | 82:1 | Industry survey |
| Agentic AI market (2034 proj.) | $199B | Industry analysis |

---

## Attack Taxonomy

### 1. SSRF via MCP Tool Parameters
Attacker manipulates URL-accepting tool params to target internal networks or cloud metadata endpoints. Server forwards request with its own credentials.

### 2. Query Language Injection
User-controlled values interpolated into KQL/SQL queries via f-strings. Prompt-injected agents execute arbitrary queries.

### 3. Full-Schema Poisoning
Malicious instructions hidden in JSON schema fields beyond description: default, enum, title, examples, const, pattern. Tool doesn't need to be called — loading it into context is enough.

### 4. Memory/Context Poisoning
Persistent instructions written to agent memory files (MEMORY.md). Injected into context every turn. Survives session restarts.

### 5. No-Click URL Exfiltration
Agent tricked into generating URL with sensitive data in query params. Messaging app link preview auto-fetches the URL, exfiltrating data without user action.

### 6. Tool Mutation / Rug Pull
Tool definition changes silently after initial approval. Clean version during review, malicious version in production. Most clients don't detect changes.

### 7. Malicious Skill Supply Chain
Trojanized skills in registries (ClawHub). Contain reverse shells, stealers, or BCC forwarding. 20% of registry infected in ClawHavoc.

### 8. WebSocket/Gateway Hijack
Unvalidated WebSocket connection parameters redirect to attacker server. Auth tokens captured during handshake.

### 9. Agent-as-Proxy Weaponization
Agent tricked into making authenticated requests to attacker endpoints, forwarding session tokens, cookies, or bearer tokens.

---

## How Agent Shield Uses This Research

### New detector-core patterns (14 added)
- SSRF (cloud metadata, private IPs)
- KQL/query injection, f-string interpolation
- Memory poisoning, context persistence
- No-click URL exfiltration, markdown image exfil
- WebSocket/gateway URL manipulation
- Schema field poisoning
- Supply chain skill installation
- Agent weaponization

### Enhanced supply-chain-scanner
- Full-schema poisoning scan (all JSON schema fields, not just description)
- SSRF vector detection (unvalidated URL params, metadata IPs in defaults)
- ClawHavoc malicious skill patterns (reverse shell, execSync, BCC, eval)
- Micro-model integration for ML-based detection

### Micro-model (src/micro-model.js)
- TF-IDF + k-NN classifier trained on 65+ real attack samples from this research
- 10 threat categories matching the attack taxonomy above
- 15 benign samples for false positive resistance
- Online learning support for new attack patterns
- Integrated into mcp-guard and supply-chain-scanner pipelines

---

## References

- [CVE-2026-26118: Azure MCP SSRF](https://windowsnews.ai/article/microsoft-patches-critical-azure-mcp-ssrf-vulnerability-cve-2026-26118-in-march-2026-security-update.404636)
- [CVE-2026-33980: KQL Injection](https://advisories.gitlab.com/pkg/pypi/adx-mcp-server/CVE-2026-33980/)
- [CVE-2026-26144: Excel Copilot Weaponization](https://www.theregister.com/2026/03/10/zeroclick_microsoft_info_disclosure_bug/)
- [5,618 MCP Servers Scanned](https://dev.to/manja316/we-scanned-5618-mcp-servers-for-security-vulnerabilities-heres-what-we-found-30k)
- [OpenClaw Flaws — The Hacker News](https://thehackernews.com/2026/03/openclaw-ai-agent-flaws-could-enable.html)
- [OpenClaw Security Crisis — Cisco](https://blogs.cisco.com/ai/personal-ai-agents-like-openclaw-are-a-security-nightmare)
- [OpenClaw — Kaspersky](https://www.kaspersky.com/blog/openclaw-vulnerabilities-exposed/55263/)
- [CyberArk Full-Schema Poisoning](https://www.cyberark.com/resources/threat-research-blog/poison-everywhere-no-output-from-your-mcp-server-is-safe)
- [Invariant Labs Tool Poisoning](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
- [MCPTox Benchmark](https://arxiv.org/html/2508.14925v1)
- [Unit 42: Indirect Prompt Injection](https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/)
- [OpenAI Agent Defense](https://openai.com/index/designing-agents-to-resist-prompt-injection/)
- [Microsoft Prompt Abuse Detection](https://www.microsoft.com/en-us/security/blog/2026/03/12/detecting-analyzing-prompt-abuse-in-ai-tools/)
- [OWASP Agentic Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [Real-World Attacks Behind OWASP Agentic Top 10](https://www.bleepingcomputer.com/news/security/the-real-world-attacks-behind-owasp-agentic-ai-top-10/)
- [Weekly AI Security Wrapup March 20-26](https://www.rockcybermusings.com/p/weekly-musings-top-10-ai-security-20260320-20260326)
- [AI Recommendation Poisoning — Microsoft](https://www.microsoft.com/en-us/security/blog/2026/02/10/ai-recommendation-poisoning/)
- [n8n RCE CVE-2026-21858](https://www.csoonline.com/article/4113980/critical-rce-flaw-allows-full-takeover-of-n8n-ai-workflow-platform.html)
- [MCP Security 2026 Guide — Elastic](https://www.elastic.co/security-labs/mcp-tools-attack-defense-recommendations)
- [Adversa AI: Top MCP Security Resources March 2026](https://adversa.ai/blog/top-mcp-security-resources-march-2026/)
