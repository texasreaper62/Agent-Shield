# Microsoft Agent Governance Toolkit Parity Audit

**Date:** April 16, 2026
**Versions:** Microsoft Agent Governance Toolkit v1.0 (April 2, 2026) vs Agent Shield v13.6

## TL;DR

Microsoft shipped a multi-package, multi-language governance toolkit that covers all 10 OWASP Agentic risks with sub-0.1ms p99 deterministic policy enforcement. Agent Shield covers the same 10 risks plus ~30 additional categories (encoding, steganography, visual deception, Sybil, side-channel, etc.), but we lag in:

- Multi-language parity (Node is primary; Python/Go/Rust are behind)
- Sub-millisecond deterministic enforcement (our best p99 is 112μs, worst 3.6ms vs their <0.1ms)
- Plug-in lifecycle management for first-party frameworks
- Multi-agent secure mesh infrastructure

We lead in:

- Detection breadth (289 patterns vs their policy-driven approach)
- Attack research (DeepMind traps, Unit 42 IDPI, 30+ recent CVEs)
- Benchmark rigor (F1 0.988 on real-world corpus)
- Adversarial self-training loop

---

## Side-by-Side Capability Comparison

| Capability | Microsoft Package | Agent Shield Module | Gap? |
|---|---|---|---|
| Policy engine / runtime guardrails | Agent OS | `detector-core.js` + `mcp-guard.js` + `middleware.js` | None on function; we're slower at p99 |
| Agent-to-agent communication | Agent Mesh | `agent-protocol.js`, `message-integrity.js` | No built-in discovery/routing |
| Dynamic execution rings / sandbox | Agent Runtime | `plugin-system.js` (IsolatedPluginSandbox, v13.6) | Comparable for plugins; no generic execution sandbox |
| Reliability safeguards (SRE) | Agent SRE | `circuit-breaker.js`, `drift-monitor.js`, `incident-response.js` | Comparable |
| Automated compliance verification | Agent Compliance | `compliance.js`, `owasp-2025.js`, `nist-mapping.js`, `eu-ai-act.js`, `certification.js` | Comparable |
| Plug-in lifecycle management | Agent Marketplace | `plugin-marketplace.js` | No first-party marketplace |
| RL training governance | Agent Lightning | None | **GAP** — we don't address training-time governance |
| Prompt injection detection | (policy-based) | `detector-core.js` (289 patterns) | We have deeper detection |
| Indirect prompt injection | (policy-based) | `ipia-detector.js` + `document-scanner.js` | We lead |
| Memory poisoning | (policy-based) | `memory-guard.js`, `render-differential.js` (v13.5) | We lead with persistent-memory detection |
| Supply chain / dependency | (policy-based) | `supply-chain-scanner.js` (27+ CVEs) | We lead |
| Sybil / coordinated agents | (none visible) | `sybil-detector.js` | We lead |
| Side-channel exfiltration | (none visible) | `side-channel-monitor.js` | We lead |
| Visual deception | (none visible) | `render-differential.js` | We lead |
| Human-in-the-loop defenses | (none visible) | `hitl-guard.js` | We lead |
| Attack genome / evolution | (none visible) | `attack-genome.js`, `evolution-simulator.js`, `self-training.js` | We lead |

## Framework Integration Comparison

| Framework | Microsoft Hook | Agent Shield Hook | Gap? |
|---|---|---|---|
| LangChain | callback handlers | `ShieldCallbackHandler` | None |
| CrewAI | task decorators | None | **GAP** — no CrewAI wrapper |
| Google ADK | plugin system | None | **GAP** — no Google ADK wrapper |
| MS Agent Framework | middleware pipeline | None | **GAP** — no MS AF wrapper |
| Anthropic | — | `shieldAnthropicClient` | We lead |
| OpenAI | — | `shieldOpenAIClient` | We lead |
| OpenAI Agents SDK | — | `shieldOpenAIAgent` (v14 in progress) | We lead (new April 2026 SDK) |
| Vercel AI SDK | — | `shieldVercelAI` | We lead |
| MCP SDK | — | `shieldMCPServer`, `MCPGuard` | We lead |
| Express / HTTP | — | `expressMiddleware`, `shieldMiddleware` | We lead |

## Multi-Language Support

| Language | Microsoft | Agent Shield | Gap |
|---|---|---|---|
| Python | First-class (7 packages) | Partial SDK (141 patterns, 32 tests) | Significant |
| TypeScript/JavaScript | First-class (7 packages) | **Primary** (289 patterns, 2000+ tests) | We lead |
| Rust | First-class (7 packages) | Partial (`rust-core/` RegexSet, not wired into Node) | Significant |
| Go | First-class (7 packages) | Partial SDK (141 patterns) | Significant |
| .NET | First-class | None | **GAP** — no C# SDK |
| Java / Kotlin | None | None | Parity |
| WASM | Not mentioned | `wasm/` browser/edge bundles | We lead |

## Performance

| Metric | Microsoft | Agent Shield |
|---|---|---|
| p99 latency | <0.1ms (vendor-claimed) | 112μs best / 1.18ms mean / 3.6ms worst (honest-measured) |
| Throughput | Not published | 18,030 scans/sec (long benign), 6,400 (short malicious) |
| Memory per scan | Not published | 400-600 bytes heap delta |
| Dependencies | Unknown | **Zero** (we stay a core differentiator) |

**Honest assessment:** Microsoft's <0.1ms claim is vendor-reported, not independently verified. If accurate, they beat us by 11.8x at best case and 36x at worst case. Our zero-dependency + detection-breadth trade-off is worth it for most users but matters for high-throughput enterprise agents.

---

## What Microsoft Has That We Don't

1. **Agent Lightning (RL training governance)** — no equivalent. Governs reward hacking and drift during RL fine-tuning.
2. **.NET SDK** — none. Significant miss for enterprise Microsoft-stack shops.
3. **Framework hooks for CrewAI, Google ADK, MS Agent Framework** — we miss three major ecosystems.
4. **Sub-0.1ms deterministic p99** — even if vendor-reported, our honest worst case is 36x theirs.
5. **Multi-language parity across all 7 packages** — their Python/Rust/Go are first-class; ours are partial.
6. **ClusterFuzzLite continuous fuzzing** — we have a fuzzer but no continuous CI fuzzing pipeline.
7. **SLSA-compatible build provenance with cryptographic hashes on CI** — we have SBOM but not build attestations.

## What We Have That They Don't

1. **297 detection patterns across 42 categories** vs their policy-only approach.
2. **Sybil detection, side-channel monitoring, visual deception, render-differential analysis** — entire categories they don't address.
3. **DeepMind AI Agent Trap defenses (v13, v13.2)** — 10 novel modules from first-principles analysis.
4. **Unit 42 research incorporation** — IDPI, persistent memory poisoning, SVG injection, acrostic evasion.
5. **Adversarial self-training loop** with 0% bypass convergence in 3 cycles.
6. **Attack genome sequencing + evolution simulator** for novel-variant detection.
7. **OpenAI Agents SDK (April 2026) native guardrail integration** — they haven't shipped this.
8. **Honest real-world F1 0.988 benchmark** on HackAPrompt/TensorTrust/research corpus.
9. **27+ MCP-specific CVE registry** with CI/CD SARIF output.
10. **WASM browser/edge bundles** for client-side detection.

---

## v14.0 Recommendations (Concrete)

Three to five items to close critical gaps. Ordered by impact.

### 1. CrewAI + Google ADK + MS Agent Framework wrappers (must-do)
Three framework integration files. Each ~50 lines. This closes a major credibility gap — we can't claim framework-agnostic while missing three ecosystems. Files:
- `src/integrations-crewai.js` — `shieldCrewAITask()` task decorator
- `src/integrations-google-adk.js` — `shieldGoogleADK()` plugin hook
- `src/integrations-ms-agent.js` — `shieldMSAgentMiddleware()` for MS Agent Framework

### 2. Rust core NAPI binding (performance)
`rust-core/` exists but Node SDK doesn't use it. Wire it via NAPI to get 5-10x speedup on pattern matching. Our 3.6ms worst-case p99 could become 0.4ms and we'd be competitive with Microsoft's claims. Use `napi-rs` and conditionally prefer Rust when available.

### 3. Python/Go SDK pattern sync (multi-language)
Port the 50 highest-impact missing patterns (xss, svg, mcp.json, offensive agent, cloud IAM, structured data, encoding chain, steganographic, prompt extraction, memory poisoning). Target 190+ patterns in both Python and Go. This takes us from "partial SDK" to "credible multi-language."

### 4. Continuous fuzzing in CI
Our `fuzzer.js` exists but isn't wired to CI. Add a GitHub Actions workflow that runs 10-minute coverage-guided fuzzing on every PR and uploads findings. This is what ClusterFuzzLite does for Microsoft and it's table stakes for a security product.

### 5. .NET SDK stub (optional, long-tail)
A minimal .NET/C# port with the top 50 patterns. Not a full SDK, but enough to unblock enterprise Microsoft-stack customers. Low priority unless we have demand.

## Not Worth Doing

- **Agent Lightning equivalent** — RL training governance is a different market. Deprioritize.
- **Full feature parity across all 7 MS packages** — diffusion of focus. We win by depth in detection, not breadth of infrastructure.
- **Matching their p99 claim exactly** — theirs is vendor-reported. Our honest numbers are fine once NAPI is wired.
