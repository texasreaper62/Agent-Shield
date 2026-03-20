# Agent Shield Roadmap

This roadmap outlines the evolution of Agent Shield from a solid v1 SDK to the industry standard for AI agent security.

## v1.1 — Hardening (Current)

- [x] Expand homoglyph detection — comprehensive Unicode mapping (Cherokee, Georgian, IPA, Math Symbols, Enclosed/Circled, Small Caps, Superscript/Subscript)
- [x] True `worker_threads` support — opt-in `ThreadedWorkerScanner` for real parallel CPU-bound scanning
- [x] Independent benchmark suite — reproducible perf script (`npm run benchmark`) with throughput, latency, scaling, accuracy, and memory metrics
- [x] Adversarial mutation resilience — synonym-aware keyword cluster detection, pre-normalization, hex-escape decoding
- [x] Expanded AI phishing patterns — QR code phishing, MFA harvesting, credential urgency, subscription scams, AI access lures

## v1.2 — Semantic Detection

- [ ] LLM-assisted classification — optional second-pass using a local model (Ollama/llama.cpp) for ambiguous inputs the regex engine flags as borderline
- [ ] Embedding-based similarity — detect paraphrased attacks that evade pattern matching
- [ ] Context-aware scoring — factor in conversation history, not just single messages
- [ ] Confidence calibration — tune detection thresholds based on real-world feedback data

## v2.0 — Platform & Ecosystem

- [ ] Python SDK — port core detection to Python for the LangChain/LlamaIndex ecosystem
- [ ] WASM build — run Agent Shield in browsers, Cloudflare Workers, Deno, Bun
- [ ] Plugin marketplace — community-contributed detection patterns with quality scoring
- [ ] Dashboard v2 — real-time web dashboard with threat visualization, timelines, and drill-downs
- [ ] VS Code extension — scan prompts and agent code inline during development

## v2.1 — Enterprise & Scale

- [ ] Distributed scanning — Redis-backed shared threat state across multiple instances
- [ ] Kubernetes operator — sidecar container that shields any agent pod
- [ ] SSO/SAML integration — tie RBAC to enterprise identity providers
- [ ] Audit log streaming — push to Splunk, Elastic, S3, or any SIEM
- [ ] Custom model fine-tuning — train org-specific detection models on your threat data

## v3.0 — Autonomous Defense

- [ ] Self-healing patterns — when a new attack bypasses detection, auto-generate and deploy a pattern fix
- [ ] Honeypot mode — let attacks through to a sandboxed agent to study attacker behavior
- [ ] Threat intelligence network — opt-in anonymous pattern sharing across Agent Shield users (privacy-preserving, no raw data)
- [ ] Multi-modal scanning — detect injection in images, audio transcripts, PDFs, and tool outputs
- [ ] Agent behavior profiling — baseline normal agent behavior and flag anomalies (not just input scanning)

## Ongoing

- [ ] CVE-style threat IDs — publish an open threat taxonomy for AI agent attacks
- [ ] Certification program — "Agent Shield Certified" badge for agent frameworks that pass the test suite
- [ ] Community CTF events — regular public competitions using the CTF engine
- [ ] Research partnerships — collaborate with academic labs on novel attack/defense research

---

**Contributing:** We welcome contributions! Check out the [issues](https://github.com/texasreaper62/Agent-Shield/issues) for ways to help, or open a new one with your ideas.
