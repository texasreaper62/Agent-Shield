# Relationship to Phylax

`agentshield-sdk` is the **public open-source security engine** that
[Phylax](https://github.com/texasreaper62/Project-Longarm) — the
privacy-AI company — builds on. This repo continues to ship as
**Agent Shield (MIT)** on npm and GitHub. Phylax is the commercial
overlay.

## Two-brand structure

| Brand | What it is | Repo | License |
|---|---|---|---|
| **Phylax** | Privacy-AI company. Integrated product across consumer, enterprise, and developer surfaces. | `texasreaper62/Project-Longarm` (renaming to `Phylax`) | UNLICENSED (proprietary) |
| **Agent Shield** | Open-source security engine. Detection, MCP guard, audit, policy DSL, etc. | This repo | MIT |

This is intentional, modeled on infrastructure companies that ship a
commercial product on top of an open-source foundation (e.g.,
HashiCorp + Terraform, Elastic + ELK).

## What changed in May 2026

- The founder pivoted the broader business thesis from "MCP/agent
  security audit platform" to "privacy-AI company." See
  `Project-Longarm/docs/adr/0001-pivot-to-privacy-ai.md`.
- The previously-planned commercial brand "Agent Shield" (for the
  commercial platform) was renamed to Phylax. The OSS engine keeps
  the Agent Shield name to preserve continuity with existing users
  of `agentshield-sdk@14.2.2+` on npm.
- The OSS engine becomes the foundation of Phylax's `core/shield/`
  runtime layer, consumed via `agentshield-sdk` as a regular npm
  dependency. Phylax does **not** vendor or fork the engine.

## What this means for OSS users

**Nothing changes.** Continue using:

```bash
npm install agentshield-sdk
```

```js
const { AgentShield } = require('agentshield-sdk');
```

- License: MIT (unchanged)
- Repo: `github.com/texasreaper62/Agent-Shield` (unchanged)
- npm: `agentshield-sdk` (unchanged)
- Release cadence: independent of Phylax's release cadence
- No telemetry, no calls home, no Phylax dependency (the OSS engine
  stays fully local-only)

If you build on Phylax's hosted runtime, you get the same engine plus
hosted audit log, hosted eval, team features, SSO. If you stay on
just the OSS engine, you get exactly what you have today.

## Where does new development happen?

| Capability | Lives in |
|---|---|
| Detection patterns, MCP guard, policy DSL, audit-immutable | This repo (OSS) |
| Phylax-specific wrappers (cloud connectivity, hosted eval) | `Project-Longarm/core/shield/` |
| Phylax product surfaces (consumer / enterprise / developer) | `Project-Longarm/surfaces/` |
| Privacy domain knowledge (playbooks, registries, evals) | `Project-Longarm/core/domain/` |

Pull requests against the public OSS engine continue to be welcome
here.
