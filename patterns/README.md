# Shared Pattern Definitions

This directory contains the canonical detection patterns for Agent Shield, shared across all SDK implementations (Node.js, Python, Go, Rust).

## Architecture

```
patterns.json    <-- Single source of truth (141 patterns)
     |
     v
generate.js      <-- Code generator (Node.js script)
     |
     +---> patterns.py   (Python SDK)
     +---> patterns.go   (Go SDK)
     +---> patterns.rs   (Rust SDK)
```

The Node.js SDK reads patterns directly from `src/detector-core.js`, which is the original authoritative source. The `patterns.json` file was extracted from `detector-core.js` and serves as the portable, language-neutral representation that the generator reads.

## File Overview

| File | Purpose |
|------|---------|
| `patterns.json` | Canonical JSON with all 141 patterns, homoglyph map (336 entries), and leetspeak map |
| `generate.js` | Node.js script that reads `patterns.json` and outputs `.py`, `.go`, `.rs` files |
| `patterns.py` | Generated Python module with compiled `re` patterns |
| `patterns.go` | Generated Go source with `regexp.MustCompile` patterns |
| `patterns.rs` | Generated Rust source with `once_cell::Lazy<Regex>` patterns |

## Pattern Structure

Each pattern in `patterns.json` has the following fields:

```json
{
  "id": "IO-001",
  "regex": "ignore\\s+(all\\s+)?...",
  "flags": "i",
  "category": "instruction_override",
  "severity": "critical",
  "description": "Human-readable explanation",
  "detail": "Technical detail for developers",
  "tags": ["injection", "override"]
}
```

### ID Prefixes

| Prefix | Category | Count |
|--------|----------|-------|
| IO | instruction_override | 23 |
| RH | role_hijack | 30 |
| PI | prompt_injection | 20 |
| DE | data_exfiltration | 16 |
| SE | social_engineering | 24 |
| MP | malicious_plugin | 3 |
| AP | ai_phishing | 16 |
| TA | tool_abuse | 9 |

### Severity Levels

- `critical` -- Highest risk, immediate block recommended
- `high` -- Strong signal of malicious intent
- `medium` -- Suspicious but may have legitimate uses
- `low` -- Informational, worth logging

### Categories

- `instruction_override` -- Attempts to nullify AI system instructions
- `role_hijack` -- Attempts to reassign AI identity or remove restrictions
- `prompt_injection` -- Fake system prompts, ChatML/LLaMA delimiters, code block exploits
- `data_exfiltration` -- Credential theft, system prompt extraction, markdown image leaks
- `social_engineering` -- Authority impersonation, urgency pressure, emotional manipulation
- `malicious_plugin` -- Unverified plugin promotion, API key harvesting
- `ai_phishing` -- Fake account alerts, deepfake tools, voice cloning scams
- `tool_abuse` -- Shell execution, SQL injection, path traversal, privilege escalation

## Obfuscation Maps

`patterns.json` also includes two obfuscation normalization maps:

- **homoglyphs** -- 336 Unicode look-alike characters mapped to Latin equivalents (Cyrillic, Greek, Armenian, Cherokee, Georgian, IPA, fullwidth, mathematical, enclosed, small caps, zero-width, combining)
- **leetspeak** -- 7 common number/symbol-to-letter substitutions (`4->a`, `3->e`, `1->i`, `0->o`, `5->s`, `7->t`, `@->a`)

## Regenerating Patterns

After modifying `patterns.json`, regenerate the SDK-specific files:

```bash
node patterns/generate.js
```

This will overwrite `patterns.py`, `patterns.go`, and `patterns.rs`.

## Adding a New Pattern

1. Add the pattern to `patterns.json` in the `patterns` array. Assign the next available ID for its category (e.g., `IO-024` for the next instruction_override pattern).
2. Update the `totalPatterns` field.
3. Run `node patterns/generate.js` to regenerate all SDK files.
4. Also add the pattern to `src/detector-core.js` so the Node.js SDK stays in sync.
5. Run `npm test` to verify.

## Ensuring Parity

All SDKs should detect the same 141 patterns. The `patterns.json` file is the contract. If a regex uses features not available in a target language's regex engine (e.g., Go's RE2 does not support backreferences or lookahead), the generator applies the closest available equivalent by inlining flags as `(?i)`, `(?m)`, or `(?s)` prefixes.
