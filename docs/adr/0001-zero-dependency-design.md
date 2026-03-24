# 1. Zero-dependency, local-only detection

## Status

Accepted

## Date

2026-03-19

## Context

AI security SDKs could use cloud APIs for detection, but that creates privacy risks and network dependencies.

## Decision

All detection runs locally via pattern matching. No external API calls. No data leaves the user's environment.

## Consequences

Higher trust from privacy-conscious users. No API keys needed. Limited to pattern-based detection (mitigated by semantic module in v1.2). Larger bundle but zero network latency.
