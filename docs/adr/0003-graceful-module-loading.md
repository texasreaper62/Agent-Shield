# 3. Graceful module loading with safeRequire

## Status

Accepted

## Date

2026-03-19

## Context

Agent Shield has 60+ modules. Users may only need a subset. A single import failure shouldn't crash everything.

## Decision

Use safeRequire() pattern in main.js — each module loads independently, failures are logged and skipped.

## Consequences

Partial imports always work. Easier debugging via console warnings. Users can import just what they need. Slight startup cost from attempting all loads.
