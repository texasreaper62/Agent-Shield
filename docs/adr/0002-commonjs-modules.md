# 2. CommonJS module system

## Status

Accepted

## Date

2026-03-19

## Context

ESM is the future standard, but Node.js 16+ still widely uses CommonJS, and many agent frameworks use require().

## Decision

Use CommonJS (require/module.exports) as primary module system. Add ESM wrapper via package.json exports.

## Consequences

Maximum compatibility with existing Node.js agent codebases. ESM users get a thin wrapper. No build step needed.
