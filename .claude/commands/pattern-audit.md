---
description: Audit Agent-Shield's detection regex for ReDoS, breadth, and dead patterns. v13.6 found 177 dead patterns; this guards against re-accumulation.
---

Audit the active detection patterns under `src/`. The targets are `detector-core.js`, `i18n-patterns.js`, and any other `*.js` containing regex literals exported as `PATTERNS` or similar.

## Checks

1. **ReDoS risk** -- flag any pattern with nested unbounded quantifiers like `(a+)+`, `(a|a)+`, `(.*)*`. Use the safe-regex heuristic: catastrophic backtracking signatures.
2. **Breadth audit** -- flag any pattern that matches < 3 chars or matches generic English words like `the`, `and`, `is`, `you`. These are likely false-positive engines.
3. **Dead pattern detection** -- run the full `npm run test:fp` and `npm run redteam` corpus through the patterns. Any pattern that has zero matches across all corpora for two consecutive audits is a dead pattern candidate. Report them; do not auto-remove.
4. **Duplicate detection** -- flag patterns whose source string is identical or where one is a strict superset of another.

## Output

Produce a Markdown report with sections: `ReDoS risk`, `Breadth concerns`, `Dead candidates`, `Duplicates`. For each finding include the pattern source, the file and line, and the suggested action (remove, narrow, or merge).

Do NOT modify the patterns file in this run. Audit only.
