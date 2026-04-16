---
description: Run the full Agent-Shield release ritual (test:full -> version bump -> CHANGELOG check -> publish -> push to both remotes -> tag). Replaces the manual Windows cmd block in CLAUDE.md.
argument-hint: <semver>
---

You are running the npm release for `agentshield-sdk`. The version bump is `$ARGUMENTS` (e.g. `14.1.0`).

Do NOT skip steps. Do NOT use --no-verify. If any step fails, stop and report.

## Steps

1. **Confirm clean working tree.** Run `git status`. If dirty, ask the user whether to commit, stash, or abort.
2. **Confirm on the right branch.** This release ritual runs from the merged-to-main state. Confirm `git branch --show-current` is `main`. If not, stop.
3. **Run the full test suite.** `npm run test:full`. If anything fails, stop and report.
4. **Validate CHANGELOG.md.** The top entry must reference the target version `$ARGUMENTS`. If it does not, stop and ask the user to add a CHANGELOG entry first.
5. **Bump the version.** `npm version $ARGUMENTS --allow-same-version`. This creates a tag.
6. **Publish to npm.** `npm publish`. The npm token must already be configured via `~/.npmrc` or `NPM_TOKEN` env var; do not pass it on the command line.
7. **Push to both remotes.** `git push origin main --follow-tags` then `git push agent-shield main --follow-tags`. Retry up to 4 times with 2s/4s/8s/16s backoff on network errors only.
8. **Verify.** `npm view agentshield-sdk version` should report `$ARGUMENTS`. Report the final state including the published URL.

## Refusals

- Refuse to publish if `npm run test:full` is skipped.
- Refuse to publish if CHANGELOG.md is not updated.
- Refuse to publish if not on `main`.
- Refuse to force-push to either remote.
