# CLAUDE.md patch -- Push & Release Workflow

Replace the existing `## Push & Release Workflow` section in `CLAUDE.md` with the block below. The hand-typed Windows cmd commands are now encoded in `/release-npm` (slash command) and the `push-both` user-level slash command.

---

```markdown
## Release

Run `/release-npm <semver>` from the project root. Do not run `npm publish` manually.

The slash command handles: full test suite -> version bump -> CHANGELOG validation -> publish -> push to `origin` and `agent-shield` -> tag. It refuses to publish if tests fail, CHANGELOG is unchanged, or the branch is not `main`.

Pushing without publishing? Use `/push-both` (user-level slash command). It pushes the current branch to both remotes with retry-on-network-error.

Rules unchanged from prior workflow:
- Always update CHANGELOG.md before a version release.
- Do not fabricate PR descriptions about work we have not done.
```

---

## Why this changed

The prior workflow encoded as cmd commands in CLAUDE.md was: error-prone (typos in `npm version` flags), inconsistent (sometimes CHANGELOG was forgotten), and platform-specific (only worked on Windows). The slash command runs the same steps with hard refusals on the easy-to-skip checks.
