# Publishing Agent Shield to the VS Code Marketplace

This document lists the exact commands to publish this extension.

## Prerequisites

1. Create a publisher (`texasreaper62`) at https://marketplace.visualstudio.com/manage
2. Generate a Personal Access Token (PAT) in Azure DevOps:
   - https://dev.azure.com/ -> User Settings -> Personal Access Tokens
   - Scope: **Marketplace -> Manage**
   - Save the token somewhere safe.
3. Install vsce globally (or use `npx`):

```bash
npm install -g @vscode/vsce
```

## One-time setup: log in

```bash
cd vscode-extension
vsce login texasreaper62
# Paste the PAT when prompted.
```

## Package the extension (produces a `.vsix`)

```bash
cd vscode-extension
vsce package
# Output: agent-shield-vscode-14.2.0.vsix
```

You can install this `.vsix` locally to test:

```bash
code --install-extension agent-shield-vscode-14.2.0.vsix
```

## Publish to the marketplace

```bash
cd vscode-extension
vsce publish
```

Or, publish a specific version bump in one shot:

```bash
vsce publish patch   # 14.2.0 -> 14.2.1
vsce publish minor   # 14.2.0 -> 14.3.0
vsce publish major   # 14.2.0 -> 15.0.0
```

## Verify

After publishing, the extension appears at:

https://marketplace.visualstudio.com/items?itemName=texasreaper62.agent-shield-vscode

## Open VSX (optional, for VSCodium/Cursor users)

```bash
npm install -g ovsx
npx ovsx publish agent-shield-vscode-14.2.0.vsix -p $OVSX_TOKEN
```

## Notes

- `icon.png` is referenced in `package.json`. Drop a 128x128 PNG at `vscode-extension/icon.png` before publishing or vsce will warn.
- `.vscodeignore` excludes `src/`, tests, and dev files from the final bundle.
- Bump the `version` field in `vscode-extension/package.json` and `CHANGELOG.md` for each release.
