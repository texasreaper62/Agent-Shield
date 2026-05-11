# Agent Shield Playground

A deployable, fully client-side playground for [Agent Shield](https://github.com/texasreaper62/Agent-Shield) — the SOTA AI security SDK.

- Detection runs **entirely in the browser**. No server, no API calls, no telemetry.
- Self-contained: the UMD bundle (`agent-shield.umd.js`) is shipped alongside `index.html`.
- Falls back to `esm.sh` only if the local bundle ever fails to load.

## Files

| File | Purpose |
| --- | --- |
| `index.html` | Single-page playground UI (dark/light mode, examples, severity badges). |
| `agent-shield.umd.js` | Agent Shield detection engine (built from `wasm/build.js`). |
| `vercel.json` | Vercel deploy config (headers, caching, CSP). |
| `netlify.toml` | Netlify deploy config (no build step). |
| `_headers` | Cloudflare Pages / Netlify security & cache headers. |

## Run locally

```bash
# any static server works
npx serve /home/user/Claude/playground
# then open http://localhost:3000
```

## Deploy

### Vercel (3 commands)

```bash
cd playground
npx vercel --prod
# follow prompts; framework: "Other", root: ".", build command: empty
```

### Netlify (3 commands)

```bash
cd playground
npx netlify-cli deploy --dir=. --prod
# or: drag this folder into https://app.netlify.com/drop
```

### Cloudflare Pages (3 commands)

```bash
cd playground
npx wrangler pages deploy . --project-name=agent-shield-playground
# (or connect the repo at https://dash.cloudflare.com/?to=/:account/pages)
```

## Rebuilding the engine bundle

The bundle is generated from the main SDK source:

```bash
cd ../wasm && node build.js
cp dist/agent-shield.umd.js ../playground/agent-shield.umd.js
```

## Security headers

All three deploy targets ship the same hardened headers:

- `Content-Security-Policy` restricting scripts to `'self'` plus `https://esm.sh` (CDN fallback only)
- `X-Frame-Options: DENY`, `frame-ancestors 'none'`
- `Strict-Transport-Security` 2 years with preload
- `Referrer-Policy: no-referrer`
- `Permissions-Policy` denies camera/mic/geo/FLoC
- Long-cache (`immutable`) for the bundle; no-cache for `index.html`

## License

MIT — same as Agent Shield.
