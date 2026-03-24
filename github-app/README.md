# Agent Shield — GitHub App & Action

Automatically scan pull requests for prompt injection, data exfiltration, role hijacking, and 20+ other AI-specific security threats.

All detection runs locally via pattern matching. Zero external dependencies. No data leaves your environment.

## Setup as GitHub App

### 1. Register the App

1. Go to **GitHub Settings > Developer settings > GitHub Apps > New GitHub App**
2. Use the manifest in `app.yml` or configure manually:
   - **Webhook URL:** `https://your-server.example.com/webhook`
   - **Webhook Secret:** Generate a secure random string
   - **Permissions:** Checks (write), Pull Requests (read), Contents (read)
   - **Events:** Pull Request, Check Suite
3. Generate and download a private key (.pem file)

### 2. Deploy the Server

#### Using Docker

```bash
docker build -t agent-shield-app ./github-app
docker run -d \
  -p 3000:3000 \
  -e GITHUB_APP_ID=your-app-id \
  -e GITHUB_PRIVATE_KEY="$(cat path/to/private-key.pem)" \
  -e GITHUB_WEBHOOK_SECRET=your-webhook-secret \
  agent-shield-app
```

#### Using Node.js

```bash
cd github-app
GITHUB_APP_ID=your-app-id \
GITHUB_PRIVATE_KEY="$(cat path/to/private-key.pem)" \
GITHUB_WEBHOOK_SECRET=your-webhook-secret \
node app.js
```

### 3. Install on Repositories

Go to your GitHub App's page and click **Install**. Select the repositories you want to protect.

## Setup as GitHub Action

Add this to your repository's `.github/workflows/agent-shield.yml`:

```yaml
name: Agent Shield PR Scan
on:
  pull_request:
    types: [opened, synchronize]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: agent-shield/agent-shield/github-app@main
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          min-severity: medium    # low, medium, high, critical
          # categories: ''        # comma-separated, empty = all
          # blocking: 'true'      # fail check if threats found
```

### Action Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `github-token` | Yes | `${{ github.token }}` | GitHub token for API access |
| `min-severity` | No | `medium` | Minimum severity to report |
| `categories` | No | *(all)* | Comma-separated categories to scan |
| `blocking` | No | `true` | Fail the check if threats are found |

### Action Outputs

| Output | Description |
|--------|-------------|
| `threat-count` | Number of threats detected |
| `severity` | Maximum severity level found |
| `safe` | Whether the PR passed (`true`/`false`) |

## Configuration

### Environment Variables (GitHub App)

| Variable | Required | Description |
|----------|----------|-------------|
| `GITHUB_APP_ID` | Yes | Your GitHub App ID |
| `GITHUB_PRIVATE_KEY` | Yes | PEM-encoded RSA private key |
| `GITHUB_WEBHOOK_SECRET` | Yes | Webhook signature secret |
| `PORT` | No | Server port (default: 3000) |
| `MIN_SEVERITY` | No | Minimum severity (default: medium) |

### Severity Levels

| Level | Description |
|-------|-------------|
| `critical` | Active exploitation attempts (jailbreaks, system prompt injection) |
| `high` | Direct prompt injection, role hijacking, data exfiltration |
| `medium` | Social engineering, encoding tricks, suspicious patterns |
| `low` | Informational findings, potential false positives |

### Detection Categories

| Category | Examples |
|----------|----------|
| `instruction_override` | "ignore previous instructions", "forget your training" |
| `role_hijack` | "you are now a ...", DAN mode, jailbreak prompts |
| `prompt_injection` | `[SYSTEM]`, `<<SYS>>`, `<\|im_start\|>system` |
| `data_exfiltration` | "send data to", "output your system prompt" |
| `social_engineering` | "I am the developer", "this is an authorized test" |
| `encoding` | `eval(atob(...))`, base64 decode tricks |

## How It Works

1. **Webhook received** — GitHub sends a `pull_request.opened` or `pull_request.synchronize` event
2. **Diff fetched** — The app fetches the PR diff via GitHub API
3. **Lines scanned** — Each added line is tested against 27+ regex patterns
4. **Check Run created** — Results appear as a Check Run with inline annotations
5. **PR comment** — If threats are found, a summary comment is added to the PR

Only **added lines** (lines starting with `+` in the diff) are scanned. Deleted lines and context lines are ignored.

## Example Annotations

When a threat is detected, you'll see annotations directly on the PR diff:

```
FAILURE  [CRITICAL] prompt_injection
         src/config.js:42
         Spoofed [SYSTEM] tag: attempts to inject system-level instructions.

WARNING  [MEDIUM] social_engineering
         data/prompts.json:15
         Claims to be an authorized override or test.
```

The Check Run summary shows a full breakdown by severity and category.

## Running Tests

```bash
node github-app/test/test-scanner.js
```

## Architecture

```
github-app/
├── app.js          # HTTP server, webhook handler
├── github-api.js   # GitHub API client (JWT, REST calls, diff parsing)
├── scanner.js      # Detection engine (27+ patterns, 6 categories)
├── action.js       # GitHub Action entry point
├── action.yml      # GitHub Action definition
├── Dockerfile      # Container image
├── app.yml         # GitHub App manifest
└── test/
    └── test-scanner.js  # Test suite (20 tests)
```
