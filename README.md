# AI Shield

**Protect yourself from AI-specific threats while browsing the web.**

AI Shield is a free, open-source Chrome extension that detects prompt injection attacks, hidden AI manipulation, AI-powered scams, and fake AI chatbots — all without sending any of your data anywhere.

## Why AI Shield?

As AI assistants become part of everyday life, a new category of threats has emerged:

- **Hidden instructions** on websites that hijack your AI assistant
- **Fake AI chatbots** that impersonate ChatGPT, Claude, or other services to steal your information
- **Prompt injection attacks** that trick AI tools into doing things you didn't ask for
- **Data exfiltration** attempts that use AI assistants to leak your private information

Existing security solutions (CrowdStrike, Microsoft Prompt Shields, etc.) only protect enterprises. **AI Shield protects you.**

## Features

- **Prompt Injection Detection** — Catches hidden instructions designed to manipulate AI assistants
- **Hidden Text Scanning** — Finds invisible text on pages that could contain attack payloads
- **Fake AI Chatbot Detection** — Identifies impersonation attempts of ChatGPT, Claude, Gemini, and other AI services
- **Data Exfiltration Alerts** — Detects attempts to steal data through AI assistants
- **Real-time Scanning** — Continuously monitors pages as content loads dynamically
- **Plain Language Alerts** — Every warning is written for real people, not security experts

## Privacy

**Your data never leaves your browser.** Period.

- All scanning happens locally on your device
- No network requests are made by the extension
- No browsing history, page content, or personal data is ever transmitted
- We use Chrome's local storage only for scan results and aggregate statistics

## Installation

### From Source (Developer Mode)

1. Download or clone this repository
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable **Developer mode** (toggle in the top right)
4. Click **Load unpacked** and select the `ai-shield` directory
5. The shield icon will appear in your toolbar

### Testing

Open `test/test-page.html` in Chrome to see AI Shield in action. The test page contains various threat examples that the extension will detect.

## How It Works

AI Shield scans every web page you visit for AI-specific threats:

1. **Pattern Matching** — Checks page content against known prompt injection patterns
2. **Hidden Content Detection** — Scans for invisible text that could contain attack payloads
3. **Comment & Metadata Scanning** — Checks HTML comments, meta tags, and data attributes
4. **Fake Interface Detection** — Identifies chat-like UIs impersonating known AI services

Results are shown via:
- A **toolbar badge** with threat count and color coding (green = safe, yellow = caution, orange = warning, red = danger)
- A **warning banner** at the top of dangerous pages
- A **detailed popup** when you click the extension icon

## Status Indicators

| Status | Meaning |
|--------|---------|
| **Safe** (Green) | No AI threats detected on this page |
| **Caution** (Yellow) | Minor items noticed, but nothing dangerous |
| **Warning** (Orange) | Content found that could manipulate AI assistants |
| **Danger** (Red) | Active manipulation attempts detected |

## Technical Details

- Chrome Extension using Manifest V3
- Vanilla JavaScript — no frameworks or external dependencies
- All detection runs client-side via content scripts
- Typical scan time: under 100ms
- DOM mutation observer for dynamic content (debounced at 2 seconds)

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## Future Roadmap

- Firefox and Edge support
- Optional AI-powered analysis for ambiguous cases
- Email content scanning
- Configurable sensitivity levels
- Domain allowlist/blocklist
- Enterprise dashboard

## License

MIT License — see [LICENSE](LICENSE) for details.

## Disclaimer

AI Shield is a detection tool that helps identify potential AI-specific threats. No security tool can guarantee 100% protection. Always exercise caution when interacting with AI assistants and unfamiliar websites.
