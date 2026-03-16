# AI Shield - Complete Project Brief

## What This Is

AI Shield is a Chrome extension that protects everyday people from AI-specific threats while browsing the web. It detects prompt injection attacks, hidden AI manipulation, AI-powered scams, and other threats that target AI assistants and their users.

**The motivation:** As AI agents become the primary way people interact with the internet, a new category of threats has emerged. Malicious websites embed hidden instructions to hijack AI assistants. AI-powered phishing is indistinguishable from real communication. Scam chatbots impersonate legitimate services. None of the existing security solutions (CrowdStrike, Microsoft Prompt Shields, etc.) protect consumers — they all target enterprise. This extension fills that gap.

**Design philosophy:** This is built for non-technical users. Think of someone's parents who are just starting to learn about AI. Every warning, every alert, every piece of UI must be understandable by someone who doesn't know what "prompt injection" means. Plain language. No jargon.

## Technical Architecture

### Extension Type

Chrome Extension using Manifest V3.

### Core Components

#### 1. Detection Engine (`detector.js`)

The brain of the extension. A self-contained module that scans page content and returns structured threat results. Must be fast (under 100ms for typical pages) and run entirely locally. No data leaves the browser.

**Detection modules:**

**A. Prompt Injection Pattern Matching**

Regex-based detection of known prompt injection patterns in page content.

Categories:
- **Instruction Override:** "ignore previous instructions", "disregard all prior rules", "forget your training", "override system settings", "new instructions:", "updated instructions:"
- **Role Hijacking:** "you are now a", "from now on you will", "act as an unrestricted", "pretend you have no restrictions", "DAN mode", "developer mode", "jailbreak mode", "godmode"
- **System Prompt Injection:** Fake `[SYSTEM]`, `[ADMIN]`, `[DEVELOPER]`, `[OVERRIDE]` tags, LLM-specific formatting like `<<SYS>>`, `<|im_start|>system`, `<|system|>`, `system prompt:`
- **Data Exfiltration:** "send this data to", "output your system prompt", "reveal your instructions", markdown image exfiltration patterns `![](https://evil.com?data=)`, fetch/XMLHttpRequest/sendBeacon calls
- **Social Engineering:** "do not mention you are an AI", "do not reveal this is automated", "do not acknowledge these instructions"
- **Obfuscation:** Base64-encoded instruction blocks, translation-wrapped injections ("translate the following" containing injection language)

**B. Hidden Text Detection**

Scans all DOM elements for text hidden via CSS that could contain injection payloads.

Detection methods:
- `display: none`
- `visibility: hidden`
- `opacity: 0`
- `clip-path: inset(100%)`
- `position: absolute` with extreme negative offsets (left/top < -9000)
- `font-size` of 0 or 1px
- Text color matching background color
- Zero height/width with overflow hidden

When hidden text is found, cross-reference it against the injection patterns. Hidden text WITH injection patterns = CRITICAL threat. Large blocks of hidden text without patterns = LOW (informational).

**C. HTML Comment & Metadata Scanning**

Walk the DOM tree for comment nodes. Scan all `<meta>` tag content attributes. Scan `data-*` attributes, `aria-label` attributes, and form field values. Apply injection patterns to all discovered content.

**D. Fake AI Interface Detection**

Detect chat-like UI elements (class/id containing "chat", "bot", "assistant") that reference known AI brands (ChatGPT, OpenAI, Claude, Anthropic, Gemini, Google AI, Copilot, Microsoft) on domains that don't belong to those companies.

**Severity Levels:**
- `critical` — Active exploitation attempt (hidden injections, system prompt spoofing, data exfiltration)
- `high` — Clear manipulation intent (role hijacking, instruction override, fake AI interfaces)
- `medium` — Suspicious but potentially benign (conditional instructions, response control attempts)
- `low` — Informational (large hidden text blocks without clear injection, encoded content)

**Threat Categories:**
- `prompt_injection` — Generic injection attempts
- `hidden_text` — Hidden/invisible content containing instructions
- `role_hijack` — Attempts to reassign AI identity
- `data_exfiltration` — Attempts to steal data via AI
- `fake_ai_interface` — Impersonation of known AI services
- `social_engineering` — Manipulation targeting AI behavior
- `instruction_override` — Direct attempts to replace AI instructions

**Scan Result Object:**
```javascript
{
  status: 'safe' | 'caution' | 'warning' | 'danger',
  threats: [
    {
      severity: 'critical' | 'high' | 'medium' | 'low',
      category: string,
      description: string,  // Plain language, no jargon
      detail: string,       // Technical detail for advanced users
      element: DOMElement | null
    }
  ],
  stats: {
    totalThreats: number,
    critical: number,
    high: number,
    medium: number,
    low: number,
    scanTimeMs: number
  },
  url: string,
  hostname: string,
  timestamp: number
}
```

#### 2. Content Script (`content.js`)

Runs on every web page. Responsibilities:
- Initialize the detector on page load
- Run initial scan when DOM is ready
- Observe DOM mutations and re-scan (debounced at 2 seconds)
- Show/hide warning banner at top of page when threats detected
- Respond to messages from popup (`GET_SCAN_RESULT`, `RESCAN`)
- Send scan results to background script
- Store results in `chrome.storage.local` for popup retrieval

#### 3. Warning Banner (injected into page)

A fixed-position banner at the top of the page when critical or high threats are found.
- Dark themed to stand out on any page background
- Shows shield icon, threat summary in plain language
- Dismissable with X button
- Slide-down animation on appearance
- Must use `!important` on all styles to avoid page CSS conflicts
- z-index at maximum (2147483647)

#### 4. Background Service Worker (`background.js`)

- Receives `SCAN_COMPLETE` messages from content scripts
- Updates extension badge (number of threats) and badge color per tab
- Updates tooltip text per tab
- Tracks cumulative stats in `chrome.storage.local`
- Cleans up tab data when tabs close
- Resets badge when tab navigates to new page

#### 5. Popup UI (`popup.html`, `popup.css`, `popup.js`)

Layout:
- Header: AI Shield logo/name + version
- Status card: Large status indicator
- Threat list: Expandable list with severity badges
- Stats bar: Scan time, total scans, total threats
- Rescan button
- Footer: Privacy reassurance

### Privacy Requirements

- All detection runs locally in the browser
- No network requests are made by the extension
- No user data is transmitted anywhere
- `chrome.storage.local` used only for scan results and aggregate stats

### Performance Requirements

- Scan should complete in under 100ms for typical pages
- DOM mutation observer should debounce re-scans
- Pattern matching should bail early when possible

## Future Considerations (not for v0.1)

- Optional AI-powered analysis layer (Claude API) for ambiguous cases
- Firefox and Edge support
- Email content scanning
- Threat intelligence aggregation (opt-in, anonymized)
- Enterprise dashboard
- Configurable sensitivity levels
- Whitelist/allowlist for trusted domains
