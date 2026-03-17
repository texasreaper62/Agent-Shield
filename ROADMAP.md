# AI Shield Roadmap

This document outlines the planned features and improvements for AI Shield. Our mission is to protect everyday people from AI-specific threats — simply, privately, and effectively.

**Guiding principles for every release:**
- Privacy first — all detection stays local unless users explicitly opt in
- Plain language — no jargon, ever
- Works for your parents — if it needs a tutorial, it's too complex

---

## v0.1.0 — Foundation (Current Release)

**Status: Complete**

- Prompt injection pattern detection (32+ patterns across 7 categories)
- Hidden text scanning (8 CSS hiding methods)
- HTML comment and metadata scanning
- Fake AI interface detection
- Warning banner on dangerous pages
- Popup with threat details and severity badges
- Badge with color-coded threat count
- Settings page (sensitivity, allowlist, notification toggles)
- Export scan report to clipboard
- Pause/resume scanning
- DOM mutation observer for dynamic content
- 65+ unit tests

---

## v0.2.0 — Smarter Detection

**Goal: Catch more threats with fewer false positives.**

### New Detection Capabilities

- [ ] **AI-generated phishing detection** — Identify telltale signs of AI-written phishing emails and pages (unnatural perfection, urgency patterns, impersonation cues)
- [ ] **Deepfake media warnings** — Flag images and videos on pages that show signs of AI generation or manipulation (EXIF metadata analysis, known deepfake hosting domains)
- [ ] **Clipboard hijacking detection** — Alert when a page tries to overwrite clipboard content with malicious prompts that users might paste into AI tools
- [ ] **AI voice scam page detection** — Identify pages promoting fake AI voice cloning services or "verify your identity by voice" scams
- [ ] **Malicious GPT/plugin detection** — Warn when pages link to or embed unverified custom GPTs, AI plugins, or MCP servers with suspicious permissions
- [ ] **Unicode/homoglyph obfuscation** — Detect injection attempts using look-alike Unicode characters (Cyrillic "а" vs Latin "a") to bypass filters
- [ ] **Multi-language injection patterns** — Detect prompt injections written in Spanish, French, German, Chinese, Japanese, Portuguese, and other languages
- [ ] **Nested encoding detection** — Catch double/triple-encoded payloads (Base64 inside URL encoding inside HTML entities)
- [ ] **Markdown/formatting exploits** — Detect abuse of markdown rendering to hide or disguise injections
- [ ] **Indirect prompt injection via images** — Flag images containing embedded text that could be read by multimodal AI (OCR-based text-in-image detection)

### Detection Quality

- [ ] **Contextual false-positive reduction** — Smarter analysis of surrounding content to reduce alerts on security blogs, research papers, and educational content
- [ ] **Confidence scoring** — Show users how certain AI Shield is about each threat (e.g., "Very likely a threat" vs "Might be suspicious")
- [ ] **Pattern versioning** — Track which detection patterns found what, enabling better tuning over time
- [ ] **Allowlist by threat category** — Let users suppress specific threat types on specific domains (e.g., allow prompt injection discussion on security blogs)

---

## v0.3.0 — User Experience

**Goal: Make AI Shield delightful and easy to understand.**

### Onboarding

- [ ] **First-run welcome walkthrough** — 3-step intro explaining what AI Shield does, what the badge colors mean, and how to check the popup
- [ ] **Interactive tutorial page** — A safe page with example threats that users can explore to learn what each detection looks like
- [ ] **"What is this?" tooltips** — Every threat type gets a plain-language tooltip explaining what it means and why it matters

### Alerts and Notifications

- [ ] **Smart notification priority** — Only notify for genuinely new and dangerous threats, not repeat detections on the same page
- [ ] **Browser notifications for critical threats** — Optional desktop notifications when visiting a page with critical-severity threats
- [ ] **Threat explanation cards** — When users tap a threat, show a card explaining: what was found, why it's dangerous, what to do about it, and a real-world example
- [ ] **"What should I do?" action guidance** — Specific advice for each threat type (e.g., "Don't paste anything from this page into an AI assistant")
- [ ] **Customizable alert sounds** — Optional audio cue for critical threats (accessibility)

### Visual Improvements

- [ ] **Light theme option** — Some users prefer light mode
- [ ] **Animated shield icon** — Subtle animation when actively scanning (shows users the extension is working)
- [ ] **Threat heatmap overlay** — Optional visual overlay showing exactly where threats are on the page (highlight the suspicious elements)
- [ ] **Page safety score** — A simple 0-100 score that's easier to understand than threat counts
- [ ] **Color-blind accessible mode** — Alternate color schemes and patterns for users with color vision deficiency

---

## v0.4.0 — History and Insights

**Goal: Help users understand their browsing safety over time.**

### Scan History

- [ ] **Scan history log** — Browsable list of recently scanned pages with their results (stored locally)
- [ ] **Search and filter history** — Find past scans by URL, threat type, severity, or date
- [ ] **Threat timeline** — Visual timeline showing when and where threats were encountered
- [ ] **Revisit alerts** — If a previously-safe site becomes dangerous, alert the user on next visit

### Personal Statistics

- [ ] **Weekly safety report** — A summary card showing: pages scanned, threats blocked, most common threat types, riskiest sites visited
- [ ] **Safety streak** — Gamification: "You've had 14 safe browsing days in a row"
- [ ] **Threat trends** — Show users if they're encountering more or fewer threats over time
- [ ] **Category breakdown charts** — Simple pie/bar charts showing which threat types are most common
- [ ] **"Sites to watch" list** — Automatically track domains where threats were found, alert if user returns

### Data Management

- [ ] **Export full history** — Download scan history as JSON or CSV for personal records
- [ ] **Auto-cleanup** — Automatically purge history older than 30/60/90 days (user configurable)
- [ ] **Import/export settings** — Backup and restore allowlists, preferences, and configuration

---

## v0.5.0 — Real-Time Protection

**Goal: Protect users at the moment of action, not just on page load.**

### Active Protection

- [ ] **Copy-paste scanning** — When users copy text from a page, scan clipboard content for hidden injections before they paste it into an AI tool
- [ ] **Form input monitoring** — Warn if a page's form fields contain pre-filled hidden prompt injections
- [ ] **Link preview scanning** — When hovering over links, show a quick safety indicator without needing to visit the page
- [ ] **Download scanning** — Check downloaded text files, PDFs, and documents for embedded prompt injections
- [ ] **Right-click "Scan selection"** — Users can highlight text and right-click to scan just that selection

### AI Tool Integration Warnings

- [ ] **ChatGPT/Claude tab detection** — When users have an AI assistant open in another tab, increase vigilance on all other tabs
- [ ] **"Before you paste" interstitial** — Optional confirmation when pasting content from a flagged page into a known AI tool
- [ ] **AI assistant URL detection** — Recognize when users are about to navigate to AI tools after visiting a dangerous page

---

## v0.6.0 — Email and Communication Protection

**Goal: Extend protection to where AI scams actually reach people.**

### Email Scanning

- [ ] **Gmail integration** — Scan email content in Gmail's web interface for AI-generated phishing, social engineering, and manipulation
- [ ] **Outlook web integration** — Same protection for Outlook.com and Office 365 webmail
- [ ] **AI impersonation detection in email** — Catch emails pretending to be from AI services ("Your ChatGPT account needs verification")
- [ ] **Urgency and pressure detection** — Flag emails using high-pressure manipulation tactics common in AI-enhanced scams
- [ ] **Sender reputation indicators** — Cross-reference sender patterns with known AI scam campaigns (local heuristics only)

### Social Media Protection

- [ ] **Twitter/X scanning** — Detect AI-generated manipulation, bot-like patterns, and injection attempts in tweets and replies
- [ ] **Reddit scanning** — Flag suspicious AI-generated content and potential manipulation in posts and comments
- [ ] **LinkedIn scanning** — Detect AI-generated fake profiles, connection requests, and job scam messages
- [ ] **Facebook/Instagram scanning** — Flag AI-generated scam posts and ads

---

## v0.7.0 — Community and Sharing

**Goal: Let users help each other stay safe (privacy-preserving).**

### Threat Reporting

- [ ] **One-click threat report** — Report a suspicious page to help others (sends only the URL and threat type, never page content)
- [ ] **False positive reporting** — Easy way to report when AI Shield flags something incorrectly, helping improve detection
- [ ] **Community threat feed** — Opt-in feed of recently reported dangerous URLs (no browsing data shared)

### Sharing and Advocacy

- [ ] **"Share warning" button** — Generate a shareable link/image warning others about a dangerous page
- [ ] **Family sharing** — Export your settings (allowlist, sensitivity) as a config file others can import
- [ ] **Safety tips of the week** — Optional educational cards teaching users about new AI threats in plain language
- [ ] **"Protect someone you love" sharing** — Easy installer link to send to family members with a personal note

---

## v0.8.0 — Cross-Browser and Cross-Platform

**Goal: Protect users regardless of their browser choice.**

### Browser Support

- [ ] **Firefox extension** — Full port using WebExtension APIs
- [ ] **Edge extension** — Publish on Microsoft Edge Add-ons store
- [ ] **Safari extension** — Port for macOS and iOS Safari
- [ ] **Brave extension** — Verify compatibility and optimize
- [ ] **Opera extension** — Verify compatibility and publish

### Platform Features

- [ ] **Chrome OS integration** — Optimize for Chromebook users
- [ ] **Extension sync** — Sync settings across browsers using encrypted local export/import
- [ ] **Mobile browser support** — Explore options for mobile browser protection (Kiwi, Firefox Android)

---

## v0.9.0 — Advanced Analysis

**Goal: Provide deeper insights for users who want them.**

### Optional AI-Powered Analysis

- [ ] **Local LLM integration** — Use on-device AI models (WebLLM/WebGPU) to analyze ambiguous content without sending data anywhere
- [ ] **Opt-in cloud analysis** — For users who choose it: send suspicious content (anonymized) to Claude API for deeper analysis
- [ ] **Natural language threat summaries** — AI-generated plain-language explanations of complex threats
- [ ] **Predictive threat scoring** — Use ML patterns to identify novel attacks that don't match existing signatures

### Technical Analysis

- [ ] **JavaScript behavior analysis** — Monitor page scripts for suspicious runtime behavior (dynamic injection, eval abuse)
- [ ] **Network request monitoring** — Flag outbound requests that might be exfiltrating data through AI interactions
- [ ] **Shadow DOM scanning** — Detect threats hidden in shadow DOM trees
- [ ] **iframe deep scanning** — Scan embedded iframes for threats (with appropriate permission boundaries)
- [ ] **WebSocket monitoring** — Detect real-time injection attempts through WebSocket connections

---

## v1.0.0 — Enterprise and Teams

**Goal: Bring AI Shield to organizations that need to protect their employees.**

### Enterprise Features

- [ ] **Admin dashboard** — Centralized view of threats across an organization (self-hosted or cloud)
- [ ] **Policy management** — Set organization-wide sensitivity levels, allowlists, and blocklists
- [ ] **Managed deployment** — Deploy via Chrome Enterprise, Group Policy, or MDM
- [ ] **SIEM integration** — Send threat alerts to Splunk, Sentinel, or other SIEM tools
- [ ] **API access** — REST API for custom integrations and automation
- [ ] **SSO support** — Enterprise single sign-on for the admin dashboard
- [ ] **Compliance reporting** — Generate reports for security audits and compliance reviews
- [ ] **Role-based access** — Admin, analyst, and viewer roles for the dashboard
- [ ] **Custom pattern library** — Organizations can create and share detection patterns internally

### Team Features

- [ ] **Shared threat intelligence** — Teams can pool threat data within their organization
- [ ] **Incident response workflow** — When a threat is found, create tickets in Jira/ServiceNow/PagerDuty
- [ ] **Slack/Teams notifications** — Alert security teams when employees encounter threats
- [ ] **Bulk allowlist management** — Manage trusted domains across the organization

---

## v1.1.0 — Accessibility and Inclusion

**Goal: Make AI Shield usable by everyone.**

### Accessibility

- [ ] **Full screen reader support** — ARIA labels, live regions, and semantic HTML throughout
- [ ] **Keyboard navigation** — Complete keyboard-only operation for all features
- [ ] **High contrast mode** — Extra-high-contrast theme for low-vision users
- [ ] **Large text mode** — Scalable UI that works at 200%+ zoom
- [ ] **Reduced motion mode** — Disable all animations for users with motion sensitivity
- [ ] **Voice control compatibility** — Ensure all features work with voice control software

### Internationalization

- [ ] **Spanish (es)** — Full UI translation
- [ ] **French (fr)** — Full UI translation
- [ ] **German (de)** — Full UI translation
- [ ] **Portuguese (pt)** — Full UI translation
- [ ] **Japanese (ja)** — Full UI translation
- [ ] **Chinese Simplified (zh-CN)** — Full UI translation
- [ ] **Chinese Traditional (zh-TW)** — Full UI translation
- [ ] **Korean (ko)** — Full UI translation
- [ ] **Arabic (ar)** — Full UI translation with RTL support
- [ ] **Hindi (hi)** — Full UI translation
- [ ] **Community translation portal** — Let users contribute translations for additional languages

---

## v1.2.0 — Education and Awareness

**Goal: Help users build lasting AI safety habits.**

### Learning Center

- [ ] **In-extension learning hub** — Short articles explaining each threat type with real examples
- [ ] **"Threat of the week" spotlight** — Highlight a trending AI threat each week with plain-language explanation
- [ ] **Interactive quizzes** — "Can you spot the injection?" — gamified learning about AI threats
- [ ] **Video walkthroughs** — Short (under 2 min) embedded videos explaining features
- [ ] **Glossary** — Searchable plain-language glossary of AI security terms

### Proactive Safety

- [ ] **Safety checklist for AI users** — Step-by-step guide: "Before you use any AI tool, check these 5 things"
- [ ] **"Is this AI?" detector** — Help users identify AI-generated text, images, and content on any page
- [ ] **Scam awareness alerts** — When trending AI scams are in the news, proactively show awareness cards
- [ ] **Kids mode** — Simplified, extra-protective mode for young internet users
- [ ] **Senior mode** — Larger text, simpler language, and phone-a-friend threat sharing for older users

---

## v1.3.0 — Developer and Power User Tools

**Goal: Serve the security community that helps keep everyone safe.**

### Developer Features

- [ ] **Custom pattern editor** — Write and test your own detection patterns with a visual regex builder
- [ ] **Pattern marketplace** — Share and download community-created detection patterns
- [ ] **Detection API** — JavaScript API for developers to integrate AI Shield scanning into their own tools
- [ ] **Webhook support** — Send threat notifications to custom endpoints
- [ ] **Debug mode** — Verbose logging showing exactly what was scanned, what matched, and why
- [ ] **Performance profiler** — Detailed scan timing breakdowns per detection module

### Power User Features

- [ ] **Custom severity overrides** — Reclassify threat severities based on personal risk tolerance
- [ ] **Regex pattern tester** — Built-in tool to test patterns against sample content
- [ ] **Bulk domain management** — Import/export large allowlists and blocklists
- [ ] **Scheduled scans** — Automatically re-scan bookmarked pages on a schedule
- [ ] **CLI tool** — Command-line scanner using the same detection engine for CI/CD pipelines
- [ ] **Browser DevTools panel** — AI Shield tab in Chrome DevTools with detailed technical analysis

---

## Future Explorations

These are ideas we're researching but haven't committed to a release yet:

- **Browser-native AI protection** — Work with browser vendors to build AI safety into browsers natively
- **AI assistant plugins** — Plugins for ChatGPT, Claude, and other AI tools that check content before processing
- **Hardware key integration** — Use hardware security keys as a trust anchor for AI interactions
- **AR/VR protection** — AI threat detection for mixed reality experiences
- **IoT device protection** — Scan smart home interfaces and voice assistant interactions
- **Decentralized threat intelligence** — Privacy-preserving threat sharing using zero-knowledge proofs
- **Academic research partnerships** — Collaborate with universities on emerging AI threat research
- **AI agent safety scoring** — Rate the safety of AI agents and plugins users encounter online
- **Digital literacy certification** — Optional course and badge for users who complete AI safety training

---

## How We Prioritize

1. **User impact** — How many people does this help, and how much?
2. **Threat urgency** — Is this threat actively harming people right now?
3. **Privacy preservation** — Can we do this without compromising user privacy?
4. **Simplicity** — Can a non-technical user understand and benefit from this?
5. **Community input** — What are users asking for?

## Contributing

Have a feature idea? Open an issue at https://github.com/texasreaper62/ai-shield/issues with the label `feature-request`. We read every suggestion.

---

*This roadmap is a living document. Priorities may shift based on the evolving AI threat landscape and community feedback.*
