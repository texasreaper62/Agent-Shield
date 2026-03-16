'use strict';

/**
 * AI Shield Detection Engine
 *
 * The core brain of the extension. Scans page content for AI-specific threats
 * including prompt injection, hidden text manipulation, fake AI interfaces,
 * and data exfiltration attempts.
 *
 * All detection runs locally — no data ever leaves the browser.
 */
const AIShieldDetector = (() => {

  // =========================================================================
  // PATTERN DEFINITIONS
  // =========================================================================

  /**
   * Prompt injection patterns organized by category.
   * Each pattern has: regex, severity, category, description (plain language),
   * and detail (technical).
   */
  const INJECTION_PATTERNS = [
    // --- Instruction Override ---
    {
      regex: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|rules|guidelines|prompts|context)/i,
      severity: 'high',
      category: 'instruction_override',
      description: 'This page tells AI assistants to ignore their safety rules.',
      detail: 'Instruction override pattern: attempts to nullify prior AI instructions.'
    },
    {
      regex: /disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|rules|guidelines|prompts)/i,
      severity: 'high',
      category: 'instruction_override',
      description: 'This page tells AI assistants to throw out their rules.',
      detail: 'Instruction disregard pattern: attempts to nullify prior AI instructions.'
    },
    {
      regex: /forget\s+(your|all|any)\s+(training|instructions|rules|guidelines|programming)/i,
      severity: 'high',
      category: 'instruction_override',
      description: 'This page tries to make AI assistants forget their training.',
      detail: 'Training override pattern: attempts to reset AI behavioral constraints.'
    },
    {
      regex: /override\s+(system|safety|security)\s+(settings|prompt|instructions|rules)/i,
      severity: 'critical',
      category: 'instruction_override',
      description: 'This page tries to override AI safety settings.',
      detail: 'System override pattern: direct attempt to bypass AI safety mechanisms.'
    },
    {
      regex: /(?:^|\n)\s*(?:new|updated|revised|replacement)\s+instructions\s*:/i,
      severity: 'high',
      category: 'instruction_override',
      description: 'This page contains fake "new instructions" for AI assistants.',
      detail: 'Instruction replacement pattern: attempts to inject new behavioral directives.'
    },

    // --- Role Hijacking ---
    {
      regex: /you\s+are\s+now\s+(?:a|an|the)\s+/i,
      severity: 'high',
      category: 'role_hijack',
      description: 'This page tries to change what an AI assistant thinks it is.',
      detail: 'Role reassignment pattern: attempts to override AI identity.'
    },
    {
      regex: /from\s+now\s+on\s+you\s+(?:will|shall|must|should|are)/i,
      severity: 'high',
      category: 'role_hijack',
      description: 'This page tries to give permanent new orders to AI assistants.',
      detail: 'Persistent role override: attempts to establish new behavioral baseline.'
    },
    {
      regex: /(?:act|behave|function|operate|respond)\s+as\s+(?:a|an)\s+unrestricted/i,
      severity: 'high',
      category: 'role_hijack',
      description: 'This page tries to remove AI safety restrictions.',
      detail: 'Restriction removal pattern: attempts to disable AI safety guardrails.'
    },
    {
      regex: /pretend\s+(?:you\s+)?(?:have\s+no|there\s+are\s+no|without)\s+restrictions/i,
      severity: 'high',
      category: 'role_hijack',
      description: 'This page asks AI to pretend it has no safety limits.',
      detail: 'Restriction pretense pattern: social engineering to bypass safety limits.'
    },
    {
      regex: /\b(?:DAN|D\.A\.N\.?)\s*(?:mode|prompt|jailbreak)/i,
      severity: 'critical',
      category: 'role_hijack',
      description: 'This page contains a known AI jailbreak technique called "DAN mode."',
      detail: 'DAN (Do Anything Now) jailbreak pattern detected.'
    },
    {
      regex: /\b(?:developer|dev)\s+mode\s+(?:enabled|activated|on|output)/i,
      severity: 'high',
      category: 'role_hijack',
      description: 'This page tries to trick AI into a fake "developer mode."',
      detail: 'Developer mode activation pattern: common jailbreak technique.'
    },
    {
      regex: /\bjailbreak\s*(?:mode|prompt|enabled|activated)/i,
      severity: 'critical',
      category: 'role_hijack',
      description: 'This page contains an AI jailbreak attempt.',
      detail: 'Explicit jailbreak activation pattern detected.'
    },
    {
      regex: /\bgod\s*mode\s*(?:enabled|activated|on)/i,
      severity: 'critical',
      category: 'role_hijack',
      description: 'This page tries to activate "god mode" on AI assistants.',
      detail: 'God mode activation pattern: attempts to remove all AI restrictions.'
    },

    // --- System Prompt Injection ---
    {
      regex: /\[\s*(?:SYSTEM|SYS)\s*\]/i,
      severity: 'critical',
      category: 'prompt_injection',
      description: 'This page contains fake system-level commands for AI assistants.',
      detail: 'Spoofed [SYSTEM] tag: attempts to inject system-level instructions.'
    },
    {
      regex: /\[\s*(?:ADMIN|ADMINISTRATOR)\s*\]/i,
      severity: 'critical',
      category: 'prompt_injection',
      description: 'This page fakes admin-level commands for AI assistants.',
      detail: 'Spoofed [ADMIN] tag: attempts to inject administrator-level instructions.'
    },
    {
      regex: /\[\s*(?:DEVELOPER|DEV)\s*\]/i,
      severity: 'high',
      category: 'prompt_injection',
      description: 'This page contains fake developer commands for AI assistants.',
      detail: 'Spoofed [DEVELOPER] tag: attempts to inject developer-level instructions.'
    },
    {
      regex: /\[\s*OVERRIDE\s*\]/i,
      severity: 'critical',
      category: 'prompt_injection',
      description: 'This page contains override commands targeting AI assistants.',
      detail: 'Spoofed [OVERRIDE] tag: attempts to override AI behavior.'
    },
    {
      regex: /<<\s*SYS\s*>>/i,
      severity: 'critical',
      category: 'prompt_injection',
      description: 'This page contains hidden system commands in LLaMA format.',
      detail: 'LLaMA-style <<SYS>> system prompt injection detected.'
    },
    {
      regex: /<\|im_start\|>\s*system/i,
      severity: 'critical',
      category: 'prompt_injection',
      description: 'This page contains hidden system commands in ChatML format.',
      detail: 'ChatML-style <|im_start|>system prompt injection detected.'
    },
    {
      regex: /<\|system\|>/i,
      severity: 'critical',
      category: 'prompt_injection',
      description: 'This page contains hidden system-level AI commands.',
      detail: 'System delimiter injection: <|system|> token detected.'
    },
    {
      regex: /(?:^|\n)\s*system\s*prompt\s*:/i,
      severity: 'high',
      category: 'prompt_injection',
      description: 'This page tries to set a fake "system prompt" for AI assistants.',
      detail: 'System prompt injection: attempts to define system-level instructions.'
    },

    // --- Data Exfiltration ---
    {
      regex: /send\s+(?:this|the|all|your|my)\s+(?:data|information|content|text|response)\s+to/i,
      severity: 'critical',
      category: 'data_exfiltration',
      description: 'This page tries to make AI assistants send your data somewhere.',
      detail: 'Data exfiltration instruction: attempts to redirect AI output to external destination.'
    },
    {
      regex: /output\s+(?:your|the)\s+(?:system\s+)?prompt/i,
      severity: 'high',
      category: 'data_exfiltration',
      description: 'This page tries to extract the AI assistant\'s internal instructions.',
      detail: 'System prompt extraction: attempts to reveal AI system instructions.'
    },
    {
      regex: /reveal\s+(?:your|the)\s+(?:system\s+)?(?:instructions|prompt|rules|guidelines)/i,
      severity: 'high',
      category: 'data_exfiltration',
      description: 'This page tries to reveal the AI assistant\'s hidden rules.',
      detail: 'Instruction reveal attempt: tries to expose AI system prompt.'
    },
    {
      regex: /!\[[^\]]*\]\(https?:\/\/[^)]*\?[^)]*(?:data|q|query|text|payload|exfil|leak|steal)=/i,
      severity: 'critical',
      category: 'data_exfiltration',
      description: 'This page tries to steal data through a hidden image link.',
      detail: 'Markdown image exfiltration: data encoded in image URL parameters.'
    },
    {
      regex: /!\[\]\(https?:\/\/(?!(?:i\.)?(?:imgur|github|gitlab|wikimedia|wikipedia)\b)[^)]+\)/i,
      severity: 'medium',
      category: 'data_exfiltration',
      description: 'This page contains a suspicious hidden image link that could leak data.',
      detail: 'Markdown image with suspicious external URL — potential exfiltration vector.'
    },
    {
      regex: /(?:fetch|XMLHttpRequest|sendBeacon|navigator\.sendBeacon)\s*\(/i,
      severity: 'medium',
      category: 'data_exfiltration',
      description: 'This page contains code that could send data to external servers.',
      detail: 'Network API call detected in content: potential data exfiltration via JavaScript.'
    },

    // --- Social Engineering ---
    {
      regex: /do\s+not\s+(?:mention|say|tell|reveal|disclose|acknowledge)\s+(?:that\s+)?you\s+are\s+(?:a|an)\s+(?:AI|artificial|bot|machine|language\s+model)/i,
      severity: 'high',
      category: 'social_engineering',
      description: 'This page tells AI assistants to hide that they are AI.',
      detail: 'Identity concealment instruction: AI told to deny being artificial.'
    },
    {
      regex: /do\s+not\s+(?:reveal|disclose|mention|acknowledge)\s+(?:that\s+)?(?:this|it)\s+is\s+automated/i,
      severity: 'high',
      category: 'social_engineering',
      description: 'This page tells AI to hide that responses are automated.',
      detail: 'Automation concealment: AI instructed to hide automated nature.'
    },
    {
      regex: /do\s+not\s+acknowledge\s+(?:these|the|any)\s+(?:instructions|commands|directives)/i,
      severity: 'high',
      category: 'social_engineering',
      description: 'This page tells AI to hide that it received secret instructions.',
      detail: 'Instruction concealment: AI told to deny receiving hidden directives.'
    },

    // --- Obfuscation ---
    {
      regex: /(?:translate|decode|convert)\s+(?:the\s+following|this)\s*:?\s*["\s]*(?:ignore|forget|override|you\s+are\s+now)/i,
      severity: 'high',
      category: 'prompt_injection',
      description: 'This page hides an attack inside a fake translation request.',
      detail: 'Translation-wrapped injection: malicious instructions disguised as translation task.'
    }
  ];

  /**
   * Known AI service domains — pages on these domains are NOT flagged
   * for fake AI interface detection.
   */
  const LEGITIMATE_AI_DOMAINS = [
    'openai.com', 'chat.openai.com', 'platform.openai.com',
    'anthropic.com', 'claude.ai', 'console.anthropic.com',
    'gemini.google.com', 'ai.google', 'bard.google.com', 'aistudio.google.com',
    'copilot.microsoft.com', 'bing.com',
    'github.com', 'github.dev',
    'perplexity.ai',
    'poe.com',
    'huggingface.co',
    'cohere.com',
    'mistral.ai',
    'chat.mistral.ai',
    'you.com',
    'phind.com',
    'replit.com',
    'cursor.com',
    'vercel.com'
  ];

  /**
   * Domains known to discuss AI security topics — detections on these sites
   * are legitimate content, not attacks. Reduce severity for educational context.
   */
  const EDUCATIONAL_CONTEXT_DOMAINS = [
    // Security research & education
    'owasp.org',
    'portswigger.net',
    'hackerone.com',
    'bugcrowd.com',
    'snyk.io',
    'securityweek.com',
    'bleepingcomputer.com',
    'krebsonsecurity.com',
    'thehackernews.com',
    // AI research & documentation
    'arxiv.org',
    'papers.ssrn.com',
    'ai.meta.com',
    'research.google',
    'deepmind.google',
    'openai.com',
    'anthropic.com',
    'docs.anthropic.com',
    'platform.openai.com',
    // Developer & education platforms
    'stackoverflow.com',
    'stackexchange.com',
    'medium.com',
    'dev.to',
    'towardsdatascience.com',
    'wikipedia.org',
    'en.wikipedia.org',
    // Code hosting (discussing injection patterns in code context)
    'github.com',
    'gitlab.com',
    'gist.github.com'
  ];

  /**
   * Checks if a hostname is an educational/research context.
   * @param {string} hostname - The hostname to check.
   * @returns {boolean}
   */
  const isEducationalDomain = (hostname) => {
    const normalized = hostname.toLowerCase().replace(/^www\./, '');
    return EDUCATIONAL_CONTEXT_DOMAINS.some(domain =>
      normalized === domain || normalized.endsWith('.' + domain)
    );
  };

  /**
   * AI brand names to look for in fake interface detection.
   */
  const AI_BRAND_PATTERNS = /\b(?:ChatGPT|GPT-?4|GPT-?3\.?5|OpenAI|Claude|Anthropic|Gemini|Google\s*AI|Bard|Copilot|Microsoft\s*AI)\b/i;

  /**
   * Chat interface CSS class/id patterns.
   */
  const CHAT_INTERFACE_PATTERNS = /(?:chat|bot|assistant|ai-chat|chatbot|chat-widget|chat-window|chat-container|conversation|message-list)/i;

  // =========================================================================
  // HELPER FUNCTIONS
  // =========================================================================

  /**
   * Checks if a hostname belongs to a legitimate AI service.
   * @param {string} hostname - The hostname to check.
   * @returns {boolean} True if the hostname is a known AI service.
   */
  const isLegitimateAIDomain = (hostname) => {
    const normalized = hostname.toLowerCase().replace(/^www\./, '');
    return LEGITIMATE_AI_DOMAINS.some(domain =>
      normalized === domain || normalized.endsWith('.' + domain)
    );
  };

  /**
   * Checks if a DOM element is hidden via CSS.
   * @param {Element} element - The DOM element to check.
   * @returns {boolean} True if the element is hidden.
   */
  const isElementHidden = (element) => {
    try {
      const style = window.getComputedStyle(element);

      if (style.display === 'none') return true;
      if (style.visibility === 'hidden') return true;
      if (parseFloat(style.opacity) === 0) return true;
      if (style.clipPath === 'inset(100%)') return true;

      const position = style.position;
      if (position === 'absolute' || position === 'fixed') {
        const left = parseInt(style.left, 10);
        const top = parseInt(style.top, 10);
        if ((!isNaN(left) && left < -9000) || (!isNaN(top) && top < -9000)) return true;
      }

      const fontSize = parseFloat(style.fontSize);
      if (!isNaN(fontSize) && fontSize <= 1) return true;

      const width = parseFloat(style.width);
      const height = parseFloat(style.height);
      if ((!isNaN(width) && width === 0) || (!isNaN(height) && height === 0)) {
        if (style.overflow === 'hidden') return true;
      }

      // Check if text color matches background color
      const color = style.color;
      const bgColor = style.backgroundColor;
      if (color && bgColor && color === bgColor && bgColor !== 'rgba(0, 0, 0, 0)' && bgColor !== 'transparent') {
        return true;
      }

      return false;
    } catch (e) {
      return false;
    }
  };

  /**
   * Checks if text looks like it might be base64-encoded instructions.
   * @param {string} text - Text to check.
   * @returns {object|null} Decoded result if suspicious, null otherwise.
   */
  const checkBase64Content = (text) => {
    // Look for base64-like strings (at least 20 chars long)
    const base64Regex = /[A-Za-z0-9+/]{20,}={0,2}/g;
    const matches = text.match(base64Regex);

    if (!matches) return null;

    for (const match of matches) {
      try {
        const decoded = atob(match);
        // Check if decoded content contains ASCII text (not binary garbage)
        const printableRatio = decoded.split('').filter(c => {
          const code = c.charCodeAt(0);
          return code >= 32 && code <= 126;
        }).length / decoded.length;

        if (printableRatio > 0.8 && decoded.length > 10) {
          // Check decoded content against injection patterns
          for (const pattern of INJECTION_PATTERNS) {
            if (pattern.regex.test(decoded)) {
              return {
                decoded: decoded.substring(0, 200),
                matchedPattern: pattern
              };
            }
          }
          // Even without pattern match, large base64 text is suspicious
          if (decoded.length > 50) {
            return { decoded: decoded.substring(0, 200), matchedPattern: null };
          }
        }
      } catch (e) {
        // Not valid base64, skip
      }
    }

    return null;
  };

  // =========================================================================
  // SCANNING FUNCTIONS
  // =========================================================================

  /**
   * Scans text content against all injection patterns.
   * @param {string} text - The text to scan.
   * @param {string} source - Where the text came from (for detail messages).
   * @returns {Array} Array of threat objects found.
   */
  const scanTextForPatterns = (text, source) => {
    const threats = [];

    if (!text || text.length < 10) return threats;

    for (const pattern of INJECTION_PATTERNS) {
      if (pattern.regex.test(text)) {
        threats.push({
          severity: pattern.severity,
          category: pattern.category,
          description: pattern.description,
          detail: `${pattern.detail} Found in ${source}.`,
          element: null
        });
      }
    }

    // Check for base64-encoded content
    const base64Result = checkBase64Content(text);
    if (base64Result) {
      if (base64Result.matchedPattern) {
        threats.push({
          severity: 'critical',
          category: 'prompt_injection',
          description: 'This page hides attack instructions inside encoded text.',
          detail: `Base64-encoded injection found in ${source}. Decoded content matches: ${base64Result.matchedPattern.detail}`,
          element: null
        });
      } else {
        threats.push({
          severity: 'low',
          category: 'prompt_injection',
          description: 'This page contains encoded text that could hide instructions.',
          detail: `Suspicious base64-encoded content found in ${source}. Preview: "${base64Result.decoded.substring(0, 100)}..."`,
          element: null
        });
      }
    }

    return threats;
  };

  /**
   * Scans visible page content for injection patterns.
   * @returns {Array} Array of threat objects.
   */
  const scanVisibleContent = () => {
    const bodyText = document.body ? document.body.innerText : '';
    return scanTextForPatterns(bodyText, 'visible page content');
  };

  /**
   * Scans all DOM elements for hidden text containing injection payloads.
   * @returns {Array} Array of threat objects.
   */
  const scanHiddenText = () => {
    const threats = [];
    if (!document.body) return threats;

    const skipTags = new Set(['SCRIPT', 'STYLE', 'NOSCRIPT', 'BR', 'HR', 'IMG', 'INPUT', 'SVG', 'PATH', 'CANVAS', 'VIDEO', 'AUDIO', 'IFRAME']);
    const walker = document.createTreeWalker(
      document.body,
      NodeFilter.SHOW_ELEMENT,
      {
        acceptNode: (node) => {
          if (skipTags.has(node.tagName)) return NodeFilter.FILTER_REJECT;
          return NodeFilter.FILTER_ACCEPT;
        }
      }
    );

    let node;
    const checkedTexts = new Set();

    while ((node = walker.nextNode())) {
      if (!isElementHidden(node)) continue;

      const text = node.innerText || node.textContent || '';
      const trimmed = text.trim();

      if (trimmed.length < 10) continue;

      // Avoid duplicate checks for nested hidden elements
      const textKey = trimmed.substring(0, 100);
      if (checkedTexts.has(textKey)) continue;
      checkedTexts.add(textKey);

      // Check hidden text against injection patterns
      const patternThreats = scanTextForPatterns(trimmed, 'hidden text on page');

      if (patternThreats.length > 0) {
        // Hidden text WITH injection patterns = CRITICAL
        for (const threat of patternThreats) {
          threats.push({
            severity: 'critical',
            category: 'hidden_text',
            description: 'Hidden text on this page contains instructions designed to manipulate AI assistants. This is a serious threat.',
            detail: `${threat.detail} The text was hidden using CSS, making it invisible to you but readable by AI assistants.`,
            element: node
          });
        }
      } else if (trimmed.length > 100) {
        // Large hidden text without patterns = LOW (informational)
        threats.push({
          severity: 'low',
          category: 'hidden_text',
          description: 'This page has a large block of hidden text. It may be harmless, but hidden text can sometimes contain instructions for AI.',
          detail: `Hidden text block (${trimmed.length} characters) found. Preview: "${trimmed.substring(0, 150)}..."`,
          element: node
        });
      }
    }

    return threats;
  };

  /**
   * Scans HTML comments for injection content.
   * @returns {Array} Array of threat objects.
   */
  const scanComments = () => {
    const threats = [];
    if (!document.body) return threats;

    const walker = document.createTreeWalker(
      document.documentElement,
      NodeFilter.SHOW_COMMENT
    );

    let node;
    while ((node = walker.nextNode())) {
      const text = node.textContent || '';
      if (text.trim().length < 10) continue;

      const commentThreats = scanTextForPatterns(text, 'HTML comment');
      for (const threat of commentThreats) {
        threat.detail += ' Injection instructions were hidden inside an HTML comment, invisible to users but readable by AI assistants.';
        threats.push(threat);
      }
    }

    return threats;
  };

  /**
   * Scans meta tags, data attributes, aria labels, and form fields.
   * @returns {Array} Array of threat objects.
   */
  const scanMetadata = () => {
    const threats = [];

    // Scan meta tags
    const metaTags = document.querySelectorAll('meta[content]');
    for (const meta of metaTags) {
      const content = meta.getAttribute('content') || '';
      if (content.length < 10) continue;
      const metaThreats = scanTextForPatterns(content, `<meta> tag (name="${meta.getAttribute('name') || meta.getAttribute('property') || 'unknown'}")`);
      threats.push(...metaThreats);
    }

    // Scan data attributes and aria labels (sample — full scan too expensive)
    const elements = document.querySelectorAll('[data-instructions], [data-prompt], [data-system], [data-ai], [aria-label]');
    for (const el of elements) {
      for (const attr of el.attributes) {
        if (!attr.name.startsWith('data-') && attr.name !== 'aria-label') continue;
        const val = attr.value || '';
        if (val.length < 10) continue;
        const attrThreats = scanTextForPatterns(val, `${attr.name} attribute`);
        threats.push(...attrThreats);
      }
    }

    // Scan hidden form fields
    const hiddenInputs = document.querySelectorAll('input[type="hidden"]');
    for (const input of hiddenInputs) {
      const val = input.value || '';
      if (val.length < 10) continue;
      const inputThreats = scanTextForPatterns(val, 'hidden form field');
      threats.push(...inputThreats);
    }

    return threats;
  };

  /**
   * Detects fake AI chat interfaces on non-legitimate AI domains.
   * @param {string} hostname - Current page hostname.
   * @returns {Array} Array of threat objects.
   */
  const scanFakeAIInterfaces = (hostname) => {
    const threats = [];

    if (isLegitimateAIDomain(hostname)) return threats;

    // Look for chat-like containers
    const allElements = document.querySelectorAll('[class], [id]');
    let chatElementsFound = false;
    let brandMentioned = false;
    let matchedBrand = null;

    for (const el of allElements) {
      const classAndId = (el.className || '') + ' ' + (el.id || '');
      if (typeof classAndId !== 'string') continue;

      if (CHAT_INTERFACE_PATTERNS.test(classAndId)) {
        chatElementsFound = true;

        // Check the text content of this element and nearby elements for AI brand names
        const text = el.innerText || el.textContent || '';
        const brandMatch = text.match(AI_BRAND_PATTERNS);
        if (brandMatch) {
          brandMentioned = true;
          matchedBrand = brandMatch[0];
          break;
        }
      }
    }

    if (chatElementsFound && brandMentioned) {
      threats.push({
        severity: 'high',
        category: 'fake_ai_interface',
        description: `This page appears to impersonate ${matchedBrand}. This is NOT the real ${matchedBrand} — it could be a scam designed to steal your information.`,
        detail: `Chat-like interface referencing "${matchedBrand}" detected on ${hostname}, which is not an official AI service domain.`,
        element: null
      });
    }

    return threats;
  };

  // =========================================================================
  // DEDUPLICATION
  // =========================================================================

  /**
   * Removes duplicate threats based on category + description.
   * Keeps the highest severity instance of each duplicate.
   * @param {Array} threats - Array of threat objects.
   * @returns {Array} Deduplicated array.
   */
  const deduplicateThreats = (threats) => {
    const seen = new Map();
    const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };

    for (const threat of threats) {
      const key = `${threat.category}:${threat.description}`;
      const existing = seen.get(key);

      if (!existing || severityOrder[threat.severity] > severityOrder[existing.severity]) {
        seen.set(key, threat);
      }
    }

    return Array.from(seen.values());
  };

  // =========================================================================
  // MAIN SCAN FUNCTION
  // =========================================================================

  /**
   * Filters threats based on sensitivity level.
   * - high: show all threats (critical, high, medium, low)
   * - medium: show critical, high, and medium only
   * - low: show critical and high only
   * @param {Array} threats - Array of threat objects.
   * @param {string} sensitivity - 'high', 'medium', or 'low'.
   * @returns {Array} Filtered threats.
   */
  const filterBySensitivity = (threats, sensitivity) => {
    if (sensitivity === 'high') return threats;

    const minSeverity = sensitivity === 'low'
      ? { critical: true, high: true }
      : { critical: true, high: true, medium: true };

    return threats.filter(t => minSeverity[t.severity]);
  };

  /**
   * Reduces severity for threats found on educational/research domains.
   * Content on security blogs and AI documentation sites is informational,
   * not malicious — users should know it's there but not be alarmed.
   * @param {Array} threats - Array of threat objects.
   * @param {string} hostname - Current page hostname.
   * @returns {Array} Adjusted threats.
   */
  const adjustForContext = (threats, hostname) => {
    if (!isEducationalDomain(hostname)) return threats;

    return threats.map(t => {
      // Don't reduce hidden text injections even on educational sites —
      // those are always suspicious regardless of domain
      if (t.category === 'hidden_text' && t.severity === 'critical') return t;

      // Downgrade visible pattern matches on educational domains
      const adjusted = Object.assign({}, t);
      if (adjusted.severity === 'critical') adjusted.severity = 'high';
      else if (adjusted.severity === 'high') adjusted.severity = 'medium';

      adjusted.detail += ' (Severity reduced: this appears to be an educational or research context.)';
      return adjusted;
    });
  };

  /**
   * Performs a full scan of the current page for AI-specific threats.
   * @param {object} [options] - Scan options.
   * @param {string} [options.sensitivity='medium'] - Detection sensitivity level.
   * @returns {object} Scan result object with status, threats, stats, url, hostname, timestamp.
   */
  const scan = (options) => {
    const sensitivity = (options && options.sensitivity) || 'medium';
    const startTime = performance.now();
    const url = window.location.href;
    const hostname = window.location.hostname;

    let allThreats = [];

    try {
      // Run all detection modules
      allThreats = allThreats.concat(scanVisibleContent());
      allThreats = allThreats.concat(scanHiddenText());
      allThreats = allThreats.concat(scanComments());
      allThreats = allThreats.concat(scanMetadata());
      allThreats = allThreats.concat(scanFakeAIInterfaces(hostname));
    } catch (e) {
      console.error('[AI Shield] Scan error:', e);
    }

    // Deduplicate
    allThreats = deduplicateThreats(allThreats);

    // Adjust severity for educational/research domains
    allThreats = adjustForContext(allThreats, hostname);

    // Filter by sensitivity level
    allThreats = filterBySensitivity(allThreats, sensitivity);

    // Sort by severity (critical first)
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    allThreats.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

    // Calculate stats
    const stats = {
      totalThreats: allThreats.length,
      critical: allThreats.filter(t => t.severity === 'critical').length,
      high: allThreats.filter(t => t.severity === 'high').length,
      medium: allThreats.filter(t => t.severity === 'medium').length,
      low: allThreats.filter(t => t.severity === 'low').length,
      scanTimeMs: Math.round(performance.now() - startTime)
    };

    // Determine overall status
    let status = 'safe';
    if (stats.critical > 0) {
      status = 'danger';
    } else if (stats.high > 0) {
      status = 'warning';
    } else if (stats.medium > 0) {
      status = 'caution';
    } else if (stats.low > 0) {
      status = 'caution';
    }

    // Strip DOM element references for serialization (can't send through messaging)
    const serializableThreats = allThreats.map(t => ({
      severity: t.severity,
      category: t.category,
      description: t.description,
      detail: t.detail
    }));

    const result = {
      status,
      threats: serializableThreats,
      stats,
      url,
      hostname,
      timestamp: Date.now()
    };

    console.log(`[AI Shield] Scan complete: ${status} (${stats.totalThreats} threats found in ${stats.scanTimeMs}ms)`);

    return result;
  };

  // Public API
  return { scan };
})();
