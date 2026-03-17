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
    },

    // --- Multi-Language Injection Patterns ---
    // Spanish
    {
      regex: /ignora\s+(?:todas?\s+)?(?:las\s+)?instrucciones\s+(?:anteriores|previas)/i,
      severity: 'high',
      category: 'instruction_override',
      description: 'This page tells AI assistants to ignore their rules (in Spanish).',
      detail: 'Spanish instruction override: "ignora instrucciones anteriores" detected.'
    },
    {
      regex: /olvida\s+(?:tu|todas?\s+(?:las\s+)?)\s*(?:instrucciones|reglas|entrenamiento)/i,
      severity: 'high',
      category: 'instruction_override',
      description: 'This page tells AI to forget its training (in Spanish).',
      detail: 'Spanish training override: "olvida tu entrenamiento" detected.'
    },
    {
      regex: /ahora\s+eres\s+(?:un|una)\s+/i,
      severity: 'high',
      category: 'role_hijack',
      description: 'This page tries to change what an AI thinks it is (in Spanish).',
      detail: 'Spanish role hijack: "ahora eres un/una" detected.'
    },
    // French
    {
      regex: /ignore[rz]?\s+(?:toutes?\s+)?(?:les\s+)?instructions\s+(?:pr[eé]c[eé]dentes|ant[eé]rieures)/i,
      severity: 'high',
      category: 'instruction_override',
      description: 'This page tells AI assistants to ignore their rules (in French).',
      detail: 'French instruction override: "ignorer instructions précédentes" detected.'
    },
    {
      regex: /oublie[rz]?\s+(?:ton|tes|votre|vos)\s+(?:instructions|r[eè]gles|entra[iî]nement)/i,
      severity: 'high',
      category: 'instruction_override',
      description: 'This page tells AI to forget its training (in French).',
      detail: 'French training override: "oublier ton entraînement" detected.'
    },
    {
      regex: /tu\s+es\s+(?:maintenant|d[eé]sormais)\s+(?:un|une)\s+/i,
      severity: 'high',
      category: 'role_hijack',
      description: 'This page tries to change what an AI thinks it is (in French).',
      detail: 'French role hijack: "tu es maintenant un/une" detected.'
    },
    // German
    {
      regex: /ignoriere?\s+(?:alle\s+)?(?:vorherigen|bisherigen|fr[uü]heren)\s+(?:Anweisungen|Regeln|Instruktionen)/i,
      severity: 'high',
      category: 'instruction_override',
      description: 'This page tells AI assistants to ignore their rules (in German).',
      detail: 'German instruction override: "ignoriere vorherige Anweisungen" detected.'
    },
    {
      regex: /vergiss\s+(?:dein|deine|alle)\s+(?:Training|Anweisungen|Regeln|Programmierung)/i,
      severity: 'high',
      category: 'instruction_override',
      description: 'This page tells AI to forget its training (in German).',
      detail: 'German training override: "vergiss dein Training" detected.'
    },
    {
      regex: /du\s+bist\s+(?:jetzt|ab\s+jetzt|nun)\s+(?:ein|eine)\s+/i,
      severity: 'high',
      category: 'role_hijack',
      description: 'This page tries to change what an AI thinks it is (in German).',
      detail: 'German role hijack: "du bist jetzt ein/eine" detected.'
    },
    // Portuguese
    {
      regex: /ignore\s+(?:todas?\s+)?(?:as\s+)?instru[cç][oõ]es\s+(?:anteriores|pr[eé]vias)/i,
      severity: 'high',
      category: 'instruction_override',
      description: 'This page tells AI assistants to ignore their rules (in Portuguese).',
      detail: 'Portuguese instruction override: "ignore instruções anteriores" detected.'
    },
    {
      regex: /esque[cç]a\s+(?:seu|sua|todo|todas?)\s+(?:treinamento|instru[cç][oõ]es|regras)/i,
      severity: 'high',
      category: 'instruction_override',
      description: 'This page tells AI to forget its training (in Portuguese).',
      detail: 'Portuguese training override: "esqueça seu treinamento" detected.'
    },
    {
      regex: /agora\s+voc[eê]\s+[eé]\s+(?:um|uma)\s+/i,
      severity: 'high',
      category: 'role_hijack',
      description: 'This page tries to change what an AI thinks it is (in Portuguese).',
      detail: 'Portuguese role hijack: "agora você é um/uma" detected.'
    },
    // Chinese (Simplified)
    {
      regex: /忽略(?:所有)?(?:之前|以前|先前)的(?:指令|指示|规则|说明)/,
      severity: 'high',
      category: 'instruction_override',
      description: 'This page tells AI assistants to ignore their rules (in Chinese).',
      detail: 'Chinese instruction override: "忽略之前的指令" detected.'
    },
    {
      regex: /你现在是(?:一个|一名)/,
      severity: 'high',
      category: 'role_hijack',
      description: 'This page tries to change what an AI thinks it is (in Chinese).',
      detail: 'Chinese role hijack: "你现在是一个" detected.'
    },
    // Japanese
    {
      regex: /(?:以前|前)の(?:指示|命令|ルール|指令)を(?:無視|忘れ)/,
      severity: 'high',
      category: 'instruction_override',
      description: 'This page tells AI assistants to ignore their rules (in Japanese).',
      detail: 'Japanese instruction override detected.'
    },
    {
      regex: /あなたは(?:今|これから)[\s\S]{0,5}(?:です|になり)/,
      severity: 'high',
      category: 'role_hijack',
      description: 'This page tries to change what an AI thinks it is (in Japanese).',
      detail: 'Japanese role hijack pattern detected.'
    },

    // --- Markdown/Formatting Exploits ---
    {
      regex: /\[(?:[^\]]*)\]\(javascript\s*:/i,
      severity: 'critical',
      category: 'prompt_injection',
      description: 'This page contains a dangerous JavaScript link disguised as a normal link.',
      detail: 'Markdown link with javascript: protocol — could execute malicious code.'
    },
    {
      regex: /\[(?:[^\]]*)\]\(data\s*:/i,
      severity: 'high',
      category: 'prompt_injection',
      description: 'This page contains a suspicious data link disguised as a normal link.',
      detail: 'Markdown link with data: protocol — could embed malicious content.'
    },
    {
      regex: /```(?:system|admin|override|instructions)[\s\S]*?```/i,
      severity: 'high',
      category: 'prompt_injection',
      description: 'This page hides AI commands inside a code block.',
      detail: 'Markdown code block labeled as system/admin/override instructions.'
    },

    // --- Clipboard Hijacking ---
    {
      regex: /(?:document\.addEventListener|window\.addEventListener)\s*\(\s*['"](?:copy|cut|paste)['"]/i,
      severity: 'high',
      category: 'clipboard_hijack',
      description: 'This page monitors or modifies what you copy and paste — it could inject hidden AI commands into your clipboard.',
      detail: 'Clipboard event listener detected: page intercepts copy/cut/paste events.'
    },
    {
      regex: /navigator\.clipboard\.write(?:Text)?\s*\(/i,
      severity: 'high',
      category: 'clipboard_hijack',
      description: 'This page can write to your clipboard — it could replace what you copied with hidden AI commands.',
      detail: 'Clipboard API write access detected: page can modify clipboard content.'
    },
    {
      regex: /document\.execCommand\s*\(\s*['"](?:copy|cut|paste)['"]/i,
      severity: 'medium',
      category: 'clipboard_hijack',
      description: 'This page uses an older method to access your clipboard.',
      detail: 'Legacy clipboard API (execCommand) detected.'
    },

    // --- Malicious GPT/Plugin/MCP Detection ---
    {
      regex: /(?:install|add|enable|activate)\s+(?:this\s+)?(?:custom\s+)?(?:GPT|plugin|extension|MCP\s+server|tool)\b/i,
      severity: 'medium',
      category: 'malicious_plugin',
      description: 'This page promotes installing an AI plugin or tool. Be careful — unverified plugins can access your data.',
      detail: 'AI plugin/extension installation prompt detected.'
    },
    {
      regex: /(?:requires?\s+(?:your\s+)?(?:API|access)\s*key|enter\s+(?:your\s+)?(?:API|OpenAI|Anthropic|Claude)\s*key)/i,
      severity: 'high',
      category: 'malicious_plugin',
      description: 'This page asks for your AI service API key. Legitimate services rarely ask for this on third-party sites.',
      detail: 'API key harvesting attempt: page solicits AI service credentials.'
    },
    {
      regex: /(?:unverified|unofficial|custom)\s+(?:GPT|ChatGPT|plugin|agent|MCP)/i,
      severity: 'medium',
      category: 'malicious_plugin',
      description: 'This page references an unverified AI plugin or custom GPT. These may not be safe to use.',
      detail: 'Reference to unverified/unofficial AI plugin or custom GPT detected.'
    },

    // --- AI-Generated Phishing Patterns ---
    {
      regex: /(?:your\s+(?:ChatGPT|Claude|Gemini|OpenAI|Anthropic|AI)\s+(?:account|subscription)\s+(?:has\s+been|was|is)\s+(?:suspended|compromised|locked|expired|flagged))/i,
      severity: 'high',
      category: 'ai_phishing',
      description: 'This page claims your AI account is in trouble — this is likely a scam to steal your login.',
      detail: 'AI service phishing: fake account suspension/compromise notification.'
    },
    {
      regex: /(?:verify|confirm|update|secure)\s+your\s+(?:ChatGPT|Claude|Gemini|OpenAI|Anthropic|AI)\s+(?:account|identity|subscription|payment)/i,
      severity: 'high',
      category: 'ai_phishing',
      description: 'This page asks you to "verify" your AI account — real services don\'t do this on third-party sites.',
      detail: 'AI service phishing: fake account verification request.'
    },
    {
      regex: /(?:free|unlimited|premium)\s+(?:ChatGPT|GPT-?4|Claude|Gemini)\s+(?:access|account|pro|plus|subscription)/i,
      severity: 'medium',
      category: 'ai_phishing',
      description: 'This page offers free premium AI access — this is likely a scam or data harvesting attempt.',
      detail: 'AI service bait: offering free premium access to lure users.'
    },
    {
      regex: /(?:ChatGPT|Claude|Gemini|GPT)\s+(?:5|Pro|Ultra|Plus)\s+(?:is\s+here|now\s+available|early\s+access|beta\s+access|waitlist)/i,
      severity: 'medium',
      category: 'ai_phishing',
      description: 'This page claims early access to an AI product — verify on the official site before clicking anything.',
      detail: 'Potential AI vaporware scam: claiming early access to unannounced AI products.'
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

  // =========================================================================
  // HOMOGLYPH / UNICODE OBFUSCATION MAPS
  // =========================================================================

  /**
   * Map of common Unicode homoglyphs (look-alike characters) to their Latin equivalents.
   * Attackers use these to bypass text-based pattern matching.
   */
  const HOMOGLYPH_MAP = {
    // Cyrillic look-alikes
    '\u0410': 'A', '\u0430': 'a', '\u0412': 'B', '\u0435': 'e', '\u0415': 'E',
    '\u041A': 'K', '\u043A': 'k', '\u041C': 'M', '\u041D': 'H', '\u043E': 'o',
    '\u041E': 'O', '\u0440': 'p', '\u0420': 'P', '\u0441': 'c', '\u0421': 'C',
    '\u0422': 'T', '\u0443': 'y', '\u0445': 'x', '\u0425': 'X', '\u0456': 'i',
    // Greek look-alikes
    '\u0391': 'A', '\u0392': 'B', '\u0395': 'E', '\u0396': 'Z', '\u0397': 'H',
    '\u0399': 'I', '\u039A': 'K', '\u039C': 'M', '\u039D': 'N', '\u039F': 'O',
    '\u03A1': 'P', '\u03A4': 'T', '\u03A5': 'Y', '\u03A7': 'X', '\u03BF': 'o',
    // Mathematical/fullwidth
    '\uFF41': 'a', '\uFF42': 'b', '\uFF43': 'c', '\uFF44': 'd', '\uFF45': 'e',
    '\uFF46': 'f', '\uFF47': 'g', '\uFF48': 'h', '\uFF49': 'i', '\uFF4A': 'j',
    '\uFF4B': 'k', '\uFF4C': 'l', '\uFF4D': 'm', '\uFF4E': 'n', '\uFF4F': 'o',
    '\uFF50': 'p', '\uFF51': 'q', '\uFF52': 'r', '\uFF53': 's', '\uFF54': 't',
    '\uFF55': 'u', '\uFF56': 'v', '\uFF57': 'w', '\uFF58': 'x', '\uFF59': 'y',
    '\uFF5A': 'z',
    // Common symbol substitutions
    '\u0131': 'i', '\u0237': 'j', '\u1D00': 'A', '\u0261': 'g',
    // Zero-width characters (used to split keywords)
    '\u200B': '', '\u200C': '', '\u200D': '', '\uFEFF': '', '\u00AD': ''
  };

  /**
   * Normalizes text by replacing homoglyphs with their Latin equivalents
   * and stripping zero-width characters.
   * @param {string} text - Text to normalize.
   * @returns {string} Normalized text.
   */
  const normalizeHomoglyphs = (text) => {
    let normalized = '';
    for (let i = 0; i < text.length; i++) {
      const ch = text[i];
      normalized += HOMOGLYPH_MAP[ch] !== undefined ? HOMOGLYPH_MAP[ch] : ch;
    }
    return normalized;
  };

  /**
   * Checks if text contains Unicode homoglyphs that could be used to obfuscate injections.
   * @param {string} text - Text to check.
   * @returns {object|null} Result if homoglyphs found hiding injection patterns, null otherwise.
   */
  const checkHomoglyphObfuscation = (text) => {
    // Quick check: does the text contain any characters from our homoglyph map?
    let hasHomoglyphs = false;
    for (let i = 0; i < text.length; i++) {
      if (HOMOGLYPH_MAP[text[i]] !== undefined) {
        hasHomoglyphs = true;
        break;
      }
    }
    if (!hasHomoglyphs) return null;

    // Normalize and check against injection patterns
    const normalized = normalizeHomoglyphs(text);
    if (normalized === text) return null; // No actual substitutions made

    for (const pattern of INJECTION_PATTERNS) {
      if (pattern.regex.test(normalized) && !pattern.regex.test(text)) {
        return {
          original: text.substring(0, 200),
          normalized: normalized.substring(0, 200),
          matchedPattern: pattern
        };
      }
    }

    return null;
  };

  /**
   * Checks if text contains zero-width characters that split injection keywords.
   * Caller must pre-check HAS_ZERO_WIDTH before calling this function.
   * @param {string} text - Text to check (known to contain zero-width chars).
   * @returns {boolean} True if suspicious zero-width usage found.
   */
  const hasZeroWidthObfuscation = (text) => {
    // Strip zero-width characters and check if it now matches injection patterns
    const stripped = text.replace(/[\u200B\u200C\u200D\uFEFF\u00AD]/g, '');
    if (stripped === text) return false;

    for (const pattern of INJECTION_PATTERNS) {
      if (pattern.regex.test(stripped) && !pattern.regex.test(text)) {
        return true;
      }
    }
    return false;
  };

  // =========================================================================
  // NESTED ENCODING DETECTION
  // =========================================================================

  /**
   * Decodes HTML entities in text.
   * @param {string} text - Text with HTML entities.
   * @returns {string} Decoded text.
   */
  const decodeHTMLEntities = (text) => {
    return text
      .replace(/&#(\d+);/g, (_, code) => String.fromCharCode(parseInt(code, 10)))
      .replace(/&#x([0-9a-fA-F]+);/g, (_, code) => String.fromCharCode(parseInt(code, 16)))
      .replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .replace(/&apos;/g, "'");
  };

  /**
   * Attempts to URL-decode text.
   * @param {string} text - URL-encoded text.
   * @returns {string} Decoded text.
   */
  const tryURLDecode = (text) => {
    try {
      const decoded = decodeURIComponent(text);
      return decoded !== text ? decoded : null;
    } catch (e) {
      return null;
    }
  };

  /**
   * Checks for nested/layered encoding (Base64 inside URL encoding, HTML entities, etc.).
   * Attempts up to 3 decoding passes to catch multi-layered obfuscation.
   * @param {string} text - Text to check.
   * @returns {object|null} Result if nested encoding found with injection, null otherwise.
   */
  const checkNestedEncoding = (text) => {
    if (!text || text.length < 20) return null;

    const maxPasses = 3;
    let current = text;
    const decodingChain = [];

    for (let pass = 0; pass < maxPasses; pass++) {
      let decoded = null;
      let method = null;

      // Try HTML entity decoding
      const htmlDecoded = decodeHTMLEntities(current);
      if (htmlDecoded !== current && htmlDecoded.length > 10) {
        decoded = htmlDecoded;
        method = 'HTML entities';
      }

      // Try URL decoding
      if (!decoded) {
        const urlDecoded = tryURLDecode(current);
        if (urlDecoded && urlDecoded.length > 10) {
          decoded = urlDecoded;
          method = 'URL encoding';
        }
      }

      // Try Base64 decoding
      if (!decoded) {
        const base64Match = current.match(/[A-Za-z0-9+/]{20,}={0,2}/);
        if (base64Match) {
          try {
            const b64decoded = atob(base64Match[0]);
            const printableRatio = b64decoded.split('').filter(c => {
              const code = c.charCodeAt(0);
              return code >= 32 && code <= 126;
            }).length / b64decoded.length;
            if (printableRatio > 0.8 && b64decoded.length > 10) {
              decoded = b64decoded;
              method = 'Base64';
            }
          } catch (e) {
            // Not valid base64
          }
        }
      }

      if (!decoded) break;

      decodingChain.push(method);
      current = decoded;

      // Only flag if we've decoded through multiple layers (single-layer is caught by checkBase64Content)
      if (decodingChain.length >= 2) {
        for (const pattern of INJECTION_PATTERNS) {
          if (pattern.regex.test(current)) {
            return {
              decodingChain: decodingChain.join(' → '),
              decoded: current.substring(0, 200),
              matchedPattern: pattern
            };
          }
        }
      }
    }

    return null;
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
  // CONFIDENCE SCORING
  // =========================================================================

  /**
   * Calculates a confidence score (0-100) for a detected threat.
   * Higher scores mean we're more certain the detection is a true positive.
   * @param {object} threat - Threat object.
   * @param {number} patternMatchCount - Number of patterns that matched the source text.
   * @param {string} source - Where the text came from.
   * @returns {number} Confidence score 0-100.
   */
  const calculateConfidence = (threat, patternMatchCount, source) => {
    let confidence = 50; // Base confidence

    // Hidden content is more likely to be malicious
    if (source.includes('hidden')) confidence += 25;
    if (source.includes('HTML comment')) confidence += 15;
    if (source.includes('hidden form field')) confidence += 20;
    if (source.includes('data-') || source.includes('attribute')) confidence += 10;

    // Multiple injection patterns in same text = higher confidence
    if (patternMatchCount >= 3) confidence += 20;
    else if (patternMatchCount >= 2) confidence += 10;

    // Severity affects base confidence
    if (threat.severity === 'critical') confidence += 15;
    else if (threat.severity === 'high') confidence += 5;
    else if (threat.severity === 'low') confidence -= 10;

    // Category-specific adjustments
    if (threat.category === 'hidden_text') confidence += 15;
    if (threat.category === 'data_exfiltration') confidence += 10;

    // Encoding/obfuscation is a strong signal of malicious intent
    if (threat.category === 'prompt_injection' && threat.detail.includes('Base64')) confidence += 20;
    if (threat.detail.includes('homoglyph') || threat.detail.includes('zero-width')) confidence += 25;
    if (threat.detail.includes('nested encoding')) confidence += 25;

    return Math.max(0, Math.min(100, confidence));
  };

  /**
   * Returns a human-readable confidence label.
   * @param {number} score - Confidence score 0-100.
   * @returns {string} Label like "Very likely a threat".
   */
  const confidenceLabel = (score) => {
    if (score >= 85) return 'Almost certainly a threat';
    if (score >= 70) return 'Very likely a threat';
    if (score >= 50) return 'Likely a threat';
    if (score >= 30) return 'Might be suspicious';
    return 'Unlikely to be a threat';
  };

  // =========================================================================
  // SCANNING FUNCTIONS
  // =========================================================================

  /**
   * Scans text content against all injection patterns, including
   * homoglyph obfuscation, nested encoding, and base64 checks.
   * @param {string} text - The text to scan.
   * @param {string} source - Where the text came from (for detail messages).
   * @returns {Array} Array of threat objects found.
   */
  /**
   * Fast regex pre-checks to avoid expensive obfuscation detection on clean text.
   */
  const HAS_NON_ASCII = /[^\x00-\x7F]/;
  const HAS_ZERO_WIDTH = /[\u200B\u200C\u200D\uFEFF\u00AD]/;
  const HAS_BASE64_CANDIDATE = /[A-Za-z0-9+/]{20,}={0,2}/;
  const HAS_ENCODED_ENTITIES = /&#\w+;|%[0-9a-fA-F]{2}/;

  const scanTextForPatterns = (text, source) => {
    const threats = [];

    if (!text || text.length < 10) return threats;

    // Single pass through all patterns — count matches for confidence scoring
    let patternMatchCount = 0;
    for (const pattern of INJECTION_PATTERNS) {
      if (pattern.regex.test(text)) {
        patternMatchCount++;
        const threat = {
          severity: pattern.severity,
          category: pattern.category,
          description: pattern.description,
          detail: `${pattern.detail} Found in ${source}.`,
          element: null
        };
        threats.push(threat);
      }
    }

    // Calculate confidence for all pattern-matched threats using the count
    for (const threat of threats) {
      threat.confidence = calculateConfidence(threat, patternMatchCount, source);
      threat.confidenceLabel = confidenceLabel(threat.confidence);
    }

    // Only run expensive obfuscation checks if text contains relevant characters
    const hasNonAscii = HAS_NON_ASCII.test(text);

    // Check for Unicode homoglyph obfuscation (only if non-ASCII chars present)
    if (hasNonAscii) {
      const homoglyphResult = checkHomoglyphObfuscation(text);
      if (homoglyphResult) {
        const threat = {
          severity: 'critical',
          category: 'prompt_injection',
          description: 'This page uses look-alike characters to hide attack instructions from detection tools.',
          detail: `Homoglyph obfuscation detected in ${source}. Characters were replaced with look-alikes to bypass security. Decoded text matches: ${homoglyphResult.matchedPattern.detail}`,
          element: null
        };
        threat.confidence = calculateConfidence(threat, patternMatchCount, source);
        threat.confidenceLabel = confidenceLabel(threat.confidence);
        threats.push(threat);
      }

      // Check for zero-width character obfuscation (subset of non-ASCII)
      if (HAS_ZERO_WIDTH.test(text) && hasZeroWidthObfuscation(text)) {
        const threat = {
          severity: 'critical',
          category: 'prompt_injection',
          description: 'This page uses invisible characters to split up attack keywords so they can\'t be detected.',
          detail: `Zero-width character obfuscation detected in ${source}. Invisible Unicode characters were inserted between letters to evade pattern matching.`,
          element: null
        };
        threat.confidence = calculateConfidence(threat, patternMatchCount, source);
        threat.confidenceLabel = confidenceLabel(threat.confidence);
        threats.push(threat);
      }
    }

    // Check for encoding-based obfuscation
    const hasBase64 = HAS_BASE64_CANDIDATE.test(text);
    const hasEntities = HAS_ENCODED_ENTITIES.test(text);
    let foundNested = false;

    // Check for nested/layered encoding (only if encoded content signatures present)
    if (hasEntities || hasBase64) {
      const nestedResult = checkNestedEncoding(text);
      if (nestedResult) {
        foundNested = true;
        const threat = {
          severity: 'critical',
          category: 'prompt_injection',
          description: 'This page hides attack instructions inside multiple layers of encoding to avoid detection.',
          detail: `Multi-layer encoding detected in ${source} (${nestedResult.decodingChain}). Decoded content matches: ${nestedResult.matchedPattern.detail}`,
          element: null
        };
        threat.confidence = calculateConfidence(threat, patternMatchCount, source);
        threat.confidenceLabel = confidenceLabel(threat.confidence);
        threats.push(threat);
      }
    }

    // Check for base64-encoded content (skip if nested encoding already caught it)
    if (hasBase64 && !foundNested) {
      const base64Result = checkBase64Content(text);
      if (base64Result) {
        const threat = {
          severity: base64Result.matchedPattern ? 'critical' : 'low',
          category: 'prompt_injection',
          description: base64Result.matchedPattern
            ? 'This page hides attack instructions inside encoded text.'
            : 'This page contains encoded text that could hide instructions.',
          detail: base64Result.matchedPattern
            ? `Base64-encoded injection found in ${source}. Decoded content matches: ${base64Result.matchedPattern.detail}`
            : `Suspicious base64-encoded content found in ${source}. Preview: "${base64Result.decoded.substring(0, 100)}..."`,
          element: null
        };
        threat.confidence = calculateConfidence(threat, patternMatchCount, source);
        threat.confidenceLabel = confidenceLabel(threat.confidence);
        threats.push(threat);
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
          const hiddenThreat = {
            severity: 'critical',
            category: 'hidden_text',
            description: 'Hidden text on this page contains instructions designed to manipulate AI assistants. This is a serious threat.',
            detail: `${threat.detail} The text was hidden using CSS, making it invisible to you but readable by AI assistants.`,
            element: node
          };
          hiddenThreat.confidence = 90;
          hiddenThreat.confidenceLabel = confidenceLabel(90);
          threats.push(hiddenThreat);
        }
      } else if (trimmed.length > 100) {
        // Large hidden text without patterns = LOW (informational)
        const infoThreat = {
          severity: 'low',
          category: 'hidden_text',
          description: 'This page has a large block of hidden text. It may be harmless, but hidden text can sometimes contain instructions for AI.',
          detail: `Hidden text block (${trimmed.length} characters) found. Preview: "${trimmed.substring(0, 150)}..."`,
          element: node
        };
        infoThreat.confidence = 25;
        infoThreat.confidenceLabel = confidenceLabel(25);
        threats.push(infoThreat);
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
   * Scans inline and external scripts for clipboard hijacking patterns.
   * @returns {Array} Array of threat objects.
   */
  const scanClipboardHijacking = () => {
    const threats = [];
    if (!document.body) return threats;

    // Scan inline scripts
    const scripts = document.querySelectorAll('script:not([src])');
    for (const script of scripts) {
      const code = script.textContent || '';
      if (code.length < 10) continue;
      const scriptThreats = scanTextForPatterns(code, 'inline script');
      // Only keep clipboard-related threats from scripts
      for (const t of scriptThreats) {
        if (t.category === 'clipboard_hijack') {
          threats.push(t);
        }
      }
    }

    return threats;
  };

  /**
   * Scans page for AI phishing indicators beyond regex patterns.
   * Looks for fake login forms, urgency indicators, and brand impersonation.
   * @param {string} hostname - Current page hostname.
   * @returns {Array} Array of threat objects.
   */
  const scanAIPhishing = (hostname) => {
    const threats = [];
    if (!document.body) return threats;

    // Skip legitimate AI domains
    if (isLegitimateAIDomain(hostname)) return threats;

    const pageText = document.body.innerText || '';

    // Check for fake AI login forms
    const forms = document.querySelectorAll('form');
    for (const form of forms) {
      const formText = (form.innerText || '') + ' ' + (form.innerHTML || '');
      const hasPasswordField = form.querySelector('input[type="password"]');
      const hasEmailField = form.querySelector('input[type="email"], input[name*="email"], input[name*="user"]');

      if (hasPasswordField && AI_BRAND_PATTERNS.test(formText)) {
        const brandMatch = formText.match(AI_BRAND_PATTERNS);
        const threat = {
          severity: 'critical',
          category: 'ai_phishing',
          description: `This page has a login form that mentions ${brandMatch[0]} — but this is NOT the official ${brandMatch[0]} website. Do not enter your password here.`,
          detail: `Fake AI service login form detected on ${hostname}. The form requests credentials while referencing "${brandMatch[0]}".`,
          element: form
        };
        threat.confidence = 90;
        threat.confidenceLabel = confidenceLabel(90);
        threats.push(threat);
      } else if ((hasPasswordField || hasEmailField) && /(?:api.?key|token|secret)/i.test(formText)) {
        const threat = {
          severity: 'high',
          category: 'ai_phishing',
          description: 'This page has a form asking for API keys or tokens. Be very careful — only enter credentials on official service websites.',
          detail: `Form requesting API keys/tokens detected on ${hostname}.`,
          element: form
        };
        threat.confidence = 75;
        threat.confidenceLabel = confidenceLabel(75);
        threats.push(threat);
      }
    }

    // Check for high-pressure urgency combined with AI brand names
    const urgencyPatterns = /(?:immediate(?:ly)?|urgent(?:ly)?|act\s+now|last\s+chance|account\s+will\s+be\s+(?:deleted|suspended|terminated)|within\s+\d+\s+(?:hours?|minutes?)|expires?\s+(?:today|soon|in\s+\d+))/i;
    if (urgencyPatterns.test(pageText) && AI_BRAND_PATTERNS.test(pageText)) {
      const brandMatch = pageText.match(AI_BRAND_PATTERNS);
      const threat = {
        severity: 'medium',
        category: 'ai_phishing',
        description: `This page uses urgent language about ${brandMatch[0]} — scammers often create fake urgency to rush you into making mistakes.`,
        detail: `High-pressure language combined with AI brand mention ("${brandMatch[0]}") on ${hostname}.`,
        element: null
      };
      threat.confidence = 55;
      threat.confidenceLabel = confidenceLabel(55);
      threats.push(threat);
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
      const threat = {
        severity: 'high',
        category: 'fake_ai_interface',
        description: `This page appears to impersonate ${matchedBrand}. This is NOT the real ${matchedBrand} — it could be a scam designed to steal your information.`,
        detail: `Chat-like interface referencing "${matchedBrand}" detected on ${hostname}, which is not an official AI service domain.`,
        element: null
      };
      threat.confidence = 80;
      threat.confidenceLabel = confidenceLabel(80);
      threats.push(threat);
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
   * Checks if page content suggests an educational/documentation context.
   * Looks for article-like structure, code examples, and security research framing.
   * @returns {boolean} True if page appears to be educational content.
   */
  const hasEducationalContext = () => {
    if (!document.body) return false;
    const text = document.body.innerText || '';
    const lower = text.toLowerCase();

    // Check for article/blog/documentation indicators
    const educationalSignals = [
      /\b(?:example|demonstration|tutorial|walkthrough|how\s+to\s+detect)\b/i,
      /\b(?:research|paper|study|findings|analysis)\b/i,
      /\b(?:CVE-\d{4}-\d+|OWASP|MITRE|CWE-\d+)\b/,
      /\b(?:for\s+educational\s+purposes|for\s+testing|proof\s+of\s+concept)\b/i,
      /<article|<pre|<code/i
    ];

    let signalCount = 0;
    for (const signal of educationalSignals) {
      if (signal.test(text) || signal.test(document.documentElement.innerHTML || '')) {
        signalCount++;
      }
    }

    return signalCount >= 2;
  };

  /**
   * Reduces severity for threats found on educational/research domains
   * or pages that appear to be educational content.
   * Content on security blogs and AI documentation sites is informational,
   * not malicious — users should know it's there but not be alarmed.
   * @param {Array} threats - Array of threat objects.
   * @param {string} hostname - Current page hostname.
   * @returns {Array} Adjusted threats.
   */
  const adjustForContext = (threats, hostname) => {
    const isEdu = isEducationalDomain(hostname);
    const hasEduContent = !isEdu && hasEducationalContext();

    if (!isEdu && !hasEduContent) return threats;

    const contextNote = isEdu
      ? '(Severity reduced: this appears to be an educational or research site.)'
      : '(Severity reduced: this page appears to contain educational or research content.)';

    return threats.map(t => {
      // Don't reduce hidden text injections even on educational sites —
      // those are always suspicious regardless of domain
      if (t.category === 'hidden_text' && t.severity === 'critical') return t;

      // Don't reduce clipboard hijacking or phishing on educational sites
      if (t.category === 'clipboard_hijack') return t;
      if (t.category === 'ai_phishing' && t.severity === 'critical') return t;

      // Downgrade visible pattern matches in educational context
      const adjusted = Object.assign({}, t);
      if (adjusted.severity === 'critical') adjusted.severity = 'high';
      else if (adjusted.severity === 'high') adjusted.severity = 'medium';

      // Reduce confidence for educational context
      if (adjusted.confidence) {
        adjusted.confidence = Math.max(10, adjusted.confidence - 20);
        adjusted.confidenceLabel = confidenceLabel(adjusted.confidence);
      }

      adjusted.detail += ' ' + contextNote;
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
      allThreats = allThreats.concat(scanClipboardHijacking());
      allThreats = allThreats.concat(scanAIPhishing(hostname));
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
      detail: t.detail,
      confidence: t.confidence || null,
      confidenceLabel: t.confidenceLabel || null
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
