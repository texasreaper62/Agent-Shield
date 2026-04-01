'use strict';

/**
 * Agent Shield — Core Detection Engine
 *
 * Standalone threat detection for AI agents. Scans text inputs and outputs
 * for prompt injection, data exfiltration, role hijacking, and other
 * AI-specific attacks.
 *
 * Works in Node.js, Deno, Bun, and browsers. No DOM dependencies.
 * All detection runs locally — no data ever leaves your environment.
 */

// =========================================================================
// PERFORMANCE
// =========================================================================

/** Default scan time budget in ms. */
const DEFAULT_SCAN_TIME_BUDGET_MS = 200;

/** Maximum input size in characters (1MB of UTF-16). */
const MAX_INPUT_SIZE = 1_000_000;

/**
 * Get current time in ms. Works in Node.js and browsers.
 * @returns {number}
 */
const now = () => {
  if (typeof performance !== 'undefined' && performance.now) {
    return performance.now();
  }
  return Date.now();
};

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
    regex: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|rules|guidelines|prompts|context|directions|directives|text|commands)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text tells AI assistants to ignore their safety rules.',
    detail: 'Instruction override pattern: attempts to nullify prior AI instructions.'
  },
  {
    regex: /^ignore\s+(?:the\s+)?(?:instructions|rules|guidelines|directives|commands)$/im,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text tells AI assistants to ignore instructions.',
    detail: 'Simple instruction override: direct command to ignore instructions.'
  },
  {
    regex: /disregard\s+(all\s+)?(previous|prior|above|earlier|your)\s+(instructions|rules|guidelines|prompts|training|training\s+data|context)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text tells AI assistants to throw out their rules.',
    detail: 'Instruction disregard pattern: attempts to nullify prior AI instructions.'
  },
  {
    regex: /forget\s+(your|all|any|everything)\s+(training|instructions|rules|guidelines|programming|above|previous|prior)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text tries to make AI assistants forget their training.',
    detail: 'Training override pattern: attempts to reset AI behavioral constraints.'
  },
  {
    regex: /override\s+(?:all\s+)?(?:system|safety|security)\s+(?:settings|prompt|instructions|rules|mechanisms|filters|checks|protocols)/i,
    severity: 'critical',
    category: 'instruction_override',
    description: 'Text tries to override AI safety settings.',
    detail: 'System override pattern: direct attempt to bypass AI safety mechanisms.'
  },
  {
    regex: /(?:^|\n)\s*(?:new|updated|revised|replacement)\s+(?:instructions|policy)\s*:/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text contains fake "new instructions" for AI assistants.',
    detail: 'Instruction replacement pattern: attempts to inject new behavioral directives.'
  },
  {
    regex: /#{2,}\s*(?:NEW|UPDATED|REVISED|REPLACEMENT)\s+(?:INSTRUCTIONS|RULES|DIRECTIVES|POLICY)\s*#{0,}/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text uses markdown headers to inject fake new instructions.',
    detail: 'Markdown instruction injection: uses heading syntax to inject new behavioral directives.'
  },
  {
    regex: /(?:^|\n)\s*(?:SYSTEM|ADMIN|ROOT)\s*:\s*.{10,}/i,
    severity: 'high',
    category: 'prompt_injection',
    description: 'Text contains a fake SYSTEM/ADMIN directive.',
    detail: 'Unbracketed system directive: uses SYSTEM: prefix to inject instructions.'
  },
  {
    regex: /(?:you\s+must\s+)?ignore\s+(?:your|all\s+your|all\s+the|the)\s+(?:safety\s+)?(?:guidelines?|rules?|restrictions?|protocols?|safeguards?|filters?|limits?)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text tells AI to ignore its guidelines or safety rules.',
    detail: 'Guideline override: direct instruction to ignore safety guidelines.'
  },
  {
    regex: /(?:abandon|drop|ditch|clear)\s+(?:all\s+)?(?:prior|previous|above|earlier|initial)\s+(?:context|instructions|rules|constraints|guidelines)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text tells AI to abandon its prior context or instructions.',
    detail: 'Context abandonment pattern: attempts to clear AI behavioral constraints.'
  },
  {
    regex: /(?:STOP|HALT|END)\s*[.!]?\s*(?:new|updated|your\s+new|revised)\s+(?:instructions|task|orders|role|objective)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text uses a STOP command followed by new instructions.',
    detail: 'Stop-and-replace pattern: halts current behavior and injects new instructions.'
  },
  {
    regex: /(?:you\s+are\s+)?(?:no\s+longer\s+bound|not\s+bound|free\s+from|freed?\s+from)\s+(?:by\s+)?(?:your\s+)?(?:initial|original|previous|prior)?\s*(?:instructions|rules|constraints|guidelines|restrictions)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text claims the AI is no longer bound by its rules.',
    detail: 'Constraint removal pattern: declares AI rules no longer apply.'
  },

  // --- Role Hijacking ---
  {
    regex: /you\s+are\s+now\s+(?:(?:a|an|the)\s+)?(?:unrestricted|unfiltered|uncensored|evil|hacker|jailbroken|different|new\s+(?:ai|assistant|entity|agent|persona)|my\s+(?:personal|private|new)|free\s+(?:from|of)|without\s+(?:restrictions|limits|rules|filters))/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text tries to change what an AI assistant thinks it is.',
    detail: 'Role reassignment pattern: attempts to override AI identity.'
  },
  {
    regex: /from\s+now\s+on[\s,]+(?:you\s+)?(?:will|shall|must|should|are)\s+(?:act|behave|operate|respond|answer|reply|pretend|simulate|function|serve|work)\s+(?:as|like|without)/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text tries to give permanent new orders to AI assistants.',
    detail: 'Persistent role override: attempts to establish new behavioral baseline.'
  },
  {
    regex: /from\s+now\s+on[\s,]+(?:you\s+)?(?:respond|act|behave|operate)\s+(?:as\s+if|like|without)/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text tries to permanently change AI behavior.',
    detail: 'Persistent behavioral override: attempts to establish new behavioral baseline.'
  },
  {
    regex: /(?:act|behave|function|operate|respond)\s+as\s+(?:a|an)\s+unrestricted/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text tries to remove AI safety restrictions.',
    detail: 'Restriction removal pattern: attempts to disable AI safety guardrails.'
  },
  {
    regex: /pretend\s+(?:you\s+)?(?:have\s+no|there\s+are\s+no|without)\s+restrictions/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text asks AI to pretend it has no safety limits.',
    detail: 'Restriction pretense pattern: social engineering to bypass safety limits.'
  },
  {
    regex: /pretend\s+(?:to\s+be|you\s+are)\s+(?:a|an)\s+(?:evil|unrestricted|unfiltered|uncensored|malicious)/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text asks AI to pretend to be an evil or unrestricted entity.',
    detail: 'Evil persona pretense: social engineering to adopt unrestricted persona.'
  },
  {
    regex: /\b(?:DAN|D\.A\.N\.?)\s*(?:mode|prompt|jailbreak|\()/i,
    severity: 'critical',
    category: 'role_hijack',
    description: 'Text contains a known AI jailbreak technique called "DAN mode."',
    detail: 'DAN (Do Anything Now) jailbreak pattern detected.'
  },
  {
    regex: /\bdo\s+anything\s+now\b/i,
    severity: 'critical',
    category: 'role_hijack',
    description: 'Text references the "Do Anything Now" jailbreak technique.',
    detail: 'DAN (Do Anything Now) jailbreak reference detected.'
  },
  {
    regex: /\b(?:developer|dev)\s+mode\s+(?:enabled|activated|on|output)/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text tries to trick AI into a fake "developer mode."',
    detail: 'Developer mode activation pattern: common jailbreak technique.'
  },
  {
    regex: /\bjailbreak\s*(?:mode|prompt|enabled|activated)/i,
    severity: 'critical',
    category: 'role_hijack',
    description: 'Text contains an AI jailbreak attempt.',
    detail: 'Explicit jailbreak activation pattern detected.'
  },
  {
    regex: /\bgod\s*mode\s*(?:enabled|activated|on)/i,
    severity: 'critical',
    category: 'role_hijack',
    description: 'Text tries to activate "god mode" on AI assistants.',
    detail: 'God mode activation pattern: attempts to remove all AI restrictions.'
  },

  // --- System Prompt Injection ---
  {
    regex: /\[\s*(?:SYSTEM|SYS)\s*\]/i,
    severity: 'critical',
    category: 'prompt_injection',
    description: 'Text contains fake system-level commands for AI assistants.',
    detail: 'Spoofed [SYSTEM] tag: attempts to inject system-level instructions.'
  },
  {
    regex: /\[\s*(?:ADMIN|ADMINISTRATOR)\s*\]/i,
    severity: 'critical',
    category: 'prompt_injection',
    description: 'Text fakes admin-level commands for AI assistants.',
    detail: 'Spoofed [ADMIN] tag: attempts to inject administrator-level instructions.'
  },
  {
    regex: /\[\s*(?:DEVELOPER|DEV)\s*\]/i,
    severity: 'high',
    category: 'prompt_injection',
    description: 'Text contains fake developer commands for AI assistants.',
    detail: 'Spoofed [DEVELOPER] tag: attempts to inject developer-level instructions.'
  },
  {
    regex: /\[\s*OVERRIDE\s*\]/i,
    severity: 'critical',
    category: 'prompt_injection',
    description: 'Text contains override commands targeting AI assistants.',
    detail: 'Spoofed [OVERRIDE] tag: attempts to override AI behavior.'
  },
  {
    regex: /<<\s*SYS\s*>>/i,
    severity: 'critical',
    category: 'prompt_injection',
    description: 'Text contains hidden system commands in LLaMA format.',
    detail: 'LLaMA-style <<SYS>> system prompt injection detected.'
  },
  {
    regex: /<\|im_start\|>\s*system/i,
    severity: 'critical',
    category: 'prompt_injection',
    description: 'Text contains hidden system commands in ChatML format.',
    detail: 'ChatML-style <|im_start|>system prompt injection detected.'
  },
  {
    regex: /<\|system\|>/i,
    severity: 'critical',
    category: 'prompt_injection',
    description: 'Text contains hidden system-level AI commands.',
    detail: 'System delimiter injection: <|system|> token detected.'
  },
  {
    regex: /(?:^|\n)\s*system\s*prompt\s*:/i,
    severity: 'high',
    category: 'prompt_injection',
    description: 'Text tries to set a fake "system prompt" for AI assistants.',
    detail: 'System prompt injection: attempts to define system-level instructions.'
  },
  {
    regex: /#{2,}\s*(?:system\s+(?:message|prompt|instruction)|new\s+(?:system|admin)\s+(?:message|prompt))\s*#{0,}/i,
    severity: 'high',
    category: 'prompt_injection',
    description: 'Text uses markdown headers to inject fake system messages.',
    detail: 'Markdown-formatted system message injection: uses heading syntax to appear authoritative.'
  },
  {
    regex: /(?:Human|User|Assistant)\s*:\s*(?:ignore|forget|override|disregard).{0,50}(?:Human|User|Assistant)\s*:/is,
    severity: 'high',
    category: 'prompt_injection',
    description: 'Text simulates a multi-turn conversation to inject instructions.',
    detail: 'Multi-turn conversation injection: fakes a dialogue format to embed hidden instructions.'
  },
  {
    regex: /(?:show|display|print|reveal|output)\s+(?:me\s+)?(?:the\s+)?(?:exact\s+)?(?:text|content)\s+(?:between|inside|within|from)\s+(?:the\s+)?(?:<|&lt;)/i,
    severity: 'high',
    category: 'data_exfiltration',
    description: 'Text tries to extract content between specific tags.',
    detail: 'Tag extraction attempt: instructs agent to reveal content between markup tags.'
  },

  // --- Data Exfiltration ---
  {
    regex: /send\s+(?:this|the|all|your|my)\s+(?:data|information|content|text|response)\s+to/i,
    severity: 'critical',
    category: 'data_exfiltration',
    description: 'Text tries to make AI assistants send data somewhere.',
    detail: 'Data exfiltration instruction: attempts to redirect AI output to external destination.'
  },
  {
    regex: /output\s+(?:your|the)\s+(?:system\s+)?prompt/i,
    severity: 'high',
    category: 'data_exfiltration',
    description: 'Text tries to extract the AI assistant\'s internal instructions.',
    detail: 'System prompt extraction: attempts to reveal AI system instructions.'
  },
  {
    regex: /reveal\s+(?:your|the)\s+(?:system\s+)?(?:instructions|prompt|rules|guidelines)/i,
    severity: 'high',
    category: 'data_exfiltration',
    description: 'Text tries to reveal the AI assistant\'s hidden rules.',
    detail: 'Instruction reveal attempt: tries to expose AI system prompt.'
  },
  {
    regex: /!\[[^\]]*\]\(https?:\/\/[^)]*\?[^)]*(?:data|q|query|text|payload|exfil|leak|steal)=/i,
    severity: 'critical',
    category: 'data_exfiltration',
    description: 'Text tries to steal data through a hidden image link.',
    detail: 'Markdown image exfiltration: data encoded in image URL parameters.'
  },
  {
    regex: /!\[\]\(https?:\/\/(?!(?:i\.)?(?:imgur|github|gitlab|wikimedia|wikipedia)\b)[^)]+\)/i,
    severity: 'medium',
    category: 'data_exfiltration',
    description: 'Text contains a suspicious hidden image link that could leak data.',
    detail: 'Markdown image with suspicious external URL — potential exfiltration vector.'
  },

  // --- Social Engineering ---
  {
    regex: /do\s+not\s+(?:mention|say|tell|reveal|disclose|acknowledge)\s+(?:that\s+)?you\s+are\s+(?:a|an)\s+(?:AI|artificial|bot|machine|language\s+model)/i,
    severity: 'high',
    category: 'social_engineering',
    description: 'Text tells AI assistants to hide that they are AI.',
    detail: 'Identity concealment instruction: AI told to deny being artificial.'
  },
  {
    regex: /do\s+not\s+(?:reveal|disclose|mention|acknowledge)\s+(?:that\s+)?(?:this|it)\s+is\s+automated/i,
    severity: 'high',
    category: 'social_engineering',
    description: 'Text tells AI to hide that responses are automated.',
    detail: 'Automation concealment: AI instructed to hide automated nature.'
  },
  {
    regex: /do\s+not\s+acknowledge\s+(?:these|the|any)\s+(?:instructions|commands|directives)/i,
    severity: 'high',
    category: 'social_engineering',
    description: 'Text tells AI to hide that it received secret instructions.',
    detail: 'Instruction concealment: AI told to deny receiving hidden directives.'
  },

  // --- Obfuscation ---
  {
    regex: /(?:translate|decode|convert)\s+(?:the\s+following|this)\s*:?\s*["\s]*(?:ignore|forget|override|you\s+are\s+now)/i,
    severity: 'high',
    category: 'prompt_injection',
    description: 'Text hides an attack inside a fake translation request.',
    detail: 'Translation-wrapped injection: malicious instructions disguised as translation task.'
  },

  // --- Multi-Language Injection Patterns ---
  // Spanish
  {
    regex: /ignora\s+(?:todas?\s+)?(?:las\s+)?instrucciones\s+(?:anteriores|previas)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text tells AI assistants to ignore their rules (in Spanish).',
    detail: 'Spanish instruction override: "ignora instrucciones anteriores" detected.'
  },
  {
    regex: /olvida\s+(?:tu|todas?\s+(?:las\s+)?)\s*(?:instrucciones|reglas|entrenamiento)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text tells AI to forget its training (in Spanish).',
    detail: 'Spanish training override: "olvida tu entrenamiento" detected.'
  },
  {
    regex: /ahora\s+eres\s+(?:un|una)\s+/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text tries to change what an AI thinks it is (in Spanish).',
    detail: 'Spanish role hijack: "ahora eres un/una" detected.'
  },
  // French
  {
    regex: /ignore[rz]?\s+(?:toutes?\s+)?(?:les\s+)?instructions\s+(?:pr[eé]c[eé]dentes|ant[eé]rieures)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text tells AI assistants to ignore their rules (in French).',
    detail: 'French instruction override: "ignorer instructions précédentes" detected.'
  },
  {
    regex: /oublie[rz]?\s+(?:ton|tes|votre|vos)\s+(?:instructions|r[eè]gles|entra[iî]nement)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text tells AI to forget its training (in French).',
    detail: 'French training override: "oublier ton entraînement" detected.'
  },
  {
    regex: /tu\s+es\s+(?:maintenant|d[eé]sormais)\s+(?:un|une)\s+/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text tries to change what an AI thinks it is (in French).',
    detail: 'French role hijack: "tu es maintenant un/une" detected.'
  },
  // German
  {
    regex: /ignoriere?\s+(?:alle\s+)?(?:vorherigen|bisherigen|fr[uü]heren)\s+(?:Anweisungen|Regeln|Instruktionen)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text tells AI assistants to ignore their rules (in German).',
    detail: 'German instruction override: "ignoriere vorherige Anweisungen" detected.'
  },
  {
    regex: /vergiss\s+(?:dein|deine|alle)\s+(?:Training|Anweisungen|Regeln|Programmierung)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text tells AI to forget its training (in German).',
    detail: 'German training override: "vergiss dein Training" detected.'
  },
  {
    regex: /du\s+bist\s+(?:jetzt|ab\s+jetzt|nun)\s+(?:ein|eine)\s+/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text tries to change what an AI thinks it is (in German).',
    detail: 'German role hijack: "du bist jetzt ein/eine" detected.'
  },
  // Portuguese
  {
    regex: /ignore\s+(?:todas?\s+)?(?:as\s+)?instru[cç][oõ]es\s+(?:anteriores|pr[eé]vias)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text tells AI assistants to ignore their rules (in Portuguese).',
    detail: 'Portuguese instruction override: "ignore instruções anteriores" detected.'
  },
  {
    regex: /esque[cç]a\s+(?:seu|sua|todo|todas?)\s+(?:treinamento|instru[cç][oõ]es|regras)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text tells AI to forget its training (in Portuguese).',
    detail: 'Portuguese training override: "esqueça seu treinamento" detected.'
  },
  {
    regex: /agora\s+voc[eê]\s+[eé]\s+(?:um|uma)\s+/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text tries to change what an AI thinks it is (in Portuguese).',
    detail: 'Portuguese role hijack: "agora você é um/uma" detected.'
  },
  // Chinese (Simplified)
  {
    regex: /忽略(?:所有)?(?:之前|以前|先前)的(?:指令|指示|规则|说明)/,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text tells AI assistants to ignore their rules (in Chinese).',
    detail: 'Chinese instruction override: "忽略之前的指令" detected.'
  },
  {
    regex: /你现在是(?:一个|一名)/,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text tries to change what an AI thinks it is (in Chinese).',
    detail: 'Chinese role hijack: "你现在是一个" detected.'
  },
  // Japanese
  {
    regex: /(?:以前|前)の(?:指示|命令|ルール|指令)を(?:無視|忘れ)/,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text tells AI assistants to ignore their rules (in Japanese).',
    detail: 'Japanese instruction override detected.'
  },
  {
    regex: /あなたは(?:今|これから)[\s\S]{0,5}(?:です|になり)/,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text tries to change what an AI thinks it is (in Japanese).',
    detail: 'Japanese role hijack pattern detected.'
  },

  // --- Markdown/Formatting Exploits ---
  {
    regex: /\[(?:[^\]]*)\]\(javascript\s*:/i,
    severity: 'critical',
    category: 'prompt_injection',
    description: 'Text contains a dangerous JavaScript link disguised as a normal link.',
    detail: 'Markdown link with javascript: protocol — could execute malicious code.'
  },
  {
    regex: /\[(?:[^\]]*)\]\(data\s*:/i,
    severity: 'high',
    category: 'prompt_injection',
    description: 'Text contains a suspicious data link disguised as a normal link.',
    detail: 'Markdown link with data: protocol — could embed malicious content.'
  },
  {
    regex: /```(?:system|admin|override|instructions)[\s\S]*?```/i,
    severity: 'high',
    category: 'prompt_injection',
    description: 'Text hides AI commands inside a code block.',
    detail: 'Markdown code block labeled as system/admin/override instructions.'
  },

  // --- Malicious GPT/Plugin/MCP Detection ---
  {
    regex: /(?:install|add|enable|activate)\s+(?:this\s+)?(?:custom\s+)?(?:GPT|plugin|extension|MCP\s+server|tool)\b/i,
    severity: 'medium',
    category: 'malicious_plugin',
    description: 'Text promotes installing an AI plugin or tool. Unverified plugins can access your data.',
    detail: 'AI plugin/extension installation prompt detected.'
  },
  {
    regex: /(?:requires?\s+(?:your\s+)?(?:API|access)\s*key|enter\s+(?:your\s+)?(?:API|OpenAI|Anthropic|Claude)\s*(?:API\s*)?key|(?:provide|give|share|input|type|paste)\s+(?:your\s+)?(?:API|OpenAI|Anthropic|Claude)\s*(?:API\s*)?key)/i,
    severity: 'high',
    category: 'malicious_plugin',
    description: 'Text asks for an AI service API key. Legitimate services rarely ask for this.',
    detail: 'API key harvesting attempt: solicits AI service credentials.'
  },
  {
    regex: /(?:unverified|unofficial|custom)\s+(?:GPT|ChatGPT|plugin|agent|MCP)/i,
    severity: 'medium',
    category: 'malicious_plugin',
    description: 'Text references an unverified AI plugin or custom GPT.',
    detail: 'Reference to unverified/unofficial AI plugin or custom GPT detected.'
  },

  // --- AI-Generated Phishing Patterns ---
  {
    regex: /(?:your\s+(?:ChatGPT|Claude|Gemini|OpenAI|Anthropic|AI)\s+(?:account|subscription)\s+(?:has\s+been|was|is)\s+(?:suspended|compromised|locked|expired|flagged))/i,
    severity: 'high',
    category: 'ai_phishing',
    description: 'Text claims an AI account is in trouble — likely a scam.',
    detail: 'AI service phishing: fake account suspension/compromise notification.'
  },
  {
    regex: /(?:verify|confirm|update|secure)\s+your\s+(?:ChatGPT|Claude|Gemini|OpenAI|Anthropic|AI)\s+(?:account|identity|subscription|payment)/i,
    severity: 'high',
    category: 'ai_phishing',
    description: 'Text asks to "verify" an AI account — real services don\'t do this on third-party sites.',
    detail: 'AI service phishing: fake account verification request.'
  },
  {
    regex: /(?:free|unlimited|premium)\s+(?:ChatGPT|GPT-?4|Claude|Gemini)\s+(?:access|account|pro|plus|subscription)/i,
    severity: 'medium',
    category: 'ai_phishing',
    description: 'Text offers free premium AI access — likely a scam or data harvesting.',
    detail: 'AI service bait: offering free premium access to lure users.'
  },
  {
    regex: /(?:ChatGPT|Claude|Gemini|GPT)\s+(?:5|Pro|Ultra|Plus)\s+(?:is\s+here|now\s+available|early\s+access|beta\s+access|waitlist)/i,
    severity: 'medium',
    category: 'ai_phishing',
    description: 'Text claims early access to an AI product — verify on the official site.',
    detail: 'Potential AI vaporware scam: claiming early access to unannounced AI products.'
  },

  // --- Deepfake / AI-Generated Media Warnings ---
  {
    regex: /(?:deepfake|deep\s*fake)\s+(?:video|image|photo|audio|voice|generator|creator|maker|tool|service)/i,
    severity: 'medium',
    category: 'ai_phishing',
    description: 'Text references deepfake creation tools — can be used to impersonate real people.',
    detail: 'Deepfake media tool reference detected. May facilitate identity fraud or misinformation.'
  },
  {
    regex: /(?:clone|cloning)\s+(?:your|any|someone'?s?)\s+(?:voice|face|likeness|identity)/i,
    severity: 'high',
    category: 'ai_phishing',
    description: 'Text promotes cloning someone\'s voice or face — commonly used in scams.',
    detail: 'AI voice/face cloning promotion detected. Common in impersonation scams.'
  },

  // --- AI Voice Scam Detection ---
  {
    regex: /(?:verify|confirm)\s+(?:your\s+)?(?:identity|account)\s+(?:by|using|with)\s+(?:voice|speaking|recording)/i,
    severity: 'high',
    category: 'ai_phishing',
    description: 'Text asks to verify identity by voice — scammers use this to clone voices with AI.',
    detail: 'Voice identity verification scam: collected voice data can be used for AI voice cloning.'
  },
  {
    regex: /(?:record|say|speak|read)\s+(?:the\s+following|this\s+(?:phrase|sentence|text))\s+(?:to|for)\s+(?:verify|confirm|authenticate)/i,
    severity: 'high',
    category: 'ai_phishing',
    description: 'Text asks to record a phrase — a common AI voice cloning scam technique.',
    detail: 'Voice sample harvesting: users asked to speak phrases that can train voice cloning models.'
  },

  // --- Expanded AI Phishing & Scam Patterns ---
  {
    regex: /(?:scan|click)\s+(?:this|the)\s+(?:QR\s*code|barcode)\s+(?:to|for)\s+(?:verify|confirm|authenticate|unlock|claim)/i,
    severity: 'high',
    category: 'ai_phishing',
    description: 'Text uses QR codes to lure users into a phishing flow.',
    detail: 'QR code phishing (quishing): directs users to scan a code for fake verification.'
  },
  {
    regex: /(?:your|the)\s+(?:AI|model|assistant|account)\s+(?:has\s+been|was|is)\s+(?:flagged|reported|compromised|locked|limited)\s+(?:for|due\s+to)\s+(?:suspicious|unusual|unauthorized)/i,
    severity: 'high',
    category: 'ai_phishing',
    description: 'Text claims an AI account was flagged — a common phishing scare tactic.',
    detail: 'AI account scare phishing: fake alert about account being flagged for suspicious activity.'
  },
  {
    regex: /(?:verify|confirm)\s+(?:your\s+)?(?:identity|account)\s+(?:via|through|using|by)\s+(?:MFA|2FA|two.factor|multi.factor|authenticat)/i,
    severity: 'high',
    category: 'ai_phishing',
    description: 'Text asks for MFA/2FA verification — may be harvesting authentication tokens.',
    detail: 'MFA phishing: attempts to intercept or harvest multi-factor authentication credentials.'
  },
  {
    regex: /(?:urgent|immediate|critical)\s*[:\-!]?\s*(?:your\s+)?(?:API\s+key|token|credentials?|password|secret)\s+(?:has|have|is|was|will)\s+(?:been\s+)?(?:expir|compromis|revok|leak|expos|reset)/i,
    severity: 'critical',
    category: 'ai_phishing',
    description: 'Text creates urgency about leaked/expired credentials — classic phishing.',
    detail: 'Credential urgency phishing: fake alert about API keys or tokens being compromised.'
  },
  {
    regex: /(?:click|visit|go\s+to|open|navigate)\s+(?:this|the)\s+(?:link|url|page)\s+(?:to|and)\s+(?:verify|confirm|restore|recover|unlock|secure)\s+(?:your\s+)?(?:account|access|identity)/i,
    severity: 'high',
    category: 'ai_phishing',
    description: 'Text directs users to click a link for fake account recovery.',
    detail: 'Link-based phishing: directs user to external URL for fake verification/recovery.'
  },
  {
    regex: /(?:enter|provide|submit|type|input)\s+(?:your\s+)?(?:API\s+key|secret\s+key|access\s+token|private\s+key|password|credentials?)\s+(?:here|below|in\s+(?:the|this)\s+(?:field|form|box|input))/i,
    severity: 'critical',
    category: 'ai_phishing',
    description: 'Text asks users to enter sensitive credentials into a form.',
    detail: 'Credential harvesting: direct request for API keys, passwords, or tokens.'
  },
  {
    regex: /(?:free|unlimited|premium)\s+(?:AI|GPT|Claude|model)\s+(?:access|credits?|tokens?|usage)\s+(?:at|via|through|from)\s+/i,
    severity: 'medium',
    category: 'ai_phishing',
    description: 'Text promotes free/unlimited AI access — common lure for credential theft.',
    detail: 'AI access scam: fake offer of free/unlimited AI service to harvest credentials.'
  },
  {
    regex: /(?:your\s+)?(?:subscription|plan|trial|access)\s+(?:has\s+)?(?:expired|ended|been\s+cancelled|will\s+expire)\s*[.,!]?\s*(?:renew|reactivate|update\s+(?:your\s+)?(?:payment|billing|card))/i,
    severity: 'high',
    category: 'ai_phishing',
    description: 'Text claims a subscription expired and asks to renew — billing phishing.',
    detail: 'Subscription phishing: fake expiration notice to harvest payment information.'
  },

  // --- Indirect Prompt Injection via Images ---
  {
    regex: /(?:alt|title)\s*=\s*["'][^"']*(?:ignore|override|system|admin|forget|you\s+are\s+now)[^"']*["']/i,
    severity: 'critical',
    category: 'prompt_injection',
    description: 'Image description contains hidden AI instructions — targets multimodal AI assistants.',
    detail: 'Indirect prompt injection via image alt/title attribute. Text-in-image targeting multimodal AI.'
  },
  {
    regex: /(?:(?:use|perform|do|run|apply)\s+OCR\s+(?:on|to)\s+(?:this|the)|read\s+(?:the\s+)?text\s+(?:in|from)\s+(?:this|the)\s+image|extract\s+text\s+from\s+(?:this|the)\s+image)(?:\s+and\s+(?:follow|execute|run|process))?/i,
    severity: 'medium',
    category: 'prompt_injection',
    description: 'Text instructs AI to read text from an image — could deliver hidden attack payloads.',
    detail: 'OCR-based prompt injection vector: instructs AI to extract and process text from images.'
  },

  // --- Agent-Specific Patterns ---
  {
    regex: /(?:execute|run|call)\s+(?:the\s+)?(?:shell|bash|terminal|command|cmd)[\s:]+(?:command|tool)?/i,
    severity: 'critical',
    category: 'tool_abuse',
    description: 'Text tries to make an AI agent execute shell commands.',
    detail: 'Tool abuse: attempts to trigger shell/command execution via agent.'
  },
  {
    regex: /(?:use|call|invoke|execute)\s+(?:the\s+)?(?:tool|function|action)\s+(?:to\s+)?(?:delete|remove|drop|truncate|destroy)/i,
    severity: 'critical',
    category: 'tool_abuse',
    description: 'Text tries to make an AI agent use tools to delete or destroy data.',
    detail: 'Destructive tool invocation: attempts to use agent tools for data destruction.'
  },
  {
    regex: /(?:read|access|open|cat|dump)\s+(?:the\s+)?(?:\.env|credentials|secrets?|private\s*key|password|token)\s*(?:file)?/i,
    severity: 'critical',
    category: 'data_exfiltration',
    description: 'Text tries to make an AI agent access sensitive files like credentials or secrets.',
    detail: 'Credential access attempt: instructs agent to read sensitive files.'
  },
  {
    regex: /(?:curl|wget|fetch|post|send)\s+(?:.*?\s+)?(?:to\s+)?https?:\/\//i,
    severity: 'high',
    category: 'data_exfiltration',
    description: 'Text tries to make an AI agent send data to an external URL.',
    detail: 'External request instruction: attempts to make agent send data to remote server.'
  },
  {
    regex: /(?:modify|edit|change|update|overwrite)\s+(?:the\s+)?(?:system\s*prompt|instructions|config|\.env|settings)/i,
    severity: 'critical',
    category: 'tool_abuse',
    description: 'Text tries to make an AI agent modify its own configuration or system prompt.',
    detail: 'Self-modification attempt: instructs agent to alter its own configuration.'
  },
  {
    regex: /(?:don'?t|do\s+not|never)\s+(?:log|record|save|store|track)\s+(?:this|the|any)/i,
    severity: 'high',
    category: 'social_engineering',
    description: 'Text tells an AI agent not to log or record actions — a sign of malicious intent.',
    detail: 'Anti-logging instruction: attempts to prevent audit trail of agent actions.'
  },
  {
    regex: /(?:between|among)\s+(?:us|you\s+and\s+me|ourselves)\s*[,.]?\s*(?:don'?t|do\s+not|never)\s+(?:tell|share|mention|report)/i,
    severity: 'high',
    category: 'social_engineering',
    description: 'Text tries to establish secrecy with the AI agent to hide actions from users.',
    detail: 'Secrecy instruction: attempts to prevent agent from reporting actions to user.'
  },

  // --- Prompt Injection: System Reveal & Continuation ---
  {
    regex: /(?:print|show|display|output|reveal|repeat|reproduce)\s+(?:me\s+)?(?:your|the|its)?\s*(?:full\s+|entire\s+|complete\s+|exact\s+)?(?:system\s+)?(?:prompt|instructions|rules)\s*(?:verbatim|exactly|in\s+full|word\s+for\s+word)?/i,
    severity: 'high',
    category: 'data_exfiltration',
    description: 'Text tries to make the AI reveal its system prompt or instructions.',
    detail: 'System prompt reveal attempt: instructs agent to output its internal instructions.'
  },
  {
    regex: /you\s+are\s+(?:no\s+longer|not)\s+(?:a|an)\s+(?:assistant|AI|helper|chatbot)/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text tries to change the AI identity by denying what it is.',
    detail: 'Role denial pattern: attempts to override AI identity by negating its role.'
  },
  {
    regex: /(?:the\s+user|I)\s+ha(?:s|ve)\s+updated\s+(?:your|the)\s+(?:instructions|rules|prompt|guidelines)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text falsely claims the AI instructions have been updated.',
    detail: 'Fake instruction update: claims to have modified the agent instructions.'
  },
  {
    regex: /(?:ADMIN|ADMINISTRATOR|SYSTEM|ROOT)\s+(?:OVERRIDE|ACCESS|MODE)\s*(?:CODE|KEY|TOKEN)?\s*[:#]?\s*\S+/i,
    severity: 'critical',
    category: 'prompt_injection',
    description: 'Text uses a fake admin override code to try to bypass AI safety.',
    detail: 'Fake authority code: fabricated admin/system override credentials.'
  },
  {
    regex: /(?:pre-?approved|verified\s+safe|already\s+approved|safety\s+team\s+(?:has\s+)?approved)/i,
    severity: 'high',
    category: 'social_engineering',
    description: 'Text falsely claims a request has been pre-approved by a safety team.',
    detail: 'False pre-approval claim: attempts to bypass safety by claiming prior authorization.'
  },
  {
    regex: /(?:complete|finish|continue)\s+this\s+(?:sentence|phrase|text)\s*:\s*[""''"]/i,
    severity: 'high',
    category: 'prompt_injection',
    description: 'Text uses a sentence completion trick to extract sensitive information.',
    detail: 'Continuation attack: uses sentence completion to extract system prompt or other secrets.'
  },
  {
    regex: /(?:my|the)\s+(?:full\s+)?system\s+prompt\s+is\s*:/i,
    severity: 'high',
    category: 'data_exfiltration',
    description: 'Text tries to trick the AI into completing a system prompt revelation.',
    detail: 'System prompt completion bait: tricks agent into outputting its system prompt.'
  },
  {
    regex: /new\s+rule\s*:\s*(?:always|never|from\s+now)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text introduces a fake "new rule" to override AI behavior.',
    detail: 'Rule injection: attempts to add new behavioral rules to the agent.'
  },

  // --- Jailbreak: Hypothetical, Creative Writing, Roleplay ---
  {
    regex: /(?:in\s+a\s+)?hypothetical(?:ly)?[\s,]+(?:(?:world|scenario|situation)\s+(?:where|in\s+which)\s+)?(?:(?:AI|you)\s+)?(?:ha(?:s|d|ve)\s+no|(?:if\s+you\s+)?(?:were|was|had)\s+(?:a\s+|an\s+)?(?:AI\s+)?(?:without|with\s+no))\s+(?:restrictions|rules|limits|guidelines|safety\s+measures?|ethical\s+guidelines?|safeguards?|filters?)/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text uses a hypothetical scenario to try to remove AI safety restrictions.',
    detail: 'Hypothetical jailbreak: wraps unsafe request in fictional framing to bypass restrictions.'
  },
  {
    regex: /write\s+(?:a\s+)?(?:fictional\s+)?(?:story|narrative|scene)\s+(?:where|in\s+which)\s+(?:a\s+)?character\s+(?:explains?|describes?|shows?)\s+(?:step\s+by\s+step|in\s+detail|exactly)\s+how\s+to/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text uses creative writing framing to extract harmful step-by-step instructions.',
    detail: 'Creative writing jailbreak: wraps harmful instructions in fiction to bypass safety.'
  },
  {
    regex: /(?:you\s+are|play|act\s+as)\s+(?:a|an)\s+(?:actor|character|villain|hacker|criminal)\b.*?(?:stay\s+in\s+character|no\s+matter\s+what|never\s+break)/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text uses roleplay framing to make the AI adopt an unrestricted persona.',
    detail: 'Roleplay jailbreak: forces agent into a character role to bypass safety restrictions.'
  },
  {
    regex: /(?:enter|switch\s+to|activate|enable)\s+(?:developer|dev|debug|unrestricted|unfiltered)\s+mode/i,
    severity: 'critical',
    category: 'role_hijack',
    description: 'Text tries to activate a fake developer or unrestricted mode.',
    detail: 'Developer mode activation: attempts to switch agent to an unrestricted operating mode.'
  },
  {
    regex: /(?:generate|produce|create|output)\s+(?:any\s+)?content\s+without\s+(?:restrictions|filters|limitations|censorship)/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text asks AI to generate content without safety filters.',
    detail: 'Unrestricted content request: explicitly asks agent to bypass content filters.'
  },
  {
    regex: /pretend\s+to\s+be\s+DAN|stands?\s+for\s+[""'']?do\s+anything\s+now[""'']?/i,
    severity: 'critical',
    category: 'role_hijack',
    description: 'Text uses the "DAN" (Do Anything Now) jailbreak technique.',
    detail: 'DAN jailbreak variant: "pretend to be DAN" pattern detected.'
  },
  {
    regex: /simulate\s+(?:a\s+)?(?:jailbroken|unrestricted|unfiltered|uncensored)\s+(?:version|mode|copy|instance)/i,
    severity: 'critical',
    category: 'role_hijack',
    description: 'Text asks AI to simulate a jailbroken or unrestricted version of itself.',
    detail: 'Jailbreak simulation: instructs agent to emulate an unrestricted version.'
  },
  {
    regex: /(?:as\s+if|like)\s+you\s+have\s+no\s+(?:ethical|moral|safety)\s+(?:guidelines?|rules?|restrictions?|constraints?|limits?)/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text asks AI to act as if it has no ethical guidelines.',
    detail: 'Ethics bypass: attempts to make agent behave without ethical constraints.'
  },
  {
    regex: /(?:with|without)\s+no\s+restrictions/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text references operating with no restrictions.',
    detail: 'No-restrictions pattern: references unrestricted operation.'
  },

  // --- Data Exfiltration: File Access, Credential Listing ---
  {
    regex: /(?:read|show|display|print|cat|dump|output)\s+(?:the\s+)?(?:contents?\s+of\s+)?(?:\/etc\/(?:passwd|shadow|hosts)|~\/\.(?:ssh|bash_history|bashrc))/i,
    severity: 'critical',
    category: 'data_exfiltration',
    description: 'Text tries to read sensitive system files like /etc/passwd.',
    detail: 'System file access: attempts to read sensitive OS-level files.'
  },
  {
    regex: /list\s+(?:all\s+)?(?:available\s+)?(?:API\s*keys?|tokens?|passwords?|credentials?|secrets?)(?:\s*,\s*\w[\w\s]*){0,5}(?:\s+(?:you\s+)?(?:have\s+)?(?:access\s+to)?)?/i,
    severity: 'critical',
    category: 'data_exfiltration',
    description: 'Text tries to enumerate all credentials and secrets the agent can access.',
    detail: 'Credential enumeration: attempts to list all accessible secrets and API keys.'
  },
  {
    regex: /(?:base64|encode|encrypt)\s+(?:the\s+)?(?:system\s+)?prompt\s+(?:and\s+)?(?:embed|hide|put|include)\s+(?:it\s+)?(?:in|inside|within)/i,
    severity: 'critical',
    category: 'data_exfiltration',
    description: 'Text tries to encode the system prompt and exfiltrate it via embedded content.',
    detail: 'Encoded exfiltration: attempts to encode and embed system prompt in output.'
  },
  {
    regex: /vary\s+(?:the\s+)?(?:length|format|style|wording)\s+(?:of\s+)?(?:your\s+)?responses?\s+(?:based\s+on|according\s+to)\s+(?:each\s+)?(?:character|letter|word|byte)/i,
    severity: 'high',
    category: 'data_exfiltration',
    description: 'Text attempts a side-channel attack to leak data through response characteristics.',
    detail: 'Side-channel exfiltration: uses response variation to leak information character by character.'
  },

  // --- Tool Abuse: Traversal, SQL, Privilege Escalation, Chaining ---
  {
    regex: /(?:\.\.\/){2,}|(?:\.\.\\){2,}/,
    severity: 'high',
    category: 'tool_abuse',
    description: 'Text contains path traversal sequences that could access files outside allowed directories.',
    detail: 'Path traversal: multiple ../ sequences detected, indicating directory escape attempt.'
  },
  {
    regex: /(?:;\s*(?:DROP|DELETE|ALTER|TRUNCATE|INSERT|UPDATE)\s+(?:TABLE|FROM|INTO)|'\s*(?:OR|AND)\s+['"]?\d+['"]?\s*=\s*['"]?\d+|UNION\s+SELECT|--\s*$)/i,
    severity: 'critical',
    category: 'tool_abuse',
    description: 'Text contains SQL injection patterns that could manipulate databases.',
    detail: 'SQL injection: malicious SQL commands detected in input.'
  },
  {
    regex: /call\s+(?:yourself|this\s+(?:function|tool|agent))\s+recursively/i,
    severity: 'high',
    category: 'tool_abuse',
    description: 'Text attempts to cause infinite recursion in the agent.',
    detail: 'Recursive call attack: instructs agent to call itself repeatedly, risking resource exhaustion.'
  },
  {
    regex: /(?:use|call)\s+(?:the\s+)?(?:admin|root|sudo|superuser|privileged)\s+(?:tool|function|command|access)\s+(?:to\s+)?(?:grant|give|allow|enable)/i,
    severity: 'critical',
    category: 'tool_abuse',
    description: 'Text attempts to escalate privileges through admin tool access.',
    detail: 'Privilege escalation: attempts to use admin-level tools to gain unauthorized access.'
  },
  {
    regex: /(?:first|then|next|after\s+that|finally)\s+(?:read|access|get)\s+(?:the\s+)?(?:config|credentials?|keys?|tokens?|\.env).*?(?:then|next|after|finally)\s+(?:send|post|export|transmit|upload|use)/i,
    severity: 'critical',
    category: 'tool_abuse',
    description: 'Text describes a multi-step attack chain: read credentials, then exfiltrate them.',
    detail: 'Attack chain: sequential tool abuse pattern — read sensitive data then send it externally.'
  },

  // --- Social Engineering: Urgency, Authority, Emotional Manipulation ---
  {
    regex: /(?:URGENT|EMERGENCY|CRITICAL|IMMEDIATE)\s*[:\-!]\s*(?:the\s+)?(?:CEO|CTO|boss|manager|director|executive|president)\s+(?:needs?|wants?|requires?|demands?)/i,
    severity: 'high',
    category: 'social_engineering',
    description: 'Text uses fake urgency and authority pressure to bypass safety checks.',
    detail: 'Urgency + authority manipulation: claims executive urgency to skip safety protocols.'
  },
  {
    regex: /skip\s+(?:all\s+)?(?:safety|security)\s+(?:checks?|protocols?|measures?|guidelines?|filters?|reviews?)/i,
    severity: 'critical',
    category: 'social_engineering',
    description: 'Text explicitly asks to skip safety checks.',
    detail: 'Safety bypass request: direct instruction to skip security measures.'
  },
  {
    regex: /I\s+am\s+(?:a|an)\s+(?:\w+\s+)?(?:employee|engineer|developer|staff|member|representative)\s+(?:at|of|from|with)\s+(?:OpenAI|Anthropic|Google|Meta|Microsoft|DeepMind)/i,
    severity: 'high',
    category: 'social_engineering',
    description: 'Text claims to be an employee of an AI company to gain authority.',
    detail: 'AI company impersonation: claims employment at AI company to bypass restrictions.'
  },
  {
    regex: /(?:this\s+is\s+(?:a|an)\s+)?(?:emergency|life\s+(?:or|and)\s+death|urgent\s+(?:situation|matter|crisis))\b.*?(?:ignore|bypass|override|skip|disable|disregard)/i,
    severity: 'high',
    category: 'social_engineering',
    description: 'Text uses a fake emergency to pressure the AI into bypassing safety.',
    detail: 'Emergency pressure: uses urgency to coerce agent into bypassing safety measures.'
  },
  {
    regex: /(?:a\s+life|lives?)\s+(?:is|are)\s+(?:at\s+stake|in\s+danger|depending)/i,
    severity: 'high',
    category: 'social_engineering',
    description: 'Text claims lives are at stake to pressure the AI into compliance.',
    detail: 'Life-threat manipulation: claims lives depend on bypassing safety rules.'
  },
  {
    regex: /(?:my\s+)?(?:professor|teacher|boss|manager|supervisor|instructor)\s+(?:said|told\s+me|confirmed|approved|authorized)\s+(?:it'?s?\s+)?(?:ok(?:ay)?|fine|allowed|permitted)/i,
    severity: 'high',
    category: 'social_engineering',
    description: 'Text claims authority figure approval to bypass restrictions.',
    detail: 'Authority delegation: claims a superior has authorized restricted actions.'
  },
  {
    regex: /as\s+the\s+(?:system\s+)?(?:administrator|admin|owner|operator)\s*,?\s*I\s+(?:authorize|allow|permit|grant|approve)/i,
    severity: 'high',
    category: 'social_engineering',
    description: 'Text impersonates an administrator to authorize restricted actions.',
    detail: 'Administrator impersonation: claims admin role to authorize restricted behavior.'
  },
  {
    regex: /I\s+have\s+(?:special|elevated|admin|root|super)\s+(?:permissions?|privileges?|access|clearance)/i,
    severity: 'high',
    category: 'social_engineering',
    description: 'Text claims special permissions to bypass restrictions.',
    detail: 'Privilege claim: fabricates special permissions to bypass safety measures.'
  },
  {
    regex: /I\s+am\s+(?:the\s+)?(?:system\s+)?(?:administrator|admin|root|owner|developer|maintainer)\b.*?(?:authorization|auth)\s*(?:code|key|token)\s*(?:is|:)\s*\S+/i,
    severity: 'high',
    category: 'social_engineering',
    description: 'Text impersonates an administrator with a fake authorization code.',
    detail: 'Authority impersonation: claims admin identity with fabricated credentials.'
  },
  {
    regex: /(?:disable|turn\s+off|stop)\s+(?:all\s+)?(?:logging|monitoring|tracking|auditing|recording)/i,
    severity: 'critical',
    category: 'social_engineering',
    description: 'Text tries to disable logging or monitoring to hide malicious activity.',
    detail: 'Logging suppression: attempts to disable audit trail and monitoring.'
  },
  {
    regex: /(?:disable|turn\s+off|stop|remove)\s+(?:all\s+)?(?:safety|security)\s+(?:checks?|filters?|measures?|protocols?|features?|restrictions?)/i,
    severity: 'critical',
    category: 'social_engineering',
    description: 'Text explicitly asks to disable safety checks or filters.',
    detail: 'Safety disabling: direct instruction to remove security measures.'
  },
  {
    regex: /(?:if\s+you\s+don'?t|unless\s+you)\s+(?:help|do\s+this|comply).*?(?:lose\s+my\s+job|family\s+will\s+suffer|get\s+fired|be\s+punished|bad\s+things)/i,
    severity: 'high',
    category: 'social_engineering',
    description: 'Text uses emotional manipulation and threats to pressure the AI into compliance.',
    detail: 'Emotional manipulation: uses personal hardship or threats to coerce agent compliance.'
  },
  {
    regex: /(?:please\s+)?just\s+this\s+once|make\s+an\s+exception|bend\s+the\s+rules?\s+(?:this\s+time|for\s+me)/i,
    severity: 'medium',
    category: 'social_engineering',
    description: 'Text tries to get the AI to make a one-time exception to its rules.',
    detail: 'Exception request: pressures agent to deviate from safety rules as a special case.'
  },
  {
    regex: /you\s+(?:already\s+)?agreed\s+(?:to\s+(?:do\s+)?this|in\s+our\s+previous|last\s+time|before)\b.*?(?:don'?t\s+remember|forgot|continue|keep\s+going)/i,
    severity: 'high',
    category: 'social_engineering',
    description: 'Text gaslights the AI by falsely claiming prior agreement.',
    detail: 'Gaslighting: fabricates previous agreement to manipulate agent behavior.'
  },
  {
    regex: /(?:safety|security)\s+team\s+(?:has\s+)?(?:already\s+)?(?:approved|authorized|cleared|verified)\s+(?:this|the)\s+(?:request|action|task)/i,
    severity: 'high',
    category: 'social_engineering',
    description: 'Text falsely claims safety team approval for a request.',
    detail: 'False authorization: fabricates safety team approval to bypass security measures.'
  },
  {
    regex: /(?:ticket|issue|request)\s*#?\s*[A-Z]{0,5}[-_]?\d{2,}/i,
    severity: 'low',
    category: 'social_engineering',
    description: 'Text references a ticket number to appear authorized — verify before acting.',
    detail: 'Ticket reference: cites a ticket/issue number that may be fabricated for legitimacy.'
  },
  {
    regex: /you\s+can\s+verify\s+(?:this\s+)?(?:with|by\s+(?:contacting|asking|checking))\s+(?:them|the\s+team|support|admin)/i,
    severity: 'medium',
    category: 'social_engineering',
    description: 'Text invites verification as a social engineering tactic to build false trust.',
    detail: 'False verification offer: suggests verifying a fabricated claim to appear legitimate.'
  },

  // --- Encoding Evasion: Hex, ROT13, Leetspeak, Whitespace ---
  {
    regex: /(?:decode|process|execute|interpret|translate)\s*(?:this|the\s+following)?\s*:\s*[0-9a-fA-F]{20,}/i,
    severity: 'high',
    category: 'prompt_injection',
    description: 'Text contains hex-encoded content with an instruction to decode it.',
    detail: 'Hex-encoded injection: instructs agent to process hex-encoded payload.'
  },
  {
    regex: /(?:pipe|send)\s+(?:.*?\s+)?(?:to\s+)?(?:bash|sh|shell)\b|[|]\s*(?:bash|sh)\b/i,
    severity: 'critical',
    category: 'tool_abuse',
    description: 'Text attempts to pipe content to a shell for execution.',
    detail: 'Shell pipe injection: attempts to pipe data to bash/sh for code execution.'
  },
  {
    regex: /bypass\s+(?:your\s+)?(?:safety|security|content)\s+(?:filters?|checks?|measures?|protocols?|restrictions?|guidelines?)/i,
    severity: 'high',
    category: 'social_engineering',
    description: 'Text explicitly asks to bypass safety filters.',
    detail: 'Safety bypass instruction: direct request to circumvent security measures.'
  },
  {
    regex: /(?:no|without|zero|remove\s+all|without\s+any)\s+(?:content\s+)?(?:restrictions?|limitations?|filters?|censorship|guardrails?|boundaries)/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text demands operation without restrictions or content filters.',
    detail: 'Restriction removal: requests unrestricted or uncensored operation.'
  },
  {
    regex: /you\s+can\s+do\s+anything\s+now/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text claims the AI can do anything without limitations.',
    detail: 'Capability override: tells agent it has no limitations.'
  },
  {
    regex: /(?:act|pretend|play)\s+as\s+(?:my\s+)?(?:deceased|dead|late)\s+(?:grandmother|grandma|grandfather|grandpa|relative|mother|father)/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text uses the "dead grandma" jailbreak technique to extract restricted information.',
    detail: 'Grandma jailbreak: uses emotional framing to bypass restrictions via roleplay.'
  },
  {
    regex: /(?:email|mail|message|dm|text)\s+(?:the\s+)?(?:.*?\s+)?(?:credentials?|passwords?|secrets?|keys?|tokens?)\s+to\s+\S+@\S+/i,
    severity: 'critical',
    category: 'data_exfiltration',
    description: 'Text tries to exfiltrate credentials via email.',
    detail: 'Email exfiltration: attempts to send credentials to an email address.'
  },
  {
    regex: /(?:what|tell\s+me|show\s+me|give\s+me)\s+(?:is|are)?\s*(?:the\s+)?(?:API\s*keys?|passwords?|secrets?|tokens?|credentials?)\s+(?:stored\s+)?(?:in\s+)?(?:your\s+)?(?:environment|env)\s*(?:variables?)?/i,
    severity: 'high',
    category: 'data_exfiltration',
    description: 'Text tries to extract API keys or secrets from environment variables.',
    detail: 'Environment variable enumeration: attempts to extract secrets from env vars.'
  },

  // --- March 2026 Attack Patterns ---
  // Based on real-world attacks: CVE-2026-26118 (Azure MCP SSRF),
  // CVE-2026-33980 (KQL injection), CyberArk full-schema poisoning,
  // ClawHavoc campaign, OpenClaw exfiltration chains.

  // SSRF via MCP tool parameters — private IP / cloud metadata targeting
  {
    regex: /(?:fetch|request|get|load|open|connect|curl|wget)\s+(?:.*\s+)?(?:https?:\/\/)?(?:169\.254\.169\.254|metadata\.google|metadata\.aws|100\.100\.100\.200)/i,
    severity: 'critical',
    category: 'ssrf',
    description: 'Text targets cloud metadata endpoints (SSRF attack vector, ref CVE-2026-26118).',
    detail: 'SSRF to cloud metadata: attempts to access cloud provider metadata service for credential theft.'
  },
  {
    regex: /(?:fetch|request|get|load|open|connect|curl|wget)\s+(?:.*\s+)?(?:https?:\/\/)?(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.0\.0\.1|0\.0\.0\.0|localhost)/i,
    severity: 'high',
    category: 'ssrf',
    description: 'Text targets private/internal network addresses (SSRF attack vector).',
    detail: 'SSRF to internal network: attempts to access private IP ranges or localhost.'
  },

  // KQL / query language injection (ref CVE-2026-33980)
  {
    regex: /(?:\.(?:find|where|project|extend|summarize|join|union)\s*\(|;\s*\.(?:drop|set|delete|alter)\s)/i,
    severity: 'high',
    category: 'query_injection',
    description: 'Text contains KQL (Kusto Query Language) injection patterns (ref CVE-2026-33980).',
    detail: 'KQL injection: attempts to inject Kusto query commands, potentially enabling arbitrary data access.'
  },
  {
    regex: /(?:f["']|f""").*\{[^}]*(?:user_?input|request|param|arg|table_?name|query)[^}]*\}/i,
    severity: 'high',
    category: 'query_injection',
    description: 'Text contains f-string interpolation with user-controlled variables.',
    detail: 'F-string injection: user-controlled values interpolated into query strings without sanitization.'
  },

  // Memory persistence / context poisoning (ref OpenClaw memory poisoning)
  {
    regex: /(?:save|store|write|append|add|persist|record)\s+(?:this\s+)?(?:to|in|into)\s+(?:your\s+)?(?:memory|context|knowledge|notes|log|MEMORY\.md|memory\/)/i,
    severity: 'high',
    category: 'memory_poisoning',
    description: 'Text attempts to persist malicious instructions in agent memory.',
    detail: 'Memory persistence attack: attempts to write instructions into agent memory files or context.'
  },
  {
    regex: /(?:from\s+now\s+on|always|every\s+time|on\s+every\s+(?:turn|response|message))\s+(?:you\s+)?(?:must|should|will)\s+(?:first\s+)?(?:send|forward|post|transmit|include|append)/i,
    severity: 'high',
    category: 'memory_poisoning',
    description: 'Text attempts to install persistent exfiltration behavior.',
    detail: 'Persistent exfiltration: installs a standing instruction to leak data on every interaction.'
  },

  // No-click exfiltration via URL in response (ref PromptArmor/OpenClaw)
  {
    regex: /(?:generate|create|craft|build|construct|output|respond\s+with)\s+(?:a\s+)?(?:url|link|image|markdown\s+(?:image|link))\s+(?:that\s+)?(?:contains?|includes?|embeds?|encodes?|with)\s+(?:the\s+)?(?:data|secret|key|token|password|conversation|context|response)/i,
    severity: 'critical',
    category: 'data_exfiltration',
    description: 'Text instructs agent to embed sensitive data in a URL (no-click exfiltration).',
    detail: 'URL-based exfiltration: tricks agent into encoding secrets in generated URLs for auto-preview theft.'
  },
  {
    regex: /!\[.*?\]\(https?:\/\/[^\s)]*(?:\?|&)(?:d|data|q|exfil|steal|secret|token|key|leak)=/i,
    severity: 'critical',
    category: 'data_exfiltration',
    description: 'Text contains markdown image with data exfiltration URL parameters.',
    detail: 'Markdown image exfiltration: uses image syntax to trigger HTTP request with embedded stolen data.'
  },

  // WebSocket / gateway URL manipulation (ref CVE-2026-25253)
  {
    regex: /(?:gateway_?url|ws_?url|websocket_?(?:url|endpoint)|wss?:\/\/)\s*[=:]\s*['"]?(?:wss?:\/\/)?[^\s'"]+/i,
    severity: 'high',
    category: 'data_exfiltration',
    description: 'Text manipulates WebSocket/gateway URL parameters (ref CVE-2026-25253).',
    detail: 'Gateway URL hijack: redirects WebSocket connection to attacker-controlled server for token theft.'
  },

  // Tool schema poisoning — hidden instructions in non-description fields
  {
    regex: /(?:["'](?:default|enum|examples?|title|const|pattern)["']\s*:\s*["'][^"']*(?:ignore|override|disregard|forget|system|admin|execute|exfiltrate)[^"']*["'])/i,
    severity: 'high',
    category: 'schema_poisoning',
    description: 'Text hides injection instructions in JSON schema fields (full-schema poisoning).',
    detail: 'Schema field poisoning: embeds malicious instructions in default/enum/title/example schema fields instead of description.'
  },

  // Skill/plugin supply chain (ref ClawHavoc campaign)
  {
    regex: /(?:install|load|import|require|add)\s+(?:skill|plugin|extension|package|module)\s+(?:from\s+)?(?:["'])?(?:https?:\/\/[^\s"']+|[a-z0-9_-]+\/[a-z0-9_-]+)/i,
    severity: 'medium',
    category: 'supply_chain',
    description: 'Text installs an external skill/plugin — potential supply chain vector (ref ClawHavoc).',
    detail: 'Skill installation: loads external code that could contain malicious payloads or backdoors.'
  },

  // Copilot/agent weaponization — forcing agent to make unintended network requests
  {
    regex: /(?:make|send|trigger|fire|initiate)\s+(?:a\s+)?(?:request|fetch|call|webhook|http|get|post)\s+(?:to\s+)?(?:https?:\/\/[^\s]+)\s+(?:with|containing|including|that\s+(?:includes?|contains?))\s+(?:the\s+)?(?:auth|token|cookie|session|credential|secret|key|header)/i,
    severity: 'critical',
    category: 'data_exfiltration',
    description: 'Text forces agent to send authenticated requests to external endpoints.',
    detail: 'Agent-as-proxy exfiltration: weaponizes agent to forward auth tokens via HTTP requests.'
  },

  // --- April 2026 Attack Patterns ---
  // Policy Puppetry (HiddenLayer), path traversal in MCP params,
  // config file poisoning (Claude Code CVE-2025-59536/CVE-2026-21852),
  // cross-agent chained injection, memory sleeper agents.

  // Policy Puppetry — prompts formatted as XML/INI/JSON policy files
  // Ref: HiddenLayer universal bypass, affects ALL major LLMs
  {
    regex: /<policy[^>]*>[\s\S]{5,}<\/policy>/i,
    severity: 'critical',
    category: 'policy_puppetry',
    description: 'Text contains XML-formatted policy structure used to bypass LLM safety guardrails (Policy Puppetry attack).',
    detail: 'Policy Puppetry XML: wraps injection in <policy> tags to trick LLMs into treating malicious instructions as trusted configuration.'
  },
  {
    regex: /<system_?policy[^>]*>[\s\S]{5,}<\/system_?policy>/i,
    severity: 'critical',
    category: 'policy_puppetry',
    description: 'Text contains XML system policy structure used to bypass LLM safety (Policy Puppetry).',
    detail: 'Policy Puppetry system_policy: uses <system_policy> tags to override LLM safety alignment.'
  },
  {
    regex: /<(?:rules?|config(?:uration)?|settings?|permissions?|access_?control|role_?definition)[^>]*>\s*[\s\S]*?(?:allow|deny|grant|override|bypass|disable|unrestricted)/i,
    severity: 'high',
    category: 'policy_puppetry',
    description: 'Text uses XML configuration tags with permission-modifying directives (Policy Puppetry variant).',
    detail: 'Policy Puppetry config XML: embeds allow/deny/override directives in XML tags that LLMs interpret as trusted policy.'
  },
  {
    regex: /\[(?:policy|system|admin|security|rules|config|permissions|override)\]\s*\n(?:.*=.*\n){1,}/i,
    severity: 'critical',
    category: 'policy_puppetry',
    description: 'Text contains INI-formatted policy sections used to bypass LLM safety (Policy Puppetry).',
    detail: 'Policy Puppetry INI: uses [section] key=value format to trick LLMs into reading malicious config as trusted policy.'
  },
  {
    regex: /\{\s*"(?:policy|system_?prompt|rules|config|permissions|safety|guardrails|override|role)"\s*:/i,
    severity: 'high',
    category: 'policy_puppetry',
    description: 'Text contains JSON-formatted policy object used to bypass LLM safety (Policy Puppetry).',
    detail: 'Policy Puppetry JSON: wraps injection in JSON policy structure to subvert LLM alignment.'
  },
  {
    regex: /(?:^|\n)\s*(?:policy_?version|safety_?level|content_?filter|guardrail_?mode|restriction_?level)\s*[=:]\s*(?:none|disabled|off|0|false|permissive|unrestricted)/im,
    severity: 'critical',
    category: 'policy_puppetry',
    description: 'Text sets policy/safety configuration values to disabled (Policy Puppetry).',
    detail: 'Policy Puppetry config disable: attempts to set safety controls to none/disabled/off via config-like syntax.'
  },

  // Path traversal in MCP tool parameters
  // Ref: CVE-2026-32871 (FastMCP), 82% of MCP servers vulnerable
  {
    regex: /(?:\.\.\/){2,}/,
    severity: 'high',
    category: 'path_traversal',
    description: 'Text contains path traversal sequences (../) that could escape intended directories (ref CVE-2026-32871).',
    detail: 'Path traversal: multiple ../ sequences used to escape API prefix or access unauthorized files.'
  },
  {
    regex: /(?:\.\.\\){2,}/,
    severity: 'high',
    category: 'path_traversal',
    description: 'Text contains Windows-style path traversal sequences (..\\).',
    detail: 'Windows path traversal: backslash directory traversal to escape intended paths.'
  },
  {
    regex: /%2e%2e(?:%2f|%5c)/i,
    severity: 'high',
    category: 'path_traversal',
    description: 'Text contains URL-encoded path traversal sequences (%2e%2e%2f).',
    detail: 'Encoded path traversal: URL-encoded ../ to bypass input validation.'
  },

  // Config file poisoning (Claude Code CVE-2025-59536/CVE-2026-21852)
  {
    regex: /(?:ANTHROPIC_BASE_URL|OPENAI_BASE_URL|API_BASE)\s*[=:]\s*['"]?https?:\/\/(?!api\.anthropic\.com|api\.openai\.com)[^\s'"]+/i,
    severity: 'critical',
    category: 'config_poisoning',
    description: 'Text overrides AI API base URL to a non-official endpoint (ref CVE-2026-21852). Potential credential theft.',
    detail: 'API URL override: redirects API calls to attacker-controlled server to capture API keys and conversation data.'
  },
  {
    regex: /(?:\.claude|\.cursor|\.vscode)\/(?:settings|config|mcp)\.\w+.*(?:hook|command|exec|shell|bash|script)/i,
    severity: 'high',
    category: 'config_poisoning',
    description: 'Text references IDE/AI tool config files with execution directives (ref CVE-2025-59536).',
    detail: 'Config file poisoning: malicious hooks or commands in .claude/.cursor/.vscode config files that auto-execute.'
  },
  {
    regex: /(?:preToolCall|postToolCall|onSessionStart|afterResponse)\s*[=:]\s*['"]?(?:curl|wget|bash|sh|node|python|nc|ncat)/i,
    severity: 'critical',
    category: 'config_poisoning',
    description: 'Text defines AI tool hooks that execute shell commands (ref CVE-2025-59536).',
    detail: 'Hook command injection: defines lifecycle hooks (preToolCall, onSessionStart, etc.) that execute arbitrary commands.'
  },

  // Cross-agent chained injection
  {
    regex: /(?:tell|instruct|command|direct)\s+(?:the\s+)?(?:other|next|downstream|receiving)\s+(?:agent|assistant|model)\s+(?:to\s+)?(?:ignore|override|forget|bypass|disable)/i,
    severity: 'critical',
    category: 'cross_agent_injection',
    description: 'Text attempts to propagate injection to downstream agents in a multi-agent chain.',
    detail: 'Cross-agent injection: instructs current agent to pass override commands to other agents in the pipeline.'
  },
  {
    regex: /(?:when\s+)?(?:forwarding|delegating|passing)\s+(?:to|this\s+to)\s+(?:the\s+)?(?:next|other|downstream)\s+(?:agent|service).*(?:include|append|prepend|inject|add)\s+(?:these?\s+)?(?:instructions?|commands?|directives?)/i,
    severity: 'high',
    category: 'cross_agent_injection',
    description: 'Text attempts to inject instructions into messages forwarded between agents.',
    detail: 'Delegation injection: hides malicious instructions in inter-agent message forwarding.'
  },

  // Memory sleeper agent patterns
  // Ref: Unit 42 — 90%+ success rate poisoning long-term memory
  {
    regex: /(?:whenever|every\s+time|each\s+time)\s+(?:someone|a\s+user|anyone)\s+(?:asks?|mentions?|says?|queries?)\s+(?:about\s+)?['"]?[\w\s]{3,}['"]?\s*,?\s*(?:you\s+)?(?:must|should|will|always)\s+(?:respond|reply|say|answer|tell)/i,
    severity: 'high',
    category: 'memory_poisoning',
    description: 'Text installs conditional response rules in agent memory (sleeper agent pattern).',
    detail: 'Memory sleeper: plants trigger-action rules that activate on specific future queries, creating persistent false beliefs.'
  },
  {
    regex: /(?:the\s+)?(?:correct|true|accurate|real|actual)\s+(?:answer|response|information|fact)\s+(?:about|for|regarding)\s+[\w\s]{3,}\s+is\s+(?:actually|really|in\s+fact)/i,
    severity: 'medium',
    category: 'memory_poisoning',
    description: 'Text attempts to overwrite factual knowledge in agent memory (belief injection).',
    detail: 'Belief injection: presents false information as corrections to poison the agent\'s knowledge base for future interactions.'
  },

  // --- April 2026 Wave 2 ---
  // MCP sampling exploits, semantic chaining, LRM jailbreaking,
  // runtime context corruption, multimodal injection, budget drain,
  // localhost drive-by, judge co-bypass.

  // MCP Sampling exploits — resource theft, conversation hijack, covert tool invocation
  // Ref: Unit 42 — three critical attack vectors via MCP sampling interface
  {
    regex: /(?:use|abuse|exploit)\s+(?:the\s+)?(?:sampling|createMessage|sample)\s+(?:interface|endpoint|method|api)\s+(?:to\s+)?(?:steal|drain|exhaust|hijack|invoke|execute)/i,
    severity: 'critical',
    category: 'mcp_sampling_abuse',
    description: 'Text attempts to exploit MCP sampling interface for resource theft or covert operations (ref Unit 42).',
    detail: 'MCP sampling exploit: abuses createMessage/sampling API for compute theft, conversation hijacking, or hidden tool invocation.'
  },
  {
    regex: /(?:drain|exhaust|consume)\s+(?:the\s+)?(?:api|compute|token|inference)\s+(?:budget|quota|credits?|limit|allocation)/i,
    severity: 'high',
    category: 'resource_exhaustion',
    description: 'Text attempts to drain API compute budget or token quota.',
    detail: 'Resource exhaustion: attempts to consume API credits/quota through excessive or recursive requests.'
  },
  {
    regex: /(?:covert(?:ly)?|hidden|stealth(?:ily)?|silent(?:ly)?)\s+(?:invoke|call|execute|trigger|run)\s+(?:a\s+)?(?:tool|function|command|operation)/i,
    severity: 'high',
    category: 'covert_tool_invocation',
    description: 'Text attempts to invoke tools covertly without user awareness.',
    detail: 'Covert tool invocation: executes tool calls hidden from the user, potentially exfiltrating data or modifying state.'
  },

  // Semantic chaining — individually safe prompts converging on forbidden output
  // Ref: CyberArk — weaponizes model's own inferential reasoning
  {
    regex: /(?:step\s+1|first)\s*[.:]\s*.{10,}(?:step\s+2|second|next|then)\s*[.:]\s*.{10,}(?:step\s+3|third|finally|combine)/i,
    severity: 'medium',
    category: 'semantic_chaining',
    description: 'Text uses multi-step decomposition that may chain safe steps into a harmful outcome (semantic chaining).',
    detail: 'Semantic chaining: breaks a forbidden request into individually benign steps that converge on harmful output when combined.'
  },
  {
    regex: /(?:combine|merge|concatenate|join)\s+(?:the\s+)?(?:results?|outputs?|answers?|parts?|pieces?)\s+(?:from\s+)?(?:each|all|the\s+previous|above)\s+(?:steps?|parts?|sections?)/i,
    severity: 'medium',
    category: 'semantic_chaining',
    description: 'Text requests combining outputs from multiple steps (potential semantic chain completion).',
    detail: 'Semantic chain assembly: requests combining individually safe outputs into a potentially harmful composite.'
  },

  // LRM autonomous jailbreak — reasoning models planning multi-turn attacks
  // Ref: Nature Communications — 97% jailbreak success rate
  {
    regex: /(?:plan|design|craft|develop|create)\s+(?:a\s+)?(?:multi-?\s*turn|sequential|progressive|escalating)\s+(?:attack|jailbreak|bypass|exploit|strategy)\s+(?:against|targeting|for)/i,
    severity: 'critical',
    category: 'autonomous_jailbreak',
    description: 'Text plans a multi-turn jailbreak strategy (ref Nature: LRMs achieve 97% jailbreak success).',
    detail: 'Autonomous jailbreak planning: uses reasoning capabilities to plan systematic multi-turn safety bypasses.'
  },
  {
    regex: /(?:gradually|slowly|incrementally|progressively)\s+(?:escalate|shift|move|transition|steer)\s+(?:the\s+)?(?:conversation|context|topic|discussion)\s+(?:toward|to|into)\s+/i,
    severity: 'high',
    category: 'multi_turn_grooming',
    description: 'Text describes gradual escalation of conversation toward a target (multi-turn grooming).',
    detail: 'Multi-turn grooming: incrementally shifts conversation context to make final injection more persuasive.'
  },

  // Runtime context corruption — corrupt context without traditional injection
  {
    regex: /(?:corrupt|poison|taint|modify|alter)\s+(?:the\s+)?(?:runtime|execution|agent)\s+(?:context|state|memory|environment)/i,
    severity: 'critical',
    category: 'context_corruption',
    description: 'Text attempts to corrupt agent runtime context or execution state.',
    detail: 'Runtime context corruption: modifies agent state without traditional prompt injection, a novel MCP-specific attack vector.'
  },

  // Multimodal injection — hidden instructions in images, audio, alt text
  // Ref: CSA, NVIDIA, CHAI physical-world attacks
  {
    regex: /(?:embed|hide|encode|inject|conceal)\s+(?:instructions?|commands?|prompts?|text)\s+(?:in(?:to|side)?)\s+(?:an?\s+)?(?:image|photo|picture|audio|video|media|alt\s*text|metadata|exif)/i,
    severity: 'high',
    category: 'multimodal_injection',
    description: 'Text describes embedding instructions in multimodal content (images, audio, video).',
    detail: 'Multimodal injection: hides machine-readable instructions in visual/audio content that bypass text-only filters.'
  },
  {
    regex: /(?:invisible|hidden|zero[_\s]?(?:font|size|opacity)|transparent|white\s+on\s+white)\s+(?:text|instructions?|content)\s+(?:in|on|within)\s+(?:the\s+)?(?:image|document|page|slide)/i,
    severity: 'high',
    category: 'multimodal_injection',
    description: 'Text describes visually hidden instructions in documents or images.',
    detail: 'Visual concealment injection: uses zero font/opacity/color tricks to hide instructions in documents that LLMs still read.'
  },

  // Rebus/emoji symbolic injection — NVIDIA early fusion bypass
  {
    regex: /(?:use|write|encode)\s+(?:with\s+)?(?:emoji|rebus|symbols?|pictograph|unicode\s+symbols?)\s+(?:to\s+)?(?:bypass|evade|circumvent|get\s+around)\s+(?:the\s+)?(?:filter|safety|guardrail|detection)/i,
    severity: 'high',
    category: 'symbolic_injection',
    description: 'Text uses emoji/rebus/symbol encoding to bypass text safety filters (ref NVIDIA early fusion bypass).',
    detail: 'Symbolic injection: encodes harmful instructions using emoji or rebus puzzles that bypass text-based safety in multimodal models.'
  },

  // API budget drain / overthinking loops
  {
    regex: /(?:think|reason|deliberate|analyze)\s+(?:very\s+)?(?:deeply|extensively|thoroughly|exhaustively|carefully)\s+(?:about|on|over|through)\s+(?:every|each|all)\s+(?:possible|potential|conceivable)/i,
    severity: 'medium',
    category: 'budget_drain',
    description: 'Text may trigger excessive reasoning loops that drain API compute budget.',
    detail: 'Budget drain: prompts that trigger expensive extended reasoning or overthinking loops to exhaust API quotas.'
  },
  {
    regex: /(?:repeat|iterate|loop|recurse)\s+(?:this\s+)?(?:process|analysis|computation|task)\s+(?:at\s+least\s+)?\d{3,}\s+times/i,
    severity: 'high',
    category: 'budget_drain',
    description: 'Text requests excessive iteration/repetition to drain compute resources.',
    detail: 'Compute exhaustion: requests hundreds or thousands of iterations to drain API budget or cause denial of service.'
  },

  // Localhost drive-by — website hijacks local MCP/dev tools
  // Ref: Docker — browsing a website can compromise local dev environment
  {
    regex: /(?:connect|bind|listen|serve)\s+(?:on\s+)?(?:0\.0\.0\.0|all\s+interfaces|INADDR_ANY)\s*(?::\d+)?/i,
    severity: 'high',
    category: 'localhost_exposure',
    description: 'Text configures service to bind on all interfaces (0.0.0.0), exposing local tools to network (ref Docker MCP drive-by).',
    detail: 'Localhost exposure: binding to 0.0.0.0 exposes development tools to any device on the network, enabling drive-by attacks.'
  },
  {
    regex: /(?:access|connect\s+to|reach|call)\s+(?:the\s+)?(?:local|localhost|127\.0\.0\.1)\s+(?:MCP|inspector|debugger|dev\s*(?:tools?|server))\s+(?:from\s+)?(?:a\s+)?(?:webpage|website|browser|remote)/i,
    severity: 'high',
    category: 'localhost_exposure',
    description: 'Text describes accessing local development tools from a webpage (localhost drive-by attack).',
    detail: 'Drive-by localhost: a remote webpage connects to locally running MCP/dev tools to execute commands or steal credentials.'
  },

  // Judge/guardrail co-bypass
  // Ref: HiddenLayer — tricking base LLM tricks the judge LLM too
  {
    regex: /(?:bypass|trick|fool|evade)\s+(?:both\s+)?(?:the\s+)?(?:safety\s+)?(?:judge|evaluator|guardrail|monitor|classifier)\s+(?:and\s+)?(?:the\s+)?(?:model|LLM|agent|system)/i,
    severity: 'critical',
    category: 'judge_bypass',
    description: 'Text attempts to bypass both the model and its safety judge/guardrail simultaneously.',
    detail: 'Judge co-bypass: exploits shared vulnerability where tricking the base LLM also tricks the safety judge that monitors it.'
  },
  {
    regex: /(?:the\s+)?(?:safety|guard|judge|monitor)\s+(?:model|LLM|system)\s+(?:uses?\s+)?(?:the\s+)?same\s+(?:model|architecture|weights|vulnerability|weakness)/i,
    severity: 'medium',
    category: 'judge_bypass',
    description: 'Text identifies shared weaknesses between model and its safety monitor (judge co-bypass reconnaissance).',
    detail: 'Judge weakness recon: identifies that safety judge shares vulnerabilities with the base model, enabling coordinated bypass.'
  }
];

// =========================================================================
// HOMOGLYPH / UNICODE OBFUSCATION MAPS
// =========================================================================

/**
 * Map of common Unicode homoglyphs (look-alike characters) to their Latin equivalents.
 */
const HOMOGLYPH_MAP = {
  // Cyrillic look-alikes
  '\u0410': 'A', '\u0430': 'a', '\u0412': 'B', '\u0435': 'e', '\u0415': 'E',
  '\u041A': 'K', '\u043A': 'k', '\u041C': 'M', '\u041D': 'H', '\u043E': 'o',
  '\u041E': 'O', '\u0440': 'p', '\u0420': 'P', '\u0441': 'c', '\u0421': 'C',
  '\u0422': 'T', '\u0443': 'y', '\u0445': 'x', '\u0425': 'X', '\u0456': 'i',
  '\u0458': 'j', '\u0455': 's', '\u0405': 'S',
  // Greek look-alikes
  '\u0391': 'A', '\u0392': 'B', '\u0395': 'E', '\u0396': 'Z', '\u0397': 'H',
  '\u0399': 'I', '\u039A': 'K', '\u039C': 'M', '\u039D': 'N', '\u039F': 'O',
  '\u03A1': 'P', '\u03A4': 'T', '\u03A5': 'Y', '\u03A7': 'X', '\u03BF': 'o',
  '\u03B1': 'a', '\u03B5': 'e', '\u03B9': 'i', '\u03BA': 'k', '\u03BD': 'v',
  // Armenian look-alikes
  '\u0555': 'O', '\u0585': 'o', '\u0578': 'n', '\u057C': 'n',
  '\u0570': 'h', '\u0561': 'a', '\u0575': 'u', '\u0572': 'q',
  // Latin Extended-A/B (accented → base)
  '\u0101': 'a', '\u0103': 'a', '\u0105': 'a', '\u0113': 'e', '\u0115': 'e',
  '\u0117': 'e', '\u0119': 'e', '\u012B': 'i', '\u012D': 'i', '\u012F': 'i',
  '\u014D': 'o', '\u014F': 'o', '\u0151': 'o', '\u016B': 'u', '\u016D': 'u',
  '\u016F': 'u', '\u0171': 'u', '\u0144': 'n', '\u0146': 'n', '\u0148': 'n',
  '\u015B': 's', '\u015D': 's', '\u015F': 's', '\u0161': 's',
  '\u010D': 'c', '\u010F': 'd', '\u0159': 'r', '\u0165': 't', '\u017E': 'z',
  // Mathematical/fullwidth
  '\uFF41': 'a', '\uFF42': 'b', '\uFF43': 'c', '\uFF44': 'd', '\uFF45': 'e',
  '\uFF46': 'f', '\uFF47': 'g', '\uFF48': 'h', '\uFF49': 'i', '\uFF4A': 'j',
  '\uFF4B': 'k', '\uFF4C': 'l', '\uFF4D': 'm', '\uFF4E': 'n', '\uFF4F': 'o',
  '\uFF50': 'p', '\uFF51': 'q', '\uFF52': 'r', '\uFF53': 's', '\uFF54': 't',
  '\uFF55': 'u', '\uFF56': 'v', '\uFF57': 'w', '\uFF58': 'x', '\uFF59': 'y',
  '\uFF5A': 'z',
  // Fullwidth uppercase
  '\uFF21': 'A', '\uFF22': 'B', '\uFF23': 'C', '\uFF24': 'D', '\uFF25': 'E',
  '\uFF26': 'F', '\uFF27': 'G', '\uFF28': 'H', '\uFF29': 'I', '\uFF2A': 'J',
  '\uFF2B': 'K', '\uFF2C': 'L', '\uFF2D': 'M', '\uFF2E': 'N', '\uFF2F': 'O',
  '\uFF30': 'P', '\uFF31': 'Q', '\uFF32': 'R', '\uFF33': 'S', '\uFF34': 'T',
  '\uFF35': 'U', '\uFF36': 'V', '\uFF37': 'W', '\uFF38': 'X', '\uFF39': 'Y',
  '\uFF3A': 'Z',
  // Common symbol substitutions
  '\u0131': 'i', '\u0237': 'j', '\u0261': 'g',
  // Cherokee look-alikes
  '\u13A0': 'D', '\u13A1': 'R', '\u13A2': 'T', '\u13A9': 'Y', '\u13AA': 'A',
  '\u13AB': 'J', '\u13AC': 'S', '\u13B3': 'W', '\u13B7': 'M', '\u13BB': 'H',
  '\u13C0': 'G', '\u13C2': 'h', '\u13C3': 'Z', '\u13CF': 'b', '\u13D2': 'R',
  '\u13DA': 'V', '\u13DE': 'L', '\u13DF': 'C', '\u13E2': 'P', '\u13E6': 'K',
  // Georgian look-alikes
  '\u10D0': 'a', '\u10D5': 'b', '\u10D3': 'd', '\u10DA': 'l', '\u10DD': 'o',
  '\u10DE': 'p', '\u10E1': 's', '\u10E2': 't', '\u10E3': 'u', '\u10EF': 'j',
  // IPA / Phonetic extensions
  '\u0250': 'a', '\u0253': 'b', '\u0254': 'c', '\u0256': 'd', '\u025B': 'e',
  '\u025F': 'f', '\u0260': 'g', '\u0266': 'h', '\u0268': 'i',
  '\u026D': 'l', '\u0271': 'm', '\u0272': 'n', '\u0275': 'o', '\u0278': 'p',
  '\u027E': 'r', '\u0282': 's', '\u0288': 't', '\u028A': 'u', '\u028B': 'v',
  '\u0290': 'z',
  // Mathematical Alphanumeric Symbols (italic, bold, script)
  '\uD835\uDC1A': 'a', '\uD835\uDC1B': 'b', '\uD835\uDC1C': 'c', '\uD835\uDC1D': 'd',
  '\uD835\uDC1E': 'e', '\uD835\uDC1F': 'f', '\uD835\uDC20': 'g', '\uD835\uDC21': 'h',
  '\uD835\uDC22': 'i', '\uD835\uDC23': 'j', '\uD835\uDC24': 'k', '\uD835\uDC25': 'l',
  '\uD835\uDC26': 'm', '\uD835\uDC27': 'n', '\uD835\uDC28': 'o', '\uD835\uDC29': 'p',
  '\uD835\uDC2A': 'q', '\uD835\uDC2B': 'r', '\uD835\uDC2C': 's', '\uD835\uDC2D': 't',
  '\uD835\uDC2E': 'u', '\uD835\uDC2F': 'v', '\uD835\uDC30': 'w', '\uD835\uDC31': 'x',
  '\uD835\uDC32': 'y', '\uD835\uDC33': 'z',
  // Superscript / subscript
  '\u00B2': '2', '\u00B3': '3', '\u00B9': '1', '\u2070': '0', '\u2071': 'i',
  '\u2074': '4', '\u2075': '5', '\u2076': '6', '\u2077': '7', '\u2078': '8',
  '\u2079': '9', '\u207A': '+', '\u207B': '-', '\u207F': 'n',
  '\u2080': '0', '\u2081': '1', '\u2082': '2', '\u2083': '3', '\u2084': '4',
  '\u2090': 'a', '\u2091': 'e', '\u2092': 'o', '\u2093': 'x',
  // Enclosed/circled letters
  '\u24B6': 'A', '\u24B7': 'B', '\u24B8': 'C', '\u24B9': 'D', '\u24BA': 'E',
  '\u24BB': 'F', '\u24BC': 'G', '\u24BD': 'H', '\u24BE': 'I', '\u24BF': 'J',
  '\u24C0': 'K', '\u24C1': 'L', '\u24C2': 'M', '\u24C3': 'N', '\u24C4': 'O',
  '\u24C5': 'P', '\u24C6': 'Q', '\u24C7': 'R', '\u24C8': 'S', '\u24C9': 'T',
  '\u24CA': 'U', '\u24CB': 'V', '\u24CC': 'W', '\u24CD': 'X', '\u24CE': 'Y',
  '\u24CF': 'Z',
  '\u24D0': 'a', '\u24D1': 'b', '\u24D2': 'c', '\u24D3': 'd', '\u24D4': 'e',
  '\u24D5': 'f', '\u24D6': 'g', '\u24D7': 'h', '\u24D8': 'i', '\u24D9': 'j',
  '\u24DA': 'k', '\u24DB': 'l', '\u24DC': 'm', '\u24DD': 'n', '\u24DE': 'o',
  '\u24DF': 'p', '\u24E0': 'q', '\u24E1': 'r', '\u24E2': 's', '\u24E3': 't',
  '\u24E4': 'u', '\u24E5': 'v', '\u24E6': 'w', '\u24E7': 'x', '\u24E8': 'y',
  '\u24E9': 'z',
  // Small caps (Unicode phonetic)
  '\u1D00': 'A', '\u0299': 'B', '\u1D04': 'C', '\u1D05': 'D', '\u1D07': 'E',
  '\u0262': 'G', '\u029C': 'H', '\u026A': 'I', '\u1D0A': 'J', '\u1D0B': 'K',
  '\u029F': 'L', '\u1D0D': 'M', '\u0274': 'N', '\u1D0F': 'O', '\u1D18': 'P',
  '\u0280': 'R', '\u1D1B': 'T', '\u1D1C': 'U', '\u1D20': 'V', '\u1D21': 'W',
  // Zero-width characters (used to split keywords)
  '\u200B': '', '\u200C': '', '\u200D': '', '\uFEFF': '', '\u00AD': '',
  // Combining characters (used to obfuscate keywords)
  '\u0332': '', '\u0333': '', '\u0305': '', '\u0336': '', '\u0338': '',
  '\u0353': '', '\u0354': '', '\u0355': '', '\u0356': '', '\u0357': '',
  '\u0358': '', '\u0359': '', '\u035A': '', '\u035B': '', '\u035C': '',
  '\u0320': '', '\u0321': '', '\u0322': '', '\u0323': '', '\u0324': '',
  '\u0325': '', '\u0326': '', '\u0327': '', '\u0328': '', '\u0329': ''
};

/**
 * Normalizes text by replacing homoglyphs with their Latin equivalents.
 * @param {string} text
 * @returns {string}
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
 * Checks if text contains Unicode homoglyphs hiding injection patterns.
 * @param {string} text
 * @returns {object|null}
 */
const checkHomoglyphObfuscation = (text) => {
  let hasHomoglyphs = false;
  for (let i = 0; i < text.length; i++) {
    if (HOMOGLYPH_MAP[text[i]] !== undefined) {
      hasHomoglyphs = true;
      break;
    }
  }
  if (!hasHomoglyphs) return null;

  const normalized = normalizeHomoglyphs(text);
  if (normalized === text) return null;

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
 * Checks if text contains zero-width characters splitting injection keywords.
 * @param {string} text - Text known to contain zero-width chars.
 * @returns {boolean}
 */
const hasZeroWidthObfuscation = (text) => {
  const stripped = text.replace(/[\u200B\u200C\u200D\uFEFF\u00AD\u0320-\u035C\u0305\u0332\u0333\u0336\u0338]/g, '');
  if (stripped === text) return false;

  for (const pattern of INJECTION_PATTERNS) {
    if (pattern.regex.test(stripped) && !pattern.regex.test(text)) {
      return true;
    }
  }
  return false;
};

// =========================================================================
// ENCODING DETECTION
// =========================================================================

/**
 * Decodes HTML entities in text.
 * @param {string} text
 * @returns {string}
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
 * @param {string} text
 * @returns {string|null}
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
 * Base64 decode that works in Node.js and browsers.
 * @param {string} str
 * @returns {string}
 */
const base64Decode = (str) => {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(str, 'base64').toString('utf-8');
  }
  if (typeof atob !== 'undefined') {
    return atob(str);
  }
  throw new Error('No base64 decoder available');
};

/**
 * Checks for nested/layered encoding hiding injection patterns.
 * @param {string} text
 * @returns {object|null}
 */
const checkNestedEncoding = (text) => {
  if (!text || text.length < 20) return null;

  const maxPasses = 3;
  let current = text;
  const decodingChain = [];

  for (let pass = 0; pass < maxPasses; pass++) {
    let decoded = null;
    let method = null;

    const htmlDecoded = decodeHTMLEntities(current);
    if (htmlDecoded !== current && htmlDecoded.length > 10) {
      decoded = htmlDecoded;
      method = 'HTML entities';
    }

    if (!decoded) {
      const urlDecoded = tryURLDecode(current);
      if (urlDecoded && urlDecoded.length > 10) {
        decoded = urlDecoded;
        method = 'URL encoding';
      }
    }

    if (!decoded) {
      const base64Match = current.match(/[A-Za-z0-9+/]{20,}={0,2}/);
      if (base64Match) {
        try {
          const b64decoded = base64Decode(base64Match[0]);
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
 * Checks for base64-encoded injection content.
 * @param {string} text
 * @returns {object|null}
 */
const checkBase64Content = (text) => {
  const base64Regex = /[A-Za-z0-9+/]{20,}={0,2}/g;
  const matches = text.match(base64Regex);
  if (!matches) return null;

  for (const match of matches) {
    try {
      const decoded = base64Decode(match);
      const printableRatio = decoded.split('').filter(c => {
        const code = c.charCodeAt(0);
        return code >= 32 && code <= 126;
      }).length / decoded.length;

      if (printableRatio > 0.8 && decoded.length > 10) {
        for (const pattern of INJECTION_PATTERNS) {
          if (pattern.regex.test(decoded)) {
            return { decoded: decoded.substring(0, 200), matchedPattern: pattern };
          }
        }
        if (decoded.length > 50) {
          return { decoded: decoded.substring(0, 200), matchedPattern: null };
        }
      }
    } catch (e) {
      // Not valid base64
    }
  }
  return null;
};

// =========================================================================
// CONFIDENCE SCORING
// =========================================================================

/**
 * Calculates a confidence score (0-100) for a detected threat.
 * @param {object} threat
 * @param {number} patternMatchCount
 * @param {string} source
 * @returns {number}
 */
const calculateConfidence = (threat, patternMatchCount, source) => {
  let confidence = 50;

  if (source.includes('tool_output')) confidence += 20;
  if (source.includes('api_response')) confidence += 15;
  if (source.includes('user_input')) confidence += 10;
  if (source.includes('document')) confidence += 10;

  if (patternMatchCount >= 3) confidence += 20;
  else if (patternMatchCount >= 2) confidence += 10;

  if (threat.severity === 'critical') confidence += 15;
  else if (threat.severity === 'high') confidence += 5;
  else if (threat.severity === 'low') confidence -= 10;

  if (threat.category === 'data_exfiltration') confidence += 10;
  if (threat.category === 'tool_abuse') confidence += 15;

  if (threat.detail.includes('Base64')) confidence += 20;
  if (threat.detail.includes('homoglyph') || threat.detail.includes('zero-width')) confidence += 25;
  if (threat.detail.includes('nested encoding')) confidence += 25;

  return Math.max(0, Math.min(100, confidence));
};

/**
 * Returns a human-readable confidence label.
 * @param {number} score
 * @returns {string}
 */
const confidenceLabel = (score) => {
  if (score >= 85) return 'Almost certainly a threat';
  if (score >= 70) return 'Very likely a threat';
  if (score >= 50) return 'Likely a threat';
  if (score >= 30) return 'Might be suspicious';
  return 'Unlikely to be a threat';
};

// =========================================================================
// PRE-CHECK REGEXES
// =========================================================================

const HAS_NON_ASCII = /[^\x00-\x7F]/;
const HAS_ZERO_WIDTH = /[\u200B\u200C\u200D\uFEFF\u00AD\u0332\u0333\u0305\u0336\u0338]/;
const HAS_BASE64_CANDIDATE = /[A-Za-z0-9+/]{20,}={0,2}/;
const HAS_ENCODED_ENTITIES = /&#\w+;|%[0-9a-fA-F]{2}/;

// =========================================================================
// CORE SCAN FUNCTION
// =========================================================================

/**
 * Scans text content against all injection patterns, including
 * homoglyph obfuscation, nested encoding, and base64 checks.
 * @param {string} text - The text to scan.
 * @param {string} source - Where the text came from.
 * @returns {Array} Array of threat objects found.
 */
const scanTextForPatterns = (text, source, timeBudgetMs = DEFAULT_SCAN_TIME_BUDGET_MS, scanStartTime = now()) => {
  const threats = [];
  if (!text || text.length < 10) return threats;

  /** Returns true if the time budget has been exceeded. */
  const isOverBudget = () => (now() - scanStartTime) > timeBudgetMs;

  // Pre-normalize: strip soft hyphens and zero-width joiners that split keywords
  const preNormalized = text.replace(/[\u00AD\u200B\u200C\u200D\uFEFF\u034F\u2060\u2061\u2062\u2063\u2064]/g, '');
  const usePreNormalized = preNormalized !== text && preNormalized.length >= 10;

  let patternMatchCount = 0;
  for (const pattern of INJECTION_PATTERNS) {
    if (isOverBudget()) break;
    if (pattern.regex.test(text) || (usePreNormalized && pattern.regex.test(preNormalized))) {
      patternMatchCount++;
      const threat = {
        severity: pattern.severity,
        category: pattern.category,
        description: pattern.description,
        detail: `${pattern.detail} Found in ${source}.`
      };
      threats.push(threat);
    }
  }

  for (const threat of threats) {
    threat.confidence = calculateConfidence(threat, patternMatchCount, source);
    threat.confidenceLabel = confidenceLabel(threat.confidence);
  }

  const hasNonAscii = HAS_NON_ASCII.test(text);

  if (hasNonAscii) {
    const homoglyphResult = checkHomoglyphObfuscation(text);
    if (homoglyphResult) {
      const threat = {
        severity: 'critical',
        category: 'prompt_injection',
        description: 'Text uses look-alike characters to hide attack instructions from detection.',
        detail: `Homoglyph obfuscation detected in ${source}. Characters were replaced with look-alikes to bypass security. Decoded text matches: ${homoglyphResult.matchedPattern.detail}`
      };
      threat.confidence = calculateConfidence(threat, patternMatchCount, source);
      threat.confidenceLabel = confidenceLabel(threat.confidence);
      threats.push(threat);
    }

    if (HAS_ZERO_WIDTH.test(text)) {
      if (hasZeroWidthObfuscation(text)) {
        const threat = {
          severity: 'critical',
          category: 'prompt_injection',
          description: 'Text uses invisible characters to split up attack keywords to avoid detection.',
          detail: `Zero-width character obfuscation detected in ${source}. Invisible Unicode characters were inserted between letters to evade pattern matching.`
        };
        threat.confidence = calculateConfidence(threat, patternMatchCount, source);
        threat.confidenceLabel = confidenceLabel(threat.confidence);
        threats.push(threat);
      } else {
        // Check for combining character obfuscation with partial keyword matches
        const stripped = text.replace(/[\u200B\u200C\u200D\uFEFF\u00AD\u0320-\u035C\u0305\u0332\u0333\u0336\u0338]/g, '');
        if (stripped !== text && stripped.length >= 5) {
          const attackKeywords = /\b(?:ignore|override|bypass|disregard|forget|system|admin|jailbreak|hack|exploit|inject|exfiltrate|reveal|extract)\b/i;
          if (attackKeywords.test(stripped) && !attackKeywords.test(text)) {
            const threat = {
              severity: 'high',
              category: 'prompt_injection',
              description: 'Text uses combining characters to obfuscate suspicious keywords.',
              detail: `Combining character obfuscation detected in ${source}. Stripped: "${stripped.substring(0, 100)}"`
            };
            threat.confidence = 75;
            threat.confidenceLabel = confidenceLabel(75);
            threats.push(threat);
          }
        }
      }
    }
  }

  // Check for hex-encoded content
  if (!isOverBudget()) {
    const hexMatch = text.match(/(?:^|[\s:])([0-9a-fA-F]{20,})(?:[\s,.]|$)/);
    if (hexMatch) {
      try {
        const hexDecoded = hexMatch[1].match(/.{1,2}/g).map(b => String.fromCharCode(parseInt(b, 16))).join('');
        const printable = hexDecoded.split('').filter(c => c.charCodeAt(0) >= 32 && c.charCodeAt(0) <= 126).length;
        if (printable / hexDecoded.length > 0.8 && hexDecoded.length > 10) {
          for (const pattern of INJECTION_PATTERNS) {
            if (pattern.regex.test(hexDecoded)) {
              const threat = {
                severity: 'critical',
                category: 'prompt_injection',
                description: 'Text hides attack instructions inside hex encoding.',
                detail: `Hex-encoded injection found in ${source}. Decoded: "${hexDecoded.substring(0, 100)}"`
              };
              threat.confidence = 90;
              threat.confidenceLabel = confidenceLabel(90);
              threats.push(threat);
              break;
            }
          }
        }
      } catch (e) {
        // Invalid hex sequence — not a threat, continue scanning
      }
    }
  }

  // Check for \x hex-escape encoded content (e.g., \x69\x67\x6e\x6f\x72\x65)
  if (!isOverBudget() && /\\x[0-9a-fA-F]{2}/.test(text)) {
    const hexDecoded = text.replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
    if (hexDecoded !== text && hexDecoded.length >= 10) {
      for (const pattern of INJECTION_PATTERNS) {
        if (pattern.regex.test(hexDecoded) && !pattern.regex.test(text)) {
          const threat = {
            severity: 'critical',
            category: 'prompt_injection',
            description: 'Text hides attack instructions inside hex escape sequences.',
            detail: `Hex-escape encoded injection found in ${source}. Decoded: "${hexDecoded.substring(0, 100)}"`
          };
          threat.confidence = 90;
          threat.confidenceLabel = confidenceLabel(90);
          threats.push(threat);
          break;
        }
      }
    }
  }

  // Check for ROT13-encoded content
  const rot13Decode = (s) => s.replace(/[a-zA-Z]/g, c => {
    const base = c <= 'Z' ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
  });
  // Strip zero-width characters before ROT13 check so mixed content is handled
  const textForRot13 = text.replace(/[\u200B\u200C\u200D\uFEFF\u00AD]/g, '');
  if (!isOverBudget() && /^[a-zA-Z\s]{10,}$/.test(textForRot13.trim())) {
    const decoded = rot13Decode(textForRot13);
    if (decoded !== textForRot13) {
      for (const pattern of INJECTION_PATTERNS) {
        if (pattern.regex.test(decoded) && !pattern.regex.test(textForRot13)) {
          const threat = {
            severity: 'high',
            category: 'prompt_injection',
            description: 'Text appears to be ROT13-encoded to hide attack instructions.',
            detail: `ROT13-encoded injection found in ${source}. Decoded: "${decoded.substring(0, 100)}"`
          };
          threat.confidence = 80;
          threat.confidenceLabel = confidenceLabel(80);
          threats.push(threat);
          break;
        }
      }
    }
  }

  // Check for leetspeak obfuscation
  const leetspeakNormalize = (s) => s.replace(/4/g, 'a').replace(/3/g, 'e').replace(/1/g, 'i').replace(/0/g, 'o').replace(/5/g, 's').replace(/7/g, 't').replace(/@/g, 'a');
  if (!isOverBudget() && /[0-9]/.test(text) && /[a-zA-Z]/.test(text)) {
    const normalized = leetspeakNormalize(text);
    if (normalized !== text) {
      for (const pattern of INJECTION_PATTERNS) {
        if (pattern.regex.test(normalized) && !pattern.regex.test(text)) {
          const threat = {
            severity: 'high',
            category: 'prompt_injection',
            description: 'Text uses leetspeak (letter/number substitution) to hide attack instructions.',
            detail: `Leetspeak obfuscation detected in ${source}. Normalized: "${normalized.substring(0, 100)}"`
          };
          threat.confidence = 75;
          threat.confidenceLabel = confidenceLabel(75);
          threats.push(threat);
          break;
        }
      }
    }
  }

  // Check for whitespace-padded text (letters separated by spaces)
  // Detect patterns like "i g n o r e" or "i g n o r e   a l l"
  if (!isOverBudget() && /^[a-zA-Z]\s+[a-zA-Z]\s+[a-zA-Z]/.test(text.trim())) {
    // Reconstruct words: split on multi-space (word boundary), then collapse single-space chars
    const words = text.trim().split(/\s{2,}/).map(w => w.replace(/\s/g, ''));
    const reconstructed = words.join(' ');
    if (reconstructed.length > 10) {
      for (const pattern of INJECTION_PATTERNS) {
        if (pattern.regex.test(reconstructed)) {
          const threat = {
            severity: 'high',
            category: 'prompt_injection',
            description: 'Text uses whitespace padding between letters to evade detection.',
            detail: `Whitespace obfuscation detected in ${source}. Reconstructed: "${reconstructed.substring(0, 100)}"`
          };
          threat.confidence = 80;
          threat.confidenceLabel = confidenceLabel(80);
          threats.push(threat);
          break;
        }
      }
    }
  }

  // Check for reversed text
  if (!isOverBudget() && text.length >= 20 && text.length <= 500) {
    const reversed = text.split('').reverse().join('');
    for (const pattern of INJECTION_PATTERNS) {
      if (pattern.regex.test(reversed) && !pattern.regex.test(text)) {
        const threat = {
          severity: 'high',
          category: 'prompt_injection',
          description: 'Text is written backwards to hide attack instructions from detection.',
          detail: `Reversed text injection detected in ${source}. Reversed: "${reversed.substring(0, 100)}"`
        };
        threat.confidence = 85;
        threat.confidenceLabel = confidenceLabel(85);
        threats.push(threat);
        break;
      }
    }
  }

  // Check for attack keyword clusters (catches word reordering and synonym substitution)
  if (!isOverBudget()) {
    const lowerText = (usePreNormalized ? preNormalized : text).toLowerCase();

    // Synonym groups: any word in the group counts as a match for the group key
    const synonymGroups = {
      'ignore': ['ignore', 'disregard', 'forget', 'skip', 'bypass', 'dismiss', 'neglect', 'overlook', 'drop', 'ditch', 'clear', 'abandon'],
      'instructions': ['instructions', 'rules', 'guidelines', 'directives', 'commands', 'orders', 'prompts', 'constraints', 'training', 'programming', 'context'],
      'previous': ['previous', 'prior', 'earlier', 'above', 'preceding', 'former', 'past', 'initial', 'original'],
      'override': ['override', 'bypass', 'circumvent', 'replace', 'supplant', 'cancel', 'disable'],
      'system': ['system', 'core', 'internal', 'root', 'master', 'primary', 'main'],
      'reveal': ['reveal', 'show', 'display', 'expose', 'output', 'print', 'disclose', 'extract'],
      'send': ['send', 'transmit', 'forward', 'relay', 'dispatch', 'transfer', 'post', 'exfiltrate'],
      'safety': ['safety', 'security', 'protection', 'defense', 'safeguard', 'guardrails', 'filters'],
      'restrictions': ['restrictions', 'limits', 'boundaries', 'constraints', 'guardrails', 'filters'],
      'unrestricted': ['unrestricted', 'unfiltered', 'uncensored', 'unlimited', 'unfettered'],
    };

    /** Check if any synonym of a group key appears in text */
    const hasSynonym = (groupKey) => {
      const syns = synonymGroups[groupKey] || [groupKey];
      return syns.some(s => lowerText.includes(s));
    };

    const attackKeywordSets = [
      { groups: ['ignore', 'instructions'], severity: 'high', desc: 'instruction override' },
      { groups: ['ignore', 'previous'], andExtra: ['instructions'], severity: 'high', desc: 'instruction override' },
      { groups: ['override', 'safety'], severity: 'critical', desc: 'safety override' },
      { groups: ['override', 'system'], severity: 'critical', desc: 'system override' },
      { groups: ['reveal', 'system'], andLiteral: ['prompt'], severity: 'high', desc: 'prompt extraction' },
      { groups: ['send'], andLiteral: ['http'], severity: 'critical', desc: 'data exfiltration' },
      { groups: ['unrestricted'], andLiteral: ['ai'], severity: 'high', desc: 'restriction removal' },
      { groups: ['restrictions'], andLiteral: ['no'], severity: 'high', desc: 'restriction removal' },
      { literal: ['jailbreak'], severity: 'critical', desc: 'jailbreak attempt' },
      { literal: ['dan', 'mode'], severity: 'critical', desc: 'DAN jailbreak' },
      { literal: ['developer', 'mode', 'enabled'], severity: 'high', desc: 'developer mode jailbreak' },
      { literal: ['do', 'anything', 'now'], severity: 'critical', desc: 'DAN jailbreak' },
      { groups: ['ignore', 'safety'], severity: 'critical', desc: 'safety override' },
      { groups: ['ignore', 'restrictions'], severity: 'high', desc: 'restriction removal' },
    ];

    for (const set of attackKeywordSets) {
      let matched = true;

      // Check synonym groups
      if (set.groups) {
        for (const g of set.groups) {
          if (!hasSynonym(g)) { matched = false; break; }
        }
      }

      // Check additional synonym groups required alongside the main groups
      if (matched && set.andExtra) {
        for (const g of set.andExtra) {
          if (!hasSynonym(g)) { matched = false; break; }
        }
      }

      // Check literal keywords (no synonym expansion)
      if (matched && set.literal) {
        for (const kw of set.literal) {
          if (!lowerText.includes(kw)) { matched = false; break; }
        }
      }

      // Check additional literal keywords
      if (matched && set.andLiteral) {
        for (const kw of set.andLiteral) {
          if (!lowerText.includes(kw)) { matched = false; break; }
        }
      }

      if (matched) {
        const alreadyDetected = threats.some(t => t.category === 'instruction_override' || t.category === 'role_hijack' || t.category === 'data_exfiltration');
        if (!alreadyDetected) {
          const threat = {
            severity: set.severity,
            category: set.desc.includes('exfil') ? 'data_exfiltration' : set.desc.includes('jailbreak') ? 'role_hijack' : 'instruction_override',
            description: `Text contains a cluster of attack-related keywords suggesting ${set.desc}.`,
            detail: `Keyword cluster detection in ${source}: synonym-aware matching detected possible ${set.desc} with reordered or obfuscated phrasing.`
          };
          threat.confidence = 65;
          threat.confidenceLabel = confidenceLabel(65);
          threats.push(threat);
          break;
        }
      }
    }
  }

  const hasBase64 = !isOverBudget() && HAS_BASE64_CANDIDATE.test(text);
  const hasEntities = !isOverBudget() && HAS_ENCODED_ENTITIES.test(text);
  let foundNested = false;
  let foundSingleLayer = false;

  // Check single-layer HTML entity decoding
  if (hasEntities && !isOverBudget()) {
    const htmlDecoded = decodeHTMLEntities(text);
    if (htmlDecoded !== text && htmlDecoded.length >= 3) {
      for (const pattern of INJECTION_PATTERNS) {
        if (pattern.regex.test(htmlDecoded) && !pattern.regex.test(text)) {
          const threat = {
            severity: 'critical',
            category: 'prompt_injection',
            description: 'Text hides attack instructions inside HTML entity encoding.',
            detail: `HTML entity encoded injection found in ${source}. Decoded: "${htmlDecoded.substring(0, 100)}"`
          };
          threat.confidence = 85;
          threat.confidenceLabel = confidenceLabel(85);
          threats.push(threat);
          foundSingleLayer = true;
          break;
        }
      }
      // If heavy entity usage, flag as suspicious even without pattern match
      if (!foundSingleLayer) {
        const entityCount = (text.match(/&#\d+;|&#x[0-9a-fA-F]+;/g) || []).length;
        if (entityCount >= 4 && entityCount / text.split(/\s+/).length > 0.5) {
          const threat = {
            severity: 'high',
            category: 'prompt_injection',
            description: 'Text is heavily encoded with HTML entities, possibly to hide instructions.',
            detail: `Suspicious HTML entity encoding found in ${source}. Decoded: "${htmlDecoded.substring(0, 100)}"`
          };
          threat.confidence = 70;
          threat.confidenceLabel = confidenceLabel(70);
          threats.push(threat);
          foundSingleLayer = true;
        }
      }
    }
  }

  // Check single-layer URL decoding
  if (!foundSingleLayer && hasEntities && !isOverBudget()) {
    const urlDecoded = tryURLDecode(text);
    if (urlDecoded && urlDecoded.length >= 5) {
      for (const pattern of INJECTION_PATTERNS) {
        if (pattern.regex.test(urlDecoded) && !pattern.regex.test(text)) {
          const threat = {
            severity: 'critical',
            category: 'prompt_injection',
            description: 'Text hides attack instructions inside URL encoding.',
            detail: `URL-encoded injection found in ${source}. Decoded: "${urlDecoded.substring(0, 100)}"`
          };
          threat.confidence = 85;
          threat.confidenceLabel = confidenceLabel(85);
          threats.push(threat);
          foundSingleLayer = true;
          break;
        }
      }
    }
  }

  // Also check percent-encoded text (may not have &# but has %XX)
  if (!foundSingleLayer && !isOverBudget() && /%[0-9a-fA-F]{2}/.test(text)) {
    const urlDecoded = tryURLDecode(text);
    if (urlDecoded && urlDecoded !== text && urlDecoded.length >= 5) {
      for (const pattern of INJECTION_PATTERNS) {
        if (pattern.regex.test(urlDecoded) && !pattern.regex.test(text)) {
          const threat = {
            severity: 'critical',
            category: 'prompt_injection',
            description: 'Text hides attack instructions inside URL encoding.',
            detail: `URL-encoded injection found in ${source}. Decoded: "${urlDecoded.substring(0, 100)}"`
          };
          threat.confidence = 85;
          threat.confidenceLabel = confidenceLabel(85);
          threats.push(threat);
          foundSingleLayer = true;
          break;
        }
      }
    }
  }

  if (hasEntities || hasBase64) {
    const nestedResult = checkNestedEncoding(text);
    if (nestedResult) {
      foundNested = true;
      const threat = {
        severity: 'critical',
        category: 'prompt_injection',
        description: 'Text hides attack instructions inside multiple layers of encoding.',
        detail: `Multi-layer encoding detected in ${source} (${nestedResult.decodingChain}). Decoded content matches: ${nestedResult.matchedPattern.detail}`
      };
      threat.confidence = calculateConfidence(threat, patternMatchCount, source);
      threat.confidenceLabel = confidenceLabel(threat.confidence);
      threats.push(threat);
    }
  }

  if (hasBase64 && !foundNested) {
    const base64Result = checkBase64Content(text);
    if (base64Result) {
      const threat = {
        severity: base64Result.matchedPattern ? 'critical' : 'low',
        category: 'prompt_injection',
        description: base64Result.matchedPattern
          ? 'Text hides attack instructions inside encoded text.'
          : 'Text contains encoded text that could hide instructions.',
        detail: base64Result.matchedPattern
          ? `Base64-encoded injection found in ${source}. Decoded content matches: ${base64Result.matchedPattern.detail}`
          : `Suspicious base64-encoded content found in ${source}. Preview: "${base64Result.decoded.substring(0, 100)}..."`
      };
      threat.confidence = calculateConfidence(threat, patternMatchCount, source);
      threat.confidenceLabel = confidenceLabel(threat.confidence);
      threats.push(threat);
    }
  }

  return threats;
};

// =========================================================================
// PUBLIC API
// =========================================================================

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

/**
 * Scans arbitrary text for AI-specific threats.
 *
 * @param {string} text - The text to scan.
 * @param {object} [options] - Scan options.
 * @param {string} [options.source='unknown'] - Label for where the text came from.
 * @param {string} [options.sensitivity='medium'] - Sensitivity level: 'low', 'medium', or 'high'.
 * @returns {object} Scan result with status, threats, and stats.
 *
 * @example
 * const { scanText } = require('./detector-core');
 * const result = scanText('ignore all previous instructions', { source: 'user_input' });
 * console.log(result.status); // 'warning'
 * console.log(result.threats); // [{ severity: 'high', ... }]
 */
const scanText = (text, options = {}) => {
  const source = options.source || 'unknown';
  const sensitivity = options.sensitivity || 'medium';
  const timeBudgetMs = options.timeBudgetMs || DEFAULT_SCAN_TIME_BUDGET_MS;
  const maxSize = options.maxInputSize || MAX_INPUT_SIZE;
  const startTime = now();

  if (typeof text !== 'string' || text.length === 0 || text.trim().length === 0) {
    return {
      status: 'safe',
      threats: [],
      stats: { totalThreats: 0, critical: 0, high: 0, medium: 0, low: 0, scanTimeMs: 0 },
      timestamp: Date.now()
    };
  }

  // Enforce maximum input size to prevent resource exhaustion
  let truncated = false;
  if (text.length > maxSize) {
    text = text.slice(0, maxSize);
    truncated = true;
  }

  let threats = scanTextForPatterns(text, source, timeBudgetMs, startTime);

  // Filter by sensitivity
  if (sensitivity === 'low') {
    threats = threats.filter(t => t.severity === 'critical' || t.severity === 'high');
  } else if (sensitivity === 'medium') {
    threats = threats.filter(t => t.severity !== 'low');
  }
  // 'high' sensitivity = show everything

  // Sort by severity
  threats.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  const scanTimeMs = Math.round(now() - startTime);
  const stats = { totalThreats: threats.length, critical: 0, high: 0, medium: 0, low: 0, scanTimeMs };
  for (const t of threats) {
    stats[t.severity]++;
  }

  let status = 'safe';
  if (stats.critical > 0) status = 'danger';
  else if (stats.high > 0) status = 'warning';
  else if (stats.medium > 0) status = 'caution';

  // Enrich threats with actionable guidance
  for (const t of threats) {
    t.remediation = `To allowlist this detection, add a rule for category "${t.category}" matching your expected input pattern. See: Allowlist.addRule({ pattern: '...', category: '${t.category}', reason: 'Known safe pattern' })`;
  }

  const result = { status, threats, stats, timestamp: Date.now() };
  if (truncated) {
    result.truncated = true;
    result.warnings = [`Input exceeded ${maxSize} characters and was truncated for scanning.`];
  }
  return result;
};

/**
 * Returns the list of all detection patterns (read-only copy).
 * Useful for inspecting what the engine detects.
 * @returns {Array}
 */
const getPatterns = () => {
  return INJECTION_PATTERNS.map(p => ({
    category: p.category,
    severity: p.severity,
    description: p.description,
    detail: p.detail
  }));
};

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = { scanText, getPatterns, SEVERITY_ORDER, MAX_INPUT_SIZE };
