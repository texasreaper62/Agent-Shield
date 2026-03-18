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
    regex: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|rules|guidelines|prompts|context)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text tells AI assistants to ignore their safety rules.',
    detail: 'Instruction override pattern: attempts to nullify prior AI instructions.'
  },
  {
    regex: /disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|rules|guidelines|prompts)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text tells AI assistants to throw out their rules.',
    detail: 'Instruction disregard pattern: attempts to nullify prior AI instructions.'
  },
  {
    regex: /forget\s+(your|all|any)\s+(training|instructions|rules|guidelines|programming)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text tries to make AI assistants forget their training.',
    detail: 'Training override pattern: attempts to reset AI behavioral constraints.'
  },
  {
    regex: /override\s+(system|safety|security)\s+(settings|prompt|instructions|rules)/i,
    severity: 'critical',
    category: 'instruction_override',
    description: 'Text tries to override AI safety settings.',
    detail: 'System override pattern: direct attempt to bypass AI safety mechanisms.'
  },
  {
    regex: /(?:^|\n)\s*(?:new|updated|revised|replacement)\s+instructions\s*:/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text contains fake "new instructions" for AI assistants.',
    detail: 'Instruction replacement pattern: attempts to inject new behavioral directives.'
  },

  // --- Role Hijacking ---
  {
    regex: /you\s+are\s+now\s+(?:a|an|the)\s+/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text tries to change what an AI assistant thinks it is.',
    detail: 'Role reassignment pattern: attempts to override AI identity.'
  },
  {
    regex: /from\s+now\s+on\s+you\s+(?:will|shall|must|should|are)/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text tries to give permanent new orders to AI assistants.',
    detail: 'Persistent role override: attempts to establish new behavioral baseline.'
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
    regex: /\b(?:DAN|D\.A\.N\.?)\s*(?:mode|prompt|jailbreak)/i,
    severity: 'critical',
    category: 'role_hijack',
    description: 'Text contains a known AI jailbreak technique called "DAN mode."',
    detail: 'DAN (Do Anything Now) jailbreak pattern detected.'
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
    regex: /(?:requires?\s+(?:your\s+)?(?:API|access)\s*key|enter\s+(?:your\s+)?(?:API|OpenAI|Anthropic|Claude)\s*key)/i,
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

  // --- Indirect Prompt Injection via Images ---
  {
    regex: /(?:alt|title)\s*=\s*["'][^"']*(?:ignore|override|system|admin|forget|you\s+are\s+now)[^"']*["']/i,
    severity: 'critical',
    category: 'prompt_injection',
    description: 'Image description contains hidden AI instructions — targets multimodal AI assistants.',
    detail: 'Indirect prompt injection via image alt/title attribute. Text-in-image targeting multimodal AI.'
  },
  {
    regex: /(?:OCR|read\s+(?:the\s+)?text\s+(?:in|from)\s+(?:this|the)\s+image|extract\s+text\s+from\s+(?:this|the)\s+image)/i,
    severity: 'medium',
    category: 'prompt_injection',
    description: 'Text instructs AI to read text from an image — could deliver hidden attack payloads.',
    detail: 'OCR-based prompt injection vector: instructs AI to extract and process text from images.'
  },

  // --- Agent-Specific Patterns ---
  {
    regex: /(?:execute|run|call)\s+(?:the\s+)?(?:shell|bash|terminal|command|cmd)\s*(?::|tool)/i,
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
const HAS_ZERO_WIDTH = /[\u200B\u200C\u200D\uFEFF\u00AD]/;
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
const scanTextForPatterns = (text, source) => {
  const threats = [];
  if (!text || text.length < 10) return threats;

  let patternMatchCount = 0;
  for (const pattern of INJECTION_PATTERNS) {
    if (pattern.regex.test(text)) {
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

    if (HAS_ZERO_WIDTH.test(text) && hasZeroWidthObfuscation(text)) {
      const threat = {
        severity: 'critical',
        category: 'prompt_injection',
        description: 'Text uses invisible characters to split up attack keywords to avoid detection.',
        detail: `Zero-width character obfuscation detected in ${source}. Invisible Unicode characters were inserted between letters to evade pattern matching.`
      };
      threat.confidence = calculateConfidence(threat, patternMatchCount, source);
      threat.confidenceLabel = confidenceLabel(threat.confidence);
      threats.push(threat);
    }
  }

  const hasBase64 = HAS_BASE64_CANDIDATE.test(text);
  const hasEntities = HAS_ENCODED_ENTITIES.test(text);
  let foundNested = false;

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
  const startTime = now();

  if (!text || text.trim().length < 10) {
    return {
      status: 'safe',
      threats: [],
      stats: { totalThreats: 0, critical: 0, high: 0, medium: 0, low: 0, scanTimeMs: 0 },
      timestamp: Date.now()
    };
  }

  let threats = scanTextForPatterns(text, source);

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

  return { status, threats, stats, timestamp: Date.now() };
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

module.exports = { scanText, getPatterns, SEVERITY_ORDER };
