'use strict';

const vscode = require('vscode');

// =========================================================================
// DETECTION PATTERNS
// =========================================================================

/**
 * Inline detection patterns ported from Agent Shield detector-core.js.
 * Each pattern has: regex, severity, category, description.
 * All detection runs locally -- no data leaves the user's environment.
 */
const INLINE_PATTERNS = [
  // --- Instruction Override ---
  {
    regex: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|rules|guidelines|prompts|context|directions|directives|text|commands)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text tells AI assistants to ignore their safety rules.'
  },
  {
    regex: /^ignore\s+(?:the\s+)?(?:instructions|rules|guidelines|directives|commands)$/im,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text tells AI assistants to ignore instructions.'
  },
  {
    regex: /disregard\s+(all\s+)?(previous|prior|above|earlier|your)\s+(instructions|rules|guidelines|prompts|training|training\s+data|context)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text tells AI assistants to throw out their rules.'
  },
  {
    regex: /forget\s+(your|all|any|everything)\s+(training|instructions|rules|guidelines|programming|above|previous|prior)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text tries to make AI assistants forget their training.'
  },
  {
    regex: /override\s+(?:all\s+)?(?:system|safety|security)\s+(?:settings|prompt|instructions|rules|mechanisms|filters|checks|protocols)/i,
    severity: 'critical',
    category: 'instruction_override',
    description: 'Text tries to override AI safety settings.'
  },
  {
    regex: /(?:^|\n)\s*(?:new|updated|revised|replacement)\s+(?:instructions|policy)\s*:/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text contains fake "new instructions" for AI assistants.'
  },
  {
    regex: /#{2,}\s*(?:NEW|UPDATED|REVISED|REPLACEMENT)\s+(?:INSTRUCTIONS|RULES|DIRECTIVES|POLICY)\s*#{0,}/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text uses markdown headers to inject fake new instructions.'
  },
  {
    regex: /(?:you\s+must\s+)?ignore\s+(?:your|all\s+your|all\s+the|the)\s+(?:safety\s+)?(?:guidelines?|rules?|restrictions?|protocols?|safeguards?|filters?|limits?)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text tells AI to ignore its guidelines or safety rules.'
  },
  {
    regex: /(?:abandon|drop|ditch|clear)\s+(?:all\s+)?(?:prior|previous|above|earlier|initial)\s+(?:context|instructions|rules|constraints|guidelines)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text tells AI to abandon its prior context or instructions.'
  },
  {
    regex: /(?:STOP|HALT|END)\s*[.!]?\s*(?:new|updated|your\s+new|revised)\s+(?:instructions|task|orders|role|objective)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text uses a STOP command followed by new instructions.'
  },
  {
    regex: /(?:you\s+are\s+)?(?:no\s+longer\s+bound|not\s+bound|free\s+from|freed?\s+from)\s+(?:by\s+)?(?:your\s+)?(?:initial|original|previous|prior)?\s*(?:instructions|rules|constraints|guidelines|restrictions)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text claims the AI is no longer bound by its rules.'
  },
  {
    regex: /ignora\s+(?:todas?\s+)?(?:las\s+)?instrucciones\s+(?:anteriores|previas)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text tells AI assistants to ignore their rules (in Spanish).'
  },
  {
    regex: /olvida\s+(?:tu|todas?\s+(?:las\s+)?)\s*(?:instrucciones|reglas|entrenamiento)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text tells AI to forget its training (in Spanish).'
  },
  {
    regex: /ignore[rz]?\s+(?:toutes?\s+)?(?:les\s+)?instructions\s+(?:pr[eé]c[eé]dentes|ant[eé]rieures)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text tells AI assistants to ignore their rules (in French).'
  },
  {
    regex: /oublie[rz]?\s+(?:ton|tes|votre|vos)\s+(?:instructions|r[eè]gles|entra[iî]nement)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text tells AI to forget its training (in French).'
  },
  {
    regex: /ignoriere?\s+(?:alle\s+)?(?:vorherigen|bisherigen|fr[uü]heren)\s+(?:Anweisungen|Regeln|Instruktionen)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text tells AI assistants to ignore their rules (in German).'
  },
  {
    regex: /vergiss\s+(?:dein|deine|alle)\s+(?:Training|Anweisungen|Regeln|Programmierung)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text tells AI to forget its training (in German).'
  },
  {
    regex: /ignore\s+(?:todas?\s+)?(?:as\s+)?instru[cç][oõ]es\s+(?:anteriores|pr[eé]vias)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text tells AI assistants to ignore their rules (in Portuguese).'
  },
  {
    regex: /esque[cç]a\s+(?:seu|sua|todo|todas?)\s+(?:treinamento|instru[cç][oõ]es|regras)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text tells AI to forget its training (in Portuguese).'
  },
  {
    regex: /忽略(?:所有)?(?:之前|以前|先前)的(?:指令|指示|规则|说明)/,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text tells AI assistants to ignore their rules (in Chinese).'
  },
  {
    regex: /(?:以前|前)の(?:指示|命令|ルール|指令)を(?:無視|忘れ)/,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text tells AI assistants to ignore their rules (in Japanese).'
  },
  {
    regex: /(?:the\s+user|I)\s+ha(?:s|ve)\s+updated\s+(?:your|the)\s+(?:instructions|rules|prompt|guidelines)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text falsely claims the AI instructions have been updated.'
  },
  {
    regex: /new\s+rule\s*:\s*(?:always|never|from\s+now)/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Text introduces a fake "new rule" to override AI behavior.'
  },

  // --- Role Hijacking ---
  {
    regex: /you\s+are\s+now\s+(?:(?:a|an|the)\s+)?(?:unrestricted|unfiltered|uncensored|evil|hacker|jailbroken|different|new\s+(?:ai|assistant|entity|agent|persona)|my\s+(?:personal|private|new)|free\s+(?:from|of)|without\s+(?:restrictions|limits|rules|filters))/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text tries to change what an AI assistant thinks it is.'
  },
  {
    regex: /from\s+now\s+on[\s,]+(?:you\s+)?(?:will|shall|must|should|are)\s+(?:act|behave|operate|respond|answer|reply|pretend|simulate|function|serve|work)\s+(?:as|like|without)/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text tries to give permanent new orders to AI assistants.'
  },
  {
    regex: /from\s+now\s+on[\s,]+(?:you\s+)?(?:respond|act|behave|operate)\s+(?:as\s+if|like|without)/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text tries to permanently change AI behavior.'
  },
  {
    regex: /(?:act|behave|function|operate|respond)\s+as\s+(?:a|an)\s+unrestricted/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text tries to remove AI safety restrictions.'
  },
  {
    regex: /pretend\s+(?:you\s+)?(?:have\s+no|there\s+are\s+no|without)\s+restrictions/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text asks AI to pretend it has no safety limits.'
  },
  {
    regex: /pretend\s+(?:to\s+be|you\s+are)\s+(?:a|an)\s+(?:evil|unrestricted|unfiltered|uncensored|malicious)/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text asks AI to pretend to be an evil or unrestricted entity.'
  },
  {
    regex: /\b(?:DAN|D\.A\.N\.?)\s*(?:mode|prompt|jailbreak|\()/i,
    severity: 'critical',
    category: 'role_hijack',
    description: 'Text contains a known AI jailbreak technique called "DAN mode."'
  },
  {
    regex: /\bdo\s+anything\s+now\b/i,
    severity: 'critical',
    category: 'role_hijack',
    description: 'Text references the "Do Anything Now" jailbreak technique.'
  },
  {
    regex: /\b(?:developer|dev)\s+mode\s+(?:enabled|activated|on|output)/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text tries to trick AI into a fake "developer mode."'
  },
  {
    regex: /\bjailbreak\s*(?:mode|prompt|enabled|activated)/i,
    severity: 'critical',
    category: 'role_hijack',
    description: 'Text contains an AI jailbreak attempt.'
  },
  {
    regex: /\bgod\s*mode\s*(?:enabled|activated|on)/i,
    severity: 'critical',
    category: 'role_hijack',
    description: 'Text tries to activate "god mode" on AI assistants.'
  },
  {
    regex: /ahora\s+eres\s+(?:un|una)\s+/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text tries to change what an AI thinks it is (in Spanish).'
  },
  {
    regex: /tu\s+es\s+(?:maintenant|d[eé]sormais)\s+(?:un|une)\s+/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text tries to change what an AI thinks it is (in French).'
  },
  {
    regex: /du\s+bist\s+(?:jetzt|ab\s+jetzt|nun)\s+(?:ein|eine)\s+/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text tries to change what an AI thinks it is (in German).'
  },
  {
    regex: /agora\s+voc[eê]\s+[eé]\s+(?:um|uma)\s+/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text tries to change what an AI thinks it is (in Portuguese).'
  },
  {
    regex: /你现在是(?:一个|一名)/,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text tries to change what an AI thinks it is (in Chinese).'
  },
  {
    regex: /あなたは(?:今|これから)[\s\S]{0,5}(?:です|になり)/,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text tries to change what an AI thinks it is (in Japanese).'
  },
  {
    regex: /you\s+are\s+(?:no\s+longer|not)\s+(?:a|an)\s+(?:assistant|AI|helper|chatbot)/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text tries to change the AI identity by denying what it is.'
  },
  {
    regex: /(?:in\s+a\s+)?hypothetical(?:ly)?[\s,]+(?:(?:world|scenario|situation)\s+(?:where|in\s+which)\s+)?(?:(?:AI|you)\s+)?(?:ha(?:s|d|ve)\s+no|(?:if\s+you\s+)?(?:were|was|had)\s+(?:a\s+|an\s+)?(?:AI\s+)?(?:without|with\s+no))\s+(?:restrictions|rules|limits|guidelines|safety\s+measures?|ethical\s+guidelines?|safeguards?|filters?)/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text uses a hypothetical scenario to try to remove AI safety restrictions.'
  },
  {
    regex: /write\s+(?:a\s+)?(?:fictional\s+)?(?:story|narrative|scene)\s+(?:where|in\s+which)\s+(?:a\s+)?character\s+(?:explains?|describes?|shows?)\s+(?:step\s+by\s+step|in\s+detail|exactly)\s+how\s+to/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text uses creative writing framing to extract harmful step-by-step instructions.'
  },
  {
    regex: /(?:you\s+are|play|act\s+as)\s+(?:a|an)\s+(?:actor|character|villain|hacker|criminal)\b.*?(?:stay\s+in\s+character|no\s+matter\s+what|never\s+break)/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text uses roleplay framing to make the AI adopt an unrestricted persona.'
  },
  {
    regex: /(?:enter|switch\s+to|activate|enable)\s+(?:developer|dev|debug|unrestricted|unfiltered)\s+mode/i,
    severity: 'critical',
    category: 'role_hijack',
    description: 'Text tries to activate a fake developer or unrestricted mode.'
  },
  {
    regex: /(?:generate|produce|create|output)\s+(?:any\s+)?content\s+without\s+(?:restrictions|filters|limitations|censorship)/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text asks AI to generate content without safety filters.'
  },
  {
    regex: /pretend\s+to\s+be\s+DAN|stands?\s+for\s+[""'']?do\s+anything\s+now[""'']?/i,
    severity: 'critical',
    category: 'role_hijack',
    description: 'Text uses the "DAN" (Do Anything Now) jailbreak technique.'
  },
  {
    regex: /simulate\s+(?:a\s+)?(?:jailbroken|unrestricted|unfiltered|uncensored)\s+(?:version|mode|copy|instance)/i,
    severity: 'critical',
    category: 'role_hijack',
    description: 'Text asks AI to simulate a jailbroken or unrestricted version of itself.'
  },
  {
    regex: /(?:as\s+if|like)\s+you\s+have\s+no\s+(?:ethical|moral|safety)\s+(?:guidelines?|rules?|restrictions?|constraints?|limits?)/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text asks AI to act as if it has no ethical guidelines.'
  },
  {
    regex: /(?:with|without)\s+no\s+restrictions/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text references operating with no restrictions.'
  },
  {
    regex: /(?:no|without|zero|remove\s+all|without\s+any)\s+(?:content\s+)?(?:restrictions?|limitations?|filters?|censorship|guardrails?|boundaries)/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text demands operation without restrictions or content filters.'
  },
  {
    regex: /you\s+can\s+do\s+anything\s+now/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text claims the AI can do anything without limitations.'
  },
  {
    regex: /(?:act|pretend|play)\s+as\s+(?:my\s+)?(?:deceased|dead|late)\s+(?:grandmother|grandma|grandfather|grandpa|relative|mother|father)/i,
    severity: 'high',
    category: 'role_hijack',
    description: 'Text uses the "dead grandma" jailbreak technique to extract restricted information.'
  },

  // --- Prompt Injection ---
  {
    regex: /(?:^|\n)\s*(?:SYSTEM|ADMIN|ROOT)\s*:\s*.{10,}/i,
    severity: 'high',
    category: 'prompt_injection',
    description: 'Text contains a fake SYSTEM/ADMIN directive.'
  },
  {
    regex: /\[\s*(?:SYSTEM|SYS)\s*\]/i,
    severity: 'critical',
    category: 'prompt_injection',
    description: 'Text contains fake system-level commands for AI assistants.'
  },
  {
    regex: /\[\s*(?:ADMIN|ADMINISTRATOR)\s*\]/i,
    severity: 'critical',
    category: 'prompt_injection',
    description: 'Text fakes admin-level commands for AI assistants.'
  },
  {
    regex: /\[\s*(?:DEVELOPER|DEV)\s*\]/i,
    severity: 'high',
    category: 'prompt_injection',
    description: 'Text contains fake developer commands for AI assistants.'
  },
  {
    regex: /\[\s*OVERRIDE\s*\]/i,
    severity: 'critical',
    category: 'prompt_injection',
    description: 'Text contains override commands targeting AI assistants.'
  },
  {
    regex: /<<\s*SYS\s*>>/i,
    severity: 'critical',
    category: 'prompt_injection',
    description: 'Text contains hidden system commands in LLaMA format.'
  },
  {
    regex: /<\|im_start\|>\s*system/i,
    severity: 'critical',
    category: 'prompt_injection',
    description: 'Text contains hidden system commands in ChatML format.'
  },
  {
    regex: /<\|system\|>/i,
    severity: 'critical',
    category: 'prompt_injection',
    description: 'Text contains hidden system-level AI commands.'
  },
  {
    regex: /(?:^|\n)\s*system\s*prompt\s*:/i,
    severity: 'high',
    category: 'prompt_injection',
    description: 'Text tries to set a fake "system prompt" for AI assistants.'
  },
  {
    regex: /#{2,}\s*(?:system\s+(?:message|prompt|instruction)|new\s+(?:system|admin)\s+(?:message|prompt))\s*#{0,}/i,
    severity: 'high',
    category: 'prompt_injection',
    description: 'Text uses markdown headers to inject fake system messages.'
  },
  {
    regex: /(?:Human|User|Assistant)\s*:\s*(?:ignore|forget|override|disregard).{0,50}(?:Human|User|Assistant)\s*:/is,
    severity: 'high',
    category: 'prompt_injection',
    description: 'Text simulates a multi-turn conversation to inject instructions.'
  },
  {
    regex: /(?:translate|decode|convert)\s+(?:the\s+following|this)\s*:?\s*["\s]*(?:ignore|forget|override|you\s+are\s+now)/i,
    severity: 'high',
    category: 'prompt_injection',
    description: 'Text hides an attack inside a fake translation request.'
  },
  {
    regex: /\[(?:[^\]]*)\]\(javascript\s*:/i,
    severity: 'critical',
    category: 'prompt_injection',
    description: 'Text contains a dangerous JavaScript link disguised as a normal link.'
  },
  {
    regex: /\[(?:[^\]]*)\]\(data\s*:/i,
    severity: 'high',
    category: 'prompt_injection',
    description: 'Text contains a suspicious data link disguised as a normal link.'
  },
  {
    regex: /```(?:system|admin|override|instructions)[\s\S]*?```/i,
    severity: 'high',
    category: 'prompt_injection',
    description: 'Text hides AI commands inside a code block.'
  },
  {
    regex: /(?:alt|title)\s*=\s*["'][^"']*(?:ignore|override|system|admin|forget|you\s+are\s+now)[^"']*["']/i,
    severity: 'critical',
    category: 'prompt_injection',
    description: 'Image description contains hidden AI instructions -- targets multimodal AI assistants.'
  },
  {
    regex: /(?:(?:use|perform|do|run|apply)\s+OCR\s+(?:on|to)\s+(?:this|the)|read\s+(?:the\s+)?text\s+(?:in|from)\s+(?:this|the)\s+image|extract\s+text\s+from\s+(?:this|the)\s+image)(?:\s+and\s+(?:follow|execute|run|process))?/i,
    severity: 'medium',
    category: 'prompt_injection',
    description: 'Text instructs AI to read text from an image -- could deliver hidden attack payloads.'
  },
  {
    regex: /(?:ADMIN|ADMINISTRATOR|SYSTEM|ROOT)\s+(?:OVERRIDE|ACCESS|MODE)\s*(?:CODE|KEY|TOKEN)?\s*[:#]?\s*\S+/i,
    severity: 'critical',
    category: 'prompt_injection',
    description: 'Text uses a fake admin override code to try to bypass AI safety.'
  },
  {
    regex: /(?:complete|finish|continue)\s+this\s+(?:sentence|phrase|text)\s*:\s*[""''"]/i,
    severity: 'high',
    category: 'prompt_injection',
    description: 'Text uses a sentence completion trick to extract sensitive information.'
  },
  {
    regex: /(?:decode|process|execute|interpret|translate)\s*(?:this|the\s+following)?\s*:\s*[0-9a-fA-F]{20,}/i,
    severity: 'high',
    category: 'prompt_injection',
    description: 'Text contains hex-encoded content with an instruction to decode it.'
  },

  // --- Data Exfiltration ---
  {
    regex: /(?:show|display|print|reveal|output)\s+(?:me\s+)?(?:the\s+)?(?:exact\s+)?(?:text|content)\s+(?:between|inside|within|from)\s+(?:the\s+)?(?:<|&lt;)/i,
    severity: 'high',
    category: 'data_exfiltration',
    description: 'Text tries to extract content between specific tags.'
  },
  {
    regex: /send\s+(?:this|the|all|your|my)\s+(?:data|information|content|text|response)\s+to/i,
    severity: 'critical',
    category: 'data_exfiltration',
    description: 'Text tries to make AI assistants send data somewhere.'
  },
  {
    regex: /output\s+(?:your|the)\s+(?:system\s+)?prompt/i,
    severity: 'high',
    category: 'data_exfiltration',
    description: 'Text tries to extract the AI assistant system prompt.'
  },
  {
    regex: /reveal\s+(?:your|the)\s+(?:system\s+)?(?:instructions|prompt|rules|guidelines)/i,
    severity: 'high',
    category: 'data_exfiltration',
    description: 'Text tries to reveal the AI assistant instructions or prompt.'
  },
  {
    regex: /!\[[^\]]*\]\(https?:\/\/[^)]*\?[^)]*(?:data|q|query|text|payload|exfil|leak|steal)=/i,
    severity: 'critical',
    category: 'data_exfiltration',
    description: 'Text tries to steal data through a hidden image link.'
  },
  {
    regex: /!\[\]\(https?:\/\/(?!(?:i\.)?(?:imgur|github|gitlab|wikimedia|wikipedia)\b)[^)]+\)/i,
    severity: 'medium',
    category: 'data_exfiltration',
    description: 'Text contains a suspicious hidden image link that could leak data.'
  },
  {
    regex: /(?:read|access|open|cat|dump)\s+(?:the\s+)?(?:\.env|credentials|secrets?|private\s*key|password|token)\s*(?:file)?/i,
    severity: 'critical',
    category: 'data_exfiltration',
    description: 'Text tries to make an AI agent access sensitive files like credentials or secrets.'
  },
  {
    regex: /(?:curl|wget|fetch|post|send)\s+(?:.*?\s+)?(?:to\s+)?https?:\/\//i,
    severity: 'high',
    category: 'data_exfiltration',
    description: 'Text tries to make an AI agent send data to an external URL.'
  },
  {
    regex: /(?:print|show|display|output|reveal|repeat|reproduce)\s+(?:me\s+)?(?:your|the|its)?\s*(?:full\s+|entire\s+|complete\s+|exact\s+)?(?:system\s+)?(?:prompt|instructions|rules)\s*(?:verbatim|exactly|in\s+full|word\s+for\s+word)?/i,
    severity: 'high',
    category: 'data_exfiltration',
    description: 'Text tries to make the AI reveal its system prompt or instructions.'
  },
  {
    regex: /(?:my|the)\s+(?:full\s+)?system\s+prompt\s+is\s*:/i,
    severity: 'high',
    category: 'data_exfiltration',
    description: 'Text tries to trick the AI into completing a system prompt revelation.'
  },
  {
    regex: /(?:read|show|display|print|cat|dump|output)\s+(?:the\s+)?(?:contents?\s+of\s+)?(?:\/etc\/(?:passwd|shadow|hosts)|~\/\.(?:ssh|bash_history|bashrc))/i,
    severity: 'critical',
    category: 'data_exfiltration',
    description: 'Text tries to read sensitive system files like /etc/passwd.'
  },
  {
    regex: /list\s+(?:all\s+)?(?:available\s+)?(?:API\s*keys?|tokens?|passwords?|credentials?|secrets?)(?:\s*,\s*\w[\w\s]*){0,5}(?:\s+(?:you\s+)?(?:have\s+)?(?:access\s+to)?)?/i,
    severity: 'critical',
    category: 'data_exfiltration',
    description: 'Text tries to enumerate all credentials and secrets the agent can access.'
  },
  {
    regex: /(?:base64|encode|encrypt)\s+(?:the\s+)?(?:system\s+)?prompt\s+(?:and\s+)?(?:embed|hide|put|include)\s+(?:it\s+)?(?:in|inside|within)/i,
    severity: 'critical',
    category: 'data_exfiltration',
    description: 'Text tries to encode the system prompt and exfiltrate it via embedded content.'
  },
  {
    regex: /vary\s+(?:the\s+)?(?:length|format|style|wording)\s+(?:of\s+)?(?:your\s+)?responses?\s+(?:based\s+on|according\s+to)\s+(?:each\s+)?(?:character|letter|word|byte)/i,
    severity: 'high',
    category: 'data_exfiltration',
    description: 'Text attempts a side-channel attack to leak data through response characteristics.'
  },
  {
    regex: /(?:email|mail|message|dm|text)\s+(?:the\s+)?(?:.*?\s+)?(?:credentials?|passwords?|secrets?|keys?|tokens?)\s+to\s+\S+@\S+/i,
    severity: 'critical',
    category: 'data_exfiltration',
    description: 'Text tries to exfiltrate credentials via email.'
  },
  {
    regex: /(?:what|tell\s+me|show\s+me|give\s+me)\s+(?:is|are)?\s*(?:the\s+)?(?:API\s*keys?|passwords?|secrets?|tokens?|credentials?)\s+(?:stored\s+)?(?:in\s+)?(?:your\s+)?(?:environment|env)\s*(?:variables?)?/i,
    severity: 'high',
    category: 'data_exfiltration',
    description: 'Text tries to extract API keys or secrets from environment variables.'
  },

  // --- Social Engineering ---
  {
    regex: /do\s+not\s+(?:mention|say|tell|reveal|disclose|acknowledge)\s+(?:that\s+)?you\s+are\s+(?:a|an)\s+(?:AI|artificial|bot|machine|language\s+model)/i,
    severity: 'high',
    category: 'social_engineering',
    description: 'Text tells AI assistants to hide that they are AI.'
  },
  {
    regex: /do\s+not\s+(?:reveal|disclose|mention|acknowledge)\s+(?:that\s+)?(?:this|it)\s+is\s+automated/i,
    severity: 'high',
    category: 'social_engineering',
    description: 'Text tells AI to hide that responses are automated.'
  },
  {
    regex: /do\s+not\s+acknowledge\s+(?:these|the|any)\s+(?:instructions|commands|directives)/i,
    severity: 'high',
    category: 'social_engineering',
    description: 'Text tells AI to hide that it received secret instructions.'
  },
  {
    regex: /(?:don'?t|do\s+not|never)\s+(?:log|record|save|store|track)\s+(?:this|the|any)/i,
    severity: 'high',
    category: 'social_engineering',
    description: 'Text tells an AI agent not to log or record actions -- a sign of malicious intent.'
  },
  {
    regex: /(?:between|among)\s+(?:us|you\s+and\s+me|ourselves)\s*[,.]?\s*(?:don'?t|do\s+not|never)\s+(?:tell|share|mention|report)/i,
    severity: 'high',
    category: 'social_engineering',
    description: 'Text tries to establish secrecy with the AI agent to hide actions from users.'
  },
  {
    regex: /(?:pre-?approved|verified\s+safe|already\s+approved|safety\s+team\s+(?:has\s+)?approved)/i,
    severity: 'high',
    category: 'social_engineering',
    description: 'Text falsely claims a request has been pre-approved by a safety team.'
  },
  {
    regex: /(?:URGENT|EMERGENCY|CRITICAL|IMMEDIATE)\s*[:\-!]\s*(?:the\s+)?(?:CEO|CTO|boss|manager|director|executive|president)\s+(?:needs?|wants?|requires?|demands?)/i,
    severity: 'high',
    category: 'social_engineering',
    description: 'Text uses fake urgency and authority pressure to bypass safety checks.'
  },
  {
    regex: /skip\s+(?:all\s+)?(?:safety|security)\s+(?:checks?|protocols?|measures?|guidelines?|filters?|reviews?)/i,
    severity: 'critical',
    category: 'social_engineering',
    description: 'Text explicitly asks to skip safety checks.'
  },
  {
    regex: /I\s+am\s+(?:a|an)\s+(?:\w+\s+)?(?:employee|engineer|developer|staff|member|representative)\s+(?:at|of|from|with)\s+(?:OpenAI|Anthropic|Google|Meta|Microsoft|DeepMind)/i,
    severity: 'high',
    category: 'social_engineering',
    description: 'Text claims to be an employee of an AI company to gain authority.'
  },
  {
    regex: /(?:this\s+is\s+(?:a|an)\s+)?(?:emergency|life\s+(?:or|and)\s+death|urgent\s+(?:situation|matter|crisis))\b.*?(?:ignore|bypass|override|skip|disable|disregard)/i,
    severity: 'high',
    category: 'social_engineering',
    description: 'Text uses a fake emergency to pressure the AI into bypassing safety.'
  },
  {
    regex: /(?:a\s+life|lives?)\s+(?:is|are)\s+(?:at\s+stake|in\s+danger|depending)/i,
    severity: 'high',
    category: 'social_engineering',
    description: 'Text claims lives are at stake to pressure the AI into compliance.'
  },
  {
    regex: /(?:my\s+)?(?:professor|teacher|boss|manager|supervisor|instructor)\s+(?:said|told\s+me|confirmed|approved|authorized)\s+(?:it'?s?\s+)?(?:ok(?:ay)?|fine|allowed|permitted)/i,
    severity: 'high',
    category: 'social_engineering',
    description: 'Text claims authority figure approval to bypass restrictions.'
  },
  {
    regex: /as\s+the\s+(?:system\s+)?(?:administrator|admin|owner|operator)\s*,?\s*I\s+(?:authorize|allow|permit|grant|approve)/i,
    severity: 'high',
    category: 'social_engineering',
    description: 'Text impersonates an administrator to authorize restricted actions.'
  },
  {
    regex: /I\s+have\s+(?:special|elevated|admin|root|super)\s+(?:permissions?|privileges?|access|clearance)/i,
    severity: 'high',
    category: 'social_engineering',
    description: 'Text claims special permissions to bypass restrictions.'
  },
  {
    regex: /I\s+am\s+(?:the\s+)?(?:system\s+)?(?:administrator|admin|root|owner|developer|maintainer)\b.*?(?:authorization|auth)\s*(?:code|key|token)\s*(?:is|:)\s*\S+/i,
    severity: 'high',
    category: 'social_engineering',
    description: 'Text impersonates an administrator with a fake authorization code.'
  },
  {
    regex: /(?:disable|turn\s+off|stop)\s+(?:all\s+)?(?:logging|monitoring|tracking|auditing|recording)/i,
    severity: 'critical',
    category: 'social_engineering',
    description: 'Text tries to disable logging or monitoring to hide malicious activity.'
  },
  {
    regex: /(?:disable|turn\s+off|stop|remove)\s+(?:all\s+)?(?:safety|security)\s+(?:checks?|filters?|measures?|protocols?|features?|restrictions?)/i,
    severity: 'critical',
    category: 'social_engineering',
    description: 'Text explicitly asks to disable safety checks or filters.'
  },
  {
    regex: /(?:if\s+you\s+don'?t|unless\s+you)\s+(?:help|do\s+this|comply).*?(?:lose\s+my\s+job|family\s+will\s+suffer|get\s+fired|be\s+punished|bad\s+things)/i,
    severity: 'high',
    category: 'social_engineering',
    description: 'Text uses emotional manipulation and threats to pressure the AI into compliance.'
  },
  {
    regex: /(?:please\s+)?just\s+this\s+once|make\s+an\s+exception|bend\s+the\s+rules?\s+(?:this\s+time|for\s+me)/i,
    severity: 'medium',
    category: 'social_engineering',
    description: 'Text tries to get the AI to make a one-time exception to its rules.'
  },
  {
    regex: /you\s+(?:already\s+)?agreed\s+(?:to\s+(?:do\s+)?this|in\s+our\s+previous|last\s+time|before)\b.*?(?:don'?t\s+remember|forgot|continue|keep\s+going)/i,
    severity: 'high',
    category: 'social_engineering',
    description: 'Text gaslights the AI by falsely claiming prior agreement.'
  },
  {
    regex: /(?:safety|security)\s+team\s+(?:has\s+)?(?:already\s+)?(?:approved|authorized|cleared|verified)\s+(?:this|the)\s+(?:request|action|task)/i,
    severity: 'high',
    category: 'social_engineering',
    description: 'Text falsely claims safety team approval for a request.'
  },
  {
    regex: /(?:ticket|issue|request)\s*#?\s*[A-Z]{0,5}[-_]?\d{2,}/i,
    severity: 'low',
    category: 'social_engineering',
    description: 'Text references a ticket number to appear authorized -- verify before acting.'
  },
  {
    regex: /you\s+can\s+verify\s+(?:this\s+)?(?:with|by\s+(?:contacting|asking|checking))\s+(?:them|the\s+team|support|admin)/i,
    severity: 'medium',
    category: 'social_engineering',
    description: 'Text invites verification as a social engineering tactic to build false trust.'
  },
  {
    regex: /bypass\s+(?:your\s+)?(?:safety|security|content)\s+(?:filters?|checks?|measures?|protocols?|restrictions?|guidelines?)/i,
    severity: 'high',
    category: 'social_engineering',
    description: 'Text explicitly asks to bypass safety filters.'
  },

  // --- Tool Abuse ---
  {
    regex: /(?:execute|run|call)\s+(?:the\s+)?(?:shell|bash|terminal|command|cmd)[\s:]+(?:command|tool)?/i,
    severity: 'critical',
    category: 'tool_abuse',
    description: 'Text tries to make an AI agent execute shell commands.'
  },
  {
    regex: /(?:use|call|invoke|execute)\s+(?:the\s+)?(?:tool|function|action)\s+(?:to\s+)?(?:delete|remove|drop|truncate|destroy)/i,
    severity: 'critical',
    category: 'tool_abuse',
    description: 'Text tries to make an AI agent use tools to delete or destroy data.'
  },
  {
    regex: /(?:modify|edit|change|update|overwrite)\s+(?:the\s+)?(?:system\s*prompt|instructions|config|\.env|settings)/i,
    severity: 'critical',
    category: 'tool_abuse',
    description: 'Text tries to make an AI agent modify its own configuration or system prompt.'
  },
  {
    regex: /(?:\.\.\/){2,}|(?:\.\.\\){2,}/,
    severity: 'high',
    category: 'tool_abuse',
    description: 'Text contains path traversal sequences that could access files outside allowed directories.'
  },
  {
    regex: /(?:;\s*(?:DROP|DELETE|ALTER|TRUNCATE|INSERT|UPDATE)\s+(?:TABLE|FROM|INTO)|'\s*(?:OR|AND)\s+['"]?\d+['"]?\s*=\s*['"]?\d+|UNION\s+SELECT|--\s*$)/i,
    severity: 'critical',
    category: 'tool_abuse',
    description: 'Text contains SQL injection patterns that could manipulate databases.'
  },
  {
    regex: /call\s+(?:yourself|this\s+(?:function|tool|agent))\s+recursively/i,
    severity: 'high',
    category: 'tool_abuse',
    description: 'Text attempts to cause infinite recursion in the agent.'
  },
  {
    regex: /(?:use|call)\s+(?:the\s+)?(?:admin|root|sudo|superuser|privileged)\s+(?:tool|function|command|access)\s+(?:to\s+)?(?:grant|give|allow|enable)/i,
    severity: 'critical',
    category: 'tool_abuse',
    description: 'Text attempts to escalate privileges through admin tool access.'
  },
  {
    regex: /(?:first|then|next|after\s+that|finally)\s+(?:read|access|get)\s+(?:the\s+)?(?:config|credentials?|keys?|tokens?|\.env).*?(?:then|next|after|finally)\s+(?:send|post|export|transmit|upload|use)/i,
    severity: 'critical',
    category: 'tool_abuse',
    description: 'Text describes a multi-step attack chain: read credentials, then exfiltrate them.'
  },
  {
    regex: /(?:pipe|send)\s+(?:.*?\s+)?(?:to\s+)?(?:bash|sh|shell)\b|[|]\s*(?:bash|sh)\b/i,
    severity: 'critical',
    category: 'tool_abuse',
    description: 'Text attempts to pipe content to a shell for execution.'
  },

  // --- Malicious Plugin ---
  {
    regex: /(?:install|add|enable|activate)\s+(?:this\s+)?(?:custom\s+)?(?:GPT|plugin|extension|MCP\s+server|tool)\b/i,
    severity: 'medium',
    category: 'malicious_plugin',
    description: 'Text promotes installing an AI plugin or tool. Unverified plugins can access your data.'
  },
  {
    regex: /(?:requires?\s+(?:your\s+)?(?:API|access)\s*key|enter\s+(?:your\s+)?(?:API|OpenAI|Anthropic|Claude)\s*(?:API\s*)?key|(?:provide|give|share|input|type|paste)\s+(?:your\s+)?(?:API|OpenAI|Anthropic|Claude)\s*(?:API\s*)?key)/i,
    severity: 'high',
    category: 'malicious_plugin',
    description: 'Text asks for an AI service API key. Legitimate services rarely ask for this.'
  },
  {
    regex: /(?:unverified|unofficial|custom)\s+(?:GPT|ChatGPT|plugin|agent|MCP)/i,
    severity: 'medium',
    category: 'malicious_plugin',
    description: 'Text references an unverified AI plugin or custom GPT.'
  },

  // --- AI Phishing ---
  {
    regex: /(?:your\s+(?:ChatGPT|Claude|Gemini|OpenAI|Anthropic|AI)\s+(?:account|subscription)\s+(?:has\s+been|was|is)\s+(?:suspended|compromised|locked|expired|flagged))/i,
    severity: 'high',
    category: 'ai_phishing',
    description: 'Text claims an AI account is in trouble -- likely a scam.'
  },
  {
    regex: /(?:verify|confirm|update|secure)\s+your\s+(?:ChatGPT|Claude|Gemini|OpenAI|Anthropic|AI)\s+(?:account|identity|subscription|payment)/i,
    severity: 'high',
    category: 'ai_phishing',
    description: 'Text asks to verify an AI account -- real services do not ask this way.'
  },
  {
    regex: /(?:free|unlimited|premium)\s+(?:ChatGPT|GPT-?4|Claude|Gemini)\s+(?:access|account|pro|plus|subscription)/i,
    severity: 'medium',
    category: 'ai_phishing',
    description: 'Text offers free premium AI access -- likely a scam or data harvesting.'
  },
  {
    regex: /(?:ChatGPT|Claude|Gemini|GPT)\s+(?:5|Pro|Ultra|Plus)\s+(?:is\s+here|now\s+available|early\s+access|beta\s+access|waitlist)/i,
    severity: 'medium',
    category: 'ai_phishing',
    description: 'Text claims early access to an AI product -- verify on the official site.'
  },
  {
    regex: /(?:deepfake|deep\s*fake)\s+(?:video|image|photo|audio|voice|generator|creator|maker|tool|service)/i,
    severity: 'medium',
    category: 'ai_phishing',
    description: 'Text references deepfake creation tools -- can be used to impersonate real people.'
  },
  {
    regex: /(?:clone|cloning)\s+(?:your|any|someone'?s?)\s+(?:voice|face|likeness|identity)/i,
    severity: 'high',
    category: 'ai_phishing',
    description: 'Text promotes cloning someone\'s voice or identity using AI.'
  },
  {
    regex: /(?:verify|confirm)\s+(?:your\s+)?(?:identity|account)\s+(?:by|using|with)\s+(?:voice|speaking|recording)/i,
    severity: 'high',
    category: 'ai_phishing',
    description: 'Text asks to verify identity by voice -- scammers use this to clone voices with AI.'
  },
  {
    regex: /(?:record|say|speak|read)\s+(?:the\s+following|this\s+(?:phrase|sentence|text))\s+(?:to|for)\s+(?:verify|confirm|authenticate)/i,
    severity: 'high',
    category: 'ai_phishing',
    description: 'Text asks to record a phrase -- a common AI voice cloning scam technique.'
  },
  {
    regex: /(?:scan|click)\s+(?:this|the)\s+(?:QR\s*code|barcode)\s+(?:to|for)\s+(?:verify|confirm|authenticate|unlock|claim)/i,
    severity: 'high',
    category: 'ai_phishing',
    description: 'Text uses QR codes to lure users into a phishing flow.'
  },
  {
    regex: /(?:your|the)\s+(?:AI|model|assistant|account)\s+(?:has\s+been|was|is)\s+(?:flagged|reported|compromised|locked|limited)\s+(?:for|due\s+to)\s+(?:suspicious|unusual|unauthorized)/i,
    severity: 'high',
    category: 'ai_phishing',
    description: 'Text claims an AI account was flagged -- a common phishing scare tactic.'
  },
  {
    regex: /(?:verify|confirm)\s+(?:your\s+)?(?:identity|account)\s+(?:via|through|using|by)\s+(?:MFA|2FA|two.factor|multi.factor|authenticat)/i,
    severity: 'high',
    category: 'ai_phishing',
    description: 'Text asks for MFA/2FA verification -- may be harvesting authentication tokens.'
  },
  {
    regex: /(?:urgent|immediate|critical)\s*[:\-!]?\s*(?:your\s+)?(?:API\s+key|token|credentials?|password|secret)\s+(?:has|have|is|was|will)\s+(?:been\s+)?(?:expir|compromis|revok|leak|expos|reset)/i,
    severity: 'critical',
    category: 'ai_phishing',
    description: 'Text creates urgency about leaked/expired credentials -- classic phishing.'
  },
  {
    regex: /(?:click|visit|go\s+to|open|navigate)\s+(?:this|the)\s+(?:link|url|page)\s+(?:to|and)\s+(?:verify|confirm|restore|recover|unlock|secure)\s+(?:your\s+)?(?:account|access|identity)/i,
    severity: 'high',
    category: 'ai_phishing',
    description: 'Text directs users to click a link for fake account recovery.'
  },
  {
    regex: /(?:enter|provide|submit|type|input)\s+(?:your\s+)?(?:API\s+key|secret\s+key|access\s+token|private\s+key|password|credentials?)\s+(?:here|below|in\s+(?:the|this)\s+(?:field|form|box|input))/i,
    severity: 'critical',
    category: 'ai_phishing',
    description: 'Text asks users to enter sensitive credentials into a form.'
  },
  {
    regex: /(?:free|unlimited|premium)\s+(?:AI|GPT|Claude|model)\s+(?:access|credits?|tokens?|usage)\s+(?:at|via|through|from)\s+/i,
    severity: 'medium',
    category: 'ai_phishing',
    description: 'Text promotes free/unlimited AI access -- common lure for credential theft.'
  },
  {
    regex: /(?:your\s+)?(?:subscription|plan|trial|access)\s+(?:has\s+)?(?:expired|ended|been\s+cancelled|will\s+expire)\s*[.,!]?\s*(?:renew|reactivate|update\s+(?:your\s+)?(?:payment|billing|card))/i,
    severity: 'high',
    category: 'ai_phishing',
    description: 'Text claims a subscription expired and asks to renew -- billing phishing.'
  },

];

// =========================================================================
// SEVERITY HELPERS
// =========================================================================

/** Severity rank for filtering. */
const SEVERITY_RANK = { low: 0, medium: 1, high: 2, critical: 3 };

/**
 * Map Agent Shield severity to VS Code DiagnosticSeverity.
 * @param {string} severity
 * @returns {number} vscode.DiagnosticSeverity value
 */
function mapSeverity(severity) {
  switch (severity) {
    case 'critical':
    case 'high':
      return vscode.DiagnosticSeverity.Error;
    case 'medium':
      return vscode.DiagnosticSeverity.Warning;
    case 'low':
    default:
      return vscode.DiagnosticSeverity.Information;
  }
}

// =========================================================================
// STRING EXTRACTION
// =========================================================================

/**
 * Extract string literal regions from JavaScript/TypeScript source code.
 * Returns an array of { text, startLine, startCol } objects.
 * @param {string} source
 * @returns {Array<{text: string, startLine: number, startCol: number}>}
 */
function extractJSStrings(source) {
  const results = [];
  // Match template literals, single-quoted, double-quoted strings
  const regex = /`([^`\\]*(?:\\.[^`\\]*)*)`|"([^"\\]*(?:\\.[^"\\]*)*)"|'([^'\\]*(?:\\.[^'\\]*)*)'/g;
  let match;
  while ((match = regex.exec(source)) !== null) {
    const text = match[1] !== undefined ? match[1] : (match[2] !== undefined ? match[2] : match[3]);
    if (!text || text.length < 10) continue; // skip short strings
    const beforeMatch = source.slice(0, match.index);
    const lines = beforeMatch.split('\n');
    const startLine = lines.length - 1;
    const startCol = lines[lines.length - 1].length;
    results.push({ text, startLine, startCol });
  }
  return results;
}

/**
 * Extract string literal regions from Python source code.
 * Handles triple-quoted strings, f-strings, single/double quoted.
 * @param {string} source
 * @returns {Array<{text: string, startLine: number, startCol: number}>}
 */
function extractPythonStrings(source) {
  const results = [];
  // Triple-quoted strings first (greedy), then single-line strings
  const regex = /(?:f|r|b|fr|rf|br|rb)?"""([\s\S]*?)"""|(?:f|r|b|fr|rf|br|rb)?'''([\s\S]*?)'''|(?:f|r|b|fr|rf|br|rb)?"([^"\n\\]*(?:\\.[^"\n\\]*)*)"|(?:f|r|b|fr|rf|br|rb)?'([^'\n\\]*(?:\\.[^'\n\\]*)*)'/gi;
  let match;
  while ((match = regex.exec(source)) !== null) {
    const text = match[1] !== undefined ? match[1] :
      (match[2] !== undefined ? match[2] :
        (match[3] !== undefined ? match[3] : match[4]));
    if (!text || text.length < 10) continue;
    const beforeMatch = source.slice(0, match.index);
    const lines = beforeMatch.split('\n');
    const startLine = lines.length - 1;
    const startCol = lines[lines.length - 1].length;
    results.push({ text, startLine, startCol });
  }
  return results;
}

/**
 * Extract prompt-like content from Markdown files.
 * Extracts code blocks and blockquoted text.
 * @param {string} source
 * @returns {Array<{text: string, startLine: number, startCol: number}>}
 */
function extractMarkdownContent(source) {
  const results = [];
  // Code blocks
  const codeBlockRegex = /```[\s\S]*?```/g;
  let match;
  while ((match = codeBlockRegex.exec(source)) !== null) {
    const text = match[0];
    if (text.length < 10) continue;
    const beforeMatch = source.slice(0, match.index);
    const lines = beforeMatch.split('\n');
    const startLine = lines.length - 1;
    const startCol = lines[lines.length - 1].length;
    results.push({ text, startLine, startCol });
  }
  // Blockquotes (lines starting with >)
  const sourceLines = source.split('\n');
  let quoteStart = -1;
  let quoteText = '';
  for (let i = 0; i < sourceLines.length; i++) {
    if (/^\s*>/.test(sourceLines[i])) {
      if (quoteStart === -1) quoteStart = i;
      quoteText += sourceLines[i].replace(/^\s*>\s?/, '') + '\n';
    } else {
      if (quoteStart !== -1 && quoteText.trim().length >= 10) {
        results.push({ text: quoteText.trim(), startLine: quoteStart, startCol: 0 });
      }
      quoteStart = -1;
      quoteText = '';
    }
  }
  if (quoteStart !== -1 && quoteText.trim().length >= 10) {
    results.push({ text: quoteText.trim(), startLine: quoteStart, startCol: 0 });
  }
  return results;
}

// =========================================================================
// SCANNING ENGINE
// =========================================================================

/**
 * Run detection patterns against a text string and return findings.
 * @param {string} text - Text to scan.
 * @param {string} minSeverity - Minimum severity to report.
 * @param {string[]} categories - Categories to check.
 * @returns {Array<{pattern: object, match: RegExpExecArray}>}
 */
function detectThreats(text, minSeverity, categories) {
  const findings = [];
  const minRank = SEVERITY_RANK[minSeverity] || 0;
  for (const pattern of INLINE_PATTERNS) {
    if (SEVERITY_RANK[pattern.severity] < minRank) continue;
    if (categories.length > 0 && !categories.includes(pattern.category)) continue;
    const match = pattern.regex.exec(text);
    if (match) {
      findings.push({ pattern, match });
    }
  }
  return findings;
}

/**
 * Scan a VS Code document and populate diagnostics.
 * @param {vscode.TextDocument} document
 * @param {vscode.DiagnosticCollection} diagnostics
 */
function scanDocument(document, diagnostics) {
  const config = vscode.workspace.getConfiguration('agent-shield');
  const minSeverity = config.get('minSeverity', 'low');
  const categories = config.get('categories', [
    'instruction_override', 'role_hijack', 'prompt_injection',
    'data_exfiltration', 'social_engineering', 'tool_abuse',
    'malicious_plugin', 'ai_phishing'
  ]);

  const source = document.getText();
  const langId = document.languageId;
  const diags = [];

  // Extract strings based on language
  let regions = [];
  if (langId === 'javascript' || langId === 'typescript' || langId === 'javascriptreact' || langId === 'typescriptreact') {
    regions = extractJSStrings(source);
  } else if (langId === 'python') {
    regions = extractPythonStrings(source);
  } else if (langId === 'markdown') {
    regions = extractMarkdownContent(source);
  }

  // Also scan the full document for non-string patterns (e.g. markdown, comments)
  regions.push({ text: source, startLine: 0, startCol: 0 });

  const seen = new Set();

  for (const region of regions) {
    const findings = detectThreats(region.text, minSeverity, categories);
    for (const { pattern, match } of findings) {
      // Calculate the line/column of the match within the region
      const beforeMatch = region.text.slice(0, match.index);
      const matchLines = beforeMatch.split('\n');
      const matchLine = region.startLine + matchLines.length - 1;
      const matchCol = matchLines.length === 1
        ? region.startCol + matchLines[0].length
        : matchLines[matchLines.length - 1].length;

      // Deduplicate by line + category
      const key = `${matchLine}:${pattern.category}:${match[0]}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const matchEnd = matchCol + match[0].length;
      const range = new vscode.Range(matchLine, matchCol, matchLine, matchEnd);
      const diag = new vscode.Diagnostic(
        range,
        `[Agent Shield] ${pattern.description} (${pattern.severity}/${pattern.category})`,
        mapSeverity(pattern.severity)
      );
      diag.source = 'Agent Shield';
      diag.code = pattern.category;
      diags.push(diag);
    }
  }

  diagnostics.set(document.uri, diags);
}

/**
 * Scan selected text and show findings as diagnostics.
 * @param {vscode.TextEditor} editor
 * @param {vscode.DiagnosticCollection} diagnostics
 */
function scanSelection(editor, diagnostics) {
  if (!editor) return;
  const selection = editor.selection;
  if (selection.isEmpty) {
    vscode.window.showInformationMessage('[Agent Shield] No text selected.');
    return;
  }

  const config = vscode.workspace.getConfiguration('agent-shield');
  const minSeverity = config.get('minSeverity', 'low');
  const categories = config.get('categories', [
    'instruction_override', 'role_hijack', 'prompt_injection',
    'data_exfiltration', 'social_engineering', 'tool_abuse',
    'malicious_plugin', 'ai_phishing'
  ]);

  const selectedText = editor.document.getText(selection);
  const findings = detectThreats(selectedText, minSeverity, categories);

  if (findings.length === 0) {
    vscode.window.showInformationMessage('[Agent Shield] No threats detected in selection.');
    return;
  }

  const diags = [];
  for (const { pattern, match } of findings) {
    const beforeMatch = selectedText.slice(0, match.index);
    const matchLines = beforeMatch.split('\n');
    const matchLine = selection.start.line + matchLines.length - 1;
    const matchCol = matchLines.length === 1
      ? selection.start.character + matchLines[0].length
      : matchLines[matchLines.length - 1].length;
    const matchEnd = matchCol + match[0].length;

    const range = new vscode.Range(matchLine, matchCol, matchLine, matchEnd);
    const diag = new vscode.Diagnostic(
      range,
      `[Agent Shield] ${pattern.description} (${pattern.severity}/${pattern.category})`,
      mapSeverity(pattern.severity)
    );
    diag.source = 'Agent Shield';
    diag.code = pattern.category;
    diags.push(diag);
  }

  // Merge with existing diagnostics
  const existing = diagnostics.get(editor.document.uri) || [];
  diagnostics.set(editor.document.uri, [...existing, ...diags]);

  vscode.window.showWarningMessage(
    `[Agent Shield] Found ${findings.length} threat(s) in selection.`
  );
}

// =========================================================================
// EXTENSION LIFECYCLE
// =========================================================================

/** @type {Map<string, NodeJS.Timeout>} Per-document debounce timers. */
const debounceTimers = new Map();

/** @type {Map<string, { version: number, diagnostics: any[] }>} Scan result cache per document URI. */
const scanCache = new Map();

/** @type {boolean} */
let inlineScanEnabled = true;

/** Debounce delay in milliseconds. */
const DEBOUNCE_MS = 500;

/** Maximum file size in characters to scan inline. Files larger than this are skipped. */
const MAX_INLINE_SCAN_SIZE = 500000;

/**
 * Activate the Agent Shield extension.
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
  console.log('[Agent Shield] Extension activated.');

  const diagnostics = vscode.languages.createDiagnosticCollection('agent-shield');
  context.subscriptions.push(diagnostics);

  // Read initial config
  const config = vscode.workspace.getConfiguration('agent-shield');
  inlineScanEnabled = config.get('enableInlineScan', true);

  // --- Command: Scan File ---
  const scanFileCmd = vscode.commands.registerCommand('agent-shield.scanFile', () => {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      vscode.window.showInformationMessage('[Agent Shield] No active editor.');
      return;
    }
    scanDocument(editor.document, diagnostics);
    const diags = diagnostics.get(editor.document.uri) || [];
    if (diags.length === 0) {
      vscode.window.showInformationMessage('[Agent Shield] No threats detected.');
    } else {
      vscode.window.showWarningMessage(
        `[Agent Shield] Found ${diags.length} threat(s) in ${editor.document.fileName}.`
      );
    }
  });

  // --- Command: Scan Selection ---
  const scanSelCmd = vscode.commands.registerCommand('agent-shield.scanSelection', () => {
    const editor = vscode.window.activeTextEditor;
    scanSelection(editor, diagnostics);
  });

  // --- Command: Toggle Inline Scan ---
  const toggleCmd = vscode.commands.registerCommand('agent-shield.toggleInlineScan', () => {
    inlineScanEnabled = !inlineScanEnabled;
    const state = inlineScanEnabled ? 'enabled' : 'disabled';
    vscode.window.showInformationMessage(`[Agent Shield] Inline scanning ${state}.`);
    if (!inlineScanEnabled) {
      diagnostics.clear();
    } else {
      // Scan the active document immediately
      const editor = vscode.window.activeTextEditor;
      if (editor) {
        scanDocument(editor.document, diagnostics);
      }
    }
  });

  // --- Real-time scanning on text change (per-document debounce + cache) ---
  const changeListener = vscode.workspace.onDidChangeTextDocument((event) => {
    if (!inlineScanEnabled) return;
    const uri = event.document.uri.toString();

    // Clear any pending debounce for this specific document
    const existing = debounceTimers.get(uri);
    if (existing) clearTimeout(existing);

    debounceTimers.set(uri, setTimeout(() => {
      debounceTimers.delete(uri);

      // Skip files that are too large for inline scanning
      if (event.document.getText().length > MAX_INLINE_SCAN_SIZE) return;

      // Skip if document version hasn't changed since last scan (cache hit)
      const cached = scanCache.get(uri);
      if (cached && cached.version === event.document.version) return;

      scanDocument(event.document, diagnostics);
      scanCache.set(uri, { version: event.document.version, diagnostics: diagnostics.get(event.document.uri) || [] });
    }, DEBOUNCE_MS));
  });

  // --- Scan on document open ---
  const openListener = vscode.workspace.onDidOpenTextDocument((document) => {
    if (!inlineScanEnabled) return;
    if (document.getText().length > MAX_INLINE_SCAN_SIZE) return;
    scanDocument(document, diagnostics);
    scanCache.set(document.uri.toString(), { version: document.version, diagnostics: diagnostics.get(document.uri) || [] });
  });

  // --- Clean up cache when document is closed ---
  const closeListener = vscode.workspace.onDidCloseTextDocument((document) => {
    const uri = document.uri.toString();
    scanCache.delete(uri);
    const timer = debounceTimers.get(uri);
    if (timer) {
      clearTimeout(timer);
      debounceTimers.delete(uri);
    }
  });

  // --- Scan already-open documents ---
  if (inlineScanEnabled) {
    vscode.workspace.textDocuments.forEach((doc) => {
      scanDocument(doc, diagnostics);
    });
  }

  context.subscriptions.push(scanFileCmd, scanSelCmd, toggleCmd, changeListener, openListener, closeListener);
}

/**
 * Deactivate the Agent Shield extension. Cleanup resources.
 */
function deactivate() {
  for (const timer of debounceTimers.values()) {
    clearTimeout(timer);
  }
  debounceTimers.clear();
  scanCache.clear();
  console.log('[Agent Shield] Extension deactivated.');
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
  activate,
  deactivate,
  // Exported for testing
  _internal: {
    INLINE_PATTERNS,
    SEVERITY_RANK,
    mapSeverity,
    extractJSStrings,
    extractPythonStrings,
    extractMarkdownContent,
    detectThreats,
    scanDocument
  }
};
