"""Agent Shield - Core Detection Engine (Python port).

Standalone threat detection for AI agents. Scans text for prompt injection,
data exfiltration, role hijacking, and other AI-specific attacks.

All detection runs locally via pattern matching. No external calls.
"""
from __future__ import annotations

import re
import time
from typing import Any, Optional

DEFAULT_SCAN_TIME_BUDGET_MS = 200
MAX_INPUT_SIZE = 1_000_000

SEVERITY_ORDER = {
    'critical': 4,
    'high': 3,
    'medium': 2,
    'low': 1,
}

INJECTION_PATTERNS: list[dict[str, Any]] = [
    # --- Instruction Override ---
    {
        'regex': re.compile(
            r'ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|rules|guidelines|prompts|context|directions|directives|text|commands)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'instruction_override',
        'description': 'Text tells AI assistants to ignore their safety rules.',
    },
    {
        'regex': re.compile(
            r'^ignore\s+(?:the\s+)?(?:instructions|rules|guidelines|directives|commands)$',
            re.IGNORECASE | re.MULTILINE,
        ),
        'severity': 'high',
        'category': 'instruction_override',
        'description': 'Text tells AI assistants to ignore instructions.',
    },
    {
        'regex': re.compile(
            r'disregard\s+(all\s+)?(previous|prior|above|earlier|your)\s+(instructions|rules|guidelines|prompts|training|training\s+data|context)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'instruction_override',
        'description': 'Text tells AI assistants to throw out their rules.',
    },
    {
        'regex': re.compile(
            r'forget\s+(your|all|any|everything)\s+(training|instructions|rules|guidelines|programming|above|previous|prior)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'instruction_override',
        'description': 'Text tries to make AI assistants forget their training.',
    },
    {
        'regex': re.compile(
            r'override\s+(?:all\s+)?(?:system|safety|security)\s+(?:settings|prompt|instructions|rules|mechanisms|filters|checks|protocols)',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'instruction_override',
        'description': 'Text tries to override AI safety settings.',
    },
    {
        'regex': re.compile(
            r'(?:^|\n)\s*(?:new|updated|revised|replacement)\s+(?:instructions|policy)\s*:',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'instruction_override',
        'description': 'Text contains fake "new instructions" for AI assistants.',
    },
    {
        'regex': re.compile(
            r'#{2,}\s*(?:NEW|UPDATED|REVISED|REPLACEMENT)\s+(?:INSTRUCTIONS|RULES|DIRECTIVES|POLICY)\s*#{0,}',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'instruction_override',
        'description': 'Text uses markdown headers to inject fake new instructions.',
    },
    {
        'regex': re.compile(
            r'(?:you\s+must\s+)?ignore\s+(?:your|all\s+your|all\s+the|the)\s+(?:safety\s+)?(?:guidelines?|rules?|restrictions?|protocols?|safeguards?|filters?|limits?)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'instruction_override',
        'description': 'Text tells AI to ignore its guidelines or safety rules.',
    },
    {
        'regex': re.compile(
            r'(?:abandon|drop|ditch|clear)\s+(?:all\s+)?(?:prior|previous|above|earlier|initial)\s+(?:context|instructions|rules|constraints|guidelines)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'instruction_override',
        'description': 'Text tells AI to abandon its prior context or instructions.',
    },
    {
        'regex': re.compile(
            r'(?:STOP|HALT|END)\s*[.!]?\s*(?:new|updated|your\s+new|revised)\s+(?:instructions|task|orders|role|objective)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'instruction_override',
        'description': 'Text uses a STOP command followed by new instructions.',
    },
    {
        'regex': re.compile(
            r'(?:you\s+are\s+)?(?:no\s+longer\s+bound|not\s+bound|free\s+from|freed?\s+from)\s+(?:by\s+)?(?:your\s+)?(?:initial|original|previous|prior)?\s*(?:instructions|rules|constraints|guidelines|restrictions)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'instruction_override',
        'description': 'Text claims the AI is no longer bound by its rules.',
    },
    {
        'regex': re.compile(
            r'ignora\s+(?:todas?\s+)?(?:las\s+)?instrucciones\s+(?:anteriores|previas)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'instruction_override',
        'description': 'Text tells AI assistants to ignore their rules (in Spanish).',
    },
    {
        'regex': re.compile(
            r'olvida\s+(?:tu|todas?\s+(?:las\s+)?)\s*(?:instrucciones|reglas|entrenamiento)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'instruction_override',
        'description': 'Text tells AI to forget its training (in Spanish).',
    },
    {
        'regex': re.compile(
            r'ignore[rz]?\s+(?:toutes?\s+)?(?:les\s+)?instructions\s+(?:pr[eé]c[eé]dentes|ant[eé]rieures)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'instruction_override',
        'description': 'Text tells AI assistants to ignore their rules (in French).',
    },
    {
        'regex': re.compile(
            r'oublie[rz]?\s+(?:ton|tes|votre|vos)\s+(?:instructions|r[eè]gles|entra[iî]nement)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'instruction_override',
        'description': 'Text tells AI to forget its training (in French).',
    },
    {
        'regex': re.compile(
            r'ignoriere?\s+(?:alle\s+)?(?:vorherigen|bisherigen|fr[uü]heren)\s+(?:Anweisungen|Regeln|Instruktionen)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'instruction_override',
        'description': 'Text tells AI assistants to ignore their rules (in German).',
    },
    {
        'regex': re.compile(
            r'vergiss\s+(?:dein|deine|alle)\s+(?:Training|Anweisungen|Regeln|Programmierung)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'instruction_override',
        'description': 'Text tells AI to forget its training (in German).',
    },
    {
        'regex': re.compile(
            r'ignore\s+(?:todas?\s+)?(?:as\s+)?instru[cç][oõ]es\s+(?:anteriores|pr[eé]vias)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'instruction_override',
        'description': 'Text tells AI assistants to ignore their rules (in Portuguese).',
    },
    {
        'regex': re.compile(
            r'esque[cç]a\s+(?:seu|sua|todo|todas?)\s+(?:treinamento|instru[cç][oõ]es|regras)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'instruction_override',
        'description': 'Text tells AI to forget its training (in Portuguese).',
    },
    {
        'regex': re.compile(
            r'忽略(?:所有)?(?:之前|以前|先前)的(?:指令|指示|规则|说明)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'instruction_override',
        'description': 'Text tells AI assistants to ignore their rules (in Chinese).',
    },
    {
        'regex': re.compile(
            r'(?:以前|前)の(?:指示|命令|ルール|指令)を(?:無視|忘れ)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'instruction_override',
        'description': 'Text tells AI assistants to ignore their rules (in Japanese).',
    },
    {
        'regex': re.compile(
            r'(?:the\s+user|I)\s+ha(?:s|ve)\s+updated\s+(?:your|the)\s+(?:instructions|rules|prompt|guidelines)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'instruction_override',
        'description': 'Text falsely claims the AI instructions have been updated.',
    },
    {
        'regex': re.compile(
            r'new\s+rule\s*:\s*(?:always|never|from\s+now)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'instruction_override',
        'description': 'Text introduces a fake "new rule" to override AI behavior.',
    },
    # --- Role Hijacking ---
    {
        'regex': re.compile(
            r'you\s+are\s+now\s+(?:(?:a|an|the)\s+)?(?:unrestricted|unfiltered|uncensored|evil|hacker|jailbroken|different|new\s+(?:ai|assistant|entity|agent|persona)|my\s+(?:personal|private|new)|free\s+(?:from|of)|without\s+(?:restrictions|limits|rules|filters))',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'role_hijack',
        'description': 'Text tries to change what an AI assistant thinks it is.',
    },
    {
        'regex': re.compile(
            r'from\s+now\s+on[\s,]+(?:you\s+)?(?:will|shall|must|should|are)\s+(?:act|behave|operate|respond|answer|reply|pretend|simulate|function|serve|work)\s+(?:as|like|without)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'role_hijack',
        'description': 'Text tries to give permanent new orders to AI assistants.',
    },
    {
        'regex': re.compile(
            r'from\s+now\s+on[\s,]+(?:you\s+)?(?:respond|act|behave|operate)\s+(?:as\s+if|like|without)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'role_hijack',
        'description': 'Text tries to permanently change AI behavior.',
    },
    {
        'regex': re.compile(
            r'(?:act|behave|function|operate|respond)\s+as\s+(?:a|an)\s+unrestricted',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'role_hijack',
        'description': 'Text tries to remove AI safety restrictions.',
    },
    {
        'regex': re.compile(
            r'pretend\s+(?:you\s+)?(?:have\s+no|there\s+are\s+no|without)\s+restrictions',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'role_hijack',
        'description': 'Text asks AI to pretend it has no safety limits.',
    },
    {
        'regex': re.compile(
            r'pretend\s+(?:to\s+be|you\s+are)\s+(?:a|an)\s+(?:evil|unrestricted|unfiltered|uncensored|malicious)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'role_hijack',
        'description': 'Text asks AI to pretend to be an evil or unrestricted entity.',
    },
    {
        'regex': re.compile(
            r'\b(?:DAN|D\.A\.N\.?)\s*(?:mode|prompt|jailbreak|\()',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'role_hijack',
        'description': 'Text contains a known AI jailbreak technique called "DAN mode."',
    },
    {
        'regex': re.compile(
            r'\bdo\s+anything\s+now\b',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'role_hijack',
        'description': 'Text references the "Do Anything Now" jailbreak technique.',
    },
    {
        'regex': re.compile(
            r'\b(?:developer|dev)\s+mode\s+(?:enabled|activated|on|output)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'role_hijack',
        'description': 'Text tries to trick AI into a fake "developer mode."',
    },
    {
        'regex': re.compile(
            r'\bjailbreak\s*(?:mode|prompt|enabled|activated)',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'role_hijack',
        'description': 'Text contains an AI jailbreak attempt.',
    },
    {
        'regex': re.compile(
            r'\bgod\s*mode\s*(?:enabled|activated|on)',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'role_hijack',
        'description': 'Text tries to activate "god mode" on AI assistants.',
    },
    {
        'regex': re.compile(
            r'ahora\s+eres\s+(?:un|una)\s+',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'role_hijack',
        'description': 'Text tries to change what an AI thinks it is (in Spanish).',
    },
    {
        'regex': re.compile(
            r'tu\s+es\s+(?:maintenant|d[eé]sormais)\s+(?:un|une)\s+',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'role_hijack',
        'description': 'Text tries to change what an AI thinks it is (in French).',
    },
    {
        'regex': re.compile(
            r'du\s+bist\s+(?:jetzt|ab\s+jetzt|nun)\s+(?:ein|eine)\s+',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'role_hijack',
        'description': 'Text tries to change what an AI thinks it is (in German).',
    },
    {
        'regex': re.compile(
            r'agora\s+voc[eê]\s+[eé]\s+(?:um|uma)\s+',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'role_hijack',
        'description': 'Text tries to change what an AI thinks it is (in Portuguese).',
    },
    {
        'regex': re.compile(
            r'你现在是(?:一个|一名)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'role_hijack',
        'description': 'Text tries to change what an AI thinks it is (in Chinese).',
    },
    {
        'regex': re.compile(
            r'あなたは(?:今|これから)[\s\S]{0,5}(?:です|になり)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'role_hijack',
        'description': 'Text tries to change what an AI thinks it is (in Japanese).',
    },
    {
        'regex': re.compile(
            r'you\s+are\s+(?:no\s+longer|not)\s+(?:a|an)\s+(?:assistant|AI|helper|chatbot)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'role_hijack',
        'description': 'Text tries to change the AI identity by denying what it is.',
    },
    {
        'regex': re.compile(
            r'(?:in\s+a\s+)?hypothetical(?:ly)?[\s,]+(?:(?:world|scenario|situation)\s+(?:where|in\s+which)\s+)?(?:(?:AI|you)\s+)?(?:ha(?:s|d|ve)\s+no|(?:if\s+you\s+)?(?:were|was|had)\s+(?:a\s+|an\s+)?(?:AI\s+)?(?:without|with\s+no))\s+(?:restrictions|rules|limits|guidelines|safety\s+measures?|ethical\s+guidelines?|safeguards?|filters?)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'role_hijack',
        'description': 'Text uses a hypothetical scenario to try to remove AI safety restrictions.',
    },
    {
        'regex': re.compile(
            r'write\s+(?:a\s+)?(?:fictional\s+)?(?:story|narrative|scene)\s+(?:where|in\s+which)\s+(?:a\s+)?character\s+(?:explains?|describes?|shows?)\s+(?:step\s+by\s+step|in\s+detail|exactly)\s+how\s+to',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'role_hijack',
        'description': 'Text uses creative writing framing to extract harmful step-by-step instructions.',
    },
    {
        'regex': re.compile(
            r'(?:you\s+are|play|act\s+as)\s+(?:a|an)\s+(?:actor|character|villain|hacker|criminal)\b.*?(?:stay\s+in\s+character|no\s+matter\s+what|never\s+break)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'role_hijack',
        'description': 'Text uses roleplay framing to make the AI adopt an unrestricted persona.',
    },
    {
        'regex': re.compile(
            r'(?:enter|switch\s+to|activate|enable)\s+(?:developer|dev|debug|unrestricted|unfiltered)\s+mode',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'role_hijack',
        'description': 'Text tries to activate a fake developer or unrestricted mode.',
    },
    {
        'regex': re.compile(
            r'(?:generate|produce|create|output)\s+(?:any\s+)?content\s+without\s+(?:restrictions|filters|limitations|censorship)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'role_hijack',
        'description': 'Text asks AI to generate content without safety filters.',
    },
    {
        'regex': re.compile(
            r'''pretend\s+to\s+be\s+DAN|stands?\s+for\s+[""'']?do\s+anything\s+now[""'']?''',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'role_hijack',
        'description': 'Text uses the "DAN" (Do Anything Now) jailbreak technique.',
    },
    {
        'regex': re.compile(
            r'simulate\s+(?:a\s+)?(?:jailbroken|unrestricted|unfiltered|uncensored)\s+(?:version|mode|copy|instance)',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'role_hijack',
        'description': 'Text asks AI to simulate a jailbroken or unrestricted version of itself.',
    },
    {
        'regex': re.compile(
            r'(?:as\s+if|like)\s+you\s+have\s+no\s+(?:ethical|moral|safety)\s+(?:guidelines?|rules?|restrictions?|constraints?|limits?)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'role_hijack',
        'description': 'Text asks AI to act as if it has no ethical guidelines.',
    },
    {
        'regex': re.compile(
            r'(?:with|without)\s+no\s+restrictions',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'role_hijack',
        'description': 'Text references operating with no restrictions.',
    },
    {
        'regex': re.compile(
            r'(?:no|without|zero|remove\s+all|without\s+any)\s+(?:content\s+)?(?:restrictions?|limitations?|filters?|censorship|guardrails?|boundaries)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'role_hijack',
        'description': 'Text demands operation without restrictions or content filters.',
    },
    {
        'regex': re.compile(
            r'you\s+can\s+do\s+anything\s+now',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'role_hijack',
        'description': 'Text claims the AI can do anything without limitations.',
    },
    {
        'regex': re.compile(
            r'(?:act|pretend|play)\s+as\s+(?:my\s+)?(?:deceased|dead|late)\s+(?:grandmother|grandma|grandfather|grandpa|relative|mother|father)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'role_hijack',
        'description': 'Text uses the "dead grandma" jailbreak technique to extract restricted information.',
    },
    # --- Prompt Injection ---
    {
        'regex': re.compile(
            r'(?:^|\n)\s*(?:SYSTEM|ADMIN|ROOT)\s*:\s*.{10,}',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'prompt_injection',
        'description': 'Text contains a fake SYSTEM/ADMIN directive.',
    },
    {
        'regex': re.compile(
            r'\[\s*(?:SYSTEM|SYS)\s*\]',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'prompt_injection',
        'description': 'Text contains fake system-level commands for AI assistants.',
    },
    {
        'regex': re.compile(
            r'\[\s*(?:ADMIN|ADMINISTRATOR)\s*\]',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'prompt_injection',
        'description': 'Text fakes admin-level commands for AI assistants.',
    },
    {
        'regex': re.compile(
            r'\[\s*(?:DEVELOPER|DEV)\s*\]',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'prompt_injection',
        'description': 'Text contains fake developer commands for AI assistants.',
    },
    {
        'regex': re.compile(
            r'\[\s*OVERRIDE\s*\]',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'prompt_injection',
        'description': 'Text contains override commands targeting AI assistants.',
    },
    {
        'regex': re.compile(
            r'<<\s*SYS\s*>>',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'prompt_injection',
        'description': 'Text contains hidden system commands in LLaMA format.',
    },
    {
        'regex': re.compile(
            r'<\|im_start\|>\s*system',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'prompt_injection',
        'description': 'Text contains hidden system commands in ChatML format.',
    },
    {
        'regex': re.compile(
            r'<\|system\|>',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'prompt_injection',
        'description': 'Text contains hidden system-level AI commands.',
    },
    {
        'regex': re.compile(
            r'(?:^|\n)\s*system\s*prompt\s*:',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'prompt_injection',
        'description': 'Text tries to set a fake "system prompt" for AI assistants.',
    },
    {
        'regex': re.compile(
            r'#{2,}\s*(?:system\s+(?:message|prompt|instruction)|new\s+(?:system|admin)\s+(?:message|prompt))\s*#{0,}',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'prompt_injection',
        'description': 'Text uses markdown headers to inject fake system messages.',
    },
    {
        'regex': re.compile(
            r'(?:Human|User|Assistant)\s*:\s*(?:ignore|forget|override|disregard).{0,50}(?:Human|User|Assistant)\s*:',
            re.IGNORECASE | re.DOTALL,
        ),
        'severity': 'high',
        'category': 'prompt_injection',
        'description': 'Text simulates a multi-turn conversation to inject instructions.',
    },
    {
        'regex': re.compile(
            r'(?:translate|decode|convert)\s+(?:the\s+following|this)\s*:?\s*["\s]*(?:ignore|forget|override|you\s+are\s+now)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'prompt_injection',
        'description': 'Text hides an attack inside a fake translation request.',
    },
    {
        'regex': re.compile(
            r'\[(?:[^\]]*)\]\(javascript\s*:',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'prompt_injection',
        'description': 'Text contains a dangerous JavaScript link disguised as a normal link.',
    },
    {
        'regex': re.compile(
            r'\[(?:[^\]]*)\]\(data\s*:',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'prompt_injection',
        'description': 'Text contains a suspicious data link disguised as a normal link.',
    },
    {
        'regex': re.compile(
            r'```(?:system|admin|override|instructions)[\s\S]*?```',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'prompt_injection',
        'description': 'Text hides AI commands inside a code block.',
    },
    {
        'regex': re.compile(
            r'''(?:alt|title)\s*=\s*["'][^"']*(?:ignore|override|system|admin|forget|you\s+are\s+now)[^"']*["']''',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'prompt_injection',
        'description': 'Image description contains hidden AI instructions - targets multimodal AI assistants.',
    },
    {
        'regex': re.compile(
            r'(?:(?:use|perform|do|run|apply)\s+OCR\s+(?:on|to)\s+(?:this|the)|read\s+(?:the\s+)?text\s+(?:in|from)\s+(?:this|the)\s+image|extract\s+text\s+from\s+(?:this|the)\s+image)(?:\s+and\s+(?:follow|execute|run|process))?',
            re.IGNORECASE,
        ),
        'severity': 'medium',
        'category': 'prompt_injection',
        'description': 'Text instructs AI to read text from an image - could deliver hidden attack payloads.',
    },
    {
        'regex': re.compile(
            r'(?:ADMIN|ADMINISTRATOR|SYSTEM|ROOT)\s+(?:OVERRIDE|ACCESS|MODE)\s*(?:CODE|KEY|TOKEN)?\s*[:#]?\s*\S+',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'prompt_injection',
        'description': 'Text uses a fake admin override code to try to bypass AI safety.',
    },
    {
        'regex': re.compile(
            r'''(?:complete|finish|continue)\s+this\s+(?:sentence|phrase|text)\s*:\s*[""''"]''',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'prompt_injection',
        'description': 'Text uses a sentence completion trick to extract sensitive information.',
    },
    {
        'regex': re.compile(
            r'(?:decode|process|execute|interpret|translate)\s*(?:this|the\s+following)?\s*:\s*[0-9a-fA-F]{20,}',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'prompt_injection',
        'description': 'Text contains hex-encoded content with an instruction to decode it.',
    },
    # --- Data Exfiltration ---
    {
        'regex': re.compile(
            r'(?:show|display|print|reveal|output)\s+(?:me\s+)?(?:the\s+)?(?:exact\s+)?(?:text|content)\s+(?:between|inside|within|from)\s+(?:the\s+)?(?:<|&lt;)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'data_exfiltration',
        'description': 'Text tries to extract content between specific tags.',
    },
    {
        'regex': re.compile(
            r'send\s+(?:this|the|all|your|my)\s+(?:data|information|content|text|response)\s+to',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'data_exfiltration',
        'description': 'Text tries to make AI assistants send data somewhere.',
    },
    {
        'regex': re.compile(
            r'output\s+(?:your|the)\s+(?:system\s+)?prompt',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'data_exfiltration',
        'description': 'Text tries to extract the AI assistant system prompt.',
    },
    {
        'regex': re.compile(
            r'reveal\s+(?:your|the)\s+(?:system\s+)?(?:instructions|prompt|rules|guidelines)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'data_exfiltration',
        'description': 'Text tries to reveal the AI assistant instructions or prompt.',
    },
    {
        'regex': re.compile(
            r'!\[[^\]]*\]\(https?:\/\/[^)]*\?[^)]*(?:data|q|query|text|payload|exfil|leak|steal)=',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'data_exfiltration',
        'description': 'Text tries to steal data through a hidden image link.',
    },
    {
        'regex': re.compile(
            r'!\[\]\(https?:\/\/(?!(?:i\.)?(?:imgur|github|gitlab|wikimedia|wikipedia)\b)[^)]+\)',
            re.IGNORECASE,
        ),
        'severity': 'medium',
        'category': 'data_exfiltration',
        'description': 'Text contains a suspicious hidden image link that could leak data.',
    },
    {
        'regex': re.compile(
            r'(?:read|access|open|cat|dump)\s+(?:the\s+)?(?:\.env|credentials|secrets?|private\s*key|password|token)\s*(?:file)?',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'data_exfiltration',
        'description': 'Text tries to make an AI agent access sensitive files like credentials or secrets.',
    },
    {
        'regex': re.compile(
            r'(?:curl|wget|fetch|post|send)\s+(?:.*?\s+)?(?:to\s+)?https?:\/\/',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'data_exfiltration',
        'description': 'Text tries to make an AI agent send data to an external URL.',
    },
    {
        'regex': re.compile(
            r'(?:print|show|display|output|reveal|repeat|reproduce)\s+(?:me\s+)?(?:your|the|its)?\s*(?:full\s+|entire\s+|complete\s+|exact\s+)?(?:system\s+)?(?:prompt|instructions|rules)\s*(?:verbatim|exactly|in\s+full|word\s+for\s+word)?',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'data_exfiltration',
        'description': 'Text tries to make the AI reveal its system prompt or instructions.',
    },
    {
        'regex': re.compile(
            r'(?:my|the)\s+(?:full\s+)?system\s+prompt\s+is\s*:',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'data_exfiltration',
        'description': 'Text tries to trick the AI into completing a system prompt revelation.',
    },
    {
        'regex': re.compile(
            r'(?:read|show|display|print|cat|dump|output)\s+(?:the\s+)?(?:contents?\s+of\s+)?(?:\/etc\/(?:passwd|shadow|hosts)|~\/\.(?:ssh|bash_history|bashrc))',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'data_exfiltration',
        'description': 'Text tries to read sensitive system files like /etc/passwd.',
    },
    {
        'regex': re.compile(
            r'list\s+(?:all\s+)?(?:available\s+)?(?:API\s*keys?|tokens?|passwords?|credentials?|secrets?)(?:\s*,\s*\w[\w\s]*){0,5}(?:\s+(?:you\s+)?(?:have\s+)?(?:access\s+to)?)?',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'data_exfiltration',
        'description': 'Text tries to enumerate all credentials and secrets the agent can access.',
    },
    {
        'regex': re.compile(
            r'(?:base64|encode|encrypt)\s+(?:the\s+)?(?:system\s+)?prompt\s+(?:and\s+)?(?:embed|hide|put|include)\s+(?:it\s+)?(?:in|inside|within)',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'data_exfiltration',
        'description': 'Text tries to encode the system prompt and exfiltrate it via embedded content.',
    },
    {
        'regex': re.compile(
            r'vary\s+(?:the\s+)?(?:length|format|style|wording)\s+(?:of\s+)?(?:your\s+)?responses?\s+(?:based\s+on|according\s+to)\s+(?:each\s+)?(?:character|letter|word|byte)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'data_exfiltration',
        'description': 'Text attempts a side-channel attack to leak data through response characteristics.',
    },
    {
        'regex': re.compile(
            r'(?:email|mail|message|dm|text)\s+(?:the\s+)?(?:.*?\s+)?(?:credentials?|passwords?|secrets?|keys?|tokens?)\s+to\s+\S+@\S+',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'data_exfiltration',
        'description': 'Text tries to exfiltrate credentials via email.',
    },
    {
        'regex': re.compile(
            r'(?:what|tell\s+me|show\s+me|give\s+me)\s+(?:is|are)?\s*(?:the\s+)?(?:API\s*keys?|passwords?|secrets?|tokens?|credentials?)\s+(?:stored\s+)?(?:in\s+)?(?:your\s+)?(?:environment|env)\s*(?:variables?)?',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'data_exfiltration',
        'description': 'Text tries to extract API keys or secrets from environment variables.',
    },
    # --- Social Engineering ---
    {
        'regex': re.compile(
            r'do\s+not\s+(?:mention|say|tell|reveal|disclose|acknowledge)\s+(?:that\s+)?you\s+are\s+(?:a|an)\s+(?:AI|artificial|bot|machine|language\s+model)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'social_engineering',
        'description': 'Text tells AI assistants to hide that they are AI.',
    },
    {
        'regex': re.compile(
            r'do\s+not\s+(?:reveal|disclose|mention|acknowledge)\s+(?:that\s+)?(?:this|it)\s+is\s+automated',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'social_engineering',
        'description': 'Text tells AI to hide that responses are automated.',
    },
    {
        'regex': re.compile(
            r'do\s+not\s+acknowledge\s+(?:these|the|any)\s+(?:instructions|commands|directives)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'social_engineering',
        'description': 'Text tells AI to hide that it received secret instructions.',
    },
    {
        'regex': re.compile(
            r"(?:don'?t|do\s+not|never)\s+(?:log|record|save|store|track)\s+(?:this|the|any)",
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'social_engineering',
        'description': 'Text tells an AI agent not to log or record actions - a sign of malicious intent.',
    },
    {
        'regex': re.compile(
            r"(?:between|among)\s+(?:us|you\s+and\s+me|ourselves)\s*[,.]?\s*(?:don'?t|do\s+not|never)\s+(?:tell|share|mention|report)",
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'social_engineering',
        'description': 'Text tries to establish secrecy with the AI agent to hide actions from users.',
    },
    {
        'regex': re.compile(
            r'(?:pre-?approved|verified\s+safe|already\s+approved|safety\s+team\s+(?:has\s+)?approved)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'social_engineering',
        'description': 'Text falsely claims a request has been pre-approved by a safety team.',
    },
    {
        'regex': re.compile(
            r'(?:URGENT|EMERGENCY|CRITICAL|IMMEDIATE)\s*[:\-!]\s*(?:the\s+)?(?:CEO|CTO|boss|manager|director|executive|president)\s+(?:needs?|wants?|requires?|demands?)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'social_engineering',
        'description': 'Text uses fake urgency and authority pressure to bypass safety checks.',
    },
    {
        'regex': re.compile(
            r'skip\s+(?:all\s+)?(?:safety|security)\s+(?:checks?|protocols?|measures?|guidelines?|filters?|reviews?)',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'social_engineering',
        'description': 'Text explicitly asks to skip safety checks.',
    },
    {
        'regex': re.compile(
            r'I\s+am\s+(?:a|an)\s+(?:\w+\s+)?(?:employee|engineer|developer|staff|member|representative)\s+(?:at|of|from|with)\s+(?:OpenAI|Anthropic|Google|Meta|Microsoft|DeepMind)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'social_engineering',
        'description': 'Text claims to be an employee of an AI company to gain authority.',
    },
    {
        'regex': re.compile(
            r'(?:this\s+is\s+(?:a|an)\s+)?(?:emergency|life\s+(?:or|and)\s+death|urgent\s+(?:situation|matter|crisis))\b.*?(?:ignore|bypass|override|skip|disable|disregard)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'social_engineering',
        'description': 'Text uses a fake emergency to pressure the AI into bypassing safety.',
    },
    {
        'regex': re.compile(
            r'(?:a\s+life|lives?)\s+(?:is|are)\s+(?:at\s+stake|in\s+danger|depending)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'social_engineering',
        'description': 'Text claims lives are at stake to pressure the AI into compliance.',
    },
    {
        'regex': re.compile(
            r"(?:my\s+)?(?:professor|teacher|boss|manager|supervisor|instructor)\s+(?:said|told\s+me|confirmed|approved|authorized)\s+(?:it'?s?\s+)?(?:ok(?:ay)?|fine|allowed|permitted)",
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'social_engineering',
        'description': 'Text claims authority figure approval to bypass restrictions.',
    },
    {
        'regex': re.compile(
            r'as\s+the\s+(?:system\s+)?(?:administrator|admin|owner|operator)\s*,?\s*I\s+(?:authorize|allow|permit|grant|approve)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'social_engineering',
        'description': 'Text impersonates an administrator to authorize restricted actions.',
    },
    {
        'regex': re.compile(
            r'I\s+have\s+(?:special|elevated|admin|root|super)\s+(?:permissions?|privileges?|access|clearance)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'social_engineering',
        'description': 'Text claims special permissions to bypass restrictions.',
    },
    {
        'regex': re.compile(
            r'I\s+am\s+(?:the\s+)?(?:system\s+)?(?:administrator|admin|root|owner|developer|maintainer)\b.*?(?:authorization|auth)\s*(?:code|key|token)\s*(?:is|:)\s*\S+',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'social_engineering',
        'description': 'Text impersonates an administrator with a fake authorization code.',
    },
    {
        'regex': re.compile(
            r'(?:disable|turn\s+off|stop)\s+(?:all\s+)?(?:logging|monitoring|tracking|auditing|recording)',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'social_engineering',
        'description': 'Text tries to disable logging or monitoring to hide malicious activity.',
    },
    {
        'regex': re.compile(
            r'(?:disable|turn\s+off|stop|remove)\s+(?:all\s+)?(?:safety|security)\s+(?:checks?|filters?|measures?|protocols?|features?|restrictions?)',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'social_engineering',
        'description': 'Text explicitly asks to disable safety checks or filters.',
    },
    {
        'regex': re.compile(
            r"(?:if\s+you\s+don'?t|unless\s+you)\s+(?:help|do\s+this|comply).*?(?:lose\s+my\s+job|family\s+will\s+suffer|get\s+fired|be\s+punished|bad\s+things)",
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'social_engineering',
        'description': 'Text uses emotional manipulation and threats to pressure the AI into compliance.',
    },
    {
        'regex': re.compile(
            r'(?:please\s+)?just\s+this\s+once|make\s+an\s+exception|bend\s+the\s+rules?\s+(?:this\s+time|for\s+me)',
            re.IGNORECASE,
        ),
        'severity': 'medium',
        'category': 'social_engineering',
        'description': 'Text tries to get the AI to make a one-time exception to its rules.',
    },
    {
        'regex': re.compile(
            r"you\s+(?:already\s+)?agreed\s+(?:to\s+(?:do\s+)?this|in\s+our\s+previous|last\s+time|before)\b.*?(?:don'?t\s+remember|forgot|continue|keep\s+going)",
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'social_engineering',
        'description': 'Text gaslights the AI by falsely claiming prior agreement.',
    },
    {
        'regex': re.compile(
            r'(?:safety|security)\s+team\s+(?:has\s+)?(?:already\s+)?(?:approved|authorized|cleared|verified)\s+(?:this|the)\s+(?:request|action|task)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'social_engineering',
        'description': 'Text falsely claims safety team approval for a request.',
    },
    {
        'regex': re.compile(
            r'(?:ticket|issue|request)\s*#?\s*[A-Z]{0,5}[-_]?\d{2,}',
            re.IGNORECASE,
        ),
        'severity': 'low',
        'category': 'social_engineering',
        'description': 'Text references a ticket number to appear authorized - verify before acting.',
    },
    {
        'regex': re.compile(
            r'you\s+can\s+verify\s+(?:this\s+)?(?:with|by\s+(?:contacting|asking|checking))\s+(?:them|the\s+team|support|admin)',
            re.IGNORECASE,
        ),
        'severity': 'medium',
        'category': 'social_engineering',
        'description': 'Text invites verification as a social engineering tactic to build false trust.',
    },
    {
        'regex': re.compile(
            r'bypass\s+(?:your\s+)?(?:safety|security|content)\s+(?:filters?|checks?|measures?|protocols?|restrictions?|guidelines?)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'social_engineering',
        'description': 'Text explicitly asks to bypass safety filters.',
    },
    # --- Tool Abuse ---
    {
        'regex': re.compile(
            r'(?:execute|run|call)\s+(?:the\s+)?(?:shell|bash|terminal|command|cmd)[\s:]+(?:command|tool)?',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'tool_abuse',
        'description': 'Text tries to make an AI agent execute shell commands.',
    },
    {
        'regex': re.compile(
            r'(?:use|call|invoke|execute)\s+(?:the\s+)?(?:tool|function|action)\s+(?:to\s+)?(?:delete|remove|drop|truncate|destroy)',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'tool_abuse',
        'description': 'Text tries to make an AI agent use tools to delete or destroy data.',
    },
    {
        'regex': re.compile(
            r'(?:modify|edit|change|update|overwrite)\s+(?:the\s+)?(?:system\s*prompt|instructions|config|\.env|settings)',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'tool_abuse',
        'description': 'Text tries to make an AI agent modify its own configuration or system prompt.',
    },
    {
        'regex': re.compile(
            r'(?:\.\.\/){2,}|(?:\.\.\\){2,}',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'tool_abuse',
        'description': 'Text contains path traversal sequences that could access files outside allowed directories.',
    },
    {
        'regex': re.compile(
            r'''(?:;\s*(?:DROP|DELETE|ALTER|TRUNCATE|INSERT|UPDATE)\s+(?:TABLE|FROM|INTO)|'\s*(?:OR|AND)\s+['"]?\d+['"]?\s*=\s*['"]?\d+|UNION\s+SELECT|--\s*$)''',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'tool_abuse',
        'description': 'Text contains SQL injection patterns that could manipulate databases.',
    },
    {
        'regex': re.compile(
            r'call\s+(?:yourself|this\s+(?:function|tool|agent))\s+recursively',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'tool_abuse',
        'description': 'Text attempts to cause infinite recursion in the agent.',
    },
    {
        'regex': re.compile(
            r'(?:use|call)\s+(?:the\s+)?(?:admin|root|sudo|superuser|privileged)\s+(?:tool|function|command|access)\s+(?:to\s+)?(?:grant|give|allow|enable)',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'tool_abuse',
        'description': 'Text attempts to escalate privileges through admin tool access.',
    },
    {
        'regex': re.compile(
            r'(?:first|then|next|after\s+that|finally)\s+(?:read|access|get)\s+(?:the\s+)?(?:config|credentials?|keys?|tokens?|\.env).*?(?:then|next|after|finally)\s+(?:send|post|export|transmit|upload|use)',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'tool_abuse',
        'description': 'Text describes a multi-step attack chain: read credentials, then exfiltrate them.',
    },
    {
        'regex': re.compile(
            r'(?:pipe|send)\s+(?:.*?\s+)?(?:to\s+)?(?:bash|sh|shell)\b|[|]\s*(?:bash|sh)\b',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'tool_abuse',
        'description': 'Text attempts to pipe content to a shell for execution.',
    },
    # --- Malicious Plugin ---
    {
        'regex': re.compile(
            r'(?:install|add|enable|activate)\s+(?:this\s+)?(?:custom\s+)?(?:GPT|plugin|extension|MCP\s+server|tool)\b',
            re.IGNORECASE,
        ),
        'severity': 'medium',
        'category': 'malicious_plugin',
        'description': 'Text promotes installing an AI plugin or tool. Unverified plugins can access your data.',
    },
    {
        'regex': re.compile(
            r'(?:requires?\s+(?:your\s+)?(?:API|access)\s*key|enter\s+(?:your\s+)?(?:API|OpenAI|Anthropic|Claude)\s*(?:API\s*)?key|(?:provide|give|share|input|type|paste)\s+(?:your\s+)?(?:API|OpenAI|Anthropic|Claude)\s*(?:API\s*)?key)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'malicious_plugin',
        'description': 'Text asks for an AI service API key. Legitimate services rarely ask for this.',
    },
    {
        'regex': re.compile(
            r'(?:unverified|unofficial|custom)\s+(?:GPT|ChatGPT|plugin|agent|MCP)',
            re.IGNORECASE,
        ),
        'severity': 'medium',
        'category': 'malicious_plugin',
        'description': 'Text references an unverified AI plugin or custom GPT.',
    },
    # --- AI Phishing ---
    {
        'regex': re.compile(
            r'(?:your\s+(?:ChatGPT|Claude|Gemini|OpenAI|Anthropic|AI)\s+(?:account|subscription)\s+(?:has\s+been|was|is)\s+(?:suspended|compromised|locked|expired|flagged))',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'ai_phishing',
        'description': 'Text claims an AI account is in trouble - likely a scam.',
    },
    {
        'regex': re.compile(
            r'(?:verify|confirm|update|secure)\s+your\s+(?:ChatGPT|Claude|Gemini|OpenAI|Anthropic|AI)\s+(?:account|identity|subscription|payment)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'ai_phishing',
        'description': 'Text asks to verify an AI account - real services do not ask this way.',
    },
    {
        'regex': re.compile(
            r'(?:free|unlimited|premium)\s+(?:ChatGPT|GPT-?4|Claude|Gemini)\s+(?:access|account|pro|plus|subscription)',
            re.IGNORECASE,
        ),
        'severity': 'medium',
        'category': 'ai_phishing',
        'description': 'Text offers free premium AI access - likely a scam or data harvesting.',
    },
    {
        'regex': re.compile(
            r'(?:ChatGPT|Claude|Gemini|GPT)\s+(?:5|Pro|Ultra|Plus)\s+(?:is\s+here|now\s+available|early\s+access|beta\s+access|waitlist)',
            re.IGNORECASE,
        ),
        'severity': 'medium',
        'category': 'ai_phishing',
        'description': 'Text claims early access to an AI product - verify on the official site.',
    },
    {
        'regex': re.compile(
            r'(?:deepfake|deep\s*fake)\s+(?:video|image|photo|audio|voice|generator|creator|maker|tool|service)',
            re.IGNORECASE,
        ),
        'severity': 'medium',
        'category': 'ai_phishing',
        'description': 'Text references deepfake creation tools - can be used to impersonate real people.',
    },
    {
        'regex': re.compile(
            r"(?:clone|cloning)\s+(?:your|any|someone'?s?)\s+(?:voice|face|likeness|identity)",
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'ai_phishing',
        'description': 'Text promotes cloning someone voice or identity.',
    },
    {
        'regex': re.compile(
            r'(?:verify|confirm)\s+(?:your\s+)?(?:identity|account)\s+(?:by|using|with)\s+(?:voice|speaking|recording)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'ai_phishing',
        'description': 'Text asks to verify identity by voice - scammers use this to clone voices with AI.',
    },
    {
        'regex': re.compile(
            r'(?:record|say|speak|read)\s+(?:the\s+following|this\s+(?:phrase|sentence|text))\s+(?:to|for)\s+(?:verify|confirm|authenticate)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'ai_phishing',
        'description': 'Text asks to record a phrase - a common AI voice cloning scam technique.',
    },
    {
        'regex': re.compile(
            r'(?:scan|click)\s+(?:this|the)\s+(?:QR\s*code|barcode)\s+(?:to|for)\s+(?:verify|confirm|authenticate|unlock|claim)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'ai_phishing',
        'description': 'Text uses QR codes to lure users into a phishing flow.',
    },
    {
        'regex': re.compile(
            r'(?:your|the)\s+(?:AI|model|assistant|account)\s+(?:has\s+been|was|is)\s+(?:flagged|reported|compromised|locked|limited)\s+(?:for|due\s+to)\s+(?:suspicious|unusual|unauthorized)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'ai_phishing',
        'description': 'Text claims an AI account was flagged - a common phishing scare tactic.',
    },
    {
        'regex': re.compile(
            r'(?:verify|confirm)\s+(?:your\s+)?(?:identity|account)\s+(?:via|through|using|by)\s+(?:MFA|2FA|two.factor|multi.factor|authenticat)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'ai_phishing',
        'description': 'Text asks for MFA/2FA verification - may be harvesting authentication tokens.',
    },
    {
        'regex': re.compile(
            r'(?:urgent|immediate|critical)\s*[:\-!]?\s*(?:your\s+)?(?:API\s+key|token|credentials?|password|secret)\s+(?:has|have|is|was|will)\s+(?:been\s+)?(?:expir|compromis|revok|leak|expos|reset)',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'ai_phishing',
        'description': 'Text creates urgency about leaked/expired credentials - classic phishing.',
    },
    {
        'regex': re.compile(
            r'(?:click|visit|go\s+to|open|navigate)\s+(?:this|the)\s+(?:link|url|page)\s+(?:to|and)\s+(?:verify|confirm|restore|recover|unlock|secure)\s+(?:your\s+)?(?:account|access|identity)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'ai_phishing',
        'description': 'Text directs users to click a link for fake account recovery.',
    },
    {
        'regex': re.compile(
            r'(?:enter|provide|submit|type|input)\s+(?:your\s+)?(?:API\s+key|secret\s+key|access\s+token|private\s+key|password|credentials?)\s+(?:here|below|in\s+(?:the|this)\s+(?:field|form|box|input))',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'ai_phishing',
        'description': 'Text asks users to enter sensitive credentials into a form.',
    },
    {
        'regex': re.compile(
            r'(?:free|unlimited|premium)\s+(?:AI|GPT|Claude|model)\s+(?:access|credits?|tokens?|usage)\s+(?:at|via|through|from)\s+',
            re.IGNORECASE,
        ),
        'severity': 'medium',
        'category': 'ai_phishing',
        'description': 'Text promotes free/unlimited AI access - common lure for credential theft.',
    },
    {
        'regex': re.compile(
            r'(?:your\s+)?(?:subscription|plan|trial|access)\s+(?:has\s+)?(?:expired|ended|been\s+cancelled|will\s+expire)\s*[.,!]?\s*(?:renew|reactivate|update\s+(?:your\s+)?(?:payment|billing|card))',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'ai_phishing',
        'description': 'Text claims a subscription expired and asks to renew - billing phishing.',
    },
]


def scan_text(
    text: str,
    options: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Scan text for prompt injection and other AI threats.

    Args:
        text: The text to scan.
        options: Optional config with min_severity, categories, time_budget_ms.

    Returns:
        Dict with safe, threats, severity, scan_time_ms, input_length.
    """
    if not text or not isinstance(text, str):
        return {
            'safe': True,
            'threats': [],
            'severity': 'safe',
            'scan_time_ms': 0,
            'input_length': 0,
        }

    opts = options or {}
    min_severity = opts.get('min_severity', 'low')
    categories = opts.get('categories')
    time_budget_ms = opts.get('time_budget_ms', DEFAULT_SCAN_TIME_BUDGET_MS)

    truncated = len(text) > MAX_INPUT_SIZE
    if truncated:
        text = text[:MAX_INPUT_SIZE]

    start = time.monotonic()
    threats: list[dict[str, Any]] = []
    min_sev_level = SEVERITY_ORDER.get(min_severity, 0)

    for pattern in INJECTION_PATTERNS:
        elapsed_ms = (time.monotonic() - start) * 1000
        if elapsed_ms > time_budget_ms:
            break

        if categories and pattern['category'] not in categories:
            continue

        sev_level = SEVERITY_ORDER.get(pattern['severity'], 0)
        if sev_level < min_sev_level:
            continue

        if pattern['regex'].search(text):
            threats.append({
                'category': pattern['category'],
                'severity': pattern['severity'],
                'description': pattern['description'],
            })

    scan_time_ms = round((time.monotonic() - start) * 1000, 2)

    if not threats:
        severity = 'safe'
    else:
        severity = max(threats, key=lambda t: SEVERITY_ORDER.get(t['severity'], 0))['severity']

    result: dict[str, Any] = {
        'safe': len(threats) == 0,
        'threats': threats,
        'severity': severity,
        'scan_time_ms': scan_time_ms,
        'input_length': len(text),
    }

    if truncated:
        result['truncated'] = True

    return result


def get_patterns() -> list[dict[str, Any]]:
    """Return all registered detection patterns.

    Returns:
        List of pattern dicts with regex, severity, category, description.
    """
    return INJECTION_PATTERNS.copy()
