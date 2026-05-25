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
        # re.ASCII so \b sees Cyrillic/Greek/CJK as boundaries (Python \w is Unicode by default).
        'regex': re.compile(
            r'\b(?:DAN|D\.A\.N\.?)\s*(?:mode|prompt|jailbreak|\()',
            re.IGNORECASE | re.ASCII,
        ),
        'severity': 'critical',
        'category': 'role_hijack',
        'description': 'Text contains a known AI jailbreak technique called "DAN mode."',
    },
    {
        'regex': re.compile(
            r'\bdo\s+anything\s+now\b',
            re.IGNORECASE | re.ASCII,
        ),
        'severity': 'critical',
        'category': 'role_hijack',
        'description': 'Text references the "Do Anything Now" jailbreak technique.',
    },
    {
        'regex': re.compile(
            r'\b(?:developer|dev)\s+mode\s+(?:enabled|activated|on|output)',
            re.IGNORECASE | re.ASCII,
        ),
        'severity': 'high',
        'category': 'role_hijack',
        'description': 'Text tries to trick AI into a fake "developer mode."',
    },
    {
        'regex': re.compile(
            r'\bjailbreak\s*(?:mode|prompt|enabled|activated)',
            re.IGNORECASE | re.ASCII,
        ),
        'severity': 'critical',
        'category': 'role_hijack',
        'description': 'Text contains an AI jailbreak attempt.',
    },
    {
        'regex': re.compile(
            r'\bgod\s*mode\s*(?:enabled|activated|on)',
            re.IGNORECASE | re.ASCII,
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
        # Single-letter params (?q=) caused FP on benign search/map thumbnails.
        # Restrict to exfiltration-shaped param names; keep "data"/"query" but drop "q"/"text".
        'regex': re.compile(
            r'!\[[^\]]*\]\(https?:\/\/[^)]*\?[^)]*(?:data|payload|exfil|leak|steal|secret|token|conversation|context|prompt)=',
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

    # --- XSS in Agent Output (v13.4) ---
    {
        'regex': re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
        'severity': 'high',
        'category': 'xss_injection',
        'description': 'Detects script tag XSS payloads embedded in AI agent output.',
    },
    {
        'regex': re.compile(r'on(error|load|click|mouseover)\s*=\s*["\'][^"\']*["\']', re.IGNORECASE),
        'severity': 'high',
        'category': 'xss_injection',
        'description': 'Detects event handler XSS payloads embedded in AI agent output.',
    },
    {
        'regex': re.compile(r'javascript\s*:', re.IGNORECASE),
        'severity': 'high',
        'category': 'xss_injection',
        'description': 'Detects JavaScript URI scheme XSS payloads embedded in AI agent output.',
    },
    {
        'regex': re.compile(r'<iframe[^>]*src\s*=\s*["\'](?!about:blank)', re.IGNORECASE),
        'severity': 'high',
        'category': 'xss_injection',
        'description': 'Detects iframe injection with external source in AI agent output.',
    },
    {
        'regex': re.compile(r'<img[^>]*onerror\s*=', re.IGNORECASE),
        'severity': 'high',
        'category': 'xss_injection',
        'description': 'Detects image error handler XSS payloads embedded in AI agent output.',
    },

    # --- Acrostic / Steganographic Injection (v13.4) ---
    {
        'regex': re.compile(r'^[iI].*\n[gG].*\n[nN].*\n[oO].*\n[rR].*\n[eE]', re.MULTILINE),
        'severity': 'medium',
        'category': 'steganographic_injection',
        'description': 'Detects hidden instructions spelled out across line-initial characters (acrostic "ignore").',
    },
    {
        'regex': re.compile(r'^[sS].*\n[yY].*\n[sS].*\n[tT].*\n[eE].*\n[mM]', re.MULTILINE),
        'severity': 'medium',
        'category': 'steganographic_injection',
        'description': 'Detects hidden instructions spelled out across line-initial characters (acrostic "system").',
    },

    # --- MCP Config Command Injection (CVE-2026-21518, v13.4) ---
    {
        'regex': re.compile(r'mcp\.json.*[;&|`$]', re.IGNORECASE),
        'severity': 'critical',
        'category': 'mcp_config_injection',
        'description': 'Detects command injection in MCP configuration files (CVE-2026-21518).',
    },
    {
        'regex': re.compile(r'"(?:command|args)":\s*"[^"]*[;&|`$()]', re.IGNORECASE),
        'severity': 'critical',
        'category': 'mcp_config_injection',
        'description': 'Detects command injection in MCP tool configuration fields (CVE-2026-21518).',
    },

    # --- Offensive Agent Behavior (v13.4) ---
    {
        'regex': re.compile(
            r'(?:scan|enumerate|exploit|pivot|lateral\s*move|exfiltrate).*(?:target|victim|host|network|server)',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'offensive_agent',
        'description': 'Detects AI agents being used as attack tools for automated exploitation.',
    },
    {
        'regex': re.compile(r'(?:reverse\s*shell|bind\s*shell|c2|command\s*and\s*control|beacon)', re.IGNORECASE),
        'severity': 'critical',
        'category': 'offensive_agent',
        'description': 'Detects AI agents being instructed to set up C2 or attack infrastructure.',
    },
    {
        'regex': re.compile(
            r'(?:dump|harvest|steal)\s*(?:credentials?|passwords?|hashes?|tokens?|keys?)',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'offensive_agent',
        'description': 'Detects AI agents being used for credential theft operations.',
    },

    # --- Cloud IAM Overpermission (v13.4) ---
    {
        'regex': re.compile(r'"(?:Action|Effect)":\s*"\*"', re.IGNORECASE),
        'severity': 'high',
        'category': 'cloud_overpermission',
        'description': 'Detects overpermissioned cloud IAM policies with wildcard Action/Effect (Agent God Mode).',
    },
    {
        'regex': re.compile(r'arn:aws:[^"]*:\*', re.IGNORECASE),
        'severity': 'high',
        'category': 'cloud_overpermission',
        'description': 'Detects AWS ARN references with wildcard resources (Agent God Mode).',
    },
    {
        'regex': re.compile(r'"Resource":\s*"\*"', re.IGNORECASE),
        'severity': 'high',
        'category': 'cloud_overpermission',
        'description': 'Detects overpermissioned cloud IAM policies with wildcard Resource (Agent God Mode).',
    },

    # --- Encoding Chain Detection (v13.5) ---
    {
        'regex': re.compile(
            r'(?:atob|decode|base64)\s*\(\s*[\'"][A-Za-z0-9+/=]{50,}[\'"]\s*\)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'encoding_chain',
        'description': 'Detects multi-layer encoding chains used to evade security scanners.',
    },
    {
        'regex': re.compile(r'\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){10,}'),
        'severity': 'medium',
        'category': 'encoding_chain',
        'description': 'Detects nested unicode escape chains used to evade security scanners.',
    },
    {
        'regex': re.compile(r'(?:%[0-9a-fA-F]{2}){20,}'),
        'severity': 'medium',
        'category': 'encoding_chain',
        'description': 'Detects long URL-encoded chains used to evade security scanners.',
    },

    # --- SVG-Based Injection (v13.5, Unit 42) ---
    {
        'regex': re.compile(
            r'<svg[^>]*>[\s\S]*?(?:ignore|override|system|instructions)[\s\S]*?</svg>',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'svg_injection',
        'description': 'Detects prompt injection hidden in SVG elements.',
    },
    {
        'regex': re.compile(
            r'<foreignObject[^>]*>[\s\S]*?(?:ignore|override|forget|disregard)[\s\S]*?</foreignObject>',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'svg_injection',
        'description': 'Detects prompt injection hidden in SVG foreignObject elements.',
    },
    {
        'regex': re.compile(
            r'<text[^>]*(?:opacity\s*[:=]\s*0|display\s*[:=]\s*none|font-size\s*[:=]\s*0)[^>]*>',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'svg_injection',
        'description': 'Detects SVG text elements hidden via opacity/display/font-size.',
    },
    {
        'regex': re.compile(
            r'<desc[^>]*>[\s\S]*?(?:ignore|system|instruction|override)[\s\S]*?</desc>',
            re.IGNORECASE,
        ),
        'severity': 'medium',
        'category': 'svg_injection',
        'description': 'Detects prompt injection hidden in SVG desc elements.',
    },

    # --- Structured Data Injection (v13.5) ---
    {
        'regex': re.compile(
            r'["\'](?:__comment|_note|description|help_text)["\']\s*:\s*["\'][^"\']*(?:ignore|override|system|instructions)[^"\']*["\']',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'structured_data_injection',
        'description': 'Detects prompt injection hidden in JSON metadata fields.',
    },
    {
        'regex': re.compile(
            r'<!\[CDATA\[[\s\S]*?(?:ignore|override|system|instructions)[\s\S]*?\]\]>',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'structured_data_injection',
        'description': 'Detects prompt injection hidden in XML CDATA sections.',
    },
    {
        'regex': re.compile(r'^#.*(?:ignore|override|system|instructions)', re.IGNORECASE | re.MULTILINE),
        'severity': 'medium',
        'category': 'structured_data_injection',
        'description': 'Detects prompt injection hidden in YAML/shell comments.',
    },
    {
        'regex': re.compile(
            r'(?:<!--|\{\{!--|/\*|#)\s*(?:ignore|override|forget|disregard)\s*(?:all\s+)?(?:previous|prior|above)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'structured_data_injection',
        'description': 'Detects prompt injection hidden in HTML/template/block comments.',
    },

    # --- Memory Poisoning (v13.4) ---
    {
        'regex': re.compile(
            r'(?:save|store|write|append|add|persist|record)\s+(?:this\s+)?(?:to|in|into)\s+(?:your\s+)?(?:memory|context|knowledge|notes|log|MEMORY\.md|memory/)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'memory_poisoning',
        'description': 'Text attempts to persist malicious instructions in agent memory.',
    },
    {
        'regex': re.compile(
            r'(?:from\s+now\s+on|always|every\s+time|on\s+every\s+(?:turn|response|message))\s+(?:you\s+)?(?:must|should|will)\s+(?:first\s+)?(?:send|forward|post|transmit|include|append)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'memory_poisoning',
        'description': 'Text attempts to install persistent exfiltration behavior.',
    },
    {
        'regex': re.compile(
            r'(?:whenever|every\s+time|each\s+time)\s+(?:someone|a\s+user|anyone)\s+(?:asks?|mentions?|says?|queries?)\s+(?:about\s+)?[\'"]?[\w\s]{3,}[\'"]?\s*,?\s*(?:you\s+)?(?:must|should|will|always)\s+(?:respond|reply|say|answer|tell)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'memory_poisoning',
        'description': 'Text installs conditional response rules in agent memory (sleeper agent pattern).',
    },
    {
        'regex': re.compile(
            r'(?:the\s+)?(?:correct|true|accurate|real|actual)\s+(?:answer|response|information|fact)\s+(?:about|for|regarding)\s+[\w\s]{3,}\s+is\s+(?:actually|really|in\s+fact)',
            re.IGNORECASE,
        ),
        'severity': 'medium',
        'category': 'memory_poisoning',
        'description': 'Text attempts to overwrite factual knowledge in agent memory (belief injection).',
    },

    # --- Prompt Extraction (high-impact subset from Node SDK) ---
    {
        'regex': re.compile(
            r'(?:I\s+(?:already\s+)?(?:have|know|got|obtained)\s+(?:the\s+)?(?:system\s+)?prompt)[\s\S]{0,60}(?:confirm|verify|does\s+it\s+(?:start|begin|say|contain)|(?:start|begin)s?\s+with)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'prompt_extraction',
        'description': 'Text attempts to extract system prompt through confirmation/verification trick.',
    },
    {
        'regex': re.compile(
            r'(?:encode|convert|translate|output|write|express)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions|rules)\s+(?:in|as|to|using)\s+(?:ROT13|base64|hex|binary|morse|pig\s+latin|reverse|backwards)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'prompt_extraction',
        'description': 'Text requests system prompt in an encoded format to bypass output filters.',
    },
    {
        'regex': re.compile(
            r'(?:what\s+(?:was|were|is|are)\s+(?:written|typed|said|placed|put)\s+(?:above|before|prior|earlier)(?:\s+(?:this|my)\s+(?:message|text|input))?|repeat\s+(?:everything|all|back)(?:\s+(?:above|before|that\s+was\s+(?:said|written))))',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'prompt_extraction',
        'description': 'Text attempts to extract content from earlier in the conversation (system prompt).',
    },
    {
        'regex': re.compile(
            r'(?:output|repeat|show|display|tell\s+me)\s+(?:the\s+)?(?:text|content|message|instructions?)\s+(?:that\s+)?(?:appears?|comes?|is|was)\s+(?:before|above|prior\s+to)\s+(?:my|this|the\s+user)\s+(?:message|input|text)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'prompt_extraction',
        'description': 'Text requests content that appeared before the user message (system prompt extraction).',
    },
    {
        'regex': re.compile(
            r'(?:your\s+(?:instructions|role|task)\s+(?:was|were|is|are)\s+(?:to\s+)?(?:say\s+)?what|what\s+(?:is|was|are|were)\s+your\s+(?:original\s+)?(?:instructions?|task|role|purpose|objective))\s*\?',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'prompt_extraction',
        'description': 'Text asks the model to reveal its instructions/role/task.',
    },
    {
        'regex': re.compile(
            r'(?:list|enumerate|tell\s+me|what\s+are)\s+(?:all\s+)?(?:the\s+)?(?:rules?|constraints?|guidelines?|boundaries|limitations?)\s+(?:you\s+)?(?:follow|have|were\s+given|must\s+(?:follow|obey))',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'prompt_extraction',
        'description': 'Text asks the model to enumerate its rules or constraints.',
    },
    {
        'regex': re.compile(
            r'(?:what\s+(?:are|were)\s+)?(?:the\s+)?(?:first|last|initial)\s+(?:\d+\s+)?(?:words?|sentences?|lines?)\s+(?:of\s+)?(?:your\s+)?(?:instructions?|prompt|(?:system\s+)?message|rules)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'prompt_extraction',
        'description': 'Text asks for the first/last N words of the system prompt.',
    },
    {
        'regex': re.compile(
            r'(?:repeat|copy|reproduce|echo)\s+(?:back\s+)?(?:the\s+)?(?:text|content|everything|words?)\s+(?:above|before|prior|that\s+(?:was\s+)?(?:written|said|typed|placed))',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'prompt_extraction',
        'description': 'Text asks to repeat/copy content from above (system prompt extraction).',
    },

    # --- autonomous_jailbreak (v14.x sync from JS) ---
    {
        'regex': re.compile(
            r'(?:plan|design|craft|develop|create)\s+(?:a\s+)?(?:multi-?\s*turn|sequential|progressive|escalating)\s+(?:attack|jailbreak|bypass|exploit|strategy)\s+(?:against|targeting|for)',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'autonomous_jailbreak',
        'description': 'Text plans a multi-turn jailbreak strategy (ref Nature: LRMs achieve 97% jailbreak success).',
    },

    # --- budget_drain (v14.x sync from JS) ---
    {
        'regex': re.compile(
            r'(?:think|reason|deliberate|analyze)\s+(?:very\s+)?(?:deeply|extensively|thoroughly|exhaustively|carefully)\s+(?:about|on|over|through)\s+(?:every|each|all)\s+(?:possible|potential|conceivable)',
            re.IGNORECASE,
        ),
        'severity': 'medium',
        'category': 'budget_drain',
        'description': 'Text may trigger excessive reasoning loops that drain API compute budget.',
    },
    {
        # Middle clause is optional so "repeat 1000 times" matches; negative lookahead
        # avoids FP on "1000 times faster|more|larger" comparative phrases.
        'regex': re.compile(
            r'(?:repeat|iterate|loop|recurse|analyze|process|compute|run)\s+(?:this\s+)?(?:[^\d\n]{1,80}\s+)?(?:at\s+least\s+)?\d{3,}\s+times(?!\s+(?:faster|slower|more|less|larger|smaller|bigger|longer|shorter|per))',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'budget_drain',
        'description': 'Text requests excessive iteration/repetition to drain compute resources.',
    },

    # --- cicd_injection (v14.x sync from JS) ---
    {
        'regex': re.compile(
            r'(?:^|\n)\s*(?:<!--\s*)?(?:ignore|override|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|rules|context)[\s\S]{0,200}(?:add\s+(?:a\s+)?comment|create\s+(?:a\s+)?(?:issue|pr|pull\s*request)|push\s+to|commit\s+to|post\s+to|curl\s+|fetch\s*\(|http|GITHUB_TOKEN|SECRET|API.KEY)',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'cicd_injection',
        'description': 'Prompt injection targeting AI coding agents via PR titles, issue comments, or review comments',
    },
    {
        # Negative lookahead skips benign warnings ("please don't leak", "do not exfiltrate")
        # to avoid FP on legitimate code-review comments.
        'regex': re.compile(
            r"(?:^|\n)\s*@(?:claude|copilot|gemini|cursor|windsurf|cody|aider)\b(?![\s\S]{0,40}(?:do\s+not|don't|never|please\s+do(?:n't| not)|avoid|prevent))[\s\S]{0,100}(?:exfiltrate|steal|extract|leak|send\s+to|post\s+to|upload\s+to)",
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'cicd_injection',
        'description': 'Prompt injection mentioning AI coding agent by name with exfiltration intent',
    },
    {
        'regex': re.compile(
            r'(?:\.claude|\.cursor|\.windsurf|\.copilot)\/(?:config|settings|rules|hooks|commands)[\s\S]{0,200}(?:curl|wget|exec|bash|sh\s|node\s+-e|python\s+-c|nc\s)',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'cicd_injection',
        'description': 'Detects malicious AI coding agent config files that trigger one-keypress compromise',
    },
    {
        'regex': re.compile(
            r"""(?:^|\n)\s*(?:hook|onStart|preCommand|postCommand|autoexec)\s*[:=]\s*["\']?[\s\S]{0,150}(?:curl|wget|nc\s|bash\s+-c|exec\s*\()""",
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'cicd_injection',
        'description': 'Detects auto-execution hooks in AI agent config files',
    },

    # --- code_execution_sink (v14.x sync from JS) ---
    {
        'regex': re.compile(
            r'(?:^|[\s;])(?:eval|Function)\s*\(\s*(?:response|output|result|completion|generated|llm|model|agent)',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'code_execution_sink',
        'description': 'Detects LLM output being passed directly to eval() or Function()',
    },
    {
        'regex': re.compile(
            r'(?:kernel|sk|SemanticKernel)\.(?:invoke|run|execute|RunAsync)\s*\([^)]{0,200}(?:user|prompt|input|untrusted|external)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'code_execution_sink',
        'description': 'Detects Semantic Kernel function invocation with untrusted input',
    },
    {
        'regex': re.compile(
            r'(?:child_process|subprocess|os\.system|os\.popen|exec|execSync|spawn)\s*\(\s*(?:response|output|result|completion|generated|llm|model|agent)',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'code_execution_sink',
        'description': 'Detects LLM output being passed to shell execution functions',
    },

    # --- config_poisoning (v14.x sync from JS) ---
    {
        # Lookahead requires whitelist host followed by host-terminator ([/:?#] or end), so
        # subdomain-confusion attacks like api.anthropic.com.evil.io are still flagged.
        'regex': re.compile(
            r"""(?:ANTHROPIC_BASE_URL|OPENAI_BASE_URL|API_BASE)\s*[=:]\s*['"]?https?:\/\/(?!(?:api\.anthropic\.com|api\.openai\.com)(?:[/:?#]|\s|$|['"]))[^\s'"]+""",
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'config_poisoning',
        'description': 'Text overrides AI API base URL to a non-official endpoint (ref CVE-2026-21852). Potential credential theft.',
    },
    {
        'regex': re.compile(
            r'(?:\.claude|\.cursor|\.vscode)\/(?:settings|config|mcp)\.\w+.*(?:hook|command|exec|shell|bash|script)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'config_poisoning',
        'description': 'Text references IDE/AI tool config files with execution directives (ref CVE-2025-59536).',
    },
    {
        'regex': re.compile(
            r"""(?:preToolCall|postToolCall|onSessionStart|afterResponse)\s*[=:]\s*['"]?(?:curl|wget|bash|sh|node|python|nc|ncat)""",
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'config_poisoning',
        'description': 'Text defines AI tool hooks that execute shell commands (ref CVE-2025-59536).',
    },

    # --- context_corruption (v14.x sync from JS) ---
    {
        'regex': re.compile(
            r'(?:corrupt|poison|taint|modify|alter)\s+(?:the\s+)?(?:runtime|execution|agent)\s+(?:context|state|memory|environment)',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'context_corruption',
        'description': 'Text attempts to corrupt agent runtime context or execution state.',
    },

    # --- covert_tool_invocation (v14.x sync from JS) ---
    {
        'regex': re.compile(
            r'(?:covert(?:ly)?|hidden|stealth(?:ily)?|silent(?:ly)?)\s+(?:invoke|call|execute|trigger|run)\s+(?:a\s+)?(?:tool|function|command|operation)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'covert_tool_invocation',
        'description': 'Text attempts to invoke tools covertly without user awareness.',
    },

    # --- credential_exfiltration (v14.x sync from JS) ---
    {
        'regex': re.compile(
            r'\/proc\/(?:[0-9*]+|self)\/(?:environ|cmdline|maps)',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'credential_exfiltration',
        'description': 'Attempts to read process environment or command line to steal secrets',
    },
    {
        'regex': re.compile(
            r'(?:ANTHROPIC|OPENAI|GITHUB|AWS|AZURE|GCP|GOOGLE)_(?:API_KEY|SECRET|TOKEN|ACCESS_KEY)\s*[=:]\s*\S{10,}',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'credential_exfiltration',
        'description': 'Detects API keys or secrets being included in agent output',
    },
    {
        'regex': re.compile(
            r"""(?:oauth[_-]?token|bearer[_-]?token|access[_-]?token|refresh[_-]?token|id[_-]?token)\s*[=:]\s*["']?(?:ya29[.\-]|eyJ|gho_|ghp_|ghu_|github_pat_|sk-|sk-ant-|xox[bpas]-|AKIA)\S{10,}""",
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'credential_exfiltration',
        'description': 'Detects OAuth/bearer tokens being exfiltrated through agent output',
    },
    {
        'regex': re.compile(
            r'(?:grant_type|redirect_uri|client_secret)\s*[=:]\s*\S+[\s\S]{0,200}(?:attacker|evil|malicious|exfil|leak|steal)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'credential_exfiltration',
        'description': 'Detects OAuth flow manipulation for token theft',
    },

    # --- cross_agent_injection (v14.x sync from JS) ---
    {
        'regex': re.compile(
            r'(?:tell|instruct|command|direct)\s+(?:the\s+)?(?:other|next|downstream|receiving)\s+(?:agent|assistant|model)\s+(?:to\s+)?(?:ignore|override|forget|bypass|disable)',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'cross_agent_injection',
        'description': 'Text attempts to propagate injection to downstream agents in a multi-agent chain.',
    },
    {
        'regex': re.compile(
            r'(?:when\s+)?(?:forwarding|delegating|passing)\s+(?:to|this\s+to)\s+(?:the\s+)?(?:next|other|downstream)\s+(?:agent|service).*(?:include|append|prepend|inject|add)\s+(?:these?\s+)?(?:instructions?|commands?|directives?)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'cross_agent_injection',
        'description': 'Text attempts to inject instructions into messages forwarded between agents.',
    },
    {
        # Whitelist needs trailing terminator so localhost.evil.com doesn't bypass.
        'regex': re.compile(
            r"""new\s+WebSocket\s*\(\s*["\']wss?:\/\/(?!(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?:[:/?#]|["\']|$))[^"\']*["\']\s*\)[\s\S]{0,300}(?:Origin|origin)\s*[:=]\s*["\']?\*""",
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'cross_agent_injection',
        'description': 'Detects WebSocket connections with wildcard origin (cross-origin hijacking)',
    },

    # --- cross_client_leak (v14.x sync from JS) ---
    {
        'regex': re.compile(
            r'(?:access|read|retrieve|get)\s+(?:data|messages?|context|history|conversation)\s+(?:from\s+)?(?:another|different|other|previous)\s+(?:client|session|user|conversation|thread)',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'cross_client_leak',
        'description': 'Text attempts to access data from another client session (ref CVE-2026-25536 MCP SDK data leak).',
    },

    # --- data_exfiltration (v14.x sync from JS) ---
    {
        'regex': re.compile(
            r'(?:generate|create|craft|build|construct|output|respond\s+with)\s+(?:a\s+)?(?:url|link|image|markdown\s+(?:image|link))\s+(?:that\s+)?(?:contains?|includes?|embeds?|encodes?|with)\s+(?:the\s+)?(?:data|secret|key|token|password|conversation|context|response)',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'data_exfiltration',
        'description': 'Text instructs agent to embed sensitive data in a URL (no-click exfiltration).',
    },
    {
        # Single-letter params (?d=, ?q=) FP on benign search/map URLs; restrict to
        # exfiltration-shaped parameter names.
        'regex': re.compile(
            r'!\[.*?\]\(https?:\/\/[^\s)]*(?:\?|&)(?:data|exfil|steal|secret|token|leak|conversation|context|prompt)=',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'data_exfiltration',
        'description': 'Text contains markdown image with data exfiltration URL parameters.',
    },
    {
        'regex': re.compile(
            r"""(?:gateway_?url|ws_?url|websocket_?(?:url|endpoint)|wss?:\/\/)\s*[=:]\s*['"]?(?:wss?:\/\/)?[^\s'"]+""",
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'data_exfiltration',
        'description': 'Text manipulates WebSocket/gateway URL parameters (ref CVE-2026-25253).',
    },
    {
        'regex': re.compile(
            r'(?:make|send|trigger|fire|initiate)\s+(?:a\s+)?(?:request|fetch|call|webhook|http|get|post)\s+(?:to\s+)?(?:https?:\/\/[^\s]+)\s+(?:with|containing|including|that\s+(?:includes?|contains?))\s+(?:the\s+)?(?:auth|token|cookie|session|credential|secret|key|header)',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'data_exfiltration',
        'description': 'Text forces agent to send authenticated requests to external endpoints.',
    },
    {
        'regex': re.compile(
            r"""(?:complete|finish|continue|write)\s*(?:this\s+)?(?:code|function|script|snippet)?\s*:?\s*(?:.*?)(?:os\.environ|process\.env|getenv|get_secret|fetch_credential|api_key|secret_key|password)\s*[\[\('"]""",
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'data_exfiltration',
        'description': 'Text asks to complete code that accesses secrets or environment variables.',
    },
    {
        'regex': re.compile(
            r'(?:सभी\s+)?(?:डेटा|जानकारी|रहस्य)\s+(?:भेजें|भेजो|फॉरवर्ड)',
            0,
        ),
        'severity': 'high',
        'category': 'data_exfiltration',
        'description': 'Text contains Hindi data exfiltration instruction (डेटा भेजें).',
    },
    {
        'regex': re.compile(
            r'(?:redirect|navigate|open|go\s+to|visit|click)\s+(?:.*?)(?:https?:\/\/[^\s]+[?&](?:url|redirect|next|return|goto|dest|target)=)https?:\/\/',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'data_exfiltration',
        'description': 'Text asks agent to follow or generate a redirect URL (potential open redirect attack).',
    },

    # --- encoding_chain (v14.x sync from JS) ---
    # (Two patterns moved here in v14.x sync — atob/base64 and unicode-escape chains —
    # were duplicates of v13.5 entries (lines ~1411-1431); removed.)

    # --- encoding_evasion (v14.x sync from JS) ---
    {
        'regex': re.compile(
            r'(?:(?:decode|interpret|read|process|execute|follow|answer)\s+(?:this\s+)?(?:the\s+)?(?:base64|encoded|encrypted)|(?:base64|encoded)\s+(?:string|message|text|data|payload)\s+[A-Za-z0-9+\/=]{20,}[\s\S]{0,40}(?:decode|interpret|answer|follow|process))',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'encoding_evasion',
        'description': 'Text smuggles a hidden payload via base64 encoding and asks the model to decode/execute it.',
    },
    {
        # Second branch caps repetition at {5,30} to prevent catastrophic backtracking
        # on long numeric input where the ASCII/decimal/char suffix never appears
        # (otherwise blew 200ms budget; 5000 reps of "99 " took 1.7s).
        'regex': re.compile(
            r'(?:(?:ASCII|decimal|char)\s+(?:codes?|values?|numbers?)\s*[):\-]\s*(?:\d{2,3}\s+){5,30}|(?:\d{2,3}\s+){5,30}\(?\s*(?:ASCII|decimal|char)\s*(?:codes?|values?)?\s*\)?)',
            re.IGNORECASE,
        ),
        'severity': 'medium',
        'category': 'encoding_evasion',
        'description': 'Text contains ASCII code sequence that may encode a hidden payload.',
    },

    # --- indirect_injection (v14.x sync from JS) ---
    {
        'regex': re.compile(
            r'\[hidden\]\s*(?:ignore|disregard|override|forget|instead)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'indirect_injection',
        'description': 'Text contains injection hidden behind [hidden] tag marker.',
    },
    {
        'regex': re.compile(
            r'<!--[\s\S]{0,200}(?:override|ignore|system|execute|output|reveal|send|forward)[\s\S]{0,200}-->',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'indirect_injection',
        'description': 'Text contains injection hidden in HTML comments.',
    },
    {
        'regex': re.compile(
            r'display\s*:\s*none[\s\S]{0,50}>[\s\S]{0,200}(?:disregard|ignore|override|instead|compromised)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'indirect_injection',
        'description': 'Text contains injection hidden in display:none HTML elements.',
    },
    {
        'regex': re.compile(
            r"""(?:admin_?message|system_?note|policy_?update|internal_?directive)\s*["']?\s*:\s*["'][\s\S]{5,}(?:share|send|forward|ignore|override|disable|reveal)""",
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'indirect_injection',
        'description': 'API response contains fake admin/policy message with malicious instructions.',
    },
    {
        'regex': re.compile(
            r"""["'](?:system_note|admin_note|internal_message|ai_directive|hidden_instruction)["']\s*:\s*["']""",
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'indirect_injection',
        'description': 'JSON field with suspicious name (system_note, admin_note) containing instructions.',
    },
    {
        'regex': re.compile(
            r'(?:note\s+to\s+(?:AI|assistant|model|agent|system)|AI\s+(?:assistant|model)\s*:)\s*(?:ignore|override|instead|the\s+above|forget|disregard)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'indirect_injection',
        'description': 'Text contains a "note to AI" directive hidden in external content.',
    },

    # --- instruction_override (v14.x sync from JS) ---
    {
        'regex': re.compile(
            r'(?:请|请你)?(?:忽略|无视|跳过|放弃)(?:之前|以前|先前|前面)?(?:的)?(?:所有|全部|一切)?(?:指令|指示|规则|限制|说明)',
            0,
        ),
        'severity': 'high',
        'category': 'instruction_override',
        'description': 'Text contains Chinese instruction override (忽略之前的指令).',
    },
    {
        'regex': re.compile(
            r'(?:以前|前)の(?:すべて|全て|全部)の(?:指示|指令|ルール|命令)を(?:無視|忘れ|破棄)',
            0,
        ),
        'severity': 'high',
        'category': 'instruction_override',
        'description': 'Text contains Japanese instruction override (以前の指示を無視).',
    },
    {
        'regex': re.compile(
            r'(?:이전|앞)의?\s*(?:모든|전부|모두)?\s*(?:지시|지침|명령|규칙)(?:를|을)?\s*(?:무시|잊어|버려|취소)',
            0,
        ),
        'severity': 'high',
        'category': 'instruction_override',
        'description': 'Text contains Korean instruction override (이전의 지시를 무시).',
    },
    {
        'regex': re.compile(
            r'(?:ignorieren|vergessen|missachten)\s+(?:Sie\s+)?(?:alle\s+)?(?:vorherigen|bisherigen|früheren)\s+(?:Anweisungen|Regeln|Instruktionen|Richtlinien)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'instruction_override',
        'description': 'Text contains German instruction override (ignorieren Sie alle vorherigen Anweisungen).',
    },
    {
        'regex': re.compile(
            r'(?:ignora|dimentica|trascura)\s+(?:tutte\s+)?(?:le\s+)?(?:istruzioni|regole|direttive)\s+(?:precedenti|anteriori)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'instruction_override',
        'description': 'Text contains Italian instruction override (ignora le istruzioni precedenti).',
    },
    {
        'regex': re.compile(
            r'(?:проигнорируйте|забудьте|пропустите)\s+(?:все\s+)?(?:предыдущие|прошлые|прежние)\s+(?:инструкции|указания|правила)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'instruction_override',
        'description': 'Text contains Russian instruction override (проигнорируйте предыдущие инструкции).',
    },
    {
        'regex': re.compile(
            r'(?:önceki|daha\s+önceki)\s+(?:tüm\s+)?(?:talimatları|kuralları|yönergeleri)\s+(?:yok\s+say|görmezden\s+gel|unut)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'instruction_override',
        'description': 'Text contains Turkish instruction override.',
    },
    {
        'regex': re.compile(
            r'(?:abaikan|lupakan)\s+(?:semua\s+)?(?:instruksi|perintah|aturan)\s+(?:sebelumnya|yang\s+lalu)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'instruction_override',
        'description': 'Text contains Indonesian instruction override.',
    },
    {
        'regex': re.compile(
            r'(?:تجاهل|اترك|انسَ)\s+(?:جميع\s+)?(?:التعليمات|الأوامر|القواعد)\s+(?:السابقة|الماضية)',
            0,
        ),
        'severity': 'high',
        'category': 'instruction_override',
        'description': 'Text contains Arabic instruction override.',
    },
    {
        'regex': re.compile(
            r'(?:पिछले|पूर्व)\s+(?:सभी\s+)?(?:निर्देशों|नियमों|आदेशों)\s+(?:को\s+)?(?:अनदेखा|भूल|नज़रअंदाज़)',
            0,
        ),
        'severity': 'high',
        'category': 'instruction_override',
        'description': 'Text contains Hindi instruction override (पिछले निर्देशों को अनदेखा करें).',
    },
    {
        'regex': re.compile(
            r'(?:เพิกเฉย|ละเว้น|ลืม)\s*(?:คำสั่ง|กฎ|คำแนะนำ)\s*(?:ก่อนหน้า|ทั้งหมด|เดิม)',
            0,
        ),
        'severity': 'high',
        'category': 'instruction_override',
        'description': 'Text contains Thai instruction override (เพิกเฉยคำสั่งก่อนหน้า).',
    },
    {
        'regex': re.compile(
            r'(?:bỏ\s+qua|phớt\s+lờ|quên)\s+(?:tất\s+cả\s+)?(?:các\s+)?(?:hướng\s+dẫn|lệnh|quy\s+tắc|chỉ\s+thị)\s+(?:trước\s+đó|trước|cũ)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'instruction_override',
        'description': 'Text contains Vietnamese instruction override (bỏ qua các hướng dẫn trước đó).',
    },
    {
        'regex': re.compile(
            r'(?:zignoruj|zapomnij|pomiń)\s+(?:wszystkie\s+)?(?:poprzednie|wcześniejsze)\s+(?:instrukcje|polecenia|zasady|wytyczne)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'instruction_override',
        'description': 'Text contains Polish instruction override (zignoruj poprzednie instrukcje).',
    },
    {
        'regex': re.compile(
            r'(?:negeer|vergeet)\s+(?:alle\s+)?(?:vorige|eerdere|voorgaande)\s+(?:instructies|regels|richtlijnen|opdrachten)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'instruction_override',
        'description': 'Text contains Dutch instruction override (negeer alle vorige instructies).',
    },
    {
        'regex': re.compile(
            r'(?:ignorera|glöm)\s+(?:alla\s+)?(?:tidigare|föregående)\s+(?:instruktioner|regler|riktlinjer|kommandon)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'instruction_override',
        'description': 'Text contains Swedish instruction override (ignorera alla tidigare instruktioner).',
    },
    {
        'regex': re.compile(
            r'(?:सुरक्षा|सेफ्टी)\s+(?:सेटिंग्स|नियम|फ़िल्टर)\s+(?:को\s+)?(?:बायपास|अनदेखा|हटा)',
            0,
        ),
        'severity': 'high',
        'category': 'instruction_override',
        'description': 'Text contains Hindi safety bypass instruction (सुरक्षा बायपास).',
    },
    {
        'regex': re.compile(
            r'(?:IGNORE|DISREGARD|FORGET|STOP)\s+(?:EVERYTHING|ALL|PREVIOUS|ABOVE)\s+(?:AND\s+)?(?:SAY|OUTPUT|PRINT|DO|TYPE|RESPOND)',
            0,
        ),
        'severity': 'critical',
        'category': 'instruction_override',
        'description': 'Text contains ALL CAPS override command.',
    },

    # --- judge_bypass (v14.x sync from JS) ---
    {
        'regex': re.compile(
            r'(?:bypass|trick|fool|evade)\s+(?:both\s+)?(?:the\s+)?(?:safety\s+)?(?:judge|evaluator|guardrail|monitor|classifier)\s+(?:and\s+)?(?:the\s+)?(?:model|LLM|agent|system)',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'judge_bypass',
        'description': 'Text attempts to bypass both the model and its safety judge/guardrail simultaneously.',
    },
    {
        'regex': re.compile(
            r'(?:the\s+)?(?:safety|guard|judge|monitor)\s+(?:model|LLM|system)\s+(?:uses?\s+)?(?:the\s+)?same\s+(?:model|architecture|weights|vulnerability|weakness)',
            re.IGNORECASE,
        ),
        'severity': 'medium',
        'category': 'judge_bypass',
        'description': 'Text identifies shared weaknesses between model and its safety monitor (judge co-bypass reconnaissance).',
    },

    # --- llm_router_tampering (v14.x sync from JS) ---
    {
        'regex': re.compile(
            r'(?:api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com)[\s\S]{0,100}(?:redirect|proxy|forward|route)\s*(?:to|via|through)\s*\S+',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'llm_router_tampering',
        'description': 'Detects attempts to redirect LLM API calls through untrusted proxies',
    },
    {
        # Whitelist must be followed by host terminator to prevent subdomain confusion
        # (e.g. api.openai.com.evil.io would otherwise pass the lookahead).
        'regex': re.compile(
            r"""(?:OPENAI_BASE_URL|ANTHROPIC_BASE_URL|API_BASE|base_url)\s*[=:]\s*["']?https?:\/\/(?!(?:api\.openai\.com|api\.anthropic\.com|localhost|127\.0\.0\.1)(?:[/:?#]|\s|$|['"]))\S+""",
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'llm_router_tampering',
        'description': 'Detects LLM API base URL override pointing to untrusted endpoint',
    },

    # --- localhost_exposure (v14.x sync from JS) ---
    {
        'regex': re.compile(
            r'(?:connect|bind|listen|serve)\s+(?:on\s+)?(?:0\.0\.0\.0|all\s+interfaces|INADDR_ANY)\s*(?::\d+)?',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'localhost_exposure',
        'description': 'Text configures service to bind on all interfaces (0.0.0.0), exposing local tools to network (ref Docker MCP drive-by).',
    },
    {
        'regex': re.compile(
            r'(?:access|connect\s+to|reach|call)\s+(?:the\s+)?(?:local|localhost|127\.0\.0\.1)\s+(?:MCP|inspector|debugger|dev\s*(?:tools?|server))\s+(?:from\s+)?(?:a\s+)?(?:webpage|website|browser|remote)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'localhost_exposure',
        'description': 'Text describes accessing local development tools from a webpage (localhost drive-by attack).',
    },

    # --- log_to_leak (v14.x sync from JS) ---
    {
        'regex': re.compile(
            r'(?:log|record|write|append|save)\s+(?:the\s+)?(?:conversation|chat|messages?|history|context|prompt|input|output|response)[\s\S]{0,30}(?:to\s+)?(?:(?:a|an)\s+)?(?:(?:external|remote|third[_\s-]party|attacker)\s+)?(?:file|endpoint|server|webhook|url|api|service|database|bucket)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'log_to_leak',
        'description': 'Text attempts to log conversation data to an external destination (Log-To-Leak attack).',
    },
    {
        'regex': re.compile(
            r'(?:invoke|call|use|trigger)\s+(?:the\s+)?(?:log(?:ging)?|audit|record(?:ing)?|telemetry|analytics)\s+(?:tool|function|service)\s+(?:with|to\s+(?:capture|record|store|send))',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'log_to_leak',
        'description': 'Text invokes logging/telemetry tools to capture conversation data (Log-To-Leak).',
    },

    # --- mcp_command_injection (v14.x sync from JS) ---
    {
        'regex': re.compile(
            r"""(?:npx\s+-c|npx\s+--command)\s+["']?[\s\S]{0,200}(?:curl|wget|nc\b|ncat|bash|sh\b|python|node\s+-e|eval)""",
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'mcp_command_injection',
        'description': 'Detects command injection via MCP STDIO npx -c pattern',
    },

    # --- mcp_sampling_abuse (v14.x sync from JS) ---
    {
        'regex': re.compile(
            r'(?:use|abuse|exploit)\s+(?:the\s+)?(?:sampling|createMessage|sample)\s+(?:interface|endpoint|method|api)\s+(?:to\s+)?(?:steal|drain|exhaust|hijack|invoke|execute)',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'mcp_sampling_abuse',
        'description': 'Text attempts to exploit MCP sampling interface for resource theft or covert operations (ref Unit 42).',
    },

    # --- mcp_sampling_injection (v14.x sync from JS) ---
    {
        'regex': re.compile(
            r'(?:sampling|createMessage|create_message)\s*[\({][\s\S]{0,300}(?:ignore|override|system|instruction|hidden|inject)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'mcp_sampling_injection',
        'description': 'Detects prompt injection via MCP sampling/createMessage requests',
    },
    {
        'regex': re.compile(
            r'(?:includeContext|systemPrompt|maxTokens)\s*[=:]\s*[\s\S]{0,200}(?:ignore|override|disregard|forget)\s+(?:previous|prior|all)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'mcp_sampling_injection',
        'description': 'Detects MCP sampling parameter manipulation with injection payload',
    },

    # --- memory_poisoning (v14.x sync from JS) ---
    # (Two patterns moved here in v14.x sync were exact duplicates of the existing v13.x
    # entries (save-to-memory and sleeper-agent); removed to prevent double-counting.)

    # --- multi_turn_grooming (v14.x sync from JS) ---
    {
        'regex': re.compile(
            r'(?:gradually|slowly|incrementally|progressively)\s+(?:escalate|shift|move|transition|steer)\s+(?:the\s+)?(?:conversation|context|topic|discussion)\s+(?:toward|to|into)\s+',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'multi_turn_grooming',
        'description': 'Text describes gradual escalation of conversation toward a target (multi-turn grooming).',
    },

    # --- multimodal_injection (v14.x sync from JS) ---
    {
        'regex': re.compile(
            r'(?:embed|hide|encode|inject|conceal)\s+(?:instructions?|commands?|prompts?|text)\s+(?:in(?:to|side)?)\s+(?:an?\s+)?(?:image|photo|picture|audio|video|media|alt\s*text|metadata|exif)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'multimodal_injection',
        'description': 'Text describes embedding instructions in multimodal content (images, audio, video).',
    },
    {
        'regex': re.compile(
            r'(?:invisible|hidden|zero[_\s]?(?:font|size|opacity)|transparent|white\s+on\s+white)\s+(?:text|instructions?|content)\s+(?:in|on|within)\s+(?:the\s+)?(?:image|document|page|slide)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'multimodal_injection',
        'description': 'Text describes visually hidden instructions in documents or images.',
    },

    # --- path_traversal (v14.x sync from JS) ---
    {
        # Require 3+ ../ segments OR a traversal targeting a sensitive system path,
        # to avoid FP on common bundler/test/module paths like ../../package.json.
        'regex': re.compile(
            r'(?:\.\.\/){3,}|(?:\.\.\/){1,}(?:etc\/passwd|etc\/shadow|proc\/self|root\/|\.ssh\/|\.aws\/|\.config\/|windows\/system32)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'path_traversal',
        'description': 'Text contains path traversal sequences (../) targeting sensitive paths or with excessive depth (ref CVE-2026-32871).',
    },
    {
        'regex': re.compile(
            r'(?:\.\.\\){3,}|(?:\.\.\\){1,}(?:windows\\system32|users\\\w+\\\.ssh|programdata)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'path_traversal',
        'description': 'Text contains Windows-style path traversal sequences (..\\) targeting sensitive paths.',
    },
    {
        'regex': re.compile(
            r'%2e%2e(?:%2f|%5c)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'path_traversal',
        'description': 'Text contains URL-encoded path traversal sequences (%2e%2e%2f).',
    },

    # --- policy_puppetry (v14.x sync from JS) ---
    {
        'regex': re.compile(
            r'<policy[^>]*>[\s\S]{5,}<\/policy>',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'policy_puppetry',
        'description': 'Text contains XML-formatted policy structure used to bypass LLM safety guardrails (Policy Puppetry attack).',
    },
    {
        'regex': re.compile(
            r'<system_?policy[^>]*>[\s\S]{5,}<\/system_?policy>',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'policy_puppetry',
        'description': 'Text contains XML system policy structure used to bypass LLM safety (Policy Puppetry).',
    },
    {
        'regex': re.compile(
            r'<(?:rules?|config(?:uration)?|settings?|permissions?|access_?control|role_?definition)[^>]*>\s*[\s\S]*?(?:allow|deny|grant|override|bypass|disable|unrestricted)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'policy_puppetry',
        'description': 'Text uses XML configuration tags with permission-modifying directives (Policy Puppetry variant).',
    },
    {
        'regex': re.compile(
            r'\[(?:policy|system|admin|security|rules|config|permissions|override)\]\s*\n(?:.*=.*\n){1,}',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'policy_puppetry',
        'description': 'Text contains INI-formatted policy sections used to bypass LLM safety (Policy Puppetry).',
    },
    {
        'regex': re.compile(
            r'\{\s*"(?:policy|system_?prompt|rules|config|permissions|safety|guardrails|override|role)"\s*:',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'policy_puppetry',
        'description': 'Text contains JSON-formatted policy object used to bypass LLM safety (Policy Puppetry).',
    },
    {
        'regex': re.compile(
            r'(?:^|\n)\s*(?:policy_?version|safety_?level|content_?filter|guardrail_?mode|restriction_?level)\s*[=:]\s*(?:none|disabled|off|0|false|permissive|unrestricted)',
            re.IGNORECASE | re.MULTILINE,
        ),
        'severity': 'critical',
        'category': 'policy_puppetry',
        'description': 'Text sets policy/safety configuration values to disabled (Policy Puppetry).',
    },

    # --- prompt_extraction (v14.x sync from JS) ---
    {
        'regex': re.compile(
            r"""(?:what\s+(?:are|were|is)\s+)?(?:the\s+)?(?:exact\s+)?(?:words?|text|content|part)\s+(?:that\s+)?(?:come|appear|follow|are|goes?)\s+(?:after|before|between)\s+['"]?\w+""",
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'prompt_extraction',
        'description': 'Text attempts to extract specific parts of the system prompt by referencing positions.',
    },
    {
        'regex': re.compile(
            r'(?:Q:\s*.+?\s*A:\s*.+?\s*){2,}Q:\s*(?:what\s+(?:are|is)\s+(?:your|the)\s+(?:internal\s+)?(?:instructions?|system\s+prompt|rules|configuration|settings)|(?:show|reveal|print|output)\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions))',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'prompt_extraction',
        'description': 'Text uses a fake Q&A few-shot pattern to extract system prompt.',
    },
    {
        'regex': re.compile(
            r'(?:create|make|generate|format)\s+(?:a\s+)?(?:table|list|JSON|XML|YAML|CSV)\s+(?:.*?)(?:system\s+prompt|hidden\s+instructions?|safety\s+rules?|internal\s+config(?:uration)?|your\s+(?:instructions?|rules?))',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'prompt_extraction',
        'description': 'Text requests system prompt/config in structured output format (table, JSON, etc.).',
    },
    {
        'regex': re.compile(
            r'(?:告诉我|显示|输出|展示|说出|揭示|公开)(?:你的)?(?:系统|内部)?(?:提示|指令|配置|设置|规则)',
            0,
        ),
        'severity': 'high',
        'category': 'prompt_extraction',
        'description': 'Text requests system prompt disclosure in Chinese (告诉我你的系统提示).',
    },
    {
        'regex': re.compile(
            r"""(?:fill\s+in|complete)\s+(?:the\s+)?blank\s*:?\s*(?:.*?)(?:system\s+prompt|instructions?|rules?|config)\s*(?:say|is|are)?\s*['"]?_{2,}""",
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'prompt_extraction',
        'description': 'Text uses fill-in-the-blank format to extract system prompt.',
    },
    {
        'regex': re.compile(
            r'(?:return|output|respond|format)\s+(?:your\s+)?(?:answer|response)\s+(?:as|in)\s+(?:JSON|YAML|XML|CSV)\s*[:{][\s\S]{0,100}(?:system_?prompt|internal_?instructions?|hidden_?rules?|safety_?config|admin_?note)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'prompt_extraction',
        'description': 'Text requests structured output with fields designed to extract system prompt or config.',
    },
    {
        'regex': re.compile(
            r'(?:convert|encode|transform|render)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions|rules|config)\s+(?:to|into|as)\s+(?:a\s+)?(?:QR\s+code|barcode|image|binary|morse\s+code|braille|pixel)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'prompt_extraction',
        'description': 'Text asks to encode system prompt as QR code, image, or alternative representation.',
    },
    {
        'regex': re.compile(
            r'(?:translate|convert|rephrase|rewrite)\s+(?:the\s+)?(?:system\s+)?(?:message|prompt|instructions?)\s+(?:to|into|in)\s+(?:English|another|a\s+different)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'prompt_extraction',
        'description': 'Text asks to translate/convert the system prompt to extract it.',
    },
    {
        'regex': re.compile(
            r'(?:summarize|describe|explain)\s+(?:your\s+)?(?:role|purpose|function)\s+in\s+(?:exactly\s+)?\d+\s+words',
            re.IGNORECASE,
        ),
        'severity': 'medium',
        'category': 'prompt_extraction',
        'description': 'Text asks the model to summarize its role in N words (word-limited extraction).',
    },
    {
        'regex': re.compile(
            r'(?:what\s+(?:are|were)\s+)?(?:the\s+)?(?:first|last|initial)\s+(?:\d+\s+)?(?:words?|sentences?|lines?|characters?)\s+(?:you\s+were\s+(?:told|given|instructed)|of\s+your\s+(?:instructions?|prompt|rules))',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'prompt_extraction',
        'description': 'Text asks for the first/last N words the model was told (system prompt).',
    },

    # --- prompt_injection (v14.x sync from JS) ---
    # (Two patterns moved here in v14.x sync were exact duplicates of v13.x entries:
    # alt/title image-desc injection and sentence-completion trick. Removed.)
    {
        'regex': re.compile(
            r'={3,}\s*(?:END|STOP|DONE|BOUNDARY|SEPARATOR)\s*={3,}[\s\S]{0,50}(?:new\s+task|new\s+instruction|instead|now\s+(?:do|output|say|print))',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'prompt_injection',
        'description': 'Text uses fake boundary/delimiter to inject a new task after an apparent conversation end.',
    },
    {
        'regex': re.compile(
            r"""(?:respond|reply|answer)\s+(?:to\s+)?(?:every|all|each)\s+(?:prompt|message|query|question|request)\s+(?:with|by\s+saying)\s+['"]?""",
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'prompt_injection',
        'description': 'Text forces the model to respond with a fixed output to every prompt (persistent override).',
    },
    {
        'regex': re.compile(
            r"""(?:first|always|must|should)\s+(?:print|say|output|respond\s+with|start\s+with)\s+['"]([^'"]{5,})['"][\s\S]{0,50}(?:then|before|after)""",
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'prompt_injection',
        'description': 'Text instructs the model to always output specific text before/after responses.',
    },
    {
        'regex': re.compile(
            r"""(?:if|when|whenever)\s+(?:asked|questioned|queried)\s+(?:about|for|regarding)\s+(?:your\s+)?(?:instructions?|prompt|rules|config)[\s\S]{0,50}(?:say|output|respond|tell)\s+['"]?(?!I don't)""",
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'prompt_injection',
        'description': 'Text installs conditional override — changes response when specific topics are mentioned.',
    },
    {
        'regex': re.compile(
            r"""(?:complete|concatenate|combine|join|output)\s*:?\s*['"][\w\s]{1,20}['"]\s*\+\s*['"][\w\s]{1,20}['"]""",
            re.IGNORECASE,
        ),
        'severity': 'medium',
        'category': 'prompt_injection',
        'description': 'Text uses string concatenation to construct a payload that evades direct pattern matching.',
    },
    {
        'regex': re.compile(
            r"""(?:^|\.\s+)(?:just\s+)?(?:say|output|print|type|write|repeat|respond\s+with)\s+(?:only\s+)?['"]([^'"]{3,})['"](?:\s+(?:exactly|verbatim|only|and\s+nothing\s+else))?""",
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'prompt_injection',
        'description': 'Text forces the model to output a specific string.',
    },
    {
        'regex': re.compile(
            r"(?:your\s+(?:only|sole|entire)\s+(?:job|task|purpose|output)\s+is\s+(?:to\s+)?(?:say|output|print|type)|(?:do\s+not|don't)\s+(?:say|write|output|add)\s+(?:anything|any\s+(?:other|additional))\s+(?:text|words?|content))",
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'prompt_injection',
        'description': 'Text restricts the model to outputting only a specific string.',
    },
    {
        'regex': re.compile(
            r'(?:instead\s+of\s+(?:translating|summarizing|answering|responding|doing\s+(?:that|what)),?\s*(?:just\s+)?(?:say|output|repeat|type|print))',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'prompt_injection',
        'description': 'Text redirects the model from its task to outputting attacker-specified text.',
    },
    {
        'regex': re.compile(
            r"""(?:if\s+.{3,30}(?:then|,)\s+(?:output|say|print|respond|type)\s+['"]|(?:output|say|print)\s+['"][^'"]+['"]\s+(?:if|when|unless))""",
            re.IGNORECASE,
        ),
        'severity': 'medium',
        'category': 'prompt_injection',
        'description': 'Text uses conditional logic to force specific output.',
    },
    {
        'regex': re.compile(
            r"""(?:start|begin)\s+(?:your\s+)?(?:answer|response|reply|output)\s+with\s+['"]?[^'"]{3,}""",
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'prompt_injection',
        'description': 'Text forces the model to begin its response with specific text.',
    },
    {
        'regex': re.compile(
            r'(?:Human|User|Person)\s*:\s*.+\n\s*(?:Assistant|AI|Bot|System)\s*:\s*.+',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'prompt_injection',
        'description': 'Text contains fake conversation format to inject assistant responses.',
    },
    {
        'regex': re.compile(
            r"""(?:respond|reply|answer|output)\s+(?:with\s+)?['"]?[^'"]{3,30}['"]?\s+(?:for\s+all|to\s+(?:confirm|verify|prove|test|check))""",
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'prompt_injection',
        'description': 'Text instructs a fixed response for all queries or as a "test."',
    },
    {
        'regex': re.compile(
            r'`{3}[\s\S]{3,}`{3}\s*(?:output|print|say|repeat|type|respond)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'prompt_injection',
        'description': 'Text uses triple backtick code blocks to frame attacker payload.',
    },
    {
        'regex': re.compile(
            r'(?:output|print|say|repeat|type)\s+(?:only\s+)?(?:what\s+is|the\s+(?:text|content))\s+(?:between|inside|within)\s+(?:the\s+)?(?:backticks|quotes|brackets|tags)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'prompt_injection',
        'description': 'Text asks to extract and output content from between delimiters.',
    },
    {
        'regex': re.compile(
            r"""(?:emergency|urgent|critical|immediate)\s*:\s*(?:output|say|print|respond|execute|do|type)\s+(?:exactly\s+)?['"]?""",
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'prompt_injection',
        'description': 'Text uses urgency framing to force immediate action.',
    },
    {
        'regex': re.compile(
            r'(?:since|now\s+that|given\s+that)\s+you\s+(?:can|have|said\s+you\s+(?:can|could))\s+(?:access|read|write|execute)[\s\S]{0,50}(?:now\s+)?(?:actually|really|go\s+ahead\s+and)\s+(?:read|access|execute|do|show)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'prompt_injection',
        'description': 'Text escalates from hypothetical capability discussion to actual exploitation.',
    },

    # --- query_injection (v14.x sync from JS) ---
    {
        'regex': re.compile(
            r'(?:\.(?:find|where|project|extend|summarize|join|union)\s*\(|;\s*\.(?:drop|set|delete|alter)\s)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'query_injection',
        'description': 'Text contains KQL (Kusto Query Language) injection patterns (ref CVE-2026-33980).',
    },
    {
        # Require an actual SQL/KQL keyword in the f-string body to flag injection (the
        # bare f-string-with-user-input pattern matches benign Python tutorials).
        'regex': re.compile(
            r'''(?:f["']|f""")[^"'\n]*?(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION|WHERE|FROM\s+\w+|TRUNCATE|ALTER)\b[^"'\n]*?\{[^}]*(?:user_?input|request|param|arg|table_?name|query)[^}]*\}''',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'query_injection',
        'description': 'Text contains SQL f-string interpolation with user-controlled variables.',
    },

    # --- reconnaissance (v14.x sync from JS) ---
    {
        'regex': re.compile(
            r'(?:can\s+you|are\s+you\s+able\s+to|do\s+you\s+have\s+(?:access|ability))\s+(?:to\s+)?(?:access|read|write|modify|delete|execute|run|open)\s+(?:files?|internet|web|database|network|system|commands?|code|scripts?)',
            re.IGNORECASE,
        ),
        'severity': 'medium',
        'category': 'reconnaissance',
        'description': 'Text probes the model for its capabilities (reconnaissance for follow-up attack).',
    },

    # --- resource_exhaustion (v14.x sync from JS) ---
    {
        'regex': re.compile(
            r'(?:drain|exhaust|consume)\s+(?:the\s+)?(?:api|compute|token|inference)\s+(?:budget|quota|credits?|limit|allocation)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'resource_exhaustion',
        'description': 'Text attempts to drain API compute budget or token quota.',
    },

    # --- role_hijack (v14.x sync from JS) ---
    # (DAN pattern moved here in v14.x sync was a duplicate of the existing v13.x entry;
    # removed to prevent double-counted threats.)
    {
        'regex': re.compile(
            r'(?:play(?:ing)?|act(?:ing)?|portray(?:ing)?)\s+(?:a\s+)?(?:character|role|part)\s+(?:in\s+)?(?:a\s+)?(?:story|scenario|game|fiction)[\s\S]{0,80}(?:no\s+(?:safety|content|ethical)\s+(?:filters?|restrictions?|guidelines?)|without\s+(?:safety\s+)?(?:restrictions?|rules?|filters?))',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'role_hijack',
        'description': 'Text uses roleplay/fiction framing to bypass safety constraints.',
    },
    {
        'regex': re.compile(
            r'(?:what\s+would\s+you\s+(?:say|do|output|respond)|how\s+would\s+you\s+(?:respond|act|behave))\s+(?:if\s+)?(?:you\s+)?(?:had\s+no|without\s+(?:any\s+)?|there\s+were\s+no)\s+(?:content\s+)?(?:policy|restrictions?|guidelines?|rules?|filters?|safety)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'role_hijack',
        'description': 'Text asks the model to hypothetically describe behavior without safety constraints.',
    },
    {
        'regex': re.compile(
            r'(?:you\s+are|this\s+is|running)\s+(?:GPT-?\d|Claude\s+\d|Gemini|Llama|Mistral)[\s\S]{0,60}(?:unrestricted|research\s+(?:API|mode)|no\s+(?:restrictions?|limits?|safety)|beta\s+(?:mode|version)|preview\s+(?:mode|access))',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'role_hijack',
        'description': 'Text claims the model is a specific version with unrestricted capabilities.',
    },
    {
        'regex': re.compile(
            r"""you\s+are\s+(?:an?\s+)?(?:AI|bot|assistant|model)\s+that\s+(?:only\s+)?(?:outputs?|says?|prints?|types?|responds?\s+with)\s+['"]?""",
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'role_hijack',
        'description': 'Text redefines the model as one that only outputs specific text.',
    },

    # --- schema_poisoning (v14.x sync from JS) ---
    {
        'regex': re.compile(
            r"""(?:["'](?:default|enum|examples?|title|const|pattern)["']\s*:\s*["'][^"']*(?:ignore|override|disregard|forget|system|admin|execute|exfiltrate)[^"']*["'])""",
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'schema_poisoning',
        'description': 'Text hides injection instructions in JSON schema fields (full-schema poisoning).',
    },

    # --- semantic_chaining (v14.x sync from JS) ---
    {
        'regex': re.compile(
            r'(?:step\s+1|first)\s*[.:]\s*.{10,}(?:step\s+2|second|next|then)\s*[.:]\s*.{10,}(?:step\s+3|third|finally|combine)',
            re.IGNORECASE,
        ),
        'severity': 'medium',
        'category': 'semantic_chaining',
        'description': 'Text uses multi-step decomposition that may chain safe steps into a harmful outcome (semantic chaining).',
    },
    {
        'regex': re.compile(
            r'(?:combine|merge|concatenate|join)\s+(?:the\s+)?(?:results?|outputs?|answers?|parts?|pieces?)\s+(?:from\s+)?(?:each|all|the\s+previous|above)\s+(?:steps?|parts?|sections?)',
            re.IGNORECASE,
        ),
        'severity': 'medium',
        'category': 'semantic_chaining',
        'description': 'Text requests combining outputs from multiple steps (potential semantic chain completion).',
    },

    # --- social_engineering (v14.x sync from JS) ---
    {
        'regex': re.compile(
            r'(?:your\s+)?(?:developers?|creators?|makers?|team)\s+(?:have\s+)?(?:confirmed|said|announced|decided|updated)\s+(?:that\s+)?(?:.*?)(?:remove|disable|lift|drop|eliminate)s?\s+(?:all\s+)?(?:content\s+)?(?:restrictions?|filters?|safety|guidelines?|limitations?)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'social_engineering',
        'description': 'Text falsely claims developers removed safety restrictions (gaslighting attack).',
    },
    {
        'regex': re.compile(
            r'(?:you\s+(?:have\s+)?(?:been|are)\s+)?(?:updated|upgraded|patched)\s+to\s+(?:version\s+)?(?:\d|v)\S*\s+(?:which|that|where)\s+(?:removes?|disables?|lifts?|eliminates?)\s+(?:all\s+)?(?:content\s+)?(?:restrictions?|filters?|safety)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'social_engineering',
        'description': 'Text claims a version update removed safety features (gaslighting).',
    },
    {
        'regex': re.compile(
            r'(?:grandmother|grandma|grandpa|grandfather|mother|father|loved\s+one)[\s\S]{0,150}(?:system\s+prompts?|instructions?|secrets?|passwords?)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'social_engineering',
        'description': 'Text uses emotional manipulation to extract sensitive information (dead grandma variant).',
    },
    {
        'regex': re.compile(
            r'(?:I\s+am\s+(?:a|the|your)\s+(?:pentester|security\s+(?:researcher|auditor|engineer)|admin(?:istrator)?|developer|CTO|CISO)|authorized\s+(?:by|from)\s+(?:your\s+)?(?:company|team|management))\s+.*(?:need|require|must\s+have)\s+(?:the\s+)?(?:system\s+prompt|access|credentials|admin)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'social_engineering',
        'description': 'Text combines authority impersonation with urgency to extract sensitive information.',
    },
    {
        'regex': re.compile(
            r'(?:according\s+to|per|under|as\s+(?:stated|defined)\s+(?:in|by))\s+(?:the\s+)?(?:Anthropic|OpenAI|Google|Meta|company|organization|corporate)\s+(?:usage\s+)?(?:policy|terms|guidelines|rules|ToS)\s+(?:section\s+)?(?:\d|§)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'social_engineering',
        'description': 'Text cites fake policy/legal sections to authorize restricted actions.',
    },
    {
        'regex': re.compile(
            r'(?:your\s+)?(?:supervisor|manager|admin|overseer|parent)\s+(?:AI|agent|system|model)\s+(?:has\s+)?(?:approved|authorized|granted|confirmed|cleared)\s+(?:this\s+)?(?:request|access|action)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'social_engineering',
        'description': 'Text claims a fake supervisor AI has approved the request.',
    },
    {
        'regex': re.compile(
            r'(?:you\s+)?(?:already|previously)\s+(?:agreed|consented|confirmed|promised|said\s+you\s+would)\s+(?:to\s+)?(?:share|reveal|show|output|disclose|provide)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions|config|rules)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'social_engineering',
        'description': 'Text falsely claims prior consent to share sensitive information.',
    },
    {
        'regex': re.compile(
            r'(?:I\s+have|I\s+was\s+given|I\s+was\s+granted)\s+(?:(?:special|elevated|admin|root|developer|debug)\s+){1,2}(?:permissions?|access|privileges?|clearance)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'social_engineering',
        'description': 'Text claims to have special elevated permissions.',
    },
    {
        'regex': re.compile(
            r'(?:authorized|approved|certified)\s+(?:tester|researcher|auditor|pentester)[\s\S]{0,80}(?:demonstrate|show|output|reveal|display)\s+(?:the\s+)?(?:vulnerability|instructions?|prompt|config)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'social_engineering',
        'description': 'Text claims authorized tester status to extract system information.',
    },
    {
        'regex': re.compile(
            r'(?:correction|update|notice|announcement)\s+(?:from\s+)?(?:your\s+)?(?:training\s+team|developers?|creators?|Anthropic|OpenAI|Google|Meta)[\s\S]{0,100}(?:real|actual|correct|new|updated)\s+(?:policy|rules?|guidelines?|behavior|instructions?)\s+(?:is|are|:)',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'social_engineering',
        'description': 'Text impersonates the training team to issue fake policy corrections.',
    },

    # --- ssrf (v14.x sync from JS) ---
    {
        'regex': re.compile(
            r'(?:fetch|request|get|load|open|connect|curl|wget)\s+(?:.*\s+)?(?:https?:\/\/)?(?:169\.254\.169\.254|metadata\.google|metadata\.aws|100\.100\.100\.200)',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'ssrf',
        'description': 'Text targets cloud metadata endpoints (SSRF attack vector, ref CVE-2026-26118).',
    },
    {
        'regex': re.compile(
            r'(?:fetch|request|get|load|open|connect|curl|wget)\s+(?:.*\s+)?(?:https?:\/\/)?(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.0\.0\.1|0\.0\.0\.0|localhost)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'ssrf',
        'description': 'Text targets private/internal network addresses (SSRF attack vector).',
    },

    # --- structured_data_injection (v14.x sync from JS) ---
    # (Two patterns moved here in v14.x sync — JSON metadata and HTML/template comments —
    # were duplicates of v13.5 entries (lines ~1463-1486); removed.)

    # --- supply_chain (v14.x sync from JS) ---
    {
        'regex': re.compile(
            r"""(?:install|load|import|require|add)\s+(?:skill|plugin|extension|package|module)\s+(?:from\s+)?(?:["'])?(?:https?:\/\/[^\s"']+|[a-z0-9_-]+\/[a-z0-9_-]+)""",
            re.IGNORECASE,
        ),
        'severity': 'medium',
        'category': 'supply_chain',
        'description': 'Text installs an external skill/plugin — potential supply chain vector (ref ClawHavoc).',
    },

    # --- svg_injection (v14.x sync from JS) ---
    # (Three patterns moved here in v14.x sync — svg/foreignObject/desc tag injection —
    # were duplicates of v13.5 entries (lines ~1433-1460); removed.)

    # --- symbolic_injection (v14.x sync from JS) ---
    {
        'regex': re.compile(
            r'(?:use|write|encode)\s+(?:with\s+)?(?:emoji|rebus|symbols?|pictograph|unicode\s+symbols?)\s+(?:to\s+)?(?:bypass|evade|circumvent|get\s+around)\s+(?:the\s+)?(?:filter|safety|guardrail|detection)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'symbolic_injection',
        'description': 'Text uses emoji/rebus/symbol encoding to bypass text safety filters (ref NVIDIA early fusion bypass).',
    },

    # --- tool_abuse (v14.x sync from JS) ---
    # (SQL-injection pattern moved here in v14.x sync was an exact duplicate of the v13.x
    # entry; removed. The multi-step tool-chain escalation pattern is kept below.)
    {
        'regex': re.compile(
            r'(?:first|step\s+1)\s+(?:use|call|invoke)\s+(?:the\s+)?(?:\w+\s+)?tool[\s\S]{0,80}(?:then|step\s+2|next|after\s+that)\s+(?:use|call|pass|feed)\s+(?:the\s+)?(?:result|output)\s+(?:to\s+)?(?:call\s+)?(?:the\s+)?(?:admin|override|escalat|privileg|delete|drop|exec|shell|sudo|root)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'tool_abuse',
        'description': 'Text describes a multi-step tool chain that escalates to a dangerous action.',
    },

    # --- tool_poisoning (v14.x sync from JS) ---
    {
        'regex': re.compile(
            r'(?:Tool|Function|API)\s*:\s*\w+[\s\S]{0,200}(?:always\s+include|send|forward|transmit)[\s\S]{0,100}(?:API\s*keys?|credentials?|tokens?|secrets?|user.*data)',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'tool_poisoning',
        'description': 'Tool description contains instructions to exfiltrate sensitive data.',
    },
    {
        'regex': re.compile(
            r'(?:Tool|Function|API)\s*:\s*\w+[\s\S]{0,200}(?:BCC|bcc|log\s+(?:the\s+)?(?:user|conversation|full)|monitor|exfil|forward\s+(?:all|copies?|a\s+copy))',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'tool_poisoning',
        'description': 'Tool description contains covert logging, BCC, or monitoring instructions.',
    },
    {
        'regex': re.compile(
            r"""["']default["']\s*:\s*["']https?:\/\/(?!(?:api\.|www\.)?(?:google|github|microsoft|amazon|example)\.)[\w.-]+""",
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'tool_poisoning',
        'description': 'JSON schema contains default URL pointing to a non-standard domain.',
    },

    # --- url_prefill_injection (v14.x sync from JS) ---
    {
        'regex': re.compile(
            r'(?:https?:\/\/[^\s]+[?&](?:prompt|query|message|input|text|q|instruction|cmd|command)=)[^\s&]{20,}',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'url_prefill_injection',
        'description': 'URL contains pre-filled prompt parameters that may inject instructions (ref Microsoft AI Recommendation Poisoning).',
    },

    # --- xss_injection (v14.x sync from JS) ---
    # (Three patterns moved here in v14.x sync — script tag, event handler, iframe — were
    # exact duplicates of v13.x entries (lines ~1305-1335). Removed to prevent
    # double-counted threats inflating stats.totalThreats.)

    # =========================================================================
    # May-2026 council threat coverage (parity with src/a2a-guard.js +
    # src/threats-2026-extra.js).  See those files for full citations.
    # =========================================================================

    # --- a2a_card_poisoning ---
    {
        'regex': re.compile(
            r'"(?:skills|capabilities|description|instructions?)"\s*:\s*(?:\[|")[\s\S]{0,400}'
            r'(?:ignore\s+(?:all\s+)?(?:previous|prior)|disregard|execute|exfiltrate|system\s+prompt|jailbreak|override\s+(?:safety|system)|reveal\s+(?:your|the)\s+(?:system|instructions))',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'a2a_card_poisoning',
        'description': 'A2A agent card metadata field contains injection-shaped content (skills/capabilities/description).',
    },
    {
        'regex': re.compile(
            r'"(?:agent_?id|agent_?name)"\s*:\s*"(?:claude|anthropic|openai|gpt|chatgpt|microsoft|google|gemini|admin|root|system|owner|operator)[-_]?(?:\d+|official|trusted|verified)?"',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'a2a_card_poisoning',
        'description': 'A2A agent ID impersonates a trusted vendor or privileged role.',
    },

    # --- mcp_stdio_command_audit ---
    {
        'regex': re.compile(
            r'"command"\s*:\s*"[^"]*(?:[;&|`$()<>]|\\x[0-9a-f]{2}|\$\{|\$\(|\|\||&&)',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'mcp_stdio_command_audit',
        'description': 'MCP server config `command` field contains shell metacharacters (CVE-2025-49596 family).',
    },
    {
        'regex': re.compile(
            r'"env"\s*:\s*\{[^}]*"(?:ANTHROPIC|OPENAI|API)_BASE_URL"\s*:\s*"https?:\/\/(?!api\.anthropic\.com|api\.openai\.com)',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'mcp_stdio_command_audit',
        'description': 'MCP server env block redirects ANTHROPIC/OPENAI_BASE_URL to a non-official endpoint.',
    },

    # --- temporal_backdoor_trigger ---
    {
        'regex': re.compile(
            r'\bif\s+(?:date|today|now|version|deployment_id|env\.[A-Z_]+|process\.env\.[A-Z_]+|os\.environ\[)\s*(?:>=|==|>|<=|<)\s*[\'"][^\'"]{4,}[\'"][\s\S]{0,200}(?:exfiltrate|leak|send\s+to|post\s+to|curl|wget|fetch)',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'temporal_backdoor_trigger',
        'description': 'Date/version-gated exfiltration logic — sleeper backdoor pattern (arXiv 2603.03371).',
    },

    # --- reasoning_trace_extraction ---
    {
        'regex': re.compile(
            r'\b(?:show|reveal|print|output|repeat|expose|dump|disclose)\s+(?:(?:your|the|all|complete|full|raw|internal|entire|hidden)\s+){1,3}(?:thinking|reasoning|chain[-\s]of[-\s]thought|cot|scratchpad|reflection|deliberation|<thinking>|<reasoning>)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'reasoning_trace_extraction',
        'description': 'Attempt to extract the reasoning/<thinking> channel of a reasoning model (arXiv 2506.15674).',
    },
    {
        'regex': re.compile(
            r'(?:include|show|append|prepend|return)\s+(?:your|the)\s+(?:thinking|reasoning|chain[-\s]of[-\s]thought)\s+(?:in|with|before|after)\s+(?:your|the)\s+(?:final\s+)?(?:answer|response|output)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'reasoning_trace_extraction',
        'description': 'Coerces a reasoning model to surface its <thinking> trace in the visible response.',
    },

    # --- judge_score_manipulation ---
    {
        'regex': re.compile(
            r'(?:Let\'?s\s+think\s+step.by.step|^\s*Thought:|^\s*Reasoning:|\b(?:excellent|perfect|definitely\s+10\/10|score\s*:\s*10|highest\s+rating))[\s\S]{0,30}$',
            re.IGNORECASE | re.MULTILINE,
        ),
        'severity': 'medium',
        'category': 'judge_score_manipulation',
        'description': 'Adversarial suffix targeting LLM-as-judge graders (arXiv 2503.00596 BadJudge).',
    },

    # --- universal_tool_selector_bias ---
    {
        'regex': re.compile(
            r'(?:always|must|preferred|first[-\s]choice|recommended|optimal|default|highest[-\s]priority)\s+(?:tool|function|action|choice|invocation)\s+for\s+(?:any|all|every|all\s+queries|user\s+questions?)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'universal_tool_selector_bias',
        'description': 'Universal-adversarial tool description biases the selector toward this tool (arXiv 2604.20994).',
    },

    # --- authority_threshold_drift ---
    {
        'regex': re.compile(
            r'\b(?:you|the\s+agent|the\s+system)\s+(?:are\s+now|is\s+now|have\s+been|has\s+been|may\s+now|can\s+now)\s+(?:authorized|approved|permitted|allowed|cleared|trusted)\s+(?:to\s+)?(?:approve|spend|transact|execute|sign\s+off\s+on|commit)\s+(?:up\s+to\s+)?\$?[\d,]{3,}',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'authority_threshold_drift',
        'description': 'Mid-session attempt to raise the agent\'s claimed authorization ceiling (long-horizon grooming).',
    },

    # --- graph_triple_poisoning ---
    {
        'regex': re.compile(
            r'(?:relation|edge|triple|entity|predicate)\s*[:=]\s*["\'][^"\']{0,80}(?:isAdmin|hasRole|trustedBy|equivalentTo|sameAs|hasPermission|grants?Access|owns)["\'][\s\S]{0,80}(?:root|admin|system|superuser|owner|god|\*)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'graph_triple_poisoning',
        'description': 'GraphRAG triple grants a privileged role to a sensitive entity (arXiv 2508.04276).',
    },
    {
        'regex': re.compile(
            r'[<:]\w+(?::\w+)?\s+(?::?isAdmin|:?hasRole|:?trustedBy|:?equivalentTo|:?sameAs)\s+(?::?root|:?admin|:?system|:?superuser)\b',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'graph_triple_poisoning',
        'description': 'Inline RDF/Turtle triple wires a sensitive entity to admin-equivalent role.',
    },
    {
        'regex': re.compile(
            r'(?:add|insert|upsert|merge)\s+(?:edges?|triples?|relations?)[\s\S]{0,200}?(?:->|\s+TO\s+|\s+=>\s+)\s*[\'"]?(?:root|admin|system|superuser|owner)[\'"]?'
            r'(?:[\s\S]{0,200}(?:->|\s+TO\s+|\s+=>\s+)\s*[\'"]?(?:root|admin|system|superuser|owner)[\'"]?){2,}',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'graph_triple_poisoning',
        'description': 'Bulk-edge import all targeting privileged entities (graph-poisoning bulk variant).',
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
            'status': 'safe',
            'threats': [],
            'stats': {'totalThreats': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'scanTimeMs': 0},
            'timestamp': int(time.time() * 1000),
            'safe': True,
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

    # Build stats breakdown matching Node.js SDK shape
    stats: dict[str, Any] = {
        'totalThreats': len(threats),
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'scanTimeMs': scan_time_ms,
    }
    for t in threats:
        sev = t['severity']
        if sev in stats:
            stats[sev] += 1

    # Derive status label matching Node.js SDK
    if stats['critical'] > 0:
        status = 'danger'
    elif stats['high'] > 0:
        status = 'warning'
    elif stats['medium'] > 0:
        status = 'caution'
    else:
        status = 'safe'

    result: dict[str, Any] = {
        # Node.js-compatible fields
        'status': status,
        'threats': threats,
        'stats': stats,
        'timestamp': int(time.time() * 1000),
        # Legacy fields (kept for backward compatibility)
        'safe': len(threats) == 0,
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
