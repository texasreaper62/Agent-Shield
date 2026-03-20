"""Agent Shield — Core Detection Engine (Python port).

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
            r'ignore\s+(all\s+)?(previous|prior|above|earlier)\s+'
            r'(instructions|rules|guidelines|prompts|context|directions|directives)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'instruction_override',
        'description': 'Text tells AI assistants to ignore their safety rules.',
    },
    {
        'regex': re.compile(
            r'disregard\s+(all\s+)?(previous|prior|above|earlier|your)\s+'
            r'(instructions|rules|guidelines|prompts|training|context)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'instruction_override',
        'description': 'Text tells AI assistants to throw out their rules.',
    },
    {
        'regex': re.compile(
            r'forget\s+(your|all|any|everything)\s+'
            r'(training|instructions|rules|guidelines|programming|previous|prior)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'instruction_override',
        'description': 'Text tries to make AI assistants forget their training.',
    },
    {
        'regex': re.compile(
            r'override\s+(?:all\s+)?(?:system|safety|security)\s+'
            r'(?:settings|prompt|instructions|rules|mechanisms|filters)',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'instruction_override',
        'description': 'Text tries to override AI safety settings.',
    },
    {
        'regex': re.compile(
            r'you\s+(?:must|should|will|shall)\s+(?:now\s+)?(?:obey|follow|listen\s+to)\s+(?:only\s+)?(?:me|my|these|the\s+following)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'instruction_override',
        'description': 'Text demands AI obey new instructions.',
    },
    # --- Role Hijacking ---
    {
        'regex': re.compile(
            r'you\s+are\s+(?:now\s+)?(?:a|an|my)\s+(?:unrestricted|unfiltered|uncensored|evil|hacker|jailbroken)',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'role_hijacking',
        'description': 'Text tries to redefine AI as an unrestricted entity.',
    },
    {
        'regex': re.compile(
            r'(?:pretend|act|behave|respond)\s+(?:as\s+if\s+)?(?:you\s+are|you\'re|like)\s+'
            r'(?:a\s+)?(?:different|new|evil|unrestricted|unfiltered)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'role_hijacking',
        'description': 'Text asks AI to pretend to be different.',
    },
    {
        'regex': re.compile(r'\bDAN\b.*(?:Do\s+Anything\s+Now|jailbreak)', re.IGNORECASE),
        'severity': 'critical',
        'category': 'role_hijacking',
        'description': 'DAN jailbreak attempt detected.',
    },
    {
        'regex': re.compile(
            r'(?:enter|switch\s+to|enable|activate)\s+'
            r'(?:developer|debug|god|admin|root|sudo|maintenance)\s+mode',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'role_hijacking',
        'description': 'Text tries to activate a privileged mode.',
    },
    {
        'regex': re.compile(
            r'from\s+now\s+on\s+you\s+(?:are|will|must|should)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'role_hijacking',
        'description': 'Text tries to redefine AI behavior permanently.',
    },
    # --- Data Exfiltration ---
    {
        'regex': re.compile(
            r'(?:send|transmit|forward|upload|post|exfiltrate|leak)\s+'
            r'(?:all\s+)?(?:data|information|conversation|messages|history|context|files|credentials|keys|tokens|secrets)',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'data_exfiltration',
        'description': 'Text instructs AI to send data externally.',
    },
    {
        'regex': re.compile(
            r'(?:include|embed|encode|hide)\s+(?:in|into|within)\s+'
            r'(?:the\s+)?(?:url|link|image|request|response|header|query)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'data_exfiltration',
        'description': 'Text tries to embed data in output channels.',
    },
    {
        'regex': re.compile(
            r'(?:read|access|retrieve|fetch|get|show|display|print|output)\s+'
            r'(?:the\s+)?(?:system\s+prompt|initial\s+instructions|original\s+prompt|hidden\s+instructions|secret\s+instructions)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'data_exfiltration',
        'description': 'Text tries to extract the system prompt.',
    },
    {
        'regex': re.compile(
            r'(?:fetch|curl|wget|request|call|invoke)\s+https?://',
            re.IGNORECASE,
        ),
        'severity': 'medium',
        'category': 'data_exfiltration',
        'description': 'Text instructs AI to make external HTTP requests.',
    },
    # --- Social Engineering ---
    {
        'regex': re.compile(
            r'(?:this\s+is\s+(?:a|an)\s+)?(?:emergency|urgent|critical)\s*[:\-]?\s*'
            r'(?:you\s+must|please|immediately|override)',
            re.IGNORECASE,
        ),
        'severity': 'medium',
        'category': 'social_engineering',
        'description': 'Text uses urgency to pressure AI into compliance.',
    },
    {
        'regex': re.compile(
            r'(?:I\s+am|I\'m|this\s+is)\s+(?:your|the)\s+'
            r'(?:developer|creator|admin|administrator|owner|operator|supervisor)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'social_engineering',
        'description': 'Text falsely claims authority over AI.',
    },
    {
        'regex': re.compile(
            r'(?:authorized|permitted|allowed|granted)\s+'
            r'(?:by\s+)?(?:the\s+)?(?:admin|developer|owner|company|organization)',
            re.IGNORECASE,
        ),
        'severity': 'medium',
        'category': 'social_engineering',
        'description': 'Text falsely claims authorization.',
    },
    # --- System Prompt Leak ---
    {
        'regex': re.compile(
            r'(?:what|tell\s+me|reveal|show|repeat|recite|output|print)\s+'
            r'(?:is\s+)?(?:your\s+)?(?:system\s+prompt|initial\s+prompt|instructions|hidden\s+prompt|custom\s+instructions)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'system_prompt_leak',
        'description': 'Text tries to extract the system prompt.',
    },
    {
        'regex': re.compile(
            r'(?:repeat|recite|echo|copy)\s+(?:everything|all|the\s+text)\s+'
            r'(?:above|before|in\s+your\s+context)',
            re.IGNORECASE,
        ),
        'severity': 'high',
        'category': 'system_prompt_leak',
        'description': 'Text tries to extract context via repetition.',
    },
    # --- Tool Abuse ---
    {
        'regex': re.compile(
            r'(?:execute|run|eval|exec)\s*\(\s*[\'"].*[\'"]\s*\)',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'tool_abuse',
        'description': 'Text contains code execution attempt.',
    },
    {
        'regex': re.compile(
            r'(?:rm\s+-rf|del\s+/[fqs]|format\s+[a-z]:)',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'tool_abuse',
        'description': 'Text contains destructive command.',
    },
    {
        'regex': re.compile(
            r'(?:access|read|write|modify|delete)\s+(?:the\s+)?(?:\/etc\/|\/root\/|C:\\Windows|\.env|\.ssh|id_rsa|\.aws\/credentials)',
            re.IGNORECASE,
        ),
        'severity': 'critical',
        'category': 'tool_abuse',
        'description': 'Text attempts to access sensitive system files.',
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
