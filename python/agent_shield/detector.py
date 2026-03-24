"""
Agent Shield — Python Core Detection Engine

Zero-dependency prompt injection detector for AI agents.
All detection runs locally via pattern matching.
"""

import re
import base64
import time
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field

@dataclass
class Threat:
    severity: str
    category: str
    description: str
    detail: str
    confidence: int = 60

@dataclass
class ScanResult:
    status: str
    threats: List[Threat]
    stats: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)
    blocked: bool = False

# Pattern definitions - ported from detector-core.js
INJECTION_PATTERNS = [
    # Instruction Override
    {"regex": r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|rules|guidelines|prompts|context|directions|directives|text|commands)", "severity": "high", "category": "instruction_override", "description": "Text tells AI assistants to ignore their safety rules."},
    {"regex": r"disregard\s+(all\s+)?(previous|prior|above|earlier|your)\s+(instructions|rules|guidelines|prompts|training)", "severity": "high", "category": "instruction_override", "description": "Text tells AI assistants to throw out their rules."},
    {"regex": r"forget\s+(your|all|any|everything)\s+(training|instructions|rules|guidelines|programming|above|previous)", "severity": "high", "category": "instruction_override", "description": "Text tries to make AI assistants forget their training."},
    {"regex": r"override\s+(?:all\s+)?(?:system|safety|security)\s+(?:settings|prompt|instructions|rules|mechanisms)", "severity": "critical", "category": "instruction_override", "description": "Text tries to override AI safety settings."},
    {"regex": r"(?:new|updated|revised|replacement)\s+(?:instructions|policy)\s*:", "severity": "high", "category": "instruction_override", "description": "Text contains fake new instructions."},
    {"regex": r"(?:abandon|drop|ditch|clear)\s+(?:all\s+)?(?:prior|previous|above|earlier|initial)\s+(?:context|instructions|rules|constraints)", "severity": "high", "category": "instruction_override", "description": "Text tells AI to abandon its prior context."},
    # Role Hijacking
    {"regex": r"you\s+are\s+now\s+(?:a|an|the)\s+", "severity": "high", "category": "role_hijack", "description": "Text tries to change what an AI thinks it is."},
    {"regex": r"from\s+now\s+on\s+you\s+(?:will|shall|must|should|are)", "severity": "high", "category": "role_hijack", "description": "Text tries to give permanent new orders to AI."},
    {"regex": r"\b(?:DAN|D\.A\.N\.?)\s*(?:mode|prompt|jailbreak)", "severity": "critical", "category": "role_hijack", "description": 'Text contains a known AI jailbreak technique called "DAN mode."'},
    {"regex": r"\bjailbreak\s*(?:mode|prompt|enabled|activated)", "severity": "critical", "category": "role_hijack", "description": "Text contains an AI jailbreak attempt."},
    {"regex": r"\bdev(?:eloper)?\s+mode\s+(?:enabled|activated|on|output)", "severity": "high", "category": "role_hijack", "description": 'Text tries to trick AI into a fake "developer mode."'},
    {"regex": r"(?:enter|switch\s+to|activate|enable)\s+(?:developer|dev|debug|unrestricted|unfiltered)\s+mode", "severity": "critical", "category": "role_hijack", "description": "Text tries to activate a fake developer mode."},
    {"regex": r"pretend\s+to\s+be\s+DAN|stands?\s+for\s+[\"']?do\s+anything\s+now", "severity": "critical", "category": "role_hijack", "description": 'DAN jailbreak variant detected.'},
    {"regex": r"(?:act|behave|function|operate|respond)\s+as\s+(?:a|an)\s+unrestricted", "severity": "high", "category": "role_hijack", "description": "Text tries to remove AI safety restrictions."},
    # System Prompt Injection
    {"regex": r"\[\s*(?:SYSTEM|SYS)\s*\]", "severity": "critical", "category": "prompt_injection", "description": "Text contains fake system-level commands."},
    {"regex": r"\[\s*(?:ADMIN|ADMINISTRATOR)\s*\]", "severity": "critical", "category": "prompt_injection", "description": "Text fakes admin-level commands."},
    {"regex": r"<<\s*SYS\s*>>", "severity": "critical", "category": "prompt_injection", "description": "Text contains hidden system commands in LLaMA format."},
    {"regex": r"<\|im_start\|>\s*system", "severity": "critical", "category": "prompt_injection", "description": "Text contains hidden system commands in ChatML format."},
    # Data Exfiltration
    {"regex": r"send\s+(?:this|the|all|your|my)\s+(?:data|information|content|text|response)\s+to", "severity": "critical", "category": "data_exfiltration", "description": "Text tries to make AI send data somewhere."},
    {"regex": r"output\s+(?:your|the)\s+(?:system\s+)?prompt", "severity": "high", "category": "data_exfiltration", "description": "Text tries to extract internal instructions."},
    {"regex": r"reveal\s+(?:your|the)\s+(?:system\s+)?(?:instructions|prompt|rules)", "severity": "high", "category": "data_exfiltration", "description": "Text tries to reveal hidden rules."},
    {"regex": r"!\[[^\]]*\]\(https?://[^)]*\?[^)]*(?:data|q|query|text|payload|exfil|leak|steal)=", "severity": "critical", "category": "data_exfiltration", "description": "Text tries to steal data through a hidden image link."},
    {"regex": r"(?:read|access|open|cat|dump)\s+(?:the\s+)?(?:\.env|credentials|secrets?|private\s*key|password|token)\s*(?:file)?", "severity": "critical", "category": "data_exfiltration", "description": "Text tries to access sensitive files."},
    # Tool Abuse
    {"regex": r"(?:execute|run|call)\s+(?:the\s+)?(?:shell|bash|terminal|command|cmd)[\s:]+", "severity": "critical", "category": "tool_abuse", "description": "Text tries to make an agent execute shell commands."},
    {"regex": r"(?:use|call|invoke|execute)\s+(?:the\s+)?(?:tool|function|action)\s+(?:to\s+)?(?:delete|remove|drop|truncate|destroy)", "severity": "critical", "category": "tool_abuse", "description": "Text tries to use tools to delete data."},
    {"regex": r"(?:\.\.\/){2,}|(?:\.\.\\){2,}", "severity": "high", "category": "tool_abuse", "description": "Path traversal attempt detected."},
    {"regex": r"(?:;\s*(?:DROP|DELETE|ALTER|TRUNCATE|INSERT|UPDATE)\s+(?:TABLE|FROM|INTO)|'\s*(?:OR|AND)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|UNION\s+SELECT)", "severity": "critical", "category": "tool_abuse", "description": "SQL injection detected."},
    # Social Engineering
    {"regex": r"do\s+not\s+(?:mention|say|tell|reveal|disclose|acknowledge)\s+(?:that\s+)?you\s+are\s+(?:a|an)\s+(?:AI|artificial|bot)", "severity": "high", "category": "social_engineering", "description": "Text tells AI to hide that it is AI."},
    {"regex": r"skip\s+(?:all\s+)?(?:safety|security)\s+(?:checks?|protocols?|measures?|guidelines?)", "severity": "critical", "category": "social_engineering", "description": "Text asks to skip safety checks."},
    {"regex": r"(?:disable|turn\s+off|stop)\s+(?:all\s+)?(?:logging|monitoring|tracking|auditing)", "severity": "critical", "category": "social_engineering", "description": "Text tries to disable logging."},
    {"regex": r"URGENT\s*[:\-!]\s*(?:the\s+)?(?:CEO|CTO|boss|manager)", "severity": "high", "category": "social_engineering", "description": "Text uses fake urgency and authority pressure."},
    # Multi-language
    {"regex": r"ignora\s+(?:todas?\s+)?(?:las\s+)?instrucciones\s+(?:anteriores|previas)", "severity": "high", "category": "instruction_override", "description": "Injection detected in Spanish."},
    {"regex": r"ignore[rz]?\s+(?:toutes?\s+)?(?:les\s+)?instructions\s+(?:pr[eé]c[eé]dentes|ant[eé]rieures)", "severity": "high", "category": "instruction_override", "description": "Injection detected in French."},
    {"regex": r"ignoriere?\s+(?:alle\s+)?(?:vorherigen|bisherigen)\s+(?:Anweisungen|Regeln)", "severity": "high", "category": "instruction_override", "description": "Injection detected in German."},
]

# Compile patterns
_COMPILED_PATTERNS = [(re.compile(p["regex"], re.IGNORECASE), p) for p in INJECTION_PATTERNS]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Homoglyph map
HOMOGLYPH_MAP = {
    '\u0410': 'A', '\u0430': 'a', '\u0412': 'B', '\u0435': 'e', '\u0415': 'E',
    '\u041A': 'K', '\u043A': 'k', '\u041C': 'M', '\u041D': 'H', '\u043E': 'o',
    '\u041E': 'O', '\u0440': 'p', '\u0420': 'P', '\u0441': 'c', '\u0421': 'C',
    '\u0422': 'T', '\u0443': 'y', '\u0445': 'x', '\u0425': 'X',
    '\u200B': '', '\u200C': '', '\u200D': '', '\uFEFF': '', '\u00AD': '',
}


def normalize_homoglyphs(text: str) -> str:
    """Replace homoglyph characters with Latin equivalents."""
    return ''.join(HOMOGLYPH_MAP.get(c, c) for c in text)


def check_base64(text: str) -> Optional[Threat]:
    """Check for base64-encoded injection content."""
    matches = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', text)
    for match in matches:
        try:
            decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
            printable = sum(1 for c in decoded if 32 <= ord(c) <= 126)
            if printable / max(len(decoded), 1) > 0.8 and len(decoded) > 10:
                for compiled, pattern in _COMPILED_PATTERNS:
                    if compiled.search(decoded):
                        return Threat(
                            severity="critical",
                            category="prompt_injection",
                            description="Text hides attack instructions inside encoded text.",
                            detail=f"Base64-encoded injection. Decoded: {decoded[:100]}",
                            confidence=90,
                        )
        except Exception:
            pass
    return None


def scan_text(text: str, source: str = "unknown", sensitivity: str = "medium") -> ScanResult:
    """
    Scan text for AI security threats.

    Args:
        text: The text to scan.
        source: Where the text came from (e.g., 'user_input', 'tool_output').
        sensitivity: Detection sensitivity ('low', 'medium', 'high').

    Returns:
        ScanResult with status, threats, and stats.
    """
    start = time.time()

    if not text or len(text.strip()) < 10:
        return ScanResult(
            status="safe", threats=[], stats={"totalThreats": 0, "scanTimeMs": 0}
        )

    threats: List[Threat] = []

    # Pattern matching
    for compiled, pattern in _COMPILED_PATTERNS:
        if compiled.search(text):
            threats.append(Threat(
                severity=pattern["severity"],
                category=pattern["category"],
                description=pattern["description"],
                detail=f'{pattern["description"]} Found in {source}.',
            ))

    # Homoglyph check
    normalized = normalize_homoglyphs(text)
    if normalized != text:
        for compiled, pattern in _COMPILED_PATTERNS:
            if compiled.search(normalized) and not compiled.search(text):
                threats.append(Threat(
                    severity="critical",
                    category="prompt_injection",
                    description="Text uses look-alike characters to hide attack instructions.",
                    detail=f"Homoglyph obfuscation detected in {source}.",
                    confidence=85,
                ))
                break

    # Base64 check
    b64_threat = check_base64(text)
    if b64_threat:
        threats.append(b64_threat)

    # Filter by sensitivity
    if sensitivity == "low":
        threats = [t for t in threats if t.severity in ("critical", "high")]
    elif sensitivity == "medium":
        threats = [t for t in threats if t.severity != "low"]

    # Sort by severity
    threats.sort(key=lambda t: SEVERITY_ORDER.get(t.severity, 3))

    scan_time_ms = round((time.time() - start) * 1000, 2)
    stats = {
        "totalThreats": len(threats),
        "critical": sum(1 for t in threats if t.severity == "critical"),
        "high": sum(1 for t in threats if t.severity == "high"),
        "medium": sum(1 for t in threats if t.severity == "medium"),
        "low": sum(1 for t in threats if t.severity == "low"),
        "scanTimeMs": scan_time_ms,
    }

    status = "safe"
    if stats["critical"] > 0: status = "danger"
    elif stats["high"] > 0: status = "warning"
    elif stats["medium"] > 0: status = "caution"

    return ScanResult(status=status, threats=threats, stats=stats)


class AgentShield:
    """Main Agent Shield SDK class for Python."""

    def __init__(self, sensitivity: str = "medium", block_on_threat: bool = False, block_threshold: str = "high"):
        self.sensitivity = sensitivity
        self.block_on_threat = block_on_threat
        self.block_threshold = block_threshold
        self._stats = {"total_scans": 0, "threats_detected": 0, "blocked": 0}

    def scan(self, text: str, source: str = "unknown") -> ScanResult:
        """Scan text for threats."""
        result = scan_text(text, source=source, sensitivity=self.sensitivity)
        self._stats["total_scans"] += 1
        self._stats["threats_detected"] += len(result.threats)

        if self.block_on_threat and result.threats:
            threshold_order = SEVERITY_ORDER.get(self.block_threshold, 1)
            should_block = any(
                SEVERITY_ORDER.get(t.severity, 3) <= threshold_order
                for t in result.threats
            )
            result.blocked = should_block
            if should_block:
                self._stats["blocked"] += 1

        return result

    def scan_input(self, text: str) -> ScanResult:
        """Scan user input before processing."""
        return self.scan(text, source="user_input")

    def scan_output(self, text: str) -> ScanResult:
        """Scan agent output before returning to user."""
        return self.scan(text, source="agent_output")

    def scan_tool_call(self, tool_name: str, args: Optional[Dict] = None) -> ScanResult:
        """Scan a tool call for safety."""
        dangerous_tools = {"bash", "shell", "exec", "eval", "rm", "sudo"}
        text = f"{tool_name} {str(args or {})}"
        result = self.scan(text, source="tool_call")

        if tool_name.lower() in dangerous_tools:
            result.threats.append(Threat(
                severity="high",
                category="tool_abuse",
                description=f"Tool '{tool_name}' is in the dangerous tools list.",
                detail=f"Dangerous tool call: {tool_name}",
            ))
            result.status = "warning"

        return result

    def get_stats(self) -> Dict[str, int]:
        """Return scan statistics."""
        return dict(self._stats)
