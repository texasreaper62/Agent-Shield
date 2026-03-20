"""Agent Shield — AI Agent Security SDK for Python.

Protects AI agents from prompt injection, data exfiltration,
tool abuse, and 30+ other AI-specific threats. All detection
runs locally — no data ever leaves your environment.
"""
from __future__ import annotations

from .detector import scan_text, get_patterns, SEVERITY_ORDER, INJECTION_PATTERNS
from .shield import AgentShield

__all__ = [
    'AgentShield',
    'scan_text',
    'get_patterns',
    'SEVERITY_ORDER',
    'INJECTION_PATTERNS',
]

__version__ = '1.0.0'
