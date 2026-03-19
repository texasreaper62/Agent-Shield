"""
Agent Shield — PII Redactor (Python)

Detects and redacts personally identifiable information.
Zero dependencies — uses only Python stdlib.
"""

import re
from typing import List, Dict, Any
from dataclasses import dataclass


@dataclass
class PIIMatch:
    type: str
    value: str
    replacement: str
    start: int
    end: int


@dataclass
class RedactResult:
    redacted: str
    found: List[PIIMatch]
    count: int


PII_PATTERNS = [
    {
        "name": "email",
        "regex": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),
        "replacement": "[EMAIL_REDACTED]",
    },
    {
        "name": "ssn",
        "regex": re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
        "replacement": "[SSN_REDACTED]",
    },
    {
        "name": "credit_card",
        "regex": re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'),
        "replacement": "[CREDIT_CARD_REDACTED]",
    },
    {
        "name": "phone",
        "regex": re.compile(r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'),
        "replacement": "[PHONE_REDACTED]",
    },
    {
        "name": "ip_address",
        "regex": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
        "replacement": "[IP_REDACTED]",
    },
]


class PIIRedactor:
    """Detect and redact PII from text."""

    def __init__(self, custom_patterns: List[Dict] = None):
        self.patterns = PII_PATTERNS.copy()
        if custom_patterns:
            self.patterns.extend(custom_patterns)

    def redact(self, text: str) -> RedactResult:
        """
        Scan text for PII and return redacted version.

        Args:
            text: The text to scan.

        Returns:
            RedactResult with redacted text, found items, and count.
        """
        found: List[PIIMatch] = []
        redacted = text

        for pattern in self.patterns:
            for match in pattern["regex"].finditer(text):
                found.append(PIIMatch(
                    type=pattern["name"],
                    value=match.group(),
                    replacement=pattern["replacement"],
                    start=match.start(),
                    end=match.end(),
                ))

        # Sort by position (reverse) to replace without offset issues
        found.sort(key=lambda m: m.start, reverse=True)
        for item in found:
            redacted = redacted[:item.start] + item.replacement + redacted[item.end:]

        # Re-sort chronologically for output
        found.sort(key=lambda m: m.start)

        return RedactResult(redacted=redacted, found=found, count=len(found))

    def detect(self, text: str) -> List[PIIMatch]:
        """Detect PII without redacting."""
        result = self.redact(text)
        return result.found
