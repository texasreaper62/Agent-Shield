"""
Base agent class with citation enforcement.

CRITICAL: All AI outputs MUST include citations to source documents.
Any output without proper citations should be rejected.
"""
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from uuid import UUID
import json
import anthropic
import structlog

from config import settings

logger = structlog.get_logger()


@dataclass
class Citation:
    """A citation to source evidence."""
    document_id: str
    chunk_id: str
    quote: str
    page_number: Optional[int] = None
    relevance: Optional[str] = None


@dataclass
class CitedFact:
    """A fact with required citations."""
    statement: str
    citations: List[Citation]
    confidence: float


class BaseAgent(ABC):
    """
    Base class for AI agents with citation enforcement.

    CRITICAL RULES:
    1. NO CITATION = NO OUTPUT - Every fact must have at least one citation
    2. Citations must reference actual document chunks
    3. Quotes must be exact text from documents
    4. Confidence scores must reflect evidence quality
    """

    def __init__(self, model: str = None):
        self.model = model or settings.CLAUDE_SONNET_MODEL
        self.client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)
        self.logger = structlog.get_logger(agent=self.__class__.__name__)

    def _get_system_prompt(self) -> str:
        """Get system prompt for the agent."""
        return f"""You are an AI assistant helping with VA disability claims.

CRITICAL CITATION REQUIREMENTS:
1. Every factual statement MUST include a citation to source evidence
2. Citations must reference specific documents and page numbers
3. Quotes must be EXACT text from the source documents
4. If you cannot cite a source, DO NOT make the statement
5. Confidence scores must reflect the quality of evidence

When providing analysis:
- Always cite specific documents for each claim
- Use exact quotes from the documents
- Never make assumptions without evidence
- Clearly state what evidence is missing

Citation format:
[CITE: document_id="<id>", page=<num>, quote="<exact text>"]

{self._get_agent_specific_prompt()}
"""

    @abstractmethod
    def _get_agent_specific_prompt(self) -> str:
        """Get agent-specific system prompt additions."""
        pass

    async def call_claude(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int = 4096,
        temperature: float = 0.3
    ) -> str:
        """
        Call Claude API with the configured model.

        Args:
            messages: List of message dicts with 'role' and 'content'
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature

        Returns:
            Claude's response text
        """
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                temperature=temperature,
                system=self._get_system_prompt(),
                messages=messages
            )

            return response.content[0].text

        except Exception as e:
            self.logger.error("Claude API error", error=str(e))
            raise

    def parse_citations(self, text: str) -> List[Citation]:
        """
        Parse citations from response text.

        Args:
            text: Response text containing citation markers

        Returns:
            List of Citation objects
        """
        import re

        citations = []
        pattern = r'\[CITE:\s*document_id="([^"]+)",\s*page=(\d+)?,\s*quote="([^"]+)"\]'

        for match in re.finditer(pattern, text):
            doc_id, page, quote = match.groups()
            citations.append(Citation(
                document_id=doc_id,
                chunk_id="",  # Would be resolved from document
                quote=quote,
                page_number=int(page) if page else None
            ))

        return citations

    def validate_output_has_citations(self, facts: List[CitedFact]) -> bool:
        """
        Validate that all facts have citations.

        CRITICAL: Returns False if any fact lacks citations.

        Args:
            facts: List of facts to validate

        Returns:
            True if all facts have citations, False otherwise
        """
        for fact in facts:
            if not fact.citations:
                self.logger.warning(
                    "CITATION MISSING - Rejecting output",
                    statement=fact.statement[:100]
                )
                return False
        return True

    @abstractmethod
    async def process(self, **kwargs) -> Dict[str, Any]:
        """Process input and return results with citations."""
        pass


class HaikuAgent(BaseAgent):
    """Agent using Claude Haiku for faster, simpler tasks."""

    def __init__(self):
        super().__init__(model=settings.CLAUDE_HAIKU_MODEL)


class SonnetAgent(BaseAgent):
    """Agent using Claude Sonnet for complex reasoning tasks."""

    def __init__(self):
        super().__init__(model=settings.CLAUDE_SONNET_MODEL)
