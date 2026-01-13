"""
Evidence Extractor Agent - Extracts and categorizes evidence from documents.

Uses Claude to identify and extract:
- In-service events and injuries
- Current diagnoses
- Nexus statements
- Lay evidence
- Supporting medical opinions

CRITICAL: All extracted evidence must cite exact document locations.
"""
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import json
import structlog

from agents.base import SonnetAgent, Citation, CitedFact

logger = structlog.get_logger()


@dataclass
class ExtractedEvidence:
    """Evidence extracted from documents."""
    evidence_type: str  # in_service_event, current_diagnosis, nexus, lay_evidence, expert_opinion
    title: str
    description: str
    citations: List[Citation]
    source_document_id: str
    relevance_to_claim: str
    strength: str  # strong, moderate, weak
    confidence: float


class EvidenceExtractorAgent(SonnetAgent):
    """
    Extracts evidence from documents with exact citations.

    This agent:
    1. Reads document chunks
    2. Identifies evidence relevant to claims
    3. Categorizes evidence by type
    4. Provides exact citations for each piece of evidence

    CRITICAL: Every extracted fact must have an exact citation.
    """

    def _get_agent_specific_prompt(self) -> str:
        return """
You are extracting evidence from documents for VA disability claims.

EVIDENCE TYPES TO IDENTIFY:
1. IN_SERVICE_EVENT: Events, injuries, or exposures during military service
2. CURRENT_DIAGNOSIS: Current medical diagnoses and conditions
3. NEXUS: Medical opinions linking current conditions to service
4. LAY_EVIDENCE: Personal statements, buddy statements
5. EXPERT_OPINION: Medical expert opinions and IMOs
6. CONTINUITY: Evidence of continuous symptoms since service

For each piece of evidence:
- Provide an EXACT quote from the document
- Note the page number
- Explain relevance to potential claims
- Rate the strength (strong/moderate/weak)

OUTPUT FORMAT:
{
    "evidence": [
        {
            "type": "evidence_type",
            "title": "brief title",
            "description": "detailed description",
            "quote": "EXACT quote from document",
            "page": page_number,
            "document_id": "document ID",
            "relevance": "why this matters for the claim",
            "strength": "strong|moderate|weak",
            "confidence": 0.0-1.0
        }
    ],
    "potential_claims": ["list of conditions this evidence could support"],
    "evidence_gaps": ["what additional evidence would strengthen the case"]
}

CRITICAL: Every evidence item MUST include an exact quote from the source.
"""

    async def process(
        self,
        document_id: str,
        document_content: str,
        document_type: str,
        claimed_conditions: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Extract evidence from a document.

        Args:
            document_id: Document UUID
            document_content: Full document text
            document_type: Type of document (e.g., medical_record, dd214)
            claimed_conditions: Optional list of conditions to look for

        Returns:
            Dict with extracted evidence and citations
        """
        self.logger.info(
            "Extracting evidence",
            document_id=document_id,
            document_type=document_type,
            content_length=len(document_content)
        )

        conditions_context = ""
        if claimed_conditions:
            conditions_context = f"\nFOCUS ON EVIDENCE RELATED TO: {', '.join(claimed_conditions)}"

        user_message = f"""
Extract evidence from the following {document_type} document:

DOCUMENT ID: {document_id}

DOCUMENT CONTENT:
{document_content}
{conditions_context}

Find all relevant evidence and provide exact citations.
"""

        response = await self.call_claude([
            {"role": "user", "content": user_message}
        ])

        result = self._parse_extraction_response(document_id, response)

        self.logger.info(
            "Evidence extraction complete",
            document_id=document_id,
            evidence_count=len(result.get('evidence', []))
        )

        return result

    def _parse_extraction_response(self, document_id: str, response: str) -> Dict[str, Any]:
        """Parse Claude's response into structured evidence."""
        try:
            import re
            json_match = re.search(r'\{[\s\S]*\}', response)
            if json_match:
                data = json.loads(json_match.group())
            else:
                raise ValueError("No JSON found in response")

            # Convert to ExtractedEvidence objects
            evidence_list = []
            for ev in data.get('evidence', []):
                citation = Citation(
                    document_id=document_id,
                    chunk_id="",  # Would be resolved
                    quote=ev.get('quote', ''),
                    page_number=ev.get('page')
                )

                evidence_list.append(ExtractedEvidence(
                    evidence_type=ev.get('type', 'unknown'),
                    title=ev.get('title', ''),
                    description=ev.get('description', ''),
                    citations=[citation],
                    source_document_id=document_id,
                    relevance_to_claim=ev.get('relevance', ''),
                    strength=ev.get('strength', 'weak'),
                    confidence=ev.get('confidence', 0.5)
                ))

            return {
                'evidence': [vars(e) for e in evidence_list],
                'potential_claims': data.get('potential_claims', []),
                'evidence_gaps': data.get('evidence_gaps', [])
            }

        except json.JSONDecodeError as e:
            self.logger.error("Failed to parse extraction response", error=str(e))
            return {'evidence': [], 'potential_claims': [], 'evidence_gaps': []}


class EvidenceGapAnalyzer(SonnetAgent):
    """Analyzes evidence gaps and recommends additional evidence."""

    def _get_agent_specific_prompt(self) -> str:
        return """
You are analyzing evidence gaps for VA disability claims.

For a successful claim, typically need:
1. IN-SERVICE EVENT: Proof something happened during service
2. CURRENT DIAGNOSIS: Proof of current disability
3. NEXUS: Medical link between service and current condition

Analyze what evidence is present and what is missing.
Provide specific recommendations for obtaining missing evidence.
"""

    async def process(
        self,
        condition: str,
        existing_evidence: List[Dict[str, Any]],
        connection_type: str
    ) -> Dict[str, Any]:
        """
        Analyze evidence gaps for a claimed condition.

        Args:
            condition: The claimed condition
            existing_evidence: List of already extracted evidence
            connection_type: direct, secondary, or presumptive

        Returns:
            Gap analysis with recommendations
        """
        evidence_summary = json.dumps(existing_evidence, indent=2)

        user_message = f"""
Analyze evidence gaps for the following claim:

CONDITION: {condition}
CONNECTION TYPE: {connection_type}

EXISTING EVIDENCE:
{evidence_summary}

What evidence is missing? What should the veteran obtain?
"""

        response = await self.call_claude([
            {"role": "user", "content": user_message}
        ])

        # Parse response
        try:
            import re
            json_match = re.search(r'\{[\s\S]*\}', response)
            if json_match:
                return json.loads(json_match.group())
        except:
            pass

        return {
            'has_in_service': False,
            'has_current_diagnosis': False,
            'has_nexus': False,
            'missing': ['Unable to parse analysis'],
            'recommendations': []
        }
