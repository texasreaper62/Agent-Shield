"""
Claim Analyzer Agent - Analyzes claims and identifies service connections.

Uses Claude Sonnet for complex reasoning about:
- Identifying all potential disability claims
- Analyzing service connection theories (direct, secondary, presumptive)
- Estimating rating levels based on 38 CFR Part 4
- Identifying missing evidence

CRITICAL: All outputs must include citations to source documents.
"""
from typing import Dict, Any, List, Optional
from uuid import UUID
from dataclasses import dataclass
import json
import structlog

from agents.base import SonnetAgent, Citation, CitedFact

logger = structlog.get_logger()


@dataclass
class ServiceConnectionAnalysis:
    """Analysis of a service connection theory."""
    connection_type: str  # direct, secondary, presumptive
    theory: str
    supporting_evidence: List[CitedFact]
    gaps: List[str]
    viability_score: float  # 0-1


@dataclass
class ConditionAnalysis:
    """Analysis of a claimed condition."""
    condition_name: str
    diagnostic_code: Optional[str]
    service_connections: List[ServiceConnectionAnalysis]
    estimated_rating: Optional[int]
    rating_rationale: CitedFact
    recommended_evidence: List[str]
    overall_strength: float


@dataclass
class ClaimAnalysisResult:
    """Complete claim analysis result."""
    claim_id: str
    conditions: List[ConditionAnalysis]
    overall_strength: float
    summary: CitedFact
    recommended_actions: List[str]
    missing_evidence: List[str]


class ClaimAnalyzerAgent(SonnetAgent):
    """
    Analyzes VA disability claims using Claude Sonnet.

    This agent:
    1. Reviews all uploaded evidence documents
    2. Identifies potential disability claims
    3. Analyzes service connection theories
    4. Estimates likely ratings based on 38 CFR
    5. Identifies gaps in evidence

    CRITICAL: Every statement must cite source documents.
    """

    def _get_agent_specific_prompt(self) -> str:
        return """
You are analyzing VA disability claims. Your task is to:

1. IDENTIFY CLAIMS: Find all conditions that could be claimed based on the evidence
2. ANALYZE SERVICE CONNECTIONS: For each condition, evaluate:
   - DIRECT: Condition occurred during or was caused by service
   - SECONDARY: Condition caused by another service-connected condition
   - PRESUMPTIVE: Condition presumed due to service era/location (Agent Orange, Gulf War, etc.)

3. ESTIMATE RATINGS: Based on 38 CFR Part 4, estimate the likely rating percentage
   - Reference specific diagnostic codes
   - Cite medical evidence supporting the rating level

4. IDENTIFY GAPS: List what evidence is missing to strengthen the claim

IMPORTANT LEGAL NOTES:
- 38 CFR §14.636: Fees cannot be charged on initial claims (original claims, not increases)
- Presumptive conditions have specific qualifying criteria (locations, dates, etc.)
- Secondary claims require medical nexus evidence

OUTPUT FORMAT:
Return a JSON object with:
{
    "conditions": [
        {
            "name": "condition name",
            "diagnostic_code": "DC number or null",
            "service_connections": [
                {
                    "type": "direct|secondary|presumptive",
                    "theory": "explanation with citations",
                    "evidence": ["list of cited evidence"],
                    "gaps": ["missing evidence"],
                    "viability": 0.0-1.0
                }
            ],
            "estimated_rating": 0-100 or null,
            "rating_rationale": "explanation with citations",
            "recommended_evidence": ["list"]
        }
    ],
    "summary": "overall assessment with citations",
    "recommended_actions": ["list"],
    "missing_evidence": ["list"],
    "overall_strength": 0.0-1.0
}

Remember: EVERY factual statement MUST include [CITE: ...] markers.
"""

    async def process(
        self,
        claim_id: str,
        veteran_id: str,
        conditions: List[str],
        documents: List[Dict[str, Any]],
        knowledge_context: Optional[str] = None
    ) -> ClaimAnalysisResult:
        """
        Analyze a claim with all available evidence.

        Args:
            claim_id: Claim UUID
            veteran_id: Veteran UUID
            conditions: List of claimed conditions
            documents: List of document data with chunks
            knowledge_context: Relevant CFR sections

        Returns:
            ClaimAnalysisResult with cited analysis
        """
        self.logger.info(
            "Starting claim analysis",
            claim_id=claim_id,
            conditions=conditions,
            document_count=len(documents)
        )

        # Build context from documents
        document_context = self._build_document_context(documents)

        # Build the analysis prompt
        user_message = f"""
Analyze the following VA disability claim:

CLAIMED CONDITIONS:
{json.dumps(conditions, indent=2)}

AVAILABLE EVIDENCE:
{document_context}

{"RELEVANT CFR SECTIONS:" + knowledge_context if knowledge_context else ""}

Provide a comprehensive analysis following the output format.
REMEMBER: Every factual claim MUST include citations to the evidence above.
"""

        # Call Claude
        response = await self.call_claude([
            {"role": "user", "content": user_message}
        ])

        # Parse response
        result = self._parse_analysis_response(claim_id, response)

        # Validate citations
        self._validate_analysis_citations(result)

        self.logger.info(
            "Claim analysis complete",
            claim_id=claim_id,
            conditions_analyzed=len(result.conditions),
            overall_strength=result.overall_strength
        )

        return result

    def _build_document_context(self, documents: List[Dict[str, Any]]) -> str:
        """Build document context string for the prompt."""
        context_parts = []

        for doc in documents:
            doc_header = f"\n--- DOCUMENT: {doc['filename']} (ID: {doc['id']}) ---"
            doc_header += f"\nType: {doc.get('document_type', 'unknown')}"
            doc_header += f"\nDate: {doc.get('document_date', 'unknown')}"

            chunks = doc.get('chunks', [])
            chunk_text = ""
            for chunk in chunks:
                chunk_text += f"\n[Page {chunk.get('page', '?')}]: {chunk.get('content', '')}\n"

            context_parts.append(doc_header + chunk_text)

        return "\n".join(context_parts)

    def _parse_analysis_response(self, claim_id: str, response: str) -> ClaimAnalysisResult:
        """Parse Claude's response into structured result."""
        # Extract JSON from response
        try:
            # Find JSON block in response
            import re
            json_match = re.search(r'\{[\s\S]*\}', response)
            if json_match:
                data = json.loads(json_match.group())
            else:
                raise ValueError("No JSON found in response")

        except json.JSONDecodeError as e:
            self.logger.error("Failed to parse analysis response", error=str(e))
            raise ValueError(f"Invalid analysis response: {e}")

        # Parse citations from text fields
        conditions = []
        for cond_data in data.get('conditions', []):
            service_connections = []
            for sc_data in cond_data.get('service_connections', []):
                evidence_facts = []
                for ev in sc_data.get('evidence', []):
                    citations = self.parse_citations(ev)
                    evidence_facts.append(CitedFact(
                        statement=ev,
                        citations=citations,
                        confidence=sc_data.get('viability', 0.5)
                    ))

                service_connections.append(ServiceConnectionAnalysis(
                    connection_type=sc_data.get('type', 'direct'),
                    theory=sc_data.get('theory', ''),
                    supporting_evidence=evidence_facts,
                    gaps=sc_data.get('gaps', []),
                    viability_score=sc_data.get('viability', 0.0)
                ))

            rating_citations = self.parse_citations(cond_data.get('rating_rationale', ''))
            conditions.append(ConditionAnalysis(
                condition_name=cond_data.get('name', ''),
                diagnostic_code=cond_data.get('diagnostic_code'),
                service_connections=service_connections,
                estimated_rating=cond_data.get('estimated_rating'),
                rating_rationale=CitedFact(
                    statement=cond_data.get('rating_rationale', ''),
                    citations=rating_citations,
                    confidence=0.8
                ),
                recommended_evidence=cond_data.get('recommended_evidence', []),
                overall_strength=max([sc.viability_score for sc in service_connections], default=0.0)
            ))

        summary_citations = self.parse_citations(data.get('summary', ''))

        return ClaimAnalysisResult(
            claim_id=claim_id,
            conditions=conditions,
            overall_strength=data.get('overall_strength', 0.0),
            summary=CitedFact(
                statement=data.get('summary', ''),
                citations=summary_citations,
                confidence=data.get('overall_strength', 0.5)
            ),
            recommended_actions=data.get('recommended_actions', []),
            missing_evidence=data.get('missing_evidence', [])
        )

    def _validate_analysis_citations(self, result: ClaimAnalysisResult) -> None:
        """
        Validate that analysis has proper citations.

        Logs warnings for any uncited statements but doesn't fail.
        """
        for condition in result.conditions:
            for sc in condition.service_connections:
                for evidence in sc.supporting_evidence:
                    if not evidence.citations:
                        self.logger.warning(
                            "Evidence statement lacks citation",
                            condition=condition.condition_name,
                            statement=evidence.statement[:100]
                        )

            if not condition.rating_rationale.citations:
                self.logger.warning(
                    "Rating rationale lacks citation",
                    condition=condition.condition_name
                )

        if not result.summary.citations:
            self.logger.warning("Summary lacks citations")
