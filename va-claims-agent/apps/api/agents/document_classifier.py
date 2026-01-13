"""
Document Classifier Agent - Classifies uploaded documents.

Uses Claude Haiku for fast document classification into:
- DD214
- Service Treatment Records
- Medical Records
- Buddy Statements
- Nexus Letters
- DBQs
- VA Decisions
- etc.
"""
from typing import Dict, Any, Optional
import json
import structlog

from agents.base import HaikuAgent

logger = structlog.get_logger()

# Document types with descriptions
DOCUMENT_TYPES = {
    "dd214": "DD Form 214 - Certificate of Release or Discharge from Active Duty",
    "service_treatment_record": "Military medical/health records from service",
    "medical_record": "Civilian medical records, doctor visits, hospital records",
    "buddy_statement": "Personal statement from fellow service member or witness",
    "nexus_letter": "Medical opinion letter linking condition to service",
    "dbq": "Disability Benefits Questionnaire completed by medical provider",
    "va_decision": "VA rating decision or correspondence",
    "rating_decision": "Specific VA rating decision letter",
    "c_file": "VA claims file contents",
    "personnel_record": "Military personnel records (not medical)",
    "deployment_record": "Deployment orders, travel records",
    "award_citation": "Military awards, decorations, citations",
    "other": "Other document type"
}


class DocumentClassifierAgent(HaikuAgent):
    """
    Fast document classification using Claude Haiku.

    Classifies documents based on:
    - Document format and structure
    - Key identifiers and headers
    - Content patterns
    """

    def _get_agent_specific_prompt(self) -> str:
        types_list = "\n".join([f"- {k}: {v}" for k, v in DOCUMENT_TYPES.items()])
        return f"""
You are classifying documents for VA disability claims.

DOCUMENT TYPES:
{types_list}

Classify the document based on:
1. Format and structure
2. Headers and titles
3. Key identifying features
4. Content patterns

OUTPUT FORMAT:
{{
    "document_type": "type_code",
    "confidence": 0.0-1.0,
    "reasoning": "why this classification",
    "key_identifiers": ["list of identifying features found"],
    "document_date": "YYYY-MM-DD or null",
    "source": "who created this document"
}}
"""

    async def process(
        self,
        document_id: str,
        filename: str,
        content_preview: str,
        mime_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Classify a document.

        Args:
            document_id: Document UUID
            filename: Original filename
            content_preview: First ~2000 chars of document text
            mime_type: MIME type of file

        Returns:
            Classification result with confidence
        """
        self.logger.info(
            "Classifying document",
            document_id=document_id,
            filename=filename
        )

        user_message = f"""
Classify this document:

FILENAME: {filename}
MIME TYPE: {mime_type or 'unknown'}

CONTENT PREVIEW:
{content_preview[:2000]}

What type of document is this?
"""

        response = await self.call_claude(
            [{"role": "user", "content": user_message}],
            max_tokens=500,
            temperature=0.1  # Low temperature for consistent classification
        )

        result = self._parse_classification(document_id, response)

        self.logger.info(
            "Document classified",
            document_id=document_id,
            type=result.get('document_type'),
            confidence=result.get('confidence')
        )

        return result

    def _parse_classification(self, document_id: str, response: str) -> Dict[str, Any]:
        """Parse classification response."""
        try:
            import re
            json_match = re.search(r'\{[\s\S]*\}', response)
            if json_match:
                data = json.loads(json_match.group())

                # Validate document type
                doc_type = data.get('document_type', 'other')
                if doc_type not in DOCUMENT_TYPES:
                    doc_type = 'other'

                return {
                    'document_id': document_id,
                    'document_type': doc_type,
                    'confidence': data.get('confidence', 0.5),
                    'reasoning': data.get('reasoning', ''),
                    'key_identifiers': data.get('key_identifiers', []),
                    'document_date': data.get('document_date'),
                    'source': data.get('source')
                }

        except json.JSONDecodeError as e:
            self.logger.error("Failed to parse classification", error=str(e))

        return {
            'document_id': document_id,
            'document_type': 'other',
            'confidence': 0.0,
            'reasoning': 'Classification failed',
            'key_identifiers': [],
            'document_date': None,
            'source': None
        }


class MetadataExtractorAgent(HaikuAgent):
    """Extracts metadata from classified documents."""

    def _get_agent_specific_prompt(self) -> str:
        return """
Extract metadata from the document.

For DD214s, extract:
- Service dates
- Branch of service
- Rank
- Discharge type
- Awards/decorations

For medical records, extract:
- Date of service
- Provider name
- Diagnoses (ICD codes if present)
- Treatments

For all documents, extract:
- Document date
- Author/source
- Key names mentioned
- Key dates mentioned

OUTPUT FORMAT:
{{
    "metadata": {{
        "document_date": "YYYY-MM-DD",
        "source": "who created",
        "key_fields": {{}}
    }},
    "extracted_dates": [],
    "extracted_names": [],
    "diagnoses": []
}}
"""

    async def process(self, document_content: str, document_type: str) -> Dict[str, Any]:
        """Extract metadata from document content."""
        user_message = f"""
Extract metadata from this {document_type}:

{document_content[:4000]}
"""

        response = await self.call_claude(
            [{"role": "user", "content": user_message}],
            max_tokens=1000
        )

        try:
            import re
            json_match = re.search(r'\{[\s\S]*\}', response)
            if json_match:
                return json.loads(json_match.group())
        except:
            pass

        return {'metadata': {}, 'extracted_dates': [], 'extracted_names': [], 'diagnoses': []}
