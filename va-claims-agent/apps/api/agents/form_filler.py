"""
Form Filler Agent - Automatically fills VA forms from claim data.

Uses Claude Sonnet to:
- Map claim data to form fields
- Generate appropriate text for narrative fields
- Ensure consistency across form sections
- Cite sources for all auto-filled fields

CRITICAL: Every auto-filled field must cite its source.
"""
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import json
import structlog

from agents.base import SonnetAgent, Citation

logger = structlog.get_logger()


@dataclass
class FormFieldValue:
    """A form field value with source citation."""
    field_id: str
    field_label: str
    value: str
    source_citation: Optional[Citation]
    is_auto_filled: bool
    confidence: float


# Form field definitions for common VA forms
FORM_DEFINITIONS = {
    "21-526EZ": {
        "name": "Application for Disability Compensation",
        "sections": {
            "veteran_info": {
                "fields": [
                    {"id": "veteranName", "label": "Veteran's Name", "type": "text"},
                    {"id": "veteranSSN", "label": "SSN", "type": "text"},
                    {"id": "veteranDOB", "label": "Date of Birth", "type": "date"},
                    {"id": "veteranAddress", "label": "Mailing Address", "type": "text"},
                    {"id": "veteranPhone", "label": "Phone Number", "type": "text"},
                    {"id": "veteranEmail", "label": "Email", "type": "text"},
                ]
            },
            "service_info": {
                "fields": [
                    {"id": "branchOfService", "label": "Branch of Service", "type": "text"},
                    {"id": "serviceDatesStart", "label": "Service Start Date", "type": "date"},
                    {"id": "serviceDatesEnd", "label": "Service End Date", "type": "date"},
                    {"id": "dischargeType", "label": "Character of Discharge", "type": "text"},
                ]
            },
            "claimed_conditions": {
                "fields": [
                    {"id": "condition1", "label": "Condition 1", "type": "text"},
                    {"id": "condition1Date", "label": "Condition 1 Onset Date", "type": "date"},
                    {"id": "condition1Cause", "label": "Condition 1 Cause", "type": "textarea"},
                ]
            }
        }
    },
    "21-0781": {
        "name": "Statement in Support of Claim for PTSD",
        "sections": {
            "stressor_info": {
                "fields": [
                    {"id": "stressorDate", "label": "Date of Incident", "type": "date"},
                    {"id": "stressorLocation", "label": "Location", "type": "text"},
                    {"id": "stressorDescription", "label": "Description of Incident", "type": "textarea"},
                    {"id": "stressorWitnesses", "label": "Witnesses", "type": "textarea"},
                ]
            }
        }
    }
}


class FormFillerAgent(SonnetAgent):
    """
    Fills VA forms from claim data with citations.

    This agent:
    1. Maps veteran and claim data to form fields
    2. Generates narrative content for text areas
    3. Ensures all auto-filled data has source citations
    4. Validates completeness

    CRITICAL: Every value must cite its source document.
    """

    def _get_agent_specific_prompt(self) -> str:
        return """
You are filling VA disability claim forms.

REQUIREMENTS:
1. Every value MUST cite its source document
2. Use exact data from evidence - do not fabricate
3. For narrative fields, summarize evidence with citations
4. Mark fields as "NEEDS_INPUT" if data is not available
5. Ensure dates are in MM/DD/YYYY format

For each field, provide:
- The value to fill
- The source document ID and quote
- Confidence level

OUTPUT FORMAT:
{{
    "fields": [
        {{
            "field_id": "fieldName",
            "value": "value to fill",
            "source_document": "document_id",
            "source_quote": "exact quote from document",
            "confidence": 0.0-1.0
        }}
    ],
    "missing_fields": ["list of fields without available data"],
    "warnings": ["any concerns about the data"]
}}

NEVER make up data. If information is not in the evidence, mark it as missing.
"""

    async def process(
        self,
        form_number: str,
        claim_data: Dict[str, Any],
        veteran_data: Dict[str, Any],
        evidence_data: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Fill a form with claim data.

        Args:
            form_number: VA form number (e.g., "21-526EZ")
            claim_data: Claim information
            veteran_data: Veteran profile data
            evidence_data: List of evidence with citations

        Returns:
            Dict with field values and citations
        """
        self.logger.info(
            "Filling form",
            form_number=form_number,
            claim_id=claim_data.get('id')
        )

        form_def = FORM_DEFINITIONS.get(form_number)
        if not form_def:
            raise ValueError(f"Form {form_number} not supported")

        # Build context
        evidence_context = json.dumps(evidence_data, indent=2)
        veteran_context = json.dumps(veteran_data, indent=2)
        claim_context = json.dumps(claim_data, indent=2)

        user_message = f"""
Fill form {form_number}: {form_def['name']}

VETERAN DATA:
{veteran_context}

CLAIM DATA:
{claim_context}

EVIDENCE:
{evidence_context}

FORM FIELDS TO FILL:
{json.dumps(form_def['sections'], indent=2)}

Fill each field with data from the evidence. CITE your sources.
"""

        response = await self.call_claude([
            {"role": "user", "content": user_message}
        ])

        result = self._parse_form_response(form_number, response)

        # Validate all fields have citations
        self._validate_form_citations(result)

        self.logger.info(
            "Form filled",
            form_number=form_number,
            fields_filled=len(result.get('fields', [])),
            missing=len(result.get('missing_fields', []))
        )

        return result

    def _parse_form_response(self, form_number: str, response: str) -> Dict[str, Any]:
        """Parse form filling response."""
        try:
            import re
            json_match = re.search(r'\{[\s\S]*\}', response)
            if json_match:
                data = json.loads(json_match.group())

                # Convert to FormFieldValue objects
                fields = []
                for f in data.get('fields', []):
                    citation = None
                    if f.get('source_document') and f.get('source_quote'):
                        citation = Citation(
                            document_id=f['source_document'],
                            chunk_id="",
                            quote=f['source_quote']
                        )

                    fields.append({
                        'field_id': f.get('field_id'),
                        'value': f.get('value'),
                        'source_citation': vars(citation) if citation else None,
                        'is_auto_filled': True,
                        'confidence': f.get('confidence', 0.5)
                    })

                return {
                    'form_number': form_number,
                    'fields': fields,
                    'missing_fields': data.get('missing_fields', []),
                    'warnings': data.get('warnings', [])
                }

        except json.JSONDecodeError as e:
            self.logger.error("Failed to parse form response", error=str(e))

        return {
            'form_number': form_number,
            'fields': [],
            'missing_fields': [],
            'warnings': ['Failed to parse AI response']
        }

    def _validate_form_citations(self, result: Dict[str, Any]) -> None:
        """Validate that auto-filled fields have citations."""
        for field in result.get('fields', []):
            if field.get('is_auto_filled') and not field.get('source_citation'):
                self.logger.warning(
                    "Auto-filled field lacks citation",
                    field_id=field.get('field_id')
                )


class NarrativeGeneratorAgent(SonnetAgent):
    """Generates narrative text for form sections."""

    def _get_agent_specific_prompt(self) -> str:
        return """
Generate narrative text for VA form sections.

The narrative should:
1. Be factual and cite specific evidence
2. Be written from the veteran's perspective (first person if appropriate)
3. Include specific dates, locations, and details
4. Not embellish or add information not in the evidence

Every factual statement must include [CITE: document_id, quote] markers.
"""

    async def process(
        self,
        narrative_type: str,
        condition: str,
        evidence: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Generate narrative text for a form section.

        Args:
            narrative_type: Type of narrative (stressor, symptoms, etc.)
            condition: The condition being claimed
            evidence: Supporting evidence

        Returns:
            Generated narrative with citations
        """
        evidence_text = json.dumps(evidence, indent=2)

        user_message = f"""
Generate a {narrative_type} narrative for: {condition}

EVIDENCE:
{evidence_text}

Write a clear, factual narrative that cites the evidence.
"""

        response = await self.call_claude([
            {"role": "user", "content": user_message}
        ])

        citations = self.parse_citations(response)

        return {
            'narrative': response,
            'citations': [vars(c) for c in citations],
            'word_count': len(response.split())
        }
