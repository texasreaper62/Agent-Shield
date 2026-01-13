"""
VA Benefits Intake API integration service.

This service handles communication with the VA's Benefits Intake API
for submitting disability claims and checking submission status.

API Documentation: https://developer.va.gov/explore/benefits/docs/benefits
"""
from typing import Optional
from uuid import UUID
import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
import structlog

from config import settings
from models.claim import Claim
from models.form import Form
from services.storage import download_blob, get_blob_url

logger = structlog.get_logger()

# VA API endpoints
VA_INTAKE_URL = settings.VA_BENEFITS_INTAKE_API_URL
VA_FORMS_URL = settings.VA_FORMS_API_URL


async def get_va_headers() -> dict:
    """Get headers for VA API requests."""
    return {
        "apiKey": settings.VA_API_KEY,
        "Content-Type": "application/json",
    }


async def submit_to_benefits_intake(claim_id: UUID, db: AsyncSession) -> dict:
    """
    Submit a claim to the VA Benefits Intake API.

    CRITICAL: This function should only be called after human approval.

    Args:
        claim_id: UUID of the claim to submit
        db: Database session

    Returns:
        VA API response containing submission ID and status
    """
    # Get claim with forms
    result = await db.execute(
        select(Claim)
        .options(selectinload(Claim.forms))
        .where(Claim.id == claim_id)
    )
    claim = result.scalar_one_or_none()
    if not claim:
        raise ValueError(f"Claim {claim_id} not found")

    # Get all generated forms
    forms_to_submit = [f for f in claim.forms if f.pdf_storage_path]
    if not forms_to_submit:
        raise ValueError("No generated forms to submit")

    logger.info(
        "Preparing VA submission",
        claim_id=str(claim_id),
        forms_count=len(forms_to_submit)
    )

    # Step 1: Get upload location from VA
    async with httpx.AsyncClient() as client:
        headers = await get_va_headers()

        # Request upload location
        init_response = await client.post(
            f"{VA_INTAKE_URL}/uploads",
            headers=headers,
            json={
                "veteranFirstName": "PLACEHOLDER",  # Would come from veteran record
                "veteranLastName": "PLACEHOLDER",
                "fileNumber": "PLACEHOLDER",
                "zipCode": "PLACEHOLDER",
            }
        )

        if init_response.status_code != 200:
            logger.error(
                "VA API error on upload init",
                status=init_response.status_code,
                response=init_response.text
            )
            raise Exception(f"VA API error: {init_response.status_code}")

        init_data = init_response.json()
        upload_url = init_data.get("attributes", {}).get("location")
        submission_id = init_data.get("id")

        # Step 2: Upload documents
        # In production, you would combine PDFs and upload as multipart
        for form in forms_to_submit:
            pdf_data = await download_blob(form.pdf_storage_path, container="forms")

            upload_response = await client.put(
                upload_url,
                content=pdf_data,
                headers={"Content-Type": "application/pdf"}
            )

            if upload_response.status_code not in [200, 201]:
                logger.error(
                    "VA upload failed",
                    status=upload_response.status_code,
                    form=form.form_number
                )
                raise Exception(f"Upload failed for form {form.form_number}")

        # Step 3: Confirm submission
        confirm_response = await client.put(
            f"{VA_INTAKE_URL}/uploads/{submission_id}",
            headers=headers,
            json={"status": "submitted"}
        )

        if confirm_response.status_code != 200:
            raise Exception(f"Submission confirmation failed")

        logger.info(
            "VA submission successful",
            submission_id=submission_id,
            claim_id=str(claim_id)
        )

        return {
            "id": submission_id,
            "status": "submitted",
            "tracking_number": init_data.get("attributes", {}).get("confirmationNumber"),
        }


async def check_submission_status(va_submission_id: str) -> dict:
    """
    Check the status of a VA submission.

    Args:
        va_submission_id: VA-assigned submission ID

    Returns:
        Status information from VA
    """
    async with httpx.AsyncClient() as client:
        headers = await get_va_headers()

        response = await client.get(
            f"{VA_INTAKE_URL}/uploads/{va_submission_id}",
            headers=headers
        )

        if response.status_code != 200:
            logger.error(
                "VA status check failed",
                status=response.status_code,
                submission_id=va_submission_id
            )
            raise Exception(f"Status check failed: {response.status_code}")

        data = response.json()
        attributes = data.get("attributes", {})

        return {
            "id": va_submission_id,
            "status": attributes.get("status"),
            "detail": attributes.get("detail"),
            "location": attributes.get("location"),
            "updated_at": attributes.get("updatedAt"),
        }


async def get_va_form_template(form_number: str) -> Optional[dict]:
    """
    Get form template/metadata from VA Forms API.

    Args:
        form_number: VA form number (e.g., "21-526EZ")

    Returns:
        Form metadata and PDF URL
    """
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{VA_FORMS_URL}/forms/{form_number}",
            headers={"apiKey": settings.VA_API_KEY}
        )

        if response.status_code != 200:
            logger.warning(
                "VA form not found",
                form_number=form_number,
                status=response.status_code
            )
            return None

        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})

        return {
            "form_number": form_number,
            "title": attributes.get("title"),
            "url": attributes.get("url"),
            "last_revision": attributes.get("last_revision"),
            "pages": attributes.get("pages"),
            "sha256": attributes.get("sha256"),
        }


async def search_va_forms(query: str, limit: int = 10) -> list:
    """
    Search VA forms by keyword.

    Args:
        query: Search query
        limit: Maximum results

    Returns:
        List of matching forms
    """
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{VA_FORMS_URL}/forms",
            params={"query": query},
            headers={"apiKey": settings.VA_API_KEY}
        )

        if response.status_code != 200:
            return []

        data = response.json()
        forms = data.get("data", [])

        return [
            {
                "form_number": f.get("id"),
                "title": f.get("attributes", {}).get("title"),
                "url": f.get("attributes", {}).get("url"),
            }
            for f in forms[:limit]
        ]
