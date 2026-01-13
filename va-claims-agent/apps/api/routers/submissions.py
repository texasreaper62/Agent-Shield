"""
Submissions router for VA Benefits Intake API.
"""
from typing import List, Optional
from uuid import UUID
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
import structlog

from config import settings
from models.database import get_db
from models.user import User, UserRole
from models.claim import Claim, ClaimStatus
from models.submission import Submission, SubmissionStatus
from models.review import Review, ReviewStatus, ReviewType
from routers.auth import get_current_active_user, require_role

router = APIRouter()
logger = structlog.get_logger()


class SubmissionCreate(BaseModel):
    claim_id: UUID


class SubmissionApproval(BaseModel):
    notes: Optional[str] = None


class SubmissionResponse(BaseModel):
    id: str
    claim_id: str
    status: str
    requires_approval: bool
    approved_by: Optional[str]
    approved_at: Optional[datetime]
    approval_notes: Optional[str]
    va_submission_id: Optional[str]
    va_status: Optional[str]
    tracking_number: Optional[str]
    confirmation_number: Optional[str]
    error_message: Optional[str]
    created_at: datetime
    submitted_at: Optional[datetime]
    received_at: Optional[datetime]

    class Config:
        from_attributes = True


@router.post("/", response_model=SubmissionResponse, status_code=201)
async def create_submission(
    submission_data: SubmissionCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Create a submission request (requires human approval before actual submission).

    CRITICAL: This does NOT submit to the VA. It creates a submission request
    that must be approved by an attorney/admin before actual submission.
    """
    # Validate claim exists and is ready
    result = await db.execute(
        select(Claim).where(Claim.id == submission_data.claim_id)
    )
    claim = result.scalar_one_or_none()
    if not claim:
        raise HTTPException(status_code=404, detail="Claim not found")

    # Check if claim has been reviewed and approved
    if settings.REQUIRE_ATTORNEY_APPROVAL:
        review_result = await db.execute(
            select(Review).where(
                Review.claim_id == claim.id,
                Review.review_type == ReviewType.FINAL_REVIEW,
                Review.status == ReviewStatus.APPROVED
            )
        )
        approved_review = review_result.scalar_one_or_none()
        if not approved_review:
            raise HTTPException(
                status_code=400,
                detail="Claim must have an approved final review before submission"
            )

    # Check for existing pending submission
    result = await db.execute(
        select(Submission).where(
            Submission.claim_id == claim.id,
            Submission.status.in_([
                SubmissionStatus.DRAFT,
                SubmissionStatus.PENDING_APPROVAL,
                SubmissionStatus.APPROVED,
                SubmissionStatus.UPLOADING,
                SubmissionStatus.SUBMITTED
            ])
        )
    )
    existing = result.scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail="Submission already exists for this claim")

    # 38 CFR §14.636 fee compliance check
    if claim.is_initial_claim:
        logger.warning(
            "Initial claim submission - fees blocked per 38 CFR §14.636",
            claim_id=str(claim.id)
        )

    submission = Submission(
        claim_id=claim.id,
        status=SubmissionStatus.PENDING_APPROVAL,
        requires_approval=True,  # ALWAYS require approval
    )
    db.add(submission)
    await db.commit()
    await db.refresh(submission)

    logger.info("Submission created (pending approval)", submission_id=str(submission.id))

    return SubmissionResponse(
        id=str(submission.id),
        claim_id=str(submission.claim_id),
        status=submission.status.value,
        requires_approval=submission.requires_approval,
        approved_by=str(submission.approved_by) if submission.approved_by else None,
        approved_at=submission.approved_at,
        approval_notes=submission.approval_notes,
        va_submission_id=submission.va_submission_id,
        va_status=submission.va_status,
        tracking_number=submission.tracking_number,
        confirmation_number=submission.confirmation_number,
        error_message=submission.error_message,
        created_at=submission.created_at,
        submitted_at=submission.submitted_at,
        received_at=submission.received_at,
    )


@router.get("/pending", response_model=List[SubmissionResponse])
async def list_pending_approvals(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ATTORNEY, UserRole.ADMIN))
):
    """List submissions pending approval (attorneys/admin only)."""
    result = await db.execute(
        select(Submission)
        .where(Submission.status == SubmissionStatus.PENDING_APPROVAL)
        .order_by(Submission.created_at.asc())
    )
    submissions = result.scalars().all()

    return [
        SubmissionResponse(
            id=str(s.id),
            claim_id=str(s.claim_id),
            status=s.status.value,
            requires_approval=s.requires_approval,
            approved_by=str(s.approved_by) if s.approved_by else None,
            approved_at=s.approved_at,
            approval_notes=s.approval_notes,
            va_submission_id=s.va_submission_id,
            va_status=s.va_status,
            tracking_number=s.tracking_number,
            confirmation_number=s.confirmation_number,
            error_message=s.error_message,
            created_at=s.created_at,
            submitted_at=s.submitted_at,
            received_at=s.received_at,
        )
        for s in submissions
    ]


@router.get("/{submission_id}", response_model=SubmissionResponse)
async def get_submission(
    submission_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get submission details."""
    result = await db.execute(
        select(Submission).where(Submission.id == submission_id)
    )
    submission = result.scalar_one_or_none()
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")

    return SubmissionResponse(
        id=str(submission.id),
        claim_id=str(submission.claim_id),
        status=submission.status.value,
        requires_approval=submission.requires_approval,
        approved_by=str(submission.approved_by) if submission.approved_by else None,
        approved_at=submission.approved_at,
        approval_notes=submission.approval_notes,
        va_submission_id=submission.va_submission_id,
        va_status=submission.va_status,
        tracking_number=submission.tracking_number,
        confirmation_number=submission.confirmation_number,
        error_message=submission.error_message,
        created_at=submission.created_at,
        submitted_at=submission.submitted_at,
        received_at=submission.received_at,
    )


@router.post("/{submission_id}/approve", response_model=SubmissionResponse)
async def approve_submission(
    submission_id: UUID,
    approval: SubmissionApproval,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ATTORNEY, UserRole.ADMIN))
):
    """
    Approve a submission for VA submission (attorneys/admin only).

    WARNING: This authorizes the system to submit the claim to the VA.
    Ensure all reviews are complete and information is accurate.
    """
    result = await db.execute(
        select(Submission).where(Submission.id == submission_id)
    )
    submission = result.scalar_one_or_none()
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")

    if submission.status != SubmissionStatus.PENDING_APPROVAL:
        raise HTTPException(status_code=400, detail="Submission not pending approval")

    submission.status = SubmissionStatus.APPROVED
    submission.approved_by = current_user.id
    submission.approved_at = datetime.utcnow()
    submission.approval_notes = approval.notes
    await db.commit()
    await db.refresh(submission)

    logger.info(
        "Submission approved",
        submission_id=str(submission.id),
        approved_by=current_user.email
    )

    return SubmissionResponse(
        id=str(submission.id),
        claim_id=str(submission.claim_id),
        status=submission.status.value,
        requires_approval=submission.requires_approval,
        approved_by=str(submission.approved_by) if submission.approved_by else None,
        approved_at=submission.approved_at,
        approval_notes=submission.approval_notes,
        va_submission_id=submission.va_submission_id,
        va_status=submission.va_status,
        tracking_number=submission.tracking_number,
        confirmation_number=submission.confirmation_number,
        error_message=submission.error_message,
        created_at=submission.created_at,
        submitted_at=submission.submitted_at,
        received_at=submission.received_at,
    )


@router.post("/{submission_id}/submit", response_model=SubmissionResponse)
async def submit_to_va(
    submission_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ATTORNEY, UserRole.ADMIN))
):
    """
    Submit the approved claim to VA Benefits Intake API (attorneys/admin only).

    CRITICAL: This performs the actual submission to the VA.
    """
    result = await db.execute(
        select(Submission).where(Submission.id == submission_id)
    )
    submission = result.scalar_one_or_none()
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")

    if submission.status != SubmissionStatus.APPROVED:
        raise HTTPException(
            status_code=400,
            detail="Submission must be approved before submitting to VA"
        )

    # Import VA submission service
    from services.va_api import submit_to_benefits_intake

    try:
        submission.status = SubmissionStatus.UPLOADING
        await db.commit()

        # Perform actual VA submission
        va_response = await submit_to_benefits_intake(submission.claim_id, db)

        submission.status = SubmissionStatus.SUBMITTED
        submission.va_submission_id = va_response.get("id")
        submission.va_status = va_response.get("status")
        submission.tracking_number = va_response.get("tracking_number")
        submission.submitted_at = datetime.utcnow()
        submission.api_responses = [va_response]

        # Update claim status
        claim_result = await db.execute(
            select(Claim).where(Claim.id == submission.claim_id)
        )
        claim = claim_result.scalar_one_or_none()
        if claim:
            claim.status = ClaimStatus.SUBMITTED
            claim.submitted_at = datetime.utcnow()

        await db.commit()
        await db.refresh(submission)

        logger.info(
            "Claim submitted to VA",
            submission_id=str(submission.id),
            va_submission_id=submission.va_submission_id
        )

    except Exception as e:
        submission.status = SubmissionStatus.ERROR
        submission.error_message = str(e)
        submission.last_error_at = datetime.utcnow()
        await db.commit()
        logger.error("VA submission failed", error=str(e), submission_id=str(submission.id))
        raise HTTPException(status_code=500, detail=f"VA submission failed: {str(e)}")

    return SubmissionResponse(
        id=str(submission.id),
        claim_id=str(submission.claim_id),
        status=submission.status.value,
        requires_approval=submission.requires_approval,
        approved_by=str(submission.approved_by) if submission.approved_by else None,
        approved_at=submission.approved_at,
        approval_notes=submission.approval_notes,
        va_submission_id=submission.va_submission_id,
        va_status=submission.va_status,
        tracking_number=submission.tracking_number,
        confirmation_number=submission.confirmation_number,
        error_message=submission.error_message,
        created_at=submission.created_at,
        submitted_at=submission.submitted_at,
        received_at=submission.received_at,
    )


@router.get("/{submission_id}/status", response_model=SubmissionResponse)
async def check_va_status(
    submission_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Check the status of a submission with the VA."""
    result = await db.execute(
        select(Submission).where(Submission.id == submission_id)
    )
    submission = result.scalar_one_or_none()
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")

    if not submission.va_submission_id:
        raise HTTPException(status_code=400, detail="Submission not yet submitted to VA")

    from services.va_api import check_submission_status

    try:
        va_status = await check_submission_status(submission.va_submission_id)

        submission.va_status = va_status.get("status")
        submission.va_status_detail = va_status.get("detail")

        if va_status.get("status") == "received":
            submission.status = SubmissionStatus.RECEIVED
            submission.received_at = datetime.utcnow()
        elif va_status.get("status") == "vbms":
            submission.status = SubmissionStatus.VBMS
            submission.va_location = va_status.get("location")

        if submission.api_responses:
            submission.api_responses.append(va_status)
        else:
            submission.api_responses = [va_status]

        await db.commit()
        await db.refresh(submission)

    except Exception as e:
        logger.error("VA status check failed", error=str(e))
        raise HTTPException(status_code=500, detail=f"Status check failed: {str(e)}")

    return SubmissionResponse(
        id=str(submission.id),
        claim_id=str(submission.claim_id),
        status=submission.status.value,
        requires_approval=submission.requires_approval,
        approved_by=str(submission.approved_by) if submission.approved_by else None,
        approved_at=submission.approved_at,
        approval_notes=submission.approval_notes,
        va_submission_id=submission.va_submission_id,
        va_status=submission.va_status,
        tracking_number=submission.tracking_number,
        confirmation_number=submission.confirmation_number,
        error_message=submission.error_message,
        created_at=submission.created_at,
        submitted_at=submission.submitted_at,
        received_at=submission.received_at,
    )
