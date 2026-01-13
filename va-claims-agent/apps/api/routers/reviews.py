"""
Reviews router for attorney review workflow.
"""
from typing import List, Optional
from uuid import UUID
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from pydantic import BaseModel
import structlog

from models.database import get_db
from models.user import User, UserRole
from models.claim import Claim, ClaimStatus
from models.form import Form, FormStatus
from models.review import Review, ReviewComment, ReviewStatus, ReviewType
from routers.auth import get_current_active_user, require_role

router = APIRouter()
logger = structlog.get_logger()


class ReviewCreate(BaseModel):
    claim_id: UUID
    review_type: ReviewType
    reviewed_item_type: Optional[str] = None
    reviewed_item_id: Optional[UUID] = None


class CommentCreate(BaseModel):
    content: str
    is_revision_request: bool = False
    revision_details: Optional[str] = None
    reference_type: Optional[str] = None
    reference_id: Optional[str] = None


class CommentResponse(BaseModel):
    id: str
    author_id: str
    content: str
    is_revision_request: bool
    revision_details: Optional[str]
    reference_type: Optional[str]
    reference_id: Optional[str]
    is_resolved: bool
    resolution_notes: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class ReviewResponse(BaseModel):
    id: str
    claim_id: str
    reviewer_id: Optional[str]
    review_type: str
    status: str
    reviewed_item_type: Optional[str]
    reviewed_item_id: Optional[str]
    summary: Optional[str]
    decision_rationale: Optional[str]
    checklist: Optional[List[dict]]
    checklist_complete: bool
    legal_risk_notes: Optional[str]
    ethical_concerns: Optional[str]
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]

    class Config:
        from_attributes = True


class ReviewDetailResponse(ReviewResponse):
    comments: List[CommentResponse]


# Standard review checklist items
REVIEW_CHECKLISTS = {
    ReviewType.CLAIM_ANALYSIS: [
        {"id": "evidence_complete", "label": "All evidence has been reviewed", "checked": False},
        {"id": "citations_valid", "label": "All citations are valid and accurate", "checked": False},
        {"id": "cfr_correct", "label": "38 CFR references are correct", "checked": False},
        {"id": "rating_reasonable", "label": "Estimated ratings are reasonable", "checked": False},
        {"id": "missing_evidence_identified", "label": "Missing evidence has been identified", "checked": False},
    ],
    ReviewType.FORM_REVIEW: [
        {"id": "fields_accurate", "label": "All form fields are accurate", "checked": False},
        {"id": "citations_present", "label": "Auto-filled fields have citations", "checked": False},
        {"id": "no_contradictions", "label": "No contradictory information", "checked": False},
        {"id": "dates_correct", "label": "All dates are correct", "checked": False},
        {"id": "signatures_ready", "label": "Ready for signature", "checked": False},
    ],
    ReviewType.FINAL_REVIEW: [
        {"id": "claim_complete", "label": "Claim is complete", "checked": False},
        {"id": "forms_complete", "label": "All required forms are complete", "checked": False},
        {"id": "evidence_sufficient", "label": "Evidence is sufficient", "checked": False},
        {"id": "legal_compliance", "label": "Meets legal/ethical requirements", "checked": False},
        {"id": "fee_compliance", "label": "Fee agreement complies with 38 CFR §14.636", "checked": False},
        {"id": "ready_for_submission", "label": "Ready for VA submission", "checked": False},
    ],
}


@router.post("/", response_model=ReviewResponse, status_code=201)
async def create_review(
    review_data: ReviewCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ATTORNEY, UserRole.ADMIN, UserRole.STAFF))
):
    """Create a new review (attorneys/staff only)."""
    # Validate claim exists
    result = await db.execute(
        select(Claim).where(Claim.id == review_data.claim_id)
    )
    claim = result.scalar_one_or_none()
    if not claim:
        raise HTTPException(status_code=404, detail="Claim not found")

    # Get appropriate checklist
    checklist = REVIEW_CHECKLISTS.get(review_data.review_type, [])

    review = Review(
        claim_id=review_data.claim_id,
        reviewer_id=current_user.id,
        review_type=review_data.review_type,
        status=ReviewStatus.PENDING,
        reviewed_item_type=review_data.reviewed_item_type,
        reviewed_item_id=review_data.reviewed_item_id,
        checklist=checklist,
    )
    db.add(review)
    await db.commit()
    await db.refresh(review)

    logger.info("Review created", review_id=str(review.id), type=review_data.review_type.value)

    return ReviewResponse(
        id=str(review.id),
        claim_id=str(review.claim_id),
        reviewer_id=str(review.reviewer_id) if review.reviewer_id else None,
        review_type=review.review_type.value,
        status=review.status.value,
        reviewed_item_type=review.reviewed_item_type,
        reviewed_item_id=str(review.reviewed_item_id) if review.reviewed_item_id else None,
        summary=review.summary,
        decision_rationale=review.decision_rationale,
        checklist=review.checklist,
        checklist_complete=review.checklist_complete,
        legal_risk_notes=review.legal_risk_notes,
        ethical_concerns=review.ethical_concerns,
        created_at=review.created_at,
        started_at=review.started_at,
        completed_at=review.completed_at,
    )


@router.get("/claim/{claim_id}", response_model=List[ReviewResponse])
async def list_claim_reviews(
    claim_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """List all reviews for a claim."""
    result = await db.execute(
        select(Review).where(Review.claim_id == claim_id).order_by(Review.created_at.desc())
    )
    reviews = result.scalars().all()

    return [
        ReviewResponse(
            id=str(r.id),
            claim_id=str(r.claim_id),
            reviewer_id=str(r.reviewer_id) if r.reviewer_id else None,
            review_type=r.review_type.value,
            status=r.status.value,
            reviewed_item_type=r.reviewed_item_type,
            reviewed_item_id=str(r.reviewed_item_id) if r.reviewed_item_id else None,
            summary=r.summary,
            decision_rationale=r.decision_rationale,
            checklist=r.checklist,
            checklist_complete=r.checklist_complete,
            legal_risk_notes=r.legal_risk_notes,
            ethical_concerns=r.ethical_concerns,
            created_at=r.created_at,
            started_at=r.started_at,
            completed_at=r.completed_at,
        )
        for r in reviews
    ]


@router.get("/pending", response_model=List[ReviewResponse])
async def list_pending_reviews(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ATTORNEY, UserRole.ADMIN, UserRole.STAFF))
):
    """List all pending reviews (attorneys/staff only)."""
    result = await db.execute(
        select(Review)
        .where(Review.status.in_([ReviewStatus.PENDING, ReviewStatus.IN_PROGRESS]))
        .order_by(Review.created_at.asc())
    )
    reviews = result.scalars().all()

    return [
        ReviewResponse(
            id=str(r.id),
            claim_id=str(r.claim_id),
            reviewer_id=str(r.reviewer_id) if r.reviewer_id else None,
            review_type=r.review_type.value,
            status=r.status.value,
            reviewed_item_type=r.reviewed_item_type,
            reviewed_item_id=str(r.reviewed_item_id) if r.reviewed_item_id else None,
            summary=r.summary,
            decision_rationale=r.decision_rationale,
            checklist=r.checklist,
            checklist_complete=r.checklist_complete,
            legal_risk_notes=r.legal_risk_notes,
            ethical_concerns=r.ethical_concerns,
            created_at=r.created_at,
            started_at=r.started_at,
            completed_at=r.completed_at,
        )
        for r in reviews
    ]


@router.get("/{review_id}", response_model=ReviewDetailResponse)
async def get_review(
    review_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get review details with comments."""
    result = await db.execute(
        select(Review)
        .options(selectinload(Review.comments))
        .where(Review.id == review_id)
    )
    review = result.scalar_one_or_none()
    if not review:
        raise HTTPException(status_code=404, detail="Review not found")

    return ReviewDetailResponse(
        id=str(review.id),
        claim_id=str(review.claim_id),
        reviewer_id=str(review.reviewer_id) if review.reviewer_id else None,
        review_type=review.review_type.value,
        status=review.status.value,
        reviewed_item_type=review.reviewed_item_type,
        reviewed_item_id=str(review.reviewed_item_id) if review.reviewed_item_id else None,
        summary=review.summary,
        decision_rationale=review.decision_rationale,
        checklist=review.checklist,
        checklist_complete=review.checklist_complete,
        legal_risk_notes=review.legal_risk_notes,
        ethical_concerns=review.ethical_concerns,
        created_at=review.created_at,
        started_at=review.started_at,
        completed_at=review.completed_at,
        comments=[
            CommentResponse(
                id=str(c.id),
                author_id=str(c.author_id),
                content=c.content,
                is_revision_request=c.is_revision_request,
                revision_details=c.revision_details,
                reference_type=c.reference_type,
                reference_id=c.reference_id,
                is_resolved=c.is_resolved,
                resolution_notes=c.resolution_notes,
                created_at=c.created_at,
            )
            for c in review.comments
        ],
    )


@router.put("/{review_id}/start")
async def start_review(
    review_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ATTORNEY, UserRole.ADMIN, UserRole.STAFF))
):
    """Start working on a review."""
    result = await db.execute(
        select(Review).where(Review.id == review_id)
    )
    review = result.scalar_one_or_none()
    if not review:
        raise HTTPException(status_code=404, detail="Review not found")

    if review.status != ReviewStatus.PENDING:
        raise HTTPException(status_code=400, detail="Review already started or completed")

    review.status = ReviewStatus.IN_PROGRESS
    review.reviewer_id = current_user.id
    review.started_at = datetime.utcnow()
    await db.commit()

    logger.info("Review started", review_id=str(review.id), reviewer=current_user.email)
    return {"message": "Review started"}


@router.put("/{review_id}/complete")
async def complete_review(
    review_id: UUID,
    decision: ReviewStatus,
    summary: Optional[str] = None,
    rationale: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ATTORNEY, UserRole.ADMIN))
):
    """Complete a review with a decision."""
    if decision not in [ReviewStatus.APPROVED, ReviewStatus.REJECTED, ReviewStatus.REVISION_REQUESTED]:
        raise HTTPException(status_code=400, detail="Invalid decision")

    result = await db.execute(
        select(Review).where(Review.id == review_id)
    )
    review = result.scalar_one_or_none()
    if not review:
        raise HTTPException(status_code=404, detail="Review not found")

    if review.status not in [ReviewStatus.PENDING, ReviewStatus.IN_PROGRESS]:
        raise HTTPException(status_code=400, detail="Review already completed")

    # Check if checklist is complete for approval
    if decision == ReviewStatus.APPROVED and review.checklist:
        all_checked = all(item.get("checked", False) for item in review.checklist)
        if not all_checked:
            raise HTTPException(status_code=400, detail="Checklist must be complete before approval")

    review.status = decision
    review.summary = summary
    review.decision_rationale = rationale
    review.completed_at = datetime.utcnow()
    await db.commit()

    # Update claim status if final review approved
    if review.review_type == ReviewType.FINAL_REVIEW and decision == ReviewStatus.APPROVED:
        claim_result = await db.execute(
            select(Claim).where(Claim.id == review.claim_id)
        )
        claim = claim_result.scalar_one_or_none()
        if claim:
            claim.status = ClaimStatus.APPROVED
            await db.commit()

    logger.info("Review completed", review_id=str(review.id), decision=decision.value)
    return {"message": f"Review completed: {decision.value}"}


@router.put("/{review_id}/checklist")
async def update_checklist(
    review_id: UUID,
    checklist: List[dict],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ATTORNEY, UserRole.ADMIN, UserRole.STAFF))
):
    """Update review checklist."""
    result = await db.execute(
        select(Review).where(Review.id == review_id)
    )
    review = result.scalar_one_or_none()
    if not review:
        raise HTTPException(status_code=404, detail="Review not found")

    review.checklist = checklist
    review.checklist_complete = all(item.get("checked", False) for item in checklist)
    await db.commit()

    logger.info("Checklist updated", review_id=str(review.id), complete=review.checklist_complete)
    return {"message": "Checklist updated", "complete": review.checklist_complete}


@router.post("/{review_id}/comments", response_model=CommentResponse)
async def add_comment(
    review_id: UUID,
    comment_data: CommentCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Add a comment to a review."""
    result = await db.execute(
        select(Review).where(Review.id == review_id)
    )
    review = result.scalar_one_or_none()
    if not review:
        raise HTTPException(status_code=404, detail="Review not found")

    comment = ReviewComment(
        review_id=review.id,
        author_id=current_user.id,
        content=comment_data.content,
        is_revision_request=comment_data.is_revision_request,
        revision_details=comment_data.revision_details,
        reference_type=comment_data.reference_type,
        reference_id=comment_data.reference_id,
    )
    db.add(comment)
    await db.commit()
    await db.refresh(comment)

    logger.info("Comment added", review_id=str(review.id), comment_id=str(comment.id))

    return CommentResponse(
        id=str(comment.id),
        author_id=str(comment.author_id),
        content=comment.content,
        is_revision_request=comment.is_revision_request,
        revision_details=comment.revision_details,
        reference_type=comment.reference_type,
        reference_id=comment.reference_id,
        is_resolved=comment.is_resolved,
        resolution_notes=comment.resolution_notes,
        created_at=comment.created_at,
    )
