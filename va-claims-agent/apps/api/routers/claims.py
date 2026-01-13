"""
Claims router for managing VA disability claims.
"""
from typing import List, Optional
from uuid import UUID
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from pydantic import BaseModel
import structlog

from models.database import get_db
from models.user import User, UserRole
from models.veteran import Veteran
from models.claim import Claim, ClaimCondition, ClaimStatus, ClaimType, ConnectionType
from routers.auth import get_current_active_user, require_role
from services.queue import send_to_analysis_queue

router = APIRouter()
logger = structlog.get_logger()


class ConditionCreate(BaseModel):
    condition_name: str
    icd_code: Optional[str] = None
    connection_type: Optional[ConnectionType] = None
    onset_date: Optional[datetime] = None
    in_service_event: Optional[str] = None
    current_symptoms: Optional[str] = None


class ClaimCreate(BaseModel):
    claim_type: ClaimType
    conditions: List[ConditionCreate]
    itf_date: Optional[datetime] = None
    itf_confirmation: Optional[str] = None


class ConditionResponse(BaseModel):
    id: str
    condition_name: str
    icd_code: Optional[str]
    diagnostic_code: Optional[str]
    connection_type: Optional[str]
    current_rating: Optional[int]
    estimated_rating: Optional[int]
    strength_score: Optional[float]
    cfr_reference: Optional[str]

    class Config:
        from_attributes = True


class ClaimResponse(BaseModel):
    id: str
    veteran_id: str
    claim_type: str
    status: str
    itf_date: Optional[datetime]
    summary: Optional[str]
    strength_assessment: Optional[str]
    confidence_score: Optional[float]
    is_initial_claim: bool
    conditions: List[ConditionResponse]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ClaimAnalysisResponse(BaseModel):
    claim_id: str
    analysis: dict
    conditions_analysis: List[dict]
    overall_strength: float
    recommended_actions: List[str]
    missing_evidence: List[str]


@router.post("/", response_model=ClaimResponse, status_code=201)
async def create_claim(
    claim_data: ClaimCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Create a new disability claim."""
    # Get veteran profile
    result = await db.execute(
        select(Veteran).where(Veteran.user_id == current_user.id)
    )
    veteran = result.scalar_one_or_none()
    if not veteran:
        raise HTTPException(status_code=400, detail="Veteran profile required")

    # Create claim
    claim = Claim(
        veteran_id=veteran.id,
        claim_type=claim_data.claim_type,
        status=ClaimStatus.DRAFT,
        itf_date=claim_data.itf_date,
        itf_confirmation=claim_data.itf_confirmation,
        is_initial_claim=claim_data.claim_type == ClaimType.INITIAL,
    )
    db.add(claim)
    await db.flush()

    # Add conditions
    for cond_data in claim_data.conditions:
        condition = ClaimCondition(
            claim_id=claim.id,
            condition_name=cond_data.condition_name,
            icd_code=cond_data.icd_code,
            connection_type=cond_data.connection_type,
            onset_date=cond_data.onset_date,
            in_service_event=cond_data.in_service_event,
            current_symptoms=cond_data.current_symptoms,
        )
        db.add(condition)

    await db.commit()
    await db.refresh(claim)

    # Load conditions
    result = await db.execute(
        select(Claim)
        .options(selectinload(Claim.conditions))
        .where(Claim.id == claim.id)
    )
    claim = result.scalar_one()

    logger.info("Claim created", claim_id=str(claim.id))

    return ClaimResponse(
        id=str(claim.id),
        veteran_id=str(claim.veteran_id),
        claim_type=claim.claim_type.value,
        status=claim.status.value,
        itf_date=claim.itf_date,
        summary=claim.summary,
        strength_assessment=claim.strength_assessment,
        confidence_score=claim.confidence_score,
        is_initial_claim=claim.is_initial_claim,
        conditions=[
            ConditionResponse(
                id=str(c.id),
                condition_name=c.condition_name,
                icd_code=c.icd_code,
                diagnostic_code=c.diagnostic_code,
                connection_type=c.connection_type.value if c.connection_type else None,
                current_rating=c.current_rating,
                estimated_rating=c.estimated_rating,
                strength_score=c.strength_score,
                cfr_reference=c.cfr_reference,
            )
            for c in claim.conditions
        ],
        created_at=claim.created_at,
        updated_at=claim.updated_at,
    )


@router.get("/", response_model=List[ClaimResponse])
async def list_claims(
    veteran_id: Optional[UUID] = None,
    status: Optional[ClaimStatus] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """List claims."""
    query = select(Claim).options(selectinload(Claim.conditions))

    if current_user.role == UserRole.VETERAN:
        result = await db.execute(
            select(Veteran).where(Veteran.user_id == current_user.id)
        )
        veteran = result.scalar_one_or_none()
        if not veteran:
            return []
        query = query.where(Claim.veteran_id == veteran.id)
    elif veteran_id:
        query = query.where(Claim.veteran_id == veteran_id)

    if status:
        query = query.where(Claim.status == status)

    result = await db.execute(query.order_by(Claim.created_at.desc()))
    claims = result.scalars().all()

    return [
        ClaimResponse(
            id=str(claim.id),
            veteran_id=str(claim.veteran_id),
            claim_type=claim.claim_type.value,
            status=claim.status.value,
            itf_date=claim.itf_date,
            summary=claim.summary,
            strength_assessment=claim.strength_assessment,
            confidence_score=claim.confidence_score,
            is_initial_claim=claim.is_initial_claim,
            conditions=[
                ConditionResponse(
                    id=str(c.id),
                    condition_name=c.condition_name,
                    icd_code=c.icd_code,
                    diagnostic_code=c.diagnostic_code,
                    connection_type=c.connection_type.value if c.connection_type else None,
                    current_rating=c.current_rating,
                    estimated_rating=c.estimated_rating,
                    strength_score=c.strength_score,
                    cfr_reference=c.cfr_reference,
                )
                for c in claim.conditions
            ],
            created_at=claim.created_at,
            updated_at=claim.updated_at,
        )
        for claim in claims
    ]


@router.get("/{claim_id}", response_model=ClaimResponse)
async def get_claim(
    claim_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get claim details."""
    result = await db.execute(
        select(Claim)
        .options(selectinload(Claim.conditions))
        .where(Claim.id == claim_id)
    )
    claim = result.scalar_one_or_none()
    if not claim:
        raise HTTPException(status_code=404, detail="Claim not found")

    # Check access
    if current_user.role == UserRole.VETERAN:
        vet_result = await db.execute(
            select(Veteran).where(Veteran.user_id == current_user.id)
        )
        veteran = vet_result.scalar_one_or_none()
        if not veteran or claim.veteran_id != veteran.id:
            raise HTTPException(status_code=403, detail="Access denied")

    return ClaimResponse(
        id=str(claim.id),
        veteran_id=str(claim.veteran_id),
        claim_type=claim.claim_type.value,
        status=claim.status.value,
        itf_date=claim.itf_date,
        summary=claim.summary,
        strength_assessment=claim.strength_assessment,
        confidence_score=claim.confidence_score,
        is_initial_claim=claim.is_initial_claim,
        conditions=[
            ConditionResponse(
                id=str(c.id),
                condition_name=c.condition_name,
                icd_code=c.icd_code,
                diagnostic_code=c.diagnostic_code,
                connection_type=c.connection_type.value if c.connection_type else None,
                current_rating=c.current_rating,
                estimated_rating=c.estimated_rating,
                strength_score=c.strength_score,
                cfr_reference=c.cfr_reference,
            )
            for c in claim.conditions
        ],
        created_at=claim.created_at,
        updated_at=claim.updated_at,
    )


@router.post("/{claim_id}/analyze", response_model=ClaimAnalysisResponse)
async def analyze_claim(
    claim_id: UUID,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Trigger AI analysis of the claim."""
    result = await db.execute(
        select(Claim)
        .options(selectinload(Claim.conditions))
        .where(Claim.id == claim_id)
    )
    claim = result.scalar_one_or_none()
    if not claim:
        raise HTTPException(status_code=404, detail="Claim not found")

    # Update status
    claim.status = ClaimStatus.ANALYSIS_PENDING
    await db.commit()

    # Queue for analysis
    await send_to_analysis_queue({
        "claim_id": str(claim.id),
        "veteran_id": str(claim.veteran_id),
        "conditions": [c.condition_name for c in claim.conditions],
    })

    logger.info("Claim analysis queued", claim_id=str(claim.id))

    return ClaimAnalysisResponse(
        claim_id=str(claim.id),
        analysis={"status": "pending", "message": "Analysis queued"},
        conditions_analysis=[],
        overall_strength=0.0,
        recommended_actions=["Analysis in progress"],
        missing_evidence=[],
    )


@router.put("/{claim_id}/status")
async def update_claim_status(
    claim_id: UUID,
    new_status: ClaimStatus,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ATTORNEY, UserRole.ADMIN))
):
    """Update claim status (attorneys/admin only)."""
    result = await db.execute(
        select(Claim).where(Claim.id == claim_id)
    )
    claim = result.scalar_one_or_none()
    if not claim:
        raise HTTPException(status_code=404, detail="Claim not found")

    claim.status = new_status
    await db.commit()

    logger.info("Claim status updated", claim_id=str(claim.id), status=new_status.value)
    return {"message": f"Status updated to {new_status.value}"}


@router.post("/{claim_id}/conditions", response_model=ConditionResponse)
async def add_condition(
    claim_id: UUID,
    condition_data: ConditionCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Add a condition to an existing claim."""
    result = await db.execute(
        select(Claim).where(Claim.id == claim_id)
    )
    claim = result.scalar_one_or_none()
    if not claim:
        raise HTTPException(status_code=404, detail="Claim not found")

    if claim.status not in [ClaimStatus.DRAFT, ClaimStatus.EVIDENCE_GATHERING]:
        raise HTTPException(status_code=400, detail="Cannot add conditions to this claim")

    condition = ClaimCondition(
        claim_id=claim.id,
        condition_name=condition_data.condition_name,
        icd_code=condition_data.icd_code,
        connection_type=condition_data.connection_type,
        onset_date=condition_data.onset_date,
        in_service_event=condition_data.in_service_event,
        current_symptoms=condition_data.current_symptoms,
    )
    db.add(condition)
    await db.commit()
    await db.refresh(condition)

    logger.info("Condition added", claim_id=str(claim.id), condition=condition_data.condition_name)

    return ConditionResponse(
        id=str(condition.id),
        condition_name=condition.condition_name,
        icd_code=condition.icd_code,
        diagnostic_code=condition.diagnostic_code,
        connection_type=condition.connection_type.value if condition.connection_type else None,
        current_rating=condition.current_rating,
        estimated_rating=condition.estimated_rating,
        strength_score=condition.strength_score,
        cfr_reference=condition.cfr_reference,
    )
