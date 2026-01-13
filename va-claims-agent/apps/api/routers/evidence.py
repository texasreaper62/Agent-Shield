"""
Evidence router for managing claim evidence and citations.
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
from models.veteran import Veteran
from models.claim import Claim
from models.evidence import Evidence, EvidenceCitation, EvidenceType, EvidenceStrength
from routers.auth import get_current_active_user

router = APIRouter()
logger = structlog.get_logger()


class CitationCreate(BaseModel):
    chunk_id: UUID
    quote: str
    page_number: Optional[int] = None
    context: Optional[str] = None
    relevance_explanation: Optional[str] = None


class EvidenceCreate(BaseModel):
    claim_id: UUID
    document_id: Optional[UUID] = None
    evidence_type: EvidenceType
    title: str
    description: str  # Must include citations
    relevance: Optional[str] = None
    source_type: Optional[str] = None
    source_date: Optional[datetime] = None
    source_author: Optional[str] = None
    citations: List[CitationCreate] = []


class CitationResponse(BaseModel):
    id: str
    chunk_id: str
    quote: str
    page_number: Optional[int]
    context: Optional[str]
    relevance_explanation: Optional[str]

    class Config:
        from_attributes = True


class EvidenceResponse(BaseModel):
    id: str
    claim_id: str
    document_id: Optional[str]
    evidence_type: str
    strength: Optional[str]
    title: str
    description: str
    relevance: Optional[str]
    source_type: Optional[str]
    source_date: Optional[datetime]
    ai_assessment: Optional[str]
    confidence_score: Optional[float]
    citations: List[CitationResponse]
    created_at: datetime

    class Config:
        from_attributes = True


@router.post("/", response_model=EvidenceResponse, status_code=201)
async def create_evidence(
    evidence_data: EvidenceCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Create evidence with required citations."""
    # Validate claim access
    result = await db.execute(
        select(Claim).where(Claim.id == evidence_data.claim_id)
    )
    claim = result.scalar_one_or_none()
    if not claim:
        raise HTTPException(status_code=404, detail="Claim not found")

    # Check access for veterans
    if current_user.role == UserRole.VETERAN:
        vet_result = await db.execute(
            select(Veteran).where(Veteran.user_id == current_user.id)
        )
        veteran = vet_result.scalar_one_or_none()
        if not veteran or claim.veteran_id != veteran.id:
            raise HTTPException(status_code=403, detail="Access denied")

    # CRITICAL: Require at least one citation for AI-generated evidence
    # (Can be relaxed for lay evidence)
    if evidence_data.evidence_type not in [EvidenceType.LAY_EVIDENCE] and not evidence_data.citations:
        raise HTTPException(
            status_code=400,
            detail="Evidence must include at least one citation to source documents"
        )

    # Create evidence
    evidence = Evidence(
        claim_id=evidence_data.claim_id,
        document_id=evidence_data.document_id,
        evidence_type=evidence_data.evidence_type,
        title=evidence_data.title,
        description=evidence_data.description,
        relevance=evidence_data.relevance,
        source_type=evidence_data.source_type,
        source_date=evidence_data.source_date,
        source_author=evidence_data.source_author,
    )
    db.add(evidence)
    await db.flush()

    # Add citations
    for cit_data in evidence_data.citations:
        citation = EvidenceCitation(
            evidence_id=evidence.id,
            chunk_id=cit_data.chunk_id,
            quote=cit_data.quote,
            page_number=cit_data.page_number,
            context=cit_data.context,
            relevance_explanation=cit_data.relevance_explanation,
        )
        db.add(citation)

    await db.commit()
    await db.refresh(evidence)

    # Load citations
    result = await db.execute(
        select(Evidence)
        .options(selectinload(Evidence.citations))
        .where(Evidence.id == evidence.id)
    )
    evidence = result.scalar_one()

    logger.info("Evidence created", evidence_id=str(evidence.id), citations=len(evidence.citations))

    return EvidenceResponse(
        id=str(evidence.id),
        claim_id=str(evidence.claim_id),
        document_id=str(evidence.document_id) if evidence.document_id else None,
        evidence_type=evidence.evidence_type.value,
        strength=evidence.strength.value if evidence.strength else None,
        title=evidence.title,
        description=evidence.description,
        relevance=evidence.relevance,
        source_type=evidence.source_type,
        source_date=evidence.source_date,
        ai_assessment=evidence.ai_assessment,
        confidence_score=evidence.confidence_score,
        citations=[
            CitationResponse(
                id=str(c.id),
                chunk_id=str(c.chunk_id),
                quote=c.quote,
                page_number=c.page_number,
                context=c.context,
                relevance_explanation=c.relevance_explanation,
            )
            for c in evidence.citations
        ],
        created_at=evidence.created_at,
    )


@router.get("/claim/{claim_id}", response_model=List[EvidenceResponse])
async def list_claim_evidence(
    claim_id: UUID,
    evidence_type: Optional[EvidenceType] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """List all evidence for a claim."""
    # Validate claim access
    result = await db.execute(
        select(Claim).where(Claim.id == claim_id)
    )
    claim = result.scalar_one_or_none()
    if not claim:
        raise HTTPException(status_code=404, detail="Claim not found")

    query = select(Evidence).options(selectinload(Evidence.citations)).where(Evidence.claim_id == claim_id)

    if evidence_type:
        query = query.where(Evidence.evidence_type == evidence_type)

    result = await db.execute(query.order_by(Evidence.created_at.desc()))
    evidence_list = result.scalars().all()

    return [
        EvidenceResponse(
            id=str(e.id),
            claim_id=str(e.claim_id),
            document_id=str(e.document_id) if e.document_id else None,
            evidence_type=e.evidence_type.value,
            strength=e.strength.value if e.strength else None,
            title=e.title,
            description=e.description,
            relevance=e.relevance,
            source_type=e.source_type,
            source_date=e.source_date,
            ai_assessment=e.ai_assessment,
            confidence_score=e.confidence_score,
            citations=[
                CitationResponse(
                    id=str(c.id),
                    chunk_id=str(c.chunk_id),
                    quote=c.quote,
                    page_number=c.page_number,
                    context=c.context,
                    relevance_explanation=c.relevance_explanation,
                )
                for c in e.citations
            ],
            created_at=e.created_at,
        )
        for e in evidence_list
    ]


@router.get("/{evidence_id}", response_model=EvidenceResponse)
async def get_evidence(
    evidence_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get evidence details with citations."""
    result = await db.execute(
        select(Evidence)
        .options(selectinload(Evidence.citations))
        .where(Evidence.id == evidence_id)
    )
    evidence = result.scalar_one_or_none()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")

    return EvidenceResponse(
        id=str(evidence.id),
        claim_id=str(evidence.claim_id),
        document_id=str(evidence.document_id) if evidence.document_id else None,
        evidence_type=evidence.evidence_type.value,
        strength=evidence.strength.value if evidence.strength else None,
        title=evidence.title,
        description=evidence.description,
        relevance=evidence.relevance,
        source_type=evidence.source_type,
        source_date=evidence.source_date,
        ai_assessment=evidence.ai_assessment,
        confidence_score=evidence.confidence_score,
        citations=[
            CitationResponse(
                id=str(c.id),
                chunk_id=str(c.chunk_id),
                quote=c.quote,
                page_number=c.page_number,
                context=c.context,
                relevance_explanation=c.relevance_explanation,
            )
            for c in evidence.citations
        ],
        created_at=evidence.created_at,
    )


@router.put("/{evidence_id}/strength")
async def update_evidence_strength(
    evidence_id: UUID,
    strength: EvidenceStrength,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Update evidence strength assessment."""
    result = await db.execute(
        select(Evidence).where(Evidence.id == evidence_id)
    )
    evidence = result.scalar_one_or_none()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")

    evidence.strength = strength
    await db.commit()

    logger.info("Evidence strength updated", evidence_id=str(evidence.id), strength=strength.value)
    return {"message": f"Strength updated to {strength.value}"}


@router.post("/{evidence_id}/citations", response_model=CitationResponse)
async def add_citation(
    evidence_id: UUID,
    citation_data: CitationCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Add a citation to existing evidence."""
    result = await db.execute(
        select(Evidence).where(Evidence.id == evidence_id)
    )
    evidence = result.scalar_one_or_none()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")

    citation = EvidenceCitation(
        evidence_id=evidence.id,
        chunk_id=citation_data.chunk_id,
        quote=citation_data.quote,
        page_number=citation_data.page_number,
        context=citation_data.context,
        relevance_explanation=citation_data.relevance_explanation,
    )
    db.add(citation)
    await db.commit()
    await db.refresh(citation)

    logger.info("Citation added", evidence_id=str(evidence.id), citation_id=str(citation.id))

    return CitationResponse(
        id=str(citation.id),
        chunk_id=str(citation.chunk_id),
        quote=citation.quote,
        page_number=citation.page_number,
        context=citation.context,
        relevance_explanation=citation.relevance_explanation,
    )
