"""
Evidence models for tracking evidence and citations.
"""
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Text, Enum as SQLEnum, Float
from sqlalchemy.dialects.postgresql import UUID, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid
import enum

from models.database import Base


class EvidenceType(str, enum.Enum):
    """Type of evidence."""
    IN_SERVICE_EVENT = "in_service_event"  # Proof event happened in service
    CURRENT_DIAGNOSIS = "current_diagnosis"  # Current medical condition
    NEXUS = "nexus"  # Link between service and condition
    CONTINUITY = "continuity"  # Continuous symptoms since service
    LAY_EVIDENCE = "lay_evidence"  # Personal/buddy statements
    EXPERT_OPINION = "expert_opinion"  # Medical expert opinion
    PRESUMPTIVE_QUALIFIER = "presumptive_qualifier"  # Proof of qualifying service


class EvidenceStrength(str, enum.Enum):
    """Strength rating of evidence."""
    STRONG = "strong"
    MODERATE = "moderate"
    WEAK = "weak"
    INSUFFICIENT = "insufficient"


class Evidence(Base):
    """Evidence item linked to a claim."""

    __tablename__ = "evidence"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    claim_id = Column(UUID(as_uuid=True), ForeignKey("claims.id"), nullable=False)
    document_id = Column(UUID(as_uuid=True), ForeignKey("documents.id"), nullable=True)

    # Evidence Classification
    evidence_type = Column(SQLEnum(EvidenceType), nullable=False)
    strength = Column(SQLEnum(EvidenceStrength), nullable=True)

    # Content (always with citations)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)  # Must include source citations
    relevance = Column(Text, nullable=True)  # Why this evidence matters

    # Source Information
    source_type = Column(String(100), nullable=True)  # Medical, Military, Lay, Expert
    source_date = Column(DateTime(timezone=True), nullable=True)
    source_author = Column(String(255), nullable=True)

    # Analysis
    ai_assessment = Column(Text, nullable=True)  # AI analysis with citations
    confidence_score = Column(Float, nullable=True)
    gaps_identified = Column(JSON, nullable=True)  # Missing elements

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # Relationships
    claim = relationship("Claim", back_populates="evidence")
    document = relationship("Document")
    citations = relationship("EvidenceCitation", back_populates="evidence", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Evidence {self.title}>"


class EvidenceCitation(Base):
    """Citation linking evidence to document chunks."""

    __tablename__ = "evidence_citations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    evidence_id = Column(UUID(as_uuid=True), ForeignKey("evidence.id"), nullable=False)
    chunk_id = Column(UUID(as_uuid=True), ForeignKey("document_chunks.id"), nullable=False)

    # Citation Details
    quote = Column(Text, nullable=False)  # Exact quote from source
    page_number = Column(Integer, nullable=True)
    context = Column(Text, nullable=True)  # Surrounding context

    # Relevance
    relevance_explanation = Column(Text, nullable=True)  # Why this citation matters
    confidence = Column(Float, nullable=True)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    evidence = relationship("Evidence", back_populates="citations")
    chunk = relationship("DocumentChunk", back_populates="citations")

    def __repr__(self):
        return f"<EvidenceCitation {self.id}>"
