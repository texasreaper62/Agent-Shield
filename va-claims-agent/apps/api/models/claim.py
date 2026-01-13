"""
Claim models for disability claims and service connections.
"""
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Text, Enum as SQLEnum, Float, Boolean
from sqlalchemy.dialects.postgresql import UUID, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid
import enum

from models.database import Base


class ClaimStatus(str, enum.Enum):
    """Status of the claim."""
    DRAFT = "draft"
    EVIDENCE_GATHERING = "evidence_gathering"
    ANALYSIS_PENDING = "analysis_pending"
    ANALYSIS_COMPLETE = "analysis_complete"
    REVIEW_PENDING = "review_pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    SUBMITTED = "submitted"
    VA_PENDING = "va_pending"
    VA_DECIDED = "va_decided"


class ClaimType(str, enum.Enum):
    """Type of VA claim."""
    INITIAL = "initial"  # First time filing for this condition
    INCREASE = "increase"  # Requesting higher rating
    SECONDARY = "secondary"  # Condition caused by service-connected condition
    SUPPLEMENTAL = "supplemental"  # New evidence for previously denied
    APPEAL = "appeal"


class ConnectionType(str, enum.Enum):
    """Type of service connection."""
    DIRECT = "direct"  # Condition occurred during service
    SECONDARY = "secondary"  # Caused by another service-connected condition
    PRESUMPTIVE = "presumptive"  # Presumed due to service location/era
    AGGRAVATION = "aggravation"  # Pre-existing condition worsened by service


class Claim(Base):
    """VA disability claim."""

    __tablename__ = "claims"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    veteran_id = Column(UUID(as_uuid=True), ForeignKey("veterans.id"), nullable=False)

    # Claim Information
    claim_type = Column(SQLEnum(ClaimType), nullable=False)
    status = Column(SQLEnum(ClaimStatus), default=ClaimStatus.DRAFT)

    # Intent to File (ITF)
    itf_date = Column(DateTime(timezone=True), nullable=True)
    itf_confirmation = Column(String(50), nullable=True)

    # Claim Summary (AI-generated, requires citations)
    summary = Column(Text, nullable=True)
    strength_assessment = Column(Text, nullable=True)
    recommended_evidence = Column(Text, nullable=True)

    # Analysis Results
    ai_analysis = Column(JSON, nullable=True)  # Full AI analysis with citations
    confidence_score = Column(Float, nullable=True)

    # Fee Information (38 CFR §14.636 compliance)
    is_initial_claim = Column(Boolean, default=True)  # Block fees if True
    fee_agreement_id = Column(String(100), nullable=True)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    submitted_at = Column(DateTime(timezone=True), nullable=True)
    decided_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    veteran = relationship("Veteran", back_populates="claims")
    conditions = relationship("ClaimCondition", back_populates="claim", cascade="all, delete-orphan")
    evidence = relationship("Evidence", back_populates="claim", cascade="all, delete-orphan")
    forms = relationship("Form", back_populates="claim", cascade="all, delete-orphan")
    reviews = relationship("Review", back_populates="claim", cascade="all, delete-orphan")
    submissions = relationship("Submission", back_populates="claim", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Claim {self.id} - {self.status}>"


class ClaimCondition(Base):
    """Individual condition within a claim."""

    __tablename__ = "claim_conditions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    claim_id = Column(UUID(as_uuid=True), ForeignKey("claims.id"), nullable=False)

    # Condition Information
    condition_name = Column(String(255), nullable=False)
    icd_code = Column(String(20), nullable=True)  # ICD-10 code
    diagnostic_code = Column(String(20), nullable=True)  # VA diagnostic code (38 CFR Part 4)

    # Service Connection
    connection_type = Column(SQLEnum(ConnectionType), nullable=True)
    connected_condition_id = Column(UUID(as_uuid=True), nullable=True)  # For secondary claims

    # Rating Information
    current_rating = Column(Integer, nullable=True)
    requested_rating = Column(Integer, nullable=True)
    estimated_rating = Column(Integer, nullable=True)  # AI estimate

    # Analysis
    onset_date = Column(DateTime(timezone=True), nullable=True)
    in_service_event = Column(Text, nullable=True)  # Description with citations
    current_symptoms = Column(Text, nullable=True)
    nexus_statement = Column(Text, nullable=True)  # Link between service and condition
    cfr_reference = Column(String(100), nullable=True)  # e.g., "38 CFR 4.71a DC 5260"

    # AI Analysis (with required citations)
    ai_rationale = Column(Text, nullable=True)
    strength_score = Column(Float, nullable=True)  # 0-1 likelihood of approval
    missing_evidence = Column(JSON, nullable=True)  # List of needed evidence

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # Relationships
    claim = relationship("Claim", back_populates="conditions")
    service_connections = relationship("ServiceConnection", back_populates="condition", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<ClaimCondition {self.condition_name}>"


class ServiceConnection(Base):
    """Service connection theory and evidence mapping."""

    __tablename__ = "service_connections"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    condition_id = Column(UUID(as_uuid=True), ForeignKey("claim_conditions.id"), nullable=False)

    # Connection Theory
    theory_type = Column(SQLEnum(ConnectionType), nullable=False)
    theory_description = Column(Text, nullable=False)

    # Evidence Mapping (all must have citations)
    in_service_evidence = Column(JSON, nullable=True)  # List of evidence IDs + citations
    current_diagnosis_evidence = Column(JSON, nullable=True)
    nexus_evidence = Column(JSON, nullable=True)

    # For presumptive claims
    presumptive_basis = Column(String(255), nullable=True)  # e.g., "Gulf War", "Agent Orange"
    qualifying_service = Column(Text, nullable=True)  # Service that qualifies for presumption

    # For secondary claims
    primary_condition = Column(String(255), nullable=True)
    medical_relationship = Column(Text, nullable=True)

    # Analysis
    viability_score = Column(Float, nullable=True)  # 0-1 score
    strengths = Column(JSON, nullable=True)  # List of strong points
    weaknesses = Column(JSON, nullable=True)  # List of weaknesses
    recommendations = Column(JSON, nullable=True)  # List of recommendations

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # Relationships
    condition = relationship("ClaimCondition", back_populates="service_connections")

    def __repr__(self):
        return f"<ServiceConnection {self.theory_type} for {self.condition_id}>"
