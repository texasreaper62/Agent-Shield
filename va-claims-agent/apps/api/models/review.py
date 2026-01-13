"""
Review models for attorney review workflow.
"""
from sqlalchemy import Column, String, DateTime, ForeignKey, Text, Enum as SQLEnum, Boolean
from sqlalchemy.dialects.postgresql import UUID, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid
import enum

from models.database import Base


class ReviewStatus(str, enum.Enum):
    """Review status."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    APPROVED = "approved"
    REJECTED = "rejected"
    REVISION_REQUESTED = "revision_requested"


class ReviewType(str, enum.Enum):
    """Type of review."""
    CLAIM_ANALYSIS = "claim_analysis"
    EVIDENCE_REVIEW = "evidence_review"
    FORM_REVIEW = "form_review"
    FINAL_REVIEW = "final_review"
    SUBMISSION_REVIEW = "submission_review"


class Review(Base):
    """Attorney/staff review of claim or forms."""

    __tablename__ = "reviews"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    claim_id = Column(UUID(as_uuid=True), ForeignKey("claims.id"), nullable=False)
    reviewer_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)

    # Review Information
    review_type = Column(SQLEnum(ReviewType), nullable=False)
    status = Column(SQLEnum(ReviewStatus), default=ReviewStatus.PENDING)

    # Content being reviewed
    reviewed_item_type = Column(String(50), nullable=True)  # form, evidence, analysis
    reviewed_item_id = Column(UUID(as_uuid=True), nullable=True)

    # Review Details
    summary = Column(Text, nullable=True)  # Overall assessment
    decision_rationale = Column(Text, nullable=True)  # Why approved/rejected

    # Checklist
    checklist = Column(JSON, nullable=True)  # Review checklist items
    checklist_complete = Column(Boolean, default=False)

    # Risk Assessment
    legal_risk_notes = Column(Text, nullable=True)
    ethical_concerns = Column(Text, nullable=True)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    claim = relationship("Claim", back_populates="reviews")
    reviewer = relationship("User", backref="reviews")
    comments = relationship("ReviewComment", back_populates="review", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Review {self.review_type} - {self.status}>"


class ReviewComment(Base):
    """Comment on a review, can request specific changes."""

    __tablename__ = "review_comments"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    review_id = Column(UUID(as_uuid=True), ForeignKey("reviews.id"), nullable=False)
    author_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)

    # Comment Content
    content = Column(Text, nullable=False)
    is_revision_request = Column(Boolean, default=False)
    revision_details = Column(Text, nullable=True)

    # Reference to specific item
    reference_type = Column(String(50), nullable=True)  # field, section, evidence
    reference_id = Column(String(255), nullable=True)

    # Resolution
    is_resolved = Column(Boolean, default=False)
    resolved_by = Column(UUID(as_uuid=True), nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    resolution_notes = Column(Text, nullable=True)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # Relationships
    review = relationship("Review", back_populates="comments")
    author = relationship("User", foreign_keys=[author_id])

    def __repr__(self):
        return f"<ReviewComment {self.id}>"
