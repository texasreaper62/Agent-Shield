"""
Submission model for VA Benefits Intake API.
"""
from sqlalchemy import Column, String, DateTime, ForeignKey, Text, Enum as SQLEnum, Boolean
from sqlalchemy.dialects.postgresql import UUID, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid
import enum

from models.database import Base


class SubmissionStatus(str, enum.Enum):
    """VA submission status."""
    DRAFT = "draft"
    PENDING_APPROVAL = "pending_approval"  # Human approval required
    APPROVED = "approved"
    UPLOADING = "uploading"
    SUBMITTED = "submitted"
    RECEIVED = "received"  # VA acknowledged receipt
    IN_PROCESS = "in_process"  # VA is processing
    SUCCESS = "success"  # Fully processed by VA
    ERROR = "error"
    VBMS = "vbms"  # In Veterans Benefits Management System


class Submission(Base):
    """Record of submission to VA Benefits Intake API."""

    __tablename__ = "submissions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    claim_id = Column(UUID(as_uuid=True), ForeignKey("claims.id"), nullable=False)

    # Status
    status = Column(SQLEnum(SubmissionStatus), default=SubmissionStatus.DRAFT)

    # Human Approval (REQUIRED before submission)
    requires_approval = Column(Boolean, default=True)
    approved_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    approval_notes = Column(Text, nullable=True)

    # VA API Response Data
    va_submission_id = Column(String(100), nullable=True)  # UUID from VA
    va_status = Column(String(50), nullable=True)
    va_status_detail = Column(Text, nullable=True)
    va_location = Column(String(255), nullable=True)  # Document location in VBMS

    # Documents Submitted
    submitted_documents = Column(JSON, nullable=True)  # List of document IDs/paths
    submission_package_path = Column(String(500), nullable=True)  # Combined PDF

    # Tracking
    tracking_number = Column(String(100), nullable=True)
    confirmation_number = Column(String(100), nullable=True)

    # Error Handling
    error_message = Column(Text, nullable=True)
    retry_count = Column(String(10), default="0")
    last_error_at = Column(DateTime(timezone=True), nullable=True)

    # API Response Storage
    api_responses = Column(JSON, nullable=True)  # History of API responses

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    submitted_at = Column(DateTime(timezone=True), nullable=True)
    received_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    claim = relationship("Claim", back_populates="submissions")
    approver = relationship("User", backref="approved_submissions")

    def __repr__(self):
        return f"<Submission {self.id} - {self.status}>"
