"""
Form models for VA forms automation.
"""
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Text, Enum as SQLEnum, Boolean
from sqlalchemy.dialects.postgresql import UUID, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid
import enum

from models.database import Base


class FormStatus(str, enum.Enum):
    """Form generation status."""
    PENDING = "pending"
    GENERATING = "generating"
    GENERATED = "generated"
    REVIEW_PENDING = "review_pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    SUBMITTED = "submitted"


class Form(Base):
    """VA form filled with claim data."""

    __tablename__ = "forms"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    claim_id = Column(UUID(as_uuid=True), ForeignKey("claims.id"), nullable=False)

    # Form Information
    form_number = Column(String(50), nullable=False)  # e.g., "21-526EZ"
    form_name = Column(String(255), nullable=False)
    form_version = Column(String(20), nullable=True)  # VA form version/revision
    va_form_url = Column(String(500), nullable=True)  # Link to official form

    # Status
    status = Column(SQLEnum(FormStatus), default=FormStatus.PENDING)

    # Generated Data
    form_data = Column(JSON, nullable=True)  # Structured form field values
    pdf_storage_path = Column(String(500), nullable=True)  # Generated PDF location

    # Validation
    validation_errors = Column(JSON, nullable=True)  # List of validation issues
    is_complete = Column(Boolean, default=False)
    completeness_score = Column(Integer, nullable=True)  # 0-100

    # Review
    reviewed_by = Column(UUID(as_uuid=True), nullable=True)
    reviewed_at = Column(DateTime(timezone=True), nullable=True)
    review_notes = Column(Text, nullable=True)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    generated_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    claim = relationship("Claim", back_populates="forms")
    fields = relationship("FormField", back_populates="form", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Form {self.form_number}>"


class FormField(Base):
    """Individual form field with value and source citation."""

    __tablename__ = "form_fields"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    form_id = Column(UUID(as_uuid=True), ForeignKey("forms.id"), nullable=False)

    # Field Information
    field_id = Column(String(100), nullable=False)  # PDF field name
    field_label = Column(String(255), nullable=True)
    field_type = Column(String(50), nullable=True)  # text, checkbox, date, etc.
    section = Column(String(100), nullable=True)  # Form section

    # Value
    value = Column(Text, nullable=True)
    is_auto_filled = Column(Boolean, default=False)

    # Citation (required for auto-filled fields)
    source_evidence_id = Column(UUID(as_uuid=True), nullable=True)
    source_document_id = Column(UUID(as_uuid=True), nullable=True)
    source_citation = Column(Text, nullable=True)  # Where the value came from

    # Validation
    is_required = Column(Boolean, default=False)
    is_valid = Column(Boolean, default=True)
    validation_message = Column(String(255), nullable=True)

    # Manual Override
    is_manually_edited = Column(Boolean, default=False)
    original_value = Column(Text, nullable=True)  # Value before manual edit
    edited_by = Column(UUID(as_uuid=True), nullable=True)
    edited_at = Column(DateTime(timezone=True), nullable=True)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # Relationships
    form = relationship("Form", back_populates="fields")

    def __repr__(self):
        return f"<FormField {self.field_id}>"
