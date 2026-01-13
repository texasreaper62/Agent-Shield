"""
Knowledge base models for 38 CFR and VA rating criteria.
"""
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Text, Float, Boolean
from sqlalchemy.dialects.postgresql import UUID, JSON, ARRAY
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from pgvector.sqlalchemy import Vector
import uuid

from models.database import Base


class KnowledgeArticle(Base):
    """General knowledge article for VA claims guidance."""

    __tablename__ = "knowledge_articles"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Article Information
    title = Column(String(255), nullable=False)
    slug = Column(String(255), unique=True, nullable=False)
    category = Column(String(100), nullable=False)  # claims, evidence, forms, etc.
    subcategory = Column(String(100), nullable=True)

    # Content
    content = Column(Text, nullable=False)
    summary = Column(Text, nullable=True)
    keywords = Column(ARRAY(String), nullable=True)

    # Embedding for semantic search
    embedding = Column(Vector(1536), nullable=True)

    # References
    cfr_references = Column(ARRAY(String), nullable=True)  # Related CFR sections
    related_articles = Column(ARRAY(UUID(as_uuid=True)), nullable=True)

    # Metadata
    source = Column(String(255), nullable=True)  # Where this info came from
    source_url = Column(String(500), nullable=True)
    last_verified = Column(DateTime(timezone=True), nullable=True)
    is_published = Column(Boolean, default=True)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    def __repr__(self):
        return f"<KnowledgeArticle {self.title}>"


class CFRSection(Base):
    """38 CFR section for reference."""

    __tablename__ = "cfr_sections"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # CFR Reference
    title = Column(Integer, default=38)  # Title 38 for VA
    part = Column(Integer, nullable=False)  # e.g., 4 for Rating Schedule
    subpart = Column(String(10), nullable=True)  # e.g., "A"
    section = Column(String(20), nullable=False)  # e.g., "4.71a"
    diagnostic_code = Column(String(20), nullable=True)  # e.g., "5260"

    # Content
    section_title = Column(String(500), nullable=False)
    full_text = Column(Text, nullable=False)
    summary = Column(Text, nullable=True)  # Plain language summary

    # Embedding for semantic search
    embedding = Column(Vector(1536), nullable=True)

    # Structured Data
    rating_percentages = Column(JSON, nullable=True)  # Available rating levels
    evaluation_criteria = Column(JSON, nullable=True)  # Structured criteria
    notes = Column(Text, nullable=True)  # Additional notes/guidance

    # Body System (for Part 4)
    body_system = Column(String(100), nullable=True)  # Musculoskeletal, Mental, etc.
    condition_category = Column(String(100), nullable=True)

    # Effective Dates
    effective_date = Column(DateTime(timezone=True), nullable=True)
    amendment_history = Column(JSON, nullable=True)  # History of changes

    # Metadata
    source_url = Column(String(500), nullable=True)
    ecfr_url = Column(String(500), nullable=True)  # Link to eCFR
    last_updated = Column(DateTime(timezone=True), nullable=True)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # Relationships
    rating_criteria = relationship("RatingCriteria", back_populates="cfr_section", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<CFRSection 38 CFR {self.section}>"


class RatingCriteria(Base):
    """Detailed rating criteria for a specific condition/DC."""

    __tablename__ = "rating_criteria"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cfr_section_id = Column(UUID(as_uuid=True), ForeignKey("cfr_sections.id"), nullable=False)

    # Rating Information
    diagnostic_code = Column(String(20), nullable=False)
    condition_name = Column(String(255), nullable=False)
    rating_percentage = Column(Integer, nullable=False)  # 0, 10, 20, 30, etc.

    # Criteria
    criteria_description = Column(Text, nullable=False)  # What's required for this rating
    objective_criteria = Column(JSON, nullable=True)  # Measurable criteria (ROM, etc.)
    subjective_criteria = Column(JSON, nullable=True)  # Functional impairment

    # Embedding for semantic search
    embedding = Column(Vector(1536), nullable=True)

    # Evidence Requirements
    required_evidence = Column(JSON, nullable=True)  # What evidence is needed
    supporting_evidence = Column(JSON, nullable=True)  # Helpful but not required

    # Related Conditions
    analogous_codes = Column(ARRAY(String), nullable=True)  # Similar DCs for analogy
    combined_ratings = Column(JSON, nullable=True)  # If multiple ratings apply

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # Relationships
    cfr_section = relationship("CFRSection", back_populates="rating_criteria")

    def __repr__(self):
        return f"<RatingCriteria DC {self.diagnostic_code} @ {self.rating_percentage}%>"
