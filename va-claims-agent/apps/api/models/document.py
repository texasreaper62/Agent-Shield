"""
Document models for uploaded files and processed chunks.
"""
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Text, Enum as SQLEnum, Float
from sqlalchemy.dialects.postgresql import UUID, ARRAY
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from pgvector.sqlalchemy import Vector
import uuid
import enum

from models.database import Base


class DocumentType(str, enum.Enum):
    """Types of documents."""
    DD214 = "dd214"
    SERVICE_TREATMENT_RECORD = "service_treatment_record"
    MEDICAL_RECORD = "medical_record"
    BUDDY_STATEMENT = "buddy_statement"
    NEXUS_LETTER = "nexus_letter"
    DBQ = "dbq"  # Disability Benefits Questionnaire
    VA_DECISION = "va_decision"
    RATING_DECISION = "rating_decision"
    C_FILE = "c_file"
    PERSONNEL_RECORD = "personnel_record"
    DEPLOYMENT_RECORD = "deployment_record"
    AWARD_CITATION = "award_citation"
    OTHER = "other"


class DocumentStatus(str, enum.Enum):
    """Document processing status."""
    UPLOADED = "uploaded"
    PROCESSING = "processing"
    OCR_COMPLETE = "ocr_complete"
    CLASSIFIED = "classified"
    CHUNKED = "chunked"
    EMBEDDED = "embedded"
    FAILED = "failed"


class Document(Base):
    """Uploaded document model."""

    __tablename__ = "documents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    veteran_id = Column(UUID(as_uuid=True), ForeignKey("veterans.id"), nullable=False)

    # File Information
    original_filename = Column(String(255), nullable=False)
    storage_path = Column(String(500), nullable=False)  # Blob storage path
    mime_type = Column(String(100), nullable=True)
    file_size = Column(Integer, nullable=True)
    page_count = Column(Integer, nullable=True)

    # Classification
    document_type = Column(SQLEnum(DocumentType), default=DocumentType.OTHER)
    document_date = Column(DateTime(timezone=True), nullable=True)  # Date of the document itself
    confidence_score = Column(Float, nullable=True)  # Classification confidence

    # Processing
    status = Column(SQLEnum(DocumentStatus), default=DocumentStatus.UPLOADED)
    ocr_text = Column(Text, nullable=True)  # Full extracted text
    ocr_confidence = Column(Float, nullable=True)
    error_message = Column(Text, nullable=True)

    # Metadata
    extracted_metadata = Column(Text, nullable=True)  # JSON string of extracted fields

    # Timestamps
    uploaded_at = Column(DateTime(timezone=True), server_default=func.now())
    processed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # Relationships
    veteran = relationship("Veteran", back_populates="documents")
    chunks = relationship("DocumentChunk", back_populates="document", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Document {self.original_filename}>"


class DocumentChunk(Base):
    """Document chunk with embedding for semantic search."""

    __tablename__ = "document_chunks"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    document_id = Column(UUID(as_uuid=True), ForeignKey("documents.id"), nullable=False)

    # Chunk content
    content = Column(Text, nullable=False)
    chunk_index = Column(Integer, nullable=False)  # Order in document
    page_number = Column(Integer, nullable=True)
    start_char = Column(Integer, nullable=True)
    end_char = Column(Integer, nullable=True)

    # Embedding (1536 dimensions for OpenAI ada-002 compatible, adjust as needed)
    embedding = Column(Vector(1536), nullable=True)

    # Metadata
    token_count = Column(Integer, nullable=True)
    keywords = Column(ARRAY(String), nullable=True)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    document = relationship("Document", back_populates="chunks")
    citations = relationship("EvidenceCitation", back_populates="chunk")

    def __repr__(self):
        return f"<DocumentChunk {self.document_id}:{self.chunk_index}>"
