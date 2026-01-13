"""
Veteran profile model.
"""
from sqlalchemy import Column, String, Date, DateTime, ForeignKey, Text, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid

from models.database import Base


class Veteran(Base):
    """Veteran profile containing service and claim information."""

    __tablename__ = "veterans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)

    # Personal Information
    first_name = Column(String(100), nullable=False)
    middle_name = Column(String(100), nullable=True)
    last_name = Column(String(100), nullable=False)
    suffix = Column(String(20), nullable=True)
    date_of_birth = Column(Date, nullable=True)
    ssn_last_four = Column(String(4), nullable=True)  # Only store last 4 for verification

    # Contact Information
    email = Column(String(255), nullable=True)
    phone = Column(String(20), nullable=True)
    address_line1 = Column(String(255), nullable=True)
    address_line2 = Column(String(255), nullable=True)
    city = Column(String(100), nullable=True)
    state = Column(String(2), nullable=True)
    zip_code = Column(String(10), nullable=True)
    country = Column(String(100), default="USA")

    # Service Information
    branch_of_service = Column(String(50), nullable=True)  # Army, Navy, Air Force, etc.
    service_number = Column(String(50), nullable=True)
    rank_at_discharge = Column(String(50), nullable=True)
    service_start_date = Column(Date, nullable=True)
    service_end_date = Column(Date, nullable=True)
    discharge_type = Column(String(50), nullable=True)  # Honorable, General, etc.
    service_periods = Column(JSON, nullable=True)  # Array of service periods for multiple tours

    # VA Information
    va_file_number = Column(String(20), nullable=True)
    current_rating = Column(String(10), nullable=True)
    existing_conditions = Column(JSON, nullable=True)  # Already service-connected conditions

    # Notes
    notes = Column(Text, nullable=True)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # Relationships
    user = relationship("User", backref="veteran_profile")
    documents = relationship("Document", back_populates="veteran", cascade="all, delete-orphan")
    claims = relationship("Claim", back_populates="veteran", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Veteran {self.first_name} {self.last_name}>"
