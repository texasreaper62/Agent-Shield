"""
Veterans router for veteran profile management.
"""
from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from datetime import date
import structlog

from models.database import get_db
from models.user import User, UserRole
from models.veteran import Veteran
from routers.auth import get_current_active_user, require_role

router = APIRouter()
logger = structlog.get_logger()


class VeteranCreate(BaseModel):
    first_name: str
    middle_name: Optional[str] = None
    last_name: str
    suffix: Optional[str] = None
    date_of_birth: Optional[date] = None
    ssn_last_four: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    address_line1: Optional[str] = None
    address_line2: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    zip_code: Optional[str] = None
    branch_of_service: Optional[str] = None
    service_start_date: Optional[date] = None
    service_end_date: Optional[date] = None
    discharge_type: Optional[str] = None
    va_file_number: Optional[str] = None
    current_rating: Optional[str] = None


class VeteranUpdate(BaseModel):
    first_name: Optional[str] = None
    middle_name: Optional[str] = None
    last_name: Optional[str] = None
    suffix: Optional[str] = None
    date_of_birth: Optional[date] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    address_line1: Optional[str] = None
    address_line2: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    zip_code: Optional[str] = None
    branch_of_service: Optional[str] = None
    service_start_date: Optional[date] = None
    service_end_date: Optional[date] = None
    discharge_type: Optional[str] = None
    va_file_number: Optional[str] = None
    current_rating: Optional[str] = None
    notes: Optional[str] = None


class VeteranResponse(BaseModel):
    id: str
    user_id: str
    first_name: str
    middle_name: Optional[str]
    last_name: str
    suffix: Optional[str]
    date_of_birth: Optional[date]
    email: Optional[str]
    phone: Optional[str]
    address_line1: Optional[str]
    address_line2: Optional[str]
    city: Optional[str]
    state: Optional[str]
    zip_code: Optional[str]
    branch_of_service: Optional[str]
    service_start_date: Optional[date]
    service_end_date: Optional[date]
    discharge_type: Optional[str]
    va_file_number: Optional[str]
    current_rating: Optional[str]

    class Config:
        from_attributes = True


@router.post("/", response_model=VeteranResponse, status_code=status.HTTP_201_CREATED)
async def create_veteran(
    veteran_data: VeteranCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Create a veteran profile for the current user."""
    # Check if user already has a veteran profile
    result = await db.execute(
        select(Veteran).where(Veteran.user_id == current_user.id)
    )
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Veteran profile already exists")

    veteran = Veteran(
        user_id=current_user.id,
        **veteran_data.model_dump()
    )
    db.add(veteran)
    await db.commit()
    await db.refresh(veteran)

    logger.info("Veteran profile created", veteran_id=str(veteran.id))
    return VeteranResponse(
        id=str(veteran.id),
        user_id=str(veteran.user_id),
        **{k: getattr(veteran, k) for k in VeteranCreate.model_fields.keys()}
    )


@router.get("/me", response_model=VeteranResponse)
async def get_my_veteran_profile(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get the current user's veteran profile."""
    result = await db.execute(
        select(Veteran).where(Veteran.user_id == current_user.id)
    )
    veteran = result.scalar_one_or_none()
    if not veteran:
        raise HTTPException(status_code=404, detail="Veteran profile not found")

    return VeteranResponse(
        id=str(veteran.id),
        user_id=str(veteran.user_id),
        first_name=veteran.first_name,
        middle_name=veteran.middle_name,
        last_name=veteran.last_name,
        suffix=veteran.suffix,
        date_of_birth=veteran.date_of_birth,
        email=veteran.email,
        phone=veteran.phone,
        address_line1=veteran.address_line1,
        address_line2=veteran.address_line2,
        city=veteran.city,
        state=veteran.state,
        zip_code=veteran.zip_code,
        branch_of_service=veteran.branch_of_service,
        service_start_date=veteran.service_start_date,
        service_end_date=veteran.service_end_date,
        discharge_type=veteran.discharge_type,
        va_file_number=veteran.va_file_number,
        current_rating=veteran.current_rating,
    )


@router.put("/me", response_model=VeteranResponse)
async def update_my_veteran_profile(
    update_data: VeteranUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Update the current user's veteran profile."""
    result = await db.execute(
        select(Veteran).where(Veteran.user_id == current_user.id)
    )
    veteran = result.scalar_one_or_none()
    if not veteran:
        raise HTTPException(status_code=404, detail="Veteran profile not found")

    # Update fields
    for field, value in update_data.model_dump(exclude_unset=True).items():
        setattr(veteran, field, value)

    await db.commit()
    await db.refresh(veteran)

    logger.info("Veteran profile updated", veteran_id=str(veteran.id))
    return VeteranResponse(
        id=str(veteran.id),
        user_id=str(veteran.user_id),
        first_name=veteran.first_name,
        middle_name=veteran.middle_name,
        last_name=veteran.last_name,
        suffix=veteran.suffix,
        date_of_birth=veteran.date_of_birth,
        email=veteran.email,
        phone=veteran.phone,
        address_line1=veteran.address_line1,
        address_line2=veteran.address_line2,
        city=veteran.city,
        state=veteran.state,
        zip_code=veteran.zip_code,
        branch_of_service=veteran.branch_of_service,
        service_start_date=veteran.service_start_date,
        service_end_date=veteran.service_end_date,
        discharge_type=veteran.discharge_type,
        va_file_number=veteran.va_file_number,
        current_rating=veteran.current_rating,
    )


@router.get("/{veteran_id}", response_model=VeteranResponse)
async def get_veteran(
    veteran_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ATTORNEY, UserRole.ADMIN, UserRole.STAFF))
):
    """Get a veteran profile by ID (attorneys/staff only)."""
    result = await db.execute(
        select(Veteran).where(Veteran.id == veteran_id)
    )
    veteran = result.scalar_one_or_none()
    if not veteran:
        raise HTTPException(status_code=404, detail="Veteran not found")

    return VeteranResponse(
        id=str(veteran.id),
        user_id=str(veteran.user_id),
        first_name=veteran.first_name,
        middle_name=veteran.middle_name,
        last_name=veteran.last_name,
        suffix=veteran.suffix,
        date_of_birth=veteran.date_of_birth,
        email=veteran.email,
        phone=veteran.phone,
        address_line1=veteran.address_line1,
        address_line2=veteran.address_line2,
        city=veteran.city,
        state=veteran.state,
        zip_code=veteran.zip_code,
        branch_of_service=veteran.branch_of_service,
        service_start_date=veteran.service_start_date,
        service_end_date=veteran.service_end_date,
        discharge_type=veteran.discharge_type,
        va_file_number=veteran.va_file_number,
        current_rating=veteran.current_rating,
    )


@router.get("/", response_model=List[VeteranResponse])
async def list_veterans(
    skip: int = 0,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ATTORNEY, UserRole.ADMIN, UserRole.STAFF))
):
    """List all veterans (attorneys/staff only)."""
    result = await db.execute(
        select(Veteran).offset(skip).limit(limit)
    )
    veterans = result.scalars().all()

    return [
        VeteranResponse(
            id=str(v.id),
            user_id=str(v.user_id),
            first_name=v.first_name,
            middle_name=v.middle_name,
            last_name=v.last_name,
            suffix=v.suffix,
            date_of_birth=v.date_of_birth,
            email=v.email,
            phone=v.phone,
            address_line1=v.address_line1,
            address_line2=v.address_line2,
            city=v.city,
            state=v.state,
            zip_code=v.zip_code,
            branch_of_service=v.branch_of_service,
            service_start_date=v.service_start_date,
            service_end_date=v.service_end_date,
            discharge_type=v.discharge_type,
            va_file_number=v.va_file_number,
            current_rating=v.current_rating,
        )
        for v in veterans
    ]
