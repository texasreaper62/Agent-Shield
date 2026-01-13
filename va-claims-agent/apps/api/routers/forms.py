"""
Forms router for VA forms automation.
"""
from typing import List, Optional
from uuid import UUID
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from pydantic import BaseModel
import structlog

from models.database import get_db
from models.user import User, UserRole
from models.claim import Claim
from models.form import Form, FormField, FormStatus
from routers.auth import get_current_active_user, require_role
from services.queue import send_to_forms_queue

router = APIRouter()
logger = structlog.get_logger()


# VA Forms that the system supports
SUPPORTED_FORMS = {
    "21-526EZ": {
        "name": "Application for Disability Compensation and Related Compensation Benefits",
        "description": "Main form for filing VA disability claims",
    },
    "21-0781": {
        "name": "Statement in Support of Claim for Service Connection for PTSD",
        "description": "Required for PTSD claims",
    },
    "21-4142": {
        "name": "Authorization to Disclose Information to VA",
        "description": "Allows VA to obtain private medical records",
    },
    "21-4138": {
        "name": "Statement in Support of Claim",
        "description": "General statement form for additional information",
    },
    "21-8940": {
        "name": "Application for Increased Compensation Based on Unemployability",
        "description": "TDIU application form",
    },
}


class FormFieldUpdate(BaseModel):
    field_id: str
    value: str


class FormCreate(BaseModel):
    claim_id: UUID
    form_number: str


class FormFieldResponse(BaseModel):
    id: str
    field_id: str
    field_label: Optional[str]
    field_type: Optional[str]
    section: Optional[str]
    value: Optional[str]
    is_auto_filled: bool
    source_citation: Optional[str]
    is_required: bool
    is_valid: bool
    validation_message: Optional[str]
    is_manually_edited: bool

    class Config:
        from_attributes = True


class FormResponse(BaseModel):
    id: str
    claim_id: str
    form_number: str
    form_name: str
    status: str
    is_complete: bool
    completeness_score: Optional[int]
    validation_errors: Optional[List[dict]]
    pdf_storage_path: Optional[str]
    reviewed_by: Optional[str]
    reviewed_at: Optional[datetime]
    created_at: datetime
    generated_at: Optional[datetime]

    class Config:
        from_attributes = True


class FormDetailResponse(FormResponse):
    fields: List[FormFieldResponse]


@router.get("/supported")
async def list_supported_forms():
    """List all supported VA forms."""
    return SUPPORTED_FORMS


@router.post("/", response_model=FormResponse, status_code=201)
async def create_form(
    form_data: FormCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Create a new form for a claim."""
    if form_data.form_number not in SUPPORTED_FORMS:
        raise HTTPException(
            status_code=400,
            detail=f"Form {form_data.form_number} not supported. Supported forms: {list(SUPPORTED_FORMS.keys())}"
        )

    # Validate claim exists
    result = await db.execute(
        select(Claim).where(Claim.id == form_data.claim_id)
    )
    claim = result.scalar_one_or_none()
    if not claim:
        raise HTTPException(status_code=404, detail="Claim not found")

    # Check for existing form of same type
    result = await db.execute(
        select(Form).where(
            Form.claim_id == form_data.claim_id,
            Form.form_number == form_data.form_number
        )
    )
    existing = result.scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail="Form already exists for this claim")

    form_info = SUPPORTED_FORMS[form_data.form_number]
    form = Form(
        claim_id=form_data.claim_id,
        form_number=form_data.form_number,
        form_name=form_info["name"],
        status=FormStatus.PENDING,
    )
    db.add(form)
    await db.commit()
    await db.refresh(form)

    # Queue for generation
    await send_to_forms_queue({
        "form_id": str(form.id),
        "claim_id": str(form_data.claim_id),
        "form_number": form_data.form_number,
    })

    logger.info("Form created", form_id=str(form.id), form_number=form_data.form_number)

    return FormResponse(
        id=str(form.id),
        claim_id=str(form.claim_id),
        form_number=form.form_number,
        form_name=form.form_name,
        status=form.status.value,
        is_complete=form.is_complete,
        completeness_score=form.completeness_score,
        validation_errors=form.validation_errors,
        pdf_storage_path=form.pdf_storage_path,
        reviewed_by=str(form.reviewed_by) if form.reviewed_by else None,
        reviewed_at=form.reviewed_at,
        created_at=form.created_at,
        generated_at=form.generated_at,
    )


@router.get("/claim/{claim_id}", response_model=List[FormResponse])
async def list_claim_forms(
    claim_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """List all forms for a claim."""
    result = await db.execute(
        select(Form).where(Form.claim_id == claim_id).order_by(Form.created_at.desc())
    )
    forms = result.scalars().all()

    return [
        FormResponse(
            id=str(f.id),
            claim_id=str(f.claim_id),
            form_number=f.form_number,
            form_name=f.form_name,
            status=f.status.value,
            is_complete=f.is_complete,
            completeness_score=f.completeness_score,
            validation_errors=f.validation_errors,
            pdf_storage_path=f.pdf_storage_path,
            reviewed_by=str(f.reviewed_by) if f.reviewed_by else None,
            reviewed_at=f.reviewed_at,
            created_at=f.created_at,
            generated_at=f.generated_at,
        )
        for f in forms
    ]


@router.get("/{form_id}", response_model=FormDetailResponse)
async def get_form(
    form_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get form details with all fields."""
    result = await db.execute(
        select(Form)
        .options(selectinload(Form.fields))
        .where(Form.id == form_id)
    )
    form = result.scalar_one_or_none()
    if not form:
        raise HTTPException(status_code=404, detail="Form not found")

    return FormDetailResponse(
        id=str(form.id),
        claim_id=str(form.claim_id),
        form_number=form.form_number,
        form_name=form.form_name,
        status=form.status.value,
        is_complete=form.is_complete,
        completeness_score=form.completeness_score,
        validation_errors=form.validation_errors,
        pdf_storage_path=form.pdf_storage_path,
        reviewed_by=str(form.reviewed_by) if form.reviewed_by else None,
        reviewed_at=form.reviewed_at,
        created_at=form.created_at,
        generated_at=form.generated_at,
        fields=[
            FormFieldResponse(
                id=str(f.id),
                field_id=f.field_id,
                field_label=f.field_label,
                field_type=f.field_type,
                section=f.section,
                value=f.value,
                is_auto_filled=f.is_auto_filled,
                source_citation=f.source_citation,
                is_required=f.is_required,
                is_valid=f.is_valid,
                validation_message=f.validation_message,
                is_manually_edited=f.is_manually_edited,
            )
            for f in form.fields
        ],
    )


@router.put("/{form_id}/fields", response_model=FormDetailResponse)
async def update_form_fields(
    form_id: UUID,
    updates: List[FormFieldUpdate],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Update form field values (manual edits)."""
    result = await db.execute(
        select(Form)
        .options(selectinload(Form.fields))
        .where(Form.id == form_id)
    )
    form = result.scalar_one_or_none()
    if not form:
        raise HTTPException(status_code=404, detail="Form not found")

    if form.status == FormStatus.SUBMITTED:
        raise HTTPException(status_code=400, detail="Cannot edit submitted form")

    # Update fields
    field_map = {f.field_id: f for f in form.fields}
    for update in updates:
        if update.field_id in field_map:
            field = field_map[update.field_id]
            if not field.is_manually_edited:
                field.original_value = field.value
            field.value = update.value
            field.is_manually_edited = True
            field.edited_by = current_user.id
            field.edited_at = datetime.utcnow()

    await db.commit()
    await db.refresh(form)

    logger.info("Form fields updated", form_id=str(form.id), updates=len(updates))

    return FormDetailResponse(
        id=str(form.id),
        claim_id=str(form.claim_id),
        form_number=form.form_number,
        form_name=form.form_name,
        status=form.status.value,
        is_complete=form.is_complete,
        completeness_score=form.completeness_score,
        validation_errors=form.validation_errors,
        pdf_storage_path=form.pdf_storage_path,
        reviewed_by=str(form.reviewed_by) if form.reviewed_by else None,
        reviewed_at=form.reviewed_at,
        created_at=form.created_at,
        generated_at=form.generated_at,
        fields=[
            FormFieldResponse(
                id=str(f.id),
                field_id=f.field_id,
                field_label=f.field_label,
                field_type=f.field_type,
                section=f.section,
                value=f.value,
                is_auto_filled=f.is_auto_filled,
                source_citation=f.source_citation,
                is_required=f.is_required,
                is_valid=f.is_valid,
                validation_message=f.validation_message,
                is_manually_edited=f.is_manually_edited,
            )
            for f in form.fields
        ],
    )


@router.post("/{form_id}/regenerate")
async def regenerate_form(
    form_id: UUID,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Regenerate form PDF with current field values."""
    result = await db.execute(
        select(Form).where(Form.id == form_id)
    )
    form = result.scalar_one_or_none()
    if not form:
        raise HTTPException(status_code=404, detail="Form not found")

    form.status = FormStatus.GENERATING
    await db.commit()

    # Queue for regeneration
    await send_to_forms_queue({
        "form_id": str(form.id),
        "claim_id": str(form.claim_id),
        "form_number": form.form_number,
        "regenerate": True,
    })

    logger.info("Form regeneration queued", form_id=str(form.id))
    return {"message": "Form regeneration queued"}


@router.get("/{form_id}/download")
async def download_form(
    form_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get form PDF download URL."""
    result = await db.execute(
        select(Form).where(Form.id == form_id)
    )
    form = result.scalar_one_or_none()
    if not form:
        raise HTTPException(status_code=404, detail="Form not found")

    if not form.pdf_storage_path:
        raise HTTPException(status_code=400, detail="Form PDF not generated yet")

    from services.storage import get_blob_url
    url = await get_blob_url(form.pdf_storage_path)
    return {"download_url": url}
