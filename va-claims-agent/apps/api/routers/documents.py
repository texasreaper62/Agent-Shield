"""
Documents router for file upload and processing.
"""
from typing import List, Optional
from uuid import UUID
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
import structlog

from config import settings
from models.database import get_db
from models.user import User, UserRole
from models.veteran import Veteran
from models.document import Document, DocumentType, DocumentStatus
from routers.auth import get_current_active_user, require_role
from services.storage import upload_to_blob, get_blob_url
from services.queue import send_to_processing_queue

router = APIRouter()
logger = structlog.get_logger()


class DocumentResponse(BaseModel):
    id: str
    veteran_id: str
    original_filename: str
    document_type: str
    status: str
    file_size: Optional[int]
    page_count: Optional[int]
    confidence_score: Optional[float]
    uploaded_at: datetime
    processed_at: Optional[datetime]

    class Config:
        from_attributes = True


class DocumentClassification(BaseModel):
    document_type: DocumentType


@router.post("/upload", response_model=DocumentResponse)
async def upload_document(
    file: UploadFile = File(...),
    document_type: Optional[DocumentType] = None,
    background_tasks: BackgroundTasks = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Upload a document for processing."""
    # Get veteran profile
    result = await db.execute(
        select(Veteran).where(Veteran.user_id == current_user.id)
    )
    veteran = result.scalar_one_or_none()
    if not veteran:
        raise HTTPException(status_code=400, detail="Veteran profile required")

    # Validate file type
    allowed_types = ["application/pdf", "image/png", "image/jpeg", "image/tiff"]
    if file.content_type not in allowed_types:
        raise HTTPException(
            status_code=400,
            detail=f"File type {file.content_type} not allowed. Allowed: {allowed_types}"
        )

    # Upload to blob storage
    content = await file.read()
    storage_path = f"veterans/{veteran.id}/documents/{file.filename}"
    await upload_to_blob(storage_path, content, file.content_type)

    # Create document record
    document = Document(
        veteran_id=veteran.id,
        original_filename=file.filename,
        storage_path=storage_path,
        mime_type=file.content_type,
        file_size=len(content),
        document_type=document_type or DocumentType.OTHER,
        status=DocumentStatus.UPLOADED,
    )
    db.add(document)
    await db.commit()
    await db.refresh(document)

    # Queue for processing
    await send_to_processing_queue({
        "document_id": str(document.id),
        "storage_path": storage_path,
        "veteran_id": str(veteran.id),
    })

    logger.info("Document uploaded", document_id=str(document.id), filename=file.filename)

    return DocumentResponse(
        id=str(document.id),
        veteran_id=str(document.veteran_id),
        original_filename=document.original_filename,
        document_type=document.document_type.value,
        status=document.status.value,
        file_size=document.file_size,
        page_count=document.page_count,
        confidence_score=document.confidence_score,
        uploaded_at=document.uploaded_at,
        processed_at=document.processed_at,
    )


@router.get("/", response_model=List[DocumentResponse])
async def list_documents(
    veteran_id: Optional[UUID] = None,
    document_type: Optional[DocumentType] = None,
    status: Optional[DocumentStatus] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """List documents for the current user or specified veteran."""
    # Build query
    query = select(Document)

    if current_user.role == UserRole.VETERAN:
        # Veterans can only see their own documents
        result = await db.execute(
            select(Veteran).where(Veteran.user_id == current_user.id)
        )
        veteran = result.scalar_one_or_none()
        if not veteran:
            return []
        query = query.where(Document.veteran_id == veteran.id)
    elif veteran_id:
        query = query.where(Document.veteran_id == veteran_id)

    if document_type:
        query = query.where(Document.document_type == document_type)
    if status:
        query = query.where(Document.status == status)

    result = await db.execute(query.order_by(Document.uploaded_at.desc()))
    documents = result.scalars().all()

    return [
        DocumentResponse(
            id=str(doc.id),
            veteran_id=str(doc.veteran_id),
            original_filename=doc.original_filename,
            document_type=doc.document_type.value,
            status=doc.status.value,
            file_size=doc.file_size,
            page_count=doc.page_count,
            confidence_score=doc.confidence_score,
            uploaded_at=doc.uploaded_at,
            processed_at=doc.processed_at,
        )
        for doc in documents
    ]


@router.get("/{document_id}", response_model=DocumentResponse)
async def get_document(
    document_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get document details."""
    result = await db.execute(
        select(Document).where(Document.id == document_id)
    )
    document = result.scalar_one_or_none()
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")

    # Check access
    if current_user.role == UserRole.VETERAN:
        vet_result = await db.execute(
            select(Veteran).where(Veteran.user_id == current_user.id)
        )
        veteran = vet_result.scalar_one_or_none()
        if not veteran or document.veteran_id != veteran.id:
            raise HTTPException(status_code=403, detail="Access denied")

    return DocumentResponse(
        id=str(document.id),
        veteran_id=str(document.veteran_id),
        original_filename=document.original_filename,
        document_type=document.document_type.value,
        status=document.status.value,
        file_size=document.file_size,
        page_count=document.page_count,
        confidence_score=document.confidence_score,
        uploaded_at=document.uploaded_at,
        processed_at=document.processed_at,
    )


@router.get("/{document_id}/download")
async def download_document(
    document_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get document download URL."""
    result = await db.execute(
        select(Document).where(Document.id == document_id)
    )
    document = result.scalar_one_or_none()
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")

    # Check access
    if current_user.role == UserRole.VETERAN:
        vet_result = await db.execute(
            select(Veteran).where(Veteran.user_id == current_user.id)
        )
        veteran = vet_result.scalar_one_or_none()
        if not veteran or document.veteran_id != veteran.id:
            raise HTTPException(status_code=403, detail="Access denied")

    url = await get_blob_url(document.storage_path)
    return {"download_url": url}


@router.put("/{document_id}/classify", response_model=DocumentResponse)
async def classify_document(
    document_id: UUID,
    classification: DocumentClassification,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Manually classify a document."""
    result = await db.execute(
        select(Document).where(Document.id == document_id)
    )
    document = result.scalar_one_or_none()
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")

    document.document_type = classification.document_type
    await db.commit()
    await db.refresh(document)

    logger.info("Document classified", document_id=str(document.id), type=classification.document_type.value)

    return DocumentResponse(
        id=str(document.id),
        veteran_id=str(document.veteran_id),
        original_filename=document.original_filename,
        document_type=document.document_type.value,
        status=document.status.value,
        file_size=document.file_size,
        page_count=document.page_count,
        confidence_score=document.confidence_score,
        uploaded_at=document.uploaded_at,
        processed_at=document.processed_at,
    )


@router.delete("/{document_id}")
async def delete_document(
    document_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Delete a document."""
    result = await db.execute(
        select(Document).where(Document.id == document_id)
    )
    document = result.scalar_one_or_none()
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")

    # Check access
    if current_user.role == UserRole.VETERAN:
        vet_result = await db.execute(
            select(Veteran).where(Veteran.user_id == current_user.id)
        )
        veteran = vet_result.scalar_one_or_none()
        if not veteran or document.veteran_id != veteran.id:
            raise HTTPException(status_code=403, detail="Access denied")

    await db.delete(document)
    await db.commit()

    logger.info("Document deleted", document_id=str(document_id))
    return {"message": "Document deleted"}
