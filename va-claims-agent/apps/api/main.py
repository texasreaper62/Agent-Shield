"""
VA Claims Agent API - Main Application
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import structlog

from config import settings
from routers import (
    auth,
    veterans,
    documents,
    claims,
    evidence,
    forms,
    reviews,
    submissions,
    knowledge,
)
from models.database import init_db

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    logger.info("Starting VA Claims Agent API")
    await init_db()
    yield
    logger.info("Shutting down VA Claims Agent API")


app = FastAPI(
    title="VA Claims Agent API",
    description="AI-powered VA disability claims processing system",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(veterans.router, prefix="/api/veterans", tags=["Veterans"])
app.include_router(documents.router, prefix="/api/documents", tags=["Documents"])
app.include_router(claims.router, prefix="/api/claims", tags=["Claims"])
app.include_router(evidence.router, prefix="/api/evidence", tags=["Evidence"])
app.include_router(forms.router, prefix="/api/forms", tags=["Forms"])
app.include_router(reviews.router, prefix="/api/reviews", tags=["Reviews"])
app.include_router(submissions.router, prefix="/api/submissions", tags=["Submissions"])
app.include_router(knowledge.router, prefix="/api/knowledge", tags=["Knowledge Base"])


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "version": "1.0.0"}


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "VA Claims Agent API",
        "docs": "/docs",
        "health": "/health",
    }
