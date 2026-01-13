"""
Knowledge base router for 38 CFR and VA claims guidance.
"""
from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text
from pydantic import BaseModel
import structlog

from models.database import get_db
from models.user import User
from models.knowledge import KnowledgeArticle, CFRSection, RatingCriteria
from routers.auth import get_current_active_user

router = APIRouter()
logger = structlog.get_logger()


class KnowledgeArticleResponse(BaseModel):
    id: str
    title: str
    slug: str
    category: str
    subcategory: Optional[str]
    content: str
    summary: Optional[str]
    keywords: Optional[List[str]]
    cfr_references: Optional[List[str]]
    source: Optional[str]
    source_url: Optional[str]

    class Config:
        from_attributes = True


class CFRSectionResponse(BaseModel):
    id: str
    title: int
    part: int
    subpart: Optional[str]
    section: str
    diagnostic_code: Optional[str]
    section_title: str
    full_text: str
    summary: Optional[str]
    rating_percentages: Optional[List[dict]]
    body_system: Optional[str]
    condition_category: Optional[str]
    ecfr_url: Optional[str]

    class Config:
        from_attributes = True


class RatingCriteriaResponse(BaseModel):
    id: str
    diagnostic_code: str
    condition_name: str
    rating_percentage: int
    criteria_description: str
    objective_criteria: Optional[List[dict]]
    subjective_criteria: Optional[List[dict]]
    required_evidence: Optional[List[dict]]

    class Config:
        from_attributes = True


class SearchResult(BaseModel):
    type: str  # "article", "cfr", "rating"
    id: str
    title: str
    snippet: str
    relevance_score: float


@router.get("/search", response_model=List[SearchResult])
async def search_knowledge(
    query: str = Query(..., min_length=3),
    category: Optional[str] = None,
    limit: int = Query(20, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Semantic search across knowledge base.

    Searches articles, CFR sections, and rating criteria using vector similarity.
    """
    from services.embeddings import get_embedding

    # Get embedding for search query
    query_embedding = await get_embedding(query)

    results = []

    # Search articles
    article_query = """
        SELECT id, title, content,
               1 - (embedding <=> :embedding::vector) as similarity
        FROM knowledge_articles
        WHERE is_published = true
        AND embedding IS NOT NULL
        ORDER BY embedding <=> :embedding::vector
        LIMIT :limit
    """
    article_results = await db.execute(
        text(article_query),
        {"embedding": str(query_embedding), "limit": limit}
    )
    for row in article_results:
        results.append(SearchResult(
            type="article",
            id=str(row.id),
            title=row.title,
            snippet=row.content[:200] + "..." if len(row.content) > 200 else row.content,
            relevance_score=float(row.similarity),
        ))

    # Search CFR sections
    cfr_query = """
        SELECT id, section_title, full_text,
               1 - (embedding <=> :embedding::vector) as similarity
        FROM cfr_sections
        WHERE embedding IS NOT NULL
        ORDER BY embedding <=> :embedding::vector
        LIMIT :limit
    """
    cfr_results = await db.execute(
        text(cfr_query),
        {"embedding": str(query_embedding), "limit": limit}
    )
    for row in cfr_results:
        results.append(SearchResult(
            type="cfr",
            id=str(row.id),
            title=row.section_title,
            snippet=row.full_text[:200] + "..." if len(row.full_text) > 200 else row.full_text,
            relevance_score=float(row.similarity),
        ))

    # Sort by relevance and limit
    results.sort(key=lambda x: x.relevance_score, reverse=True)
    return results[:limit]


@router.get("/articles", response_model=List[KnowledgeArticleResponse])
async def list_articles(
    category: Optional[str] = None,
    skip: int = 0,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """List knowledge articles."""
    query = select(KnowledgeArticle).where(KnowledgeArticle.is_published == True)

    if category:
        query = query.where(KnowledgeArticle.category == category)

    result = await db.execute(query.offset(skip).limit(limit))
    articles = result.scalars().all()

    return [
        KnowledgeArticleResponse(
            id=str(a.id),
            title=a.title,
            slug=a.slug,
            category=a.category,
            subcategory=a.subcategory,
            content=a.content,
            summary=a.summary,
            keywords=a.keywords,
            cfr_references=a.cfr_references,
            source=a.source,
            source_url=a.source_url,
        )
        for a in articles
    ]


@router.get("/articles/{slug}", response_model=KnowledgeArticleResponse)
async def get_article(
    slug: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get a knowledge article by slug."""
    result = await db.execute(
        select(KnowledgeArticle).where(KnowledgeArticle.slug == slug)
    )
    article = result.scalar_one_or_none()
    if not article:
        raise HTTPException(status_code=404, detail="Article not found")

    return KnowledgeArticleResponse(
        id=str(article.id),
        title=article.title,
        slug=article.slug,
        category=article.category,
        subcategory=article.subcategory,
        content=article.content,
        summary=article.summary,
        keywords=article.keywords,
        cfr_references=article.cfr_references,
        source=article.source,
        source_url=article.source_url,
    )


@router.get("/cfr", response_model=List[CFRSectionResponse])
async def list_cfr_sections(
    part: Optional[int] = None,
    body_system: Optional[str] = None,
    skip: int = 0,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """List 38 CFR sections."""
    query = select(CFRSection)

    if part:
        query = query.where(CFRSection.part == part)
    if body_system:
        query = query.where(CFRSection.body_system == body_system)

    result = await db.execute(query.offset(skip).limit(limit))
    sections = result.scalars().all()

    return [
        CFRSectionResponse(
            id=str(s.id),
            title=s.title,
            part=s.part,
            subpart=s.subpart,
            section=s.section,
            diagnostic_code=s.diagnostic_code,
            section_title=s.section_title,
            full_text=s.full_text,
            summary=s.summary,
            rating_percentages=s.rating_percentages,
            body_system=s.body_system,
            condition_category=s.condition_category,
            ecfr_url=s.ecfr_url,
        )
        for s in sections
    ]


@router.get("/cfr/{section}", response_model=CFRSectionResponse)
async def get_cfr_section(
    section: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get a specific CFR section."""
    result = await db.execute(
        select(CFRSection).where(CFRSection.section == section)
    )
    cfr = result.scalar_one_or_none()
    if not cfr:
        raise HTTPException(status_code=404, detail="CFR section not found")

    return CFRSectionResponse(
        id=str(cfr.id),
        title=cfr.title,
        part=cfr.part,
        subpart=cfr.subpart,
        section=cfr.section,
        diagnostic_code=cfr.diagnostic_code,
        section_title=cfr.section_title,
        full_text=cfr.full_text,
        summary=cfr.summary,
        rating_percentages=cfr.rating_percentages,
        body_system=cfr.body_system,
        condition_category=cfr.condition_category,
        ecfr_url=cfr.ecfr_url,
    )


@router.get("/diagnostic-codes/{dc}", response_model=List[RatingCriteriaResponse])
async def get_diagnostic_code_ratings(
    dc: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get all rating criteria for a diagnostic code."""
    result = await db.execute(
        select(RatingCriteria)
        .where(RatingCriteria.diagnostic_code == dc)
        .order_by(RatingCriteria.rating_percentage.desc())
    )
    criteria = result.scalars().all()

    if not criteria:
        raise HTTPException(status_code=404, detail="Diagnostic code not found")

    return [
        RatingCriteriaResponse(
            id=str(c.id),
            diagnostic_code=c.diagnostic_code,
            condition_name=c.condition_name,
            rating_percentage=c.rating_percentage,
            criteria_description=c.criteria_description,
            objective_criteria=c.objective_criteria,
            subjective_criteria=c.subjective_criteria,
            required_evidence=c.required_evidence,
        )
        for c in criteria
    ]


@router.get("/body-systems")
async def list_body_systems(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """List all body systems in the rating schedule."""
    result = await db.execute(
        select(CFRSection.body_system)
        .where(CFRSection.body_system.isnot(None))
        .distinct()
    )
    systems = [row[0] for row in result.all()]
    return {"body_systems": systems}


@router.get("/conditions/search")
async def search_conditions(
    query: str = Query(..., min_length=2),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Search for conditions by name."""
    result = await db.execute(
        select(RatingCriteria)
        .where(RatingCriteria.condition_name.ilike(f"%{query}%"))
        .distinct(RatingCriteria.diagnostic_code)
        .limit(20)
    )
    conditions = result.scalars().all()

    return [
        {
            "diagnostic_code": c.diagnostic_code,
            "condition_name": c.condition_name,
            "max_rating": c.rating_percentage,
        }
        for c in conditions
    ]
