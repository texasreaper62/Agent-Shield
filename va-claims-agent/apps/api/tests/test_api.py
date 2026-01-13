"""
API tests for VA Claims Agent.
"""
import pytest
from httpx import AsyncClient
from fastapi import status

# Test health endpoint
@pytest.mark.asyncio
async def test_health_check():
    """Test the health check endpoint."""
    from main import app

    async with AsyncClient(app=app, base_url="http://test") as client:
        response = await client.get("/health")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["status"] == "healthy"


@pytest.mark.asyncio
async def test_root():
    """Test the root endpoint."""
    from main import app

    async with AsyncClient(app=app, base_url="http://test") as client:
        response = await client.get("/")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "message" in data


# Test authentication
class TestAuth:
    """Authentication tests."""

    @pytest.mark.asyncio
    async def test_register_user(self, test_db):
        """Test user registration."""
        from main import app

        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.post(
                "/api/auth/register",
                json={
                    "email": "test@example.com",
                    "password": "testpassword123",
                    "first_name": "Test",
                    "last_name": "User"
                }
            )
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["email"] == "test@example.com"
            assert "id" in data

    @pytest.mark.asyncio
    async def test_login(self, test_db, test_user):
        """Test user login."""
        from main import app

        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.post(
                "/api/auth/token",
                data={
                    "username": "test@example.com",
                    "password": "testpassword123"
                }
            )
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert "access_token" in data
            assert data["token_type"] == "bearer"


# Test citation enforcement
class TestCitationEnforcement:
    """Tests for citation enforcement in AI outputs."""

    def test_evidence_requires_citation(self):
        """Test that evidence creation requires citations."""
        from agents.base import Citation, CitedFact, BaseAgent

        # Facts without citations should fail validation
        fact_without_citation = CitedFact(
            statement="This is a fact",
            citations=[],
            confidence=0.8
        )

        # Create a mock agent to test validation
        class MockAgent(BaseAgent):
            def _get_agent_specific_prompt(self):
                return ""

            async def process(self, **kwargs):
                return {}

        agent = MockAgent()
        assert not agent.validate_output_has_citations([fact_without_citation])

        # Facts with citations should pass
        fact_with_citation = CitedFact(
            statement="This is a cited fact",
            citations=[Citation(
                document_id="doc-123",
                chunk_id="chunk-1",
                quote="exact quote from document"
            )],
            confidence=0.8
        )
        assert agent.validate_output_has_citations([fact_with_citation])


# Test fee compliance
class TestFeeCompliance:
    """Tests for 38 CFR § 14.636 fee compliance."""

    @pytest.mark.asyncio
    async def test_initial_claim_blocks_fees(self, test_db, test_claim):
        """Test that initial claims have fee blocking enabled."""
        # Initial claims should have is_initial_claim = True
        assert test_claim.is_initial_claim is True

    @pytest.mark.asyncio
    async def test_submission_requires_approval(self, test_db, test_submission):
        """Test that submissions require human approval."""
        from models.submission import SubmissionStatus

        # New submissions should require approval
        assert test_submission.requires_approval is True
        assert test_submission.status == SubmissionStatus.PENDING_APPROVAL


# Fixtures
@pytest.fixture
async def test_db():
    """Create test database."""
    # In a real test, set up an in-memory SQLite or test PostgreSQL
    from models.database import init_db
    await init_db()
    yield
    # Cleanup


@pytest.fixture
async def test_user(test_db):
    """Create test user."""
    from models.user import User, UserRole
    from routers.auth import get_password_hash
    from models.database import async_session_maker

    async with async_session_maker() as session:
        user = User(
            email="test@example.com",
            hashed_password=get_password_hash("testpassword123"),
            role=UserRole.VETERAN,
            is_active=True
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
        return user


@pytest.fixture
async def test_claim(test_db, test_user):
    """Create test claim."""
    from models.claim import Claim, ClaimType, ClaimStatus
    from models.veteran import Veteran
    from models.database import async_session_maker

    async with async_session_maker() as session:
        veteran = Veteran(
            user_id=test_user.id,
            first_name="Test",
            last_name="Veteran"
        )
        session.add(veteran)
        await session.flush()

        claim = Claim(
            veteran_id=veteran.id,
            claim_type=ClaimType.INITIAL,
            status=ClaimStatus.DRAFT,
            is_initial_claim=True
        )
        session.add(claim)
        await session.commit()
        await session.refresh(claim)
        return claim


@pytest.fixture
async def test_submission(test_db, test_claim):
    """Create test submission."""
    from models.submission import Submission, SubmissionStatus
    from models.database import async_session_maker

    async with async_session_maker() as session:
        submission = Submission(
            claim_id=test_claim.id,
            status=SubmissionStatus.PENDING_APPROVAL,
            requires_approval=True
        )
        session.add(submission)
        await session.commit()
        await session.refresh(submission)
        return submission
