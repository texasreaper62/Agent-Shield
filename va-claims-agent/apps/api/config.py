"""
Application configuration using Pydantic Settings.
"""
from typing import List
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Application
    APP_NAME: str = "VA Claims Agent"
    DEBUG: bool = False
    SECRET_KEY: str = "change-this-in-production"
    JWT_SECRET: str = "change-this-jwt-secret"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_HOURS: int = 24

    # CORS
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:8000"]

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://localhost/vaclaims"

    # Azure Storage
    AZURE_STORAGE_ACCOUNT: str = ""
    AZURE_STORAGE_KEY: str = ""
    AZURE_BLOB_CONTAINER_UPLOADS: str = "uploads"
    AZURE_BLOB_CONTAINER_PROCESSED: str = "processed"
    AZURE_BLOB_CONTAINER_FORMS: str = "forms"

    # Azure Service Bus
    AZURE_SERVICE_BUS_CONNECTION_STRING: str = ""
    AZURE_SERVICE_BUS_QUEUE_DOCUMENTS: str = "document-processing"
    AZURE_SERVICE_BUS_QUEUE_CLAIMS: str = "claim-analysis"
    AZURE_SERVICE_BUS_QUEUE_FORMS: str = "forms-generation"

    # Azure Document Intelligence (OCR)
    AZURE_DOCUMENT_INTELLIGENCE_ENDPOINT: str = ""
    AZURE_DOCUMENT_INTELLIGENCE_KEY: str = ""

    # Anthropic (Claude)
    ANTHROPIC_API_KEY: str = ""
    CLAUDE_SONNET_MODEL: str = "claude-sonnet-4-20250514"
    CLAUDE_HAIKU_MODEL: str = "claude-3-5-haiku-20241022"

    # VA APIs
    VA_BENEFITS_INTAKE_API_URL: str = "https://sandbox-api.va.gov/services/vba_documents/v1"
    VA_FORMS_API_URL: str = "https://sandbox-api.va.gov/services/va_forms/v0"
    VA_API_KEY: str = ""

    # Feature Flags
    ENABLE_AUTO_SUBMISSION: bool = False
    REQUIRE_ATTORNEY_APPROVAL: bool = True

    # Rate Limiting
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_PERIOD: int = 60

    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


settings = get_settings()
