"""Application configuration using Pydantic settings."""

from functools import lru_cache
from typing import Optional

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Application
    app_name: str = "Enterprise Guardrails API"
    app_version: str = "1.0.0"
    debug: bool = False
    log_level: str = "INFO"

    # API Keys
    anthropic_api_key: str = ""

    # Database
    database_url: str = "postgresql://postgres:postgres@localhost:5432/guardrails"

    # GitHub Integration
    github_app_secret: str = ""

    # Security
    api_key: Optional[str] = None  # Optional API key for backend authentication

    # Claude Settings
    claude_model: str = "claude-sonnet-4-20250514"
    claude_max_tokens: int = 4096

    # Analysis Settings
    max_diff_size: int = 100000  # Max diff size in characters
    default_enforcement_mode: str = "warning"  # advisory, warning, blocking

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
