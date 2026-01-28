# nosemgrep: detect-generic-ai-anthprop
"""Application configuration using Pydantic settings."""

import logging
from functools import lru_cache
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)

# Get the backend directory (parent of app/core/)
BACKEND_DIR = Path(__file__).resolve().parent.parent.parent
ENV_FILE = BACKEND_DIR / ".env"

# Load .env file with override=True to handle empty env vars
if ENV_FILE.exists():
    load_dotenv(ENV_FILE, override=True)
    logger.info(f"Loaded environment from {ENV_FILE}")
else:
    logger.warning(f"No .env file found at {ENV_FILE}")


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Application
    app_name: str = "Enterprise Guardrails API"
    app_version: str = "1.0.0"
    env: str = "development"  # development, staging, production
    debug: bool = False
    log_level: str = "INFO"

    @property
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.env.lower() == "production"

    @property
    def is_development(self) -> bool:
        """Check if running in development environment."""
        return self.env.lower() == "development"

    # API Keys
    anthropic_api_key: str = ""
    google_api_key: str = ""
    groq_api_key: str = ""

    # AI Provider: "anthropic", "gemini", or "groq"
    ai_provider: str = "groq"

    # Database
    database_url: str = "postgresql://postgres:postgres@localhost:5432/guardrails"

    # GitHub Integration
    github_app_secret: str = ""

    # Security
    api_key: Optional[str] = None  # Optional API key for backend authentication

    # Claude Settings
    claude_model: str = "claude-sonnet-4-20250514"
    claude_max_tokens: int = 4096

    # Gemini Settings
    gemini_model: str = "gemini-2.0-flash"

    # Groq Settings
    groq_model: str = "llama-3.3-70b-versatile"

    # Analysis Settings
    max_diff_size: int = 100000  # Max diff size in characters
    default_enforcement_mode: str = "warning"  # advisory, warning, blocking


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    settings = Settings()

    # Log loaded configuration (mask sensitive values)
    logger.info("Configuration loaded:")
    logger.info(f"  ENV: {settings.env}")
    logger.info(f"  DATABASE_URL: {settings.database_url[:30]}...")
    logger.info(f"  AI_PROVIDER: {settings.ai_provider}")
    logger.info(f"  ANTHROPIC_API_KEY: {'[SET]' if settings.anthropic_api_key else '[NOT SET]'}")
    logger.info(f"  GOOGLE_API_KEY: {'[SET]' if settings.google_api_key else '[NOT SET]'}")
    logger.info(f"  GROQ_API_KEY: {'[SET]' if settings.groq_api_key else '[NOT SET]'}")
    logger.info(f"  GITHUB_APP_SECRET: {'[SET]' if settings.github_app_secret else '[NOT SET]'}")
    logger.info(f"  API_KEY: {'[SET]' if settings.api_key else '[NOT SET]'}")
    logger.info(f"  DEBUG: {settings.debug}")
    logger.info(f"  LOG_LEVEL: {settings.log_level}")
    logger.info(f"  CLAUDE_MODEL: {settings.claude_model}")
    logger.info(f"  GEMINI_MODEL: {settings.gemini_model}")

    return settings
