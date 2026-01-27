"""FastAPI application entry point."""

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api.routes import router
from .core.config import get_settings
from .models.audit import init_db

settings = get_settings()

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def get_cors_origins() -> list[str]:
    """Get CORS allowed origins from environment or use defaults.

    In production, set CORS_ORIGINS environment variable to a comma-separated
    list of allowed origins (e.g., "https://app.example.com,https://admin.example.com").
    """
    cors_origins_env = os.environ.get("CORS_ORIGINS", "")

    if cors_origins_env:
        origins = [origin.strip() for origin in cors_origins_env.split(",") if origin.strip()]
        logger.info(f"CORS origins configured: {origins}")
        return origins

    # Default development origins - warn in production
    if not settings.debug:
        logger.warning(
            "CORS_ORIGINS not configured - using permissive defaults. "
            "Set CORS_ORIGINS environment variable in production."
        )

    return [
        "http://localhost:3000",
        "http://localhost:8000",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8000",
    ]


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    logger.info("Starting Enterprise Guardrails API...")
    # Initialize database
    await init_db()
    yield
    logger.info("Shutting down Enterprise Guardrails API...")


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="AI-powered enterprise guardrails for GitHub Copilot code review",
    lifespan=lifespan,
)

# CORS middleware - use specific origins instead of wildcard for security
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_cors_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(router, prefix="/api/v1")


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "status": "running",
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}
