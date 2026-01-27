"""Database models for audit logging."""

import logging
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from ..core.config import get_settings

logger = logging.getLogger(__name__)
Base = declarative_base()


# Import override model to ensure it's registered with Base metadata
# This is imported after Base is defined but before init_db is called
def _register_override_model():
    """Lazy import to avoid circular dependency."""
    from .override import OverrideLog  # noqa: F401
    return OverrideLog


class AuditLog(Base):
    """Audit log table for tracking all analysis actions."""

    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    request_id = Column(String(36), unique=True, nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    repository = Column(String(255), nullable=False, index=True)
    pull_request_number = Column(Integer, nullable=True)
    commit_sha = Column(String(40), nullable=True)
    action = Column(String(50), default="analyze", nullable=False)
    enforcement_mode = Column(String(20), nullable=False)
    violations_count = Column(Integer, default=0, nullable=False)
    critical_count = Column(Integer, default=0, nullable=False)
    high_count = Column(Integer, default=0, nullable=False)
    blocked = Column(Boolean, default=False, nullable=False)
    user = Column(String(255), nullable=True)
    metadata_json = Column(Text, nullable=True)  # JSON string for additional metadata


# Async engine and session factory
_async_engine = None
_async_session_factory = None


async def get_async_engine():
    """Get or create async database engine."""
    global _async_engine
    if _async_engine is None:
        settings = get_settings()
        # Convert postgresql:// to postgresql+asyncpg://
        db_url = settings.database_url
        if db_url.startswith("postgresql://"):
            db_url = db_url.replace("postgresql://", "postgresql+asyncpg://", 1)

        _async_engine = create_async_engine(
            db_url,
            echo=settings.debug,
            pool_pre_ping=True,
        )
    return _async_engine


async def get_async_session() -> AsyncSession:
    """Get an async database session."""
    global _async_session_factory
    if _async_session_factory is None:
        engine = await get_async_engine()
        _async_session_factory = async_sessionmaker(
            engine, class_=AsyncSession, expire_on_commit=False
        )
    return _async_session_factory()


async def init_db():
    """Initialize the database tables."""
    try:
        # Register override model to ensure its table is created
        _register_override_model()

        engine = await get_async_engine()
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database tables initialized successfully")
    except Exception as e:
        logger.warning(f"Failed to initialize database: {e}")
        logger.warning("Audit logging will be disabled")
