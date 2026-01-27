"""Database model for override logs."""

from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String, Text

from .audit import Base


class OverrideLog(Base):
    """Override log table for tracking blocking overrides."""

    __tablename__ = "override_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    request_id = Column(String(36), nullable=False, index=True)
    repository = Column(String(255), nullable=False, index=True)
    pull_request_number = Column(Integer, nullable=False)
    overridden_by = Column(String(255), nullable=False)
    reason = Column(Text, nullable=False)
    violations_count = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
