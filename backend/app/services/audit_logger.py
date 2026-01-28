"""Audit logging service for compliance tracking."""

import json
import logging
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import desc, select
from sqlalchemy.exc import SQLAlchemyError

from ..models.audit import AuditLog, get_async_session

logger = logging.getLogger(__name__)


class AuditLogger:
    """Service for logging analysis actions for compliance and audit."""

    async def log_analysis(
        self,
        request_id: str,
        repository: str,
        enforcement_mode: str,
        violations_count: int,
        critical_count: int,
        high_count: int,
        blocked: bool,
        pull_request_number: Optional[int] = None,
        commit_sha: Optional[str] = None,
        user: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> Optional[int]:
        """Log an analysis action.

        Args:
            request_id: Unique identifier for this analysis request
            repository: Repository name (owner/repo)
            enforcement_mode: The enforcement mode used
            violations_count: Total number of violations found
            critical_count: Number of critical violations
            high_count: Number of high severity violations
            blocked: Whether the merge was blocked
            pull_request_number: PR number if applicable
            commit_sha: Commit SHA being analyzed
            user: User who triggered the analysis
            metadata: Additional metadata to store

        Returns:
            The audit log entry ID, or None if logging failed
        """
        try:
            session = await get_async_session()
            async with session:
                log_entry = AuditLog(
                    request_id=request_id,
                    timestamp=datetime.utcnow(),
                    repository=repository,
                    pull_request_number=pull_request_number,
                    commit_sha=commit_sha,
                    action="analyze",
                    enforcement_mode=enforcement_mode,
                    violations_count=violations_count,
                    critical_count=critical_count,
                    high_count=high_count,
                    blocked=blocked,
                    user=user,
                    metadata_json=json.dumps(metadata) if metadata else None,
                )

                session.add(log_entry)
                await session.commit()
                await session.refresh(log_entry)

                logger.info(
                    f"Audit log created: {request_id} - {repository} - "
                    f"{violations_count} violations, blocked={blocked}"
                )

                return log_entry.id

        except SQLAlchemyError as e:
            logger.error(f"Failed to create audit log: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error in audit logging: {e}")
            return None

    async def get_logs(
        self,
        repository: Optional[str] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> dict[str, Any]:
        """Retrieve audit logs with optional filtering.

        Args:
            repository: Filter by repository name
            page: Page number (1-indexed)
            page_size: Number of items per page

        Returns:
            Dictionary with entries, total count, and pagination info
        """
        try:
            session = await get_async_session()
            async with session:
                # Build query
                query = select(AuditLog).order_by(desc(AuditLog.timestamp))

                if repository:
                    query = query.where(AuditLog.repository == repository)

                # Get total count using SQL COUNT (more efficient than fetching all)
                from sqlalchemy import func
                count_query = select(func.count()).select_from(AuditLog)
                if repository:
                    count_query = count_query.where(AuditLog.repository == repository)

                # Apply pagination
                offset = (page - 1) * page_size
                query = query.offset(offset).limit(page_size)

                # Execute queries
                result = await session.execute(query)
                entries = result.scalars().all()

                count_result = await session.execute(count_query)
                total = count_result.scalar() or 0

                return {
                    "entries": [
                        {
                            "id": str(entry.id),
                            "timestamp": entry.timestamp.isoformat(),
                            "repository": entry.repository,
                            "pull_request_number": entry.pull_request_number,
                            "commit_sha": entry.commit_sha,
                            "action": entry.action,
                            "enforcement_mode": entry.enforcement_mode,
                            "violations_count": entry.violations_count,
                            "critical_count": entry.critical_count,
                            "high_count": entry.high_count,
                            "blocked": entry.blocked,
                            "user": entry.user,
                            "metadata": (
                                json.loads(entry.metadata_json)
                                if entry.metadata_json
                                else {}
                            ),
                        }
                        for entry in entries
                    ],
                    "total": total,
                    "page": page,
                    "page_size": page_size,
                }

        except SQLAlchemyError as e:
            logger.error(f"Failed to retrieve audit logs: {e}")
            return {
                "entries": [],
                "total": 0,
                "page": page,
                "page_size": page_size,
            }
        except Exception as e:
            logger.error(f"Unexpected error retrieving audit logs: {e}")
            return {
                "entries": [],
                "total": 0,
                "page": page,
                "page_size": page_size,
            }

    async def check_connection(self) -> bool:
        """Check if database connection is working.

        Returns:
            True if connection is working, False otherwise
        """
        try:
            session = await get_async_session()
            async with session:
                await session.execute(select(AuditLog).limit(1))
                return True
        except Exception as e:
            logger.error(f"Database connection check failed: {e}")
            raise

    async def export_logs(
        self,
        repository: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> list[dict[str, Any]]:
        """Export audit logs for compliance reporting.

        Args:
            repository: Filter by repository name
            start_date: Start date for export range
            end_date: End date for export range

        Returns:
            List of audit log entries
        """
        try:
            session = await get_async_session()
            async with session:
                query = select(AuditLog).order_by(desc(AuditLog.timestamp))

                if repository:
                    query = query.where(AuditLog.repository == repository)
                if start_date:
                    query = query.where(AuditLog.timestamp >= start_date)
                if end_date:
                    query = query.where(AuditLog.timestamp <= end_date)

                result = await session.execute(query)
                entries = result.scalars().all()

                return [
                    {
                        "id": str(entry.id),
                        "request_id": entry.request_id,
                        "timestamp": entry.timestamp.isoformat(),
                        "repository": entry.repository,
                        "pull_request_number": entry.pull_request_number,
                        "commit_sha": entry.commit_sha,
                        "action": entry.action,
                        "enforcement_mode": entry.enforcement_mode,
                        "violations_count": entry.violations_count,
                        "critical_count": entry.critical_count,
                        "high_count": entry.high_count,
                        "blocked": entry.blocked,
                        "user": entry.user,
                        "metadata": (
                            json.loads(entry.metadata_json)
                            if entry.metadata_json
                            else {}
                        ),
                    }
                    for entry in entries
                ]

        except Exception as e:
            logger.error(f"Failed to export audit logs: {e}")
            return []
