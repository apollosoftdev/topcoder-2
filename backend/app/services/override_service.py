"""Service for handling blocking overrides."""

import logging
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import select, desc
from sqlalchemy.exc import SQLAlchemyError

from ..models.audit import get_async_session
from ..models.override import OverrideLog

logger = logging.getLogger(__name__)


class OverrideService:
    """Service for managing blocking overrides."""

    async def create_override(
        self,
        request_id: str,
        repository: str,
        pull_request_number: int,
        overridden_by: str,
        reason: str,
        violations_count: int = 0,
    ) -> Optional[int]:
        """Create an override log entry.

        Args:
            request_id: The original analysis request ID
            repository: Repository name (owner/repo)
            pull_request_number: PR number
            overridden_by: Username of the person overriding
            reason: Reason for the override
            violations_count: Number of violations being overridden

        Returns:
            The override log entry ID, or None if creation failed
        """
        try:
            session = await get_async_session()
            async with session:
                override_entry = OverrideLog(
                    request_id=request_id,
                    repository=repository,
                    pull_request_number=pull_request_number,
                    overridden_by=overridden_by,
                    reason=reason,
                    violations_count=violations_count,
                    created_at=datetime.utcnow(),
                )

                session.add(override_entry)
                await session.commit()
                await session.refresh(override_entry)

                logger.info(
                    f"Override created: {request_id} - {repository} PR#{pull_request_number} "
                    f"by {overridden_by}"
                )

                return override_entry.id

        except SQLAlchemyError as e:
            logger.error(f"Failed to create override log: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error creating override: {e}")
            return None

    async def get_override(
        self,
        repository: str,
        pull_request_number: int,
    ) -> Optional[dict[str, Any]]:
        """Get the latest override for a PR.

        Args:
            repository: Repository name
            pull_request_number: PR number

        Returns:
            Override details if found, None otherwise
        """
        try:
            session = await get_async_session()
            async with session:
                query = (
                    select(OverrideLog)
                    .where(
                        OverrideLog.repository == repository,
                        OverrideLog.pull_request_number == pull_request_number,
                    )
                    .order_by(desc(OverrideLog.created_at))
                    .limit(1)
                )

                result = await session.execute(query)
                override = result.scalar_one_or_none()

                if override:
                    return {
                        "id": override.id,
                        "request_id": override.request_id,
                        "repository": override.repository,
                        "pull_request_number": override.pull_request_number,
                        "overridden_by": override.overridden_by,
                        "reason": override.reason,
                        "violations_count": override.violations_count,
                        "created_at": override.created_at.isoformat(),
                    }
                return None

        except SQLAlchemyError as e:
            logger.error(f"Failed to get override: {e}")
            return None

    async def get_overrides(
        self,
        repository: Optional[str] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> dict[str, Any]:
        """Get override logs with optional filtering.

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
                query = select(OverrideLog).order_by(desc(OverrideLog.created_at))

                if repository:
                    query = query.where(OverrideLog.repository == repository)

                # Get total count using SQL COUNT (more efficient than fetching all)
                from sqlalchemy import func
                count_query = select(func.count()).select_from(OverrideLog)
                if repository:
                    count_query = count_query.where(OverrideLog.repository == repository)

                # Apply pagination
                offset = (page - 1) * page_size
                query = query.offset(offset).limit(page_size)

                result = await session.execute(query)
                entries = result.scalars().all()

                count_result = await session.execute(count_query)
                total = count_result.scalar() or 0

                return {
                    "entries": [
                        {
                            "id": entry.id,
                            "request_id": entry.request_id,
                            "repository": entry.repository,
                            "pull_request_number": entry.pull_request_number,
                            "overridden_by": entry.overridden_by,
                            "reason": entry.reason,
                            "violations_count": entry.violations_count,
                            "created_at": entry.created_at.isoformat(),
                        }
                        for entry in entries
                    ],
                    "total": total,
                    "page": page,
                    "page_size": page_size,
                }

        except SQLAlchemyError as e:
            logger.error(f"Failed to get override logs: {e}")
            return {
                "entries": [],
                "total": 0,
                "page": page,
                "page_size": page_size,
            }

    async def check_override_exists(
        self,
        repository: str,
        pull_request_number: int,
    ) -> bool:
        """Check if an override exists for a PR.

        Args:
            repository: Repository name
            pull_request_number: PR number

        Returns:
            True if override exists, False otherwise
        """
        override = await self.get_override(repository, pull_request_number)
        return override is not None
