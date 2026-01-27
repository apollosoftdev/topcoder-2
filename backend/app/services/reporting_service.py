"""Reporting service for dashboard statistics and organization-level insights."""

import logging
from datetime import datetime, timedelta
from typing import Any, Optional

from sqlalchemy import func, select, and_
from sqlalchemy.exc import SQLAlchemyError

from ..models.audit import AuditLog, get_async_session

logger = logging.getLogger(__name__)


class ReportingService:
    """Service for generating statistics and reports from audit data."""

    async def get_summary(
        self,
        repository: Optional[str] = None,
        days: int = 30,
    ) -> dict[str, Any]:
        """Get summary statistics.

        Args:
            repository: Filter by repository name (optional)
            days: Number of days to include in summary

        Returns:
            Summary statistics dictionary
        """
        try:
            session = await get_async_session()
            async with session:
                start_date = datetime.utcnow() - timedelta(days=days)

                # Base filter
                filters = [AuditLog.timestamp >= start_date]
                if repository:
                    filters.append(AuditLog.repository == repository)

                # Total analyses
                total_query = select(func.count(AuditLog.id)).where(and_(*filters))
                total_result = await session.execute(total_query)
                total_analyses = total_result.scalar() or 0

                # Total violations
                violations_query = select(func.sum(AuditLog.violations_count)).where(and_(*filters))
                violations_result = await session.execute(violations_query)
                total_violations = violations_result.scalar() or 0

                # Total blocked
                blocked_query = select(func.count(AuditLog.id)).where(
                    and_(*filters, AuditLog.blocked == True)
                )
                blocked_result = await session.execute(blocked_query)
                total_blocked = blocked_result.scalar() or 0

                # Block rate
                block_rate = (total_blocked / total_analyses * 100) if total_analyses > 0 else 0.0

                # Violations by severity
                critical_query = select(func.sum(AuditLog.critical_count)).where(and_(*filters))
                critical_result = await session.execute(critical_query)
                critical_count = critical_result.scalar() or 0

                high_query = select(func.sum(AuditLog.high_count)).where(and_(*filters))
                high_result = await session.execute(high_query)
                high_count = high_result.scalar() or 0

                # Calculate medium/low (total - critical - high)
                other_count = max(0, total_violations - critical_count - high_count)

                return {
                    "total_analyses": total_analyses,
                    "total_violations": total_violations,
                    "total_blocked": total_blocked,
                    "block_rate": round(block_rate, 2),
                    "violations_by_severity": {
                        "critical": critical_count,
                        "high": high_count,
                        "medium_low": other_count,
                    },
                    "period_days": days,
                    "repository": repository,
                }

        except SQLAlchemyError as e:
            logger.error(f"Failed to get summary stats: {e}")
            return {
                "total_analyses": 0,
                "total_violations": 0,
                "total_blocked": 0,
                "block_rate": 0.0,
                "violations_by_severity": {"critical": 0, "high": 0, "medium_low": 0},
                "period_days": days,
                "repository": repository,
            }

    async def get_trends(
        self,
        interval: str = "day",
        periods: int = 30,
        repository: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Get trend data over time.

        Args:
            interval: Time interval ('day', 'week', 'month')
            periods: Number of periods to return
            repository: Filter by repository name (optional)

        Returns:
            List of trend data points
        """
        try:
            session = await get_async_session()
            async with session:
                # Calculate interval duration
                if interval == "week":
                    delta = timedelta(weeks=1)
                elif interval == "month":
                    delta = timedelta(days=30)
                else:
                    delta = timedelta(days=1)

                trends = []
                end_date = datetime.utcnow()

                for i in range(periods):
                    period_end = end_date - (delta * i)
                    period_start = period_end - delta

                    filters = [
                        AuditLog.timestamp >= period_start,
                        AuditLog.timestamp < period_end,
                    ]
                    if repository:
                        filters.append(AuditLog.repository == repository)

                    # Count analyses
                    analyses_query = select(func.count(AuditLog.id)).where(and_(*filters))
                    analyses_result = await session.execute(analyses_query)
                    analyses = analyses_result.scalar() or 0

                    # Sum violations
                    violations_query = select(func.sum(AuditLog.violations_count)).where(and_(*filters))
                    violations_result = await session.execute(violations_query)
                    violations = violations_result.scalar() or 0

                    # Count blocked
                    blocked_query = select(func.count(AuditLog.id)).where(
                        and_(*filters, AuditLog.blocked == True)
                    )
                    blocked_result = await session.execute(blocked_query)
                    blocked = blocked_result.scalar() or 0

                    trends.append({
                        "date": period_start.strftime("%Y-%m-%d"),
                        "analyses": analyses,
                        "violations": violations,
                        "blocked": blocked,
                    })

                # Return in chronological order
                return list(reversed(trends))

        except SQLAlchemyError as e:
            logger.error(f"Failed to get trends: {e}")
            return []

    async def get_violation_breakdown(
        self,
        group_by: str = "severity",
        repository: Optional[str] = None,
        days: int = 30,
    ) -> list[dict[str, Any]]:
        """Get violation breakdown by category.

        Args:
            group_by: Field to group by ('severity', 'repository', 'enforcement_mode')
            repository: Filter by repository name (optional)
            days: Number of days to include

        Returns:
            List of violation statistics grouped by category
        """
        try:
            session = await get_async_session()
            async with session:
                start_date = datetime.utcnow() - timedelta(days=days)

                filters = [AuditLog.timestamp >= start_date]
                if repository:
                    filters.append(AuditLog.repository == repository)

                if group_by == "severity":
                    # Get severity breakdown
                    critical_query = select(func.sum(AuditLog.critical_count)).where(and_(*filters))
                    critical_result = await session.execute(critical_query)
                    critical = critical_result.scalar() or 0

                    high_query = select(func.sum(AuditLog.high_count)).where(and_(*filters))
                    high_result = await session.execute(high_query)
                    high = high_result.scalar() or 0

                    total_query = select(func.sum(AuditLog.violations_count)).where(and_(*filters))
                    total_result = await session.execute(total_query)
                    total = total_result.scalar() or 0

                    other = max(0, total - critical - high)

                    return [
                        {"category": "critical", "count": critical, "percentage": round(critical / total * 100, 2) if total > 0 else 0},
                        {"category": "high", "count": high, "percentage": round(high / total * 100, 2) if total > 0 else 0},
                        {"category": "medium_low", "count": other, "percentage": round(other / total * 100, 2) if total > 0 else 0},
                    ]

                elif group_by == "repository":
                    # Group by repository
                    query = (
                        select(
                            AuditLog.repository,
                            func.count(AuditLog.id).label("analyses"),
                            func.sum(AuditLog.violations_count).label("violations"),
                        )
                        .where(and_(*filters))
                        .group_by(AuditLog.repository)
                        .order_by(func.sum(AuditLog.violations_count).desc())
                    )
                    result = await session.execute(query)
                    rows = result.all()

                    return [
                        {"category": row.repository, "count": row.violations or 0, "analyses": row.analyses}
                        for row in rows
                    ]

                elif group_by == "enforcement_mode":
                    # Group by enforcement mode
                    query = (
                        select(
                            AuditLog.enforcement_mode,
                            func.count(AuditLog.id).label("analyses"),
                            func.sum(AuditLog.violations_count).label("violations"),
                        )
                        .where(and_(*filters))
                        .group_by(AuditLog.enforcement_mode)
                    )
                    result = await session.execute(query)
                    rows = result.all()

                    return [
                        {"category": row.enforcement_mode, "count": row.violations or 0, "analyses": row.analyses}
                        for row in rows
                    ]

                return []

        except SQLAlchemyError as e:
            logger.error(f"Failed to get violation breakdown: {e}")
            return []

    async def get_repository_stats(
        self,
        limit: int = 20,
        days: int = 30,
    ) -> list[dict[str, Any]]:
        """Get statistics per repository.

        Args:
            limit: Maximum number of repositories to return
            days: Number of days to include

        Returns:
            List of repository statistics
        """
        try:
            session = await get_async_session()
            async with session:
                start_date = datetime.utcnow() - timedelta(days=days)

                query = (
                    select(
                        AuditLog.repository,
                        func.count(AuditLog.id).label("total_analyses"),
                        func.sum(AuditLog.violations_count).label("total_violations"),
                        func.sum(AuditLog.critical_count).label("critical_violations"),
                        func.sum(AuditLog.high_count).label("high_violations"),
                        func.count(AuditLog.id).filter(AuditLog.blocked == True).label("blocked_count"),
                    )
                    .where(AuditLog.timestamp >= start_date)
                    .group_by(AuditLog.repository)
                    .order_by(func.sum(AuditLog.violations_count).desc())
                    .limit(limit)
                )

                result = await session.execute(query)
                rows = result.all()

                return [
                    {
                        "repository": row.repository,
                        "total_analyses": row.total_analyses,
                        "total_violations": row.total_violations or 0,
                        "critical_violations": row.critical_violations or 0,
                        "high_violations": row.high_violations or 0,
                        "blocked_count": row.blocked_count or 0,
                        "block_rate": round((row.blocked_count or 0) / row.total_analyses * 100, 2) if row.total_analyses > 0 else 0,
                    }
                    for row in rows
                ]

        except SQLAlchemyError as e:
            logger.error(f"Failed to get repository stats: {e}")
            return []
