"""API routes for the guardrails service."""

import logging
from datetime import datetime
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status

from ..core.config import get_settings
from ..core.security import verify_api_key
from ..services.analyzer import CodeAnalyzer
from ..services.audit_logger import AuditLogger
from ..services.override_service import OverrideService
from ..services.reporting_service import ReportingService
from ..rules.engine import RuleEngine
from .schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    AuditLogResponse,
    ErrorResponse,
    HealthResponse,
    OverrideCheckResponse,
    OverrideLogEntry,
    OverrideLogsResponse,
    OverrideRequest,
    OverrideResponse,
    RepositoryStat,
    RepositoryStatsResponse,
    RulePackInfo,
    RulePacksResponse,
    SummaryStats,
    TrendPoint,
    TrendsResponse,
    ViolationBreakdownResponse,
    ViolationSchema,
    ViolationStat,
)

logger = logging.getLogger(__name__)
router = APIRouter()

# Initialize services
rule_engine = RuleEngine()
analyzer = CodeAnalyzer(rule_engine)
audit_logger = AuditLogger()
reporting_service = ReportingService()
override_service = OverrideService()


@router.post(
    "/analyze",
    response_model=AnalyzeResponse,
    responses={
        400: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
    },
    summary="Analyze code for violations",
    description="Analyze code diff for security violations, quality issues, and AI-generated code markers",
)
async def analyze_code(
    request: AnalyzeRequest,
    _: bool = Depends(verify_api_key),
) -> AnalyzeResponse:
    """Analyze code changes for violations."""
    request_id = str(uuid4())
    logger.info(f"Analysis request {request_id} for {request.repository}")

    try:
        # Perform analysis
        result = await analyzer.analyze(
            diff=request.diff,
            repository=request.repository,
            files=request.files,
            config=request.config,
        )

        # Determine if we should block
        should_block = False
        critical_count = sum(
            1 for v in result["violations"] if v.severity == "critical"
        )
        high_count = sum(1 for v in result["violations"] if v.severity == "high")
        medium_count = sum(1 for v in result["violations"] if v.severity == "medium")

        # Check if AI-generated code with stricter enforcement
        copilot = result.get("copilot_detection")
        copilot_config = request.config.copilot_enforcement
        is_ai_code = (
            copilot_config.enabled
            and copilot
            and copilot.detected
            and copilot.confidence >= copilot_config.confidence_threshold
        )

        if result["enforcement_mode"] == "blocking":
            if is_ai_code and copilot_config.block_on_medium:
                # Stricter enforcement for AI-generated code
                should_block = critical_count > 0 or high_count > 0 or medium_count > 0
            else:
                should_block = critical_count > 0 or high_count > 0

        # Generate summary
        total_violations = len(result["violations"])
        summary_parts = []
        if total_violations == 0:
            summary_parts.append("No violations found.")
        else:
            summary_parts.append(f"Found {total_violations} violation(s).")
            if critical_count:
                summary_parts.append(f"{critical_count} critical.")
            if high_count:
                summary_parts.append(f"{high_count} high severity.")
            if medium_count:
                summary_parts.append(f"{medium_count} medium severity.")

        copilot_detection = result.get("copilot_detection")
        if copilot_detection and copilot_detection.detected:
            summary_parts.append("AI-generated code indicators detected.")
            if is_ai_code:
                summary_parts.append("Stricter enforcement applied.")

        # Convert violations to schema
        violations = [
            ViolationSchema(
                type=v.type,
                severity=v.severity,
                rule=v.rule,
                file=v.file,
                line=v.line,
                column=v.column,
                message=v.message,
                suggestion=v.suggestion,
                code_snippet=v.code_snippet,
                cwe=v.cwe,
                owasp=v.owasp,
            )
            for v in result["violations"]
        ]

        # Add license summary info to summary parts if available
        license_summary = result.get("license_summary")
        if license_summary:
            if license_summary.has_restricted_licenses:
                summary_parts.append("Restricted licenses detected!")
            elif license_summary.has_copyleft_licenses:
                summary_parts.append("Copyleft licenses detected.")

        response = AnalyzeResponse(
            request_id=request_id,
            repository=request.repository,
            pull_request_number=request.pull_request_number,
            commit_sha=request.commit_sha,
            violations=violations,
            ai_review=result.get("ai_review"),
            copilot_detection=result.get("copilot_detection"),
            license_summary=license_summary,
            enforcement_action=result["enforcement_mode"],
            should_block=should_block,
            ai_code_detected=is_ai_code,
            stricter_enforcement_applied=is_ai_code and copilot_config.enabled,
            summary=" ".join(summary_parts),
            analyzed_at=datetime.utcnow(),
        )

        # Log to audit
        await audit_logger.log_analysis(
            request_id=request_id,
            repository=request.repository,
            pull_request_number=request.pull_request_number,
            commit_sha=request.commit_sha,
            enforcement_mode=result["enforcement_mode"],
            violations_count=total_violations,
            critical_count=critical_count,
            high_count=high_count,
            blocked=should_block,
        )

        return response

    except Exception as e:
        logger.error(f"Analysis failed: {e}")  # nosemgrep: logging-error-without-handling
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


@router.get(
    "/audit-logs",
    response_model=AuditLogResponse,
    summary="Get audit logs",
    description="Retrieve audit logs with optional filtering",
)
async def get_audit_logs(
    repository: Optional[str] = Query(None, description="Filter by repository"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, description="Items per page"),
    _: bool = Depends(verify_api_key),
) -> AuditLogResponse:
    """Get audit log entries."""
    try:
        result = await audit_logger.get_logs(
            repository=repository,
            page=page,
            page_size=page_size,
        )
        return AuditLogResponse(**result)
    except Exception as e:
        # nosemgrep: python.lang.best-practice.logging-error-without-handling
        logger.error(f"Failed to retrieve audit logs: {e}")  # nosemgrep: logging-error-without-handling
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


@router.get(
    "/rule-packs",
    response_model=RulePacksResponse,
    summary="List available rule packs",
    description="Get information about all available rule packs",
)
async def list_rule_packs() -> RulePacksResponse:
    """List all available rule packs."""
    packs = []
    for pack in rule_engine.get_all_packs():
        packs.append(
            RulePackInfo(
                id=pack.id,
                name=pack.name,
                description=pack.description,
                version=pack.version,
                rules_count=len(pack.rules),
                enforcement_mode=pack.enforcement_mode.value,
            )
        )
    return RulePacksResponse(packs=packs)


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    description="Check the health status of the service",
)
async def health_check() -> HealthResponse:
    """Health check endpoint."""
    settings = get_settings()

    # Check database connection
    db_status = "connected"
    try:
        await audit_logger.check_connection()
    except Exception:
        db_status = "disconnected"

    # Check AI service
    ai_status = "available" if settings.anthropic_api_key else "not_configured"

    return HealthResponse(
        status="healthy",
        version=settings.app_version,
        database=db_status,
        ai_service=ai_status,
    )


# Dashboard & Reporting Endpoints

@router.get(
    "/stats/summary",
    response_model=SummaryStats,
    summary="Get summary statistics",
    description="Get aggregated statistics for the dashboard",
)
async def get_stats_summary(
    days: int = Query(30, ge=1, le=365, description="Number of days to include"),
    repository: Optional[str] = Query(None, description="Filter by repository"),
    _: bool = Depends(verify_api_key),
) -> SummaryStats:
    """Get summary statistics for dashboard."""
    try:
        result = await reporting_service.get_summary(
            repository=repository,
            days=days,
        )
        return SummaryStats(**result)
    except Exception as e:
        # nosemgrep: python.lang.best-practice.logging-error-without-handling
        logger.error(f"Failed to get summary stats: {e}")  # nosemgrep: logging-error-without-handling
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


@router.get(
    "/stats/trends",
    response_model=TrendsResponse,
    summary="Get trend data",
    description="Get trend data over time for charts",
)
async def get_stats_trends(
    interval: str = Query("day", description="Time interval (day, week, month)"),
    periods: int = Query(30, ge=1, le=365, description="Number of periods"),
    repository: Optional[str] = Query(None, description="Filter by repository"),
    _: bool = Depends(verify_api_key),
) -> TrendsResponse:
    """Get trend data over time."""
    if interval not in ["day", "week", "month"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid interval. Must be 'day', 'week', or 'month'",
        )

    try:
        trends = await reporting_service.get_trends(
            interval=interval,
            periods=periods,
            repository=repository,
        )
        return TrendsResponse(
            trends=[TrendPoint(**t) for t in trends],
            interval=interval,
            periods=periods,
        )
    except Exception as e:
        # nosemgrep: python.lang.best-practice.logging-error-without-handling
        logger.error(f"Failed to get trends: {e}")  # nosemgrep: logging-error-without-handling
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


@router.get(
    "/stats/violations",
    response_model=ViolationBreakdownResponse,
    summary="Get violation breakdown",
    description="Get violation statistics grouped by category",
)
async def get_violation_breakdown(
    group_by: str = Query("severity", description="Field to group by (severity, repository, enforcement_mode)"),
    days: int = Query(30, ge=1, le=365, description="Number of days to include"),
    repository: Optional[str] = Query(None, description="Filter by repository"),
    _: bool = Depends(verify_api_key),
) -> ViolationBreakdownResponse:
    """Get violation breakdown by category."""
    if group_by not in ["severity", "repository", "enforcement_mode"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid group_by. Must be 'severity', 'repository', or 'enforcement_mode'",
        )

    try:
        breakdown = await reporting_service.get_violation_breakdown(
            group_by=group_by,
            repository=repository,
            days=days,
        )
        return ViolationBreakdownResponse(
            breakdown=[ViolationStat(**b) for b in breakdown],
            group_by=group_by,
            period_days=days,
        )
    except Exception as e:
        # nosemgrep: python.lang.best-practice.logging-error-without-handling
        logger.error(f"Failed to get violation breakdown: {e}")  # nosemgrep: logging-error-without-handling
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


@router.get(
    "/stats/repositories",
    response_model=RepositoryStatsResponse,
    summary="Get repository statistics",
    description="Get statistics per repository",
)
async def get_repository_stats(
    limit: int = Query(20, ge=1, le=100, description="Maximum repositories to return"),
    days: int = Query(30, ge=1, le=365, description="Number of days to include"),
    _: bool = Depends(verify_api_key),
) -> RepositoryStatsResponse:
    """Get statistics per repository."""
    try:
        repositories = await reporting_service.get_repository_stats(
            limit=limit,
            days=days,
        )
        return RepositoryStatsResponse(
            repositories=[RepositoryStat(**r) for r in repositories],
            period_days=days,
        )
    except Exception as e:
        # nosemgrep: python.lang.best-practice.logging-error-without-handling
        logger.error(f"Failed to get repository stats: {e}")  # nosemgrep: logging-error-without-handling
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


# Override Endpoints

@router.post(
    "/override",
    response_model=OverrideResponse,
    summary="Override a blocking decision",
    description="Allow authorized users to override a blocking decision on a PR",
)
async def create_override(
    request: OverrideRequest,
    _: bool = Depends(verify_api_key),
) -> OverrideResponse:
    """Create an override for a blocked PR."""
    try:
        override_id = await override_service.create_override(
            request_id=request.request_id,
            repository=request.repository,
            pull_request_number=request.pull_request_number,
            overridden_by=request.overridden_by,
            reason=request.reason,
            violations_count=request.violations_count,
        )

        if override_id:
            return OverrideResponse(
                success=True,
                override_id=override_id,
                message="Override created successfully",
                repository=request.repository,
                pull_request_number=request.pull_request_number,
                overridden_by=request.overridden_by,
                created_at=datetime.utcnow(),
            )
        else:
            return OverrideResponse(
                success=False,
                message="Failed to create override",
                repository=request.repository,
                pull_request_number=request.pull_request_number,
                overridden_by=request.overridden_by,
            )

    except Exception as e:
        # nosemgrep: python.lang.best-practice.logging-error-without-handling
        logger.error(f"Failed to create override: {e}")  # nosemgrep: logging-error-without-handling
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


@router.get(
    "/override/{repository:path}/pr/{pull_request_number}",
    response_model=OverrideCheckResponse,
    summary="Check if override exists",
    description="Check if an override exists for a specific PR",
)
async def check_override(
    repository: str,
    pull_request_number: int,
    _: bool = Depends(verify_api_key),
) -> OverrideCheckResponse:
    """Check if an override exists for a PR."""
    try:
        override = await override_service.get_override(
            repository=repository,
            pull_request_number=pull_request_number,
        )

        if override:
            return OverrideCheckResponse(
                has_override=True,
                override=OverrideLogEntry(
                    id=override["id"],
                    request_id=override["request_id"],
                    repository=override["repository"],
                    pull_request_number=override["pull_request_number"],
                    overridden_by=override["overridden_by"],
                    reason=override["reason"],
                    violations_count=override["violations_count"],
                    created_at=datetime.fromisoformat(override["created_at"]),
                ),
            )
        else:
            return OverrideCheckResponse(has_override=False)

    except Exception as e:
        # nosemgrep: python.lang.best-practice.logging-error-without-handling
        logger.error(f"Failed to check override: {e}")  # nosemgrep: logging-error-without-handling
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


@router.get(
    "/overrides",
    response_model=OverrideLogsResponse,
    summary="Get override logs",
    description="Retrieve override logs with optional filtering",
)
async def get_override_logs(
    repository: Optional[str] = Query(None, description="Filter by repository"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, description="Items per page"),
    _: bool = Depends(verify_api_key),
) -> OverrideLogsResponse:
    """Get override log entries."""
    try:
        result = await override_service.get_overrides(
            repository=repository,
            page=page,
            page_size=page_size,
        )

        return OverrideLogsResponse(
            entries=[
                OverrideLogEntry(
                    id=entry["id"],
                    request_id=entry["request_id"],
                    repository=entry["repository"],
                    pull_request_number=entry["pull_request_number"],
                    overridden_by=entry["overridden_by"],
                    reason=entry["reason"],
                    violations_count=entry["violations_count"],
                    created_at=datetime.fromisoformat(entry["created_at"]),
                )
                for entry in result["entries"]
            ],
            total=result["total"],
            page=result["page"],
            page_size=result["page_size"],
        )
    except Exception as e:
        # nosemgrep: python.lang.best-practice.logging-error-without-handling
        logger.error(f"Failed to retrieve override logs: {e}")  # nosemgrep: logging-error-without-handling
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )
