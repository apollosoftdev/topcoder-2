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
from ..rules.engine import RuleEngine
from .schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    AuditLogResponse,
    ErrorResponse,
    HealthResponse,
    RulePackInfo,
    RulePacksResponse,
    ViolationSchema,
)

logger = logging.getLogger(__name__)
router = APIRouter()

# Initialize services
rule_engine = RuleEngine()
analyzer = CodeAnalyzer(rule_engine)
audit_logger = AuditLogger()


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

        if result["enforcement_mode"] == "blocking":
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

        if result.get("copilot_detection", {}).get("detected"):
            summary_parts.append("AI-generated code indicators detected.")

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

        response = AnalyzeResponse(
            request_id=request_id,
            repository=request.repository,
            pull_request_number=request.pull_request_number,
            commit_sha=request.commit_sha,
            violations=violations,
            ai_review=result.get("ai_review"),
            copilot_detection=result.get("copilot_detection"),
            enforcement_action=result["enforcement_mode"],
            should_block=should_block,
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
        logger.error(f"Analysis failed: {e}")
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
        logger.error(f"Failed to retrieve audit logs: {e}")
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
