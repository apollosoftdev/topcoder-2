"""Pydantic schemas for API request/response models."""

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class EnforcementMode(str, Enum):
    """Policy enforcement modes."""

    ADVISORY = "advisory"
    WARNING = "warning"
    BLOCKING = "blocking"


class AnalysisConfig(BaseModel):
    """Configuration for code analysis."""

    enforcement_mode: EnforcementMode = EnforcementMode.WARNING
    rule_packs: list[str] = Field(default=["security"])
    custom_rules: Optional[str] = None  # YAML content for custom rules
    ai_review_enabled: bool = True
    copilot_detection_enabled: bool = True


class AnalyzeRequest(BaseModel):
    """Request to analyze code changes."""

    repository: str = Field(..., description="Repository name (owner/repo)")
    pull_request_number: Optional[int] = Field(None, description="PR number if applicable")
    commit_sha: Optional[str] = Field(None, description="Commit SHA being analyzed")
    diff: str = Field(..., description="Git diff content to analyze")
    files: list[str] = Field(default=[], description="List of files in the diff")
    config: AnalysisConfig = Field(default_factory=AnalysisConfig)


class ViolationSchema(BaseModel):
    """Schema for a detected violation."""

    type: str = Field(..., description="Violation type (security, quality, etc.)")
    severity: str = Field(..., description="Severity level")
    rule: str = Field(..., description="Rule ID that triggered the violation")
    file: str = Field(..., description="File where violation was found")
    line: int = Field(..., description="Line number")
    column: int = Field(default=0, description="Column number")
    message: str = Field(..., description="Violation message")
    suggestion: str = Field(default="", description="Suggested fix")
    code_snippet: str = Field(default="", description="Code snippet around violation")
    cwe: Optional[str] = Field(None, description="CWE identifier")
    owasp: Optional[str] = Field(None, description="OWASP category")


class AISecurityIssue(BaseModel):
    """Security issue identified by AI review."""

    severity: str
    title: str
    description: str
    file: Optional[str] = None
    line: Optional[int] = None
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    recommendation: str


class AICodeQualityIssue(BaseModel):
    """Code quality issue identified by AI review."""

    severity: str
    title: str
    description: str
    file: Optional[str] = None
    line: Optional[int] = None
    recommendation: str


class AIReviewSchema(BaseModel):
    """AI review results."""

    summary: str
    security_issues: list[AISecurityIssue] = []
    code_quality_issues: list[AICodeQualityIssue] = []
    recommendations: list[str] = []
    copilot_indicators: list[str] = []
    risk_score: int = Field(default=0, ge=0, le=100)


class CopilotDetection(BaseModel):
    """Copilot/AI-generated code detection results."""

    detected: bool
    confidence: int = Field(default=0, ge=0, le=100)
    indicators: list[str] = []


class AnalyzeResponse(BaseModel):
    """Response from code analysis."""

    request_id: str
    repository: str
    pull_request_number: Optional[int] = None
    commit_sha: Optional[str] = None
    violations: list[ViolationSchema] = []
    ai_review: Optional[AIReviewSchema] = None
    copilot_detection: Optional[CopilotDetection] = None
    enforcement_action: EnforcementMode
    should_block: bool = Field(default=False, description="Whether to block merge")
    summary: str = Field(default="", description="Summary of findings")
    analyzed_at: datetime = Field(default_factory=datetime.utcnow)


class AuditLogEntry(BaseModel):
    """Audit log entry schema."""

    id: str
    timestamp: datetime
    repository: str
    pull_request_number: Optional[int] = None
    commit_sha: Optional[str] = None
    action: str
    enforcement_mode: str
    violations_count: int
    critical_count: int
    high_count: int
    blocked: bool
    user: Optional[str] = None
    metadata: dict[str, Any] = {}


class AuditLogResponse(BaseModel):
    """Response for audit log queries."""

    entries: list[AuditLogEntry]
    total: int
    page: int
    page_size: int


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = "healthy"
    version: str
    database: str = "connected"
    ai_service: str = "available"


class ErrorResponse(BaseModel):
    """Error response schema."""

    error: str
    detail: Optional[str] = None
    code: Optional[str] = None


class RulePackInfo(BaseModel):
    """Information about a rule pack."""

    id: str
    name: str
    description: str
    version: str
    rules_count: int
    enforcement_mode: str


class RulePacksResponse(BaseModel):
    """Response listing available rule packs."""

    packs: list[RulePackInfo]
