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


class CopilotEnforcementConfig(BaseModel):
    """Configuration for stricter enforcement on AI-generated code."""

    enabled: bool = True
    escalate_medium_to_high: bool = True  # Treat medium as high for AI code
    block_on_medium: bool = True  # Block on medium violations for AI code
    confidence_threshold: int = Field(default=60, ge=0, le=100)  # Min confidence to trigger stricter enforcement


class AnalysisConfig(BaseModel):
    """Configuration for code analysis."""

    enforcement_mode: EnforcementMode = EnforcementMode.WARNING
    rule_packs: list[str] = Field(default=["security"])
    custom_rules: Optional[str] = None  # YAML content for custom rules
    ai_review_enabled: bool = True
    copilot_detection_enabled: bool = True
    copilot_enforcement: CopilotEnforcementConfig = Field(default_factory=CopilotEnforcementConfig)


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

    type: str = Field(..., description="Violation type (security, quality, license, ip, etc.)")
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
    license_type: Optional[str] = Field(None, description="License type if this is a license violation")


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


class LicenseInfo(BaseModel):
    """Information about a detected license."""

    count: int
    severity: str
    files: list[str]


class LicenseSummary(BaseModel):
    """Summary of license and IP compliance analysis."""

    total_license_violations: int = 0
    total_ip_violations: int = 0
    licenses_found: dict[str, LicenseInfo] = {}
    has_restricted_licenses: bool = False
    has_copyleft_licenses: bool = False


class AnalyzeResponse(BaseModel):
    """Response from code analysis."""

    request_id: str
    repository: str
    pull_request_number: Optional[int] = None
    commit_sha: Optional[str] = None
    violations: list[ViolationSchema] = []
    ai_review: Optional[AIReviewSchema] = None
    copilot_detection: Optional[CopilotDetection] = None
    license_summary: Optional[LicenseSummary] = None
    enforcement_action: EnforcementMode
    should_block: bool = Field(default=False, description="Whether to block merge")
    ai_code_detected: bool = Field(default=False, description="Whether AI-generated code was detected with high confidence")
    stricter_enforcement_applied: bool = Field(default=False, description="Whether stricter enforcement was applied due to AI code")
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


# Dashboard & Reporting Schemas

class SummaryStats(BaseModel):
    """Summary statistics for dashboard."""

    total_analyses: int
    total_violations: int
    total_blocked: int
    block_rate: float = Field(description="Percentage of analyses that resulted in blocking")
    violations_by_severity: dict[str, int]
    period_days: int
    repository: Optional[str] = None


class TrendPoint(BaseModel):
    """Single data point in a trend series."""

    date: str
    analyses: int
    violations: int
    blocked: int


class TrendsResponse(BaseModel):
    """Response containing trend data."""

    trends: list[TrendPoint]
    interval: str
    periods: int


class ViolationStat(BaseModel):
    """Violation statistic by category."""

    category: str
    count: int
    percentage: Optional[float] = None
    analyses: Optional[int] = None


class ViolationBreakdownResponse(BaseModel):
    """Response containing violation breakdown."""

    breakdown: list[ViolationStat]
    group_by: str
    period_days: int


class RepositoryStat(BaseModel):
    """Statistics for a single repository."""

    repository: str
    total_analyses: int
    total_violations: int
    critical_violations: int
    high_violations: int
    blocked_count: int
    block_rate: float


class RepositoryStatsResponse(BaseModel):
    """Response containing repository statistics."""

    repositories: list[RepositoryStat]
    period_days: int


# Override Schemas

class OverrideRequest(BaseModel):
    """Request to override a blocking decision."""

    repository: str = Field(..., description="Repository name (owner/repo)")
    pull_request_number: int = Field(..., description="PR number")
    request_id: str = Field(..., description="Original analysis request ID")
    overridden_by: str = Field(..., description="Username of the person overriding")
    reason: str = Field(..., min_length=10, description="Reason for the override (min 10 characters)")
    violations_count: int = Field(default=0, ge=0, description="Number of violations being overridden")


class OverrideResponse(BaseModel):
    """Response from override request."""

    success: bool
    override_id: Optional[int] = None
    message: str
    repository: str
    pull_request_number: int
    overridden_by: str
    created_at: Optional[datetime] = None


class OverrideLogEntry(BaseModel):
    """Override log entry schema."""

    id: int
    request_id: str
    repository: str
    pull_request_number: int
    overridden_by: str
    reason: str
    violations_count: int
    created_at: datetime


class OverrideLogsResponse(BaseModel):
    """Response for override log queries."""

    entries: list[OverrideLogEntry]
    total: int
    page: int
    page_size: int


class OverrideCheckResponse(BaseModel):
    """Response for checking if an override exists."""

    has_override: bool
    override: Optional[OverrideLogEntry] = None
