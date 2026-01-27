"""Claude AI integration for intelligent code review."""

import logging
from dataclasses import dataclass
from typing import Optional

from anthropic import Anthropic

from ..core.config import get_settings

logger = logging.getLogger(__name__)


@dataclass
class AIReviewResult:
    """Result from AI code review."""

    summary: str
    security_issues: list[dict]
    code_quality_issues: list[dict]
    recommendations: list[str]
    copilot_indicators: list[str]
    risk_score: int  # 0-100


SYSTEM_PROMPT = """You are an expert code security reviewer for enterprise software.
Your role is to analyze code changes and identify:

1. Security vulnerabilities (OWASP Top 10, CWE)
2. Code quality issues that could lead to security problems
3. Best practice violations
4. Signs of AI-generated code that may need extra scrutiny

Be thorough but avoid false positives. Focus on actual security risks.
Provide actionable recommendations with specific fixes.

When reviewing, consider:
- The context of the changes
- Enterprise compliance requirements
- Banking/healthcare regulatory standards when applicable
- Potential for data leaks or unauthorized access
"""

REVIEW_PROMPT_TEMPLATE = """Review the following code changes for security and quality issues.

Repository: {repository}
File(s) being changed: {files}

Code Diff:
```
{diff}
```

{context}

Analyze the code and provide your review in the following JSON format:
{{
    "summary": "Brief summary of findings (2-3 sentences)",
    "security_issues": [
        {{
            "severity": "critical|high|medium|low",
            "title": "Issue title",
            "description": "Detailed description",
            "file": "filename",
            "line": line_number_or_null,
            "cwe": "CWE-XXX or null",
            "owasp": "OWASP category or null",
            "recommendation": "How to fix"
        }}
    ],
    "code_quality_issues": [
        {{
            "severity": "high|medium|low",
            "title": "Issue title",
            "description": "Description",
            "file": "filename",
            "line": line_number_or_null,
            "recommendation": "How to fix"
        }}
    ],
    "recommendations": [
        "General recommendation 1",
        "General recommendation 2"
    ],
    "copilot_indicators": [
        "Indicator 1 (e.g., generic variable names, boilerplate patterns)",
        "Indicator 2"
    ],
    "risk_score": 0-100
}}

Important:
- Only report genuine issues, not style preferences
- Be specific about line numbers when possible
- Focus on security-relevant findings
- Include CWE/OWASP references for security issues
- Identify patterns that suggest AI-generated code (repetitive structures, generic naming, etc.)
- Risk score: 0=no risk, 100=critical security flaw

Return ONLY valid JSON, no markdown formatting or explanation outside the JSON.
"""


class AIReviewer:
    """Claude AI-powered code reviewer."""

    def __init__(self, api_key: Optional[str] = None):
        """Initialize the AI reviewer."""
        settings = get_settings()
        self.api_key = api_key or settings.anthropic_api_key
        self.model = settings.claude_model
        self.max_tokens = settings.claude_max_tokens

        if not self.api_key:
            logger.warning("No Anthropic API key configured - AI review disabled")
            self.client = None
        else:
            self.client = Anthropic(api_key=self.api_key)

    async def review(
        self,
        diff: str,
        repository: str,
        files: list[str],
        context: Optional[str] = None,
    ) -> Optional[AIReviewResult]:
        """Perform AI-powered code review.

        Args:
            diff: Git diff content
            repository: Repository name (owner/repo)
            files: List of files being changed
            context: Additional context (e.g., rule pack requirements)

        Returns:
            AIReviewResult with findings, or None if AI review unavailable
        """
        if not self.client:
            logger.warning("AI review skipped - no API client")
            return None

        # Truncate diff if too large
        settings = get_settings()
        if len(diff) > settings.max_diff_size:
            diff = diff[: settings.max_diff_size] + "\n... (truncated)"
            logger.warning("Diff truncated due to size")

        prompt = REVIEW_PROMPT_TEMPLATE.format(
            repository=repository,
            files=", ".join(files),
            diff=diff,
            context=context or "No additional context provided.",
        )

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )

            # Parse the response
            content = response.content[0].text
            return self._parse_response(content)

        except Exception as e:
            logger.error(f"AI review failed: {e}")
            return None

    def _parse_response(self, content: str) -> AIReviewResult:
        """Parse Claude's response into structured result."""
        import json

        # Try to extract JSON from the response
        try:
            # Handle potential markdown code blocks
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]

            data = json.loads(content.strip())

            return AIReviewResult(
                summary=data.get("summary", "No summary provided"),
                security_issues=data.get("security_issues", []),
                code_quality_issues=data.get("code_quality_issues", []),
                recommendations=data.get("recommendations", []),
                copilot_indicators=data.get("copilot_indicators", []),
                risk_score=min(100, max(0, data.get("risk_score", 0))),
            )

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse AI response: {e}")
            # Return a basic result with the raw summary
            return AIReviewResult(
                summary=content[:500] if content else "Failed to parse AI response",
                security_issues=[],
                code_quality_issues=[],
                recommendations=[],
                copilot_indicators=[],
                risk_score=0,
            )

    def detect_copilot_markers(self, diff: str) -> dict:
        """Detect indicators of AI-generated code.

        Args:
            diff: Git diff content

        Returns:
            Dict with copilot detection results
        """
        indicators = []
        confidence = 0

        # Check for Copilot commit message patterns
        copilot_patterns = [
            ("Co-authored-by: Copilot", "Copilot co-author signature"),
            ("Generated by GitHub Copilot", "Copilot generation marker"),
            ("copilot", "Copilot reference in code/comments"),
        ]

        for pattern, description in copilot_patterns:
            if pattern.lower() in diff.lower():
                indicators.append(description)
                confidence += 30

        # Check for common AI-generated code patterns
        ai_patterns = [
            # Generic/placeholder naming
            (r"\b(?:foo|bar|baz|temp|data|result|value)\d*\b", "Generic variable names"),
            # Repetitive structure
            (r"(?:\/\/ TODO|# TODO).*\n.*(?:\/\/ TODO|# TODO)", "Multiple TODO comments"),
            # Boilerplate comments
            (
                r"(?:\/\*\*|\"\"\"|''')\s*(?:This function|This method|This class)",
                "Boilerplate documentation",
            ),
        ]

        import re

        for pattern, description in ai_patterns:
            if re.search(pattern, diff, re.IGNORECASE):
                indicators.append(description)
                confidence += 10

        return {
            "detected": len(indicators) > 0,
            "confidence": min(100, confidence),
            "indicators": indicators,
        }
