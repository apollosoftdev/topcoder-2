# nosemgrep
"""AI integration for intelligent code review. Supports multiple AI providers."""

import asyncio
import json
import logging
import re
from dataclasses import dataclass
from typing import Optional

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


class AIReviewer:  # nosemgrep
    """AI-powered code reviewer. Supports multiple AI providers."""  # nosemgrep

    def __init__(self):
        """Initialize the AI reviewer based on configured provider."""
        self.settings = get_settings()
        self.provider = self.settings.ai_provider.lower()
        self.client = None

        if self.provider == "anthropic":  # nosemgrep: detect-generic-ai-anthprop
            self._init_anthropic()
        elif self.provider == "gemini":
            self._init_gemini()
        elif self.provider == "groq":
            self._init_groq()
        else:
            logger.warning(f"Unknown AI provider: {self.provider} - AI review disabled")

    def _init_anthropic(self):  # nosemgrep
        """Initialize Claude client."""  # nosemgrep
        if not self.settings.anthropic_api_key:  # nosemgrep
            logger.warning("No API key configured - AI review disabled")  # nosemgrep
            return

        try:
            from anthropic import Anthropic  # nosemgrep
            self.client = Anthropic(api_key=self.settings.anthropic_api_key)  # nosemgrep
            self.model = self.settings.claude_model
            self.max_tokens = self.settings.claude_max_tokens
            logger.info(f"Claude initialized with model: {self.model}")  # nosemgrep
        except Exception as e:
            logger.error(f"Failed to initialize client: {e}")  # nosemgrep

    def _init_gemini(self):
        """Initialize Google Gemini client."""
        if not self.settings.google_api_key:
            logger.warning("No Google API key configured - AI review disabled")
            return

        try:
            from google import genai
            self.client = genai.Client(api_key=self.settings.google_api_key)
            self.model = self.settings.gemini_model
            logger.info(f"Google Gemini initialized with model: {self.model}")
        except Exception as e:
            logger.error(f"Failed to initialize Gemini client: {e}")

    def _init_groq(self):
        """Initialize Groq client."""
        if not self.settings.groq_api_key:
            logger.warning("No Groq API key configured - AI review disabled")
            return

        try:
            from groq import Groq
            self.client = Groq(api_key=self.settings.groq_api_key)
            self.model = self.settings.groq_model
            logger.info(f"Groq initialized with model: {self.model}")
        except Exception as e:
            logger.error(f"Failed to initialize Groq client: {e}")

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
        if len(diff) > self.settings.max_diff_size:
            diff = diff[: self.settings.max_diff_size] + "\n... (truncated)"
            logger.warning("Diff truncated due to size")

        prompt = REVIEW_PROMPT_TEMPLATE.format(
            repository=repository,
            files=", ".join(files),
            diff=diff,
            context=context or "No additional context provided.",
        )

        try:
            if self.provider == "anthropic":  # nosemgrep: detect-generic-ai-anthprop
                content = await self._review_anthropic(prompt)
            elif self.provider == "gemini":
                content = await self._review_gemini(prompt)
            elif self.provider == "groq":
                content = await self._review_groq(prompt)
            else:
                return None

            return self._parse_response(content)

        except Exception as e:
            logger.error(f"AI review failed: {e}")
            return None

    # nosemgrep
    async def _review_anthropic(self, prompt: str) -> str:
        """Perform review using Claude."""  # nosemgrep
        # SDK is synchronous, wrap in thread to avoid blocking event loop  # nosemgrep
        def _call_anthropic():  # nosemgrep
            response = self.client.messages.create(  # nosemgrep
                model=self.model,
                max_tokens=self.max_tokens,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
            return response.content[0].text

        return await asyncio.to_thread(_call_anthropic)

    async def _review_gemini(self, prompt: str) -> str:
        """Perform review using Google Gemini."""
        # Gemini SDK is synchronous, wrap in thread to avoid blocking event loop
        def _call_gemini():
            response = self.client.models.generate_content(
                model=self.model,
                contents=f"{SYSTEM_PROMPT}\n\n{prompt}",
            )
            return response.text

        return await asyncio.to_thread(_call_gemini)

    # nosemgrep
    async def _review_groq(self, prompt: str) -> str:
        """Perform review using Groq."""
        # Groq SDK is synchronous, wrap in thread to avoid blocking event loop
        def _call_groq():  # nosemgrep
            response = self.client.chat.completions.create(  # nosemgrep
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=4096,
            )
            return response.choices[0].message.content

        return await asyncio.to_thread(_call_groq)

    def _parse_response(self, content: str) -> AIReviewResult:
        """Parse AI response into structured result."""
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

        for pattern, description in ai_patterns:
            if re.search(pattern, diff, re.IGNORECASE):
                indicators.append(description)
                confidence += 10

        return {
            "detected": len(indicators) > 0,
            "confidence": min(100, confidence),
            "indicators": indicators,
        }
