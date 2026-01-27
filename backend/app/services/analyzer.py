"""Main analysis orchestrator service."""

import logging
from typing import Any, Optional

from ..api.schemas import (
    AICodeQualityIssue,
    AIReviewSchema,
    AISecurityIssue,
    AnalysisConfig,
    CopilotDetection,
    LicenseInfo,
    LicenseSummary,
)
from ..rules.engine import RuleEngine
from .ai_review import AIReviewer
from .license_analyzer import LicenseAnalyzer
from .static_analysis import StaticAnalyzer, Violation

logger = logging.getLogger(__name__)


class CodeAnalyzer:
    """Orchestrates code analysis using multiple analysis methods."""

    def __init__(self, rule_engine: Optional[RuleEngine] = None):
        """Initialize the analyzer.

        Args:
            rule_engine: Optional RuleEngine instance
        """
        self.rule_engine = rule_engine or RuleEngine()
        self.static_analyzer = StaticAnalyzer()
        self.ai_reviewer = AIReviewer()
        self.license_analyzer = LicenseAnalyzer()

    async def analyze(
        self,
        diff: str,
        repository: str,
        files: list[str],
        config: AnalysisConfig,
    ) -> dict[str, Any]:
        """Perform comprehensive code analysis.

        Args:
            diff: Git diff content
            repository: Repository name (owner/repo)
            files: List of files being changed
            config: Analysis configuration

        Returns:
            Dictionary with analysis results
        """
        logger.info(f"Starting analysis for {repository} with packs: {config.rule_packs}")

        violations: list[Violation] = []
        ai_review: Optional[AIReviewSchema] = None
        copilot_detection: Optional[CopilotDetection] = None
        license_summary: Optional[LicenseSummary] = None

        # Load custom rules if provided
        if config.custom_rules:
            try:
                self.rule_engine.load_custom_rules(config.custom_rules)
            except Exception as e:
                logger.error(f"Failed to load custom rules: {e}")

        # Determine enforcement mode from rule packs
        enforcement_mode = self.rule_engine.get_enforcement_mode(config.rule_packs)

        # Run static analysis
        try:
            static_violations = self.static_analyzer.analyze_diff(diff)
            violations.extend(static_violations)
            logger.info(f"Static analysis found {len(static_violations)} violations")
        except Exception as e:
            logger.error(f"Static analysis failed: {e}")

        # Run rule-based analysis
        try:
            rule_violations = self._run_rule_analysis(diff, config.rule_packs)
            violations.extend(rule_violations)
            logger.info(f"Rule analysis found {len(rule_violations)} violations")
        except Exception as e:
            logger.error(f"Rule analysis failed: {e}")

        # Deduplicate violations
        violations = self._deduplicate_violations(violations)

        # Run AI review if enabled
        if config.ai_review_enabled:
            try:
                # Build context for AI review
                context = self._build_ai_context(config.rule_packs, violations)

                ai_result = await self.ai_reviewer.review(
                    diff=diff,
                    repository=repository,
                    files=files,
                    context=context,
                )

                if ai_result:
                    ai_review = AIReviewSchema(
                        summary=ai_result.summary,
                        security_issues=[
                            AISecurityIssue(**issue) for issue in ai_result.security_issues
                        ],
                        code_quality_issues=[
                            AICodeQualityIssue(**issue)
                            for issue in ai_result.code_quality_issues
                        ],
                        recommendations=ai_result.recommendations,
                        copilot_indicators=ai_result.copilot_indicators,
                        risk_score=ai_result.risk_score,
                    )
                    logger.info(f"AI review completed with risk score: {ai_result.risk_score}")
            except Exception as e:
                logger.error(f"AI review failed: {e}")

        # Run Copilot detection if enabled
        if config.copilot_detection_enabled:
            try:
                copilot_result = self.ai_reviewer.detect_copilot_markers(diff)
                copilot_detection = CopilotDetection(
                    detected=copilot_result["detected"],
                    confidence=copilot_result["confidence"],
                    indicators=copilot_result["indicators"],
                )

                # Add AI review's copilot indicators if available
                if ai_review and ai_review.copilot_indicators:
                    copilot_detection.indicators.extend(ai_review.copilot_indicators)
                    copilot_detection.detected = True
                    copilot_detection.confidence = min(
                        100, copilot_detection.confidence + 20
                    )

                logger.info(
                    f"Copilot detection: {copilot_detection.detected} "
                    f"({copilot_detection.confidence}% confidence)"
                )
            except Exception as e:
                logger.error(f"Copilot detection failed: {e}")

        # Run license analysis if license pack is enabled
        if "license" in config.rule_packs:
            try:
                license_violations = self.license_analyzer.analyze_diff(diff)

                # Convert license violations to standard Violation objects
                for lv in license_violations:
                    violation = Violation(
                        type=lv.type,
                        severity=lv.severity,
                        rule=f"lic-{lv.type}-{lv.license_type or 'unknown'}".lower().replace(" ", "-"),
                        file=lv.file,
                        line=lv.line,
                        column=0,
                        message=lv.message,
                        suggestion=lv.suggestion,
                        code_snippet=lv.code_snippet,
                        cwe=None,
                        owasp=None,
                    )
                    violations.append(violation)

                # Get license summary
                summary_data = self.license_analyzer.get_license_summary(license_violations)
                license_summary = LicenseSummary(
                    total_license_violations=summary_data["total_license_violations"],
                    total_ip_violations=summary_data["total_ip_violations"],
                    licenses_found={
                        k: LicenseInfo(
                            count=v["count"],
                            severity=v["severity"],
                            files=v["files"],
                        )
                        for k, v in summary_data["licenses_found"].items()
                    },
                    has_restricted_licenses=summary_data["has_restricted_licenses"],
                    has_copyleft_licenses=summary_data["has_copyleft_licenses"],
                )

                logger.info(
                    f"License analysis found {len(license_violations)} violations "
                    f"({summary_data['total_license_violations']} license, "
                    f"{summary_data['total_ip_violations']} IP)"
                )
            except Exception as e:
                logger.error(f"License analysis failed: {e}")

        return {
            "violations": violations,
            "ai_review": ai_review,
            "copilot_detection": copilot_detection,
            "license_summary": license_summary,
            "enforcement_mode": enforcement_mode.value,
        }

    def _run_rule_analysis(
        self, diff: str, rule_packs: list[str]
    ) -> list[Violation]:
        """Run rule-based analysis on the diff.

        Args:
            diff: Git diff content
            rule_packs: List of rule pack IDs to apply

        Returns:
            List of violations
        """
        import re

        violations = []
        rules = self.rule_engine.get_rules_for_packs(rule_packs)

        # Parse diff to get file context
        current_file = ""
        current_line = 0
        lines_content: dict[str, list[tuple[int, str]]] = {}

        for line in diff.split("\n"):
            if line.startswith("+++ "):
                current_file = line[4:].lstrip("b/")
                lines_content[current_file] = []
            elif line.startswith("@@"):
                match = re.search(r"\+(\d+)", line)
                if match:
                    current_line = int(match.group(1)) - 1
            elif line.startswith("+") and not line.startswith("+++"):
                current_line += 1
                if current_file:
                    lines_content.setdefault(current_file, []).append(
                        (current_line, line[1:])
                    )
            elif not line.startswith("-"):
                current_line += 1

        # Apply rules to each file's content
        for filename, file_lines in lines_content.items():
            if not file_lines:
                continue

            file_content = "\n".join(content for _, content in file_lines)
            line_mapping = {
                i: orig_line for i, (orig_line, _) in enumerate(file_lines, 1)
            }

            # Detect language from filename
            language = self._detect_language(filename)

            for rule in rules:
                if not rule.pattern:
                    continue

                # Check language applicability
                if "*" not in rule.languages and language not in rule.languages:
                    continue

                try:
                    pattern = re.compile(rule.pattern, re.MULTILINE | re.IGNORECASE)
                    for match in pattern.finditer(file_content):
                        # Calculate line number in the file content
                        content_line = file_content[: match.start()].count("\n") + 1

                        # Map to original line number
                        original_line = line_mapping.get(content_line, content_line)

                        # Get code snippet
                        lines = file_content.split("\n")
                        snippet_start = max(0, content_line - 2)
                        snippet_end = min(len(lines), content_line + 1)
                        code_snippet = "\n".join(lines[snippet_start:snippet_end])

                        violation = Violation(
                            type="compliance" if "bank" in rule.id or "hipaa" in rule.id else "security",
                            severity=rule.severity.value,
                            rule=rule.id,
                            file=filename,
                            line=original_line,
                            column=match.start() - file_content.rfind("\n", 0, match.start()),
                            message=rule.message or rule.description,
                            suggestion=rule.suggestion,
                            code_snippet=code_snippet,
                            cwe=rule.cwe,
                            owasp=rule.owasp,
                        )
                        violations.append(violation)

                except re.error as e:
                    logger.warning(f"Invalid pattern in rule {rule.id}: {e}")

        return violations

    def _deduplicate_violations(
        self, violations: list[Violation]
    ) -> list[Violation]:
        """Remove duplicate violations.

        Args:
            violations: List of violations

        Returns:
            Deduplicated list
        """
        seen = set()
        unique = []

        for v in violations:
            key = (v.rule, v.file, v.line)
            if key not in seen:
                seen.add(key)
                unique.append(v)

        return unique

    def _build_ai_context(
        self, rule_packs: list[str], violations: list[Violation]
    ) -> str:
        """Build context string for AI review.

        Args:
            rule_packs: Active rule packs
            violations: Already detected violations

        Returns:
            Context string for AI
        """
        context_parts = []

        # Add rule pack context
        if "banking" in rule_packs:
            context_parts.append(
                "This code is for a banking/financial application. "
                "Apply PCI-DSS, SOX, and GLBA compliance requirements. "
                "Be extra vigilant about credit card numbers, SSNs, and account data."
            )

        if "healthcare" in rule_packs:
            context_parts.append(
                "This code is for a healthcare application. "
                "Apply HIPAA and HITECH compliance requirements. "
                "Be extra vigilant about PHI, medical records, and patient data."
            )

        # Add already-found violations
        if violations:
            context_parts.append(
                f"Static analysis has already found {len(violations)} potential issues. "
                "Focus on issues that pattern matching might miss, such as logic errors, "
                "improper access control, and architectural security concerns."
            )

        return " ".join(context_parts) if context_parts else ""

    def _detect_language(self, filename: str) -> str:
        """Detect programming language from filename."""
        extension_map = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".jsx": "javascript",
            ".java": "java",
            ".go": "go",
            ".rb": "ruby",
            ".php": "php",
            ".cs": "csharp",
            ".cpp": "cpp",
            ".c": "c",
            ".rs": "rust",
        }

        for ext, lang in extension_map.items():
            if filename.endswith(ext):
                return lang

        return "unknown"
