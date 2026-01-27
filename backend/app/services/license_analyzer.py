"""License and IP compliance analyzer service."""

import logging
import re
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class LicenseViolation:
    """Represents a detected license or IP violation."""

    type: str  # "license" or "ip"
    severity: str  # "critical", "high", "medium", "low"
    license_type: Optional[str]
    file: str
    line: int
    message: str
    suggestion: str
    code_snippet: str


# License categories and their risk levels
RESTRICTED_LICENSES = {
    "AGPL-3.0": {
        "severity": "critical",
        "message": "AGPL-3.0 license detected - requires source code disclosure for network use",
        "suggestion": "Consult legal team before using AGPL-licensed code in proprietary applications",
    },
    "GPL-3.0": {
        "severity": "high",
        "message": "GPL-3.0 license detected - strong copyleft license",
        "suggestion": "Consider alternatives or ensure compliance with GPL distribution requirements",
    },
    "SSPL-1.0": {
        "severity": "critical",
        "message": "SSPL-1.0 license detected - requires disclosure of service code",
        "suggestion": "Do not use SSPL-licensed code in production services without legal review",
    },
}

COPYLEFT_LICENSES = {
    "GPL-2.0": {
        "severity": "high",
        "message": "GPL-2.0 license detected - copyleft license",
        "suggestion": "Ensure compliance with GPL-2.0 distribution requirements",
    },
    "LGPL-2.1": {
        "severity": "medium",
        "message": "LGPL-2.1 license detected - weak copyleft license",
        "suggestion": "LGPL is generally safe for dynamic linking, review usage context",
    },
    "LGPL-3.0": {
        "severity": "medium",
        "message": "LGPL-3.0 license detected - weak copyleft license",
        "suggestion": "LGPL is generally safe for dynamic linking, review usage context",
    },
    "MPL-2.0": {
        "severity": "medium",
        "message": "MPL-2.0 license detected - file-level copyleft",
        "suggestion": "Modified MPL files must be disclosed, but can be combined with proprietary code",
    },
    "EPL-2.0": {
        "severity": "medium",
        "message": "EPL-2.0 license detected - weak copyleft license",
        "suggestion": "Review Eclipse Public License requirements for modifications",
    },
}

PERMISSIVE_LICENSES = {
    "MIT": {"severity": "low", "message": "MIT license detected"},
    "Apache-2.0": {"severity": "low", "message": "Apache-2.0 license detected"},
    "BSD-2-Clause": {"severity": "low", "message": "BSD-2-Clause license detected"},
    "BSD-3-Clause": {"severity": "low", "message": "BSD-3-Clause license detected"},
    "ISC": {"severity": "low", "message": "ISC license detected"},
    "Unlicense": {"severity": "low", "message": "Unlicense (public domain) detected"},
    "CC0-1.0": {"severity": "low", "message": "CC0-1.0 (public domain) detected"},
}

# Patterns to detect licenses
LICENSE_PATTERNS = [
    # SPDX identifier
    (r"SPDX-License-Identifier:\s*(\S+)", "spdx"),
    # Common license headers
    (r"Licensed under the ([\w\s\-\.]+)(?: License)?", "header"),
    # License file references
    (r"See (LICENSE|COPYING|NOTICE)(?:\.(?:txt|md))?", "reference"),
    # Full license names
    (r"(GNU (?:General|Lesser|Affero) Public License|Apache License|MIT License|BSD License)", "full_name"),
]

# Patterns for potential IP issues
IP_PATTERNS = [
    {
        "pattern": r"Copyright\s+(?:\(c\)|©)?\s*\d{4}(?:-\d{4})?\s+(?!Your Company|Your Name|<.*>|\[.*\])[\w\s,\.]+(?:All rights reserved\.?)?",
        "severity": "medium",
        "message": "Third-party copyright notice detected",
        "suggestion": "Verify you have rights to use this code and proper attribution is maintained",
    },
    {
        "pattern": r"(?:PROPRIETARY|CONFIDENTIAL|TRADE SECRET)",
        "severity": "high",
        "message": "Proprietary/confidential marker detected",
        "suggestion": "This code may be proprietary - verify you have authorization to use it",
    },
    {
        "pattern": r"(?:DO NOT (?:COPY|DISTRIBUTE|MODIFY|SHARE))",
        "severity": "high",
        "message": "Usage restriction detected",
        "suggestion": "This code has explicit usage restrictions - review before including",
    },
]


class LicenseAnalyzer:
    """Analyzes code for license and IP compliance issues."""

    def __init__(self):
        """Initialize the license analyzer."""
        self.all_licenses = {
            **RESTRICTED_LICENSES,
            **COPYLEFT_LICENSES,
            **PERMISSIVE_LICENSES,
        }

    def analyze_diff(self, diff: str) -> list[LicenseViolation]:
        """Analyze a diff for license and IP violations.

        Args:
            diff: Git diff content

        Returns:
            List of license violations found
        """
        violations = []

        # Parse diff to get file contents
        current_file = ""
        current_line = 0
        file_lines: dict[str, list[tuple[int, str]]] = {}

        for line in diff.split("\n"):
            if line.startswith("+++ "):
                current_file = line[4:].lstrip("b/")
                file_lines[current_file] = []
            elif line.startswith("@@"):
                match = re.search(r"\+(\d+)", line)
                if match:
                    current_line = int(match.group(1)) - 1
            elif line.startswith("+") and not line.startswith("+++"):
                current_line += 1
                if current_file:
                    file_lines.setdefault(current_file, []).append(
                        (current_line, line[1:])
                    )
            elif not line.startswith("-"):
                current_line += 1

        # Analyze each file
        for filename, lines in file_lines.items():
            if not lines:
                continue

            file_violations = self._analyze_file_content(filename, lines)
            violations.extend(file_violations)

        return violations

    def _analyze_file_content(
        self, filename: str, lines: list[tuple[int, str]]
    ) -> list[LicenseViolation]:
        """Analyze file content for license violations.

        Args:
            filename: Name of the file
            lines: List of (line_number, content) tuples

        Returns:
            List of violations
        """
        violations = []
        full_content = "\n".join(content for _, content in lines)

        # Check for license patterns
        for pattern, pattern_type in LICENSE_PATTERNS:
            for match in re.finditer(pattern, full_content, re.IGNORECASE):
                license_id = self._normalize_license_id(match.group(1))
                violation = self._check_license(
                    license_id, filename, lines, match.start(), full_content
                )
                if violation:
                    violations.append(violation)

        # Check for IP patterns
        for ip_pattern in IP_PATTERNS:
            for match in re.finditer(ip_pattern["pattern"], full_content, re.IGNORECASE):
                line_num = self._get_line_number(match.start(), lines, full_content)
                snippet = self._get_snippet(match.start(), full_content)

                violations.append(
                    LicenseViolation(
                        type="ip",
                        severity=ip_pattern["severity"],
                        license_type=None,
                        file=filename,
                        line=line_num,
                        message=ip_pattern["message"],
                        suggestion=ip_pattern["suggestion"],
                        code_snippet=snippet,
                    )
                )

        return violations

    def _normalize_license_id(self, license_str: str) -> str:
        """Normalize a license string to standard SPDX identifier.

        Args:
            license_str: Raw license string

        Returns:
            Normalized license identifier
        """
        license_str = license_str.strip()

        # Common mappings
        mappings = {
            "GNU General Public License": "GPL-3.0",
            "GNU Lesser General Public License": "LGPL-3.0",
            "GNU Affero General Public License": "AGPL-3.0",
            "Apache License": "Apache-2.0",
            "MIT License": "MIT",
            "BSD License": "BSD-3-Clause",
            "GPL": "GPL-3.0",
            "LGPL": "LGPL-3.0",
            "Apache": "Apache-2.0",
        }

        for key, value in mappings.items():
            if key.lower() in license_str.lower():
                return value

        # Return as-is if already looks like SPDX
        return license_str.upper() if len(license_str) <= 20 else license_str

    def _check_license(
        self,
        license_id: str,
        filename: str,
        lines: list[tuple[int, str]],
        match_pos: int,
        full_content: str,
    ) -> Optional[LicenseViolation]:
        """Check if a license requires attention.

        Args:
            license_id: License identifier
            filename: File name
            lines: File lines
            match_pos: Position of match in content
            full_content: Full file content

        Returns:
            LicenseViolation if license needs attention, None otherwise
        """
        # Find the license info
        license_info = None
        normalized_id = license_id

        for lid, info in self.all_licenses.items():
            if lid.lower() in license_id.lower() or license_id.lower() in lid.lower():
                license_info = info
                normalized_id = lid
                break

        if not license_info:
            # Unknown license
            return LicenseViolation(
                type="license",
                severity="medium",
                license_type=license_id,
                file=filename,
                line=self._get_line_number(match_pos, lines, full_content),
                message=f"Unknown license detected: {license_id}",
                suggestion="Review this license to ensure it's compatible with your project",
                code_snippet=self._get_snippet(match_pos, full_content),
            )

        # Only report non-permissive licenses or if specifically configured
        if normalized_id in RESTRICTED_LICENSES or normalized_id in COPYLEFT_LICENSES:
            return LicenseViolation(
                type="license",
                severity=license_info["severity"],
                license_type=normalized_id,
                file=filename,
                line=self._get_line_number(match_pos, lines, full_content),
                message=license_info["message"],
                suggestion=license_info.get(
                    "suggestion", "Review license compatibility"
                ),
                code_snippet=self._get_snippet(match_pos, full_content),
            )

        return None

    def _get_line_number(
        self, pos: int, lines: list[tuple[int, str]], full_content: str
    ) -> int:
        """Get the original line number from a position in content.

        Args:
            pos: Character position
            lines: Original lines with line numbers
            full_content: Full content string

        Returns:
            Line number
        """
        content_line = full_content[:pos].count("\n") + 1
        if content_line <= len(lines):
            return lines[content_line - 1][0]
        return lines[-1][0] if lines else 1

    def _get_snippet(self, pos: int, content: str, context: int = 50) -> str:
        """Get a code snippet around a position.

        Args:
            pos: Character position
            content: Full content
            context: Characters of context to include

        Returns:
            Code snippet
        """
        start = max(0, pos - context)
        end = min(len(content), pos + context)
        snippet = content[start:end]

        # Clean up snippet
        if start > 0:
            snippet = "..." + snippet
        if end < len(content):
            snippet = snippet + "..."

        return snippet.replace("\n", " ").strip()

    def get_license_summary(self, violations: list[LicenseViolation]) -> dict:
        """Get a summary of license violations.

        Args:
            violations: List of violations

        Returns:
            Summary dictionary
        """
        license_violations = [v for v in violations if v.type == "license"]
        ip_violations = [v for v in violations if v.type == "ip"]

        licenses_found = {}
        for v in license_violations:
            if v.license_type:
                if v.license_type not in licenses_found:
                    licenses_found[v.license_type] = {
                        "count": 0,
                        "severity": v.severity,
                        "files": [],
                    }
                licenses_found[v.license_type]["count"] += 1
                licenses_found[v.license_type]["files"].append(v.file)

        return {
            "total_license_violations": len(license_violations),
            "total_ip_violations": len(ip_violations),
            "licenses_found": licenses_found,
            "has_restricted_licenses": any(
                v.license_type in RESTRICTED_LICENSES for v in license_violations if v.license_type
            ),
            "has_copyleft_licenses": any(
                v.license_type in COPYLEFT_LICENSES for v in license_violations if v.license_type
            ),
        }
