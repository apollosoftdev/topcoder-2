"""Static analysis engine for pattern-based security scanning."""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class SecurityPattern:
    """Definition of a security pattern to detect."""

    id: str
    name: str
    pattern: str
    severity: Severity
    description: str
    suggestion: str
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    languages: list[str] = field(default_factory=lambda: ["*"])


@dataclass
class Violation:
    """Represents a detected security violation."""

    type: str
    severity: str
    rule: str
    file: str
    line: int
    column: int
    message: str
    suggestion: str
    code_snippet: str
    cwe: Optional[str] = None
    owasp: Optional[str] = None


# Security patterns to detect
SECURITY_PATTERNS: list[SecurityPattern] = [
    # Hardcoded secrets
    SecurityPattern(
        id="hardcoded_api_key",
        name="Hardcoded API Key",
        pattern=r"""(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{16,}['\"]""",
        severity=Severity.CRITICAL,
        description="Hardcoded API key detected",
        suggestion="Use environment variables to store API keys securely",
        cwe="CWE-798",
        owasp="A3:2017",
    ),
    SecurityPattern(
        id="hardcoded_password",
        name="Hardcoded Password",
        pattern=r"""(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]""",
        severity=Severity.CRITICAL,
        description="Hardcoded password detected",
        suggestion="Use environment variables or a secrets manager for passwords",
        cwe="CWE-798",
        owasp="A3:2017",
    ),
    SecurityPattern(
        id="hardcoded_secret",
        name="Hardcoded Secret",
        pattern=r"""(?i)(secret|token|private[_-]?key)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{8,}['\"]""",
        severity=Severity.CRITICAL,
        description="Hardcoded secret or token detected",
        suggestion="Use environment variables or a secrets manager",
        cwe="CWE-798",
        owasp="A3:2017",
    ),
    SecurityPattern(
        id="aws_access_key",
        name="AWS Access Key",
        pattern=r"""(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}""",
        severity=Severity.CRITICAL,
        description="AWS Access Key ID detected",
        suggestion="Remove AWS credentials and use IAM roles or environment variables",
        cwe="CWE-798",
        owasp="A3:2017",
    ),
    SecurityPattern(
        id="private_key",
        name="Private Key",
        pattern=r"""-----BEGIN\s+(RSA|DSA|EC|OPENSSH|PGP)?\s*PRIVATE KEY-----""",
        severity=Severity.CRITICAL,
        description="Private key detected in code",
        suggestion="Remove private keys from source code and use secure key management",
        cwe="CWE-321",
        owasp="A3:2017",
    ),
    # SQL Injection
    SecurityPattern(
        id="sql_injection_fstring",
        name="SQL Injection (f-string)",
        pattern=r"""(?:execute|cursor\.execute|query)\s*\(\s*f['\"].*\{.*\}""",
        severity=Severity.HIGH,
        description="Potential SQL injection via f-string interpolation",
        suggestion="Use parameterized queries instead of string interpolation",
        cwe="CWE-89",
        owasp="A1:2017",
        languages=["python"],
    ),
    SecurityPattern(
        id="sql_injection_format",
        name="SQL Injection (format)",
        pattern=r"""(?:execute|cursor\.execute|query)\s*\([^)]*\.format\s*\(""",
        severity=Severity.HIGH,
        description="Potential SQL injection via .format() method",
        suggestion="Use parameterized queries instead of string formatting",
        cwe="CWE-89",
        owasp="A1:2017",
        languages=["python"],
    ),
    SecurityPattern(
        id="sql_injection_concat",
        name="SQL Injection (concatenation)",
        pattern=r"""(?:execute|query)\s*\(\s*['\"](?:SELECT|INSERT|UPDATE|DELETE).*['\"\s]*\+""",
        severity=Severity.HIGH,
        description="Potential SQL injection via string concatenation",
        suggestion="Use parameterized queries instead of string concatenation",
        cwe="CWE-89",
        owasp="A1:2017",
    ),
    # Command Injection
    SecurityPattern(
        id="command_injection_os_system",
        name="Command Injection (os.system)",
        pattern=r"""os\.system\s*\([^)]*(?:\+|\.format|\{)""",
        severity=Severity.HIGH,
        description="Potential command injection via os.system",
        suggestion="Use subprocess with shell=False and pass arguments as a list",
        cwe="CWE-78",
        owasp="A1:2017",
        languages=["python"],
    ),
    SecurityPattern(
        id="command_injection_subprocess",
        name="Command Injection (subprocess)",
        pattern=r"""subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True""",
        severity=Severity.HIGH,
        description="Subprocess called with shell=True, potential command injection",
        suggestion="Use shell=False and pass command arguments as a list",
        cwe="CWE-78",
        owasp="A1:2017",
        languages=["python"],
    ),
    SecurityPattern(
        id="eval_usage",
        name="Dangerous eval() Usage",
        pattern=r"""\beval\s*\([^)]*(?:request|input|user|data|param)""",
        severity=Severity.CRITICAL,
        description="eval() used with potentially untrusted input",
        suggestion="Avoid eval() with user input; use safe alternatives like ast.literal_eval",
        cwe="CWE-95",
        owasp="A1:2017",
    ),
    # Insecure Deserialization
    SecurityPattern(
        id="pickle_loads",
        name="Insecure Deserialization (pickle)",
        pattern=r"""pickle\.loads?\s*\(""",
        severity=Severity.HIGH,
        description="pickle.load/loads can execute arbitrary code",
        suggestion="Avoid pickle for untrusted data; use JSON or other safe formats",
        cwe="CWE-502",
        owasp="A8:2017",
        languages=["python"],
    ),
    SecurityPattern(
        id="yaml_load",
        name="Insecure YAML Loading",
        pattern=r"""yaml\.load\s*\([^)]*(?!Loader\s*=\s*yaml\.SafeLoader)""",
        severity=Severity.HIGH,
        description="yaml.load without SafeLoader can execute arbitrary code",
        suggestion="Use yaml.safe_load() or specify Loader=yaml.SafeLoader",
        cwe="CWE-502",
        owasp="A8:2017",
        languages=["python"],
    ),
    # Path Traversal
    SecurityPattern(
        id="path_traversal",
        name="Path Traversal",
        pattern=r"""(?:open|read|write)\s*\([^)]*(?:request|input|user|param)""",
        severity=Severity.MEDIUM,
        description="Potential path traversal vulnerability",
        suggestion="Validate and sanitize file paths; use os.path.basename or pathlib",
        cwe="CWE-22",
        owasp="A5:2017",
    ),
    # XSS
    SecurityPattern(
        id="xss_innerhtml",
        name="XSS (innerHTML)",
        pattern=r"""\.innerHTML\s*=\s*(?!['\"]\s*['\""])""",
        severity=Severity.MEDIUM,
        description="Direct innerHTML assignment may lead to XSS",
        suggestion="Use textContent or sanitize HTML before assignment",
        cwe="CWE-79",
        owasp="A7:2017",
        languages=["javascript", "typescript"],
    ),
    SecurityPattern(
        id="xss_document_write",
        name="XSS (document.write)",
        pattern=r"""document\.write\s*\(""",
        severity=Severity.MEDIUM,
        description="document.write can lead to XSS vulnerabilities",
        suggestion="Use DOM manipulation methods instead of document.write",
        cwe="CWE-79",
        owasp="A7:2017",
        languages=["javascript", "typescript"],
    ),
    # Insecure Cryptography
    SecurityPattern(
        id="weak_hash_md5",
        name="Weak Hash (MD5)",
        pattern=r"""(?:hashlib\.md5|MD5|createHash\s*\(\s*['\"]md5['\"])""",
        severity=Severity.MEDIUM,
        description="MD5 is cryptographically weak",
        suggestion="Use SHA-256 or stronger hashing algorithms",
        cwe="CWE-328",
        owasp="A3:2017",
    ),
    SecurityPattern(
        id="weak_hash_sha1",
        name="Weak Hash (SHA1)",
        pattern=r"""(?:hashlib\.sha1|SHA1|createHash\s*\(\s*['\"]sha1['\"])""",
        severity=Severity.LOW,
        description="SHA1 is considered weak for security purposes",
        suggestion="Use SHA-256 or stronger hashing algorithms",
        cwe="CWE-328",
        owasp="A3:2017",
    ),
    # Insecure Random
    SecurityPattern(
        id="insecure_random",
        name="Insecure Random Number Generator",
        pattern=r"""\brandom\.(?:random|randint|choice|shuffle)\s*\(""",
        severity=Severity.MEDIUM,
        description="random module is not cryptographically secure",
        suggestion="Use secrets module for security-sensitive random values",
        cwe="CWE-330",
        owasp="A3:2017",
        languages=["python"],
    ),
    # Debug/Development Code
    SecurityPattern(
        id="debug_true",
        name="Debug Mode Enabled",
        pattern=r"""(?:DEBUG|debug)\s*[:=]\s*(?:True|true|1)""",
        severity=Severity.LOW,
        description="Debug mode appears to be enabled",
        suggestion="Ensure debug mode is disabled in production",
        cwe="CWE-489",
        owasp="A6:2017",
    ),
    SecurityPattern(
        id="console_log",
        name="Console Log in Production",
        pattern=r"""console\.log\s*\([^)]*(?:password|secret|token|key|credential)""",
        severity=Severity.MEDIUM,
        description="Sensitive data may be logged to console",
        suggestion="Remove or mask sensitive data from logs",
        cwe="CWE-532",
        owasp="A3:2017",
        languages=["javascript", "typescript"],
    ),
]


class StaticAnalyzer:
    """Static analysis engine for code scanning."""

    def __init__(self, patterns: Optional[list[SecurityPattern]] = None):
        """Initialize with security patterns."""
        self.patterns = patterns or SECURITY_PATTERNS

    def analyze(
        self,
        code: str,
        filename: str,
        language: Optional[str] = None,
    ) -> list[Violation]:
        """Analyze code for security violations.

        Args:
            code: Source code to analyze
            filename: Name of the file being analyzed
            language: Programming language (auto-detected if not provided)

        Returns:
            List of detected violations
        """
        if not language:
            language = self._detect_language(filename)

        violations: list[Violation] = []
        lines = code.split("\n")

        for pattern in self.patterns:
            # Check if pattern applies to this language
            if "*" not in pattern.languages and language not in pattern.languages:
                continue

            # Search for pattern matches
            compiled_pattern = re.compile(pattern.pattern, re.MULTILINE | re.IGNORECASE)

            for match in compiled_pattern.finditer(code):
                # Calculate line number
                line_number = code[: match.start()].count("\n") + 1
                column = match.start() - code.rfind("\n", 0, match.start())

                # Get code snippet
                snippet_start = max(0, line_number - 2)
                snippet_end = min(len(lines), line_number + 1)
                code_snippet = "\n".join(lines[snippet_start:snippet_end])

                violation = Violation(
                    type="security",
                    severity=pattern.severity.value,
                    rule=pattern.id,
                    file=filename,
                    line=line_number,
                    column=column,
                    message=pattern.description,
                    suggestion=pattern.suggestion,
                    code_snippet=code_snippet,
                    cwe=pattern.cwe,
                    owasp=pattern.owasp,
                )
                violations.append(violation)

        return violations

    def analyze_diff(self, diff: str, base_filename: str = "") -> list[Violation]:
        """Analyze a git diff for security violations.

        Args:
            diff: Git diff content
            base_filename: Base filename for the diff

        Returns:
            List of detected violations
        """
        violations: list[Violation] = []

        # Parse diff to extract added lines and their file context
        current_file = base_filename
        current_line = 0
        added_code_blocks: dict[str, list[tuple[int, str]]] = {}

        for line in diff.split("\n"):
            # Track current file
            if line.startswith("+++ "):
                current_file = line[4:].lstrip("b/")
                if current_file not in added_code_blocks:
                    added_code_blocks[current_file] = []

            # Track line numbers from hunk headers
            elif line.startswith("@@"):
                # Parse @@ -old,count +new,count @@
                match = re.search(r"\+(\d+)", line)
                if match:
                    current_line = int(match.group(1)) - 1

            # Track added lines
            elif line.startswith("+") and not line.startswith("+++"):
                current_line += 1
                added_code_blocks.setdefault(current_file, []).append(
                    (current_line, line[1:])
                )
            elif not line.startswith("-"):
                current_line += 1

        # Analyze each file's added code
        for filename, code_lines in added_code_blocks.items():
            if not code_lines:
                continue

            # Combine added lines for analysis
            code = "\n".join(line for _, line in code_lines)
            language = self._detect_language(filename)

            file_violations = self.analyze(code, filename, language)

            # Adjust line numbers to match original diff positions
            line_mapping = {i: orig_line for i, (orig_line, _) in enumerate(code_lines, 1)}

            for violation in file_violations:
                # Map violation line to original diff line
                if violation.line in line_mapping:
                    violation.line = line_mapping[violation.line]
                violations.append(violation)

        return violations

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
            ".swift": "swift",
            ".kt": "kotlin",
            ".scala": "scala",
        }

        for ext, lang in extension_map.items():
            if filename.endswith(ext):
                return lang

        return "unknown"
