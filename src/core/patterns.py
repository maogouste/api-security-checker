"""Detection patterns for security scanning."""

import re
from typing import Dict, List, Pattern, Optional, Tuple
from dataclasses import dataclass


@dataclass
class DetectionResult:
    """Result of pattern detection."""
    matched: bool
    pattern_name: str
    match_text: str = ""
    confidence: float = 1.0  # 0.0 to 1.0


class PatternMatcher:
    """Robust pattern matching for vulnerability detection."""

    # SQL Error patterns by database type
    SQL_ERRORS: Dict[str, List[Pattern]] = {
        "generic": [
            re.compile(r"SQL\s*syntax.*?error", re.I),
            re.compile(r"syntax\s+error\s+at\s+or\s+near", re.I),
            re.compile(r"unclosed\s+quotation\s+mark", re.I),
            re.compile(r"quoted\s+string\s+not\s+properly\s+terminated", re.I),
        ],
        "mysql": [
            re.compile(r"you\s+have\s+an\s+error\s+in\s+your\s+SQL\s+syntax", re.I),
            re.compile(r"mysql_fetch", re.I),
            re.compile(r"mysqli?[_\.]", re.I),
            re.compile(r"com\.mysql\.jdbc", re.I),
            re.compile(r"MySqlClient", re.I),
            re.compile(r"MariaDB", re.I),
        ],
        "postgresql": [
            re.compile(r"pg_query", re.I),
            re.compile(r"pg_exec", re.I),
            re.compile(r"PostgreSQL.*?ERROR", re.I),
            re.compile(r"psycopg2?\.", re.I),
            re.compile(r"org\.postgresql", re.I),
            re.compile(r"SQLSTATE\[\d{5}\]", re.I),
        ],
        "sqlite": [
            re.compile(r"sqlite3?\.", re.I),
            re.compile(r"SQLite.*?error", re.I),
            re.compile(r"SQLITE_ERROR", re.I),
            re.compile(r"sqlite\.SQLiteException", re.I),
        ],
        "mssql": [
            re.compile(r"Microsoft\s+SQL\s+Server", re.I),
            re.compile(r"ODBC\s+SQL\s+Server\s+Driver", re.I),
            re.compile(r"\bUnclosed\s+quotation\s+mark\b", re.I),
            re.compile(r"mssql_query", re.I),
            re.compile(r"System\.Data\.SqlClient", re.I),
        ],
        "oracle": [
            re.compile(r"ORA-\d{5}", re.I),
            re.compile(r"oracle\.jdbc", re.I),
            re.compile(r"Oracle\s+error", re.I),
            re.compile(r"PLS-\d{5}", re.I),
        ],
    }

    # Command injection output patterns
    CMD_OUTPUT: Dict[str, List[Pattern]] = {
        "unix_id": [
            re.compile(r"uid=\d+\([^)]+\)\s+gid=\d+", re.I),
            re.compile(r"uid=\d+", re.I),
        ],
        "unix_passwd": [
            re.compile(r"root:[x*]?:\d+:\d+:", re.I),
            re.compile(r"[a-z_][a-z0-9_-]*:[x*]?:\d+:\d+:", re.I),
            re.compile(r"nobody:[x*]?:\d+:\d+:", re.I),
        ],
        "unix_paths": [
            re.compile(r"/(?:bin|sbin|usr|home|var|etc|tmp)/", re.I),
            re.compile(r"(?:^|\s)/[a-z]+(?:/[a-z0-9._-]+)+", re.I | re.M),
        ],
        "windows_paths": [
            re.compile(r"[A-Z]:\\(?:Windows|Users|Program)", re.I),
            re.compile(r"\[extensions\]", re.I),  # win.ini
            re.compile(r"\[fonts\]", re.I),  # win.ini
        ],
        "network_info": [
            re.compile(r"inet\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", re.I),
            re.compile(r"PING\s+\S+\s+\(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\)", re.I),
        ],
    }

    # Sensitive data patterns
    SENSITIVE_DATA: Dict[str, Tuple[Pattern, float]] = {
        "ssn": (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), 0.9),
        "credit_card": (re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"), 0.95),
        "email": (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"), 0.7),
        "jwt": (re.compile(r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*"), 0.95),
        "api_key": (re.compile(r"\b(?:api[_-]?key|apikey|access[_-]?token)[\"']?\s*[:=]\s*[\"']?([a-zA-Z0-9_-]{20,})", re.I), 0.85),
        "password_hash": (re.compile(r"\$(?:2[aby]?|5|6)\$[./A-Za-z0-9]{22,}"), 0.95),  # bcrypt, sha256, sha512
        "md5_hash": (re.compile(r"\b[a-f0-9]{32}\b", re.I), 0.6),
        "sha256_hash": (re.compile(r"\b[a-f0-9]{64}\b", re.I), 0.7),
        "private_key": (re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----", re.I), 0.99),
        "aws_key": (re.compile(r"(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}"), 0.95),
        "github_token": (re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"), 0.95),
    }

    # Field names indicating sensitive data
    SENSITIVE_FIELDS: List[Pattern] = [
        re.compile(r"(?:password|passwd|pwd)(?:_?hash)?", re.I),
        re.compile(r"(?:secret|private)[_-]?(?:key|token)?", re.I),
        re.compile(r"(?:api|access|auth)[_-]?(?:key|token|secret)", re.I),
        re.compile(r"(?:ssn|social[_-]?security)", re.I),
        re.compile(r"(?:credit[_-]?card|cc[_-]?num)", re.I),
        re.compile(r"(?:cvv|cvc|security[_-]?code)", re.I),
        re.compile(r"(?:internal|private)[_-]?(?:id|notes?|data)", re.I),
        re.compile(r"(?:supplier|vendor)[_-]?(?:cost|price|margin)", re.I),
    ]

    # Path traversal patterns
    PATH_TRAVERSAL: List[Pattern] = [
        re.compile(r"(?:root|nobody|daemon):[x*]?:\d+:\d+:", re.I),  # /etc/passwd content
        re.compile(r"\[boot\s+loader\]", re.I),  # boot.ini
        re.compile(r"\[operating\s+systems\]", re.I),  # boot.ini
        re.compile(r"\[extensions\]", re.I),  # win.ini
    ]

    # XSS reflection patterns
    XSS_REFLECTION: List[Pattern] = [
        re.compile(r"<script[^>]*>.*?</script>", re.I | re.S),
        re.compile(r"<img[^>]+onerror\s*=", re.I),
        re.compile(r"<svg[^>]+onload\s*=", re.I),
        re.compile(r"javascript\s*:", re.I),
        re.compile(r"on(?:error|load|click|mouseover)\s*=", re.I),
    ]

    # GraphQL error patterns
    GRAPHQL_ERRORS: List[Pattern] = [
        re.compile(r'(?:Cannot|Did you mean)[^"]*"([^"]+)"', re.I),  # Field suggestions
        re.compile(r"Unknown\s+(?:field|type|argument)", re.I),
        re.compile(r'Field\s+"[^"]+"\s+(?:must\s+not|cannot)\s+have', re.I),
        re.compile(r"Max(?:imum)?\s+(?:query\s+)?depth\s+(?:exceeded|reached)", re.I),
    ]

    @classmethod
    def detect_sql_error(cls, text: str) -> DetectionResult:
        """Detect SQL error messages in response."""
        for db_type, patterns in cls.SQL_ERRORS.items():
            for pattern in patterns:
                match = pattern.search(text)
                if match:
                    return DetectionResult(
                        matched=True,
                        pattern_name=f"sql_error_{db_type}",
                        match_text=match.group(0),
                        confidence=0.9 if db_type != "generic" else 0.8,
                    )
        return DetectionResult(matched=False, pattern_name="sql_error")

    @classmethod
    def detect_cmd_output(cls, text: str) -> DetectionResult:
        """Detect command execution output in response."""
        for output_type, patterns in cls.CMD_OUTPUT.items():
            for pattern in patterns:
                match = pattern.search(text)
                if match:
                    # Higher confidence for more specific patterns
                    confidence = 0.95 if output_type in ["unix_id", "unix_passwd"] else 0.8
                    return DetectionResult(
                        matched=True,
                        pattern_name=f"cmd_output_{output_type}",
                        match_text=match.group(0),
                        confidence=confidence,
                    )
        return DetectionResult(matched=False, pattern_name="cmd_output")

    @classmethod
    def detect_sensitive_data(cls, text: str) -> List[DetectionResult]:
        """Detect sensitive data patterns in response."""
        results = []
        for data_type, (pattern, confidence) in cls.SENSITIVE_DATA.items():
            matches = pattern.findall(text)
            if matches:
                results.append(DetectionResult(
                    matched=True,
                    pattern_name=f"sensitive_{data_type}",
                    match_text=str(matches[0])[:50],  # Truncate for safety
                    confidence=confidence,
                ))
        return results

    @classmethod
    def is_sensitive_field(cls, field_name: str) -> bool:
        """Check if a field name indicates sensitive data."""
        for pattern in cls.SENSITIVE_FIELDS:
            if pattern.search(field_name):
                return True
        return False

    @classmethod
    def detect_path_traversal_success(cls, text: str) -> DetectionResult:
        """Detect successful path traversal from response content."""
        for pattern in cls.PATH_TRAVERSAL:
            match = pattern.search(text)
            if match:
                return DetectionResult(
                    matched=True,
                    pattern_name="path_traversal",
                    match_text=match.group(0),
                    confidence=0.95,
                )
        return DetectionResult(matched=False, pattern_name="path_traversal")

    @classmethod
    def detect_xss_reflection(cls, text: str, payload: str) -> DetectionResult:
        """Detect XSS payload reflection in response."""
        # First check if payload is reflected
        if payload.lower() in text.lower():
            # Then check if it's in a dangerous context
            for pattern in cls.XSS_REFLECTION:
                match = pattern.search(text)
                if match:
                    return DetectionResult(
                        matched=True,
                        pattern_name="xss_reflection",
                        match_text=match.group(0)[:100],
                        confidence=0.9,
                    )
        return DetectionResult(matched=False, pattern_name="xss_reflection")

    @classmethod
    def extract_graphql_suggestions(cls, text: str) -> List[str]:
        """Extract field name suggestions from GraphQL errors."""
        suggestions = []
        for pattern in cls.GRAPHQL_ERRORS:
            matches = pattern.findall(text)
            suggestions.extend(matches)
        return list(set(suggestions))


# Convenience functions
def detect_sql_error(text: str) -> DetectionResult:
    """Detect SQL error in text."""
    return PatternMatcher.detect_sql_error(text)


def detect_cmd_output(text: str) -> DetectionResult:
    """Detect command output in text."""
    return PatternMatcher.detect_cmd_output(text)


def detect_sensitive_data(text: str) -> List[DetectionResult]:
    """Detect sensitive data patterns."""
    return PatternMatcher.detect_sensitive_data(text)


def is_sensitive_field(field_name: str) -> bool:
    """Check if field name is sensitive."""
    return PatternMatcher.is_sensitive_field(field_name)
