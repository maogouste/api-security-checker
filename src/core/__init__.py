"""Core scanner framework."""

from .scanner import Scanner, ScanResult, Severity, Finding
from .target import Target
from .logging import setup_logging, get_logger
from .payloads import PayloadManager, get_payloads
from .patterns import (
    PatternMatcher,
    DetectionResult,
    detect_sql_error,
    detect_cmd_output,
    detect_sensitive_data,
    is_sensitive_field,
)

__all__ = [
    "Scanner",
    "ScanResult",
    "Severity",
    "Finding",
    "Target",
    "setup_logging",
    "get_logger",
    "PayloadManager",
    "get_payloads",
    "PatternMatcher",
    "DetectionResult",
    "detect_sql_error",
    "detect_cmd_output",
    "detect_sensitive_data",
    "is_sensitive_field",
]
