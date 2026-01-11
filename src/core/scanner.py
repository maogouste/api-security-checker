"""Base scanner framework."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import httpx


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    """A security finding."""
    id: str
    name: str
    severity: Severity
    description: str
    endpoint: str
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "severity": self.severity.value,
            "description": self.description,
            "endpoint": self.endpoint,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": self.references,
        }


@dataclass
class ScanResult:
    """Result of a scan."""
    scanner_name: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    def add_finding(self, finding: Finding):
        self.findings.append(finding)

    def add_error(self, error: str):
        self.errors.append(error)


class Scanner(ABC):
    """Base class for all scanners."""

    name: str = "BaseScanner"
    description: str = "Base scanner class"

    def __init__(self, client: httpx.Client):
        self.client = client

    @abstractmethod
    async def scan(self, target: "Target") -> ScanResult:
        """Run the scan against the target."""
        pass

    def make_request(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> httpx.Response:
        """Make an HTTP request with error handling."""
        try:
            return self.client.request(method, url, **kwargs)
        except httpx.RequestError as e:
            raise ScannerError(f"Request failed: {e}")


class ScannerError(Exception):
    """Scanner-specific error."""
    pass
