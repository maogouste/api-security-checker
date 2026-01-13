"""Tests for core module components."""

import pytest
from src.core import Severity, Finding, ScanResult, Target, setup_logging, get_logger


class TestSeverity:
    """Tests for Severity enum."""

    def test_severity_values(self):
        """Verify all severity levels exist."""
        assert Severity.INFO.value == "info"
        assert Severity.LOW.value == "low"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.HIGH.value == "high"
        assert Severity.CRITICAL.value == "critical"

    def test_severity_comparison(self):
        """Severity levels can be compared."""
        # Enum members are comparable by identity
        assert Severity.CRITICAL != Severity.HIGH
        assert Severity.INFO == Severity.INFO


class TestFinding:
    """Tests for Finding dataclass."""

    def test_finding_creation(self):
        """Create a basic finding."""
        finding = Finding(
            id="TEST-001",
            name="Test Finding",
            severity=Severity.HIGH,
            description="Test description",
            endpoint="/api/test",
        )
        assert finding.id == "TEST-001"
        assert finding.severity == Severity.HIGH
        assert finding.evidence is None
        assert finding.references == []

    def test_finding_with_all_fields(self):
        """Create a finding with all optional fields."""
        finding = Finding(
            id="TEST-002",
            name="Full Finding",
            severity=Severity.CRITICAL,
            description="Full description",
            endpoint="/api/vulnerable",
            evidence="SQL error found",
            remediation="Use parameterized queries",
            references=["https://owasp.org/test"],
        )
        assert finding.evidence == "SQL error found"
        assert len(finding.references) == 1

    def test_finding_to_dict(self):
        """Finding can be converted to dict."""
        finding = Finding(
            id="TEST-003",
            name="Dict Test",
            severity=Severity.MEDIUM,
            description="Test",
            endpoint="/test",
        )
        result = finding.to_dict()
        assert result["id"] == "TEST-003"
        assert result["severity"] == "medium"
        assert isinstance(result, dict)


class TestScanResult:
    """Tests for ScanResult dataclass."""

    def test_empty_result(self):
        """Empty scan result has no findings."""
        result = ScanResult(scanner_name="TestScanner")
        assert result.scanner_name == "TestScanner"
        assert result.findings == []
        assert result.errors == []
        assert result.has_findings is False

    def test_add_finding(self):
        """Add finding to result."""
        result = ScanResult(scanner_name="TestScanner")
        finding = Finding(
            id="TEST",
            name="Test",
            severity=Severity.LOW,
            description="Test",
            endpoint="/test",
        )
        result.add_finding(finding)
        assert len(result.findings) == 1
        assert result.has_findings is True

    def test_add_error(self):
        """Add error to result."""
        result = ScanResult(scanner_name="TestScanner")
        result.add_error("Connection failed")
        assert len(result.errors) == 1
        assert "Connection failed" in result.errors

    def test_multiple_findings(self):
        """Add multiple findings."""
        result = ScanResult(scanner_name="TestScanner")
        for i in range(5):
            result.add_finding(Finding(
                id=f"TEST-{i}",
                name=f"Finding {i}",
                severity=Severity.MEDIUM,
                description="Test",
                endpoint=f"/test/{i}",
            ))
        assert len(result.findings) == 5


class TestTarget:
    """Tests for Target dataclass."""

    def test_basic_target(self):
        """Create basic target."""
        target = Target(base_url="http://localhost:8000")
        assert target.base_url == "http://localhost:8000"
        assert target.name == "Unknown"
        assert target.verify_ssl is True

    def test_target_with_credentials(self):
        """Create target with auth credentials."""
        target = Target(
            base_url="http://localhost:8000",
            valid_username="admin",
            valid_password="secret",
        )
        assert target.valid_username == "admin"
        assert target.valid_password == "secret"

    def test_target_get_auth_header(self):
        """Get auth header from target."""
        target = Target(
            base_url="http://localhost:8000",
            auth_token="test-token-123",
        )
        headers = target.get_auth_header()
        assert headers["Authorization"] == "Bearer test-token-123"

    def test_target_get_auth_header_empty(self):
        """Get auth header when no token set."""
        target = Target(base_url="http://localhost:8000")
        headers = target.get_auth_header()
        assert headers == {}

    def test_target_get_headers(self):
        """Get all headers including custom ones."""
        target = Target(
            base_url="http://localhost:8000",
            auth_token="my-token",
            headers={"X-Custom": "value"},
        )
        headers = target.get_headers()
        assert headers["Content-Type"] == "application/json"
        assert headers["X-Custom"] == "value"
        assert "Authorization" in headers

    def test_target_verify_ssl_disabled(self):
        """Target with SSL verification disabled."""
        target = Target(
            base_url="https://self-signed.example.com",
            verify_ssl=False,
        )
        assert target.verify_ssl is False


class TestLogging:
    """Tests for logging module."""

    def test_setup_logging(self):
        """Setup logging returns logger."""
        logger = setup_logging()
        assert logger is not None
        assert logger.name == "apisec"

    def test_setup_logging_verbose(self):
        """Setup logging with verbose mode."""
        logger = setup_logging(verbose=True)
        assert logger is not None

    def test_get_logger(self):
        """Get logger by name."""
        logger = get_logger("test")
        assert logger.name == "apisec.test"

    def test_get_root_logger(self):
        """Get root logger."""
        logger = get_logger("apisec")
        assert logger.name == "apisec"
