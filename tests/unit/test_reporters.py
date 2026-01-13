"""Tests for reporters."""

import json
import tempfile
from pathlib import Path

import pytest

from src.core import ScanResult, Finding, Severity
from src.reporters import ConsoleReporter, JSONReporter


@pytest.fixture
def sample_findings():
    """Create sample findings for testing."""
    return [
        Finding(
            id="V01-BOLA",
            name="Broken Object Level Authorization",
            severity=Severity.HIGH,
            description="User can access other users' data",
            endpoint="/api/users/1",
            evidence="Accessed user 1 without authorization",
        ),
        Finding(
            id="V06-SQLI",
            name="SQL Injection",
            severity=Severity.CRITICAL,
            description="Endpoint vulnerable to SQL injection",
            endpoint="/api/products",
            evidence="SQL error in response",
        ),
        Finding(
            id="V08-HDR",
            name="Missing Security Headers",
            severity=Severity.MEDIUM,
            description="HSTS header not set",
            endpoint="/",
        ),
    ]


@pytest.fixture
def sample_results(sample_findings):
    """Create sample scan results."""
    result1 = ScanResult(scanner_name="BOLAScanner")
    result1.add_finding(sample_findings[0])

    result2 = ScanResult(scanner_name="InjectionScanner")
    result2.add_finding(sample_findings[1])
    result2.add_error("Connection timeout on /api/test")

    result3 = ScanResult(scanner_name="HeadersScanner")
    result3.add_finding(sample_findings[2])

    return [result1, result2, result3]


@pytest.fixture
def empty_results():
    """Create empty scan results."""
    return [
        ScanResult(scanner_name="AuthScanner"),
        ScanResult(scanner_name="BOLAScanner"),
    ]


class TestJSONReporter:
    """Tests for JSON reporter."""

    def test_generates_report_structure(self, sample_results):
        """Report has correct structure."""
        reporter = JSONReporter()
        report = reporter.report(sample_results, "http://test.local")

        assert "scan_info" in report
        assert "summary" in report
        assert "findings" in report
        assert "errors" in report

    def test_scan_info_fields(self, sample_results):
        """Scan info has required fields."""
        reporter = JSONReporter()
        report = reporter.report(sample_results, "http://test.local")

        assert report["scan_info"]["target"] == "http://test.local"
        assert "timestamp" in report["scan_info"]
        assert report["scan_info"]["tool"] == "api-security-checker"

    def test_summary_counts(self, sample_results):
        """Summary counts findings by severity."""
        reporter = JSONReporter()
        report = reporter.report(sample_results, "http://test.local")

        assert report["summary"]["total_findings"] == 3
        assert report["summary"]["by_severity"]["critical"] == 1
        assert report["summary"]["by_severity"]["high"] == 1
        assert report["summary"]["by_severity"]["medium"] == 1

    def test_summary_scanners(self, sample_results):
        """Summary lists scanners run."""
        reporter = JSONReporter()
        report = reporter.report(sample_results, "http://test.local")

        assert "BOLAScanner" in report["summary"]["scanners_run"]
        assert "InjectionScanner" in report["summary"]["scanners_run"]
        assert "HeadersScanner" in report["summary"]["scanners_run"]

    def test_findings_content(self, sample_results):
        """Findings contain correct data."""
        reporter = JSONReporter()
        report = reporter.report(sample_results, "http://test.local")

        finding_ids = [f["id"] for f in report["findings"]]
        assert "V01-BOLA" in finding_ids
        assert "V06-SQLI" in finding_ids

    def test_errors_collected(self, sample_results):
        """Errors are collected from results."""
        reporter = JSONReporter()
        report = reporter.report(sample_results, "http://test.local")

        assert len(report["errors"]) == 1
        assert "Connection timeout" in report["errors"][0]

    def test_writes_to_file(self, sample_results):
        """Report is written to file."""
        reporter = JSONReporter()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            output_path = f.name

        try:
            reporter.report(sample_results, "http://test.local", output_path)

            # Verify file was written
            content = Path(output_path).read_text()
            data = json.loads(content)
            assert data["scan_info"]["target"] == "http://test.local"
        finally:
            Path(output_path).unlink()

    def test_empty_results(self, empty_results):
        """Handles empty results."""
        reporter = JSONReporter()
        report = reporter.report(empty_results, "http://test.local")

        assert report["summary"]["total_findings"] == 0
        assert len(report["findings"]) == 0


class TestConsoleReporter:
    """Tests for console reporter."""

    def test_creates_reporter(self):
        """Reporter can be instantiated."""
        reporter = ConsoleReporter()
        assert reporter.console is not None

    def test_severity_colors_defined(self):
        """All severity levels have colors."""
        reporter = ConsoleReporter()
        for severity in Severity:
            assert severity in reporter.SEVERITY_COLORS

    def test_severity_icons_defined(self):
        """All severity levels have icons."""
        reporter = ConsoleReporter()
        for severity in Severity:
            assert severity in reporter.SEVERITY_ICONS

    def test_report_with_findings(self, sample_results, capsys):
        """Report with findings produces output."""
        reporter = ConsoleReporter()
        reporter.report(sample_results, "http://test.local")

        # Just verify it runs without error
        # Rich output is complex to test directly

    def test_report_empty_results(self, empty_results, capsys):
        """Report with no findings shows message."""
        reporter = ConsoleReporter()
        reporter.report(empty_results, "http://test.local")

        # Verify it runs without error

    def test_print_summary(self, sample_findings):
        """Summary prints correctly."""
        reporter = ConsoleReporter()
        # Just verify method exists and runs
        reporter._print_summary(sample_findings)

    def test_print_findings(self, sample_findings):
        """Findings print correctly."""
        reporter = ConsoleReporter()
        reporter._print_findings(sample_findings)

    def test_print_errors(self):
        """Errors print correctly."""
        reporter = ConsoleReporter()
        reporter._print_errors(["Error 1", "Error 2"])
