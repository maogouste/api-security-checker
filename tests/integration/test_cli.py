"""Integration tests for CLI."""

import pytest
from typer.testing import CliRunner
from src.cli import app

runner = CliRunner()


class TestScanCommand:
    """Tests for the scan command."""

    def test_scan_help(self):
        """Scan command shows help."""
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "Scan an API for security vulnerabilities" in result.stdout
        assert "--insecure" in result.stdout
        assert "--verbose" in result.stdout

    def test_scan_requires_url(self):
        """Scan command requires URL argument."""
        result = runner.invoke(app, ["scan"])
        assert result.exit_code != 0
        # Typer outputs error messages to stdout or the output may be in result.output
        output = result.stdout + (result.output if hasattr(result, 'output') else "")
        assert result.exit_code == 2  # Typer exits with 2 for missing args

    def test_scan_invalid_type(self):
        """Scan command validates scan type."""
        result = runner.invoke(app, ["scan", "http://localhost:8000", "--type", "invalid"])
        # Should fail with unknown scan type
        assert result.exit_code != 0 or "Unknown scan type" in result.stdout

    def test_scan_insecure_warning(self):
        """Scan command shows warning for --insecure."""
        # This will fail to connect but should show the warning
        result = runner.invoke(app, ["scan", "https://localhost:9999", "--insecure", "--timeout", "1"])
        assert "SSL" in result.stdout or "Warning" in result.stdout


class TestVulnapiCommand:
    """Tests for the vulnapi command."""

    def test_vulnapi_help(self):
        """Vulnapi command shows help."""
        result = runner.invoke(app, ["vulnapi", "--help"])
        assert result.exit_code == 0
        assert "Quick scan against VulnAPI" in result.stdout
        assert "--backend" in result.stdout

    def test_vulnapi_backend_options(self):
        """Vulnapi command accepts backend options."""
        result = runner.invoke(app, ["vulnapi", "--help"])
        assert "fastapi" in result.stdout
        assert "express" in result.stdout


class TestListScannersCommand:
    """Tests for the list-scanners command."""

    def test_list_scanners(self):
        """List scanners command works."""
        result = runner.invoke(app, ["list-scanners"])
        assert result.exit_code == 0
        assert "AuthScanner" in result.stdout
        assert "BOLAScanner" in result.stdout
        assert "InjectionScanner" in result.stdout
        assert "GraphQLScanner" in result.stdout
        assert "HeadersScanner" in result.stdout

    def test_list_scanners_shows_descriptions(self):
        """List scanners shows descriptions."""
        result = runner.invoke(app, ["list-scanners"])
        assert "V01" in result.stdout or "V02" in result.stdout
        assert "auth" in result.stdout.lower() or "injection" in result.stdout.lower()


class TestCLIOptions:
    """Tests for CLI options parsing."""

    def test_config_option_accepted(self):
        """Config option is accepted."""
        result = runner.invoke(app, ["scan", "--help"])
        assert "--config" in result.stdout
        assert "-c" in result.stdout

    def test_output_option_accepted(self):
        """Output option is accepted."""
        result = runner.invoke(app, ["scan", "--help"])
        assert "--output" in result.stdout
        assert "-o" in result.stdout

    def test_timeout_option_accepted(self):
        """Timeout option is accepted."""
        result = runner.invoke(app, ["scan", "--help"])
        assert "--timeout" in result.stdout

    def test_verbose_option_accepted(self):
        """Verbose option is accepted."""
        result = runner.invoke(app, ["scan", "--help"])
        assert "--verbose" in result.stdout
        assert "-v" in result.stdout

    def test_log_file_option_accepted(self):
        """Log file option is accepted."""
        result = runner.invoke(app, ["scan", "--help"])
        assert "--log-file" in result.stdout
