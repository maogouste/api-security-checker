"""Tests for InjectionScanner."""

import pytest
import httpx
import respx

from src.core import Severity
from src.scanners import InjectionScanner


class TestInjectionScanner:
    """Tests for SQL and Command injection scanner."""

    def test_scanner_name(self, mock_client):
        """Scanner has correct name."""
        client, _ = mock_client
        scanner = InjectionScanner(client)
        assert scanner.name == "InjectionScanner"
        assert "V06" in scanner.description or "V07" in scanner.description

    def test_sql_payloads_defined(self, mock_client):
        """SQL injection payloads are loaded from config."""
        client, _ = mock_client
        scanner = InjectionScanner(client)
        assert len(scanner.sql_payloads) >= 5
        # Check that some common SQL payloads are present
        payloads_str = " ".join(scanner.sql_payloads)
        assert "OR" in payloads_str or "UNION" in payloads_str

    def test_cmd_payloads_defined(self, mock_client):
        """Command injection payloads are loaded from config."""
        client, _ = mock_client
        scanner = InjectionScanner(client)
        assert len(scanner.cmd_payloads) >= 5
        # Check that some common command payloads are present
        payloads_str = " ".join(scanner.cmd_payloads)
        assert "id" in payloads_str or "cat" in payloads_str


class TestSQLInjection:
    """Tests for SQL injection detection."""

    @respx.mock
    async def test_detects_sql_error_in_response(self, base_url, target, sql_error_response):
        """Detects SQL injection via error message."""
        # Login for auth
        respx.post(f"{base_url}/api/login").mock(
            return_value=httpx.Response(200, json={"access_token": "token"})
        )
        # SQL error in response
        respx.get(url__regex=r".*/api/products\?search=.*").mock(
            return_value=httpx.Response(500, text=sql_error_response)
        )

        with httpx.Client() as client:
            scanner = InjectionScanner(client)
            result = await scanner.scan(target)

        sqli_findings = [f for f in result.findings if "SQLI" in f.id]
        assert len(sqli_findings) == 1
        assert sqli_findings[0].severity == Severity.CRITICAL

    @respx.mock
    async def test_detects_union_injection(self, base_url, target):
        """Detects UNION-based SQL injection."""
        respx.post(f"{base_url}/api/login").mock(
            return_value=httpx.Response(200, json={"access_token": "token"})
        )
        # UNION injection returns many results
        respx.get(url__regex=r".*/api/products\?search=.*UNION.*").mock(
            return_value=httpx.Response(200, json=[{"id": i} for i in range(10)])
        )
        # Normal queries return few results
        respx.get(url__regex=r".*/api/products\?search=(?!.*UNION).*").mock(
            return_value=httpx.Response(200, json=[{"id": 1}])
        )

        with httpx.Client() as client:
            scanner = InjectionScanner(client)
            result = await scanner.scan(target)

        sqli_findings = [f for f in result.findings if "SQLI" in f.id]
        assert len(sqli_findings) >= 1

    @respx.mock
    async def test_detects_boolean_injection(self, base_url, target):
        """Detects boolean-based SQL injection."""
        respx.post(f"{base_url}/api/login").mock(
            return_value=httpx.Response(200, json={"access_token": "token"})
        )
        # OR 1=1 returns more results than normal
        respx.get(url__regex=r".*/api/products\?search=.*OR.*").mock(
            return_value=httpx.Response(200, json=[{"id": i} for i in range(10)])
        )
        respx.get(url__regex=r".*/api/products\?search=test$").mock(
            return_value=httpx.Response(200, json=[{"id": 1}])
        )
        # Other endpoints
        respx.get(url__regex=r".*/api/users\?search=.*").mock(
            return_value=httpx.Response(404)
        )

        with httpx.Client() as client:
            scanner = InjectionScanner(client)
            result = await scanner.scan(target)

        sqli_findings = [f for f in result.findings if "SQLI" in f.id]
        assert len(sqli_findings) >= 1

    @respx.mock
    async def test_no_sqli_on_safe_response(self, base_url, target):
        """No finding when responses are normal."""
        respx.post(f"{base_url}/api/login").mock(
            return_value=httpx.Response(200, json={"access_token": "token"})
        )
        # All responses return same small result set
        respx.get(url__regex=r".*/api/products\?.*").mock(
            return_value=httpx.Response(200, json=[{"id": 1}])
        )
        respx.get(url__regex=r".*/api/users\?.*").mock(
            return_value=httpx.Response(404)
        )

        with httpx.Client() as client:
            scanner = InjectionScanner(client)
            result = await scanner.scan(target)

        sqli_findings = [f for f in result.findings if "SQLI" in f.id]
        assert len(sqli_findings) == 0


class TestCommandInjection:
    """Tests for command injection detection."""

    @respx.mock
    async def test_detects_command_output(self, base_url, target, command_output_response):
        """Detects command injection via output."""
        respx.post(f"{base_url}/api/login").mock(
            return_value=httpx.Response(200, json={"access_token": "token"})
        )
        respx.post(f"{base_url}/api/tools/ping").mock(
            return_value=httpx.Response(200, json=command_output_response)
        )
        respx.post(f"{base_url}/api/tools/dns").mock(
            return_value=httpx.Response(404)
        )

        with httpx.Client() as client:
            scanner = InjectionScanner(client)
            result = await scanner.scan(target)

        cmdi_findings = [f for f in result.findings if "CMDI" in f.id]
        assert len(cmdi_findings) == 1
        assert cmdi_findings[0].severity == Severity.CRITICAL

    @respx.mock
    async def test_detects_etc_passwd(self, base_url, target):
        """Detects command injection via /etc/passwd content."""
        respx.post(f"{base_url}/api/login").mock(
            return_value=httpx.Response(200, json={"access_token": "token"})
        )
        respx.post(f"{base_url}/api/tools/ping").mock(
            return_value=httpx.Response(200, json={"output": "root:x:0:0:root:/root:/bin/bash"})
        )
        respx.post(f"{base_url}/api/tools/dns").mock(
            return_value=httpx.Response(404)
        )

        with httpx.Client() as client:
            scanner = InjectionScanner(client)
            result = await scanner.scan(target)

        cmdi_findings = [f for f in result.findings if "CMDI" in f.id]
        assert len(cmdi_findings) == 1

    @respx.mock
    async def test_no_cmdi_on_normal_response(self, base_url, target):
        """No finding when response is normal."""
        respx.post(f"{base_url}/api/login").mock(
            return_value=httpx.Response(200, json={"access_token": "token"})
        )
        respx.post(f"{base_url}/api/tools/ping").mock(
            return_value=httpx.Response(200, json={"output": "PING localhost: 64 bytes"})
        )
        respx.post(f"{base_url}/api/tools/dns").mock(
            return_value=httpx.Response(404)
        )

        with httpx.Client() as client:
            scanner = InjectionScanner(client)
            result = await scanner.scan(target)

        cmdi_findings = [f for f in result.findings if "CMDI" in f.id]
        assert len(cmdi_findings) == 0

    @respx.mock
    async def test_handles_endpoint_not_found(self, base_url, target):
        """Handles missing endpoints gracefully."""
        respx.post(f"{base_url}/api/login").mock(
            return_value=httpx.Response(200, json={"access_token": "token"})
        )
        respx.post(f"{base_url}/api/tools/ping").mock(
            return_value=httpx.Response(404)
        )
        respx.post(f"{base_url}/api/tools/dns").mock(
            return_value=httpx.Response(404)
        )
        respx.get(url__regex=r".*").mock(
            return_value=httpx.Response(404)
        )

        with httpx.Client() as client:
            scanner = InjectionScanner(client)
            result = await scanner.scan(target)

        # Should complete without errors
        assert len(result.errors) == 0
