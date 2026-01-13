"""Tests for HeadersScanner."""

import pytest
import httpx
import respx

from src.core import Severity
from src.scanners import HeadersScanner


class TestHeadersScanner:
    """Tests for security headers scanner."""

    def test_scanner_name(self, mock_client):
        """Scanner has correct name."""
        client, _ = mock_client
        scanner = HeadersScanner(client)
        assert scanner.name == "HeadersScanner"
        assert "V08" in scanner.description

    def test_security_headers_defined(self, mock_client):
        """Security headers to check are defined."""
        client, _ = mock_client
        scanner = HeadersScanner(client)
        assert "Strict-Transport-Security" in scanner.SECURITY_HEADERS
        assert "Content-Security-Policy" in scanner.SECURITY_HEADERS
        assert "X-Frame-Options" in scanner.SECURITY_HEADERS

    def test_dangerous_headers_defined(self, mock_client):
        """Dangerous headers to detect are defined."""
        client, _ = mock_client
        scanner = HeadersScanner(client)
        assert "Server" in scanner.DANGEROUS_HEADERS
        assert "X-Powered-By" in scanner.DANGEROUS_HEADERS


class TestMissingSecurityHeaders:
    """Tests for missing security header detection."""

    @respx.mock
    async def test_detects_missing_hsts(self, base_url, target):
        """Detects missing HSTS header."""
        respx.get(f"{base_url}/").mock(
            return_value=httpx.Response(200, headers={})
        )
        respx.options(f"{base_url}/api/products").mock(
            return_value=httpx.Response(200, headers={})
        )

        with httpx.Client() as client:
            scanner = HeadersScanner(client)
            result = await scanner.scan(target)

        # ID format: V08-HDR-STRICTTRANSPORTSECURITY
        hsts_findings = [f for f in result.findings if "TRANSPORT" in f.id.upper() or "HSTS" in f.name.upper()]
        assert len(hsts_findings) == 1
        assert hsts_findings[0].severity == Severity.MEDIUM

    @respx.mock
    async def test_detects_missing_csp(self, base_url, target):
        """Detects missing Content-Security-Policy."""
        respx.get(f"{base_url}/").mock(
            return_value=httpx.Response(200, headers={})
        )
        respx.options(f"{base_url}/api/products").mock(
            return_value=httpx.Response(200, headers={})
        )

        with httpx.Client() as client:
            scanner = HeadersScanner(client)
            result = await scanner.scan(target)

        csp_findings = [f for f in result.findings if "CSP" in f.name.upper() or "SECURITY" in f.name.upper()]
        assert len(csp_findings) >= 1

    @respx.mock
    async def test_no_finding_when_headers_present(self, base_url, target):
        """No finding when security headers are present."""
        respx.get(f"{base_url}/").mock(
            return_value=httpx.Response(
                200,
                headers={
                    "Strict-Transport-Security": "max-age=31536000",
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                    "Content-Security-Policy": "default-src 'self'",
                    "X-XSS-Protection": "1; mode=block",
                    "Referrer-Policy": "strict-origin",
                    "Permissions-Policy": "geolocation=()",
                }
            )
        )
        respx.options(f"{base_url}/api/products").mock(
            return_value=httpx.Response(200, headers={})
        )

        with httpx.Client() as client:
            scanner = HeadersScanner(client)
            result = await scanner.scan(target)

        # Filter for missing header findings only
        missing_findings = [f for f in result.findings if "not set" in f.name.lower()]
        assert len(missing_findings) == 0


class TestDangerousHeaders:
    """Tests for dangerous header detection."""

    @respx.mock
    async def test_detects_server_header(self, base_url, target):
        """Detects exposed Server header."""
        respx.get(f"{base_url}/").mock(
            return_value=httpx.Response(
                200,
                headers={"Server": "Apache/2.4.51 (Ubuntu)"}
            )
        )
        respx.options(f"{base_url}/api/products").mock(
            return_value=httpx.Response(200, headers={})
        )

        with httpx.Client() as client:
            scanner = HeadersScanner(client)
            result = await scanner.scan(target)

        server_findings = [f for f in result.findings if "Server" in f.name]
        assert len(server_findings) == 1
        assert "Apache" in server_findings[0].evidence

    @respx.mock
    async def test_detects_x_powered_by(self, base_url, target):
        """Detects X-Powered-By header."""
        respx.get(f"{base_url}/").mock(
            return_value=httpx.Response(
                200,
                headers={"X-Powered-By": "Express"}
            )
        )
        respx.options(f"{base_url}/api/products").mock(
            return_value=httpx.Response(200, headers={})
        )

        with httpx.Client() as client:
            scanner = HeadersScanner(client)
            result = await scanner.scan(target)

        powered_findings = [f for f in result.findings if "Powered" in f.name]
        assert len(powered_findings) == 1


class TestCORSConfiguration:
    """Tests for CORS misconfiguration detection."""

    @respx.mock
    async def test_detects_wildcard_cors(self, base_url, target):
        """Detects CORS with wildcard origin."""
        respx.get(f"{base_url}/").mock(
            return_value=httpx.Response(200, headers={})
        )
        respx.options(f"{base_url}/api/products").mock(
            return_value=httpx.Response(
                200,
                headers={"Access-Control-Allow-Origin": "*"}
            )
        )

        with httpx.Client() as client:
            scanner = HeadersScanner(client)
            result = await scanner.scan(target)

        cors_findings = [f for f in result.findings if "CORS" in f.id]
        assert len(cors_findings) == 1
        assert cors_findings[0].severity == Severity.MEDIUM

    @respx.mock
    async def test_detects_wildcard_with_credentials(self, base_url, target):
        """Detects CORS wildcard with credentials."""
        respx.get(f"{base_url}/").mock(
            return_value=httpx.Response(200, headers={})
        )
        respx.options(f"{base_url}/api/products").mock(
            return_value=httpx.Response(
                200,
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Credentials": "true",
                }
            )
        )

        with httpx.Client() as client:
            scanner = HeadersScanner(client)
            result = await scanner.scan(target)

        cors_findings = [f for f in result.findings if "CORS" in f.id]
        assert len(cors_findings) == 1
        assert cors_findings[0].severity == Severity.HIGH

    @respx.mock
    async def test_detects_origin_reflection(self, base_url, target):
        """Detects CORS origin reflection."""
        respx.get(f"{base_url}/").mock(
            return_value=httpx.Response(200, headers={})
        )
        respx.options(f"{base_url}/api/products").mock(
            return_value=httpx.Response(
                200,
                headers={"Access-Control-Allow-Origin": "https://evil.com"}
            )
        )

        with httpx.Client() as client:
            scanner = HeadersScanner(client)
            result = await scanner.scan(target)

        cors_findings = [f for f in result.findings if "REFLECT" in f.id]
        assert len(cors_findings) == 1
        assert cors_findings[0].severity == Severity.HIGH
