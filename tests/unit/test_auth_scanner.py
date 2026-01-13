"""Tests for AuthScanner."""

import pytest
import httpx
import respx
from respx import MockRouter

from src.core import Severity
from src.scanners import AuthScanner


class TestAuthScanner:
    """Tests for authentication vulnerability scanner."""

    @pytest.fixture
    def scanner(self, mock_client):
        """Create scanner with mocked client."""
        client, _ = mock_client
        return AuthScanner(client)

    def test_scanner_name(self, mock_client):
        """Scanner has correct name."""
        client, _ = mock_client
        scanner = AuthScanner(client)
        assert scanner.name == "AuthScanner"
        assert "V02" in scanner.description or "V04" in scanner.description

    @respx.mock
    async def test_detects_user_enumeration(self, base_url, target):
        """Detects user enumeration via different error messages."""
        # Mock different error messages for invalid vs valid user
        respx.post(f"{base_url}/api/login").mock(
            side_effect=[
                httpx.Response(401, json={"detail": "User not found"}),
                httpx.Response(401, json={"detail": "Invalid password"}),
            ]
        )

        with httpx.Client() as client:
            scanner = AuthScanner(client)
            result = await scanner.scan(target)

        # Should detect user enumeration
        enum_findings = [f for f in result.findings if "ENUM" in f.id]
        assert len(enum_findings) == 1
        assert enum_findings[0].severity == Severity.MEDIUM

    @respx.mock
    async def test_no_user_enumeration_same_message(self, base_url, target):
        """No finding when error messages are the same."""
        respx.post(f"{base_url}/api/login").mock(
            return_value=httpx.Response(401, json={"detail": "Invalid credentials"})
        )

        with httpx.Client() as client:
            scanner = AuthScanner(client)
            result = await scanner.scan(target)

        enum_findings = [f for f in result.findings if "ENUM" in f.id]
        assert len(enum_findings) == 0

    @respx.mock
    async def test_detects_weak_jwt_hs256(self, base_url, target):
        """Detects JWT with HS256 algorithm."""
        # HS256 JWT token
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.fake"
        respx.post(f"{base_url}/api/login").mock(
            return_value=httpx.Response(200, json={"access_token": token})
        )

        with httpx.Client() as client:
            scanner = AuthScanner(client)
            result = await scanner.scan(target)

        jwt_findings = [f for f in result.findings if "JWT" in f.id]
        assert len(jwt_findings) == 1
        assert jwt_findings[0].severity == Severity.HIGH
        assert "HS256" in jwt_findings[0].evidence

    @respx.mock
    async def test_detects_no_rate_limiting(self, base_url, target):
        """Detects missing rate limiting on login."""
        # All requests succeed without 429
        respx.post(f"{base_url}/api/login").mock(
            return_value=httpx.Response(401, json={"detail": "Invalid"})
        )

        with httpx.Client() as client:
            scanner = AuthScanner(client)
            result = await scanner.scan(target)

        rate_findings = [f for f in result.findings if "RATE" in f.id]
        assert len(rate_findings) == 1
        assert rate_findings[0].severity == Severity.MEDIUM

    @respx.mock
    async def test_rate_limiting_present(self, base_url, target):
        """No finding when rate limiting is present."""
        # Return 429 after a few attempts
        responses = [httpx.Response(401, json={"detail": "Invalid"})] * 3
        responses.append(httpx.Response(429, json={"detail": "Too many requests"}))
        respx.post(f"{base_url}/api/login").mock(side_effect=responses)

        with httpx.Client() as client:
            scanner = AuthScanner(client)
            result = await scanner.scan(target)

        rate_findings = [f for f in result.findings if "RATE" in f.id]
        assert len(rate_findings) == 0

    @respx.mock
    async def test_handles_connection_error(self, base_url, target):
        """Handles connection errors gracefully."""
        respx.post(f"{base_url}/api/login").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )

        with httpx.Client() as client:
            scanner = AuthScanner(client)
            result = await scanner.scan(target)

        # Should have errors logged, not crash
        assert len(result.errors) > 0
