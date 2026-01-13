"""Tests for BOLAScanner."""

import pytest
import httpx
import respx

from src.core import Severity, Target
from src.scanners import BOLAScanner


class TestBOLAScanner:
    """Tests for Broken Object Level Authorization scanner."""

    def test_scanner_name(self, mock_client):
        """Scanner has correct name."""
        client, _ = mock_client
        scanner = BOLAScanner(client)
        assert scanner.name == "BOLAScanner"
        assert "V01" in scanner.description

    @respx.mock
    async def test_requires_credentials(self, base_url, target_no_auth):
        """Returns error when no credentials provided."""
        with httpx.Client() as client:
            scanner = BOLAScanner(client)
            result = await scanner.scan(target_no_auth)

        assert len(result.errors) > 0
        assert "Credentials required" in result.errors[0]

    @respx.mock
    async def test_detects_bola_vulnerability(self, base_url, target, user_with_sensitive_data):
        """Detects BOLA when user can access other users' data."""
        # Login succeeds
        respx.post(f"{base_url}/api/login").mock(
            return_value=httpx.Response(200, json={"access_token": "valid-token"})
        )
        # Current user endpoint
        respx.get(f"{base_url}/api/users/me").mock(
            return_value=httpx.Response(200, json={"id": 5, "username": "testuser"})
        )
        # Can access other user's data (BOLA!)
        respx.get(f"{base_url}/api/users/1").mock(
            return_value=httpx.Response(200, json=user_with_sensitive_data)
        )
        respx.get(f"{base_url}/api/users/2").mock(
            return_value=httpx.Response(200, json=user_with_sensitive_data)
        )
        respx.get(f"{base_url}/api/users/3").mock(
            return_value=httpx.Response(200, json=user_with_sensitive_data)
        )
        respx.get(f"{base_url}/api/users/4").mock(
            return_value=httpx.Response(200, json=user_with_sensitive_data)
        )

        with httpx.Client() as client:
            scanner = BOLAScanner(client)
            result = await scanner.scan(target)

        bola_findings = [f for f in result.findings if "BOLA" in f.id]
        assert len(bola_findings) == 1
        assert bola_findings[0].severity == Severity.HIGH
        assert "ssn" in bola_findings[0].evidence.lower() or "credit" in bola_findings[0].evidence.lower()

    @respx.mock
    async def test_no_bola_when_access_denied(self, base_url, target):
        """No finding when access to other users is denied."""
        respx.post(f"{base_url}/api/login").mock(
            return_value=httpx.Response(200, json={"access_token": "valid-token"})
        )
        respx.get(f"{base_url}/api/users/me").mock(
            return_value=httpx.Response(200, json={"id": 5, "username": "testuser"})
        )
        # Access denied for other users
        respx.get(f"{base_url}/api/users/1").mock(
            return_value=httpx.Response(403, json={"detail": "Forbidden"})
        )
        respx.get(f"{base_url}/api/users/2").mock(
            return_value=httpx.Response(403, json={"detail": "Forbidden"})
        )
        respx.get(f"{base_url}/api/users/3").mock(
            return_value=httpx.Response(403, json={"detail": "Forbidden"})
        )
        respx.get(f"{base_url}/api/users/4").mock(
            return_value=httpx.Response(403, json={"detail": "Forbidden"})
        )

        with httpx.Client() as client:
            scanner = BOLAScanner(client)
            result = await scanner.scan(target)

        bola_findings = [f for f in result.findings if "BOLA" in f.id]
        assert len(bola_findings) == 0

    @respx.mock
    async def test_login_failure(self, base_url, target):
        """Returns error when login fails."""
        respx.post(f"{base_url}/api/login").mock(
            return_value=httpx.Response(401, json={"detail": "Invalid credentials"})
        )

        with httpx.Client() as client:
            scanner = BOLAScanner(client)
            result = await scanner.scan(target)

        assert len(result.errors) > 0
        assert "authenticate" in result.errors[0].lower()

    @respx.mock
    async def test_tries_form_data_login(self, base_url, target):
        """Falls back to form data login if JSON fails."""
        # JSON login fails
        respx.post(f"{base_url}/api/login", json={"username": "testuser", "password": "testpass123"}).mock(
            return_value=httpx.Response(422, json={"detail": "Unprocessable"})
        )
        # Form data login succeeds
        respx.post(f"{base_url}/api/login").mock(
            return_value=httpx.Response(200, json={"access_token": "form-token"})
        )
        respx.get(f"{base_url}/api/users/me").mock(
            return_value=httpx.Response(200, json={"id": 1, "username": "testuser"})
        )
        # No BOLA - returns 404 for other users
        for i in [2, 3]:
            respx.get(f"{base_url}/api/users/{i}").mock(
                return_value=httpx.Response(404)
            )

        with httpx.Client() as client:
            scanner = BOLAScanner(client)
            result = await scanner.scan(target)

        # Should not have authentication error
        auth_errors = [e for e in result.errors if "authenticate" in e.lower()]
        assert len(auth_errors) == 0
